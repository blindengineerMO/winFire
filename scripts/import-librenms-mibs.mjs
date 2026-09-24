#!/usr/bin/env node
// Import source data only. MIB files never execute commands or contact devices.
import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import {execFileSync} from 'node:child_process'
import {Worker} from 'node:worker_threads'
import snmp from 'net-snmp'
import {db,all,one,run,json,id,now,audit} from '../api/src/db.js'
import {recordMibFile,readSource} from '../api/src/snmpMibStorage.js'
import {seed} from '../api/src/snmpMibLibrary.js'
import {mibEnvelope} from '../api/src/snmpMibSyntax.js'

const origin='librenms/librenms'
const base=new Set(snmp.createModuleStore().getModuleNames(true))
const sourceUrl=(revision,filename)=>`https://github.com/${origin}/blob/${revision}/${filename.split('/').map(encodeURIComponent).join('/')}`
const lexical=(a,b)=>a<b?-1:a>b?1:0
const preferred=(a,b)=>a.filename.split('/').length-b.filename.split('/').length||lexical(a.filename,b.filename)
function proximity(filename,requester){
  const a=filename.split('/').slice(0,-1),b=requester.split('/').slice(0,-1)
  let shared=0;while(shared<Math.min(a.length,b.length)&&a[shared]===b[shared])shared++
  return shared
}
function compile(files){
  return new Promise(resolve=>{
    const worker=new Worker(new URL('../api/src/snmpMibParserWorker.js',import.meta.url),{workerData:{files},resourceLimits:{maxOldGenerationSizeMb:256,maxYoungGenerationSizeMb:32},execArgv:[]})
    let settled=false
    const finish=result=>{if(settled)return;settled=true;clearTimeout(timer);void worker.terminate();resolve(result)}
    const timer=setTimeout(()=>finish({error:'Parser exceeded 15 seconds'}),15000)
    worker.once('message',finish)
    worker.once('error',error=>finish({error:error.message}))
    worker.once('exit',()=>finish({error:'Parser stopped before validation completed'}))
  })
}

export async function importLibreNmsCatalog({repo=path.resolve('data/mib-sources/librenms'),revision,log=console.log}={}){
  repo=path.resolve(repo)
  revision??=execFileSync('git',['-C',repo,'rev-parse','HEAD'],{encoding:'utf8'}).trim()
  if(!/^[a-f0-9]{40}$/.test(revision))throw Error('Expected the full repository commit SHA')
  const root=path.join(repo,'mibs')
  if(!fs.statSync(root).isDirectory())throw Error('The checkout must contain a mibs directory')
  seed()
  const sources=[],index=new Map()
  function walk(dir){
    for(const entry of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>lexical(a.name,b.name))){
      const file=path.join(dir,entry.name)
      if(entry.isDirectory()){walk(file);continue}
      // Do not follow links outside the downloaded repository.
      if(!entry.isFile())continue
      const content=fs.readFileSync(file),filename=path.relative(repo,file).split(path.sep).join('/')
      let moduleName=null,imports=[],error=null
      try{
        const clean=mibEnvelope(content.toString('utf8'))
        const headers=[...clean.matchAll(/\b([A-Za-z][\w-]*)\s+DEFINITIONS\s*::=\s*BEGIN/g)]
        if(headers.length!==1||! /\bEND\s*$/.test(clean.trim()))throw Error('Expected one complete ASN.1 MIB module')
        moduleName=headers[0][1]
        imports=[...(clean.match(/\bIMPORTS\b([\s\S]*?);/)?.[1]||'').matchAll(/\bFROM\s+([A-Za-z][\w-]*)/g)].map(m=>m[1])
      }catch(e){error=e.message}
      const stored=recordMibFile({moduleName,filename,content,origin,revision,sourceUrl:sourceUrl(revision,filename),status:error?'error':'archived',error})
      const item={...stored,source_path:stored.sourcePath,moduleName,filename,imports,error}
      sources.push(item)
      if(moduleName&&!error){if(!index.has(moduleName))index.set(moduleName,[]);index.get(moduleName).push(item)}
    }
  }
  walk(root)
  for(const candidates of index.values())candidates.sort(preferred)
  log(JSON.stringify({origin,revision,sourceFiles:sources.length,uniqueModules:index.size}))
  // Read source metadata only; the complete catalog is never loaded into a parser.
  const fallback=new Map(all("SELECT module_name,filename,source_path,content,json_extract(metadata_json,'$.imports') AS imports FROM snmp_mib_library WHERE parse_status='ready' AND (source_path IS NOT NULL OR content IS NOT NULL)").map(r=>[r.module_name,{...r,moduleName:r.module_name,imports:JSON.parse(r.imports||'[]')}]))
  const outcomes=[],queue=[...index].sort(([a],[b])=>lexical(a,b))
  let cursor=0,completed=0
  function graph(item){
    const selected=new Map(),files=[],references=[]
    let bytes=0
    function visit(name,requester){
      if(base.has(name)||selected.has(name))return
      const candidates=index.get(name)
      const chosen=name===item.moduleName?item:candidates?.slice().sort((a,b)=>proximity(b.filename,requester)-proximity(a.filename,requester)||preferred(a,b))[0]||fallback.get(name)
      if(!chosen)throw Error('Missing dependency '+name)
      selected.set(name,chosen)
      const content=readSource(chosen)
      bytes+=Buffer.byteLength(content)
      if(bytes>32*1024*1024)throw Error('Dependency graph exceeds the 32 MiB compilation budget')
      for(const dep of chosen.imports)visit(dep,chosen.filename)
      files.push({filename:chosen.filename,content})
      references.push({module:name,filename:chosen.filename,sha256:chosen.sha256||null})
    }
    visit(item.moduleName,item.filename)
    return {files,references}
  }
  async function worker(){
    while(cursor<queue.length){
      const [name,candidates]=queue[cursor++]
      if(base.has(name)){
        for(const item of candidates)run("UPDATE snmp_mib_files SET status='bundled',error=NULL WHERE id=?",item.id)
        outcomes.push({module:name,status:'bundled'})
      }else{
        const existing=one('SELECT * FROM snmp_mib_library WHERE module_name=?',name)
        if(existing?.parse_status==='ready'){
          // Keep working Cisco/user definitions and their collection configuration.
          // A rerun keeps its own ready sources ready instead of archiving them.
          for(const item of candidates)if(item.sha256===existing.sha256)run("UPDATE snmp_mib_files SET status='ready',error=NULL WHERE id=?",item.id)
          outcomes.push({module:name,status:'retained-existing'})
        }else{
          let chosen=null,metadata=null,references=[],lastError=null
          for(const item of candidates){
            try{
              const input=graph(item),result=await compile(input.files)
              if(result.error)throw Error(result.error)
              const meta=result.modules?.find(m=>m.moduleName===name)
              if(!meta)throw Error('Parser returned no module metadata')
              chosen=item;metadata=meta;references=input.references
              break
            }catch(error){
              lastError=String(error.message).slice(0,1000)
              run("UPDATE snmp_mib_files SET status='error',error=? WHERE id=?",lastError,item.id)
            }
          }
          const item=chosen||candidates[0],error=chosen?null:lastError
          const meta=metadata||{moduleName:name,objects:[],imports:item.imports,description:'Source retained; compilation needs attention',match:{sysObjectIdPrefixes:[],sysDescrContains:[]}}
          Object.assign(meta,{sourceUrl:sourceUrl(revision,item.filename),repositoryRevision:revision,sourceDependencies:references})
          // Re-read after worker awaits so a concurrent operator edit is respected.
          db.transaction(()=>{
            const old=one('SELECT * FROM snmp_mib_library WHERE module_name=?',name)
            if(old?.parse_status==='ready'){outcomes.push({module:name,status:'retained-existing'});return}
            const config=old?JSON.parse(old.config_json):{match:meta.match,selectedObjects:meta.objects.slice(0,64).map(o=>o.name)}
            if(!error)config.selectedObjects=config.selectedObjects.filter(n=>meta.objects.some(o=>o.name===n))
            run('INSERT INTO snmp_mib_library(id,module_name,source,filename,source_path,sha256,metadata_json,config_json,enabled,created_at,updated_at,parse_status,parse_error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(module_name) DO UPDATE SET source=excluded.source,filename=excluded.filename,source_path=excluded.source_path,content=NULL,sha256=excluded.sha256,metadata_json=excluded.metadata_json,config_json=excluded.config_json,enabled=excluded.enabled,updated_at=excluded.updated_at,parse_status=excluded.parse_status,parse_error=excluded.parse_error',old?.id||id(),name,'imported',item.filename,item.sourcePath,item.sha256,json(meta),json(config),error?0:old?.enabled||0,old?.created_at||now(),now(),error?'error':'ready',error)
            if(chosen)run("UPDATE snmp_mib_files SET status='ready',error=NULL WHERE id=?",item.id)
            outcomes.push({module:name,filename:item.filename,status:error?'error':'ready',objects:meta.objects.length,error})
          }).immediate()
        }
      }
      completed++
      if(completed%100===0)log(JSON.stringify({processed:completed,total:queue.length,errors:outcomes.filter(r=>r.error).length}))
    }
  }
  await Promise.all([worker(),worker(),worker()])
  const report={origin,revision,sourceFiles:sources.length,modules:index.size,fileStatuses:all('SELECT status,count(*) count FROM snmp_mib_files WHERE origin=? GROUP BY status',origin),ready:outcomes.filter(x=>x.status==='ready').length,retainedExisting:outcomes.filter(x=>x.status==='retained-existing').length,bundled:outcomes.filter(x=>x.status==='bundled').length,errors:all("SELECT filename,error FROM snmp_mib_files WHERE origin=? AND status='error' ORDER BY filename",origin),completedAt:now()}
  fs.writeFileSync(path.join(path.dirname(repo),'librenms-import-report.json'),JSON.stringify(report,null,2))
  audit(null,'snmp-mib.catalog-import','snmp-library',null,null,{origin,revision,sourceFiles:report.sourceFiles,modules:report.modules,ready:report.ready,retainedExisting:report.retainedExisting,errors:report.errors.length})
  log(JSON.stringify({...report,errors:report.errors.length}))
  return report
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{await importLibreNmsCatalog({repo:process.argv[2]})}catch(error){console.error(error.message);process.exitCode=1}finally{db.close()}
}
