#!/usr/bin/env node
// Run locally against a downloaded Cisco repository; no vendor source is executed.
import fs from 'node:fs'
import path from 'node:path'
import {execFileSync} from 'node:child_process'
import {Worker} from 'node:worker_threads'
import snmp from 'net-snmp'
import {db,all,one,run,json,id,now,audit} from '../api/src/db.js'
import {recordMibFile,readSource} from '../api/src/snmpMibStorage.js'
import {seed} from '../api/src/snmpMibLibrary.js'
import {mibEnvelope} from '../api/src/snmpMibSyntax.js'
import {builtinMibProfiles} from '../api/src/snmpMibCatalog.js'
const repo=path.resolve(process.argv[2]||'data/mib-sources/cisco-mibs'),origin='cisco/cisco-mibs'
const revision=execFileSync('git',['-C',repo,'rev-parse','HEAD'],{encoding:'utf8'}).trim()
const base=new Set(snmp.createModuleStore().getModuleNames(true)),index=new Map(),archive=[]
const rank=f=>f.startsWith('v2/')?0:f.startsWith('v1/')?2:f.startsWith('archive/')?3:1
function walk(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true})){if(entry.name==='.git')continue;const file=path.join(dir,entry.name);if(entry.isDirectory())walk(file);else if(entry.isFile()&&/\.(my|mib|txt)$/i.test(entry.name)){const content=fs.readFileSync(file);if(!/DEFINITIONS\s*::=\s*BEGIN/.test(content.toString('utf8')))continue;const filename=path.relative(repo,file).split(path.sep).join('/');let moduleName=null,error=null,imports=[];try{const clean=mibEnvelope(content.toString('utf8'));moduleName=clean.match(/\b([A-Za-z][\w-]*)\s+DEFINITIONS\s*::=\s*BEGIN/)?.[1];imports=[...(clean.match(/\bIMPORTS\b([\s\S]*?);/)?.[1]||'').matchAll(/\bFROM\s+([A-Za-z][\w-]*)/g)].map(m=>m[1])}catch(e){error=e.message}const stored=recordMibFile({moduleName,filename,content,origin,revision,sourceUrl:`https://github.com/cisco/cisco-mibs/blob/${revision}/${filename}`,status:error?'error':'archived',error});const item={...stored,source_path:stored.sourcePath,moduleName,filename,imports,error};archive.push(item);if(moduleName&&!error&&(!index.has(moduleName)||rank(filename)<rank(index.get(moduleName).filename)))index.set(moduleName,item)}}}
seed();walk(repo)
console.log(JSON.stringify({revision,sourceFiles:archive.length,uniqueModules:index.size}))
const preferences={
 'CISCO-CDP-MIB':['cdpCacheDeviceId','cdpCacheDevicePort','cdpCachePlatform','cdpCacheAddress','cdpCacheCapabilities','cdpCacheVersion'],
 'CISCO-PROCESS-MIB':['cpmCPUTotal5secRev','cpmCPUTotal1minRev','cpmCPUTotal5minRev'],
 'CISCO-MEMORY-POOL-MIB':['ciscoMemoryPoolName','ciscoMemoryPoolUsed','ciscoMemoryPoolFree'],
 'CISCO-ENTITY-SENSOR-MIB':['entSensorType','entSensorScale','entSensorPrecision','entSensorValue','entSensorStatus'],
 'CISCO-ENTITY-FRU-CONTROL-MIB':['cefcFRUPowerAdminStatus','cefcFRUPowerOperStatus','cefcFanTrayOperStatus'],
 'CISCO-VLAN-MEMBERSHIP-MIB':['vmVlanType','vmVlan'],
 'CISCO-STACKWISE-MIB':['cswSwitchRole','cswSwitchState','cswSwitchMacAddress','cswSwitchSoftwareImage']
}
let completed=0;const outcomes=[]
function compile(files){return new Promise(resolve=>{const worker=new Worker(new URL('../api/src/snmpMibParserWorker.js',import.meta.url),{workerData:{files},resourceLimits:{maxOldGenerationSizeMb:256,maxYoungGenerationSizeMb:32},execArgv:[]});const timer=setTimeout(()=>{worker.terminate();resolve({error:'Parser exceeded 15 seconds'})},15000);worker.once('message',r=>{clearTimeout(timer);worker.terminate();resolve(r)});worker.once('error',e=>{clearTimeout(timer);resolve({error:e.message})});worker.once('exit',code=>{clearTimeout(timer);if(code!==0)resolve({error:'Parser stopped'})})})}
const queue=[...index.values()].sort((a,b)=>a.moduleName.localeCompare(b.moduleName));let cursor=0
async function worker(){while(cursor<queue.length){const item=queue[cursor++];if(base.has(item.moduleName)){run("UPDATE snmp_mib_files SET status='bundled' WHERE id=?",item.id);continue}
 const visited=new Set(),files=[];let error=null
 function dependency(name){if(base.has(name)||visited.has(name))return;visited.add(name);const f=index.get(name);if(!f)throw Error('Missing dependency '+name);f.imports.forEach(dependency);files.push({filename:path.basename(f.filename),content:readSource(f)})}
 let result;try{dependency(item.moduleName);result=await compile(files);error=result.error||null}catch(e){error=e.message}
 const metadata=result?.modules?.find(m=>m.moduleName===item.moduleName),old=one('SELECT * FROM snmp_mib_library WHERE module_name=?',item.moduleName),curated=builtinMibProfiles.find(p=>p.moduleName===item.moduleName)
 // Keep an existing usable profile when a vendor source cannot be compiled.
 if(error&&old?.parse_status==='ready'){run("UPDATE snmp_mib_files SET status='error',error=? WHERE id=?",error,item.id);outcomes.push({module:item.moduleName,status:'error',error,retainedExisting:true})}
 else{
  const meta=metadata||{moduleName:item.moduleName,objects:[],imports:item.imports,description:'Source retained; compilation needs attention',match:{sysObjectIdPrefixes:[],sysDescrContains:[]}}
  meta.sourceUrl=`https://github.com/cisco/cisco-mibs/blob/${revision}/${item.filename}`;meta.repositoryRevision=revision
  if(curated&&metadata)for(const object of curated.objects)if(!meta.objects.some(o=>o.name===object.name))meta.objects.push(object)
  const config=old?JSON.parse(old.config_json):{match:meta.match,selectedObjects:(preferences[item.moduleName]||[]).filter(n=>meta.objects.some(o=>o.name===n))}
  const enabled=error?0:old?old.enabled:config.selectedObjects.length?1:0
  run('INSERT INTO snmp_mib_library(id,module_name,source,filename,source_path,sha256,metadata_json,config_json,enabled,created_at,updated_at,parse_status,parse_error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(module_name) DO UPDATE SET source=excluded.source,filename=excluded.filename,source_path=excluded.source_path,content=NULL,sha256=excluded.sha256,metadata_json=excluded.metadata_json,config_json=excluded.config_json,enabled=excluded.enabled,updated_at=excluded.updated_at,parse_status=excluded.parse_status,parse_error=excluded.parse_error',old?.id||id(),item.moduleName,'imported',path.basename(item.filename),item.sourcePath,item.sha256,json(meta),json(config),enabled,old?.created_at||now(),now(),error?'error':'ready',error)
  run('UPDATE snmp_mib_files SET status=?,error=? WHERE id=?',error?'error':'ready',error,item.id)
  outcomes.push({module:item.moduleName,status:error?'error':'ready',objects:meta.objects.length,error})
 }
 completed++;if(completed%50===0)console.log(JSON.stringify({processed:completed,total:queue.length,errors:outcomes.filter(r=>r.error).length}))
}}
await Promise.all([worker(),worker(),worker()])
const report={origin,revision,fileStatuses:all('SELECT status,count(*) count FROM snmp_mib_files WHERE origin=? GROUP BY status',origin),sourceFiles:archive.length,modules:queue.length,ready:outcomes.filter(x=>x.status==='ready').length,errors:outcomes.filter(x=>x.error),completedAt:now()}
fs.writeFileSync(path.join(path.dirname(repo),'cisco-import-report.json'),JSON.stringify(report,null,2))
audit(null,'snmp-mib.catalog-import','snmp-library',null,null,{origin,revision,sourceFiles:archive.length,modules:queue.length,ready:report.ready,errors:report.errors.length})
console.log(JSON.stringify({...report,errors:report.errors.length}));db.close()
