import {Worker} from 'node:worker_threads'
import {createHash} from 'node:crypto'
import {z} from 'zod'
import {db,all,one,run,id,now,json,audit} from './db.js'
import {builtinMibProfiles,collectedObjectName} from './snmpMibCatalog.js'
import {mibModuleName} from './snmpMibSyntax.js'

const fail=(message,status=400)=>Object.assign(new Error(message),{status})
const oidPattern=/^(?:0|1|2)(?:\.(?:0|[1-9]\d*)){2,127}$/
export const mibMatchSchema=z.object({sysObjectIdPrefixes:z.array(z.string().trim().max(512).regex(oidPattern)).max(32).default([]),sysDescrContains:z.array(z.string().trim().min(2).max(120)).max(32).default([])})
export const mibImportSchema=z.object({files:z.array(z.object({filename:z.string().trim().min(1).max(200),content:z.string().min(1).max(1048576)})).min(1).max(20),replace:z.boolean().default(false)})
export const mibUpdateSchema=z.object({enabled:z.boolean().optional(),match:mibMatchSchema.optional(),selectedObjects:z.array(z.string().min(1).max(128)).max(64).optional()}).strict()
function seed(){
  const stamp=now()
  const insert=db.prepare('INSERT OR IGNORE INTO snmp_mib_library(id,module_name,source,metadata_json,config_json,enabled,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?)')
  db.transaction(()=>{for(const profile of builtinMibProfiles)insert.run(`builtin:${profile.moduleName}`,profile.moduleName,'builtin',json({...profile,imports:[],definitionCount:profile.objects.length}),json({match:profile.match,selectedObjects:profile.objects.map(o=>o.name)}),stamp,stamp)})()
}
const parseRow=row=>({...row,metadata:JSON.parse(row.metadata_json),config:JSON.parse(row.config_json)})
export function mibRecord(mibId){seed();const row=one('SELECT * FROM snmp_mib_library WHERE id=?',mibId);if(!row)throw fail('MIB not found',404);return parseRow(row)}
function publicRow(row){const r=parseRow(row);return {id:r.id,moduleName:r.module_name,source:r.source,filename:r.filename,sha256:r.sha256,enabled:!!r.enabled,description:r.metadata.description,sourceUrl:r.metadata.sourceUrl||null,imports:r.metadata.imports,objectCount:r.metadata.objects.length,selectedCount:r.config.selectedObjects.length,match:r.config.match,linkedNodes:row.linked_nodes||0,updatedAt:r.updated_at}}
export function listMibs(query={}){
  seed()
  const parsed=z.object({search:z.string().max(200).default(''),source:z.enum(['all','builtin','imported']).default('all'),page:z.coerce.number().int().min(1).default(1),limit:z.coerce.number().int().min(1).max(100).default(25),sort:z.enum(['name','source','updated']).default('name'),direction:z.enum(['asc','desc']).default('asc')}).parse(query)
  const clauses=[],args=[]
  if(parsed.search){clauses.push('(module_name LIKE ? OR filename LIKE ?)');args.push(`%${parsed.search}%`,`%${parsed.search}%`)}
  if(parsed.source!=='all'){clauses.push('source=?');args.push(parsed.source)}
  const where=clauses.length?'WHERE '+clauses.join(' AND '):'',total=one(`SELECT count(*) AS n FROM snmp_mib_library ${where}`,...args).n
  const sort={name:'module_name',source:'source',updated:'updated_at'}[parsed.sort],page=Math.min(parsed.page,Math.max(1,Math.ceil(total/parsed.limit)))
  const rows=all(`SELECT *, (SELECT count(*) FROM node_snmp_mibs b WHERE b.mib_id=snmp_mib_library.id) AS linked_nodes FROM snmp_mib_library ${where} ORDER BY ${sort} ${parsed.direction},id LIMIT ? OFFSET ?`,...args,parsed.limit,(page-1)*parsed.limit)
  return {items:rows.map(publicRow),total,page,limit:parsed.limit}
}
export function mibDetails(mibId,query={}){
  const row=mibRecord(mibId)
  const {search,page,limit}=z.object({search:z.string().max(200).default(''),page:z.coerce.number().int().min(1).default(1),limit:z.coerce.number().int().min(1).max(100).default(25)}).parse(query)
  const objects=row.metadata.objects.filter(o=>!search||`${o.name} ${o.oid}`.toLowerCase().includes(search.toLowerCase()))
  const actualPage=Math.min(page,Math.max(1,Math.ceil(objects.length/limit)))
  return {...publicRow(row),selectedObjects:row.config.selectedObjects,objects:objects.slice((actualPage-1)*limit,actualPage*limit),total:objects.length,page:actualPage,limit,bindings:all('SELECT b.node_id AS nodeId,n.hostname,b.status,b.last_polled_at AS lastPolledAt,b.evidence_json FROM node_snmp_mibs b JOIN nodes n ON n.id=b.node_id WHERE b.mib_id=? ORDER BY b.last_polled_at DESC LIMIT 100',row.id).map(({evidence_json,...b})=>({...b,evidence:JSON.parse(evidence_json)}))}
}
let parsing=false
async function parseFiles(files){
  if(parsing)throw fail('Another MIB import is being validated. Retry shortly.',409)
  parsing=true
  try{return await new Promise((resolve,reject)=>{
    const worker=new Worker(new URL('./snmpMibParserWorker.js',import.meta.url),{workerData:{files},resourceLimits:{maxOldGenerationSizeMb:128,maxYoungGenerationSizeMb:16},execArgv:[]})
    const timer=setTimeout(()=>{worker.terminate();reject(fail('MIB parsing exceeded the 10 second limit'))},10000)
    worker.once('message',message=>{clearTimeout(timer);worker.terminate();message.error?reject(fail(message.error)):resolve(message.modules)})
    worker.once('error',()=>{clearTimeout(timer);reject(fail('MIB parser could not process these files within its resource limits'))})
    worker.once('exit',code=>{clearTimeout(timer);if(code!==0)reject(fail('MIB parser stopped before validation completed'))})
  })}finally{parsing=false}
}
const digest=text=>createHash('sha256').update(text).digest('hex')
function currentRevision(){return digest(json(all('SELECT id,sha256,config_json,enabled,updated_at FROM snmp_mib_library ORDER BY id')))}
export async function importMibs(input,actorId,{preview=false}={}){
  seed();const data=mibImportSchema.parse(input),files=data.files
  if(files.reduce((sum,f)=>sum+Buffer.byteLength(f.content),0)>1500000)throw fail('Import is limited to 1.5 MB per batch')
  for(const f of files)if(/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(f.content))throw fail(`${f.filename}: upload plain text ASN.1 MIB files`)
  const revision=currentRevision(),existing=all("SELECT * FROM snmp_mib_library WHERE source='imported'")
  let incomingNames;try{incomingNames=files.map(f=>mibModuleName(f.content))}catch(error){throw fail(error.message)}
  const retained=existing.filter(r=>!incomingNames.includes(r.module_name)).map(r=>({filename:r.filename,content:r.content}))
  if(retained.length+files.length>100||[...retained,...files].reduce((n,f)=>n+Buffer.byteLength(f.content),0)>8000000)throw fail('Imported library limit: 100 modules or 8 MB of source text')
  const modules=await parseFiles([...retained,...files]),parsed=modules.filter(m=>incomingNames.includes(m.moduleName))
  if(parsed.length!==files.length)throw fail('Unable to identify every submitted MIB module')
  const candidates=parsed.map(m=>{
    const file=files[incomingNames.indexOf(m.moduleName)],old=one('SELECT * FROM snmp_mib_library WHERE module_name=?',m.moduleName),sha256=digest(file.content)
    if(old&&old.sha256!==sha256&&!data.replace)throw fail(`${m.moduleName} already exists. Enable replacement to update it.`,409)
    const objects=m.objects.slice(0,64).map(o=>o.name)
    return {m,file,old,sha256,action:old?.sha256===sha256?'unchanged':old?'replace':'import',selectedObjects:objects}
  })
  const report={modules:candidates.map(c=>({moduleName:c.m.moduleName,action:c.action,objectCount:c.m.objects.length,selectedCount:c.selectedObjects.length,imports:c.m.imports,match:c.m.match,warnings:[...(!c.m.match.sysObjectIdPrefixes.length?['No vendor enterprise OID found. Configure a device match to enable automatic collection.']:[]),...(c.m.objects.length>64?['First 64 readable objects selected; review selection before polling.']:[])]}))}
  if(preview)return report
  if(revision!==currentRevision())throw fail('Library changed during validation. Preview and import again.',409)
  db.transaction(()=>{
    const stamp=now()
    for(const {m,file,old,sha256,action,selectedObjects} of candidates){
      if(action==='unchanged')continue
      const config=old?JSON.parse(old.config_json):{match:m.match,selectedObjects}
      config.selectedObjects=config.selectedObjects.filter(name=>m.objects.some(o=>o.name===name))
      // Replacing a curated profile keeps its matching criteria; selections use imported symbols.
      if(old?.source==='builtin')config.selectedObjects=selectedObjects
      run('INSERT INTO snmp_mib_library(id,module_name,source,filename,content,sha256,metadata_json,config_json,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(module_name) DO UPDATE SET source=excluded.source,filename=excluded.filename,content=excluded.content,sha256=excluded.sha256,metadata_json=excluded.metadata_json,config_json=excluded.config_json,updated_at=excluded.updated_at',old?.id||id(),m.moduleName,'imported',file.filename,file.content,sha256,json(m),json(config),old?.enabled??1,old?.created_at||stamp,stamp)
    }
    // Recompile dependent metadata when a dependency was replaced.
    for(const m of modules.filter(m=>!incomingNames.includes(m.moduleName))){
      const r=one('SELECT * FROM snmp_mib_library WHERE module_name=?',m.moduleName),config=JSON.parse(r.config_json)
      config.selectedObjects=config.selectedObjects.filter(name=>m.objects.some(o=>o.name===name))
      run('UPDATE snmp_mib_library SET metadata_json=?,config_json=?,updated_at=? WHERE id=?',json(m),json(config),stamp,r.id)
    }
    audit(actorId,'snmp-mib.import','snmp-library',null,null,report)
  })()
  return report
}
export function updateMib(mibId,input,actorId){
  const data=mibUpdateSchema.parse(input),row=mibRecord(mibId),config=row.config
  if(data.match)config.match=data.match
  if(data.selectedObjects){if(data.selectedObjects.some(name=>!row.metadata.objects.some(o=>o.name===name)))throw fail('Selected object is not a readable object in this MIB');config.selectedObjects=[...new Set(data.selectedObjects)]}
  run('UPDATE snmp_mib_library SET enabled=?,config_json=?,updated_at=? WHERE id=?',data.enabled===undefined?row.enabled:Number(data.enabled),json(config),now(),row.id)
  audit(actorId,'snmp-mib.update','snmp-mib',row.id,null,{enabled:data.enabled,config})
  return mibDetails(row.id)
}
export function deleteMib(mibId,actorId){
  const row=mibRecord(mibId)
  if(row.source==='builtin')throw fail('Built-in profiles can be disabled, not deleted',409)
  const dependents=all("SELECT * FROM snmp_mib_library WHERE source='imported' AND id<>?",row.id).map(parseRow).filter(r=>r.metadata.imports.includes(row.module_name))
  if(dependents.length)throw fail(`Required by: ${dependents.map(r=>r.module_name).join(', ')}. Remove dependent modules first.`,409)
  db.transaction(()=>{run('DELETE FROM snmp_mib_library WHERE id=?',row.id);audit(actorId,'snmp-mib.delete','snmp-mib',row.id,{moduleName:row.module_name},null)})()
}
const normalizedOid=value=>String(value||'').replace(/^\./,'')
export function matchMib(identity,match={}){
  const oid=normalizedOid(identity.sysObjectId),descr=String(identity.sysDescr||'').toLowerCase()
  if(match.all)return {method:'standard',signal:'Standard MIB capability probe'}
  const prefix=match.sysObjectIdPrefixes?.find(p=>oid===p||oid.startsWith(p+'.'))
  if(prefix)return {method:'sysObjectID',signal:prefix}
  const text=match.sysDescrContains?.find(p=>descr.includes(p.toLowerCase()))
  return text?{method:'sysDescr',signal:text}:null
}
export function collectionPlan(identity,{nodeId=null,host=null}={}){
  seed()
  if(!nodeId&&host)nodeId=one('SELECT id FROM nodes WHERE ip=? OR lower(hostname)=lower(?) OR lower(fqdn)=lower(?) LIMIT 1',host,host,host)?.id
  const identityKey=json([normalizedOid(identity.sysObjectId),identity.sysDescr||''])
  const linked=new Set(nodeId?all('SELECT mib_id FROM node_snmp_mibs WHERE node_id=? AND identity_key=?',nodeId,identityKey).map(r=>r.mib_id):[])
  const profiles=all('SELECT * FROM snmp_mib_library WHERE enabled=1 ORDER BY source DESC,module_name').map(parseRow).map(r=>{
    const evidence=matchMib(identity,r.config.match)
    return evidence?{id:r.id,moduleName:r.module_name,source:r.source,sha256:r.sha256,evidence:{...evidence,reused:linked.has(r.id)},objects:r.metadata.objects.filter(o=>r.config.selectedObjects.includes(o.name))}:null
  }).filter(Boolean).sort((a,b)=>Number(b.evidence.method==='standard')-Number(a.evidence.method==='standard')||Number(b.evidence.reused)-Number(a.evidence.reused))
  return {identityKey,profiles}
}
export function persistMibBindings(nodeId,collection,stamp){
  if(!collection)return
  db.transaction(()=>{
    run('DELETE FROM node_snmp_mibs WHERE node_id=?',nodeId)
    for(const profile of collection.profiles||[]){
      if(!one('SELECT id FROM snmp_mib_library WHERE id=?',profile.id))continue
      run('INSERT INTO node_snmp_mibs(node_id,mib_id,identity_key,evidence_json,status,last_polled_at) VALUES(?,?,?,?,?,?)',nodeId,profile.id,collection.identityKey,json(profile.evidence),profile.status,stamp)
    }
  })()
}

export function nodeMibFacts(nodeId,query={}){
  if(!one('SELECT id FROM nodes WHERE id=?',nodeId))throw fail('Node not found',404)
  const {moduleId,search,page,limit}=z.object({moduleId:z.string().max(200).default(''),search:z.string().max(200).default(''),page:z.coerce.number().int().min(1).default(1),limit:z.coerce.number().int().min(1).max(100).default(25)}).parse(query)
  const row=one('SELECT snapshot_json,collected_at FROM node_facts WHERE node_id=?',nodeId)
  const facts=JSON.parse(row?.snapshot_json||'{}'),collection=facts.mibCollection||{profiles:[]}
  const profiles=collection.profiles.map(({objects,...profile})=>({...profile,objectCount:objects.length,valueCount:objects.reduce((n,o)=>n+o.values.length,0),enabled:!!one('SELECT enabled FROM snmp_mib_library WHERE id=?',profile.id)?.enabled}))
  const rows=collection.profiles.filter(p=>!moduleId||p.id===moduleId).flatMap(p=>p.objects.flatMap(o=>o.values.length?o.values.map(v=>({moduleName:p.moduleName,object:collectedObjectName(o,v.oid),oid:v.oid,value:v.value,units:o.units,status:o.status,truncated:!!o.truncated})): [{moduleName:p.moduleName,object:o.name,oid:o.oid,value:null,status:o.status,error:o.error}]))
    .filter(r=>!search||`${r.moduleName} ${r.object} ${r.oid} ${r.value??''}`.toLowerCase().includes(search.toLowerCase()))
  const actualPage=Math.min(page,Math.max(1,Math.ceil(rows.length/limit)))
  const hardwareSummary=(facts.hardware||[]).find(h=>h.class===3)||(facts.hardware||[]).find(h=>h.serialNumber)||null
  return {hardwareSummary,profiles,items:rows.slice((actualPage-1)*limit,actualPage*limit),total:rows.length,page:actualPage,limit,collectedAt:row?.collected_at||null,queryCount:collection.queryCount||0,truncated:!!collection.truncated}
}
