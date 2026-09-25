import {db,all,one,run,id,now,audit} from '../db.js'
import {canonicalIp,configuredCidrs,inLocalCidrs,unicastIp,subnetMatcher} from '../services/networkBoundary.js'
import {scopeSchema,pageSchema} from './schemas.js'
const parse=v=>{try{return JSON.parse(v||'{}')}catch{return {}}}
const uuid=v=>{const s=String(v||'').toLowerCase().replace(/[{}]/g,'');return /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(s)&&!/^0+-0+-0+-0+-0+$/.test(s)?s:null}
const mac=v=>String(v||'').replace(/[^a-f\d]/gi,'').toLowerCase()
export const scopes=()=>all('SELECT * FROM inventory_scopes ORDER BY name').map(r=>({...r,cidrs:r.id==='default'?configuredCidrs():parse(r.cidrs_json),directManagement:!!r.direct_management,cidrs_json:undefined}))
export function saveScope(data,actor,scopeId=null){
  const value=scopeSchema.parse(data),before=scopeId?one('SELECT * FROM inventory_scopes WHERE id=?',scopeId):null
  if(scopeId==='default')throw Object.assign(new Error('Edit default local CIDRs in Server config'),{status:409})
  if(scopeId&&!before)throw Object.assign(new Error('Scope not found'),{status:404})
  if(value.directManagement){
    const other=scopes().filter(s=>s.id!==scopeId&&s.directManagement)
    if(!value.cidrs.length||other.some(s=>!s.cidrs.length||s.cidrs.some(a=>value.cidrs.some(b=>subnetMatcher(a)(b.split('/')[0])||subnetMatcher(b)(a.split('/')[0])))))throw Object.assign(new Error('Direct management requires explicit CIDRs that do not overlap another directly managed scope'),{status:409})
  }
  const scope=scopeId||id()
  run('INSERT INTO inventory_scopes(id,name,cidrs_json,kind,direct_management,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,cidrs_json=excluded.cidrs_json,kind=excluded.kind,direct_management=excluded.direct_management',scope,value.name,JSON.stringify(value.cidrs),value.kind,Number(value.directManagement),now())
  audit(actor,'inventory.scope.save','inventory-scope',scope,before,{...value,id:scope});return scopes().find(s=>s.id===scope)
}
export function sourceScope(record,config){
  const mapped=new Set((record.networkIds||[]).map(n=>config.networkScopes?.find(m=>m.networkId.toLowerCase()===n.toLowerCase())?.scopeId).filter(Boolean))
  if(mapped.size>1)return null
  return [...mapped][0]||config.scopeId
}
export function eligibleSource(record,scopeId){
  const scope=one('SELECT * FROM inventory_scopes WHERE id=?',scopeId||'')
  if(!scope)return false
  const cidrs=scope.id==='default'?configuredCidrs():parse(scope.cidrs_json)
  // Cloud import requires a positively configured boundary, even when legacy LAN discovery is unrestricted.
  return Array.isArray(cidrs)&&cidrs.length>0&&(record.addresses||[]).some(a=>unicastIp(a,cidrs)&&inLocalCidrs(a,cidrs))
}
function candidates(record,scopeId){
  const strong=[],weak=[],ids=new Set([uuid(record.uuid),uuid(record.vmId)].filter(Boolean))
  const macs=new Set((record.macs||[]).map(mac).filter(v=>v.length===12&&!/^0+$/.test(v)))
  for(const n of all('SELECT n.*,f.snapshot_json FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id WHERE n.scope_id=?',scopeId)){
    const facts=parse(n.snapshot_json),vm=parse(n.virtual_machine_details_json)
    const sameUuid=[facts.uuid,facts.identity?.biosUuid,facts.system?.UUID,vm.uuid].map(uuid).some(v=>v&&ids.has(v))
    const sameAd=record.adGuid&&n.ad_guid===record.adGuid
    const sameName=record.fqdn&&record.fqdn.toLowerCase()===String(n.fqdn||'').toLowerCase()
    const sameMac=macs.has(mac(n.mac_address))
    if(sameUuid||sameAd||(sameName&&sameMac))strong.push({nodeId:n.id,reason:sameUuid?'Hardware/VM UUID':sameAd?'AD object GUID':'FQDN and scoped MAC'})
    else if(sameName||(record.addresses||[]).includes(canonicalIp(n.ip)))weak.push({nodeId:n.id,reason:'Name or address only; identity review required'})
  }
  for(const s of all("SELECT node_id,evidence_json FROM asset_sources WHERE scope_id=? AND node_id IS NOT NULL AND state='linked'",scopeId)){
    const other=parse(s.evidence_json)
    if(uuid(other.uuid)&&ids.has(uuid(other.uuid))&&!strong.some(c=>c.nodeId===s.node_id))strong.push({nodeId:s.node_id,reason:'Matching scoped provider VM UUID'})
  }
  return {strong,weak}
}
function conflict(sourceId,reason,items){
  const old=one("SELECT id FROM asset_identity_conflicts WHERE source_id=? AND state='open'",sourceId)
  if(old)run('UPDATE asset_identity_conflicts SET reason=?,candidates_json=? WHERE id=?',reason,JSON.stringify(items),old.id)
  else run('INSERT INTO asset_identity_conflicts(id,source_id,reason,candidates_json,created_at) VALUES(?,?,?,?,?)',id(),sourceId,reason,JSON.stringify(items),now())
}
export function reconcileRecord(record,config,runId,actor=null){
  if(!record.resourceId||!record.tenantId)throw new Error('Provider identity is required')
  const resourceId=record.resourceId.toLowerCase(),tenant=record.tenantId.toLowerCase(),scopeId=sourceScope(record,config)
  const previous=one('SELECT * FROM asset_sources WHERE provider=? AND tenant_id=? AND resource_id=?',record.provider,tenant,resourceId)
  const sourceId=previous?.id||id(),stamp=now(),evidence=JSON.stringify(record),previousRecord=parse(previous?.evidence_json)
  let nodeId=previous?.node_id||null,state=previous?.state==='ignored'?'ignored':'candidate',why='New source observation'
  const identityChanged=previous&&uuid(previousRecord.uuid)&&uuid(record.uuid)&&uuid(previousRecord.uuid)!==uuid(record.uuid)
  if(state==='ignored')why='Operator excluded source'
  else if(previous?.manual_link===2){state='candidate';why='Operator unlinked source; automatic linking is paused'}
  else if(!scopeId){state='conflict';why='Resource has interfaces in multiple configured scopes'}
  else if(!eligibleSource(record,scopeId)){state='out-of-scope';why='No address inside configured scope'}
  else if(identityChanged||previous?.scope_id&&previous.scope_id!==scopeId){state='conflict';why=identityChanged?'Resource identity changed or was recreated':'Network scope changed'}
  else if(previous?.state==='conflict'){state='conflict';why=one("SELECT reason FROM asset_identity_conflicts WHERE source_id=? AND state='open'",sourceId)?.reason||'Identity review is still required'}
  else if(nodeId){state='linked';why='Existing provider identity link'}
  else{
    const {strong,weak}=candidates(record,scopeId)
    const duplicateProvider=strong.length===1&&one("SELECT id FROM asset_sources WHERE node_id=? AND provider=? AND resource_id<>? AND state='linked'",strong[0].nodeId,record.provider,resourceId)
    if(strong.length===1&&!duplicateProvider){nodeId=strong[0].nodeId;state='linked';why=strong[0].reason}
    else if(duplicateProvider){state='conflict';why='Possible clone or resource move: another resource of this provider uses the identity'}
    else if(strong.length>1||weak.length){state='conflict';why=strong.length>1?'Multiple matching identities':'Only weak identity evidence'}
    else{
      const scope=one('SELECT * FROM inventory_scopes WHERE id=?',scopeId),cidrs=scopeId==='default'?configuredCidrs():parse(scope.cidrs_json)
      const ip=(record.addresses||[]).find(a=>unicastIp(a,cidrs)&&inLocalCidrs(a,cidrs))
      nodeId=id();state='linked';why='New in-scope source identity'
      run("INSERT INTO nodes(id,hostname,fqdn,ip,scope_id,os_name,os_version,inventory_source,firewall_state,agent_required,status,manageability,virtual_machine) VALUES(?,?,?,?,?,?,?,?,'unmanaged',1,'unknown','unmanaged',?)",nodeId,record.hostname||record.name,record.fqdn||null,ip,scopeId,record.osName||null,record.osVersion||null,record.provider,Number(record.kind==='vm'))
    }
  }
  if(nodeId&&state==='linked'&&previous){
    const n=one('SELECT * FROM nodes WHERE id=?',nodeId),fields={hostname:'hostname',fqdn:'fqdn',os_name:'osName',os_version:'osVersion'}
    // Update only fields still equal to our last observation. Authenticated facts and manual
    // changes remain authoritative; raw provider fields remain available on the source record.
    if(n?.inventory_source===record.provider&&!one('SELECT node_id FROM node_facts WHERE node_id=?',nodeId)){
      for(const [field,key] of Object.entries(fields))if(record[key]&&n[field]===previousRecord[key])run(`UPDATE nodes SET ${field}=? WHERE id=?`,record[key],nodeId)
      const scope=one('SELECT cidrs_json FROM inventory_scopes WHERE id=?',scopeId),cidrs=scopeId==='default'?configuredCidrs():parse(scope.cidrs_json),ip=record.addresses?.find(a=>unicastIp(a,cidrs)&&inLocalCidrs(a,cidrs))
      if(ip&&previousRecord.addresses?.includes(n.ip))run('UPDATE nodes SET ip=? WHERE id=?',ip,nodeId)
    }
  }
  run(`INSERT INTO asset_sources(id,provider,tenant_id,resource_id,scope_id,node_id,state,evidence_json,observed_at,fetched_at,first_seen_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET scope_id=excluded.scope_id,node_id=excluded.node_id,state=excluded.state,evidence_json=excluded.evidence_json,observed_at=excluded.observed_at,fetched_at=excluded.fetched_at,missing_since=NULL,missing_runs=0`,sourceId,record.provider,tenant,resourceId,scopeId,nodeId,state,evidence,record.observedAt||null,stamp,stamp)
  run('INSERT INTO asset_source_connections(source_id,connection_id,last_run_id) VALUES(?,?,?) ON CONFLICT(source_id,connection_id) DO UPDATE SET last_run_id=excluded.last_run_id',sourceId,config.id,runId)
  if(state==='conflict'){
    const matches=candidates(record,scopeId),items=matches.strong.concat(matches.weak)
    if(previous?.node_id&&!items.some(c=>c.nodeId===previous.node_id))items.push({nodeId:previous.node_id,reason:'Previous source binding; verify the replacement identity before linking'})
    conflict(sourceId,why,items)
  }
  const change=!previous?'new':previous.state!==state||previous.node_id!==nodeId||previous.evidence_json!==evidence?'changed':'unchanged'
  if(change!=='unchanged'){
    const after={state,nodeId,scopeId,record,reason:why}
    run('INSERT INTO asset_source_history(source_id,run_id,change,before_json,after_json,at) VALUES(?,?,?,?,?,?)',sourceId,runId,change,previous?JSON.stringify({state:previous.state,nodeId:previous.node_id,record:previousRecord}):null,JSON.stringify(after),stamp)
    audit(actor,'inventory.source.reconcile','asset-source',sourceId,previous?{nodeId:previous.node_id,state:previous.state}:null,{nodeId,state,reason:why})
  }
  return {sourceId,nodeId,state,change,reason:why}
}
export function listSources(query={}){
  const q=pageSchema.parse(query),args=[],clauses=[]
  if(q.q){clauses.push("(s.resource_id LIKE ? ESCAPE '\\' OR json_extract(s.evidence_json,'$.name') LIKE ? ESCAPE '\\')");const term='%'+q.q.replace(/[\\%_]/g,'\\$&')+'%';args.push(term,term)}
  if(q.state!=='all'){clauses.push('s.state=?');args.push(q.state)}
  if(q.scopeId){clauses.push('s.scope_id=?');args.push(q.scopeId)}
  if(q.connectionId){clauses.push('EXISTS(SELECT 1 FROM asset_source_connections c WHERE c.source_id=s.id AND c.connection_id=?)');args.push(q.connectionId)}
  const where=clauses.length?'WHERE '+clauses.join(' AND '):'',sort={name:"json_extract(s.evidence_json,'$.name')",state:'s.state',updated:'s.fetched_at'}[q.sort]
  const total=one(`SELECT COUNT(*) n FROM asset_sources s ${where}`,...args).n
  const items=all(`SELECT s.* FROM asset_sources s ${where} ORDER BY ${sort} ${q.direction},s.id LIMIT ? OFFSET ?`,...args,q.pageSize,(q.page-1)*q.pageSize).map(r=>({...r,evidence:parse(r.evidence_json),evidence_json:undefined}))
  return {items,total,page:q.page,pageSize:q.pageSize}
}
export const nodeSources=nodeId=>all('SELECT * FROM asset_sources WHERE node_id=? ORDER BY fetched_at DESC',nodeId).map(r=>({...r,evidence:parse(r.evidence_json),evidence_json:undefined}))
export function sourceHistory(sourceId,query={}){
  if(!one('SELECT id FROM asset_sources WHERE id=?',sourceId))throw Object.assign(new Error('Source not found'),{status:404})
  const q=pageSchema.parse(query)
  return {items:all('SELECT * FROM asset_source_history WHERE source_id=? ORDER BY id DESC LIMIT ? OFFSET ?',sourceId,q.pageSize,(q.page-1)*q.pageSize).map(r=>({...r,before:parse(r.before_json),after:parse(r.after_json),before_json:undefined,after_json:undefined})),total:one('SELECT COUNT(*) n FROM asset_source_history WHERE source_id=?',sourceId).n,page:q.page,pageSize:q.pageSize}
}
// Operators can review/reverse an automatic source link as well as a queued conflict.
export function resolveSource(sourceId,data,actor){
  return db.transaction(()=>{
    if(!one('SELECT id FROM asset_sources WHERE id=?',sourceId))throw Object.assign(new Error('Source not found'),{status:404})
    let review=one("SELECT id FROM asset_identity_conflicts WHERE source_id=? AND state='open'",sourceId)
    if(!review){conflict(sourceId,'Operator requested source review',[]);review=one("SELECT id FROM asset_identity_conflicts WHERE source_id=? AND state='open'",sourceId)}
    return resolveConflict(review.id,data,actor)
  })()
}
export function resolveConflict(conflictId,{nodeId,action,reason},actor){
  if(!['link','unlink','ignore','reopen'].includes(action)||typeof reason!=='string'||!reason.trim()||reason.length>1000)throw Object.assign(new Error('Choose a resolution and supply a reason'),{status:400})
  return db.transaction(()=>{
    const row=one('SELECT * FROM asset_identity_conflicts WHERE id=?',conflictId),source=row&&one('SELECT * FROM asset_sources WHERE id=?',row.source_id)
    if(!source)throw Object.assign(new Error('Conflict not found'),{status:404})
    if(action==='link'){
      const node=one('SELECT * FROM nodes WHERE id=?',nodeId)
      if(!node||node.scope_id!==source.scope_id||!eligibleSource(parse(source.evidence_json),source.scope_id))throw Object.assign(new Error('Select an eligible node in the same scope'),{status:409})
    }
    const target=action==='link'?nodeId:null,state=action==='ignore'?'ignored':action==='link'?'linked':'candidate'
    const decision={action,reason,nodeId:target,previousNodeId:source.node_id,previousState:source.state}
    run('UPDATE asset_sources SET node_id=?,state=?,manual_link=? WHERE id=?',target,state,action==='unlink'?2:Number(action==='link'),source.id)
    run('UPDATE asset_identity_conflicts SET state=?,decision_json=?,resolved_at=? WHERE id=?',action==='reopen'?'open':'resolved',JSON.stringify(decision),now(),conflictId)
    run('INSERT INTO asset_source_history(source_id,change,before_json,after_json,at) VALUES(?,?,?,?,?)',source.id,'resolution',JSON.stringify({nodeId:source.node_id,state:source.state}),JSON.stringify(decision),now())
    audit(actor,'inventory.conflict.resolve','asset-source',source.id,{nodeId:source.node_id,state:source.state},decision)
    return {ok:true,...decision}
  })()
}
