import {createHmac,randomBytes} from 'node:crypto'
import {z} from 'zod'
import {db,all,one,run,id,now,json,audit} from '../db.js'
import {seal,openSealed} from '../security.js'
import {fleetCoverage} from './capabilities.js'

const fail=(message,status=400)=>{throw Object.assign(new Error(message),{status})}
const endpoint=z.string().url().max(2048).refine(value=>{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password&&!u.hash&&!u.search},'Use an HTTPS URL without credentials, query string or fragment')
export const evidenceDestinationSchema=z.object({name:z.string().trim().min(1).max(120),endpoint,scopeId:z.string().min(1).max(200).default('default'),enabled:z.boolean().default(false),intervalMinutes:z.number().int().min(15).max(10080).default(1440),eventTypes:z.array(z.enum(['policy','drift','containment','connector'])).max(4).default([]),secret:z.string().min(32).max(512).optional()}).strict()
const publicDestination=r=>({id:r.id,name:r.name,endpoint:r.endpoint,scopeId:r.scope_id,enabled:!!r.enabled,intervalMinutes:r.interval_minutes,eventTypes:JSON.parse(r.event_types_json),nextRunAt:r.next_run_at,hasSecret:!!r.secret_blob,revision:r.revision,lastError:r.last_error})
export const evidenceDestinations=()=>all('SELECT * FROM evidence_destinations ORDER BY name,id').map(publicDestination)
export function saveEvidenceDestination(input,actor,key=null){
  const q=evidenceDestinationSchema.parse(input),old=key?one('SELECT * FROM evidence_destinations WHERE id=?',key):null
  if(key&&!old)fail('Evidence destination not found',404)
  if(!old&&one('SELECT count(*) n FROM evidence_destinations').n>=20)fail('At most 20 evidence destinations are supported',409)
  if(!one('SELECT id FROM inventory_scopes WHERE id=?',q.scopeId))fail('Select an existing inventory scope')
  const secret=q.secret||(!old?randomBytes(32).toString('base64url'):null),stamp=now();key||=id()
  db.transaction(()=>{
    if(old)run("UPDATE evidence_deliveries SET status='cancelled',last_error='Destination configuration changed' WHERE destination_id=? AND status IN ('pending','failed')",key)
    run(`INSERT INTO evidence_destinations(id,name,endpoint,secret_blob,scope_id,enabled,interval_minutes,event_types_json,next_run_at,audit_cursor,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,endpoint=excluded.endpoint,secret_blob=excluded.secret_blob,scope_id=excluded.scope_id,enabled=excluded.enabled,interval_minutes=excluded.interval_minutes,event_types_json=excluded.event_types_json,next_run_at=excluded.next_run_at,audit_cursor=excluded.audit_cursor,revision=revision+1,updated_at=excluded.updated_at,last_error=NULL`,key,q.name,q.endpoint,secret?seal({secret}):old.secret_blob,q.scopeId,Number(q.enabled),q.intervalMinutes,json([...new Set(q.eventTypes)]),new Date(Date.now()+q.intervalMinutes*60000).toISOString(),one('SELECT COALESCE(MAX(rowid),0) n FROM audit_log').n,old?.created_at||stamp,stamp)
    audit(actor,'evidence.destination.save','evidence-destination',key,null,{name:q.name,endpoint:q.endpoint,scopeId:q.scopeId,enabled:q.enabled,secretRotated:!!secret})
  })()
  return {...publicDestination(one('SELECT * FROM evidence_destinations WHERE id=?',key)),...(secret?{oneTimeSecret:secret}:{})}
}
export function evidenceSnapshot(scopeId='default'){
  if(!one('SELECT id FROM inventory_scopes WHERE id=?',scopeId))fail('Inventory scope not found',404)
  if(one('SELECT count(*) n FROM nodes WHERE scope_id=?',scopeId).n>500)fail('Evidence snapshot supports at most 500 assets per scope; use smaller site scopes',413)
  const coverage=fleetCoverage({scopeId,page:1,pageSize:500}),nodeIds=coverage.items.map(n=>n.nodeId)
  const policies=all(`SELECT DISTINCT p.id,p.name,p.current_version_id versionId FROM policies p JOIN policy_assignments a ON a.policy_id=p.id JOIN nodes n ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id) WHERE n.id IN (SELECT value FROM json_each(?)) ORDER BY p.id LIMIT 501`,json(nodeIds))
  if(policies.length>500)fail('Evidence snapshot exceeds 500 policies',413)
  const nodes=coverage.items.map(n=>({nodeId:n.nodeId,hostname:n.hostname,scopeId:n.scopeId,transport:n.transport,capabilities:Object.fromEntries(Object.entries(n.capabilities).map(([key,c])=>[key,{state:c.state,lastSuccessAt:c.lastSuccessAt,lastFailureAt:c.lastFailureAt,thresholdHours:c.thresholdHours,sources:c.sources}])),gaps:n.gaps,learningReady:n.learningReady}))
  const outcomes=all(`SELECT p.id,p.node_id nodeId,p.policy_id policyId,p.version_id versionId,p.status,p.finished_at finishedAt FROM policy_apply_runs p WHERE p.node_id IN (SELECT value FROM json_each(?)) ORDER BY julianday(p.finished_at) DESC LIMIT 100`,json(nodeIds))
  const verification=all(`SELECT v.id,v.node_id nodeId,v.policy_id policyId,v.passed,v.status,v.run_at checkedAt FROM verifier_results v WHERE v.node_id IN (SELECT value FROM json_each(?)) ORDER BY julianday(v.run_at) DESC LIMIT 100`,json(nodeIds))
  return {schemaVersion:1,type:'coverage.snapshot',generatedAt:now(),scopeId,total:nodes.length,summary:coverage.summary,policies,nodes,outcomes,verification,limits:{assets:500,policies:500,recentOutcomes:100,recentVerification:100},source:'retained evidence; no active probes',reachability:'not-established'}
}
export function evidenceDeliveries(input={}){
  const q=z.object({destinationId:z.string().optional(),status:z.enum(['pending','sent','failed','cancelled']).optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(100).default(25)}).parse(input),filters=[],args=[]
  if(q.destinationId){filters.push('destination_id=?');args.push(q.destinationId)}if(q.status){filters.push('status=?');args.push(q.status)}
  const where=filters.length?' WHERE '+filters.join(' AND '):''
  return {items:all('SELECT id,destination_id,event_key,status,attempts,created_at,sent_at,last_error FROM evidence_deliveries'+where+' ORDER BY created_at DESC,id LIMIT ? OFFSET ?',...args,q.pageSize,(q.page-1)*q.pageSize),total:one('SELECT count(*) n FROM evidence_deliveries'+where,...args).n,page:q.page,pageSize:q.pageSize}
}
function enqueue(destination,eventKey,payload){
  const encoded=json(payload)
  if(Buffer.byteLength(encoded)>2*1024*1024)fail('Evidence snapshot exceeds 2 MiB; reduce the scope',413)
  if(one("SELECT count(*) n FROM evidence_deliveries WHERE status IN ('pending','failed')").n>=1000)fail('Evidence failure queue is full; review pending/failed deliveries',429)
  const key=id();run('INSERT OR IGNORE INTO evidence_deliveries(id,destination_id,event_key,payload_json,revision,next_attempt_at,created_at) VALUES(?,?,?,?,?,?,?)',key,destination.id,eventKey,encoded,destination.revision,now(),now())
  return one('SELECT id FROM evidence_deliveries WHERE destination_id=? AND event_key=?',destination.id,eventKey)
}
export function queueEvidenceSnapshot(destinationId,actor){
  const d=one('SELECT * FROM evidence_destinations WHERE id=?',destinationId);if(!d)fail('Destination not found',404);if(!d.enabled)fail('Enable the destination before queueing a delivery',409)
  const result=enqueue(d,'manual:'+id(),evidenceSnapshot(d.scope_id));audit(actor,'evidence.snapshot.queue','evidence-destination',d.id,null,{deliveryId:result.id});return result
}
function auditKind(row){if(row.action.startsWith('policy.drift.'))return 'drift';if(row.action.startsWith('policy.'))return 'policy';if(row.action.startsWith('containment.'))return 'containment';if(/^(azure\.run\.(failed|finish)|node\.(unreachable|transport)|credential\.preflight\.failure)/.test(row.action))return 'connector';return null}
function auditReferences(row){
  let after={}
  try{if(row.after_json&&row.after_json.length<=1024*1024)after=JSON.parse(row.after_json)||{}}catch{}
  return Object.fromEntries(['versionId','policyId','jobId','nodeId','status','code'].filter(key=>typeof after[key]==='string'&&/^[A-Za-z0-9_.:/-]{1,200}$/.test(after[key])).map(key=>[key,after[key]]))
}
function auditInScope(row,scope){
  if(row.entity_type==='node')return !!one('SELECT id FROM nodes WHERE id=? AND scope_id=?',row.entity_id,scope)
  if(row.entity_type==='policy')return !!one('SELECT n.id FROM nodes n JOIN policy_assignments a ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id) WHERE a.policy_id=? AND n.scope_id=? LIMIT 1',row.entity_id,scope)
  if(row.entity_type==='containment')return !!one('SELECT n.id FROM nodes n JOIN containment_targets t ON t.node_id=n.id WHERE t.job_id=? AND n.scope_id=? LIMIT 1',row.entity_id,scope)
  if(row.entity_type==='azure-run')return one('SELECT json_extract(c.config_json,\'$.scopeId\') scope FROM azure_runs r JOIN azure_connections c ON c.id=r.connection_id WHERE r.id=?',row.entity_id)?.scope===scope
  return false
}
export function enqueueDueEvidence(){
  for(const d of all('SELECT * FROM evidence_destinations WHERE enabled=1 ORDER BY id LIMIT 20')){
    try{
      if(Date.parse(d.next_run_at)<=Date.now())db.transaction(()=>{enqueue(d,'schedule:'+d.next_run_at,evidenceSnapshot(d.scope_id));run('UPDATE evidence_destinations SET next_run_at=?,last_error=NULL WHERE id=?',new Date(Date.now()+d.interval_minutes*60000).toISOString(),d.id)})()
      const types=JSON.parse(d.event_types_json)
      for(const row of all('SELECT rowid sequence,id,action,entity_type,entity_id,at,after_json FROM audit_log WHERE rowid>? ORDER BY rowid LIMIT 100',d.audit_cursor))db.transaction(()=>{
        const kind=auditKind(row)
        if(types.includes(kind)&&auditInScope(row,d.scope_id))enqueue(d,'audit:'+row.id,{schemaVersion:1,type:kind+'.event',scopeId:d.scope_id,event:{id:row.id,action:row.action,entityType:row.entity_type,entityId:row.entity_id,at:row.at,references:auditReferences(row)},redaction:'Only allowlisted references are included; raw audit before/after values, credentials and remote error text are omitted'})
        run('UPDATE evidence_destinations SET audit_cursor=? WHERE id=?',row.sequence,d.id)
      })()
    }catch(error){run('UPDATE evidence_destinations SET last_error=? WHERE id=?',error.status?error.message:'Evidence generation failed; inspect local logs',d.id)}
  }
}
let delivering=false
export async function deliverEvidence({limit=10,fetchImpl=fetch}={}){
  if(delivering)return {processed:0};delivering=true;let processed=0
  try{
    for(const item of all("SELECT * FROM evidence_deliveries WHERE status='pending' AND next_attempt_at<=? ORDER BY next_attempt_at,id LIMIT ?",now(),Math.max(1,Math.min(25,limit)))){
      const d=one('SELECT * FROM evidence_destinations WHERE id=?',item.destination_id)
      if(!d?.enabled||d.revision!==item.revision){run("UPDATE evidence_deliveries SET status='cancelled' WHERE id=?",item.id);continue}
      try{
        const timestamp=String(Math.floor(Date.now()/1000)),secret=openSealed(d.secret_blob).secret
        const signature=createHmac('sha256',secret).update(timestamp+'.'+item.id+'.'+item.payload_json).digest('hex')
        const response=await fetchImpl(d.endpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/json','X-WinFire-Delivery':item.id,'Idempotency-Key':item.id,'X-WinFire-Timestamp':timestamp,'X-WinFire-Signature':'sha256='+signature},body:item.payload_json})
        await response.body?.cancel()
        if(!response.ok)throw new Error('HTTP '+response.status)
        run("UPDATE evidence_deliveries SET status='sent',sent_at=?,last_error=NULL WHERE id=? AND status='pending'",now(),item.id)
      }catch(error){const attempts=item.attempts+1;run('UPDATE evidence_deliveries SET status=?,attempts=?,next_attempt_at=?,last_error=? WHERE id=? AND status=\'pending\'',attempts>=5?'failed':'pending',attempts,new Date(Date.now()+Math.min(3600,30*2**attempts)*1000).toISOString(),/^HTTP \d+$/.test(error.message)?error.message:'Webhook delivery failed; check DNS, TLS, timeout and destination availability',item.id)}
      processed++
    }
    run("DELETE FROM evidence_deliveries WHERE rowid IN (SELECT rowid FROM evidence_deliveries WHERE status IN ('sent','cancelled') AND julianday(created_at)<julianday('now','-30 days') LIMIT 1000)")
    return {processed}
  }finally{delivering=false}
}
export function retryEvidence(key,actor){
  const item=one('SELECT * FROM evidence_deliveries WHERE id=?',key),d=item&&one('SELECT * FROM evidence_destinations WHERE id=?',item.destination_id)
  if(!item||!d)fail('Delivery not found',404)
  if(item.status!=='failed'||!d.enabled||item.revision!==d.revision)fail('Only failed deliveries to an unchanged enabled destination can retry',409)
  run("UPDATE evidence_deliveries SET status='pending',attempts=0,next_attempt_at=? WHERE id=?",now(),key);audit(actor,'evidence.delivery.retry','evidence-delivery',key,null,null)
  return {id:key,status:'pending'}
}
