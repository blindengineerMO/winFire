import {db,all,one,run,id,now,audit} from '../db.js'
import {seal,openSealed} from '../security.js'
import {azureCredentialSchema,connectionSchema,pageSchema} from './schemas.js'
import {azureClient,validateCertificate,AzureError} from './client.js'
import {discoverAzure} from './azureAdapter.js'
import {reconcileRecord,eligibleSource,sourceScope} from './inventory.js'
const parse=v=>JSON.parse(v||'{}'),lease=()=>new Date(Date.now()+120000).toISOString()
const fail=(message,status=400)=>{throw Object.assign(new Error(message),{status})}
export function saveAzureCredential(data,actor,credentialId){
  const value=azureCredentialSchema.parse(data);validateCertificate(value)
  // Rotation can also change the authentication method. Retain only the material
  // that method uses in the shared vault entry.
  if(value.authMethod!=='secret')delete value.clientSecret
  if(value.authMethod!=='certificate'){delete value.clientCertificatePem;delete value.clientPrivateKeyPem}
  const before=credentialId?one("SELECT * FROM credentials WHERE id=? AND type='azure'",credentialId):null
  if(credentialId&&!before)fail('Azure credential not found',404)
  const key=credentialId||id()
  db.transaction(()=>{
    run("INSERT INTO credentials(id,name,type,username,encrypted_blob,owner_user_id,visibility,team_id,priority) VALUES(?,?,'azure',?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,username=excluded.username,encrypted_blob=excluded.encrypted_blob,visibility=excluded.visibility,team_id=excluded.team_id,priority=excluded.priority",key,value.name,value.clientId||'system-assigned',seal(value),actor,value.visibility,value.teamId||null,value.priority)
    // A queued run must re-test the rotated credential; never persist tokens or secrets in a run snapshot.
    run('UPDATE azure_connections SET revision=revision+1,last_status=NULL,last_error=NULL WHERE credential_id=?',key)
    audit(actor,credentialId?'azure.credential.rotate':'azure.credential.create','credential',key,null,{name:value.name,tenantId:value.tenantId,clientId:value.clientId,authMethod:value.authMethod})
  })()
  return {id:key,name:value.name,type:'azure',tenantId:value.tenantId,clientId:value.clientId,authMethod:value.authMethod}
}
export function azureCredentialMetadata(credentialId){const c=one("SELECT encrypted_blob FROM credentials WHERE id=? AND type='azure'",credentialId);let s={};try{s=openSealed(c.encrypted_blob)}catch{}return {tenantId:s.tenantId,clientId:s.clientId,authMethod:s.authMethod}}
export const connections=()=>all('SELECT * FROM azure_connections ORDER BY name').map(r=>({...parse(r.config_json),id:r.id,revision:r.revision,enabled:!!r.enabled,nextRunAt:r.next_run_at,lastRunAt:r.last_run_at,lastStatus:r.last_status,lastError:r.last_error}))
export function saveConnection(data,actor,connectionId){
  const config=connectionSchema.parse(data),before=connectionId?one('SELECT * FROM azure_connections WHERE id=?',connectionId):null
  if(connectionId&&!before)fail('Azure connection not found',404)
  if(!one("SELECT id FROM credentials WHERE id=? AND type='azure'",config.credentialId))fail('Choose an Azure credential')
  for(const scope of [config.scopeId,...config.networkScopes.map(s=>s.scopeId)])if(!one('SELECT id FROM inventory_scopes WHERE id=?',scope))fail('Inventory scope does not exist')
  config.subscriptions=[...new Set(config.subscriptions.map(v=>v.toLowerCase()))]
  config.resourceGroups=[...new Set(config.resourceGroups)]
  const key=connectionId||id()
  run('INSERT INTO azure_connections(id,name,credential_id,config_json,enabled,interval_minutes,next_run_at,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,credential_id=excluded.credential_id,config_json=excluded.config_json,enabled=excluded.enabled,interval_minutes=excluded.interval_minutes,next_run_at=excluded.next_run_at,revision=azure_connections.revision+1',key,config.name,config.credentialId,JSON.stringify(config),Number(config.enabled),config.intervalMinutes,config.enabled?now():null,now())
  audit(actor,'azure.connection.save','azure-connection',key,before?parse(before.config_json):null,config)
  return connections().find(c=>c.id===key)
}
export function deleteConnection(key,actor){
  if(!one('SELECT id FROM azure_connections WHERE id=?',key))fail('Azure connection not found',404)
  if(one("SELECT id FROM azure_runs WHERE connection_id=? AND status IN ('queued','running')",key))fail('Cancel active runs before deleting the connection',409)
  run('DELETE FROM azure_connections WHERE id=?',key);audit(actor,'azure.connection.delete','azure-connection',key,null,{observationsRetained:true})
}
export function enqueueRun(connectionId,kind,actor=null){
  if(!['test','preview','sync'].includes(kind))fail('Unsupported discovery action')
  return db.transaction(()=>{
    const c=one('SELECT * FROM azure_connections WHERE id=?',connectionId);if(!c)fail('Azure connection not found',404)
    const active=one("SELECT id FROM azure_runs WHERE connection_id=? AND status IN ('queued','running')",connectionId)
    if(active)fail('This connection already has an active run',409)
    const key=id(),config={...parse(c.config_json),id:c.id,revision:c.revision,credentialId:c.credential_id}
    run("INSERT INTO azure_runs(id,connection_id,kind,status,config_json,requested_by,created_at) VALUES(?,?,?,'queued',?,?,?)",key,connectionId,kind,JSON.stringify(config),actor,now())
    audit(actor,'azure.run.queue','azure-run',key,null,{connectionId,kind});return getRun(key)
  }).immediate()
}
export function getRun(key){const r=one('SELECT * FROM azure_runs WHERE id=?',key);if(!r)fail('Azure run not found',404);return {...r,result:parse(r.result_json),result_json:undefined,config_json:undefined,cancel_requested:!!r.cancel_requested}}
export function listRuns(query){const q=pageSchema.parse(query),args=q.connectionId?[q.connectionId]:[],where=q.connectionId?'WHERE connection_id=?':'';return {items:all(`SELECT id FROM azure_runs ${where} ORDER BY created_at DESC,id LIMIT ? OFFSET ?`,...args,q.pageSize,(q.page-1)*q.pageSize).map(r=>getRun(r.id)),total:one(`SELECT COUNT(*) n FROM azure_runs ${where}`,...args).n,page:q.page,pageSize:q.pageSize}}
export function cancelRun(key,actor){const r=getRun(key);if(['queued','running'].includes(r.status))run("UPDATE azure_runs SET cancel_requested=1,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,finished_at=CASE WHEN status='queued' THEN ? ELSE finished_at END WHERE id=?",now(),key);audit(actor,'azure.run.cancel','azure-run',key,null,null);return getRun(key)}
function missingSources(connectionId,runId,result,confirmedMissing=new Set()){
  // Incomplete enumeration never contributes evidence of disappearance. A source needs three
  // complete misses spanning seven days; retirement is an observation state, never a node delete.
  if(!result.complete)return 0
  let changed=0
  for(const s of all("SELECT s.* FROM asset_sources s JOIN asset_source_connections c ON c.source_id=s.id WHERE c.connection_id=? AND c.last_run_id<>? AND s.state NOT IN ('ignored','conflict','retired')",connectionId,runId)){
    const record=parse(s.evidence_json)
    if(!result.scopes.some(v=>v.subscriptionId===record.subscriptionId&&(!v.resourceGroup||v.resourceGroup.toLowerCase()===record.resourceGroup?.toLowerCase())))continue
    const since=s.missing_since||now(),count=s.missing_runs+1,state=count>=3&&Date.now()-Date.parse(since)>=7*86400000&&confirmedMissing.has(s.id)?'retired':'missing'
    // A recent observation through another connection prevents a false disappearance.
    if(one('SELECT 1 FROM asset_source_connections WHERE source_id=? AND connection_id<>? AND last_run_id IN (SELECT id FROM azure_runs WHERE finished_at>?)',s.id,connectionId,s.fetched_at))continue
    run('UPDATE asset_sources SET state=?,missing_since=?,missing_runs=? WHERE id=?',state,since,count,s.id)
    if(state!==s.state){changed++;run('INSERT INTO asset_source_history(source_id,run_id,change,before_json,after_json,at) VALUES(?,?,?,?,?,?)',s.id,runId,state,JSON.stringify({state:s.state}),JSON.stringify({state,completeMisses:count}),now())}
  }
  return changed
}
let busy=false
export async function processAzureWork({clientFactory=azureClient,adapter=discoverAzure,schedule=true}={}){
  if(busy)return;busy=true
  let heartbeat
  try{
    run("UPDATE azure_runs SET status=CASE WHEN cancel_requested=1 THEN 'cancelled' ELSE 'queued' END,lease_until=NULL WHERE status='running' AND lease_until<?",now())
    if(schedule)for(const c of all('SELECT * FROM azure_connections WHERE enabled=1 AND (next_run_at IS NULL OR next_run_at<=?)',now())){
      if(!one("SELECT id FROM azure_runs WHERE connection_id=? AND status IN ('queued','running')",c.id))enqueueRun(c.id,'sync')
      run('UPDATE azure_connections SET next_run_at=? WHERE id=?',new Date(Date.now()+c.interval_minutes*60000).toISOString(),c.id)
    }
    const job=db.transaction(()=>{const j=one("SELECT * FROM azure_runs WHERE status='queued' ORDER BY created_at,id LIMIT 1");if(j)run("UPDATE azure_runs SET status='running',started_at=?,lease_until=? WHERE id=?",now(),lease(),j.id);return j}).immediate()
    if(!job)return
    const controller=new AbortController(),config=parse(job.config_json)
    heartbeat=setInterval(()=>{const r=one('SELECT cancel_requested FROM azure_runs WHERE id=?',job.id);if(r?.cancel_requested)controller.abort();else run('UPDATE azure_runs SET lease_until=? WHERE id=?',lease(),job.id)},1000);heartbeat.unref()
    const deadline=setTimeout(()=>controller.abort(),15*60000);deadline.unref()
    try{
      const connection=one('SELECT * FROM azure_connections WHERE id=?',job.connection_id)
      if(!connection||connection.revision!==config.revision)fail('Connection or credential changed. Start a new run.',409)
      const credential=one("SELECT * FROM credentials WHERE id=? AND type='azure'",config.credentialId)
      if(!credential)fail('Azure credential is unavailable. Select a vault credential.',409)
      const settings=openSealed(credential.encrypted_blob),client=clientFactory(settings,{signal:controller.signal})
      const result=await adapter(config,settings,client,{preflight:job.kind==='test',onProgress:progress=>run('UPDATE azure_runs SET result_json=?,lease_until=? WHERE id=?',JSON.stringify(progress),lease(),job.id)})
      const confirmedMissing=new Set()
      if(job.kind==='sync'&&result.complete){
        const present=new Set(result.records.map(r=>r.resourceId.toLowerCase()))
        for(const s of all('SELECT s.* FROM asset_sources s JOIN asset_source_connections c ON c.source_id=s.id WHERE c.connection_id=? AND s.missing_runs>=2 AND s.missing_since<?',job.connection_id,new Date(Date.now()-7*86400000).toISOString())){
          if(present.has(s.resource_id))continue
          // Resource-group/tag filtering can hide a still-existing resource. Confirm a provider
          // 404 before retirement; lack of Reader access is never evidence of deletion.
          try{await client.request(s.resource_id+'?api-version='+(s.provider==='azure-arc'?'2025-01-13':'2024-07-01'))}
          catch(error){if(error.code==='resource_unavailable')confirmedMissing.add(s.id);else if(error.code==='cancelled')throw error}
        }
      }
      if(controller.signal.aborted||one('SELECT cancel_requested FROM azure_runs WHERE id=?',job.id)?.cancel_requested)throw new AzureError('cancelled','Discovery cancelled',409)
      if(one('SELECT revision FROM azure_connections WHERE id=?',job.connection_id)?.revision!==config.revision)fail('Connection changed during discovery. Start a new run.',409)
      const outcome={...result,records:result.records.length,preview:job.kind==='preview'?result.records.slice(0,250).map(r=>({...r,scopeId:sourceScope(r,config),eligible:eligibleSource(r,sourceScope(r,config))})):undefined,previewLimit:250,diff:{new:0,changed:0,unchanged:0,missing:0,conflict:0}}
      db.transaction(()=>{
        if(job.kind==='sync'){
          for(const record of result.records){const change=reconcileRecord(record,config,job.id,job.requested_by);outcome.diff[change.change]++;if(change.state==='conflict')outcome.diff.conflict++}
          outcome.diff.missing=missingSources(job.connection_id,job.id,result,confirmedMissing)
        }
        const status=result.complete?'completed':'partial'
        run('UPDATE azure_runs SET status=?,result_json=?,finished_at=?,lease_until=NULL WHERE id=?',status,JSON.stringify(outcome),now(),job.id)
        run('UPDATE azure_connections SET last_run_at=?,last_status=?,last_error=NULL WHERE id=?',now(),status,job.connection_id)
        audit(job.requested_by,'azure.run.finish','azure-run',job.id,null,{status,records:outcome.records,diff:outcome.diff})
      })()
    }catch(error){
      const cancelled=controller.signal.aborted||one('SELECT cancel_requested FROM azure_runs WHERE id=?',job.id)?.cancel_requested
      const message=error instanceof AzureError||[400,404,409].includes(error.status)?error.message:'Azure discovery failed. Check server configuration and connection permissions.'
      run('UPDATE azure_runs SET status=?,error=?,finished_at=?,lease_until=NULL WHERE id=?',cancelled?'cancelled':'failed',message,now(),job.id)
      run('UPDATE azure_connections SET last_run_at=?,last_status=?,last_error=? WHERE id=?',now(),cancelled?'cancelled':'failed',message,job.connection_id)
      audit(job.requested_by,'azure.run.failed','azure-run',job.id,null,{code:error.code||'discovery_failed',cancelled})
    }finally{clearTimeout(deadline)}
    return getRun(job.id)
  }finally{clearInterval(heartbeat);busy=false}
}
