import {findRuleConflicts} from '../../../packages/shared/index.js'
import {z} from 'zod'
import {db,all,one,run,id,now,json,audit} from '../db.js'
import {remote,tcpProbe} from '../connector.js'
import {assertManagementAccess} from '../managementGuard.js'
import {canReadResource,canWriteResource} from '../access.js'
import {simulation,targetsHash} from './policySimulation.js'
import {nodeCoverage} from './capabilities.js'
import {emitNotification} from '../notifications.js'
const fail=(message,status=400)=>{throw Object.assign(new Error(message),{status})},parse=v=>JSON.parse(v||'null')
export const stagedDeploymentSchema=z.object({simulationId:z.string().min(1),canaryNodeIds:z.array(z.string()).min(1).max(10),batchSize:z.number().int().min(1).max(10).default(2),recoverySeconds:z.number().int().min(300).max(3600).default(600),healthPorts:z.array(z.number().int().min(1).max(65535)).min(1).max(16),maxFailures:z.number().int().min(0).max(100).default(0),windowStart:z.string().datetime({offset:true}),windowEnd:z.string().datetime({offset:true}),reason:z.string().trim().min(1).max(2000)}).strict()
const active="('queued','running','paused','partial','cancelling','restoring')"
function access(jobId,user,write=false){const j=one('SELECT * FROM policy_deployment_jobs WHERE id=?',jobId);if(!j)fail('Deployment not found',404);const p=one('SELECT * FROM policies WHERE id=?',j.policy_id);if(!(write?canWriteResource:canReadResource)(user,'policy',p))fail('Insufficient policy permission',403);return j}
export function deployment(jobId,user){const j=access(jobId,user);return {...j,config:parse(j.config_json),config_json:undefined,targets:all('SELECT * FROM policy_deployment_targets WHERE job_id=? ORDER BY batch,node_id',j.id).map(t=>({...t,snapshot:parse(t.snapshot_json),health:parse(t.health_json),snapshot_json:undefined,health_json:undefined}))}}
export function listDeployments(policyId,user){const p=one('SELECT * FROM policies WHERE id=?',policyId);if(!p||!canReadResource(user,'policy',p))fail('Policy not found',404);return all('SELECT id FROM policy_deployment_jobs WHERE policy_id=? ORDER BY created_at DESC LIMIT 100',policyId).map(j=>deployment(j.id,user))}
const supported=n=>n.connection_mode!=='agent'&&['winrm','winrms'].includes(n.transport)&&!/^(?:5\.|6\.[01]\.)/.test(n.os_version||'')
function pilotAllowed(nodeId){return String(process.env.WINFIRE_POLICY_SAFETY_PILOT_NODES||'').split(',').map(v=>v.trim()).includes(nodeId)}
export function deploymentPreview(input,user){
 const q=stagedDeploymentSchema.parse(input),s=simulation(q.simulationId,user);if(!s.approvalValid||s.status!=='completed')fail('A completed, current, reviewed simulation is required',409)
 const p=one('SELECT * FROM policies WHERE id=?',s.policy_id);if(!canWriteResource(user,'policy',p))fail('Insufficient policy permission',403)
 if(Date.parse(q.windowEnd)<=Date.parse(q.windowStart)||Date.parse(q.windowEnd)<=Date.now()||Date.parse(q.windowEnd)-Date.parse(q.windowStart)>86400000)fail('Choose a future deployment window no longer than 24 hours')
 const targets=s.snapshot.nodeIds.map(nodeId=>one('SELECT * FROM nodes WHERE id=?',nodeId));if(targets.some(n=>!n))fail('A target no longer exists',409)
 const canaries=[...new Set(q.canaryNodeIds)];if(q.recoverySeconds<Math.max(canaries.length,q.batchSize)*(160+q.healthPorts.length*8))fail('Increase the recovery window or reduce batch/canary size to cover bounded health and management timeouts');if(canaries.some(n=>!s.snapshot.nodeIds.includes(n)))fail('Every canary must be in the evaluated target set')
 const assigned=all('SELECT DISTINCT n.id FROM nodes n JOIN policy_assignments a ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id) WHERE a.policy_id=? ORDER BY n.id',p.id).map(n=>n.id)
 if(json(assigned)!==json([...s.snapshot.nodeIds].sort()))fail('Evaluate the complete assigned target set before staging; this prevents implicit rollout to unevaluated group members',409)
 assertManagementAccess(s.snapshot.rules)
 for(const node of targets){const policies=all('SELECT DISTINCT p.* FROM policies p JOIN policy_assignments a ON a.policy_id=p.id WHERE p.id<>? AND (a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?))',p.id,node.id,node.id);for(const other of policies){const rules=parse(one('SELECT rules_compiled_json FROM policy_versions WHERE id=?',other.current_version_id)?.rules_compiled_json)||[];if(findRuleConflicts(s.snapshot.rules,rules).length)fail('The staged draft conflicts with another assigned policy on '+node.hostname,409)}}
 const retirementExceptions=all("SELECT id,rule_id,owner,status FROM rule_exceptions WHERE policy_id=? AND version_id=? AND (status='retirement-requested' OR status='active' AND expires_at<=?)",p.id,p.current_version_id,now()).filter(e=>!s.snapshot.graph.nodes.some(n=>n.id===e.rule_id))
 const unsupportedRules=s.snapshot.rules.some(r=>r.localUserSid||r.schedule)||s.snapshot.graph.nodes.some(n=>n.type==='mfaGate')
 const later=targets.filter(n=>!canaries.includes(n.id)),batches=[canaries,...Array.from({length:Math.ceil(later.length/q.batchSize)},(_,i)=>later.slice(i*q.batchSize,(i+1)*q.batchSize).map(n=>n.id))]
 return {retirementExceptions,simulationId:s.id,policyId:p.id,baseVersionId:p.current_version_id,targetHash:targetsHash(s.snapshot.nodeIds),batches,targets:targets.map(n=>({nodeId:n.id,hostname:n.hostname,transport:n.transport,coverage:nodeCoverage(n),supported:supported(n)&&!unsupportedRules,pilotEnabled:pilotAllowed(n.id),reason:unsupportedRules?'Identity/schedule/MFA rules require another recovery adapter':!supported(n)?'Native recovery is currently available for modern agentless Windows WinRM only':!pilotAllowed(n.id)?'Controlled host pilot authorization is required before this recovery adapter is enabled':null})),productionEnabled:false,config:q}
}
export function queueDeployment(input,user){
 const preview=deploymentPreview(input,user);if(preview.targets.some(n=>!n.supported||!n.pilotEnabled))fail('This rollout is blocked: select validated recovery transports and explicitly authorized pilot nodes',409)
 return db.transaction(()=>{
  for(const node of preview.targets)if(one("SELECT t.job_id FROM containment_targets t JOIN containment_jobs j ON j.id=t.job_id WHERE t.node_id=? AND j.status<>'restored'",node.nodeId))fail('Restore containment before staging policy changes',409)
  const s=simulation(preview.simulationId,user),key=id(),versionId=id(),stamp=now()
  if(one(`SELECT id FROM policy_deployment_jobs WHERE policy_id=? AND status IN ${active}`,preview.policyId))fail('This policy already has an active staged deployment',409)
  for(const node of preview.targets)if(one(`SELECT t.job_id FROM policy_deployment_targets t JOIN policy_deployment_jobs j ON j.id=t.job_id WHERE t.node_id=? AND j.status IN ${active}`,node.nodeId))fail('A target already belongs to another active deployment',409)
  const versionNo=one('SELECT COALESCE(MAX(version_no),0)+1 n FROM policy_versions WHERE policy_id=?',preview.policyId).n
  run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,preview.policyId,versionNo,json(s.snapshot.graph),json(s.snapshot.rules),user.id,'Staged candidate: '+preview.config.reason)
  run('INSERT INTO policy_deployment_jobs(id,policy_id,version_id,simulation_id,target_hash,config_json,status,requested_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)',key,preview.policyId,versionId,s.id,preview.targetHash,json({...preview.config,baseVersionId:preview.baseVersionId,batches:preview.batches,rules:s.snapshot.rules,retirementExceptionIds:preview.retirementExceptions.map(e=>e.id)}),'queued',user.id,stamp,stamp)
  for(const [batch,nodeIds] of preview.batches.entries())for(const nodeId of nodeIds)run('INSERT INTO policy_deployment_targets(job_id,node_id,transaction_id,batch,updated_at) VALUES(?,?,?,?,?)',key,nodeId,id(),batch,stamp)
  for(const e of preview.retirementExceptions)run("UPDATE rule_exceptions SET status='retiring',retirement_version_id=?,updated_at=? WHERE id=?",versionId,stamp,e.id)
  audit(user.id,'policy.deployment.queue','policy-deployment',key,null,{...preview.config,versionId,batches:preview.batches});return deployment(key,user)
 }).immediate()
}
export function deploymentAction(key,action,reason,user){
 const j=access(key,user,true);if(typeof reason!=='string'||!reason.trim()||reason.length>2000)fail('A reason up to 2000 characters is required')
 if(action==='resume'){
  if(!['paused','partial'].includes(j.status))fail('Only paused or partial deployments can resume',409)
  const targets=all('SELECT * FROM policy_deployment_targets WHERE job_id=?',key),s=simulation(j.simulation_id,user)
  if(!s.approvalValid||j.target_hash!==targetsHash(s.snapshot.nodeIds))fail('Policy, approval or targets changed; create a fresh evaluation',409)
  if(targets.some(t=>['armed','applied','unknown','restore-failed'].includes(t.status)))fail('Restore unresolved host transactions before retrying',409)
  if(Date.parse(parse(j.config_json).windowEnd)<=Date.now())fail('The deployment window expired; restore this job and create a fresh plan',409)
  db.transaction(()=>{for(const t of targets.filter(t=>t.status!=='committed'))run("UPDATE policy_deployment_targets SET transaction_id=?,status='pending',snapshot_json=NULL,health_json=NULL,error=NULL,updated_at=? WHERE job_id=? AND node_id=?",id(),now(),key,t.node_id);run("UPDATE policy_deployment_jobs SET status='queued',next_batch=?,error=NULL,lease_until=NULL,updated_at=? WHERE id=?",targets.some(t=>t.status!=='committed')?Math.min(...targets.filter(t=>t.status!=='committed').map(t=>t.batch)):j.next_batch,now(),key)})()
 }else if(action==='cancel'||action==='restore'){
  if(['restored','cancelled'].includes(j.status))return deployment(key,user)
  if(j.status==='completed'&&one('SELECT current_version_id FROM policies WHERE id=?',j.policy_id)?.current_version_id!==j.version_id)fail('A newer approved policy version exists; evaluate a separate rollback draft instead',409)
  run("UPDATE policy_deployment_jobs SET status='cancelling',updated_at=? WHERE id=?",now(),key)
 }else fail('Unsupported deployment action')
 audit(user.id,'policy.deployment.'+action,'policy-deployment',key,{status:j.status},{reason});return deployment(key,user)
}
const defaultDriver={
 async health(node,ports){await remote(node,'auth');const results=[];for(const port of [...new Set([node.transport==='winrms'?5986:5985,...ports])]){const result=await tcpProbe(node.ip||node.fqdn,port,4000);results.push({port,status:result.status,vantage:'api-server'})}if(results.some(r=>r.status!=='open'))throw new Error('Independent management/application TCP health check failed');return {authenticated:true,checks:results,checkedAt:now()}},
 async arm(node,args){return remote(node,'safety_arm',args)},async apply(node,args){return remote(node,'safety_apply',args)},async status(node,args){return remote(node,'safety_status',args)},async commit(node,args){return remote(node,'safety_commit',args)},async restore(node,args){return remote(node,'safety_restore',{...args,manual:true})}
}
let processing=false
export async function processDeployments({driver=defaultDriver,at=Date.now()}={}){
 if(processing)return;processing=true
 try{
  const stamp=new Date(at).toISOString(),j=one("SELECT * FROM policy_deployment_jobs WHERE status IN ('queued','running','cancelling','restoring') AND (lease_until IS NULL OR lease_until<=?) ORDER BY created_at LIMIT 1",stamp);if(!j)return
  const claimed=run("UPDATE policy_deployment_jobs SET lease_until=?,updated_at=? WHERE id=? AND (lease_until IS NULL OR lease_until<=?)",new Date(at+600000).toISOString(),stamp,j.id,stamp);if(!claimed.changes)return
  const config=parse(j.config_json),targets=all('SELECT * FROM policy_deployment_targets WHERE job_id=? ORDER BY batch,node_id',j.id)
  const update=(t,status,{snapshot,health,error=null}={})=>{run('UPDATE policy_deployment_targets SET status=?,snapshot_json=COALESCE(?,snapshot_json),health_json=COALESCE(?,health_json),error=?,updated_at=? WHERE job_id=? AND node_id=?',status,snapshot?json(snapshot):null,health?json(health):null,error,now(),j.id,t.node_id);t.status=status}
  const cancelled=()=>['cancelling','restoring'].includes(one('SELECT status FROM policy_deployment_jobs WHERE id=?',j.id)?.status)
  const restore=async t=>{try{const n=one('SELECT * FROM nodes WHERE id=?',t.node_id);if(!n)throw new Error('Target no longer exists');const snapshot=await driver.restore(n,{id:t.transaction_id});if(snapshot.phase!=='restored')throw new Error('Host recovery did not confirm restoration');update(t,'restored',{snapshot});audit(j.requested_by,'policy.deployment.node-restored','node',n.id,null,{jobId:j.id,transactionId:t.transaction_id})}catch(error){update(t,'restore-failed',{error:error.message})}}
  if(cancelled()){
   for(const t of targets)if(!['pending','restored','failed'].includes(t.status))await restore(t)
   const failed=one("SELECT node_id FROM policy_deployment_targets WHERE job_id=? AND status='restore-failed'",j.id)
   if(!failed)for(const key of config.retirementExceptionIds||[])run("UPDATE rule_exceptions SET status='retirement-requested',retirement_version_id=NULL,updated_at=? WHERE id=? AND retirement_version_id=?",now(),key,j.version_id)
   if(!failed)run('UPDATE policies SET current_version_id=? WHERE id=? AND current_version_id=?',config.baseVersionId,j.policy_id,j.version_id)
   run('UPDATE policy_deployment_jobs SET status=?,lease_until=NULL,error=?,updated_at=? WHERE id=?',failed?'paused':'restored',failed?'Some hosts could not confirm restoration':null,now(),j.id);return
  }
  if(at<Date.parse(config.windowStart)){run('UPDATE policy_deployment_jobs SET lease_until=NULL WHERE id=?',j.id);return}
  if(at>=Date.parse(config.windowEnd)||j.target_hash!==targetsHash(targets.map(t=>t.node_id).sort())){run("UPDATE policy_deployment_jobs SET status='paused',error=?,lease_until=NULL,updated_at=? WHERE id=?",at>=Date.parse(config.windowEnd)?'Deployment window expired':'Policy or target context changed',now(),j.id);return}
  run("UPDATE policy_deployment_jobs SET status='running',updated_at=? WHERE id=?",now(),j.id)
  const batch=targets.filter(t=>t.batch===j.next_batch&&t.status!=='committed')
  let failure=null
  for(const t of batch){
   if(cancelled())break
   const node=one('SELECT * FROM nodes WHERE id=?',t.node_id),args={id:t.transaction_id,policyId:j.policy_id,seconds:config.recoverySeconds}
   try{
    if(t.status==='pending'){
     await driver.health(node,config.healthPorts);if(cancelled())break
     // Record intent before the remote call: a lost reply must still be recovered.
     update(t,'unknown');const armed=await driver.arm(node,args);if(!armed.nativeRecovery||armed.phase!=='armed')throw new Error('Native recovery was not armed');update(t,'armed',{snapshot:armed})
    }else{const state=await driver.status(node,{id:t.transaction_id});if(state.phase==='restored'){update(t,'restored',{snapshot:state});throw new Error('Host recovery already restored this transaction; review before retrying')}if(state.phase==='committed'){update(t,'committed',{snapshot:state});continue}if(state.phase==='applied')update(t,'applied',{snapshot:state});else if(state.phase!=='armed')throw new Error('Host transaction is not safe to resume')}
    if(cancelled())break
    if(t.status!=='applied'){const applied=await driver.apply(node,{...args,rules:config.rules});if(applied.phase!=='applied')throw new Error('Host did not confirm candidate readback');update(t,'applied',{snapshot:applied})}
    const health=await driver.health(node,config.healthPorts);update(t,'applied',{health})
   }catch(error){if(!['pending','restored'].includes(t.status))await restore(t);else update(t,'failed',{error:error.message});run('UPDATE policy_deployment_targets SET error=? WHERE job_id=? AND node_id=?',error.message,j.id,t.node_id);const failures=one("SELECT COUNT(*) n FROM policy_deployment_targets WHERE job_id=? AND error IS NOT NULL AND status IN ('failed','restored','restore-failed')",j.id).n;if(j.next_batch===0||failures>(config.maxFailures||0)||t.status==='restore-failed'){failure=error.message;break}}
  }
  if(cancelled()){run('UPDATE policy_deployment_jobs SET lease_until=NULL WHERE id=?',j.id);return}
  if(failure){for(const t of batch.filter(t=>['armed','applied','unknown'].includes(t.status)))await restore(t);run("UPDATE policy_deployment_jobs SET status='paused',error=?,lease_until=NULL,updated_at=? WHERE id=?",failure,now(),j.id);emitNotification({eventKey:`staged-pause:${j.id}:${j.next_batch}`,category:'security_policy',title:'Staged deployment paused',body:failure,entityType:'policy',entityId:j.policy_id});return}
  if(j.target_hash!==targetsHash(targets.map(t=>t.node_id).sort())){for(const t of batch.filter(t=>['armed','applied','unknown'].includes(t.status)))await restore(t);run("UPDATE policy_deployment_jobs SET status='paused',error='Policy or targets changed during health checks',lease_until=NULL,updated_at=? WHERE id=?",now(),j.id);return}
  for(const t of batch.filter(t=>t.status==='applied')){
   if(cancelled())break
   try{const state=await driver.commit(one('SELECT * FROM nodes WHERE id=?',t.node_id),{id:t.transaction_id});if(state.phase!=='committed')throw new Error('Commit not confirmed');update(t,'committed',{snapshot:state});run('INSERT OR REPLACE INTO policy_apply_runs(id,policy_id,version_id,node_id,status,finished_at,diff_json) VALUES(?,?,?,?,?,?,?)',t.transaction_id,j.policy_id,j.version_id,t.node_id,'success',now(),json({stagedJobId:j.id,nativeRecovery:true,health:parse(one('SELECT health_json FROM policy_deployment_targets WHERE job_id=? AND node_id=?',j.id,t.node_id).health_json)}));audit(j.requested_by,'policy.deployment.node-commit','node',t.node_id,null,{jobId:j.id,versionId:j.version_id})}
   catch(error){run("UPDATE policy_deployment_jobs SET status='paused',error=?,lease_until=NULL,updated_at=? WHERE id=?",'Commit outcome requires readback: '+error.message,now(),j.id);return}
  }
  if(cancelled()){run('UPDATE policy_deployment_jobs SET lease_until=NULL WHERE id=?',j.id);return}
  const remaining=one("SELECT COUNT(*) n FROM policy_deployment_targets WHERE job_id=? AND status<>'committed'",j.id).n
  if(!remaining){
   db.transaction(()=>{if(j.target_hash!==targetsHash(targets.map(t=>t.node_id).sort())){run("UPDATE policy_deployment_jobs SET status='paused',error='Targets changed before publication',lease_until=NULL WHERE id=?",j.id);return}const published=run('UPDATE policies SET current_version_id=? WHERE id=? AND current_version_id IS ?',j.version_id,j.policy_id,config.baseVersionId);if(!published.changes)throw new Error('A newer approved version prevents publication');run("UPDATE policy_deployment_jobs SET status='completed',lease_until=NULL,updated_at=? WHERE id=?",now(),j.id);for(const key of config.retirementExceptionIds||[])run("UPDATE rule_exceptions SET status='retired',updated_at=? WHERE id=? AND retirement_version_id=?",now(),key,j.version_id);audit(j.requested_by,'policy.deployment.complete','policy',j.policy_id,{versionId:config.baseVersionId},{versionId:j.version_id,jobId:j.id})})();return
  }
  if(j.next_batch>=config.batches.length-1){run("UPDATE policy_deployment_jobs SET status='partial',error='Some targets failed and were restored; resume or restore the rollout after review',lease_until=NULL,updated_at=? WHERE id=?",now(),j.id);return}
  run("UPDATE policy_deployment_jobs SET status='queued',next_batch=next_batch+1,lease_until=NULL,updated_at=? WHERE id=?",now(),j.id)
 }finally{processing=false}
}
