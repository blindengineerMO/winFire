import express from 'express'
import crypto from 'node:crypto'
import {rateLimit} from 'express-rate-limit'
import {z} from 'zod'
import {db,one,all,run,id,now,audit,json,parse} from '../db.js'
import {hashToken} from '../security.js'
import {agentPkiReady,signAgentCsr} from '../agentPki.js'
import {normalizeWindowsEvent} from '../eventNormalizer.js'
import {isLoopbackEvent} from '../eventPattern.js'
import {diffRules} from '../connector.js'
import {emitNotification} from '../notifications.js'
import {normalizeProfileSnapshot} from '../breakGlass.js'
import {effectiveAgentPollSeconds,effectiveAgentChannelMode} from '../agentPoll.js'
import {isExcludedFirewallEvent} from '../processExclusions.js'
import {isIgnoredFirewallEvent} from '../trafficIgnores.js'
import {getAgentUpdateManifest,getAgentUpdatePackagePath} from '../agentUpdate.js'
import {recordNetworkFlow,recordArpEntries} from '../services/networkMapping.js'
import {asyncHandler} from '../middleware/asyncHandler.js'

export const agentRoutes=express.Router()
const wrap=asyncHandler
const normalizeLogAction=(eventId,action)=>Number(eventId)===4624?'logon':Number(eventId)===4634?'logoff':action||null
const enrollLimit=rateLimit({windowMs:15*60*1000,limit:20,standardHeaders:'draft-8',legacyHeaders:false})
const readRuleSchema=z.array(z.object({name:z.string(),action:z.string(),direction:z.string(),protocol:z.string(),localPort:z.string(),remotePort:z.string(),remoteAddress:z.string(),program:z.string(),profile:z.string()})).max(1000)

function requireAgent(req,res,next) {
  if(!req.socket.encrypted||!req.socket.authorized)return res.status(401).json({error:'Trusted client certificate required'})
  const peer=req.socket.getPeerCertificate()
  const fingerprint=peer?.fingerprint256?.replaceAll(':','').toUpperCase()
  if(!fingerprint)return res.status(401).json({error:'Client certificate required'})
  const agent=one('SELECT * FROM agents WHERE id=? AND cert_thumbprint=? AND revoked_at IS NULL',req.params.id,fingerprint)
  if(!agent||!agent.cert_expires_at||agent.cert_expires_at<=now())return res.status(401).json({error:'Agent certificate revoked or expired'})
  req.agent=agent
  next()
}

function claimPushJobs(agentId){
  const leaseUntil=new Date(Date.now()+60_000).toISOString()
  return db.transaction(()=>all("SELECT * FROM agent_jobs WHERE agent_id=? AND ((status='queued') OR (status='leased' AND lease_until<?)) AND attempt_count<5 ORDER BY created_at LIMIT 10",agentId,now()).map(job=>{
    const leaseToken=crypto.randomBytes(24).toString('base64url')
    run("UPDATE agent_jobs SET status='leased',lease_until=?,lease_token=?,attempt_count=attempt_count+1 WHERE id=? AND ((status='queued') OR (status='leased' AND lease_until<?))",leaseUntil,leaseToken,job.id,now())
    return {id:job.id,type:job.type,payload:parse(job.payload_json),attempt:job.attempt_count+1,leaseToken}
  }))()
}

agentRoutes.post('/enroll',enrollLimit,wrap(async(req,res)=>{
  if(!req.socket.encrypted||!agentPkiReady())return res.status(503).json({error:'Agent enrollment requires configured HTTPS and PKI'})
  const {token,csr}=z.object({token:z.string().min(32),csr:z.string().min(100).max(12000)}).parse(req.body)
  const enrollment=one('SELECT * FROM enrollment_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?',hashToken(token),now())
  if(!enrollment)return res.status(401).json({error:'Invalid or expired enrollment token'})
  if(one('SELECT id FROM agents WHERE node_id=?',enrollment.node_id))return res.status(409).json({error:'Node already has an agent; use certificate renewal'})
  const signed=await signAgentCsr(csr,enrollment.node_id),agentId=id()
  db.transaction(()=>{
    const used=run('UPDATE enrollment_tokens SET used_at=? WHERE id=? AND used_at IS NULL',now(),enrollment.id)
    if(used.changes!==1)throw Object.assign(new Error('Enrollment token already used'),{status:409})
    run('INSERT INTO agents(id,node_id,cert_thumbprint,cert_expires_at,version,mode,last_checkin_at) VALUES(?,?,?,?,?,?,?)',agentId,enrollment.node_id,signed.fingerprint,signed.expiresAt,'enrolling','pull',now())
    run("UPDATE nodes SET agent_id=?,connection_mode='agent',status='reachable',last_seen_at=? WHERE id=?",agentId,now(),enrollment.node_id)
    audit(null,'agent.enroll','agent',agentId,null,{nodeId:enrollment.node_id,expiresAt:signed.expiresAt})
  })()
  res.status(201).json({agentId,nodeId:enrollment.node_id,certificate:signed.certificate,caCertificate:signed.caCertificate,expiresAt:signed.expiresAt})
}))

agentRoutes.post('/:id/heartbeat',requireAgent,(req,res)=>{
  const {version,platform,osVersion,firewallBackend,capabilities}=z.object({version:z.string().trim().min(1).max(100),mode:z.enum(['pull','push']).default('pull'),platform:z.string().trim().max(80).optional(),osVersion:z.string().trim().max(200).optional(),firewallBackend:z.string().trim().max(80).optional(),capabilities:z.array(z.string().trim().max(80)).max(100).optional()}).parse(req.body)
  const channelMode=effectiveAgentChannelMode(req.agent.node_id)
  const previous=one('SELECT status FROM nodes WHERE id=?',req.agent.node_id)?.status
  run('UPDATE agents SET version=?,mode=?,last_checkin_at=? WHERE id=?',version,channelMode,now(),req.agent.id)
  run("UPDATE nodes SET status='reachable',last_seen_at=?,failures=0,platform=COALESCE(?,platform),os_version=COALESCE(?,os_version),firewall_backend=COALESCE(?,firewall_backend),agent_required=0 WHERE id=?",now(),platform||null,osVersion||null,firewallBackend||null,req.agent.node_id)
  if(platform||osVersion||firewallBackend||capabilities)run('UPDATE agents SET capabilities_json=? WHERE id=?',json({platform:platform||null,osVersion:osVersion||null,firewallBackend:firewallBackend||null,capabilities:capabilities||[]}),req.agent.id)
  if(previous==='unreachable')audit(null,'agent.online','node',req.agent.node_id,null,{agentId:req.agent.id})
  let update={available:false}
  try {
    update=getAgentUpdateManifest(version,`${req.protocol}://${req.get('host')}/api/v1/agents/${req.agent.id}/update/package`)
  } catch (error) {
    // A missing package or signer pin must never make an otherwise healthy
    // agent appear offline. It simply disables self-update advertisement.
    update={available:false,error:error.message}
  }
  res.json({ok:true,serverTime:now(),pollSeconds:effectiveAgentPollSeconds(req.agent.node_id),channelMode,pushUrl:channelMode==='push'?`api/v1/agents/${req.agent.id}/stream`:null,update})
})

// Push mode uses a mutually authenticated, long-lived HTTP stream so the
// control plane can deliver a queued job as soon as it is created. Keeping it
// HTTP rather than adding a second listener preserves single-port deployment.
agentRoutes.get('/:id/stream',requireAgent,(req,res)=>{
  if(effectiveAgentChannelMode(req.agent.node_id)!=='push')return res.status(409).json({error:'Push channel is not enabled for this agent'})
  res.status(200).set({'Cache-Control':'no-store','Content-Type':'text/event-stream','Connection':'keep-alive','X-Accel-Buffering':'no'});res.flushHeaders?.()
  let closed=false
  const send=()=>{
    if(closed)return
    for(const job of claimPushJobs(req.agent.id))res.write(`event: job\ndata: ${JSON.stringify(job)}\n\n`)
    run('UPDATE agents SET last_checkin_at=? WHERE id=?',now(),req.agent.id)
    res.write(`event: ping\ndata: ${JSON.stringify({serverTime:now()})}\n\n`)
  }
  const timer=setInterval(send,1000);timer.unref?.();send()
  const close=()=>{if(closed)return;closed=true;clearInterval(timer);res.end()}
  req.on('aborted',close);req.on('close',()=>{clearInterval(timer);closed=true})
})

agentRoutes.get('/:id/update',requireAgent,(req,res)=>{
  try {
    const manifest=getAgentUpdateManifest(String(req.query.version || ''),`${req.protocol}://${req.get('host')}/api/v1/agents/${req.agent.id}/update/package`)
    res.set('Cache-Control','no-store').json(manifest)
  } catch (error) { res.status(503).json({error:error.message}) }
})

agentRoutes.get('/:id/update/package',requireAgent,(req,res)=>{
  try {
    const packagePath=getAgentUpdatePackagePath()
    if(!packagePath)return res.status(503).json({error:'Signed agent update package is not configured'})
    res.set('Cache-Control','private, no-store').type('application/octet-stream').sendFile(packagePath)
  } catch (error) { res.status(503).json({error:error.message}) }
})

agentRoutes.post('/:id/events',requireAgent,(req,res)=>{
  const event=z.object({recordId:z.number().int().positive(),id:z.number().int().positive(),timeCreated:z.string().datetime({offset:true}),fields:z.record(z.string(),z.string()).default({})})
  const {events}=z.object({events:z.array(event).min(1).max(500)}).parse(req.body)
  const ignoreLoopback=one("SELECT value FROM app_settings WHERE key='ignore_loopback_ingest'")?.value==='true'
  let inserted=0,excluded=0
  db.transaction(()=>{
    for(const raw of events){
      const item=normalizeWindowsEvent(raw)
      if(ignoreLoopback&&isLoopbackEvent(item))continue
      if(isExcludedFirewallEvent(item)||isIgnoredFirewallEvent(item)){excluded++;continue}
      const result=run('INSERT OR IGNORE INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,src_port,dst_ip,dst_port,direction,program,process_id,account_sid,event_time,event_type,logon_type,filter_origin,filter_runtime_id,logon_status,logon_sub_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',id(),req.agent.node_id,item.recordId,item.eventId,normalizeLogAction(item.eventId,item.action),item.protocol,item.srcIp,item.srcPort,item.dstIp,item.dstPort,item.direction,item.program,item.processId,item.accountSid,item.eventTime,item.eventType,item.logonType,item.filterOrigin,item.filterRuntimeId,item.logonStatus,item.logonSubStatus)
      inserted+=result.changes
      if(result.changes && item.eventType==='firewall')recordNetworkFlow(req.agent.node_id,item)
      if(!result.changes&&item.filterOrigin)run('UPDATE log_events SET filter_origin=COALESCE(filter_origin,?),filter_runtime_id=COALESCE(filter_runtime_id,?) WHERE node_id=? AND record_id=? AND filter_origin IS NULL',item.filterOrigin,item.filterRuntimeId,req.agent.node_id,item.recordId)
      if(!result.changes&&item.eventType==='firewall'&&item.direction==='in')run('UPDATE log_events SET src_ip=?,src_port=?,dst_ip=?,dst_port=? WHERE node_id=? AND record_id=? AND pattern_id IS NULL AND (src_ip IS NOT ? OR src_port IS NOT ? OR dst_ip IS NOT ? OR dst_port IS NOT ?)',item.srcIp,item.srcPort,item.dstIp,item.dstPort,req.agent.node_id,item.recordId,item.srcIp,item.srcPort,item.dstIp,item.dstPort)
    }
    run('UPDATE agents SET last_checkin_at=? WHERE id=?',now(),req.agent.id)
    run("UPDATE nodes SET status='reachable',last_seen_at=?,failures=0 WHERE id=?",now(),req.agent.node_id)
    audit(null,'agent.events.ingest','node',req.agent.node_id,null,{agentId:req.agent.id,received:events.length,inserted,excluded,lastRecordId:events.at(-1).recordId})
  })()
  res.status(201).json({received:events.length,inserted,excluded,lastRecordId:events.at(-1).recordId})
})

agentRoutes.post('/:id/network',requireAgent,(req,res)=>{
  const data=z.object({flows:z.array(z.object({srcIp:z.string().max(64).optional(),dstIp:z.string().max(64).optional(),srcPort:z.number().int().min(0).max(65535).optional(),dstPort:z.number().int().min(0).max(65535).optional(),protocol:z.string().max(20).optional(),direction:z.string().max(12).optional(),program:z.string().max(512).optional(),eventType:z.string().max(30).optional(),eventTime:z.string().max(80).optional()})).max(2000).default([]),arp:z.array(z.object({ip:z.string().max(64),mac:z.string().max(80).optional(),hostname:z.string().max(255).optional(),interface:z.string().max(128).optional(),state:z.string().max(40).optional(),observedAt:z.string().max(80).optional()})).max(5000).default([])}).parse(req.body)
  let mapped=0
  for(const flow of data.flows)if(recordNetworkFlow(req.agent.node_id,{...flow,eventType:'firewall'}))mapped++
  const arp=recordArpEntries(req.agent.node_id,data.arp,'agent')
  run('UPDATE agents SET last_checkin_at=? WHERE id=?',now(),req.agent.id)
  res.status(201).json({received:data.flows.length+data.arp.length,mapped,arp})
})

agentRoutes.get('/:id/jobs',requireAgent,(req,res)=>{
  if(effectiveAgentChannelMode(req.agent.node_id)==='push')return res.status(409).json({error:'Push channel is enabled for this agent; connect to the stream endpoint'})
  const leaseUntil=new Date(Date.now()+60_000).toISOString()
  const jobs=db.transaction(()=>{
    const abandoned=all("SELECT * FROM agent_jobs WHERE agent_id=? AND status='leased' AND lease_until<? AND attempt_count>=5",req.agent.id,now())
    for(const job of abandoned){
      run("UPDATE agent_jobs SET status='failed',error='Job lease expired after five attempts',finished_at=?,lease_token=NULL WHERE id=?",now(),job.id)
      const payload=parse(job.payload_json)||{}
      if(payload.applyRunId)run("UPDATE policy_apply_runs SET status='failed',error='Agent did not complete job after five attempts',finished_at=? WHERE id=?",now(),payload.applyRunId)
      if(payload.loopbackBaseline)run("UPDATE node_loopback_baseline SET status='failed',last_error='Agent did not complete loopback baseline job',job_id=NULL WHERE node_id=? AND job_id=?",req.agent.node_id,job.id)
      if(payload.removalAssignmentId){
        run('UPDATE policy_assignments SET removal_job_id=NULL WHERE id=? AND removal_job_id=?',payload.removalAssignmentId,job.id)
        audit(null,'policy.unassign.failed','policy',payload.policyId,null,{assignmentId:payload.removalAssignmentId,jobId:job.id,error:'Agent did not complete job after five attempts'})
      }
      if(payload.driftCheckId)run("UPDATE policy_drift_checks SET status='unknown',error='Agent did not complete readback after five attempts',checked_at=? WHERE id=?",now(),payload.driftCheckId)
      if(payload.learningAttemptId){
        const learning=one("SELECT id FROM learning_sessions WHERE id=? AND node_id=? AND current_apply_attempt_id=? AND status='applying'",payload.learningSessionId,req.agent.node_id,payload.learningAttemptId)
        if(learning){run("UPDATE learning_sessions SET status='apply-failed',last_error='Agent did not complete the apply job' WHERE id=?",learning.id);run("UPDATE nodes SET firewall_state='review' WHERE id=?",req.agent.node_id)}
      }
      if(payload.progressiveSessionId)run("UPDATE learning_sessions SET last_error='Agent did not complete progressive apply',next_progressive_at=?,last_attempt_at=? WHERE id=? AND status='active'",now(),now(),payload.progressiveSessionId)
      if(job.type==='mfa.prompt'&&payload.promptId){
        run("UPDATE mfa_prompt_events SET status='failed',error=? WHERE id=? AND status IN ('pending','queued')",'Agent did not open MFA prompt after five attempts',payload.promptId)
        if(payload.applyRunId)run("UPDATE policy_apply_runs SET status='unknown',error=?,finished_at=? WHERE id=?",'Agent did not open MFA prompt after five attempts',now(),payload.applyRunId)
        audit(null,'mfa.prompt.abandoned','mfa-prompt',payload.promptId,null,{promptId:payload.promptId,nodeId:req.agent.node_id,jobId:job.id,attempts:job.attempt_count})
      }
      if(payload.breakGlassSessionId){
        if(job.type==='breakglass.start')run("UPDATE break_glass_sessions SET status='failed',last_error='Agent did not confirm activation' WHERE id=? AND status='activating'",payload.breakGlassSessionId)
        if(job.type==='breakglass.end')run("UPDATE break_glass_sessions SET status='active',last_error='Agent did not confirm firewall restoration' WHERE id=? AND status='ending'",payload.breakGlassSessionId)
        audit(null,'break-glass.agent-job.abandoned','node',req.agent.node_id,null,{sessionId:payload.breakGlassSessionId,jobId:job.id})
      }
      if(payload.policyId&&!payload.learningAttemptId){
        const learning=one("SELECT id FROM learning_sessions WHERE generated_policy_id=? AND node_id=? AND status='applying'",payload.policyId,req.agent.node_id)
        if(learning){run("UPDATE learning_sessions SET status='apply-failed',last_error='Agent did not complete the apply job' WHERE id=?",learning.id);run("UPDATE nodes SET firewall_state='review' WHERE id=?",req.agent.node_id)}
      }
      audit(null,'agent.job.abandoned','agent-job',job.id,null,{agentId:req.agent.id,attempts:job.attempt_count})
    }
    const available=all("SELECT * FROM agent_jobs WHERE agent_id=? AND ((status='queued') OR (status='leased' AND lease_until<?)) AND attempt_count<5 ORDER BY created_at LIMIT 10",req.agent.id,now())
    return available.map(job=>{
      const leaseToken=crypto.randomBytes(24).toString('base64url')
      run("UPDATE agent_jobs SET status='leased',lease_until=?,lease_token=?,attempt_count=attempt_count+1 WHERE id=?",leaseUntil,leaseToken,job.id)
      return {id:job.id,type:job.type,payload:parse(job.payload_json),attempt:job.attempt_count+1,leaseToken}
    })
  })()
  res.json({jobs,leaseUntil})
})

agentRoutes.post('/:id/jobs/:jobId/result',requireAgent,(req,res)=>{
  const data=z.object({leaseToken:z.string().min(20),success:z.boolean(),diff:z.any().optional(),result:z.any().optional(),error:z.string().max(2000).optional()}).parse(req.body)
  const job=one('SELECT * FROM agent_jobs WHERE id=? AND agent_id=?',req.params.jobId,req.agent.id)
  if(!job)return res.status(404).json({error:'Job not found'})
  if(job.status!=='leased'||job.lease_until<=now()||job.lease_token!==data.leaseToken)return res.status(409).json({error:'Job lease expired or superseded'})
  const payload=parse(job.payload_json)||{}
  let breakGlassValid=true
  if(payload.breakGlassSessionId&&job.type==='breakglass.start')breakGlassValid=data.result?.active===true&&!!normalizeProfileSnapshot(data.result?.profiles)
  if(payload.breakGlassSessionId&&job.type==='breakglass.end')breakGlassValid=data.result?.restored===true
  const mfaPrompt=job.type==='mfa.prompt'&&payload.promptId?one('SELECT status,expires_at FROM mfa_prompt_events WHERE id=?',payload.promptId):null
  const mfaActive=job.type!=='mfa.prompt'||!!mfaPrompt&&['pending','queued'].includes(mfaPrompt.status)&&Number.isFinite(Date.parse(mfaPrompt.expires_at))&&Date.parse(mfaPrompt.expires_at)>Date.now()
  const mfaOpened=job.type!=='mfa.prompt'||mfaActive&&data.result?.opened===true
  const status=data.success&&breakGlassValid&&mfaOpened?'success':'failed'
  const resultError=data.error||(!breakGlassValid?'Agent break-glass readback was invalid':job.type==='mfa.prompt'&&!mfaActive?'MFA prompt expired or was already resolved':!mfaOpened?'No interactive browser session was confirmed':null)
  db.transaction(()=>{
    run('UPDATE agent_jobs SET status=?,result_json=?,error=?,finished_at=?,lease_until=NULL,lease_token=NULL WHERE id=?',status,json(data.result||data.diff||null),resultError,now(),job.id)
    if(job.type==='arp.collect'&&data.success&&Array.isArray(data.result?.arp))recordArpEntries(req.agent.node_id,data.result.arp,'agent')
    if(payload.applyRunId)run('UPDATE policy_apply_runs SET status=?,diff_json=?,error=?,finished_at=? WHERE id=?',status,json(data.diff||null),resultError,now(),payload.applyRunId)
    if(payload.loopbackBaseline){
      run('UPDATE node_loopback_baseline SET status=?,applied_at=?,last_error=?,job_id=NULL WHERE node_id=? AND job_id=?',data.success?'applied':'failed',data.success?now():null,data.error||null,req.agent.node_id,job.id)
      audit(null,data.success?'node.loopback.applied':'node.loopback.failed','node',req.agent.node_id,null,{jobId:job.id,error:data.error||null})
    }
    if(payload.removalAssignmentId){
      const assignment=one('SELECT * FROM policy_assignments WHERE id=? AND removal_job_id=?',payload.removalAssignmentId,job.id)
      if(assignment){
        if(data.success)run('DELETE FROM policy_assignments WHERE id=?',assignment.id)
        else run('UPDATE policy_assignments SET removal_job_id=NULL WHERE id=?',assignment.id)
        audit(null,data.success?'policy.unassign':'policy.unassign.failed','policy',assignment.policy_id,assignment,{assignmentId:assignment.id,jobId:job.id,nodeId:req.agent.node_id,error:data.error||null})
      }
    }
    if(payload.driftCheckId){
      const check=one('SELECT * FROM policy_drift_checks WHERE id=? AND node_id=?',payload.driftCheckId,req.agent.node_id)
      if(check){
        let driftStatus='unknown',driftDiff=null,driftError=data.error||'Agent firewall readback failed'
        const current=one('SELECT current_version_id FROM policies WHERE id=?',check.policy_id)
        const observed=readRuleSchema.safeParse(data.result?.rules)
        if(data.success&&current?.current_version_id===check.version_id&&observed.success){
          const expected=parse(one('SELECT rules_compiled_json FROM policy_versions WHERE id=?',check.version_id)?.rules_compiled_json)||[]
          driftDiff=diffRules(expected,observed.data)
          driftStatus=driftDiff.add.length||driftDiff.remove.length?'drift':'in-sync'
          driftError=null
        } else if(data.success)driftError='Agent readback was invalid or the policy version changed'
        run('UPDATE policy_drift_checks SET status=?,diff_json=?,error=?,checked_at=? WHERE id=?',driftStatus,json(driftDiff),driftError,now(),check.id)
        const previous=one("SELECT status FROM policy_drift_checks WHERE policy_id=? AND node_id=? AND version_id=? AND id<>? ORDER BY checked_at DESC,rowid DESC LIMIT 1",check.policy_id,check.node_id,check.version_id,check.id)?.status
        if(driftStatus==='drift'&&previous!=='drift')emitNotification({eventKey:`drift:${check.id}`,category:'policy_drift',title:'Policy drift detected',body:`${one('SELECT name FROM policies WHERE id=?',check.policy_id)?.name||'Policy'} differs from the firewall rules on ${one('SELECT hostname FROM nodes WHERE id=?',check.node_id)?.hostname||check.node_id}.`,entityType:'node',entityId:check.node_id})
      }
    }
    if(payload.learningAttemptId){
      const learning=one("SELECT id FROM learning_sessions WHERE id=? AND node_id=? AND current_apply_attempt_id=? AND status='applying'",payload.learningSessionId,req.agent.node_id,payload.learningAttemptId)
      if(learning){
        const jobs=all("SELECT status FROM agent_jobs WHERE json_extract(payload_json,'$.learningAttemptId')=?",payload.learningAttemptId)
        const completed=jobs.length>=Number(payload.learningExpectedJobs||1)&&jobs.every(item=>item.status==='success'),failed=jobs.some(item=>item.status==='failed')
        if(completed||failed){
          run('UPDATE learning_sessions SET status=?,last_error=? WHERE id=?',completed?'enforced':'apply-failed',completed?null:data.error||'Agent policy apply failed',learning.id)
          run('UPDATE nodes SET firewall_state=? WHERE id=?',completed?'enforcing':'review',req.agent.node_id)
          audit(null,completed?'learning.enforced':'learning.apply.failed','node',req.agent.node_id,null,{sessionId:learning.id,jobId:job.id})
        }
      }
    }else if(payload.policyId&&!payload.progressiveSessionId){
      const learning=one("SELECT id FROM learning_sessions WHERE generated_policy_id=? AND node_id=? AND status='applying'",payload.policyId,req.agent.node_id)
      if(learning){
        run('UPDATE learning_sessions SET status=?,last_error=? WHERE id=?',data.success?'enforced':'apply-failed',data.success?null:data.error||'Agent apply failed',learning.id)
        run('UPDATE nodes SET firewall_state=? WHERE id=?',data.success?'enforcing':'review',req.agent.node_id)
        audit(null,data.success?'learning.enforced':'learning.apply.failed','node',req.agent.node_id,null,{sessionId:learning.id,jobId:job.id})
      }
    }
    if(payload.progressiveSessionId){
      if(!data.success)run('UPDATE learning_sessions SET last_error=?,next_progressive_at=?,last_attempt_at=? WHERE id=? AND status=\'active\'',data.error||'Agent progressive apply failed',now(),now(),payload.progressiveSessionId)
      audit(null,data.success?'learning.progressive.applied':'learning.progressive.failed','node',req.agent.node_id,null,{sessionId:payload.progressiveSessionId,jobId:job.id,error:data.error||null})
    }
    if(payload.breakGlassSessionId){
      const session=one('SELECT * FROM break_glass_sessions WHERE id=? AND node_id=?',payload.breakGlassSessionId,req.agent.node_id)
      if(session&&job.type==='breakglass.start'&&session.status==='activating'){
        const profiles=normalizeProfileSnapshot(data.result?.profiles)
        const active=data.success&&data.result?.active===true&&!!profiles
        run('UPDATE break_glass_sessions SET status=?,profile_snapshot_json=?,last_error=? WHERE id=?',active?'active':'failed',active?json(profiles):null,active?null:data.error||'Agent did not confirm firewall state',session.id)
        if(payload.applyRunId)run('UPDATE policy_apply_runs SET status=?,diff_json=?,error=?,finished_at=? WHERE id=?',active?'success':'failed',active?json({operation:'breakglass_start',sessionId:session.id,profiles}):null,active?null:data.error||'Agent did not confirm firewall state',now(),payload.applyRunId)
        audit(null,active?'break-glass.active':'break-glass.start.failed','node',req.agent.node_id,null,{sessionId:session.id,jobId:job.id,expiresAt:session.expires_at,error:active?null:data.error||'Invalid agent readback'})
      }
      if(session&&job.type==='breakglass.end'&&session.status==='ending'){
        const restored=data.success&&data.result?.restored===true
        run('UPDATE break_glass_sessions SET status=?,ended_at=?,last_error=? WHERE id=?',restored?payload.finalStatus||'ended':'active',restored?now():null,restored?null:data.error||'Agent did not confirm firewall restoration',session.id)
        if(payload.applyRunId)run('UPDATE policy_apply_runs SET status=?,diff_json=?,error=?,finished_at=? WHERE id=?',restored?'success':'failed',restored?json({operation:'breakglass_end',sessionId:session.id,profiles:data.result?.profiles||null}):null,restored?null:data.error||'Agent did not confirm firewall restoration',now(),payload.applyRunId)
        audit(null,restored?(payload.finalStatus==='expired'?'break-glass.expired':'break-glass.end'):'break-glass.end.failed','node',req.agent.node_id,null,{sessionId:session.id,jobId:job.id,error:restored?null:data.error||'Invalid agent readback'})
      }
      if(payload.applyRunId&&(!session||(job.type==='breakglass.start'&&session.status!=='activating')||(job.type==='breakglass.end'&&session.status!=='ending')))run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','unknown','Break-glass session was unavailable or changed before agent readback',now(),payload.applyRunId)
    }
    if(job.type==='mfa.prompt'&&payload.promptId){
      const opened=data.success&&mfaActive&&data.result?.opened===true
      const promptError=data.error||(!mfaActive?'MFA prompt expired or was already resolved':!opened?'No interactive browser session was confirmed':null)
      run('UPDATE mfa_prompt_events SET status=?,opened_at=?,opened_user=?,opened_session_id=?,opened_process_id=?,source_event_record_id=?,error=? WHERE id=? AND status IN (\'pending\',\'queued\')',opened?'opened':'failed',opened?now():null,opened?data.result?.user||null:null,opened?Number(data.result?.sessionId)||null:null,opened?Number(data.result?.processId)||null:null,opened?Number(data.result?.sourceEventRecordId)||null:null,promptError,payload.promptId)
      if(payload.applyRunId)run('UPDATE policy_apply_runs SET status=?,diff_json=?,error=?,finished_at=? WHERE id=?',opened?'success':'failed',opened?json({operation:'mfa.prompt',promptId:payload.promptId,sessionId:data.result?.sessionId,processId:data.result?.processId}):null,promptError,now(),payload.applyRunId)
      audit(null,opened?'mfa.prompt.opened':'mfa.prompt.failed','mfa-prompt',payload.promptId,null,{promptId:payload.promptId,nodeId:req.agent.node_id,jobId:job.id,sessionId:opened?data.result?.sessionId:null,error:promptError})
    }
    audit(null,status==='success'?'agent.job.success':'agent.job.failed','agent-job',job.id,null,{agentId:req.agent.id,type:job.type,error:resultError})
  })()
  res.json({ok:true})
})

agentRoutes.post('/:id/renew',requireAgent,wrap(async(req,res)=>{
  const {csr}=z.object({csr:z.string().min(100).max(12000)}).parse(req.body)
  const signed=await signAgentCsr(csr,req.agent.node_id)
  run('UPDATE agents SET cert_thumbprint=?,cert_expires_at=? WHERE id=?',signed.fingerprint,signed.expiresAt,req.agent.id)
  audit(null,'agent.cert.renew','agent',req.agent.id,null,{expiresAt:signed.expiresAt})
  res.json({agentId:req.agent.id,nodeId:req.agent.node_id,certificate:signed.certificate,caCertificate:signed.caCertificate,expiresAt:signed.expiresAt})
}))
