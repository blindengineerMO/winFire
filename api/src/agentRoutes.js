import express from 'express'
import crypto from 'node:crypto'
import {rateLimit} from 'express-rate-limit'
import {z} from 'zod'
import {db,one,all,run,id,now,audit,json,parse} from './db.js'
import {hashToken} from './security.js'
import {agentPkiReady,signAgentCsr} from './agentPki.js'
import {normalizeWindowsEvent} from './eventNormalizer.js'
import {diffRules} from './connector.js'
import {emitNotification} from './notifications.js'

export const agentRoutes=express.Router()
const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next)
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
  const {version,mode}=z.object({version:z.string().max(100),mode:z.enum(['pull','push']).default('pull')}).parse(req.body)
  const previous=one('SELECT status FROM nodes WHERE id=?',req.agent.node_id)?.status
  run('UPDATE agents SET version=?,mode=?,last_checkin_at=? WHERE id=?',version,mode,now(),req.agent.id)
  run("UPDATE nodes SET status='reachable',last_seen_at=?,failures=0 WHERE id=?",now(),req.agent.node_id)
  if(previous==='unreachable')audit(null,'agent.online','node',req.agent.node_id,null,{agentId:req.agent.id})
  res.json({ok:true,serverTime:now()})
})

agentRoutes.post('/:id/events',requireAgent,(req,res)=>{
  const event=z.object({recordId:z.number().int().positive(),id:z.number().int().positive(),timeCreated:z.string().datetime({offset:true}),fields:z.record(z.string(),z.string()).default({})})
  const {events}=z.object({events:z.array(event).min(1).max(500)}).parse(req.body)
  let inserted=0
  db.transaction(()=>{
    for(const raw of events){
      const item=normalizeWindowsEvent(raw)
      const result=run('INSERT OR IGNORE INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,src_port,dst_ip,dst_port,direction,program,account_sid,event_time,event_type,logon_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',id(),req.agent.node_id,item.recordId,item.eventId,item.action,item.protocol,item.srcIp,item.srcPort,item.dstIp,item.dstPort,item.direction,item.program,item.accountSid,item.eventTime,item.eventType,item.logonType)
      inserted+=result.changes
    }
    run('UPDATE agents SET last_checkin_at=? WHERE id=?',now(),req.agent.id)
    run("UPDATE nodes SET status='reachable',last_seen_at=?,failures=0 WHERE id=?",now(),req.agent.node_id)
    audit(null,'agent.events.ingest','node',req.agent.node_id,null,{agentId:req.agent.id,received:events.length,inserted,lastRecordId:events.at(-1).recordId})
  })()
  res.status(201).json({received:events.length,inserted,lastRecordId:events.at(-1).recordId})
})

agentRoutes.get('/:id/jobs',requireAgent,(req,res)=>{
  const leaseUntil=new Date(Date.now()+60_000).toISOString()
  const jobs=db.transaction(()=>{
    const abandoned=all("SELECT * FROM agent_jobs WHERE agent_id=? AND status='leased' AND lease_until<? AND attempt_count>=5",req.agent.id,now())
    for(const job of abandoned){
      run("UPDATE agent_jobs SET status='failed',error='Job lease expired after five attempts',finished_at=?,lease_token=NULL WHERE id=?",now(),job.id)
      const payload=parse(job.payload_json)||{}
      if(payload.applyRunId)run("UPDATE policy_apply_runs SET status='failed',error='Agent did not complete job after five attempts',finished_at=? WHERE id=?",now(),payload.applyRunId)
      if(payload.driftCheckId)run("UPDATE policy_drift_checks SET status='unknown',error='Agent did not complete readback after five attempts',checked_at=? WHERE id=?",now(),payload.driftCheckId)
      if(payload.policyId){
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
  const status=data.success?'success':'failed',payload=parse(job.payload_json)||{}
  db.transaction(()=>{
    run('UPDATE agent_jobs SET status=?,result_json=?,error=?,finished_at=?,lease_until=NULL,lease_token=NULL WHERE id=?',status,json(data.result||data.diff||null),data.error||null,now(),job.id)
    if(payload.applyRunId)run('UPDATE policy_apply_runs SET status=?,diff_json=?,error=?,finished_at=? WHERE id=?',status,json(data.diff||null),data.error||null,now(),payload.applyRunId)
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
    if(payload.policyId){
      const learning=one("SELECT id FROM learning_sessions WHERE generated_policy_id=? AND node_id=? AND status='applying'",payload.policyId,req.agent.node_id)
      if(learning){
        run('UPDATE learning_sessions SET status=?,last_error=? WHERE id=?',data.success?'enforced':'apply-failed',data.success?null:data.error||'Agent apply failed',learning.id)
        run('UPDATE nodes SET firewall_state=? WHERE id=?',data.success?'enforcing':'review',req.agent.node_id)
        audit(null,data.success?'learning.enforced':'learning.apply.failed','node',req.agent.node_id,null,{sessionId:learning.id,jobId:job.id})
      }
    }
    audit(null,data.success?'agent.job.success':'agent.job.failed','agent-job',job.id,null,{agentId:req.agent.id,type:job.type,error:data.error||null})
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
