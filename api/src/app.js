import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import {rateLimit} from 'express-rate-limit'
import argon2 from 'argon2'
import crypto from 'node:crypto'
import {isIP} from 'node:net'
import PDFDocument from 'pdfkit'
import {z} from 'zod'
import {compilePolicy, graphSchema, findRuleConflicts,validateAddressExpression,validateProgramPath} from '@winfire/shared'
import {db, all, one, run, id, now, audit, json, parse} from './db.js'
import {auth, requireRole, publicUser, issueAccess, issueRefresh, rotateRefresh, hashToken, seal, openSealed} from './security.js'
import {probeNode, collectFacts, lookupDns, remote, applyRules, diffRules, tcpProbe} from './connector.js'
import {classifyVerification,hasManagedRule} from './verifier.js'
import {makeTotpSecret,verifyTotp,matchingTotpCounter} from './totp.js'
import {agentRoutes} from './agentRoutes.js'
import {agentPkiReady} from './agentPki.js'
import {normalizeWindowsEvent} from './eventNormalizer.js'
import {isLoopbackEvent} from './eventPattern.js'
import {deliverInvite,deliverVerification,inviteLink} from './mailer.js'
import {saveAvatar,readAvatar,removeAvatar} from './avatar.js'
import {readDirectoryComputers,testDirectoryConnection} from './directory.js'
import {observabilitySettings} from './maintenance.js'
import {resourceRecord,canReadResource,canWriteResource} from './access.js'
import {emitNotification,notificationSummary,preferenceKeys} from './notifications.js'
import {buildOpenApi} from './openapi.js'
import {parseSeceditRights} from './logonRights.js'
import {normalizeProfileSnapshot,publicBreakGlass} from './breakGlass.js'
import {normalizeSourceIp,sourceMatches} from './mfaPortal.js'
import {entraConfigured,startEntraAuthentication,completeEntraAuthentication} from './entraPortal.js'
import {portalBranding,setPortalCompanyName,savePortalImage,readPortalImage,removePortalImage} from './portalBranding.js'
import {assertManagementAccess} from './managementGuard.js'
import {mfaPromptSettings} from './mfaPromptSettings.js'

export const app=express()
app.disable('x-powered-by')
if(process.env.TRUST_PROXY_CIDRS)app.set('trust proxy',process.env.TRUST_PROXY_CIDRS.split(',').map(item=>item.trim()).filter(Boolean))
app.use(helmet({contentSecurityPolicy:false}))
app.use(cors({origin:(origin,cb)=>{const allowed=(process.env.CORS_ORIGIN||'').split(',').filter(Boolean);cb(null,!origin||allowed.includes(origin))}}))
app.use(express.json({limit:'2mb'}))
const api=express.Router()
app.use('/api/v1',api)
const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next)
const body=(schema,req)=>schema.parse(req.body)
const reqId=req=>String(req.params.id)
const notFound=(res,label='Record')=>res.status(404).json({error:`${label} not found`})
const latestTraining=nodeId=>one('SELECT id,mode,status,started_at,ends_at,generated_policy_id,last_error,progressive_enabled,progressive_start_at,progressive_interval_hours,next_progressive_at,last_progressive_at FROM learning_sessions WHERE node_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1',nodeId)
const latestVerification=nodeId=>one('SELECT status,reason,run_at FROM verifier_results WHERE node_id=? ORDER BY run_at DESC,rowid DESC LIMIT 1',nodeId)||null
function policyVerification(policyId){
  const latest=one('SELECT run_id FROM verifier_results WHERE policy_id=? ORDER BY run_at DESC,rowid DESC LIMIT 1',policyId)
  if(!latest)return null
  const checks=all('SELECT status FROM verifier_results WHERE policy_id=? AND run_id=?',policyId,latest.run_id)
  return checks.some(check=>check.status==='fail')?'fail':checks.some(check=>check.status==='inconclusive')?'inconclusive':checks.length?'pass':null
}
const publicNode=node=>node && ({...node,failures:Number(node.failures),facts:parse(node.snapshot_json),ad:parse(node.ad_snapshot_json),training:latestTraining(node.id)||null,verification:latestVerification(node.id)})
const canUseCredential=(user,credential)=>credential&&(user.role==='owner'||user.role==='admin'||credential.owner_user_id===user.id||credential.visibility==='team'&&credential.team_id&&credential.team_id===user.team_id||canWriteResource(user,'credential',credential))
function getNode(idValue) {return one('SELECT * FROM nodes WHERE id=?',idValue)}
function getPolicy(idValue) {return one('SELECT * FROM policies WHERE id=?',idValue)}
function hasActiveLearning(policyId) {return !!one("SELECT id FROM learning_sessions WHERE generated_policy_id=? AND status='active'",policyId)}
function readablePolicyIds(user) {return new Set(all('SELECT * FROM policies').filter(policy=>canReadResource(user,'policy',policy)).map(policy=>policy.id))}
function trainingDays() {return Number(one("SELECT value FROM app_settings WHERE key='new_host_training_days'")?.value||30)}
function progressiveSettings() {return {
  enabled:one("SELECT value FROM app_settings WHERE key='progressive_learning_enabled'")?.value==='true',
  startDays:Number(one("SELECT value FROM app_settings WHERE key='progressive_learning_start_days'")?.value||15),
  intervalHours:Number(one("SELECT value FROM app_settings WHERE key='progressive_learning_interval_hours'")?.value||24)
}}
const directorySettings=()=>one("SELECT * FROM directory_connections WHERE id='default'")
const publicDirectory=settings=>settings&&({url:settings.url||'',baseDn:settings.base_dn||'',bindCredentialId:settings.bind_credential_id||null,nodeCredentialId:settings.node_credential_id||null,enabled:!!settings.enabled,syncIntervalMinutes:settings.sync_interval_minutes,allowLdapFallback:!!settings.allow_ldap_fallback,ldapFallbackApprovedBy:settings.ldap_fallback_approved_by||null,ldapFallbackApprovedAt:settings.ldap_fallback_approved_at||null,lastTransport:settings.last_transport||null,lastSyncedAt:settings.last_synced_at,lastSyncAttemptAt:settings.last_sync_attempt_at,lastSyncStatus:settings.last_sync_status,lastSyncError:settings.last_sync_error,lastSyncCount:settings.last_sync_count})
function directoryCredential(settings) {
  const credential=one('SELECT * FROM credentials WHERE id=?',settings.bind_credential_id)
  if(!credential)throw Object.assign(new Error('Directory bind credential is missing'),{status:400})
  return {username:credential.username,password:openSealed(credential.encrypted_blob).password}
}
function startTraining(node,days,mode,actorId=null) {
  if(one("SELECT id FROM learning_sessions WHERE node_id=? AND status IN ('active','review','applying','apply-failed')",node.id))throw Object.assign(new Error('Finish the current learning session before starting another'),{status:409})
  const sessionId=id(),endsAt=new Date(Date.now()+days*864e5).toISOString(),policy=ensurePersonalPolicy(node,actorId)
  const progressive=progressiveSettings(),progressiveEnabled=mode==='auto'&&progressive.enabled&&days>progressive.startDays
  const progressiveStartAt=progressiveEnabled?new Date(Date.now()+progressive.startDays*864e5).toISOString():null
  run('INSERT INTO learning_sessions(id,node_id,ends_at,status,mode,generated_policy_id,progressive_enabled,progressive_start_at,progressive_interval_hours,next_progressive_at) VALUES(?,?,?,?,?,?,?,?,?,?)',sessionId,node.id,endsAt,'active',mode,policy.id,Number(progressiveEnabled),progressiveStartAt,progressiveEnabled?progressive.intervalHours:null,progressiveStartAt)
  run("UPDATE nodes SET firewall_state='learning' WHERE id=?",node.id)
  audit(actorId,'learning.start','node',node.id,null,{sessionId,endsAt,days,mode,policyId:policy.id,progressiveEnabled})
  return {id:sessionId,nodeId:node.id,endsAt,days,mode,status:'active',generatedPolicyId:policy.id,progressiveEnabled}
}
function ensurePersonalPolicy(node,actorId=null) {
  const existing=one("SELECT * FROM policies WHERE origin='learned' AND source_node_id=?",node.id)
  if(existing)return existing
  const policyId=id(),versionId=id(),empty={nodes:[],edges:[]}
  run("INSERT INTO policies(id,name,description,owner_user_id,current_version_id,origin,source_node_id) VALUES(?,?,?,?,?,'learned',?)",policyId,`Learned ${node.hostname}`,`Personal learned firewall policy for ${node.hostname}`,actorId,versionId,node.id)
  run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,policyId,1,json(empty),json([]),actorId,'Learning started')
  return getPolicy(policyId)
}
async function requestEmailVerification(user,email,actorId) {
  if(!process.env.SMTP_HOST)throw Object.assign(new Error('Email verification requires SMTP configuration'),{status:503})
  if(email!==user.email&&one('SELECT id FROM users WHERE email=?',email))throw Object.assign(new Error('An account already uses this email'),{status:409})
  const token=crypto.randomBytes(32).toString('base64url'),verificationId=id(),expiresAt=new Date(Date.now()+864e5).toISOString()
  run('INSERT INTO email_verifications(id,user_id,new_email,token_hash,expires_at) VALUES(?,?,?,?,?)',verificationId,user.id,email,hashToken(token),expiresAt)
  try {await deliverVerification(email,token)}
  catch(error){run('DELETE FROM email_verifications WHERE id=?',verificationId);throw error}
  audit(actorId,'user.email.verification.request','user',user.id,null,{email,expiresAt})
  return {sent:true,expiresAt}
}
function assignedNodes(policyId) {
  return all(`SELECT DISTINCT n.* FROM nodes n JOIN policy_assignments a ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id) WHERE a.policy_id=?`,policyId)
}
function pendingPolicySync(){
  const pairs=all(`SELECT DISTINCT p.id policy_id,p.name policy_name,p.current_version_id version_id,n.id node_id,n.hostname
    FROM policies p JOIN policy_assignments a ON a.policy_id=p.id
    JOIN nodes n ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id)
    WHERE p.current_version_id IS NOT NULL AND NOT EXISTS
      (SELECT 1 FROM learning_sessions s WHERE s.node_id=n.id AND s.status IN ('active','review','applying'))`)
  return pairs.filter(pair=>{
    const applied=one('SELECT version_id,status FROM policy_apply_runs WHERE policy_id=? AND node_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1',pair.policy_id,pair.node_id)
    return applied?.version_id!==pair.version_id||!['success','queued','running'].includes(applied.status)
  })
}
let policySyncRunning=false
async function performPolicySync(actorId){
  if(policySyncRunning)throw Object.assign(new Error('A policy sync is already running'),{status:409})
  policySyncRunning=true
  try{
    const results=[]
    for(const pair of pendingPolicySync()){
      const policy=getPolicy(pair.policy_id),node=getNode(pair.node_id)
      if(!policy||!node)continue
      try{results.push(...await applyPolicy(policy,actorId,[node]))}
      catch(error){results.push({nodeId:node.id,policyId:policy.id,status:'failed',error:error.message});audit(actorId,'policy.sync.failed','node',node.id,null,{policyId:policy.id,error:error.message})}
    }
    audit(actorId,'policy.sync','policy',null,null,{count:results.length,failed:results.filter(item=>item.status==='failed').length})
    return results
  }finally{policySyncRunning=false}
}
export async function processDuePolicySync(){
  const schedules=all("SELECT * FROM policy_sync_schedules WHERE status='scheduled' AND execute_at<=? ORDER BY execute_at LIMIT 5",now())
  for(const schedule of schedules){
    if(policySyncRunning)break
    run("UPDATE policy_sync_schedules SET status='running' WHERE id=? AND status='scheduled'",schedule.id)
    try{const results=await performPolicySync(schedule.requested_by);run('UPDATE policy_sync_schedules SET status=?,result_json=?,finished_at=? WHERE id=?','complete',json(results),now(),schedule.id)}
    catch(error){run('UPDATE policy_sync_schedules SET status=?,result_json=?,finished_at=? WHERE id=?','failed',json({error:error.message}),now(),schedule.id)}
  }
}
function assignmentConflicts(policyId,rules,nodes) {
  const conflicts=[]
  if(!rules.length)return conflicts
  for(const node of nodes) {
    const others=all(`SELECT DISTINCT p.id,p.name,v.rules_compiled_json FROM policies p JOIN policy_versions v ON v.id=p.current_version_id JOIN policy_assignments a ON a.policy_id=p.id WHERE p.id<>? AND (a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?))`,policyId,node.id,node.id)
    for(const other of others)for(const match of findRuleConflicts(rules,parse(other.rules_compiled_json)||[]))conflicts.push({nodeId:node.id,hostname:node.hostname,otherPolicyId:other.id,otherPolicy:other.name,...match})
  }
  return conflicts
}
function rejectConflicts(res,conflicts) {return res.status(409).json({error:'Conflicting firewall rules on assigned nodes',conflicts})}
async function applyPolicy(policy,actorId=null,targetNodes=null,context={}) {
  if(one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id))throw Object.assign(new Error('Wait for pending agent firewall cleanup before applying this policy'),{status:409})
  const version=one('SELECT * FROM policy_versions WHERE id=? AND policy_id=?',policy.current_version_id,policy.id)
  if (!version) throw Object.assign(new Error('Policy has no version'),{status:400})
  const rules=parse(version.rules_compiled_json)||[], results=[]
  assertManagementAccess(rules)
  const targets=targetNodes||assignedNodes(policy.id)
  const conflicts=assignmentConflicts(policy.id,rules,targets)
  if(conflicts.length)throw Object.assign(new Error('Conflicting firewall rules on assigned nodes'),{status:409,conflicts})
  for (const node of targets) {
    const runId=id()
    run('INSERT INTO policy_apply_runs(id,policy_id,version_id,node_id,status) VALUES(?,?,?,?,?)',runId,policy.id,version.id,node.id,'running')
    try {
      if(node.connection_mode==='agent') {
        const agent=one('SELECT * FROM agents WHERE id=? AND revoked_at IS NULL',node.agent_id)
        if(!agent)throw new Error('No active enrolled agent for node')
        const jobId=id()
        run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',jobId,agent.id,'policy.apply',json({applyRunId:runId,policyId:policy.id,versionId:version.id,group:`WinFireSecure:${policy.id}`,rules,...context}))
        run("UPDATE policy_apply_runs SET status='queued' WHERE id=?",runId)
        audit(actorId,'policy.apply.queued','node',node.id,null,{policyId:policy.id,versionId:version.id,jobId})
        results.push({nodeId:node.id,status:'queued',jobId})
        continue
      }
      const diff=await applyRules(node,policy.id,rules)
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json(diff),now(),runId)
      audit(actorId,'policy.apply','node',node.id,null,{policyId:policy.id,versionId:version.id,diff})
      results.push({nodeId:node.id,status:'success',diff})
    } catch(error) {
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',error.message,now(),runId)
      audit(actorId,'policy.apply.failed','node',node.id,null,{policyId:policy.id,error:error.message})
      results.push({nodeId:node.id,status:'failed',error:error.message})
    }
  }
  return results
}

api.get('/health',(req,res)=>res.json({status:'ok',service:'winfire',time:now()}))
api.get('/openapi.json',(_req,res)=>res.json(buildOpenApi(api,agentRoutes)))
const loginLimit=rateLimit({windowMs:15*60*1000,limit:Number(process.env.AUTH_RATE_LIMIT||20),standardHeaders:'draft-8',legacyHeaders:false})
api.post('/auth/login',loginLimit,wrap(async(req,res)=>{
  const {email,password,totp}=body(z.object({email:z.email(),password:z.string().min(1),totp:z.string().optional()}),req)
  const user=one('SELECT * FROM users WHERE email=?',email.toLowerCase())
  if (!user || user.suspended || user.locked_until && user.locked_until>now() || !await argon2.verify(user.password_hash,password)) {
    if(user && !user.suspended) {
      const attempts=user.failed_attempts+1
      run('UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?',attempts,attempts>=5?new Date(Date.now()+15*60*1000).toISOString():null,user.id)
    }
    return res.status(401).json({error:'Invalid credentials or account locked'})
  }
  if(user.totp_secret&&!verifyTotp(openSealed(user.totp_secret).secret,totp)){
    const attempts=user.failed_attempts+1
    run('UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?',attempts,attempts>=5?new Date(Date.now()+15*60*1000).toISOString():null,user.id)
    return res.status(401).json({error:'TOTP code required or invalid',totpRequired:true})
  }
  run('UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?',user.id)
  audit(user.id,'auth.login','user',user.id,null,null)
  res.json({accessToken:issueAccess(user),refreshToken:issueRefresh(user.id),user:publicUser(user)})
}))
api.post('/auth/refresh',loginLimit,(req,res)=>{const tokens=rotateRefresh(req.body?.refreshToken);return tokens?res.json(tokens):res.status(401).json({error:'Invalid refresh token'})})
api.post('/auth/logout',auth,(req,res)=>{if(req.body?.refreshToken)run('UPDATE refresh_tokens SET revoked_at=? WHERE token_hash=?',now(),hashToken(req.body.refreshToken));audit(req.user.id,'auth.logout','user',req.user.id,null,null);res.json({ok:true})})
api.get('/auth/me',auth,(req,res)=>res.json({...publicUser(req.user),totpEnabled:!!req.user.totp_secret,emailVerified:!!req.user.email_verified,profile:one('SELECT avatar_url,theme,notification_prefs FROM user_profiles WHERE user_id=?',req.user.id)}))

api.post('/invites/accept',loginLimit,wrap(async(req,res)=>{
  const {token,password}=body(z.object({token:z.string().min(32),password:z.string().min(12)}),req)
  const invitation=one('SELECT * FROM invites WHERE token_hash=? AND accepted_at IS NULL AND expires_at>?',hashToken(token),now())
  if(!invitation)return res.status(400).json({error:'Invitation is invalid or expired'})
  if(one('SELECT id FROM users WHERE email=?',invitation.email))return res.status(409).json({error:'An account already uses this email'})
  const passwordHash=await argon2.hash(password),userId=id()
  db.transaction(()=>{
    const consumed=run('UPDATE invites SET accepted_at=? WHERE id=? AND accepted_at IS NULL',now(),invitation.id)
    if(consumed.changes!==1)throw Object.assign(new Error('Invitation was already accepted'),{status:409})
    run('INSERT INTO users(id,email,password_hash,role,team_id,email_verified) VALUES(?,?,?,?,?,?)',userId,invitation.email,passwordHash,invitation.role,invitation.team_id||null,invitation.delivered_at?1:0)
    run('INSERT INTO user_profiles(user_id) VALUES(?)',userId)
    if(invitation.team_id)run('INSERT INTO team_members(team_id,user_id) VALUES(?,?)',invitation.team_id,userId)
    audit(userId,'invite.accept','user',userId,null,{invitationId:invitation.id,email:invitation.email})
  })()
  res.status(201).json(publicUser(one('SELECT * FROM users WHERE id=?',userId)))
}))
api.post('/auth/verify-email',loginLimit,(req,res)=>{
  const {token}=body(z.object({token:z.string().min(32)}),req)
  const verification=one('SELECT * FROM email_verifications WHERE token_hash=? AND used_at IS NULL AND expires_at>?',hashToken(token),now())
  if(!verification)return res.status(400).json({error:'Verification link is invalid or expired'})
  const user=one('SELECT * FROM users WHERE id=?',verification.user_id)
  if(!user)return notFound(res,'User')
  db.transaction(()=>{
    const consumed=run('UPDATE email_verifications SET used_at=? WHERE id=? AND used_at IS NULL',now(),verification.id)
    if(consumed.changes!==1)throw Object.assign(new Error('Verification link already used'),{status:409})
    run('UPDATE users SET email=?,email_verified=1,session_version=session_version+1 WHERE id=?',verification.new_email,user.id)
    run('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=?',now(),user.id)
    audit(user.id,'user.email.verified','user',user.id,{email:user.email},{email:verification.new_email})
  })()
  res.json({verified:true,email:verification.new_email})
})
api.get('/avatars/:id',(req,res)=>{
  const avatar=readAvatar(reqId(req))
  if(!avatar)return notFound(res,'Avatar')
  res.set('Cache-Control','private, max-age=300').type(avatar.mimeType).send(avatar.bytes)
})
api.get('/portal-branding',(_req,res)=>res.json(portalBranding()))
api.get('/portal-branding/image',(_req,res)=>{
  const image=readPortalImage()
  if(!image)return notFound(res,'Portal image')
  res.set('Cache-Control','public, max-age=300').type(image.mimeType).send(image.bytes)
})

api.use('/agents',agentRoutes)
api.use(auth)
api.get('/settings/mfa-prompt',requireRole('admin'),(_req,res)=>res.json(mfaPromptSettings()))
api.patch('/settings/mfa-prompt',requireRole('admin'),(req,res)=>{
  const data=body(z.object({failureMode:z.enum(['closed','open']),failOpenMinutes:z.number().int().min(2).max(15),approval:z.string().optional()}),req)
  const before=mfaPromptSettings()
  if(data.failureMode==='open'&&before.failureMode!=='open'&&data.approval!=='ENABLE MFA FAIL OPEN')return res.status(400).json({error:'Type ENABLE MFA FAIL OPEN to approve temporary access without MFA when a client cannot be controlled'})
  db.transaction(()=>{
    run("UPDATE app_settings SET value=? WHERE key='mfa_prompt_failure_mode'",data.failureMode)
    run("UPDATE app_settings SET value=? WHERE key='mfa_prompt_fail_open_minutes'",String(data.failOpenMinutes))
    audit(req.user.id,'mfa.prompt.settings.update','app-settings','mfa-prompt',before,{failureMode:data.failureMode,failOpenMinutes:data.failOpenMinutes})
  })()
  res.json(mfaPromptSettings())
})
api.patch('/settings/portal-branding',requireRole('admin'),(req,res)=>{
  const {companyName}=body(z.object({companyName:z.string().trim().min(1).max(80)}),req)
  const before=portalBranding(),after=setPortalCompanyName(companyName)
  audit(req.user.id,'portal.branding.name','settings',null,before,after)
  res.json(after)
})
api.put('/settings/portal-branding/image',requireRole('admin'),(req,res)=>{
  const {mimeType,base64}=body(z.object({mimeType:z.string(),base64:z.string()}),req)
  const after=savePortalImage(mimeType,base64)
  audit(req.user.id,'portal.branding.image','settings',null,null,{mimeType})
  res.json(after)
})
api.delete('/settings/portal-branding/image',requireRole('admin'),(_req,res)=>{
  const after=removePortalImage()
  audit(_req.user.id,'portal.branding.image.delete','settings',null,null,null)
  res.json(after)
})
api.get('/notifications',(req,res)=>res.json(notificationSummary(req.user.id)))
api.patch('/notifications/:id/read',(req,res)=>{
  const result=run('UPDATE notifications SET read_at=COALESCE(read_at,?) WHERE id=? AND user_id=?',now(),reqId(req),req.user.id)
  return result.changes?res.json({ok:true}):notFound(res,'Notification')
})
api.post('/notifications/read-all',(req,res)=>{
  run('UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL',now(),req.user.id)
  res.json(notificationSummary(req.user.id))
})
api.post('/auth/email-verification/request',wrap(async(req,res)=>{
  if(req.user.email_verified)return res.status(409).json({error:'Email is already verified'})
  res.json(await requestEmailVerification(req.user,req.user.email,req.user.id))
}))
api.post('/auth/totp/setup',(req,res)=>{
  if(req.user.totp_secret)return res.status(409).json({error:'TOTP is already enabled'})
  const secret=makeTotpSecret()
  run('UPDATE users SET totp_pending=? WHERE id=?',seal({secret}),req.user.id)
  audit(req.user.id,'auth.totp.setup','user',req.user.id,null,null)
  res.json({secret,uri:`otpauth://totp/WinFire:${encodeURIComponent(req.user.email)}?secret=${secret}&issuer=WinFire&algorithm=SHA1&digits=6&period=30`})
})
api.post('/auth/totp/confirm',(req,res)=>{
  const {code}=body(z.object({code:z.string().regex(/^\d{6}$/)}),req)
  const pending=one('SELECT totp_pending FROM users WHERE id=?',req.user.id)?.totp_pending
  if(!pending||!verifyTotp(openSealed(pending).secret,code))return res.status(400).json({error:'Invalid TOTP code'})
  run('UPDATE users SET totp_secret=?,totp_pending=NULL WHERE id=?',pending,req.user.id)
  audit(req.user.id,'auth.totp.enable','user',req.user.id,null,null)
  res.json({enabled:true})
})
api.post('/auth/totp/disable',wrap(async(req,res)=>{
  const {password,code}=body(z.object({password:z.string(),code:z.string()}),req)
  if(!req.user.totp_secret||!await argon2.verify(req.user.password_hash,password)||!verifyTotp(openSealed(req.user.totp_secret).secret,code))return res.status(401).json({error:'Invalid credentials'})
  run('UPDATE users SET totp_secret=NULL WHERE id=?',req.user.id)
  audit(req.user.id,'auth.totp.disable','user',req.user.id,null,null)
  res.json({enabled:false})
}))
api.get('/users',requireRole('admin'),(req,res)=>res.json(all('SELECT id,email,role,team_id,suspended,created_at FROM users ORDER BY created_at DESC')))
api.get('/invites',requireRole('admin'),(_req,res)=>res.json(all('SELECT id,email,team_id,role,expires_at,accepted_at,delivered_at,created_by FROM invites ORDER BY expires_at DESC LIMIT 200')))
api.post('/invites',requireRole('admin'),wrap(async(req,res)=>{
  const data=body(z.object({email:z.email(),role:z.enum(['owner','admin','editor','auditor']).default('auditor'),teamId:z.string().optional()}),req)
  const email=data.email.toLowerCase()
  if(data.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can invite another owner'})
  if(one('SELECT id FROM users WHERE email=?',email))return res.status(409).json({error:'An account already uses this email'})
  if(data.teamId&&!one('SELECT id FROM teams WHERE id=?',data.teamId))return notFound(res,'Team')
  const token=crypto.randomBytes(32).toString('base64url'),invitationId=id(),expiresAt=new Date(Date.now()+7*864e5).toISOString()
  run('INSERT INTO invites(id,email,team_id,role,token_hash,expires_at,created_by) VALUES(?,?,?,?,?,?,?)',invitationId,email,data.teamId||null,data.role,hashToken(token),expiresAt,req.user.id)
  let delivered
  try {delivered=await deliverInvite(email,token)}
  catch(error){run('DELETE FROM invites WHERE id=?',invitationId);throw error}
  if(delivered)run('UPDATE invites SET delivered_at=? WHERE id=?',now(),invitationId)
  audit(req.user.id,'invite.create','invite',invitationId,null,{email,role:data.role,teamId:data.teamId||null,delivered})
  res.status(201).json({id:invitationId,email,role:data.role,teamId:data.teamId||null,expiresAt,delivered,inviteUrl:delivered?undefined:inviteLink(token)})
}))
api.delete('/invites/:id',requireRole('admin'),(req,res)=>{
  const invitation=one('SELECT * FROM invites WHERE id=?',reqId(req));if(!invitation)return notFound(res,'Invitation')
  if(invitation.accepted_at)return res.status(409).json({error:'Accepted invitations cannot be canceled'})
  run('DELETE FROM invites WHERE id=?',invitation.id)
  audit(req.user.id,'invite.cancel','invite',invitation.id,null,{email:invitation.email})
  res.status(204).end()
})
api.post('/users',requireRole('admin'),wrap(async(req,res)=>{
  const data=body(z.object({email:z.email(),password:z.string().min(12),role:z.enum(['owner','admin','editor','auditor']).default('auditor'),teamId:z.string().optional()}),req)
  if(data.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can create another owner'})
  const uid=id();run('INSERT INTO users(id,email,password_hash,role,team_id) VALUES(?,?,?,?,?)',uid,data.email.toLowerCase(),await argon2.hash(data.password),data.role,data.teamId||null)
  run('INSERT INTO user_profiles(user_id) VALUES(?)',uid);audit(req.user.id,'user.create','user',uid,null,{email:data.email,role:data.role});res.status(201).json(publicUser(one('SELECT * FROM users WHERE id=?',uid)))
}))
api.patch('/users/:id',requireRole('admin'),wrap(async(req,res)=>{
  const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res)
  const data=body(z.object({role:z.enum(['owner','admin','editor','auditor']).optional(),suspended:z.boolean().optional(),password:z.string().min(12).optional()}),req)
  if((user.role==='owner'||data.role==='owner')&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can manage owner accounts'})
  if(user.id===req.user.id && data.suspended) return res.status(400).json({error:'Cannot suspend yourself'})
  if(user.role==='owner'&&!user.suspended&&(data.role&&data.role!=='owner'||data.suspended)&&!one("SELECT id FROM users WHERE role='owner' AND suspended=0 AND id<>? LIMIT 1",user.id))return res.status(400).json({error:'At least one active owner is required'})
  run('UPDATE users SET role=?,suspended=?,password_hash=?,session_version=? WHERE id=?',data.role||user.role,data.suspended===undefined?user.suspended:Number(data.suspended),data.password?await argon2.hash(data.password):user.password_hash,user.session_version+(data.password?1:0),user.id)
  if(data.suspended||data.password)run('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=?',now(),user.id)
  audit(req.user.id,'user.update','user',user.id,publicUser(user),{role:data.role,suspended:data.suspended,passwordChanged:!!data.password});res.json(publicUser(one('SELECT * FROM users WHERE id=?',user.id)))
}))
api.delete('/users/:id',requireRole('owner'),(req,res)=>{if(reqId(req)===req.user.id)return res.status(400).json({error:'Cannot delete yourself'});const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res);removeAvatar(user.id);run('DELETE FROM users WHERE id=?',user.id);audit(req.user.id,'user.delete','user',user.id,publicUser(user),null);res.status(204).end()})
api.post('/users/:id/revoke-sessions',requireRole('admin'),(req,res)=>{
  const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res)
  if(user.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can manage owner accounts'})
  db.transaction(()=>{run('UPDATE users SET session_version=session_version+1 WHERE id=?',user.id);run('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=?',now(),user.id);audit(req.user.id,'user.sessions.revoke','user',user.id,null,null)})()
  res.json({revoked:true})
})
api.patch('/users/:id/profile',wrap(async(req,res)=>{
  if(reqId(req)!==req.user.id && !['owner','admin'].includes(req.user.role))return res.status(403).json({error:'Insufficient permission'})
  const data=body(z.object({theme:z.enum(['system','hacker','enterprise','dark','light']).optional(),notificationPrefs:z.record(z.string(),z.boolean()).refine(value=>Object.keys(value).every(key=>preferenceKeys.includes(key)),'Unknown notification preference').optional(),email:z.email().optional(),password:z.string().min(12).optional(),currentPassword:z.string().optional()}),req)
  const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res)
  if(user.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can manage owner accounts'})
  if(data.password&&user.id===req.user.id&&(!data.currentPassword||!await argon2.verify(user.password_hash,data.currentPassword)))return res.status(401).json({error:'Current password is incorrect'})
  const emailChangeRequested=!!(data.email&&data.email.toLowerCase()!==user.email)
  if(emailChangeRequested)await requestEmailVerification(user,data.email.toLowerCase(),req.user.id)
  if(data.password){run('UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?',await argon2.hash(data.password),user.id);run('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=?',now(),user.id)}
  const prior=one('SELECT * FROM user_profiles WHERE user_id=?',user.id)
  run('UPDATE user_profiles SET theme=?,notification_prefs=? WHERE user_id=?',data.theme||prior.theme,data.notificationPrefs?json(data.notificationPrefs):prior.notification_prefs,user.id)
  audit(req.user.id,'user.profile','user',user.id,null,{theme:data.theme,emailChangeRequested,passwordChanged:!!data.password,notificationPrefsChanged:!!data.notificationPrefs});res.json({...one('SELECT avatar_url,theme,notification_prefs FROM user_profiles WHERE user_id=?',user.id),emailChangeRequested})
}))
api.put('/users/:id/avatar',(req,res)=>{
  const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res,'User')
  if(user.id!==req.user.id&&req.user.role!=='owner'&&req.user.role!=='admin')return res.status(403).json({error:'Insufficient permission'})
  if(user.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can manage owner accounts'})
  const data=body(z.object({mimeType:z.string(),base64:z.string()}),req)
  const avatarUrl=saveAvatar(user.id,data.mimeType,data.base64)
  audit(req.user.id,'user.avatar.update','user',user.id,null,{avatarUrl})
  res.json({avatarUrl})
})
api.delete('/users/:id/avatar',(req,res)=>{
  const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res,'User')
  if(user.id!==req.user.id&&req.user.role!=='owner'&&req.user.role!=='admin')return res.status(403).json({error:'Insufficient permission'})
  if(user.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can manage owner accounts'})
  removeAvatar(user.id);audit(req.user.id,'user.avatar.delete','user',user.id,null,null);res.status(204).end()
})
api.get('/teams',(_req,res)=>res.json(all('SELECT * FROM teams ORDER BY name')))
api.post('/teams',requireRole('admin'),(req,res)=>{const data=body(z.object({name:z.string().min(1)}),req),teamId=id();run('INSERT INTO teams(id,name) VALUES(?,?)',teamId,data.name);audit(req.user.id,'team.create','team',teamId,null,data);res.status(201).json(one('SELECT * FROM teams WHERE id=?',teamId))})
api.patch('/teams/:id',requireRole('admin'),(req,res)=>{
  const team=one('SELECT * FROM teams WHERE id=?',reqId(req));if(!team)return notFound(res,'Team')
  const {name}=body(z.object({name:z.string().trim().min(1)}),req)
  run('UPDATE teams SET name=? WHERE id=?',name,team.id)
  audit(req.user.id,'team.update','team',team.id,team,{name})
  res.json(one('SELECT * FROM teams WHERE id=?',team.id))
})
api.delete('/teams/:id',requireRole('admin'),(req,res)=>{
  const team=one('SELECT * FROM teams WHERE id=?',reqId(req));if(!team)return notFound(res,'Team')
  db.transaction(()=>{
    run('UPDATE users SET team_id=NULL WHERE team_id=?',team.id)
    run("UPDATE credentials SET visibility='private',team_id=NULL WHERE team_id=?",team.id)
    run('UPDATE invites SET team_id=NULL WHERE team_id=?',team.id)
    run('DELETE FROM teams WHERE id=?',team.id)
    audit(req.user.id,'team.delete','team',team.id,team,null)
  })()
  res.status(204).end()
})
api.post('/teams/:id/members',requireRole('admin'),(req,res)=>{
  const data=body(z.object({userId:z.string()}),req)
  if(!one('SELECT id FROM teams WHERE id=?',reqId(req)))return notFound(res,'Team')
  if(!one('SELECT id FROM users WHERE id=?',data.userId))return notFound(res,'User')
  db.transaction(()=>{
    run('DELETE FROM team_members WHERE user_id=?',data.userId)
    run('INSERT INTO team_members(team_id,user_id) VALUES(?,?)',reqId(req),data.userId)
    run('UPDATE users SET team_id=? WHERE id=?',reqId(req),data.userId)
    audit(req.user.id,'team.member.add','team',reqId(req),null,data)
  })()
  res.json({ok:true})
})
api.delete('/teams/:id/members/:userId',requireRole('admin'),(req,res)=>{
  const team=one('SELECT * FROM teams WHERE id=?',reqId(req));if(!team)return notFound(res,'Team')
  const membership=one('SELECT 1 FROM team_members WHERE team_id=? AND user_id=?',team.id,req.params.userId)
  if(!membership)return notFound(res,'Membership')
  db.transaction(()=>{
    run('DELETE FROM team_members WHERE team_id=? AND user_id=?',team.id,req.params.userId)
    run('UPDATE users SET team_id=NULL WHERE id=? AND team_id=?',req.params.userId,team.id)
    audit(req.user.id,'team.member.remove','team',team.id,null,{userId:req.params.userId})
  })()
  res.status(204).end()
})
api.get('/roles',(_req,res)=>res.json([{id:'owner',name:'Owner'},{id:'admin',name:'Admin'},{id:'editor',name:'Policy Editor'},{id:'auditor',name:'Auditor'}]))
api.get('/access/users',requireRole('editor'),(req,res)=>res.json(all('SELECT id,email,role FROM users WHERE suspended=0 AND id<>? ORDER BY email',req.user.id)))
api.get('/access/resources',requireRole('editor'),(req,res)=>{
  const resources=[
    ...all('SELECT id,name,owner_user_id FROM policies').map(item=>({...item,type:'policy'})),
    ...all("SELECT id,name,owner_user_id FROM node_groups WHERE id<>'winfire-global-all-nodes'").map(item=>({...item,type:'node_group'})),
    ...all('SELECT id,name,owner_user_id FROM credentials').map(item=>({...item,type:'credential'}))
  ]
  res.json(resources.filter(item=>canWriteResource(req.user,item.type,item)).map(({id,name,type})=>({id,name,type})).sort((a,b)=>a.type.localeCompare(b.type)||a.name.localeCompare(b.name)))
})
const resourceType=z.enum(['policy','node_group','credential'])
api.get('/access/grants',requireRole('editor'),(req,res)=>{
  const {type,resourceId}=z.object({type:resourceType,resourceId:z.string().min(1)}).parse(req.query)
  const resource=resourceRecord(type,resourceId);if(!resource)return notFound(res,'Resource')
  if(!canWriteResource(req.user,type,resource))return res.status(403).json({error:'Insufficient permission'})
  res.json(all('SELECT g.id,g.grantee_user_id,g.permission,g.created_at,u.email FROM resource_grants g JOIN users u ON u.id=g.grantee_user_id WHERE g.resource_type=? AND g.resource_id=? ORDER BY u.email',type,resourceId))
})
api.post('/access/grants',requireRole('editor'),(req,res)=>{
  const data=body(z.object({type:resourceType,resourceId:z.string().min(1),userId:z.string().min(1),permission:z.enum(['read','write'])}),req)
  if(data.type==='node_group'&&data.resourceId==='winfire-global-all-nodes')return res.status(409).json({error:'Global policy scope is managed by administrators'})
  const resource=resourceRecord(data.type,data.resourceId);if(!resource)return notFound(res,'Resource')
  if(!canWriteResource(req.user,data.type,resource))return res.status(403).json({error:'Insufficient permission'})
  const grantee=one('SELECT id,role,suspended FROM users WHERE id=?',data.userId);if(!grantee)return notFound(res,'User')
  if(grantee.suspended)return res.status(400).json({error:'Cannot grant access to a suspended user'})
  if(data.permission==='write'&&grantee.role==='auditor')return res.status(400).json({error:'Auditors cannot receive write grants'})
  const grantId=id()
  db.transaction(()=>{
    run('INSERT INTO resource_grants(id,resource_type,resource_id,grantee_user_id,permission,created_by) VALUES(?,?,?,?,?,?) ON CONFLICT(resource_type,resource_id,grantee_user_id) DO UPDATE SET permission=excluded.permission,created_by=excluded.created_by',grantId,data.type,data.resourceId,data.userId,data.permission,req.user.id)
    audit(req.user.id,'resource.grant','resource',data.resourceId,null,{type:data.type,userId:data.userId,permission:data.permission})
  })()
  res.status(201).json({type:data.type,resourceId:data.resourceId,userId:data.userId,permission:data.permission})
})
api.delete('/access/grants/:id',requireRole('editor'),(req,res)=>{
  const grant=one('SELECT * FROM resource_grants WHERE id=?',reqId(req));if(!grant)return notFound(res,'Grant')
  const resource=resourceRecord(grant.resource_type,grant.resource_id);if(!resource)return notFound(res,'Resource')
  if(!canWriteResource(req.user,grant.resource_type,resource))return res.status(403).json({error:'Insufficient permission'})
  db.transaction(()=>{run('DELETE FROM resource_grants WHERE id=?',grant.id);audit(req.user.id,'resource.grant.revoke','resource',grant.resource_id,{type:grant.resource_type,userId:grant.grantee_user_id,permission:grant.permission},null)})()
  res.status(204).end()
})
api.get('/audit',requireRole('auditor'),(req,res)=>res.json(all('SELECT * FROM audit_log ORDER BY at DESC LIMIT 500')))
api.get('/audit/search',requireRole('auditor'),(req,res)=>{
  const query=z.object({q:z.string().max(200).optional(),action:z.string().max(100).optional(),entityType:z.string().max(100).optional(),actor:z.string().max(200).optional(),from:z.iso.datetime({offset:true}).optional(),to:z.iso.datetime({offset:true}).optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(500).default(100),sortBy:z.enum(['time','action','entity','actor']).default('time'),sortDir:z.enum(['asc','desc']).default('desc'),export:z.enum(['csv','pdf','xls']).optional()}).parse(req.query)
  const conditions=[],values=[]
  for(const [field,column] of [['action','a.action'],['entityType','a.entity_type']])if(query[field]){conditions.push(`${column}=?`);values.push(query[field])}
  if(query.actor){conditions.push('(u.email LIKE ? OR a.actor_user_id LIKE ?)');values.push(`%${query.actor}%`,`%${query.actor}%`)}
  if(query.q){conditions.push('(a.action LIKE ? OR a.entity_type LIKE ? OR a.entity_id LIKE ? OR u.email LIKE ?)');values.push(...Array(4).fill(`%${query.q}%`))}
  if(query.from){conditions.push('a.at>=?');values.push(query.from)}
  if(query.to){conditions.push('a.at<=?');values.push(query.to)}
  const where=conditions.length?'WHERE '+conditions.join(' AND '):''
  const fromSql=`FROM audit_log a LEFT JOIN users u ON u.id=a.actor_user_id ${where}`
  const sortColumn={time:'a.at',action:'a.action',entity:'a.entity_type',actor:'u.email'}[query.sortBy]
  const total=one(`SELECT COUNT(*) count ${fromSql}`,...values).count
  const limit=query.export?50000:query.pageSize,offset=query.export?0:(query.page-1)*query.pageSize
  const items=all(`SELECT a.id,a.at,a.action,a.entity_type,a.entity_id,a.actor_user_id,u.email actor_email ${fromSql} ORDER BY ${sortColumn} ${query.sortDir.toUpperCase()},a.id DESC LIMIT ? OFFSET ?`,...values,limit,offset)
  if(!query.export)return res.json({items,total,page:query.page,pageSize:query.pageSize,totalPages:Math.ceil(total/query.pageSize)})
  const fields=['at','action','entity_type','entity_id','actor_email','actor_user_id']
  if(query.export==='csv'){
    const cell=value=>`"${String(value??'').replace(/^[=+\-@]/,"'$&").replaceAll('"','""')}"`
    return res.type('text/csv').attachment('audit-trail.csv').send([fields.join(','),...items.map(row=>fields.map(key=>cell(row[key])).join(','))].join('\n'))
  }
  if(query.export==='xls'){
    const xml=value=>String(value??'').replace(/[<>&"']/g,char=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&apos;'}[char]))
    const row=values=>`<Row>${values.map(value=>`<Cell><Data ss:Type="String">${xml(value)}</Data></Cell>`).join('')}</Row>`
    const sheet=`<?xml version="1.0"?><Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"><Worksheet ss:Name="Audit trail"><Table>${row(fields)}${items.map(item=>row(fields.map(key=>item[key]))).join('')}</Table></Worksheet></Workbook>`
    return res.type('application/vnd.ms-excel').attachment('audit-trail.xls').send(sheet)
  }
  res.type('application/pdf').attachment('audit-trail.pdf')
  const pdf=new PDFDocument({margin:38});pdf.pipe(res);pdf.fontSize(16).text('WinFire audit trail');pdf.fontSize(8).text(`Generated ${now()} · ${items.length} of ${total} matching records`);pdf.moveDown()
  for(const item of items){pdf.fontSize(8).text(`${item.at}  ${item.action}  ${item.entity_type}/${item.entity_id||'—'}  ${item.actor_email||'system'}`,{width:520});pdf.moveDown(.25)}
  pdf.end()
})
const publicTrainingSettings=()=>({newHostTrainingDays:trainingDays(),progressiveLearning:progressiveSettings()})
api.get('/settings/training',(_req,res)=>res.json(publicTrainingSettings()))
api.patch('/settings/training',requireRole('admin'),(req,res)=>{
  const data=body(z.object({newHostTrainingDays:z.number().int().min(1).max(365),progressiveLearning:z.object({enabled:z.boolean(),startDays:z.number().int().min(1).max(364),intervalHours:z.number().int().min(1).max(168)}).optional()}),req)
  const before=publicTrainingSettings()
  if(data.progressiveLearning?.enabled&&data.progressiveLearning.startDays>=data.newHostTrainingDays)return res.status(400).json({error:'Progressive learning must start before the training period ends'})
  db.transaction(()=>{
    run("UPDATE app_settings SET value=? WHERE key='new_host_training_days'",String(data.newHostTrainingDays))
    if(data.progressiveLearning){
      for(const [key,value] of [['progressive_learning_enabled',data.progressiveLearning.enabled],['progressive_learning_start_days',data.progressiveLearning.startDays],['progressive_learning_interval_hours',data.progressiveLearning.intervalHours]])run('UPDATE app_settings SET value=? WHERE key=?',String(value),key)
    }
    audit(req.user.id,'training.settings.update','app-settings','training',before,{newHostTrainingDays:data.newHostTrainingDays,progressiveLearning:data.progressiveLearning||before.progressiveLearning})
  })()
  res.json(publicTrainingSettings())
})
api.get('/settings/observability',requireRole('admin'),(_req,res)=>res.json(observabilitySettings()))
api.get('/settings/logs-display',(_req,res)=>res.json({hideLoopbackEvents:observabilitySettings().hideLoopbackEvents}))
api.patch('/settings/observability',requireRole('admin'),(req,res)=>{
  const data=body(z.object({logRetentionDays:z.number().int().min(1).max(3650),dnsRefreshHours:z.number().int().min(1).max(720),eventCompactHours:z.number().int().min(1).max(720).optional(),hideLoopbackEvents:z.boolean().optional(),ignoreLoopbackIngest:z.boolean().optional()}),req)
  const before=observabilitySettings()
  db.transaction(()=>{
    run("UPDATE app_settings SET value=? WHERE key='log_retention_days'",String(data.logRetentionDays))
    run("UPDATE app_settings SET value=? WHERE key='dns_refresh_hours'",String(data.dnsRefreshHours))
    if(data.eventCompactHours!==undefined)run("UPDATE app_settings SET value=? WHERE key='event_compact_hours'",String(data.eventCompactHours))
    if(data.hideLoopbackEvents!==undefined)run("UPDATE app_settings SET value=? WHERE key='hide_loopback_events'",String(data.hideLoopbackEvents))
    if(data.ignoreLoopbackIngest!==undefined)run("UPDATE app_settings SET value=? WHERE key='ignore_loopback_ingest'",String(data.ignoreLoopbackIngest))
    audit(req.user.id,'observability.settings.update','app-settings','observability',before,data)
  })()
  res.json(observabilitySettings())
})
api.get('/settings/directory',requireRole('admin'),(_req,res)=>res.json(publicDirectory(directorySettings())))
api.patch('/settings/directory',requireRole('admin'),(req,res)=>{
  const data=body(z.object({
    url:z.string().url().refine(value=>{const parsed=new URL(value);return parsed.protocol==='ldaps:'&&!parsed.username&&!parsed.password&&parsed.pathname==='/'&&!parsed.search&&!parsed.hash},{message:'Use an ldaps:// server URL without embedded credentials or query parameters'}),
    baseDn:z.string().min(3).max(512).refine(value=>/(^|,)\s*DC=/i.test(value),{message:'Search base must include a DC component'}),
    bindCredentialId:z.string().min(1),nodeCredentialId:z.string().nullable().optional(),enabled:z.boolean().default(false),syncIntervalMinutes:z.number().int().min(5).max(1440).default(60),allowLdapFallback:z.boolean().optional(),ldapFallbackApproval:z.string().optional()
  }),req)
  for(const credentialId of [data.bindCredentialId,data.nodeCredentialId].filter(Boolean)){
    const credential=one('SELECT * FROM credentials WHERE id=?',credentialId)
    if(!credential||!canUseCredential(req.user,credential))return res.status(400).json({error:'Selected directory credential is unavailable'})
  }
  const prior=directorySettings(),before=publicDirectory(prior)
  const allowLdapFallback=data.allowLdapFallback===undefined?!!prior.allow_ldap_fallback:data.allowLdapFallback
  const scopeChanged=data.url!==prior.url||data.bindCredentialId!==prior.bind_credential_id
  const needsApproval=allowLdapFallback&&(!prior.allow_ldap_fallback||!prior.ldap_fallback_approved_at||scopeChanged)
  if(needsApproval&&data.ldapFallbackApproval!=='ALLOW LDAP 389')return res.status(400).json({error:'Administrator approval is required: type ALLOW LDAP 389 to permit an unencrypted bind when LDAPS is unavailable'})
  const approvedAt=needsApproval?now():allowLdapFallback?prior.ldap_fallback_approved_at:null
  const approvedBy=needsApproval?req.user.id:allowLdapFallback?prior.ldap_fallback_approved_by:null
  db.transaction(()=>{
    run("UPDATE directory_connections SET url=?,base_dn=?,bind_credential_id=?,node_credential_id=?,enabled=?,sync_interval_minutes=?,allow_ldap_fallback=?,ldap_fallback_approved_by=?,ldap_fallback_approved_at=?,last_transport=CASE WHEN ? THEN NULL ELSE last_transport END,last_sync_status=CASE WHEN ? THEN NULL ELSE last_sync_status END,last_sync_error=CASE WHEN ? THEN NULL ELSE last_sync_error END WHERE id='default'",data.url,data.baseDn,data.bindCredentialId,data.nodeCredentialId||null,Number(data.enabled),data.syncIntervalMinutes,Number(allowLdapFallback),approvedBy,approvedAt,Number(scopeChanged),Number(scopeChanged),Number(scopeChanged))
    if(needsApproval)audit(req.user.id,'directory.ldap_fallback.approve','directory','default',null,{url:data.url,bindCredentialId:data.bindCredentialId,approvedAt})
    if(prior.allow_ldap_fallback&&!allowLdapFallback)audit(req.user.id,'directory.ldap_fallback.revoke','directory','default',null,{url:data.url})
    audit(req.user.id,'directory.settings.update','directory','default',before,{url:data.url,baseDn:data.baseDn,bindCredentialId:data.bindCredentialId,nodeCredentialId:data.nodeCredentialId||null,enabled:data.enabled,syncIntervalMinutes:data.syncIntervalMinutes,allowLdapFallback})
  })()
  res.json(publicDirectory(directorySettings()))
})
api.post('/directory/test',requireRole('admin'),wrap(async(req,res)=>{
  const settings=directorySettings()
  if(!settings?.url||!settings.base_dn)throw Object.assign(new Error('Configure the directory connection first'),{status:400})
  const result=await testDirectoryConnection(settings,directoryCredential(settings))
  audit(req.user.id,'directory.test','directory','default',null,{connected:result.connected,transport:result.transport,fallbackUsed:result.fallbackUsed})
  res.json(result)
}))
let directorySyncInFlight=false
export async function syncDirectory(actorId=null,clientFactory=undefined) {
  if(directorySyncInFlight)throw Object.assign(new Error('Directory sync is already running'),{status:409})
  directorySyncInFlight=true
  try {
  const settings=directorySettings()
  if(!settings?.enabled)throw Object.assign(new Error('Directory sync is disabled'),{status:409})
  if(!settings.url||!settings.base_dn)throw Object.assign(new Error('Directory connection is incomplete'),{status:400})
  run("UPDATE directory_connections SET last_sync_attempt_at=?,last_sync_status='running',last_sync_error=NULL WHERE id='default'",now())
  try {
    const {computers,transport}=await readDirectoryComputers(settings,directoryCredential(settings),clientFactory)
    const seenAt=now(),stats={found:computers.length,created:0,updated:0,missing:0,transport,fallbackUsed:transport==='ldap'}
    db.transaction(()=>{
      run('UPDATE nodes SET ad_missing=1 WHERE ad_guid IS NOT NULL')
      for(const computer of computers){
        let node=one('SELECT * FROM nodes WHERE ad_guid=?',computer.guid)
        if(!node)node=one('SELECT * FROM nodes WHERE fqdn=? COLLATE NOCASE AND ad_guid IS NULL',computer.fqdn)
        if(!node){const matches=all('SELECT * FROM nodes WHERE hostname=? COLLATE NOCASE AND ad_guid IS NULL',computer.name);if(matches.length===1)node=matches[0]}
        if(node){
          const hasFacts=!!one('SELECT 1 FROM node_facts WHERE node_id=?',node.id)
          run('UPDATE nodes SET hostname=?,fqdn=?,ad_guid=?,ad_sid=?,ad_dn=?,ad_snapshot_json=?,ad_last_seen_at=?,ad_enabled=?,ad_missing=0,inventory_source=?,os_version=?,os_build=? WHERE id=?',computer.name,computer.fqdn,computer.guid,computer.sid,computer.dn,json(computer),seenAt,Number(computer.enabled),node.inventory_source.startsWith('manual')?'manual+ad':'ad',hasFacts?node.os_version:computer.operatingSystem||node.os_version,hasFacts?node.os_build:computer.operatingSystemVersion||node.os_build,node.id)
          if(computer.enabled&&node.firewall_state==='unmanaged'&&!one('SELECT 1 FROM learning_sessions WHERE node_id=?',node.id))startTraining(node,trainingDays(),'auto',actorId)
          stats.updated++
        } else {
          const nodeId=id()
          run("INSERT INTO nodes(id,hostname,fqdn,os_version,os_build,inventory_source,ad_guid,ad_sid,ad_dn,ad_snapshot_json,ad_last_seen_at,ad_enabled,ad_missing,firewall_state) VALUES(?,?,?,?,?,'ad',?,?,?,?,?,?,0,?)",nodeId,computer.name,computer.fqdn,computer.operatingSystem||null,computer.operatingSystemVersion||null,computer.guid,computer.sid,computer.dn,json(computer),seenAt,Number(computer.enabled),computer.enabled?'enforcing':'unmanaged')
          node=getNode(nodeId)
          if(computer.enabled)startTraining(node,trainingDays(),'auto',actorId)
          audit(actorId,'directory.node.import','node',nodeId,null,{guid:computer.guid,fqdn:computer.fqdn})
          stats.created++
        }
        if(settings.node_credential_id&&!one('SELECT 1 FROM credential_assignments WHERE credential_id=? AND node_id=?',settings.node_credential_id,node.id))run('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)',settings.node_credential_id,node.id)
      }
      stats.missing=one('SELECT COUNT(*) n FROM nodes WHERE ad_guid IS NOT NULL AND ad_missing=1')?.n||0
      run("UPDATE directory_connections SET last_synced_at=?,last_sync_status='success',last_sync_error=NULL,last_sync_count=?,last_transport=? WHERE id='default'",seenAt,stats.found,transport)
      audit(actorId,'directory.sync','directory','default',null,stats)
    })()
    return stats
  } catch(error) {
    run("UPDATE directory_connections SET last_sync_status='failed',last_sync_error=? WHERE id='default'",error.message.slice(0,2000))
    audit(actorId,'directory.sync.failed','directory','default',null,{error:error.message})
    throw error
  }
  } finally {directorySyncInFlight=false}
}
api.post('/directory/sync',requireRole('admin'),wrap(async(req,res)=>res.json(await syncDirectory(req.user.id))))

const visibleCredentials=user=>(user.role==='owner'||user.role==='admin' ? all('SELECT id,name,type,username,owner_user_id,visibility,team_id,priority,created_at FROM credentials ORDER BY priority,name') : all(`SELECT id,name,type,username,owner_user_id,visibility,team_id,priority,created_at FROM credentials WHERE owner_user_id=? OR (visibility='team' AND team_id=?) OR EXISTS (SELECT 1 FROM resource_grants g WHERE g.resource_type='credential' AND g.resource_id=credentials.id AND g.grantee_user_id=?) ORDER BY priority,name`,user.id,user.team_id,user.id)).map(credential=>({...credential,canWrite:canWriteResource(user,'credential',credential)}))
api.get('/credentials',(req,res)=>res.json(visibleCredentials(req.user)))
api.post('/credentials',requireRole('editor'),(req,res)=>{
  const data=body(z.object({name:z.string().min(1),type:z.enum(['local','domain']),username:z.string().min(1),password:z.string().min(1),visibility:z.enum(['private','team']).default('private'),teamId:z.string().optional(),priority:z.number().int().default(100)}),req)
  const credentialId=id();run('INSERT INTO credentials(id,name,type,username,encrypted_blob,owner_user_id,visibility,team_id,priority) VALUES(?,?,?,?,?,?,?,?,?)',credentialId,data.name,data.type,data.username,seal({password:data.password}),req.user.id,data.visibility,data.teamId||req.user.team_id||null,data.priority)
  audit(req.user.id,'credential.create','credential',credentialId,null,{name:data.name,type:data.type});res.status(201).json({id:credentialId,name:data.name,type:data.type,username:data.username,visibility:data.visibility})
})
api.patch('/credentials/:id',requireRole('editor'),(req,res)=>{
  const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res)
  if(!canWriteResource(req.user,'credential',credential))return res.status(403).json({error:'Insufficient permission'})
  const data=body(z.object({name:z.string().min(1).optional(),username:z.string().min(1).optional(),password:z.string().min(1).optional(),priority:z.number().int().optional()}),req)
  db.transaction(()=>{
    run('UPDATE credentials SET name=?,username=?,encrypted_blob=?,priority=? WHERE id=?',data.name||credential.name,data.username||credential.username,data.password?seal({password:data.password}):credential.encrypted_blob,data.priority??credential.priority,credential.id)
    if(data.password||data.username&&data.username!==credential.username){
      const directory=directorySettings()
      if(directory?.bind_credential_id===credential.id&&directory.allow_ldap_fallback&&directory.ldap_fallback_approved_at){
        run("UPDATE directory_connections SET ldap_fallback_approved_by=NULL,ldap_fallback_approved_at=NULL WHERE id='default'")
        audit(req.user.id,'directory.ldap_fallback.revoke','directory','default',null,{reason:'bind_credential_changed',bindCredentialId:credential.id})
      }
    }
    audit(req.user.id,'credential.rotate','credential',credential.id,null,{rotated:!!data.password})
  })()
  res.json({id:credential.id,name:data.name||credential.name})
})
api.delete('/credentials/:id',requireRole('editor'),(req,res)=>{const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res);if(!canWriteResource(req.user,'credential',credential))return res.status(403).json({error:'Insufficient permission'});db.transaction(()=>{run("DELETE FROM resource_grants WHERE resource_type='credential' AND resource_id=?",credential.id);run('DELETE FROM credentials WHERE id=?',credential.id);audit(req.user.id,'credential.delete','credential',credential.id,null,null)})();res.status(204).end()})
api.post('/credentials/:id/assignments',requireRole('editor'),(req,res)=>{
  const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res)
  if(!canUseCredential(req.user,credential))return res.status(403).json({error:'Insufficient permission'})
  const data=body(z.object({nodeId:z.string().optional(),nodeGroupId:z.string().optional()}),req)
  if(Number(!!data.nodeId)+Number(!!data.nodeGroupId)!==1)return res.status(400).json({error:'Specify exactly one nodeId or nodeGroupId'})
  if(data.nodeId&&!getNode(data.nodeId))return notFound(res,'Node')
  const targetGroup=data.nodeGroupId?one('SELECT * FROM node_groups WHERE id=?',data.nodeGroupId):null
  if(data.nodeGroupId&&!targetGroup)return notFound(res,'Node group')
  if(targetGroup&&!canWriteResource(req.user,'node_group',targetGroup))return res.status(403).json({error:'Insufficient permission for node group'})
  if(one('SELECT 1 FROM credential_assignments WHERE credential_id=? AND node_id IS ? AND node_group_id IS ?',credential.id,data.nodeId||null,data.nodeGroupId||null))return res.json({ok:true,alreadyAssigned:true})
  run('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,?)',reqId(req),data.nodeId||null,data.nodeGroupId||null)
  audit(req.user.id,'credential.assign','credential',reqId(req),null,data);res.status(201).json({ok:true})
})
api.post('/credentials/:id/test',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({nodeId:z.string()}),req),node=getNode(data.nodeId)
  if(!node)return notFound(res,'Node')
  const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res,'Credential')
  if(!canUseCredential(req.user,credential))return res.status(403).json({error:'Insufficient permission'})
  const assigned=one('SELECT 1 FROM credential_assignments WHERE credential_id=? AND (node_id=? OR node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?))',credential.id,node.id,node.id)
  if(!assigned)return res.status(400).json({error:'Assign credential to node first'})
  try {const account=await remote(node,'auth',{}, {credentialId:credential.id});res.json({success:true,account})}catch(error){res.json({success:false,error:error.message})}
}))

api.get('/nodes',(_req,res)=>res.json(all('SELECT n.*,f.snapshot_json FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id ORDER BY n.created_at DESC').map(publicNode)))
api.post('/nodes',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({hostname:z.string().min(1),fqdn:z.string().optional(),ip:z.string().optional(),connectionMode:z.enum(['agentless','agent']).default('agentless'),credentialIds:z.array(z.string()).default([])}),req)
  if(data.credentialIds.some(credentialId=>!canUseCredential(req.user,one('SELECT * FROM credentials WHERE id=?',credentialId))))return res.status(403).json({error:'Credential unavailable'})
  const nodeId=id(),days=trainingDays()
  const training=db.transaction(()=>{
    run('INSERT INTO nodes(id,hostname,fqdn,ip,connection_mode) VALUES(?,?,?,?,?)',nodeId,data.hostname,data.fqdn||null,data.ip||null,data.connectionMode)
    for(const credentialId of data.credentialIds)run('INSERT OR IGNORE INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)',credentialId,nodeId)
    audit(req.user.id,'node.create','node',nodeId,null,data)
    return startTraining(getNode(nodeId),days,'auto',req.user.id)
  })()
  const node=getNode(nodeId),dns=await lookupDns(node);res.status(201).json({...node,dns,training})
}))
api.get('/nodes/:id',(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json({...node,ad:parse(node.ad_snapshot_json),training:latestTraining(node.id)||null,verification:latestVerification(node.id),facts:parse(one('SELECT snapshot_json FROM node_facts WHERE node_id=?',node.id)?.snapshot_json),dns:one('SELECT * FROM dns_lookups WHERE node_id=?',node.id),groups:all('SELECT g.* FROM node_groups g JOIN node_group_members m ON m.group_id=g.id WHERE m.node_id=? ORDER BY g.name',node.id).filter(group=>canReadResource(req.user,'node_group',group)).map(group=>({id:group.id,name:group.name,canWrite:canWriteResource(req.user,'node_group',group)}))})})
api.post('/nodes/:id/training',requireRole('editor'),(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const {durationDays}=body(z.object({durationDays:z.number().int().min(1).max(365)}),req)
  const session=db.transaction(()=>startTraining(node,durationDays,'auto',req.user.id))()
  res.status(201).json(session)
})
api.patch('/nodes/:id',requireRole('editor'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const data=body(z.object({hostname:z.string().trim().min(1).optional(),fqdn:z.string().trim().nullable().optional(),ip:z.string().refine(value=>isIP(value)!==0,'Invalid IP address').nullable().optional(),connectionMode:z.enum(['agentless','agent']).optional()}),req)
  const hostname=data.hostname??node.hostname,fqdn=data.fqdn===undefined?node.fqdn:data.fqdn,ip=data.ip===undefined?node.ip:data.ip,mode=data.connectionMode||node.connection_mode
  if(node.ad_guid&&(hostname!==node.hostname||fqdn!==node.fqdn))return res.status(409).json({error:'Active Directory manages this computer name and FQDN; edit them in the directory'})
  if(mode==='agent'&&!node.agent_id)return res.status(409).json({error:'Enroll an agent before switching to agent mode'})
  if(mode==='agentless'&&node.agent_id)return res.status(409).json({error:'Revoke the agent before switching to agentless mode'})
  const targetChanged=(fqdn||ip||hostname)!==(node.fqdn||node.ip||node.hostname)
  if(targetChanged&&one('SELECT id FROM policy_assignments WHERE node_id=? OR node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?)',node.id,node.id))return res.status(409).json({error:'Remove assigned policies before changing the management address; existing firewall rules may still be present on the old host'})
  const identityChanged=hostname!==node.hostname||fqdn!==node.fqdn||ip!==node.ip
  db.transaction(()=>{
    run('UPDATE nodes SET hostname=?,fqdn=?,ip=?,connection_mode=?,transport=?,status=?,failures=?,next_retry_at=? WHERE id=?',hostname,fqdn,ip,mode,targetChanged?null:node.transport,targetChanged?'unknown':node.status,targetChanged?0:node.failures,targetChanged?null:node.next_retry_at,node.id)
    if(targetChanged)run('DELETE FROM node_facts WHERE node_id=?',node.id)
    audit(req.user.id,'node.update','node',node.id,node,{hostname,fqdn,ip,connectionMode:mode,targetChanged})
  })()
  if(identityChanged)await lookupDns(getNode(node.id))
  res.json(getNode(node.id))
}))
api.delete('/nodes/:id',requireRole('admin'),(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  if(node.ad_guid)return res.status(409).json({error:'This computer is managed by Active Directory and will be imported again. Remove it from the directory search scope first.'})
  if(one('SELECT id FROM agents WHERE node_id=? AND revoked_at IS NULL',node.id))return res.status(409).json({error:'Revoke the enrolled agent before removing this node'})
  if(one("SELECT id FROM break_glass_sessions WHERE node_id=? AND status IN ('activating','activation-unknown','active','ending')",node.id))return res.status(409).json({error:'End break glass before removing this node'})
  if(one('SELECT id FROM identity_segments WHERE node_id=?',node.id))return res.status(409).json({error:'Remove identity segments for this node before deleting it'})
  if(one('SELECT id FROM policy_assignments WHERE node_id=? OR node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?)',node.id,node.id))return res.status(409).json({error:'Remove policy assignments for this node and its groups before deleting it; managed firewall rules may still be present on the host'})
  db.transaction(()=>{
    run('DELETE FROM credential_assignments WHERE node_id=?',node.id)
    run('DELETE FROM enrollment_tokens WHERE node_id=?',node.id)
    run('DELETE FROM node_group_members WHERE node_id=?',node.id)
    run('DELETE FROM learning_sessions WHERE node_id=?',node.id)
    run('DELETE FROM agent_jobs WHERE agent_id IN (SELECT id FROM agents WHERE node_id=?)',node.id)
    run('DELETE FROM agents WHERE node_id=?',node.id)
    run('DELETE FROM nodes WHERE id=?',node.id)
    audit(req.user.id,'node.delete','node',node.id,node,{inventoryRemoved:true,historyRetained:true})
  })()
  res.status(204).end()
})
api.post('/nodes/:id/probe',requireRole('editor'),wrap(async(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json(await probeNode(node))}))
function queueBreakGlassJob(node,type,payload){
  const agent=one('SELECT id,last_checkin_at FROM agents WHERE id=? AND revoked_at IS NULL',node.agent_id)
  if(!agent)throw Object.assign(new Error('No active agent is enrolled on this node'),{status:409})
  if(!agent.last_checkin_at||Date.parse(agent.last_checkin_at)<Date.now()-5*60_000)throw Object.assign(new Error('Agent is offline; break glass requires an online agent'),{status:409})
  const jobId=id()
  run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',jobId,agent.id,type,json(payload))
  return jobId
}
async function endBreakGlass(session,actorId=null,finalStatus='ended'){
  const node=getNode(session.node_id)
  if(!node)throw Object.assign(new Error('Node is missing'),{status:404})
  if(node.connection_mode==='agent'){
    if(session.status==='ending')return {queued:true,session:publicBreakGlass(session)}
    const jobId=queueBreakGlassJob(node,'breakglass.end',{action:'end',breakGlassSessionId:session.id,sessionId:session.id,profiles:parse(session.profile_snapshot_json)||[],finalStatus})
    run("UPDATE break_glass_sessions SET status='ending',agent_job_id=?,last_error=NULL WHERE id=?",jobId,session.id)
    audit(actorId,'break-glass.end.queued','node',node.id,null,{sessionId:session.id,jobId,finalStatus})
    return {queued:true,session:publicBreakGlass(one('SELECT * FROM break_glass_sessions WHERE id=?',session.id))}
  }
  try{
    const result=await remote(node,'breakglass_end',{sessionId:session.id,profiles:parse(session.profile_snapshot_json)||[]})
    if(result?.restored!==true)throw new Error('Firewall profile restore was not confirmed')
    run('UPDATE break_glass_sessions SET status=?,ended_at=?,last_error=NULL WHERE id=?',finalStatus,now(),session.id)
    audit(actorId,finalStatus==='expired'?'break-glass.expired':'break-glass.end','node',node.id,null,{sessionId:session.id,profiles:result.profiles})
    return {queued:false,session:publicBreakGlass(one('SELECT * FROM break_glass_sessions WHERE id=?',session.id))}
  }catch(error){
    run('UPDATE break_glass_sessions SET last_error=? WHERE id=?',error.message,session.id)
    audit(actorId,'break-glass.end.failed','node',node.id,null,{sessionId:session.id,error:error.message})
    throw Object.assign(new Error(`Firewall restoration was not confirmed: ${error.message}`),{status:502})
  }
}
api.get('/nodes/:id/break-glass',requireRole('admin'),(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const sessions=all('SELECT * FROM break_glass_sessions WHERE node_id=? ORDER BY started_at DESC LIMIT 10',node.id).map(publicBreakGlass)
  res.json({active:sessions.find(session=>['activating','activation-unknown','active','ending'].includes(session.status))||null,history:sessions})
})
api.post('/nodes/:id/break-glass',requireRole('admin'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const data=body(z.object({durationMinutes:z.number().int().min(5).max(240),reason:z.string().trim().min(10).max(500),confirmation:z.literal('OPEN FIREWALL')}),req)
  if(node.connection_mode!=='agent'&&!['winrm','winrms'].includes(node.transport))return res.status(409).json({error:'Break glass requires WinRM or an enrolled agent'})
  if(one("SELECT id FROM break_glass_sessions WHERE node_id=? AND status IN ('activating','activation-unknown','active','ending')",node.id))return res.status(409).json({error:'Break glass is already active or pending for this node'})
  const sessionId=id(),startedAt=now(),expiresAt=new Date(Date.now()+data.durationMinutes*60_000).toISOString()
  run("INSERT INTO break_glass_sessions(id,node_id,actor_user_id,reason,started_at,expires_at,status) VALUES(?,?,?,?,?,?,'activating')",sessionId,node.id,req.user.id,data.reason,startedAt,expiresAt)
  audit(req.user.id,'break-glass.request','node',node.id,null,{sessionId,reason:data.reason,durationMinutes:data.durationMinutes,expiresAt})
  try{
    if(node.connection_mode==='agent'){
      const jobId=queueBreakGlassJob(node,'breakglass.start',{action:'start',breakGlassSessionId:sessionId,sessionId,expiresAt})
      run('UPDATE break_glass_sessions SET agent_job_id=? WHERE id=?',jobId,sessionId)
      return res.status(202).json({queued:true,session:publicBreakGlass(one('SELECT * FROM break_glass_sessions WHERE id=?',sessionId))})
    }
    const result=await remote(node,'breakglass_start',{sessionId,expiresAt})
    const profiles=normalizeProfileSnapshot(result?.profiles)
    if(result?.active!==true||!profiles)throw new Error('Firewall disable readback or profile snapshot was invalid')
    run("UPDATE break_glass_sessions SET status='active',profile_snapshot_json=? WHERE id=?",json(profiles),sessionId)
    audit(req.user.id,'break-glass.active','node',node.id,null,{sessionId,expiresAt,profiles})
    res.status(201).json({queued:false,session:publicBreakGlass(one('SELECT * FROM break_glass_sessions WHERE id=?',sessionId))})
  }catch(error){
    run('UPDATE break_glass_sessions SET status=?,last_error=? WHERE id=?',node.connection_mode==='agent'?'failed':'activation-unknown',error.message,sessionId)
    audit(req.user.id,'break-glass.start.failed','node',node.id,null,{sessionId,error:error.message})
    res.status(error.status||502).json({error:error.message})
  }
}))
api.post('/nodes/:id/break-glass/end',requireRole('admin'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const {sessionId}=body(z.object({sessionId:z.string().uuid()}),req)
  const session=one('SELECT * FROM break_glass_sessions WHERE id=? AND node_id=?',sessionId,node.id)
  if(!session)return notFound(res,'Break-glass session')
  if(!['activating','activation-unknown','active','ending'].includes(session.status))return res.status(409).json({error:'Break glass is not active'})
  if(session.status==='activating'&&node.connection_mode==='agent'){
    const job=one('SELECT status FROM agent_jobs WHERE id=?',session.agent_job_id)
    if(job?.status==='queued'){
      run("UPDATE agent_jobs SET status='failed',error='Cancelled before activation',finished_at=? WHERE id=?",now(),session.agent_job_id)
      run("UPDATE break_glass_sessions SET status='ended',ended_at=? WHERE id=?",now(),session.id)
      audit(req.user.id,'break-glass.cancel','node',node.id,null,{sessionId:session.id})
      return res.json({queued:false,session:publicBreakGlass(one('SELECT * FROM break_glass_sessions WHERE id=?',session.id))})
    }
    return res.status(409).json({error:'Wait for the agent to finish activating break glass before ending it'})
  }
  const result=await endBreakGlass(session,req.user.id)
  res.status(result.queued?202:200).json(result)
}))
api.get('/nodes/:id/facts',(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json(parse(one('SELECT snapshot_json FROM node_facts WHERE node_id=?',node.id)?.snapshot_json)||{})})
api.get('/nodes/:id/audit-policy',wrap(async(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');if(node.connection_mode==='agent')return res.status(409).json({error:'Audit policy inspection requires a WinRM node'});res.json(await remote(node,'audit_policy'))}))
api.post('/nodes/:id/audit-policy/enable',requireRole('admin'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  if(node.connection_mode==='agent')return res.status(409).json({error:'Audit policy changes require a WinRM node'})
  body(z.object({confirmation:z.literal('ENABLE WFP AUDITING')}),req)
  const runId=id()
  run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',runId,node.id,'running')
  let before=null
  try {
    before=await remote(node,'audit_policy')
    const after=await remote(node,'audit_policy_enable')
    if(after?.successEnabled!==true||after?.failureEnabled!==true)throw Object.assign(new Error('Audit policy readback did not confirm success and failure auditing'),{status:502})
    db.transaction(()=>{
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json({operation:'audit_policy_enable',before,after}),now(),runId)
      audit(req.user.id,'node.audit-policy.enable','node',node.id,before,{...after,runId})
    })()
    res.json(after)
  } catch(error){
    db.transaction(()=>{
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',error.message,now(),runId)
      audit(req.user.id,'node.audit-policy.enable.failed','node',node.id,before,{runId,error:error.message})
    })()
    throw error
  }
}))
api.post('/nodes/:id/facts/refresh',requireRole('editor'),wrap(async(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');const facts=await collectFacts(node);audit(req.user.id,'node.facts.refresh','node',node.id,null,facts);res.json(facts)}))
api.get('/nodes/:id/firewall-rules',wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  if(node.connection_mode==='agent')return res.status(409).json({error:'Live rule inventory requires a WinRM node'})
  const {offset,limit}=z.object({offset:z.coerce.number().int().min(0).default(0),limit:z.coerce.number().int().min(1).max(200).default(100)}).parse(req.query)
  const result=await remote(node,'all_rules',{offset,limit})
  res.json({total:Number(result?.total||0),offset,rules:Array.isArray(result?.rules)?result.rules:result?.rules?[result.rules]:[]})
}))
api.get('/nodes/:id/dns',(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json(one('SELECT * FROM dns_lookups WHERE node_id=?',node.id)||{})})
api.post('/nodes/:id/dns/refresh',requireRole('editor'),wrap(async(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json(await lookupDns(node))}))
api.get('/node-groups',(req,res)=>res.json(all('SELECT * FROM node_groups ORDER BY name').filter(group=>canReadResource(req.user,'node_group',group))))
api.get('/node-groups/:id',(req,res)=>{
  const group=one('SELECT * FROM node_groups WHERE id=?',reqId(req));if(!group)return notFound(res,'Node group')
  if(!canReadResource(req.user,'node_group',group))return res.status(403).json({error:'Insufficient permission for node group'})
  const members=all('SELECT n.id,n.hostname,n.fqdn,n.ip,n.status,n.firewall_state FROM nodes n JOIN node_group_members m ON m.node_id=n.id WHERE m.group_id=? ORDER BY n.hostname',group.id)
  res.json({...group,count:members.length,members,canWrite:canWriteResource(req.user,'node_group',group)})
})
api.post('/node-groups',requireRole('editor'),(req,res)=>{const {name}=body(z.object({name:z.string().min(1)}),req),groupId=id();run('INSERT INTO node_groups(id,name,owner_user_id) VALUES(?,?,?)',groupId,name,req.user.id);audit(req.user.id,'node-group.create','node-group',groupId,null,{name});res.status(201).json({id:groupId,name,owner_user_id:req.user.id})})
api.post('/node-groups/:id/members',requireRole('editor'),(req,res)=>{
  const {nodeId}=body(z.object({nodeId:z.string()}),req),node=getNode(nodeId),group=one('SELECT * FROM node_groups WHERE id=?',reqId(req))
  if(!node)return notFound(res,'Node')
  if(!group)return notFound(res,'Node group')
  if(!canWriteResource(req.user,'node_group',group))return res.status(403).json({error:'Insufficient permission for node group'})
  const assigned=all(`SELECT DISTINCT p.id,p.name,v.rules_compiled_json FROM policies p JOIN policy_assignments a ON a.policy_id=p.id JOIN policy_versions v ON v.id=p.current_version_id WHERE a.node_group_id=?`,group.id)
  if(assigned.some(policy=>one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id)))return res.status(409).json({error:'Wait for pending agent firewall cleanup before changing this group'})
  const conflicts=[]
  for(const policy of assigned)conflicts.push(...assignmentConflicts(policy.id,parse(policy.rules_compiled_json)||[],[node]))
  for(let i=0;i<assigned.length;i++)for(let j=i+1;j<assigned.length;j++)for(const match of findRuleConflicts(parse(assigned[i].rules_compiled_json)||[],parse(assigned[j].rules_compiled_json)||[]))conflicts.push({nodeId:node.id,hostname:node.hostname,otherPolicyId:assigned[j].id,otherPolicy:assigned[j].name,...match})
  if(conflicts.length)return rejectConflicts(res,conflicts)
  run('INSERT OR IGNORE INTO node_group_members(group_id,node_id) VALUES(?,?)',group.id,nodeId)
  audit(req.user.id,'node-group.member','node-group',group.id,null,{nodeId});res.json({ok:true})
})
api.delete('/node-groups/:id/members/:nodeId',requireRole('editor'),wrap(async(req,res)=>{
  const group=one('SELECT * FROM node_groups WHERE id=?',reqId(req)),node=getNode(req.params.nodeId)
  if(!group)return notFound(res,'Node group')
  if(!node)return notFound(res,'Node')
  if(group.id==='winfire-global-all-nodes')return res.status(409).json({error:'Every node belongs to the global policy scope'})
  if(!canWriteResource(req.user,'node_group',group))return res.status(403).json({error:'Insufficient permission for node group'})
  if(!one('SELECT 1 FROM node_group_members WHERE group_id=? AND node_id=?',group.id,node.id))return notFound(res,'Group membership')
  const policies=all('SELECT DISTINCT p.* FROM policies p JOIN policy_assignments a ON a.policy_id=p.id WHERE a.node_group_id=?',group.id)
  if(policies.some(policy=>!canWriteResource(req.user,'policy',policy)))return res.status(403).json({error:'Write access to each assigned policy is required to remove this member'})
  if(policies.some(policy=>one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id)))return res.status(409).json({error:'Wait for pending agent firewall cleanup before changing this group'})
  const cleanup=policies.filter(policy=>!one(`SELECT a.id FROM policy_assignments a WHERE a.policy_id=? AND (a.node_id=? OR a.node_group_id IN (SELECT m.group_id FROM node_group_members m WHERE m.node_id=? AND m.group_id<>?))`,policy.id,node.id,node.id,group.id))
  if(cleanup.length&&node.connection_mode==='agent')return res.status(409).json({error:'Removing an agent node from a policy group needs coordinated agent cleanup and is not available yet'})
  const snapshots=[]
  try {
    for(const policy of cleanup){
      const observed=await remote(node,'rules',{group:`WinFireSecure:${policy.id}`})
      snapshots.push({policy,rules:Array.isArray(observed)?observed:observed?[observed]:[]})
    }
  } catch(error){return res.status(502).json({error:`Could not read managed rules before membership removal: ${error.message}`})}
  const completed=[]
  for(const snapshot of snapshots){
    const runId=id()
    run('INSERT INTO policy_apply_runs(id,policy_id,version_id,node_id,status) VALUES(?,?,?,?,?)',runId,snapshot.policy.id,snapshot.policy.current_version_id,node.id,'running')
    try {completed.push({...snapshot,runId,diff:await applyRules(node,snapshot.policy.id,[])})}
    catch(error){
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',error.message,now(),runId)
      const rollbackErrors=[]
      for(const prior of completed.reverse()){
        try {await applyRules(node,prior.policy.id,prior.rules)}
        catch(rollbackError){rollbackErrors.push({policyId:prior.policy.id,error:rollbackError.message})}
        run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',rollbackErrors.find(item=>item.policyId===prior.policy.id)?.error||'Membership removal aborted; original rules restored',now(),prior.runId)
      }
      audit(req.user.id,'node-group.member.remove.failed','node-group',group.id,null,{nodeId:node.id,policyId:snapshot.policy.id,error:error.message,rollbackErrors})
      return res.status(502).json({error:'Firewall cleanup failed; group membership retained',policyId:snapshot.policy.id,detail:error.message,rollbackErrors})
    }
  }
  db.transaction(()=>{
    run('DELETE FROM node_group_members WHERE group_id=? AND node_id=?',group.id,node.id)
    for(const item of completed)run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json(item.diff),now(),item.runId)
    audit(req.user.id,'node-group.member.remove','node-group',group.id,{nodeId:node.id},{cleanedPolicies:completed.map(item=>item.policy.id),retainedByOtherAssignment:policies.length-completed.length})
  })()
  res.json({removed:true,cleanedPolicies:completed.map(item=>item.policy.id),retainedByOtherAssignment:policies.length-completed.length})
}))

api.get('/policies',(req,res)=>res.json(all('SELECT p.*,v.version_no FROM policies p LEFT JOIN policy_versions v ON v.id=p.current_version_id ORDER BY p.created_at DESC').filter(policy=>canReadResource(req.user,'policy',policy)).map(policy=>({...policy,scopes:all('SELECT node_id,node_group_id FROM policy_assignments WHERE policy_id=?',policy.id),verificationStatus:policyVerification(policy.id),learning:policy.origin==='learned'?one('SELECT id,status,ends_at,progressive_enabled,next_progressive_at,last_progressive_at FROM learning_sessions WHERE generated_policy_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1',policy.id):null}))))
api.get('/policies/sync',requireRole('admin'),(_req,res)=>res.json({pending:pendingPolicySync(),schedules:all("SELECT id,execute_at,status,created_at,finished_at,result_json FROM policy_sync_schedules WHERE status IN ('scheduled','running') ORDER BY execute_at") }))
api.post('/policies/sync',requireRole('admin'),wrap(async(req,res)=>{
  const data=body(z.object({executeAt:z.iso.datetime({offset:true}).optional()}),req)
  if(data.executeAt&&Date.parse(data.executeAt)>Date.now()+10_000){
    const scheduleId=id()
    run('INSERT INTO policy_sync_schedules(id,requested_by,execute_at,status) VALUES(?,?,?,?)',scheduleId,req.user.id,data.executeAt,'scheduled')
    audit(req.user.id,'policy.sync.schedule','policy',null,null,{scheduleId,executeAt:data.executeAt})
    return res.status(201).json({id:scheduleId,status:'scheduled',executeAt:data.executeAt})
  }
  const results=await performPolicySync(req.user.id)
  res.json({results,pending:pendingPolicySync().length})
}))
api.delete('/policies/sync/:scheduleId',requireRole('admin'),(req,res)=>{
  const schedule=one("SELECT * FROM policy_sync_schedules WHERE id=? AND status='scheduled'",req.params.scheduleId)
  if(!schedule)return notFound(res,'Scheduled sync')
  run("UPDATE policy_sync_schedules SET status='cancelled',finished_at=? WHERE id=?",now(),schedule.id)
  audit(req.user.id,'policy.sync.cancel','policy',null,schedule,null)
  res.status(204).end()
})
api.post('/policies',requireRole('editor'),(req,res)=>{const data=body(z.object({name:z.string().min(1),description:z.string().default('')}),req),policyId=id();run('INSERT INTO policies(id,name,description,owner_user_id) VALUES(?,?,?,?)',policyId,data.name,data.description,req.user.id);audit(req.user.id,'policy.create','policy',policyId,null,data);res.status(201).json(getPolicy(policyId))})
api.get('/policies/:id',(req,res)=>{const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy');if(!canReadResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'});res.json({...policy,versions:all('SELECT id,version_no,created_at,comment FROM policy_versions WHERE policy_id=? ORDER BY version_no DESC',policy.id),assignments:all('SELECT * FROM policy_assignments WHERE policy_id=?',policy.id)})})
api.get('/policies/:id/versions',(req,res)=>{const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy');if(!canReadResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'});res.json(all('SELECT * FROM policy_versions WHERE policy_id=? ORDER BY version_no DESC',policy.id).map(v=>({...v,graph:parse(v.graph_json),rules:parse(v.rules_compiled_json)})))})
api.get('/policies/:id/learning-preview',(req,res)=>{
  const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy')
  if(!canReadResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'})
  const session=one("SELECT * FROM learning_sessions WHERE generated_policy_id=? AND status='active' ORDER BY started_at DESC,rowid DESC LIMIT 1",policy.id)
  if(!session)return res.status(409).json({error:'This policy has no active learning session'})
  res.json(learningPreview(session))
})
api.post('/policies/:id/versions',requireRole('editor'),(req,res)=>{
  const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy')
  if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'})
  if(hasActiveLearning(policy.id))return res.status(409).json({error:'Automatic learning owns this policy until training ends'})
  if(one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id))return res.status(409).json({error:'Wait for pending agent firewall cleanup before changing this policy'})
  const data=body(z.object({graph:graphSchema,comment:z.string().default('')}),req),rules=compilePolicy(data.graph,policy.id),versionId=id()
  assertManagementAccess(rules)
  const conflicts=assignmentConflicts(policy.id,rules,assignedNodes(policy.id))
  if(conflicts.length)return rejectConflicts(res,conflicts)
  const last=one('SELECT MAX(version_no) as n FROM policy_versions WHERE policy_id=?',policy.id)?.n||0
  db.transaction(()=>{run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,policy.id,last+1,json(data.graph),json(rules),req.user.id,data.comment);run('UPDATE policies SET current_version_id=? WHERE id=?',versionId,policy.id);audit(req.user.id,'policy.version.create','policy',policy.id,null,{versionId,versionNo:last+1,rules})})()
  res.status(201).json({id:versionId,versionNo:last+1,rules})
})
api.post('/policies/:id/versions/:versionId/recall',requireRole('editor'),(req,res)=>{const policy=getPolicy(reqId(req)),version=one('SELECT * FROM policy_versions WHERE id=? AND policy_id=?',req.params.versionId,reqId(req));if(!policy||!version)return notFound(res,'Version');if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'});if(hasActiveLearning(policy.id))return res.status(409).json({error:'Automatic learning owns this policy until training ends'});if(one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id))return res.status(409).json({error:'Wait for pending agent firewall cleanup before changing this policy'});const conflicts=assignmentConflicts(policy.id,parse(version.rules_compiled_json)||[],assignedNodes(policy.id));if(conflicts.length)return rejectConflicts(res,conflicts);run('UPDATE policies SET current_version_id=? WHERE id=?',version.id,policy.id);audit(req.user.id,'policy.recall','policy',policy.id,{versionId:policy.current_version_id},{versionId:version.id});res.json({versionId:version.id,pendingSync:true})})
api.post('/policies/:id/assignments',requireRole('editor'),(req,res)=>{const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy');if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'});if(hasActiveLearning(policy.id))return res.status(409).json({error:'Automatic learning owns this policy until training ends'});if(one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id))return res.status(409).json({error:'Wait for pending agent firewall cleanup before assigning this policy'});if(one("SELECT id FROM learning_sessions WHERE generated_policy_id=? AND status IN ('review','apply-failed')",policy.id))return res.status(409).json({error:'Approve the learning proposal before assigning it'});const data=body(z.object({nodeId:z.string().optional(),nodeGroupId:z.string().optional()}),req);if(Number(!!data.nodeId)+Number(!!data.nodeGroupId)!==1)return res.status(400).json({error:'Specify exactly one nodeId or nodeGroupId'});const targets=data.nodeId?[getNode(data.nodeId)].filter(Boolean):all('SELECT n.* FROM nodes n JOIN node_group_members m ON m.node_id=n.id WHERE m.group_id=?',data.nodeGroupId);if(data.nodeId&&!targets.length)return notFound(res,'Node');const targetGroup=data.nodeGroupId?one('SELECT * FROM node_groups WHERE id=?',data.nodeGroupId):null;if(data.nodeGroupId&&!targetGroup)return notFound(res,'Node group');if(targetGroup&&!canWriteResource(req.user,'node_group',targetGroup))return res.status(403).json({error:'Insufficient permission for node group'});const rules=parse(one('SELECT rules_compiled_json FROM policy_versions WHERE id=?',policy.current_version_id)?.rules_compiled_json)||[];const conflicts=assignmentConflicts(policy.id,rules,targets);if(conflicts.length)return rejectConflicts(res,conflicts);const assignmentId=id();run('INSERT INTO policy_assignments(id,policy_id,node_id,node_group_id,assigned_by) VALUES(?,?,?,?,?)',assignmentId,policy.id,data.nodeId||null,data.nodeGroupId||null,req.user.id);audit(req.user.id,'policy.assign','policy',policy.id,null,data);res.status(201).json({id:assignmentId,...data})})
api.delete('/policies/:id/assignments/:assignmentId',requireRole('editor'),wrap(async(req,res)=>{
  const policy=getPolicy(reqId(req))
  if(!policy)return notFound(res,'Policy')
  if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'})
  if(hasActiveLearning(policy.id))return res.status(409).json({error:'Automatic learning owns this policy until training ends'})
  const assignment=one('SELECT * FROM policy_assignments WHERE id=? AND policy_id=?',req.params.assignmentId,policy.id)
  if(!assignment)return notFound(res,'Assignment')
  const group=assignment.node_group_id?one('SELECT * FROM node_groups WHERE id=?',assignment.node_group_id):null
  if(group&&!canWriteResource(req.user,'node_group',group))return res.status(403).json({error:'Insufficient permission for node group'})
  if(assignment.removal_job_id)return res.status(202).json({queued:true,jobId:assignment.removal_job_id})
  const targets=assignment.node_id?[getNode(assignment.node_id)].filter(Boolean):all('SELECT n.* FROM nodes n JOIN node_group_members m ON m.node_id=n.id WHERE m.group_id=?',assignment.node_group_id)
  const cleanup=targets.filter(node=>!one(`SELECT id FROM policy_assignments WHERE policy_id=? AND id<>? AND (node_id=? OR node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?))`,policy.id,assignment.id,node.id,node.id))
  if(cleanup.some(node=>node.connection_mode==='agent')){
    if(!assignment.node_id||cleanup.length!==1)return res.status(409).json({error:'Group removal with agent nodes needs coordinated cleanup and is not available yet'})
    const node=cleanup[0],agent=one('SELECT * FROM agents WHERE id=? AND revoked_at IS NULL',node.agent_id)
    if(!agent)return res.status(409).json({error:'No active enrolled agent can remove these firewall rules'})
    const pendingApply=all("SELECT * FROM agent_jobs WHERE agent_id=? AND type='policy.apply' AND status IN ('queued','leased') AND json_extract(payload_json,'$.policyId')=?",agent.id,policy.id)
    if(pendingApply.some(job=>job.status==='leased'))return res.status(409).json({error:'Wait for the current agent policy apply job before removing this assignment'})
    const runId=id(),jobId=id()
    db.transaction(()=>{
      for(const job of pendingApply){
        run("UPDATE agent_jobs SET status='failed',error='Superseded by policy unassignment',finished_at=? WHERE id=?",now(),job.id)
        const oldRunId=parse(job.payload_json)?.applyRunId
        if(oldRunId)run("UPDATE policy_apply_runs SET status='failed',error='Superseded by policy unassignment',finished_at=? WHERE id=?",now(),oldRunId)
      }
      run('INSERT INTO policy_apply_runs(id,policy_id,version_id,node_id,status) VALUES(?,?,?,?,?)',runId,policy.id,policy.current_version_id,node.id,'queued')
      run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',jobId,agent.id,'policy.apply',json({applyRunId:runId,policyId:policy.id,versionId:policy.current_version_id,group:`WinFireSecure:${policy.id}`,rules:[],removalAssignmentId:assignment.id}))
      run('UPDATE policy_assignments SET removal_job_id=? WHERE id=?',jobId,assignment.id)
      audit(req.user.id,'policy.unassign.queued','policy',policy.id,assignment,{assignmentId:assignment.id,nodeId:node.id,jobId})
    })()
    return res.status(202).json({queued:true,jobId,nodeId:node.id})
  }
  const snapshots=[]
  try {
    for(const node of cleanup){
      const observed=await remote(node,'rules',{group:`WinFireSecure:${policy.id}`})
      snapshots.push({node,rules:Array.isArray(observed)?observed:observed?[observed]:[]})
    }
  } catch(error){return res.status(502).json({error:`Could not read managed rules before removal: ${error.message}`})}
  const completed=[]
  for(const snapshot of snapshots){
    const runId=id()
    run('INSERT INTO policy_apply_runs(id,policy_id,version_id,node_id,status) VALUES(?,?,?,?,?)',runId,policy.id,policy.current_version_id,snapshot.node.id,'running')
    try {
      const diff=await applyRules(snapshot.node,policy.id,[])
      completed.push({...snapshot,runId,diff})
    } catch(error){
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',error.message,now(),runId)
      const rollbackErrors=[]
      for(const prior of completed.reverse()){
        try {await applyRules(prior.node,policy.id,prior.rules)}
        catch(rollbackError){rollbackErrors.push({nodeId:prior.node.id,error:rollbackError.message})}
        run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',rollbackErrors.find(item=>item.nodeId===prior.node.id)?.error||'Removal aborted; original rules restored',now(),prior.runId)
      }
      audit(req.user.id,'policy.unassign.failed','policy',policy.id,null,{assignmentId:assignment.id,nodeId:snapshot.node.id,error:error.message,rollbackErrors})
      return res.status(502).json({error:'Firewall cleanup failed; assignment retained',nodeId:snapshot.node.id,detail:error.message,rollbackErrors})
    }
  }
  db.transaction(()=>{
    run('DELETE FROM policy_assignments WHERE id=?',assignment.id)
    for(const item of completed)run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json(item.diff),now(),item.runId)
    audit(req.user.id,'policy.unassign','policy',policy.id,assignment,{assignmentId:assignment.id,cleanedNodes:completed.map(item=>item.node.id),retainedByOtherAssignment:targets.length-completed.length})
  })()
  res.json({removed:true,cleanedNodes:completed.map(item=>item.node.id),retainedByOtherAssignment:targets.length-completed.length})
}))
api.post('/policies/:id/apply',requireRole('admin'),wrap(async(req,res)=>{const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy');if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'});if(hasActiveLearning(policy.id))return res.status(409).json({error:'Automatic learning owns this policy until training ends'});if(one("SELECT id FROM learning_sessions WHERE generated_policy_id=? AND status IN ('review','apply-failed')",policy.id))return res.status(409).json({error:'Approve the learning proposal before applying it'});res.json({results:await applyPolicy(policy,req.user.id)})}))
api.get('/policies/:id/diff',(req,res)=>{
  const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy')
  if(!canReadResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'})
  const a=one('SELECT * FROM policy_versions WHERE id=? AND policy_id=?',req.query.from,reqId(req)),b=one('SELECT * FROM policy_versions WHERE id=? AND policy_id=?',req.query.to,reqId(req))
  if(!a||!b)return notFound(res,'Version')
  const left=parse(a.rules_compiled_json)||[],right=parse(b.rules_compiled_json)||[]
  const before=parse(a.graph_json)||{nodes:[],edges:[]},after=parse(b.graph_json)||{nodes:[],edges:[]}
  const oldNodes=new Map(before.nodes.map(node=>[node.id,node])),newNodes=new Map(after.nodes.map(node=>[node.id,node]))
  const edgeKey=edge=>`${edge.source}\u0000${edge.target}`
  const oldEdges=new Set(before.edges.map(edgeKey)),newEdges=new Set(after.edges.map(edgeKey))
  res.json({
    from:{id:a.id,versionNo:a.version_no},to:{id:b.id,versionNo:b.version_no},
    added:right.filter(rule=>!left.some(previous=>JSON.stringify(previous)===JSON.stringify(rule))),
    removed:left.filter(rule=>!right.some(next=>JSON.stringify(next)===JSON.stringify(rule))),
    graph:{
      addedNodes:after.nodes.filter(node=>!oldNodes.has(node.id)),
      removedNodes:before.nodes.filter(node=>!newNodes.has(node.id)),
      changedNodes:after.nodes.filter(node=>oldNodes.has(node.id)&&JSON.stringify(oldNodes.get(node.id))!==JSON.stringify(node)).map(node=>({before:oldNodes.get(node.id),after:node})),
      addedEdges:after.edges.filter(edge=>!oldEdges.has(edgeKey(edge))),
      removedEdges:before.edges.filter(edge=>!newEdges.has(edgeKey(edge)))
    }
  })
})

export async function runDriftCheck(data={},actorId=null,canCheckPolicy=()=>true) {
  if(data.policyId&&!getPolicy(data.policyId))throw Object.assign(new Error('Policy not found'),{status:404})
  if(data.nodeId&&!getNode(data.nodeId))throw Object.assign(new Error('Node not found'),{status:404})
  const policies=(data.policyId?[getPolicy(data.policyId)]:all('SELECT * FROM policies WHERE current_version_id IS NOT NULL')).filter(canCheckPolicy)
  const checks=[]
  for(const policy of policies){
    const version=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
    if(!version)continue
    const desired=parse(version.rules_compiled_json)||[]
    for(const node of assignedNodes(policy.id).filter(item=>!data.nodeId||item.id===data.nodeId)){
      if(node.connection_mode==='agent'){
        const pending=one(`SELECT d.* FROM policy_drift_checks d JOIN agent_jobs j ON json_extract(j.payload_json,'$.driftCheckId')=d.id WHERE d.node_id=? AND d.policy_id=? AND d.version_id=? AND d.status='pending' AND j.status IN ('queued','leased') ORDER BY datetime(d.checked_at) DESC LIMIT 1`,node.id,policy.id,version.id)
        if(pending){checks.push({id:pending.id,policyId:policy.id,versionId:version.id,nodeId:node.id,status:'pending',diff:null,error:null,checkedAt:pending.checked_at,reused:true});continue}
      }
      let status='unknown',diff=null,error=null,agent=null
      try {
        if(node.connection_mode==='agent'){
          agent=one('SELECT * FROM agents WHERE id=? AND revoked_at IS NULL',node.agent_id)
          if(!agent)throw new Error('No active enrolled agent for firewall readback')
          status='pending'
        } else {
          const observed=await remote(node,'rules',{group:`WinFireSecure:${policy.id}`})
          diff=diffRules(desired,Array.isArray(observed)?observed:observed?[observed]:[])
          status=diff.add.length||diff.remove.length?'drift':'in-sync'
        }
      } catch(cause){error=cause.message}
      const check={id:id(),policyId:policy.id,versionId:version.id,nodeId:node.id,status,diff,error,checkedAt:now()}
      const previous=one('SELECT status FROM policy_drift_checks WHERE policy_id=? AND node_id=? AND version_id=? ORDER BY checked_at DESC,rowid DESC LIMIT 1',policy.id,node.id,version.id)?.status
      db.transaction(()=>{
        run('INSERT INTO policy_drift_checks(id,policy_id,version_id,node_id,status,diff_json,error,checked_at) VALUES(?,?,?,?,?,?,?,?)',check.id,check.policyId,check.versionId,check.nodeId,check.status,json(check.diff),check.error,check.checkedAt)
        if(status==='pending')run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',id(),agent.id,'policy.read',json({driftCheckId:check.id,policyId:policy.id,versionId:version.id,group:`WinFireSecure:${policy.id}`}))
      })()
      if(status==='drift'&&previous!=='drift')emitNotification({eventKey:`drift:${check.id}`,category:'policy_drift',title:'Policy drift detected',body:`${policy.name} differs from the firewall rules on ${node.hostname}.`,entityType:'node',entityId:node.id})
      checks.push(check)
    }
  }
  audit(actorId,'policy.drift.check','policy',data.policyId||null,null,{nodeId:data.nodeId||null,checks:checks.length,drift:checks.filter(check=>check.status==='drift').length,unknown:checks.filter(check=>check.status==='unknown').length})
  return {checks}
}
api.post('/drift/checks',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({nodeId:z.string().optional(),policyId:z.string().optional()}),req)
  if(data.policyId&&!canWriteResource(req.user,'policy',getPolicy(data.policyId)))return res.status(403).json({error:'Insufficient permission for policy'})
  res.status(201).json(await runDriftCheck(data,req.user.id,policy=>canWriteResource(req.user,'policy',policy)))
}))
api.get('/drift/checks',(req,res)=>{
  const filters=[],args=[]
  if(req.query.nodeId){filters.push('node_id=?');args.push(String(req.query.nodeId))}
  if(req.query.policyId){filters.push('policy_id=?');args.push(String(req.query.policyId))}
  const visible=readablePolicyIds(req.user)
  res.json(all(`SELECT * FROM policy_drift_checks ${filters.length?'WHERE '+filters.join(' AND '):''} ORDER BY datetime(checked_at) DESC LIMIT 500`,...args).filter(row=>visible.has(row.policy_id)).map(row=>({...row,diff:parse(row.diff_json)})))
})

async function verifyOne(node,policy,rule,runId,actualRules) {
  const singleTcpPort=rule.direction==='in' && rule.protocol==='TCP' && /^\d{1,5}$/.test(String(rule.localPort))
  const port=singleTcpPort?Number(rule.localPort):null
  const supported=port!==null && port>=1 && port<=65535
  const started=Date.now(),probe=supported?await tcpProbe(node.ip||node.fqdn||node.hostname,port,1500):null
  const managedRulePresent=actualRules===null?null:hasManagedRule(rule,actualRules)
  const evidence=supported?classifyVerification(rule,probe.status,managedRulePresent):{status:'inconclusive',reason:'Only single-port inbound TCP rules have a network probe'}
  const expected=rule.action==='allow'?'open':'closed',actual=probe?.status==='open'?'open':probe?.status||'not-probed'
  const result={id:id(),runId,nodeId:node.id,policyId:policy.id,port,proto:rule.protocol,expected,actual,probeStatus:probe?.status||null,managedRulePresent,latencyMs:Date.now()-started,...evidence,passed:evidence.status==='inconclusive'?null:evidence.status==='pass'}
  const previous=one('SELECT status FROM verifier_results WHERE node_id=? AND policy_id=? AND port IS ? AND proto=? AND expected=? ORDER BY run_at DESC,rowid DESC LIMIT 1',node.id,policy.id,port,rule.protocol,expected)?.status
  run('INSERT INTO verifier_results(id,run_id,node_id,policy_id,port,proto,expected,actual,latency_ms,passed,status,reason,probe_status,managed_rule_present) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',result.id,runId,node.id,policy.id,port,rule.protocol,expected,actual,result.latencyMs,result.passed===null?null:Number(result.passed),result.status,result.reason,result.probeStatus,result.managedRulePresent===null?null:Number(result.managedRulePresent))
  if(result.status==='fail'&&previous!=='fail')emitNotification({eventKey:`verifier:${result.id}`,category:'verifier_failure',title:'Firewall verification failed',body:`${policy.name} on ${node.hostname}: ${rule.protocol} ${port||'rule'} — ${result.reason}.`,entityType:'node',entityId:node.id})
  return result
}
export async function runVerification(data={},actorId=null,canCheckPolicy=()=>true) {
  const runId=id()
  run('INSERT INTO verifier_runs(id,status,requested_by) VALUES(?,?,?)',runId,'running',actorId)
  const policies=(data.policyId?[getPolicy(data.policyId)].filter(Boolean):all('SELECT * FROM policies WHERE current_version_id IS NOT NULL')).filter(canCheckPolicy)
  const results=[]
  for(const policy of policies){
    const version=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
    const rules=parse(version.rules_compiled_json)||[]
    for(const node of assignedNodes(policy.id).filter(n=>!data.nodeId||n.id===data.nodeId)){
      let actualRules=null
      if(rules.some(rule=>rule.action==='block')) {
        try {const response=await remote(node,'rules',{group:`WinFireSecure:${policy.id}`});actualRules=Array.isArray(response)?response:response?[response]:[]}
        catch {actualRules=null}
      }
      for(const rule of rules){const result=await verifyOne(node,policy,rule,runId,actualRules);if(result)results.push(result)}
    }
  }
  run('UPDATE verifier_runs SET status=?,finished_at=? WHERE id=?','complete',now(),runId)
  audit(actorId,'verifier.run','verifier',runId,null,{results:results.length})
  return {id:runId,status:'complete',results}
}
api.post('/verifier/runs',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({nodeId:z.string().optional(),policyId:z.string().optional()}),req)
  if(data.policyId&&!canWriteResource(req.user,'policy',getPolicy(data.policyId)))return res.status(403).json({error:'Insufficient permission for policy'})
  res.status(201).json(await runVerification(data,req.user.id,policy=>canWriteResource(req.user,'policy',policy)))
}))
api.get('/verifier/runs/:id',(req,res)=>{const result=one('SELECT * FROM verifier_runs WHERE id=?',reqId(req));if(!result)return notFound(res,'Verifier run');const visible=readablePolicyIds(req.user),results=all('SELECT * FROM verifier_results WHERE run_id=?',result.id).filter(row=>visible.has(row.policy_id));if(!results.length&&result.requested_by!==req.user.id&&!['owner','admin'].includes(req.user.role))return notFound(res,'Verifier run');res.json({...result,results})})
api.get('/verifier/results',(req,res)=>{const visible=readablePolicyIds(req.user);res.json(all('SELECT * FROM verifier_results ORDER BY run_at DESC LIMIT 500').filter(row=>visible.has(row.policy_id)))})

function driftSummaryByNode() {
  const assignments=all(`SELECT DISTINCT a.policy_id,COALESCE(a.node_id,m.node_id) node_id FROM policy_assignments a LEFT JOIN node_group_members m ON m.group_id=a.node_group_id WHERE COALESCE(a.node_id,m.node_id) IS NOT NULL`)
  const latest=all(`SELECT d.node_id,d.policy_id,d.status FROM policy_drift_checks d JOIN policies p ON p.id=d.policy_id AND p.current_version_id=d.version_id WHERE d.rowid=(SELECT d2.rowid FROM policy_drift_checks d2 WHERE d2.node_id=d.node_id AND d2.policy_id=d.policy_id AND d2.version_id=d.version_id ORDER BY datetime(d2.checked_at) DESC,d2.rowid DESC LIMIT 1)`)
  const byPair=new Map(latest.map(row=>[`${row.node_id}:${row.policy_id}`,row.status]))
  const byNode=new Map()
  for(const assignment of assignments){
    const statuses=byNode.get(assignment.node_id)||[]
    statuses.push(byPair.get(`${assignment.node_id}:${assignment.policy_id}`)||'unchecked')
    byNode.set(assignment.node_id,statuses)
  }
  return new Map([...byNode].map(([nodeId,statuses])=>[nodeId,statuses.includes('drift')?'drift':statuses.includes('unknown')?'unknown':statuses.includes('pending')?'pending':statuses.includes('unchecked')?'unchecked':'in-sync']))
}
function report(name,user=null) {
  if(name==='inventory')return all(`SELECT n.id,n.hostname,n.fqdn,n.ip,n.os_version,n.os_build,n.status,n.last_seen_at,n.connection_mode,n.inventory_source,n.ad_enabled,n.ad_missing,n.firewall_state,f.snapshot_json,f.collected_at,(SELECT status FROM policy_apply_runs WHERE node_id=n.id AND policy_id IS NOT NULL ORDER BY started_at DESC,rowid DESC LIMIT 1) last_apply_status,(SELECT finished_at FROM policy_apply_runs WHERE node_id=n.id AND policy_id IS NOT NULL ORDER BY started_at DESC,rowid DESC LIMIT 1) last_apply_at,(SELECT status FROM verifier_results WHERE node_id=n.id ORDER BY run_at DESC,rowid DESC LIMIT 1) last_verify_status FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id ORDER BY n.hostname`).map(({snapshot_json,...row})=>{
    const facts=parse(snapshot_json)||{}
    const profiles=Array.isArray(facts.firewall)?facts.firewall:facts.firewall?[facts.firewall]:[]
    return {...row,model:facts.computer?.Model||null,manufacturer:facts.computer?.Manufacturer||null,bios_serial:facts.bios?.SerialNumber||null,firewall_service:facts.service?.Status||null,firewall_profiles:profiles.map(profile=>`${profile.Name}: ${profile.Enabled?'on':'off'}`).join(', ')||null}
  })
  if(name==='dns')return all(`SELECT n.id,n.hostname,n.fqdn,n.ip,d.forward_result,d.reverse_result,d.mismatch,d.checked_at FROM nodes n LEFT JOIN dns_lookups d ON d.node_id=n.id ORDER BY n.hostname`).map(row=>{
    const forward=parse(row.forward_result)||[],reverse=parse(row.reverse_result)||[]
    const expected=String(row.fqdn||row.hostname).toLowerCase().replace(/\.$/,'')
    const ptrMissing=!!(row.ip&&!reverse.length)
    const ptrMismatch=!!(reverse.length&&!reverse.some(name=>String(name).toLowerCase().replace(/\.$/,'')===expected))
    const forwardMismatch=!!(row.ip&&forward.length&&!forward.some(address=>address.address===row.ip))
    return {id:row.id,hostname:row.hostname,fqdn:row.fqdn,ip:row.ip,forward_addresses:forward.map(address=>address.address).join(', '),reverse_names:reverse.join(', '),ptr_missing:ptrMissing,ptr_mismatch:ptrMismatch,forward_mismatch:forwardMismatch,mismatch:ptrMissing||ptrMismatch||forwardMismatch,checked_at:row.checked_at}
  })
  if(name==='coverage'){
    const drift=driftSummaryByNode()
    return all(`SELECT n.id,n.hostname,n.status,COUNT(DISTINCT a.policy_id) AS policy_count,(SELECT status FROM policy_apply_runs WHERE node_id=n.id AND policy_id IS NOT NULL ORDER BY started_at DESC LIMIT 1) AS last_apply_status,(SELECT passed FROM verifier_results WHERE node_id=n.id ORDER BY run_at DESC LIMIT 1) AS last_verify_passed FROM nodes n LEFT JOIN policy_assignments a ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id) GROUP BY n.id ORDER BY n.hostname`).map(row=>({...row,drift_status:drift.get(row.id)||null}))
  }
  if(name==='verification'){
    const visible=user?readablePolicyIds(user):null
    return all(`SELECT n.hostname,p.id AS policy_id,p.name AS policy,r.port,r.proto,r.expected,r.actual,r.status,r.reason,r.managed_rule_present,r.run_at FROM verifier_results r LEFT JOIN nodes n ON n.id=r.node_id LEFT JOIN policies p ON p.id=r.policy_id ORDER BY r.run_at DESC LIMIT 1000`).filter(row=>!visible||visible.has(row.policy_id)).map(({policy_id,...row})=>row)
  }
  const drift=driftSummaryByNode()
  return all(`SELECT n.id,n.hostname,n.status,COUNT(DISTINCT a.policy_id) AS policies,COALESCE((SELECT SUM(passed) FROM verifier_results WHERE node_id=n.id),0) AS checks_passed,COALESCE((SELECT COUNT(passed) FROM verifier_results WHERE node_id=n.id),0) AS checks_decisive,COALESCE((SELECT COUNT(*) FROM verifier_results WHERE node_id=n.id AND passed IS NULL),0) AS checks_inconclusive FROM nodes n LEFT JOIN policy_assignments a ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id) GROUP BY n.id ORDER BY n.hostname`).map(row=>({...row,drift_status:drift.get(row.id)||null}))
}
function exportReport(req,res,name,data) {
  if(req.query.export==='csv'){
    const columns=Object.keys(data[0]||{hostname:''})
    const cell=value=>'"'+String(value??'').replaceAll('"','""')+'"'
    res.type('text/csv').attachment(`${name}.csv`).send([columns.map(cell).join(','),...data.map(row=>columns.map(key=>cell(row[key])).join(','))].join('\n'));return
  }
  if(req.query.export==='pdf'){
    res.type('application/pdf').attachment(`${name}.pdf`)
    const pdf=new PDFDocument({margin:40});pdf.pipe(res);pdf.fontSize(18).text(`WinFire ${name} report`);pdf.fontSize(9).text(`Generated ${now()}`);pdf.moveDown()
    for(const row of data){pdf.fontSize(10).text(Object.entries(row).map(([k,v])=>`${k}: ${typeof v==='string'?v.slice(0,100):v}`).join(' | '),{width:510});pdf.moveDown(.4)}pdf.end();return
  }
  res.json(data)
}
for(const name of ['inventory','dns','coverage','compliance','verification'])api.get(`/reports/${name}`,(req,res)=>exportReport(req,res,name,report(name,req.user)))
api.get('/reports/dashboard',(_req,res)=>{
  const total=one('SELECT COUNT(*) n FROM nodes').n, reachable=one("SELECT COUNT(*) n FROM nodes WHERE status='reachable'").n
  const policies=one('SELECT COUNT(*) n FROM policies').n, failed=one("SELECT COUNT(*) n FROM policy_apply_runs WHERE status='failed' AND policy_id IS NOT NULL").n
  const checks=one('SELECT COUNT(passed) n,COALESCE(SUM(passed),0) passed,COUNT(*)-COUNT(passed) inconclusive FROM verifier_results')
  const agentCutoff=new Date(Date.now()-120_000).toISOString()
  const agents=one('SELECT COUNT(*) total,COALESCE(SUM(CASE WHEN revoked_at IS NULL AND last_checkin_at>=? THEN 1 ELSE 0 END),0) online FROM agents',agentCutoff)
  const denied=all("SELECT COALESCE(e.dst_port,p.dst_port) dst_port,COUNT(*) count FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE e.action='block' GROUP BY COALESCE(e.dst_port,p.dst_port) ORDER BY count DESC LIMIT 6")
  const verifierTrend=all("SELECT date(run_at) day,COUNT(passed) decisive,SUM(CASE WHEN passed=1 THEN 1 ELSE 0 END) passed FROM verifier_results WHERE datetime(run_at)>=datetime('now','-14 days') GROUP BY date(run_at) ORDER BY day").map(row=>({day:row.day,decisive:row.decisive,passRate:row.decisive?Math.round(row.passed/row.decisive*100):null}))
  const mfaTrend=all("SELECT date(resolved_at) day,SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) approved,SUM(CASE WHEN status='denied' THEN 1 ELSE 0 END) denied FROM mfa_challenges WHERE datetime(resolved_at)>=datetime('now','-14 days') GROUP BY date(resolved_at) ORDER BY day")
  const coverage=report('coverage')
  const compliant=coverage.filter(row=>row.policy_count>0&&row.drift_status==='in-sync'&&row.last_apply_status==='success'&&row.last_verify_passed===1).length
  res.json({totalNodes:total,reachableNodes:reachable,agentsOnline:agents.online,agentsOffline:agents.total-agents.online,policies,failedApplies:failed,verifierPassRate:checks.n?Math.round(checks.passed/checks.n*100):null,verifierInconclusive:checks.inconclusive,deniedPorts:denied,compliantNodes:compliant,fleetCompliancePct:total?Math.round(compliant/total*100):null,verifierTrend,mfaTrend})
})

api.get('/segments',(_req,res)=>res.json(all('SELECT * FROM identity_segments ORDER BY created_at DESC')))
api.post('/segments',requireRole('admin'),(req,res)=>{
  const data=body(z.object({name:z.string().min(1),nodeId:z.string().optional(),nodeGroupId:z.string().optional(),policyId:z.string().nullable().optional(),port:z.number().int().min(1).max(65535),accountSid:z.string().optional(),sourceIp:z.string().optional(),extraPorts:z.array(z.number().int().min(1).max(65535)).default([]),sourceProcess:z.string().optional(),fallbackToLoggedOnUser:z.boolean().default(false),failOpen:z.boolean().default(false),ttlMinutes:z.number().int().min(1).max(10080).default(240),mode:z.enum(['agentless','agent']).default('agentless'),mfaProvider:z.enum(['totp','entra']).default('totp'),allowedUpns:z.array(z.email()).max(100).default([]),portalEnabled:z.boolean().default(true),autoPromptEnabled:z.boolean().default(false)}),req)
  if(Number(!!data.nodeId)+Number(!!data.nodeGroupId)!==1)return res.status(400).json({error:'Choose one node or node group'})
  if(data.nodeId&&!getNode(data.nodeId))return notFound(res,'Node')
  if(data.nodeGroupId&&!one('SELECT id FROM node_groups WHERE id=?',data.nodeGroupId))return notFound(res,'Node group')
  if(data.policyId&&!getPolicy(data.policyId))return notFound(res,'Policy')
  const segmentId=id();run('INSERT INTO identity_segments(id,name,node_id,node_group_id,policy_id,port,account_sid,source_ip,extra_ports,source_process,fallback_to_logged_on_user,fail_open,ttl_minutes,mode,mfa_provider,allowed_upns,portal_enabled,auto_prompt_enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',segmentId,data.name,data.nodeId||null,data.nodeGroupId||null,data.policyId||null,data.port,data.accountSid||null,data.sourceIp||null,json(data.extraPorts),data.sourceProcess||null,Number(data.fallbackToLoggedOnUser),Number(data.failOpen),data.ttlMinutes,data.mode,data.mfaProvider,json(data.allowedUpns.map(value=>value.toLowerCase())),Number(data.portalEnabled),Number(data.autoPromptEnabled))
  audit(req.user.id,'segment.create','segment',segmentId,null,data);res.status(201).json(one('SELECT * FROM identity_segments WHERE id=?',segmentId))
})
api.patch('/segments/:id',requireRole('admin'),(req,res)=>{
  const before=one('SELECT * FROM identity_segments WHERE id=?',reqId(req))
  if(!before)return notFound(res,'Segment')
  const data=body(z.object({allowedUpns:z.array(z.email()).max(100).optional(),mfaProvider:z.enum(['totp','entra']).optional(),portalEnabled:z.boolean().optional(),autoPromptEnabled:z.boolean().optional(),ttlMinutes:z.number().int().min(2).max(10080).optional(),sourceIp:z.string().max(255).optional(),policyId:z.string().nullable().optional()}),req)
  if(data.policyId&&!getPolicy(data.policyId))return notFound(res,'Policy')
  const next={allowedUpns:data.allowedUpns?data.allowedUpns.map(value=>value.toLowerCase()):parse(before.allowed_upns)||[],mfaProvider:data.mfaProvider||before.mfa_provider,portalEnabled:data.portalEnabled===undefined?!!before.portal_enabled:data.portalEnabled,autoPromptEnabled:data.autoPromptEnabled===undefined?!!before.auto_prompt_enabled:data.autoPromptEnabled,ttlMinutes:data.ttlMinutes||before.ttl_minutes,sourceIp:data.sourceIp===undefined?before.source_ip:data.sourceIp||null,policyId:data.policyId===undefined?before.policy_id:data.policyId}
  run('UPDATE identity_segments SET allowed_upns=?,mfa_provider=?,portal_enabled=?,auto_prompt_enabled=?,ttl_minutes=?,source_ip=?,policy_id=? WHERE id=?',json(next.allowedUpns),next.mfaProvider,Number(next.portalEnabled),Number(next.autoPromptEnabled),next.ttlMinutes,next.sourceIp,next.policyId,before.id)
  audit(req.user.id,'segment.update','segment',before.id,{allowedUpns:parse(before.allowed_upns),mfaProvider:before.mfa_provider,portalEnabled:!!before.portal_enabled,autoPromptEnabled:!!before.auto_prompt_enabled,ttlMinutes:before.ttl_minutes,sourceIp:before.source_ip,policyId:before.policy_id},next)
  res.json(one('SELECT * FROM identity_segments WHERE id=?',before.id))
})
const portalAccessLimit=rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:'draft-8',legacyHeaders:false})
function portalTarget(req,segment,requestedNodeId){
  if(!segment)throw Object.assign(new Error('Segment not found'),{status:404})
  if(!segment.portal_enabled||segment.mode!=='agentless')throw Object.assign(new Error('The access portal is disabled for this segment'),{status:409})
  if(!(parse(segment.allowed_upns)||[]).includes(req.user.email.toLowerCase()))throw Object.assign(new Error('Your account is not assigned to this segment'),{status:403})
  if(segment.fail_open)throw Object.assign(new Error('Portal access requires a fail-closed segment'),{status:409})
  if(segment.source_process)throw Object.assign(new Error('Agentless portal access cannot enforce a source process'),{status:409})
  const nodeId=segment.node_id||requestedNodeId
  if(!nodeId||segment.node_id&&requestedNodeId&&requestedNodeId!==segment.node_id||segment.node_group_id&&!one('SELECT 1 FROM node_group_members WHERE group_id=? AND node_id=?',segment.node_group_id,nodeId))throw Object.assign(new Error('Choose a node covered by this segment'),{status:400})
  const node=getNode(nodeId)
  if(!node)throw Object.assign(new Error('Node not found'),{status:404})
  if(node.connection_mode!=='agentless'||!['winrm','winrms'].includes(node.transport))throw Object.assign(new Error('Agentless portal access requires a working WinRM node'),{status:409})
  if(node.firewall_state==='learning')throw Object.assign(new Error('The target is still learning; enforce its firewall policy before enabling portal access'),{status:409})
  if(segment.policy_id){
    const policy=getPolicy(segment.policy_id)
    if(!policy||!assignedNodes(policy.id).some(target=>target.id===node.id))throw Object.assign(new Error('The linked MFA policy is not assigned to this node'),{status:409})
    const applied=one('SELECT version_id,status FROM policy_apply_runs WHERE policy_id=? AND node_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1',policy.id,node.id)
    if(!applied||applied.version_id!==policy.current_version_id||applied.status!=='success')throw Object.assign(new Error('Sync the linked MFA policy to this node before granting access'),{status:409})
  }
  if(segment.ttl_minutes<2)throw Object.assign(new Error('Portal access TTL must be at least two minutes'),{status:409})
  const sourceIp=normalizeSourceIp(req.ip)
  if(!sourceMatches(sourceIp,segment.source_ip))throw Object.assign(new Error('Your source IP is outside this segment'),{status:403})
  return {node,sourceIp}
}
function portalPrompt(req,segment,node,sourceIp,promptId){
  if(!promptId)return null
  const prompt=one('SELECT * FROM mfa_prompt_events WHERE id=?',promptId)
  if(!prompt||prompt.segment_id!==segment.id||prompt.target_node_id!==node.id||prompt.source_ip!==sourceIp||prompt.status!=='opened'||prompt.expires_at<=now())throw Object.assign(new Error('MFA browser prompt is invalid or expired'),{status:409})
  return prompt
}
async function grantPortalAccess(req,segment,node,sourceIp,provider,promptId=null){
  portalPrompt(req,segment,node,sourceIp,promptId)
  if(promptId){
    const reserved=run("UPDATE mfa_prompt_events SET status='consuming' WHERE id=? AND status='opened' AND expires_at>?",promptId,now())
    if(reserved.changes!==1)throw Object.assign(new Error('MFA browser prompt was already used'),{status:409})
  }
  const challengeId=id(),grantId=id(),expiresAt=new Date(Date.now()+segment.ttl_minutes*60_000).toISOString()
  let ruleStarted=false,grantRecorded=false
  run('INSERT INTO mfa_challenges(id,node_id,user_upn,segment_id,connection_5tuple,status,expires_at) VALUES(?,?,?,?,?,?,?)',challengeId,node.id,req.user.email,segment.id,json({srcIp:sourceIp,dstPort:segment.port,protocol:'TCP'}),'pending',new Date(Date.now()+300_000).toISOString())
  try{
    const preflight=await remote(node,'jit_preflight',{port:segment.port})
    if(!preflight?.safe){
      const names=[...(preflight?.conflictingAllows||[]),...(preflight?.conflictingBlocks||[])].map(item=>item.name).slice(0,3).join(', ')
      throw Object.assign(new Error(`Firewall gate is not ready for TCP ${segment.port}; check inbound profile defaults${names?` and overlapping rules: ${names}`:' and overlapping rules'}`),{status:409})
    }
    const args={grantId,sourceIp,port:segment.port,expiresAt}
    try{await remote(node,'jit_start',args);ruleStarted=true}
    catch(error){
      const current=await remote(node,'rules',{group:`WinFireSecure:JIT:${grantId}`}).catch(()=>null)
      if(!(Array.isArray(current)?current.length:current?1:0))throw error
      ruleStarted=true
    }
    run('INSERT INTO jit_grants(id,segment_id,node_id,account_sid,src_ip,dst_port,rule_path,grant_type,ttl_seconds,granted_at,expires_at,mfa_challenge_id,prompt_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',grantId,segment.id,node.id,segment.account_sid||null,sourceIp,segment.port,`WinFireSecure:JIT:${grantId}`,'portal_firewall',segment.ttl_minutes*60,now(),expiresAt,challengeId,promptId)
    grantRecorded=true
    run("UPDATE mfa_challenges SET status='approved',resolved_at=? WHERE id=?",now(),challengeId)
    if(promptId)run("UPDATE mfa_prompt_events SET status='consumed',consumed_at=? WHERE id=?",now(),promptId)
    audit(req.user.id,'mfa.portal.granted','jit-grant',grantId,null,{segmentId:segment.id,nodeId:node.id,sourceIp,port:segment.port,expiresAt,provider,promptId})
    return {grantId,nodeId:node.id,sourceIp,port:segment.port,expiresAt}
  }catch(error){
    if(ruleStarted){
      try{
        await remote(node,'jit_end',{grantId})
        if(grantRecorded)run('UPDATE jit_grants SET revoked_at=? WHERE id=?',now(),grantId)
      }catch(cleanupError){
        audit(req.user.id,'mfa.portal.cleanup.failed','jit-grant',grantId,null,{nodeId:node.id,error:cleanupError.message})
      }
    }
    run("UPDATE mfa_challenges SET status='denied',resolved_at=? WHERE id=?",now(),challengeId)
    if(promptId)run("UPDATE mfa_prompt_events SET status='failed',error=? WHERE id=? AND status='consuming'",error.message,promptId)
    audit(req.user.id,'mfa.portal.failed','challenge',challengeId,null,{segmentId:segment.id,nodeId:node.id,sourceIp,error:error.message,provider})
    throw error
  }
}
api.get('/segments/access',(req,res)=>{
  const segments=all("SELECT * FROM identity_segments WHERE portal_enabled=1 AND mode='agentless' ORDER BY name")
    .filter(segment=>(parse(segment.allowed_upns)||[]).includes(req.user.email.toLowerCase()))
    .map(segment=>({id:segment.id,name:segment.name,nodeId:segment.node_id,nodeGroupId:segment.node_group_id,port:segment.port,ttlMinutes:segment.ttl_minutes,mfaProvider:segment.mfa_provider,nodes:segment.node_group_id?all('SELECT n.id,n.hostname FROM nodes n JOIN node_group_members m ON m.node_id=n.id WHERE m.group_id=? ORDER BY n.hostname',segment.node_group_id):[{id:segment.node_id,hostname:getNode(segment.node_id)?.hostname||segment.node_id}]}))
  res.json(segments)
})
api.get('/segments/access/grants',(req,res)=>{
  const admin=['owner','admin'].includes(req.user.role)
  const grants=all(`SELECT g.id,g.node_id,g.src_ip,g.dst_port,g.granted_at,g.expires_at,g.segment_id,g.fallback_reason,c.user_upn,n.hostname FROM jit_grants g LEFT JOIN mfa_challenges c ON c.id=g.mfa_challenge_id LEFT JOIN nodes n ON n.id=g.node_id WHERE g.grant_type='portal_firewall' AND g.revoked_at IS NULL AND g.expires_at>? AND (?=1 OR c.user_upn=?) ORDER BY g.expires_at`,now(),Number(admin),req.user.email)
  res.json(grants)
})
api.get('/segments/access/prompts/:promptId',(req,res)=>{
  const prompt=one('SELECT * FROM mfa_prompt_events WHERE id=?',req.params.promptId)
  if(!prompt||prompt.status!=='opened'||prompt.expires_at<=now()||prompt.source_ip!==normalizeSourceIp(req.ip))return notFound(res,'MFA prompt')
  const segment=one('SELECT * FROM identity_segments WHERE id=?',prompt.segment_id)
  if(!segment?.portal_enabled||!(parse(segment.allowed_upns)||[]).includes(req.user.email.toLowerCase()))return notFound(res,'MFA prompt')
  res.json({id:prompt.id,segmentId:prompt.segment_id,nodeId:prompt.target_node_id,sourceIp:prompt.source_ip,sourceNode:one('SELECT hostname FROM nodes WHERE id=?',prompt.source_node_id)?.hostname||null,sessionUser:prompt.opened_user,sessionId:prompt.opened_session_id,processId:prompt.opened_process_id,port:segment.port,expiresAt:prompt.expires_at})
})
api.post('/segments/access/grants/:grantId/revoke',wrap(async(req,res)=>{
  const grant=one(`SELECT g.*,c.user_upn FROM jit_grants g LEFT JOIN mfa_challenges c ON c.id=g.mfa_challenge_id WHERE g.id=? AND g.grant_type='portal_firewall'`,req.params.grantId)
  if(!grant)return notFound(res,'Access grant')
  if(!['owner','admin'].includes(req.user.role)&&grant.user_upn!==req.user.email)return res.status(403).json({error:'This grant belongs to another user'})
  if(grant.revoked_at)return res.json({revoked:true})
  const node=getNode(grant.node_id)
  if(node)await remote(node,'jit_end',{grantId:grant.id})
  run('UPDATE jit_grants SET revoked_at=? WHERE id=?',now(),grant.id)
  audit(req.user.id,'mfa.portal.revoked','jit-grant',grant.id,null,{nodeId:grant.node_id})
  res.json({revoked:true})
}))
api.post('/segments/:id/access',portalAccessLimit,wrap(async(req,res)=>{
  const segment=one('SELECT * FROM identity_segments WHERE id=?',reqId(req))
  const data=body(z.object({nodeId:z.string().optional(),promptId:z.uuid().optional(),code:z.string().regex(/^\d{6}$/)}),req)
  const {node,sourceIp}=portalTarget(req,segment,data.nodeId)
  portalPrompt(req,segment,node,sourceIp,data.promptId)
  if(segment.mfa_provider!=='totp')return res.status(409).json({error:'Use the Entra sign-in action for this segment'})
  if(!req.user.totp_secret)return res.status(409).json({error:'Set up Google Authenticator or another TOTP app in Administration → Security first'})
  const counter=matchingTotpCounter(openSealed(req.user.totp_secret).secret,data.code)
  if(counter===null){audit(req.user.id,'mfa.portal.denied','segment',segment.id,null,{nodeId:node.id,sourceIp,reason:'invalid-code'});return res.status(401).json({error:'Invalid authenticator code'})}
  const consumed=run('INSERT INTO mfa_totp_replay(user_id,last_counter) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET last_counter=excluded.last_counter WHERE excluded.last_counter>mfa_totp_replay.last_counter',req.user.id,counter)
  if(consumed.changes!==1)return res.status(401).json({error:'Authenticator code was already used; wait for a new code'})
  res.status(201).json(await grantPortalAccess(req,segment,node,sourceIp,'totp',data.promptId))
}))
api.post('/segments/:id/entra/start',portalAccessLimit,wrap(async(req,res)=>{
  const segment=one('SELECT * FROM identity_segments WHERE id=?',reqId(req))
  const data=body(z.object({nodeId:z.string().optional(),promptId:z.uuid().optional()}),req)
  const {node,sourceIp}=portalTarget(req,segment,data.nodeId)
  portalPrompt(req,segment,node,sourceIp,data.promptId)
  if(segment.mfa_provider!=='entra')return res.status(409).json({error:'This segment uses an authenticator code'})
  if(!entraConfigured())return res.status(503).json({error:'Entra tenant, app, secret, and public URL are not configured'})
  const flow=await startEntraAuthentication()
  run('INSERT INTO mfa_entra_flows(state_hash,user_id,segment_id,node_id,source_ip,sealed_checks,expires_at,prompt_id) VALUES(?,?,?,?,?,?,?,?)',hashToken(flow.state),req.user.id,segment.id,node.id,sourceIp,seal({verifier:flow.verifier,nonce:flow.nonce}),new Date(Date.now()+5*60_000).toISOString(),data.promptId||null)
  audit(req.user.id,'mfa.entra.start','segment',segment.id,null,{nodeId:node.id,sourceIp})
  res.json({authorizationUrl:flow.url})
}))
api.post('/segments/entra/complete',portalAccessLimit,wrap(async(req,res)=>{
  const data=body(z.object({code:z.string().min(8).max(4096),state:z.string().min(16).max(512)}),req)
  const flow=one('SELECT * FROM mfa_entra_flows WHERE state_hash=?',hashToken(data.state))
  if(!flow||flow.used_at||flow.expires_at<=now()||flow.user_id!==req.user.id)return res.status(401).json({error:'Entra sign-in has expired or was already used'})
  if(normalizeSourceIp(req.ip)!==flow.source_ip)return res.status(403).json({error:'Entra sign-in source IP changed'})
  const segment=one('SELECT * FROM identity_segments WHERE id=?',flow.segment_id)
  const {node,sourceIp}=portalTarget(req,segment,flow.node_id)
  portalPrompt(req,segment,node,sourceIp,flow.prompt_id)
  if(segment.mfa_provider!=='entra')return res.status(409).json({error:'This segment no longer uses Entra'})
  const reserved=run('UPDATE mfa_entra_flows SET used_at=? WHERE state_hash=? AND used_at IS NULL',now(),flow.state_hash)
  if(reserved.changes!==1)return res.status(401).json({error:'Entra sign-in was already used'})
  try{
    const checks=openSealed(flow.sealed_checks)
    const identity=await completeEntraAuthentication({code:data.code,state:data.state,...checks})
    if(identity.email!==req.user.email.toLowerCase())throw Object.assign(new Error('Entra identity does not match your WinFire account'),{status:403})
    res.status(201).json(await grantPortalAccess(req,segment,node,sourceIp,'entra',flow.prompt_id))
  }catch(error){audit(req.user.id,'mfa.entra.failed','segment',segment.id,null,{nodeId:node.id,sourceIp,error:error.message});throw error}
}))
api.get('/segments/:id/challenges',(req,res)=>res.json(all('SELECT * FROM mfa_challenges WHERE segment_id=? ORDER BY challenged_at DESC LIMIT 200',reqId(req))))
api.post('/segments/:id/challenges',requireRole('editor'),(req,res)=>{
  const segment=one('SELECT * FROM identity_segments WHERE id=?',reqId(req));if(!segment)return notFound(res,'Segment')
  const data=body(z.object({userUpn:z.email(),nodeId:z.string().optional(),connection:z.record(z.string(),z.any()).optional()}),req),challengeId=id(),expires=new Date(Date.now()+5*60*1000).toISOString()
  const nodeId=segment.node_id||data.nodeId
  if(!nodeId||segment.node_group_id&&!one('SELECT 1 FROM node_group_members WHERE group_id=? AND node_id=?',segment.node_group_id,nodeId))return res.status(400).json({error:'Choose a node in this segment group'})
  run('INSERT INTO mfa_challenges(id,node_id,user_upn,segment_id,connection_5tuple,status,expires_at) VALUES(?,?,?,?,?,?,?)',challengeId,nodeId,data.userUpn,segment.id,json(data.connection),'pending',expires)
  audit(req.user.id,'mfa.challenge.create','challenge',challengeId,null,{segmentId:segment.id,userUpn:data.userUpn});res.status(201).json({id:challengeId,status:'pending',expiresAt:expires})
})
api.post('/segments/:id/challenges/:challengeId/resolve',requireRole('admin'),(req,res)=>{
  const challenge=one('SELECT * FROM mfa_challenges WHERE id=? AND segment_id=?',req.params.challengeId,reqId(req));if(!challenge)return notFound(res,'Challenge')
  if(challenge.status!=='pending'||challenge.expires_at<now())return res.status(409).json({error:'Challenge expired or already resolved'})
  const data=body(z.object({approved:z.boolean()}),req);run('UPDATE mfa_challenges SET status=?,resolved_at=? WHERE id=?',data.approved?'approved':'denied',now(),challenge.id);audit(req.user.id,'mfa.challenge.resolve','challenge',challenge.id,{status:'pending'},{approved:data.approved});if(!data.approved)emitNotification({eventKey:`mfa:${challenge.id}`,category:'mfa_challenge_failure',title:'MFA challenge denied',body:`The challenge for ${challenge.user_upn} on segment ${one('SELECT name FROM identity_segments WHERE id=?',challenge.segment_id)?.name||challenge.segment_id} was denied.`,entityType:'challenge',entityId:challenge.id});res.json({ok:true})
})

api.get('/logon-rights',(req,res)=>res.json(all('SELECT * FROM logon_rights WHERE (? IS NULL OR node_id=?) ORDER BY at DESC LIMIT 500',req.query.nodeId||null,req.query.nodeId||null)))
api.post('/logon-rights/baseline',requireRole('admin'),wrap(async(req,res)=>{
  const {nodeId}=body(z.object({nodeId:z.string()}),req),node=getNode(nodeId);if(!node)return notFound(res,'Node')
  const raw=await remote(node,'rights'),lines=Array.isArray(raw)?raw:[raw].filter(Boolean)
  let parsed
  try{parsed=parseSeceditRights(lines)}catch(error){throw Object.assign(error,{status:502})}
  const rights=db.transaction(()=>{
    run('DELETE FROM logon_rights WHERE node_id=? AND baseline=1',node.id)
    const collected=parsed.map(right=>{const rightId=id();run('INSERT INTO logon_rights(id,node_id,account_sid,logon_type,right_assignment,source,baseline,created_by) VALUES(?,?,?,?,?,?,1,?)',rightId,node.id,right.accountSid,right.logonType,right.assignment,'secedit',req.user.id);return {id:rightId,...right}})
    audit(req.user.id,'logon-rights.baseline','node',node.id,null,{count:collected.length,allow:collected.filter(right=>right.assignment==='allow').length,deny:collected.filter(right=>right.assignment==='deny').length})
    return collected
  })()
  res.status(201).json(rights)
}))

api.get('/logs/search',(req,res)=>{
  const query=z.object({
    nodeId:z.string().optional(),action:z.enum(['allow','block','success','failure']).optional(),direction:z.enum(['in','out']).optional(),
    program:z.string().max(1024).optional(),challengeId:z.string().max(128).optional(),
    eventId:z.coerce.number().int().min(0).optional(),protocol:z.string().max(32).optional(),srcIp:z.string().max(128).optional(),dstIp:z.string().max(128).optional(),
    port:z.coerce.number().int().min(1).max(65535).optional(),from:z.iso.datetime({local:true,offset:true}).optional(),to:z.iso.datetime({local:true,offset:true}).optional(),
    page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(500).default(100),
    sortBy:z.enum(['time','node','eventId','action','direction','srcIp','dstIp','port','program']).default('time'),sortDir:z.enum(['asc','desc']).default('desc'),hideLoopback:z.enum(['true','false']).optional()
  }).parse(req.query)
  if(query.from&&query.to&&new Date(query.from)>new Date(query.to))return res.status(400).json({error:'From must be earlier than To'})
  const filters=[],args=[]
  for(const [key,column] of [['nodeId','e.node_id'],['action','e.action'],['direction','COALESCE(e.direction,p.direction)'],['challengeId','e.challenge_id'],['eventId','e.event_id'],['port','COALESCE(e.dst_port,p.dst_port)']])if(query[key]!==undefined){filters.push(`${column}=?`);args.push(query[key])}
  for(const [key,column] of [['program','COALESCE(e.program,p.program)'],['protocol','COALESCE(e.protocol,p.protocol)'],['srcIp','COALESCE(e.src_ip,p.src_ip)'],['dstIp','COALESCE(e.dst_ip,p.dst_ip)']])if(query[key]){filters.push(`${column} LIKE ? ESCAPE '\\'`);args.push(`%${query[key].replace(/[\\%_]/g,'\\$&')}%`)}
  if(query.from){filters.push('datetime(COALESCE(e.event_time,e.received_at))>=datetime(?)');args.push(query.from)}
  if(query.to){filters.push('datetime(COALESCE(e.event_time,e.received_at))<=datetime(?)');args.push(query.to)}
  if((query.hideLoopback===undefined?observabilitySettings().hideLoopbackEvents:query.hideLoopback==='true'))filters.push("NOT ((COALESCE(e.src_ip,p.src_ip,'') LIKE '127.%' OR COALESCE(e.src_ip,p.src_ip,'') IN ('::1','0:0:0:0:0:0:0:1')) AND (COALESCE(e.dst_ip,p.dst_ip,'') LIKE '127.%' OR COALESCE(e.dst_ip,p.dst_ip,'') IN ('::1','0:0:0:0:0:0:0:1')))")
  const where=filters.length?'WHERE '+filters.join(' AND '):''
  const sortColumns={time:'julianday(COALESCE(e.event_time,e.received_at))',node:'n.hostname COLLATE NOCASE',eventId:'e.event_id',action:'e.action COLLATE NOCASE',direction:'COALESCE(e.direction,p.direction) COLLATE NOCASE',srcIp:'COALESCE(e.src_ip,p.src_ip) COLLATE NOCASE',dstIp:'COALESCE(e.dst_ip,p.dst_ip) COLLATE NOCASE',port:'COALESCE(e.dst_port,p.dst_port)',program:'COALESCE(e.program,p.program) COLLATE NOCASE'}
  const fromSql=`FROM log_events e LEFT JOIN nodes n ON n.id=e.node_id LEFT JOIN event_patterns p ON p.id=e.pattern_id ${where}`
  const total=one(`SELECT COUNT(*) AS count ${fromSql}`,...args).count
  const items=all(`SELECT e.*,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,COALESCE(e.program,p.program) program,COALESCE(e.event_type,p.event_type) event_type ${fromSql} ORDER BY ${sortColumns[query.sortBy]} ${query.sortDir.toUpperCase()}, e.id DESC LIMIT ? OFFSET ?`,...args,query.pageSize,(query.page-1)*query.pageSize)
  res.json({items,total,page:query.page,pageSize:query.pageSize,totalPages:Math.ceil(total/query.pageSize)})
})
api.post('/logs/:id/rule',requireRole('admin'),(req,res)=>{
  const event=one('SELECT e.*,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,COALESCE(e.program,p.program) program FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE e.id=?',reqId(req));if(!event)return notFound(res,'Event')
  const node=getNode(event.node_id);if(!node)return notFound(res,'Node')
  const data=body(z.object({action:z.enum(['allow','block']),policyId:z.string().optional()}),req)
  if(!['in','out'].includes(event.direction)||!['TCP','UDP'].includes(event.protocol)||!Number.isInteger(event.dst_port)||event.dst_port<1||event.dst_port>65535)return res.status(400).json({error:'This event lacks a direction, TCP/UDP protocol, or valid destination port'})
  const remoteAddress=event.direction==='in'?event.src_ip:event.dst_ip
  if(!validateAddressExpression(remoteAddress))return res.status(400).json({error:'This event has no valid remote address for a scoped rule'})
  const policy=data.policyId?getPolicy(data.policyId):ensurePersonalPolicy(node,req.user.id)
  if(!policy)return notFound(res,'Policy')
  if(data.policyId&&policy.origin==='learned'&&policy.source_node_id!==node.id)return res.status(400).json({error:'A personal policy belongs to a different node'})
  if(data.policyId&&policy.origin!=='learned'&&!one('SELECT id FROM policy_assignments WHERE policy_id=? AND node_group_id IS NOT NULL',policy.id))return res.status(400).json({error:'Choose a group or global policy'})
  if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'})
  if(hasActiveLearning(policy.id))return res.status(409).json({error:'This personal policy is still owned by host training. Finish training before adding a manual rule.'})
  const previous=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
  const graph=parse(previous?.graph_json)||{nodes:[],edges:[]}
  const ruleId=id(),port=String(event.dst_port)
  graph.nodes.push({id:ruleId,type:data.action==='block'?'deny':'allow',position:{x:80+(graph.nodes.length%3)*230,y:80+Math.floor(graph.nodes.length/3)*140},data:{name:`${data.action==='block'?'Reject':'Allow'} ${event.protocol} ${port} from event ${event.event_id}`,direction:event.direction,protocol:event.protocol,localPort:event.direction==='in'?port:'Any',remotePort:event.direction==='out'?port:'Any',remoteAddress,profile:'Any',program:validateProgramPath(event.program)?event.program:'Any'}})
  const rules=compilePolicy(graph,policy.id),conflicts=assignmentConflicts(policy.id,rules,assignedNodes(policy.id))
  assertManagementAccess(rules)
  if(conflicts.length)return rejectConflicts(res,conflicts)
  const versionId=id(),versionNo=(one('SELECT MAX(version_no) n FROM policy_versions WHERE policy_id=?',policy.id)?.n||0)+1
  db.transaction(()=>{
    run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,policy.id,versionNo,json(graph),json(rules),req.user.id,`Rule from firewall event ${event.id}`)
    run('UPDATE policies SET current_version_id=? WHERE id=?',versionId,policy.id)
    if(!data.policyId&&!one('SELECT id FROM policy_assignments WHERE policy_id=? AND node_id=?',policy.id,node.id))run('INSERT INTO policy_assignments(id,policy_id,node_id,assigned_by) VALUES(?,?,?,?)',id(),policy.id,node.id,req.user.id)
    audit(req.user.id,'policy.rule.from-event','policy',policy.id,null,{eventId:event.id,nodeId:node.id,action:data.action,versionId,versionNo})
  })()
  res.status(201).json({policyId:policy.id,versionId,versionNo,ruleCount:rules.length,pendingSync:true})
})
api.post('/logs/ingest',requireRole('editor'),(req,res)=>{
  const data=body(z.object({nodeId:z.string(),events:z.array(z.object({recordId:z.number().optional(),eventId:z.number().int(),action:z.string().optional(),protocol:z.string().optional(),srcIp:z.string().optional(),dstIp:z.string().optional(),dstPort:z.number().optional(),direction:z.string().optional(),program:z.string().optional(),accountSid:z.string().optional(),challengeId:z.string().optional()})).max(1000)}),req)
  const ignoreLoopback=observabilitySettings().ignoreLoopbackIngest
  let inserted=0;db.transaction(()=>{for(const event of data.events){if(ignoreLoopback&&isLoopbackEvent(event))continue;const result=run('INSERT OR IGNORE INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,program,account_sid,challenge_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',id(),data.nodeId,event.recordId??null,event.eventId,event.action||null,event.protocol||null,event.srcIp||null,event.dstIp||null,event.dstPort||null,event.direction||null,event.program||null,event.accountSid||null,event.challengeId||null);inserted+=result.changes}})()
  res.status(201).json({inserted})
})

export async function pullLogs(nodeId,actorId=null,maxPages=5,quiet=false) {
  const node=getNode(nodeId);if(!node)throw Object.assign(new Error('Node not found'),{status:404})
  const ignoreLoopback=observabilitySettings().ignoreLoopbackIngest
  let cursor=one('SELECT last_record_id FROM node_log_cursors WHERE node_id=?',nodeId)?.last_record_id??one('SELECT MAX(record_id) n FROM log_events WHERE node_id=?',nodeId)?.n??0
  let inserted=0,pages=0,caughtUp=false
  for(;pages<maxPages;pages++){
    const raw=await remote(node,'events',{after:cursor}),events=Array.isArray(raw)?raw:[raw].filter(Boolean)
    if(!events.length){caughtUp=true;break}
    db.transaction(()=>{for(const event of events){
      const item=normalizeWindowsEvent(event)
      if(ignoreLoopback&&isLoopbackEvent(item))continue
      const result=run('INSERT OR IGNORE INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,src_port,dst_ip,dst_port,direction,program,account_sid,event_time,event_type,logon_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',id(),nodeId,item.recordId,item.eventId,item.action,item.protocol,item.srcIp,item.srcPort,item.dstIp,item.dstPort,item.direction,item.program,item.accountSid,item.eventTime,item.eventType,item.logonType)
      inserted+=result.changes
    }})()
    const next=Number(events.at(-1).RecordId)
    if(next<=cursor)break
    cursor=next
    run('INSERT INTO node_log_cursors(node_id,last_record_id,updated_at) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET last_record_id=excluded.last_record_id,updated_at=excluded.updated_at',nodeId,cursor,now())
    if(events.length<500){caughtUp=true;pages++;break}
  }
  if(!quiet)audit(actorId,'logs.pull','node',nodeId,null,{inserted,pages,lastRecordId:cursor,caughtUp})
  return {inserted,pages,lastRecordId:cursor,caughtUp}
}
api.post('/logs/pull',requireRole('editor'),wrap(async(req,res)=>{
  const {nodeId}=body(z.object({nodeId:z.string()}),req)
  res.json(await pullLogs(nodeId,req.user.id))
}))
api.get('/learning-sessions',(req,res)=>res.json(all('SELECT * FROM learning_sessions WHERE (? IS NULL OR node_id=?) ORDER BY started_at DESC,rowid DESC LIMIT 500',req.query.nodeId||null,req.query.nodeId||null)))
api.post('/learning-sessions',requireRole('editor'),(req,res)=>{
  const {nodeId,durationHours}=body(z.object({nodeId:z.string(),durationHours:z.number().min(1).max(720).default(24)}),req),node=getNode(nodeId)
  if(!node)return notFound(res,'Node')
  const active=one("SELECT * FROM learning_sessions WHERE node_id=? AND status='active'",nodeId)
  if(active?.mode==='manual')return res.status(409).json({error:'Node already learning'})
  if(!active&&one("SELECT id FROM learning_sessions WHERE node_id=? AND status IN ('review','applying','apply-failed')",nodeId))return res.status(409).json({error:'Finish the current learning session before starting another'})
  const endsAt=new Date(Date.now()+durationHours*360e4).toISOString()
  const sessionId=active?.id||id()
  db.transaction(()=>{
    const policy=ensurePersonalPolicy(node,req.user.id)
    if(active)run("UPDATE learning_sessions SET mode='manual',ends_at=?,last_error=NULL,progressive_enabled=0,next_progressive_at=NULL,generated_policy_id=? WHERE id=?",endsAt,policy.id,sessionId)
    else run("INSERT INTO learning_sessions(id,node_id,ends_at,status,mode,generated_policy_id) VALUES(?,?,?,'active','manual',?)",sessionId,nodeId,endsAt,policy.id)
    run("UPDATE nodes SET firewall_state='learning' WHERE id=?",nodeId)
    audit(req.user.id,active?'learning.switch-to-manual':'learning.start','node',nodeId,null,{sessionId,endsAt,durationHours,mode:'manual'})
  })()
  res.status(201).json({id:sessionId,nodeId,endsAt,mode:'manual',status:'active'})
})
function learningRuleKey(direction,protocol,port,address){return [direction,String(protocol).toUpperCase(),String(port),String(address).toLowerCase()].join('|')}
function ruleLearningKey(rule){return learningRuleKey(rule.direction,rule.protocol,rule.direction==='in'?rule.localPort:rule.remotePort,rule.remoteAddress)}
function learningPreview(session) {
  const policy=getPolicy(session.generated_policy_id)
  if(!policy)throw Object.assign(new Error('Personal learning policy is missing'),{status:409})
  const current=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
  const base=parse(current?.graph_json)||{nodes:[],edges:[]}
  const known=new Set((parse(current?.rules_compiled_json)||[]).filter(rule=>rule.action==='allow').map(ruleLearningKey))
  const assigned=all(`SELECT DISTINCT v.rules_compiled_json FROM policy_versions v JOIN policies p ON p.current_version_id=v.id JOIN policy_assignments a ON a.policy_id=p.id WHERE p.id<>? AND (a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?))`,policy.id,session.node_id,session.node_id)
  for(const row of assigned)for(const rule of parse(row.rules_compiled_json)||[])if(rule.action==='allow')known.add(ruleLearningKey(rule))
  const endAt=new Date(Math.min(Date.now(),Date.parse(session.ends_at))).toISOString()
  const observations=all("SELECT DISTINCT COALESCE(e.direction,p.direction) direction,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE e.node_id=? AND datetime(COALESCE(e.event_time,e.received_at)) BETWEEN datetime(?) AND datetime(?) AND e.action='allow' AND COALESCE(e.dst_port,p.dst_port) BETWEEN 1 AND 65535 AND COALESCE(e.protocol,p.protocol) IN ('TCP','UDP') AND COALESCE(e.direction,p.direction) IN ('in','out') ORDER BY direction,protocol,dst_port,src_ip,dst_ip",session.node_id,session.started_at,endAt)
  const additions=[],seen=new Set()
  for(const event of observations){
    const remoteAddress=event.direction==='in'?event.src_ip:event.dst_ip
    if(!isIP(remoteAddress||''))continue
    const key=learningRuleKey(event.direction,event.protocol,event.dst_port,remoteAddress)
    if(known.has(key)||seen.has(key))continue
    seen.add(key);additions.push({...event,remoteAddress,key})
    if(additions.length>500)throw Object.assign(new Error('Learning preview exceeds 500 distinct new flows; narrow the session'),{status:409})
  }
  const nodes=[...base.nodes,...additions.map((event,index)=>({id:`learned-${crypto.createHash('sha256').update(event.key).digest('hex').slice(0,16)}`,type:'allow',position:{x:80+((base.nodes.length+index)%4)*180,y:80+Math.floor((base.nodes.length+index)/4)*100},data:{name:`Learned ${event.protocol} ${event.dst_port} ${event.direction}`,localPort:event.direction==='in'?String(event.dst_port):'Any',remotePort:event.direction==='out'?String(event.dst_port):'Any',protocol:event.protocol,remoteAddress:event.remoteAddress,direction:event.direction}}))]
  const graph={nodes,edges:base.edges||[]},rules=compilePolicy(graph,policy.id)
  assertManagementAccess(rules)
  return {policyId:policy.id,nodeId:session.node_id,sessionId:session.id,status:session.status,graph,rules,newFlowCount:additions.length,observedFlowCount:observations.length,asOf:now(),endsAt:session.ends_at,progressiveEnabled:!!session.progressive_enabled,nextProgressiveAt:session.next_progressive_at,lastProgressiveAt:session.last_progressive_at}
}
function saveLearningVersion(session,preview,actorId,comment){
  const policy=getPolicy(session.generated_policy_id),current=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
  if(current?.graph_json===json(preview.graph))return current
  const versionId=id(),versionNo=(one('SELECT MAX(version_no) n FROM policy_versions WHERE policy_id=?',policy.id)?.n||0)+1
  db.transaction(()=>{
    run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,policy.id,versionNo,json(preview.graph),json(preview.rules),actorId,comment)
    run('UPDATE policies SET current_version_id=? WHERE id=?',versionId,policy.id)
    audit(actorId,'learning.version','policy',policy.id,null,{sessionId:session.id,versionId,versionNo,ruleCount:preview.rules.length})
  })()
  return one('SELECT * FROM policy_versions WHERE id=?',versionId)
}
export function finalizeLearning(sessionId,actorId=null) {
  const session=one('SELECT * FROM learning_sessions WHERE id=?',sessionId)
  if(!session)throw Object.assign(new Error('Learning session not found'),{status:404})
  if(!['active','expired'].includes(session.status))throw Object.assign(new Error('Session already finalized'),{status:409})
  if(!session.generated_policy_id){const policy=ensurePersonalPolicy(getNode(session.node_id),actorId);run('UPDATE learning_sessions SET generated_policy_id=? WHERE id=?',policy.id,session.id);session.generated_policy_id=policy.id}
  const preview=learningPreview(session)
  const version=saveLearningVersion(session,preview,actorId,'Final learning snapshot')
  db.transaction(()=>{
    run("UPDATE learning_sessions SET status='review',last_error=NULL WHERE id=?",session.id)
    run("UPDATE nodes SET firewall_state='review' WHERE id=?",session.node_id)
    audit(actorId,'learning.finalize','node',session.node_id,null,{policyId:preview.policyId,observations:preview.newFlowCount,mode:session.mode})
  })()
  return {policyId:preview.policyId,versionId:version.id,ruleCount:preview.rules.length,status:'review'}
}
api.post('/learning-sessions/:id/finalize',requireRole('editor'),(req,res)=>{
  const session=one('SELECT * FROM learning_sessions WHERE id=?',reqId(req))
  if(!session)return notFound(res,'Learning session')
  if(session.mode==='auto')return res.status(409).json({error:'Automatic training finalizes at its scheduled end'})
  res.json(finalizeLearning(session.id,req.user.id))
})
function assignedPoliciesForNode(nodeId){return all(`SELECT DISTINCT p.* FROM policies p JOIN policy_assignments a ON a.policy_id=p.id WHERE a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?) ORDER BY CASE WHEN p.origin='learned' THEN 0 ELSE 1 END,p.name`,nodeId,nodeId)}
export async function approveLearning(sessionId,actorId=null) {
  const session=one('SELECT * FROM learning_sessions WHERE id=?',sessionId)
  if(!session)throw Object.assign(new Error('Learning session not found'),{status:404})
  if(!['review','apply-failed'].includes(session.status))throw Object.assign(new Error('Session is not awaiting approval'),{status:409})
  const policy=getPolicy(session.generated_policy_id),node=getNode(session.node_id)
  if(!policy||!node)throw Object.assign(new Error('Learning proposal or node is missing'),{status:409})
  const rules=parse(one('SELECT rules_compiled_json FROM policy_versions WHERE id=?',policy.current_version_id)?.rules_compiled_json)||[]
  const conflicts=assignmentConflicts(policy.id,rules,[node])
  if(conflicts.length)throw Object.assign(new Error('Conflicting firewall rules on assigned nodes'),{status:409,conflicts})
  const attemptId=id()
  db.transaction(()=>{
    if(!one('SELECT id FROM policy_assignments WHERE policy_id=? AND node_id=?',policy.id,node.id))run('INSERT INTO policy_assignments(id,policy_id,node_id,assigned_by) VALUES(?,?,?,?)',id(),policy.id,node.id,actorId)
    run("UPDATE learning_sessions SET status='applying',last_attempt_at=?,last_error=NULL,current_apply_attempt_id=? WHERE id=?",now(),attemptId,session.id)
    audit(actorId,session.mode==='auto'?'learning.auto-apply':'learning.approve','node',node.id,null,{sessionId:session.id,policyId:policy.id})
  })()
  const results=[],assignedPolicies=assignedPoliciesForNode(node.id)
  try{for(const assigned of assignedPolicies)results.push(...await applyPolicy(assigned,actorId,[node],{learningSessionId:session.id,learningAttemptId:attemptId,learningExpectedJobs:assignedPolicies.length}))}
  catch(error){run("UPDATE learning_sessions SET status='apply-failed',last_error=? WHERE id=?",error.message,session.id);run("UPDATE nodes SET firewall_state='review' WHERE id=?",node.id);throw error}
  const status=results.every(result=>result.status==='success')?'enforced':results.some(result=>result.status==='failed')?'apply-failed':'applying'
  run('UPDATE learning_sessions SET status=?,last_error=? WHERE id=?',status,results.find(result=>result.status==='failed')?.error||null,session.id)
  run('UPDATE nodes SET firewall_state=? WHERE id=?',status==='enforced'?'enforcing':status==='applying'?'applying':'review',node.id)
  return {status,results}
}
api.post('/learning-sessions/:id/approve',requireRole('editor'),wrap(async(req,res)=>res.json(await approveLearning(reqId(req),req.user.id))))

async function collectTrainingTelemetry(node){
  if(node.connection_mode==='agent'){
    const agent=one('SELECT last_checkin_at FROM agents WHERE id=? AND revoked_at IS NULL',node.agent_id)
    if(!agent?.last_checkin_at||Date.parse(agent.last_checkin_at)<Date.now()-5*60_000)throw new Error('Agent is not online to confirm training telemetry')
  }else{
    if(!['winrm','winrms'].includes(node.transport))throw new Error('No working event collection transport; probe the node before training can finish')
    const auditPolicy=await remote(node,'audit_policy')
    if(auditPolicy?.successEnabled!==true)throw new Error('Filtering Platform Connection success auditing is disabled; enable it before automatic training can finish')
    const collection=await pullLogs(node.id)
    if(!collection.caughtUp)throw new Error('Security event backlog remains; training will finish after collection catches up')
  }
}
async function applyProgressiveLearning(session,node){
  const pending=one("SELECT id FROM agent_jobs WHERE agent_id=? AND type='policy.apply' AND status IN ('queued','leased') AND json_extract(payload_json,'$.policyId')=?",node.agent_id,session.generated_policy_id)
  if(pending)throw new Error('Previous agent learning apply is still pending')
  const preview=learningPreview(session),policy=getPolicy(session.generated_policy_id)
  const conflicts=assignmentConflicts(policy.id,preview.rules,[node])
  if(conflicts.length)throw Object.assign(new Error('Learned rules conflict with another assigned policy'),{status:409,conflicts})
  const current=one('SELECT graph_json FROM policy_versions WHERE id=?',policy.current_version_id)
  const changed=current?.graph_json!==json(preview.graph)
  if(changed)saveLearningVersion(session,preview,null,'Progressive learning snapshot')
  if(preview.rules.length&&!one('SELECT id FROM policy_assignments WHERE policy_id=? AND node_id=?',policy.id,node.id))run('INSERT INTO policy_assignments(id,policy_id,node_id) VALUES(?,?,?)',id(),policy.id,node.id)
  let result={status:'unchanged'}
  if(preview.rules.length&&(changed||session.last_error)){
    result=(await applyPolicy(getPolicy(policy.id),null,[node],{progressiveSessionId:session.id}))[0]
    if(result.status==='failed')throw new Error(result.error)
  }
  const at=now(),next=new Date(Math.min(Date.parse(session.ends_at),Date.now()+session.progressive_interval_hours*36e5)).toISOString()
  run('UPDATE learning_sessions SET last_progressive_at=?,next_progressive_at=?,last_attempt_at=?,last_error=NULL WHERE id=?',at,next,at,session.id)
  audit(null,'learning.progressive','node',node.id,null,{sessionId:session.id,policyId:policy.id,newFlows:preview.newFlowCount,ruleCount:preview.rules.length,status:result.status,next})
  return {sessionId:session.id,status:result.status==='queued'?'queued':changed?'updated':'unchanged',ruleCount:preview.rules.length,nextProgressiveAt:next}
}
export async function processDueTraining(limit=25) {
  const cutoff=now(),retryBefore=new Date(Date.now()-60*60*1000).toISOString()
  const due=all("SELECT * FROM learning_sessions WHERE mode='auto' AND (((status='active' AND (ends_at<=? OR (progressive_enabled=1 AND next_progressive_at<=?))) OR status IN ('review','apply-failed')) AND (last_attempt_at IS NULL OR last_attempt_at<=?)) ORDER BY ends_at LIMIT ?",cutoff,cutoff,retryBefore,limit)
  const results=[]
  for(const session of due){
    try{
      if(session.status==='active'){
        const node=getNode(session.node_id)
        if(!node)throw new Error('Node is missing')
        await collectTrainingTelemetry(node)
        if(session.ends_at>cutoff){results.push(await applyProgressiveLearning(session,node));continue}
        if(node.connection_mode==='agent'&&one("SELECT id FROM agent_jobs WHERE agent_id=? AND type='policy.apply' AND status IN ('queued','leased') AND json_extract(payload_json,'$.progressiveSessionId')=?",node.agent_id,session.id))throw new Error('Wait for the previous progressive apply before finalizing learning')
        finalizeLearning(session.id)
      }
      const applied=await approveLearning(session.id)
      results.push({sessionId:session.id,status:applied.status})
    }catch(error){
      run('UPDATE learning_sessions SET last_error=?,last_attempt_at=? WHERE id=?',error.message,now(),session.id)
      audit(null,'learning.auto-failed','node',session.node_id,null,{sessionId:session.id,error:error.message})
      results.push({sessionId:session.id,status:'failed',error:error.message})
    }
  }
  return results
}

export async function processDueBreakGlass(limit=25){
  const due=all("SELECT * FROM break_glass_sessions WHERE status IN ('activating','activation-unknown','active','ending') AND expires_at<=? ORDER BY expires_at LIMIT ?",now(),limit)
  const results=[]
  for(const session of due){
    try{
      if(session.status==='ending'){results.push({sessionId:session.id,status:'ending'});continue}
      if(session.status==='activating'&&getNode(session.node_id)?.connection_mode==='agent'){
        const job=one('SELECT status FROM agent_jobs WHERE id=?',session.agent_job_id)
        if(job?.status==='queued'){
          run("UPDATE agent_jobs SET status='failed',error='Break-glass window expired before activation',finished_at=? WHERE id=?",now(),session.agent_job_id)
          run("UPDATE break_glass_sessions SET status='failed',last_error='Expired before agent activation' WHERE id=?",session.id)
          results.push({sessionId:session.id,status:'failed'})
        }else results.push({sessionId:session.id,status:'activation-pending'})
        continue
      }
      const result=await endBreakGlass(session,null,'expired')
      results.push({sessionId:session.id,status:result.queued?'ending':'expired'})
    }catch(error){results.push({sessionId:session.id,status:'failed',error:error.message})}
  }
  return results
}

api.get('/rpc-filters',(_req,res)=>res.json(all('SELECT * FROM rpc_filter_rules ORDER BY label')))
api.post('/rpc-filters',requireRole('admin'),(req,res)=>{
  const data=body(z.object({nodeId:z.string(),interfaceUuid:z.uuid(),opnum:z.number().int().min(0).optional(),source:z.string().min(1),action:z.enum(['allow','block']),audit:z.boolean().default(true),label:z.string().default('')}),req),ruleId=id()
  run('INSERT INTO rpc_filter_rules(id,node_id,interface_uuid,opnum,source,action,audit,label) VALUES(?,?,?,?,?,?,?,?)',ruleId,data.nodeId,data.interfaceUuid,data.opnum??null,data.source,data.action,Number(data.audit),data.label)
  audit(req.user.id,'rpc-filter.create','rpc-filter',ruleId,null,data);res.status(201).json(one('SELECT * FROM rpc_filter_rules WHERE id=?',ruleId))
})
api.post('/rpc-filters/:id/apply-inventory',requireRole('admin'),(req,res)=>res.status(501).json({error:'RPC filter deployment requires a validated Windows test target and is not enabled by this build'}))
api.post('/logon-rights/revoke',requireRole('admin'),(req,res)=>res.status(501).json({error:'LSA rights mutation requires a validated Windows test target and is not enabled by this build'}))
api.post('/logon-rights/jit-grant',requireRole('admin'),(req,res)=>res.status(501).json({error:'JIT logon-rights mutation requires a validated Windows test target and is not enabled by this build'}))

api.get('/agents',(_req,res)=>res.json(all('SELECT * FROM agents ORDER BY last_checkin_at DESC')))
api.post('/agents/:id/revoke',requireRole('admin'),(req,res)=>{
  const agent=one('SELECT * FROM agents WHERE id=?',reqId(req));if(!agent)return notFound(res,'Agent')
  db.transaction(()=>{
    for(const assignment of all(`SELECT a.* FROM policy_assignments a JOIN agent_jobs j ON j.id=a.removal_job_id WHERE j.agent_id=?`,agent.id)){
      run("UPDATE agent_jobs SET status='failed',error='Agent revoked before firewall cleanup',finished_at=? WHERE id=?",now(),assignment.removal_job_id)
      const applyRunId=parse(one('SELECT payload_json FROM agent_jobs WHERE id=?',assignment.removal_job_id)?.payload_json)?.applyRunId
      if(applyRunId)run("UPDATE policy_apply_runs SET status='failed',error='Agent revoked before firewall cleanup',finished_at=? WHERE id=?",now(),applyRunId)
      run('UPDATE policy_assignments SET removal_job_id=NULL WHERE id=?',assignment.id)
      audit(req.user.id,'policy.unassign.failed','policy',assignment.policy_id,assignment,{reason:'agent_revoked',nodeId:agent.node_id})
    }
    run('UPDATE agents SET revoked_at=? WHERE id=?',now(),agent.id)
    run("UPDATE nodes SET status='unreachable' WHERE id=?",agent.node_id)
    audit(req.user.id,'agent.revoke','agent',agent.id,null,{nodeId:agent.node_id})
  })()
  res.json({revoked:true})
})
api.post('/agents/enrollment-tokens',requireRole('admin'),(req,res)=>{
  if(!agentPkiReady())return res.status(503).json({error:'Configure HTTPS and agent PKI before generating enrollment tokens'})
  const {nodeId}=body(z.object({nodeId:z.string()}),req);if(!getNode(nodeId))return notFound(res,'Node')
  if(one('SELECT id FROM agents WHERE node_id=?',nodeId))return res.status(409).json({error:'This node already has an agent; use certificate renewal'})
  const token=crypto.randomBytes(32).toString('base64url'),tokenId=id(),expires=new Date(Date.now()+15*60*1000).toISOString()
  run('INSERT INTO enrollment_tokens(id,node_id,token_hash,expires_at) VALUES(?,?,?,?)',tokenId,nodeId,hashToken(token),expires)
  audit(req.user.id,'agent.token.create','node',nodeId,null,{expires});res.status(201).json({token,expiresAt:expires})
})
api.get('/agents/:id',(req,res)=>{const agent=one('SELECT * FROM agents WHERE id=?',reqId(req));return agent?res.json(agent):notFound(res,'Agent')})

app.use((error,req,res,_next)=>{
  if(error instanceof z.ZodError)return res.status(400).json({error:'Validation failed',issues:error.issues})
  if(error?.code==='SQLITE_CONSTRAINT_UNIQUE'||error?.code==='SQLITE_CONSTRAINT_PRIMARYKEY')return res.status(409).json({error:'Record already exists'})
  if([400,401,403,404,409,413,429,502,503].includes(error.status))return res.status(error.status).json({error:error.message,...(error.conflicts?{conflicts:error.conflicts}:{})})
  console.error(error)
  res.status(500).json({error:'Internal server error'})
})
