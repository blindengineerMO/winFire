import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import {rateLimit} from 'express-rate-limit'
import argon2 from 'argon2'
import crypto from 'node:crypto'
import {isIP} from 'node:net'
import PDFDocument from 'pdfkit'
import {z} from 'zod'
import {compilePolicy, graphSchema, findRuleConflicts} from '@winfire/shared'
import {db, all, one, run, id, now, audit, json, parse} from './db.js'
import {auth, requireRole, publicUser, issueAccess, issueRefresh, rotateRefresh, hashToken, seal, openSealed} from './security.js'
import {probeNode, collectFacts, lookupDns, remote, applyRules, diffRules, tcpProbe} from './connector.js'
import {classifyVerification,hasManagedRule} from './verifier.js'
import {makeTotpSecret,verifyTotp} from './totp.js'
import {agentRoutes} from './agentRoutes.js'
import {agentPkiReady} from './agentPki.js'
import {normalizeWindowsEvent} from './eventNormalizer.js'
import {deliverInvite,deliverVerification,inviteLink} from './mailer.js'
import {saveAvatar,readAvatar,removeAvatar} from './avatar.js'

export const app=express()
app.disable('x-powered-by')
app.use(helmet({contentSecurityPolicy:false}))
app.use(cors({origin:(origin,cb)=>{const allowed=(process.env.CORS_ORIGIN||'').split(',').filter(Boolean);cb(null,!origin||allowed.includes(origin))}}))
app.use(express.json({limit:'1mb'}))
const api=express.Router()
app.use('/api/v1',api)
const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next)
const body=(schema,req)=>schema.parse(req.body)
const reqId=req=>String(req.params.id)
const notFound=(res,label='Record')=>res.status(404).json({error:`${label} not found`})
const publicNode=node=>node && ({...node,failures:Number(node.failures),facts:parse(node.snapshot_json)})
const canUseCredential=(user,credential)=>credential&&(user.role==='owner'||user.role==='admin'||credential.owner_user_id===user.id||credential.visibility==='team'&&credential.team_id&&credential.team_id===user.team_id)
function getNode(idValue) {return one('SELECT * FROM nodes WHERE id=?',idValue)}
function getPolicy(idValue) {return one('SELECT * FROM policies WHERE id=?',idValue)}
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
async function applyPolicy(policy,actorId=null) {
  const version=one('SELECT * FROM policy_versions WHERE id=? AND policy_id=?',policy.current_version_id,policy.id)
  if (!version) throw Object.assign(new Error('Policy has no version'),{status:400})
  const rules=parse(version.rules_compiled_json)||[], results=[]
  const conflicts=assignmentConflicts(policy.id,rules,assignedNodes(policy.id))
  if(conflicts.length)throw Object.assign(new Error('Conflicting firewall rules on assigned nodes'),{status:409,conflicts})
  for (const node of assignedNodes(policy.id)) {
    const runId=id()
    run('INSERT INTO policy_apply_runs(id,policy_id,version_id,node_id,status) VALUES(?,?,?,?,?)',runId,policy.id,version.id,node.id,'running')
    try {
      if(node.connection_mode==='agent') {
        const agent=one('SELECT * FROM agents WHERE id=? AND revoked_at IS NULL',node.agent_id)
        if(!agent)throw new Error('No active enrolled agent for node')
        const jobId=id()
        run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',jobId,agent.id,'policy.apply',json({applyRunId:runId,policyId:policy.id,versionId:version.id,group:`WinFireSecure:${policy.id}`,rules}))
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
api.get('/openapi.json',(req,res)=>res.json({openapi:'3.1.0',info:{title:'WinFire Secure API',version:'0.1.0'},servers:[{url:'/api/v1'}],paths:{'/health':{get:{responses:{200:{description:'Healthy'}}}},'/auth/login':{post:{responses:{200:{description:'Access and refresh tokens'}}}},'/nodes':{get:{security:[{bearerAuth:[]}],responses:{200:{description:'Node inventory'}}}},'/policies':{get:{security:[{bearerAuth:[]}],responses:{200:{description:'Policies'}}}}},components:{securitySchemes:{bearerAuth:{type:'http',scheme:'bearer',bearerFormat:'JWT'}}}}))
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

api.use('/agents',agentRoutes)
api.use(auth)
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
  const data=body(z.object({theme:z.enum(['system','dark','light']).optional(),notificationPrefs:z.record(z.string(),z.boolean()).optional(),email:z.email().optional(),password:z.string().min(12).optional()}),req)
  const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res)
  if(user.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can manage owner accounts'})
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
api.get('/audit',requireRole('auditor'),(req,res)=>res.json(all('SELECT * FROM audit_log ORDER BY at DESC LIMIT 500')))

const visibleCredentials=user=>user.role==='owner'||user.role==='admin' ? all('SELECT id,name,type,username,owner_user_id,visibility,team_id,priority,created_at FROM credentials ORDER BY priority,name') : all(`SELECT id,name,type,username,owner_user_id,visibility,team_id,priority,created_at FROM credentials WHERE owner_user_id=? OR (visibility='team' AND team_id=?) ORDER BY priority,name`,user.id,user.team_id)
api.get('/credentials',(req,res)=>res.json(visibleCredentials(req.user)))
api.post('/credentials',requireRole('editor'),(req,res)=>{
  const data=body(z.object({name:z.string().min(1),type:z.enum(['local','domain']),username:z.string().min(1),password:z.string().min(1),visibility:z.enum(['private','team']).default('private'),teamId:z.string().optional(),priority:z.number().int().default(100)}),req)
  const credentialId=id();run('INSERT INTO credentials(id,name,type,username,encrypted_blob,owner_user_id,visibility,team_id,priority) VALUES(?,?,?,?,?,?,?,?,?)',credentialId,data.name,data.type,data.username,seal({password:data.password}),req.user.id,data.visibility,data.teamId||req.user.team_id||null,data.priority)
  audit(req.user.id,'credential.create','credential',credentialId,null,{name:data.name,type:data.type});res.status(201).json({id:credentialId,name:data.name,type:data.type,username:data.username,visibility:data.visibility})
})
api.patch('/credentials/:id',requireRole('editor'),(req,res)=>{
  const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res)
  if(credential.owner_user_id!==req.user.id && !['owner','admin'].includes(req.user.role))return res.status(403).json({error:'Insufficient permission'})
  const data=body(z.object({name:z.string().min(1).optional(),username:z.string().min(1).optional(),password:z.string().min(1).optional(),priority:z.number().int().optional()}),req)
  run('UPDATE credentials SET name=?,username=?,encrypted_blob=?,priority=? WHERE id=?',data.name||credential.name,data.username||credential.username,data.password?seal({password:data.password}):credential.encrypted_blob,data.priority??credential.priority,credential.id)
  audit(req.user.id,'credential.rotate','credential',credential.id,null,{rotated:!!data.password});res.json({id:credential.id,name:data.name||credential.name})
})
api.delete('/credentials/:id',requireRole('editor'),(req,res)=>{const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res);if(credential.owner_user_id!==req.user.id&&!['owner','admin'].includes(req.user.role))return res.status(403).json({error:'Insufficient permission'});run('DELETE FROM credentials WHERE id=?',credential.id);audit(req.user.id,'credential.delete','credential',credential.id,null,null);res.status(204).end()})
api.post('/credentials/:id/assignments',requireRole('editor'),(req,res)=>{
  const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res)
  if(!canUseCredential(req.user,credential))return res.status(403).json({error:'Insufficient permission'})
  const data=body(z.object({nodeId:z.string().optional(),nodeGroupId:z.string().optional()}),req)
  if(!data.nodeId&&!data.nodeGroupId)return res.status(400).json({error:'nodeId or nodeGroupId required'})
  run('INSERT OR IGNORE INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,?)',reqId(req),data.nodeId||null,data.nodeGroupId||null)
  audit(req.user.id,'credential.assign','credential',reqId(req),null,data);res.status(201).json({ok:true})
})
api.post('/credentials/:id/test',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({nodeId:z.string()}),req),node=getNode(data.nodeId)
  if(!node)return notFound(res,'Node')
  const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res,'Credential')
  if(!canUseCredential(req.user,credential))return res.status(403).json({error:'Insufficient permission'})
  const assigned=one('SELECT 1 FROM credential_assignments WHERE credential_id=? AND node_id=?',credential.id,node.id)
  if(!assigned)return res.status(400).json({error:'Assign credential to node first'})
  try {await remote(node,'facts');res.json({success:true})}catch(error){res.json({success:false,error:error.message})}
}))

api.get('/nodes',(_req,res)=>res.json(all('SELECT n.*,f.snapshot_json FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id ORDER BY n.created_at DESC').map(publicNode)))
api.post('/nodes',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({hostname:z.string().min(1),fqdn:z.string().optional(),ip:z.string().optional(),connectionMode:z.enum(['agentless','agent']).default('agentless'),credentialIds:z.array(z.string()).default([])}),req)
  if(data.credentialIds.some(credentialId=>!canUseCredential(req.user,one('SELECT * FROM credentials WHERE id=?',credentialId))))return res.status(403).json({error:'Credential unavailable'})
  const nodeId=id();run('INSERT INTO nodes(id,hostname,fqdn,ip,connection_mode) VALUES(?,?,?,?,?)',nodeId,data.hostname,data.fqdn||null,data.ip||null,data.connectionMode)
  for(const credentialId of data.credentialIds)run('INSERT OR IGNORE INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)',credentialId,nodeId)
  audit(req.user.id,'node.create','node',nodeId,null,data)
  const node=getNode(nodeId);const dns=await lookupDns(node);res.status(201).json({...node,dns})
}))
api.get('/nodes/:id',(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json({...node,facts:parse(one('SELECT snapshot_json FROM node_facts WHERE node_id=?',node.id)?.snapshot_json),dns:one('SELECT * FROM dns_lookups WHERE node_id=?',node.id)})})
api.patch('/nodes/:id',requireRole('editor'),(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');const data=body(z.object({hostname:z.string().min(1).optional(),fqdn:z.string().nullable().optional(),ip:z.string().nullable().optional(),connectionMode:z.enum(['agentless','agent']).optional()}),req);run('UPDATE nodes SET hostname=?,fqdn=?,ip=?,connection_mode=? WHERE id=?',data.hostname||node.hostname,data.fqdn===undefined?node.fqdn:data.fqdn,data.ip===undefined?node.ip:data.ip,data.connectionMode||node.connection_mode,node.id);audit(req.user.id,'node.update','node',node.id,node,data);res.json(getNode(node.id))})
api.delete('/nodes/:id',requireRole('admin'),(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');run('DELETE FROM nodes WHERE id=?',node.id);audit(req.user.id,'node.delete','node',node.id,node,null);res.status(204).end()})
api.post('/nodes/:id/probe',requireRole('editor'),wrap(async(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json(await probeNode(node))}))
api.get('/nodes/:id/facts',(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json(parse(one('SELECT snapshot_json FROM node_facts WHERE node_id=?',node.id)?.snapshot_json)||{})})
api.post('/nodes/:id/facts/refresh',requireRole('editor'),wrap(async(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');const facts=await collectFacts(node);audit(req.user.id,'node.facts.refresh','node',node.id,null,facts);res.json(facts)}))
api.get('/nodes/:id/dns',(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json(one('SELECT * FROM dns_lookups WHERE node_id=?',node.id)||{})})
api.post('/nodes/:id/dns/refresh',requireRole('editor'),wrap(async(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json(await lookupDns(node))}))
api.get('/node-groups',(_req,res)=>res.json(all('SELECT * FROM node_groups ORDER BY name')))
api.post('/node-groups',requireRole('editor'),(req,res)=>{const {name}=body(z.object({name:z.string().min(1)}),req),groupId=id();run('INSERT INTO node_groups(id,name) VALUES(?,?)',groupId,name);audit(req.user.id,'node-group.create','node-group',groupId,null,{name});res.status(201).json({id:groupId,name})})
api.post('/node-groups/:id/members',requireRole('editor'),(req,res)=>{
  const {nodeId}=body(z.object({nodeId:z.string()}),req),node=getNode(nodeId),group=one('SELECT * FROM node_groups WHERE id=?',reqId(req))
  if(!node)return notFound(res,'Node')
  if(!group)return notFound(res,'Node group')
  const assigned=all(`SELECT DISTINCT p.id,p.name,v.rules_compiled_json FROM policies p JOIN policy_assignments a ON a.policy_id=p.id JOIN policy_versions v ON v.id=p.current_version_id WHERE a.node_group_id=?`,group.id)
  const conflicts=[]
  for(const policy of assigned)conflicts.push(...assignmentConflicts(policy.id,parse(policy.rules_compiled_json)||[],[node]))
  for(let i=0;i<assigned.length;i++)for(let j=i+1;j<assigned.length;j++)for(const match of findRuleConflicts(parse(assigned[i].rules_compiled_json)||[],parse(assigned[j].rules_compiled_json)||[]))conflicts.push({nodeId:node.id,hostname:node.hostname,otherPolicyId:assigned[j].id,otherPolicy:assigned[j].name,...match})
  if(conflicts.length)return rejectConflicts(res,conflicts)
  run('INSERT OR IGNORE INTO node_group_members(group_id,node_id) VALUES(?,?)',group.id,nodeId)
  audit(req.user.id,'node-group.member','node-group',group.id,null,{nodeId});res.json({ok:true})
})

api.get('/policies',(_req,res)=>res.json(all('SELECT p.*,v.version_no FROM policies p LEFT JOIN policy_versions v ON v.id=p.current_version_id ORDER BY p.created_at DESC')))
api.post('/policies',requireRole('editor'),(req,res)=>{const data=body(z.object({name:z.string().min(1),description:z.string().default('')}),req),policyId=id();run('INSERT INTO policies(id,name,description,owner_user_id) VALUES(?,?,?,?)',policyId,data.name,data.description,req.user.id);audit(req.user.id,'policy.create','policy',policyId,null,data);res.status(201).json(getPolicy(policyId))})
api.get('/policies/:id',(req,res)=>{const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy');res.json({...policy,versions:all('SELECT id,version_no,created_at,comment FROM policy_versions WHERE policy_id=? ORDER BY version_no DESC',policy.id),assignments:all('SELECT * FROM policy_assignments WHERE policy_id=?',policy.id)})})
api.get('/policies/:id/versions',(req,res)=>{if(!getPolicy(reqId(req)))return notFound(res,'Policy');res.json(all('SELECT * FROM policy_versions WHERE policy_id=? ORDER BY version_no DESC',reqId(req)).map(v=>({...v,graph:parse(v.graph_json),rules:parse(v.rules_compiled_json)})))})
api.post('/policies/:id/versions',requireRole('editor'),(req,res)=>{
  const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy')
  const data=body(z.object({graph:graphSchema,comment:z.string().default('')}),req),rules=compilePolicy(data.graph,policy.id),versionId=id()
  const conflicts=assignmentConflicts(policy.id,rules,assignedNodes(policy.id))
  if(conflicts.length)return rejectConflicts(res,conflicts)
  const last=one('SELECT MAX(version_no) as n FROM policy_versions WHERE policy_id=?',policy.id)?.n||0
  db.transaction(()=>{run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,policy.id,last+1,json(data.graph),json(rules),req.user.id,data.comment);run('UPDATE policies SET current_version_id=? WHERE id=?',versionId,policy.id);audit(req.user.id,'policy.version.create','policy',policy.id,null,{versionId,versionNo:last+1,rules})})()
  res.status(201).json({id:versionId,versionNo:last+1,rules})
})
api.post('/policies/:id/versions/:versionId/recall',requireRole('editor'),wrap(async(req,res)=>{const policy=getPolicy(reqId(req)),version=one('SELECT * FROM policy_versions WHERE id=? AND policy_id=?',req.params.versionId,reqId(req));if(!policy||!version)return notFound(res,'Version');const conflicts=assignmentConflicts(policy.id,parse(version.rules_compiled_json)||[],assignedNodes(policy.id));if(conflicts.length)return rejectConflicts(res,conflicts);run('UPDATE policies SET current_version_id=? WHERE id=?',version.id,policy.id);audit(req.user.id,'policy.recall','policy',policy.id,{versionId:policy.current_version_id},{versionId:version.id});res.json({versionId:version.id,results:await applyPolicy(getPolicy(policy.id),req.user.id)})}))
api.post('/policies/:id/assignments',requireRole('editor'),(req,res)=>{const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy');if(one("SELECT id FROM learning_sessions WHERE generated_policy_id=? AND status IN ('review','apply-failed')",policy.id))return res.status(409).json({error:'Approve the learning proposal before assigning it'});const data=body(z.object({nodeId:z.string().optional(),nodeGroupId:z.string().optional()}),req);if(Number(!!data.nodeId)+Number(!!data.nodeGroupId)!==1)return res.status(400).json({error:'Specify exactly one nodeId or nodeGroupId'});const targets=data.nodeId?[getNode(data.nodeId)].filter(Boolean):all('SELECT n.* FROM nodes n JOIN node_group_members m ON m.node_id=n.id WHERE m.group_id=?',data.nodeGroupId);if(data.nodeId&&!targets.length)return notFound(res,'Node');if(data.nodeGroupId&&!one('SELECT id FROM node_groups WHERE id=?',data.nodeGroupId))return notFound(res,'Node group');const rules=parse(one('SELECT rules_compiled_json FROM policy_versions WHERE id=?',policy.current_version_id)?.rules_compiled_json)||[];const conflicts=assignmentConflicts(policy.id,rules,targets);if(conflicts.length)return rejectConflicts(res,conflicts);const assignmentId=id();run('INSERT INTO policy_assignments(id,policy_id,node_id,node_group_id,assigned_by) VALUES(?,?,?,?,?)',assignmentId,policy.id,data.nodeId||null,data.nodeGroupId||null,req.user.id);audit(req.user.id,'policy.assign','policy',policy.id,null,data);res.status(201).json({id:assignmentId,...data})})
api.post('/policies/:id/apply',requireRole('editor'),wrap(async(req,res)=>{const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy');if(one("SELECT id FROM learning_sessions WHERE generated_policy_id=? AND status IN ('review','apply-failed')",policy.id))return res.status(409).json({error:'Approve the learning proposal before applying it'});res.json({results:await applyPolicy(policy,req.user.id)})}))
api.get('/policies/:id/diff',(req,res)=>{
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

export async function runDriftCheck(data={},actorId=null) {
  if(data.policyId&&!getPolicy(data.policyId))throw Object.assign(new Error('Policy not found'),{status:404})
  if(data.nodeId&&!getNode(data.nodeId))throw Object.assign(new Error('Node not found'),{status:404})
  const policies=data.policyId?[getPolicy(data.policyId)]:all('SELECT * FROM policies WHERE current_version_id IS NOT NULL')
  const checks=[]
  for(const policy of policies){
    const version=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
    if(!version)continue
    const desired=parse(version.rules_compiled_json)||[]
    for(const node of assignedNodes(policy.id).filter(item=>!data.nodeId||item.id===data.nodeId)){
      let status='unknown',diff=null,error=null
      try {
        if(node.connection_mode==='agent')throw new Error('Agent firewall readback is not available')
        const observed=await remote(node,'rules',{group:`WinFireSecure:${policy.id}`})
        diff=diffRules(desired,Array.isArray(observed)?observed:observed?[observed]:[])
        status=diff.add.length||diff.remove.length?'drift':'in-sync'
      } catch(cause){error=cause.message}
      const check={id:id(),policyId:policy.id,versionId:version.id,nodeId:node.id,status,diff,error,checkedAt:now()}
      run('INSERT INTO policy_drift_checks(id,policy_id,version_id,node_id,status,diff_json,error,checked_at) VALUES(?,?,?,?,?,?,?,?)',check.id,check.policyId,check.versionId,check.nodeId,check.status,json(check.diff),check.error,check.checkedAt)
      checks.push(check)
    }
  }
  audit(actorId,'policy.drift.check','policy',data.policyId||null,null,{nodeId:data.nodeId||null,checks:checks.length,drift:checks.filter(check=>check.status==='drift').length,unknown:checks.filter(check=>check.status==='unknown').length})
  return {checks}
}
api.post('/drift/checks',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({nodeId:z.string().optional(),policyId:z.string().optional()}),req)
  res.status(201).json(await runDriftCheck(data,req.user.id))
}))
api.get('/drift/checks',(req,res)=>{
  const filters=[],args=[]
  if(req.query.nodeId){filters.push('node_id=?');args.push(String(req.query.nodeId))}
  if(req.query.policyId){filters.push('policy_id=?');args.push(String(req.query.policyId))}
  res.json(all(`SELECT * FROM policy_drift_checks ${filters.length?'WHERE '+filters.join(' AND '):''} ORDER BY datetime(checked_at) DESC LIMIT 500`,...args).map(row=>({...row,diff:parse(row.diff_json)})))
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
  run('INSERT INTO verifier_results(id,run_id,node_id,policy_id,port,proto,expected,actual,latency_ms,passed,status,reason,probe_status,managed_rule_present) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',result.id,runId,node.id,policy.id,port,rule.protocol,expected,actual,result.latencyMs,result.passed===null?null:Number(result.passed),result.status,result.reason,result.probeStatus,result.managedRulePresent===null?null:Number(result.managedRulePresent))
  return result
}
export async function runVerification(data={},actorId=null) {
  const runId=id()
  run('INSERT INTO verifier_runs(id,status,requested_by) VALUES(?,?,?)',runId,'running',actorId)
  const policies=data.policyId?[getPolicy(data.policyId)].filter(Boolean):all('SELECT * FROM policies WHERE current_version_id IS NOT NULL')
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
  res.status(201).json(await runVerification(data,req.user.id))
}))
api.get('/verifier/runs/:id',(req,res)=>{const result=one('SELECT * FROM verifier_runs WHERE id=?',reqId(req));return result?res.json({...result,results:all('SELECT * FROM verifier_results WHERE run_id=?',result.id)}):notFound(res,'Verifier run')})
api.get('/verifier/results',(req,res)=>res.json(all('SELECT * FROM verifier_results ORDER BY run_at DESC LIMIT 500')))

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
  return new Map([...byNode].map(([nodeId,statuses])=>[nodeId,statuses.includes('drift')?'drift':statuses.includes('unknown')?'unknown':statuses.includes('unchecked')?'unchecked':'in-sync']))
}
function report(name) {
  if(name==='inventory')return all(`SELECT n.id,n.hostname,n.fqdn,n.ip,n.os_version,n.os_build,n.status,n.last_seen_at,n.connection_mode,f.snapshot_json,d.forward_result,d.reverse_result,d.mismatch FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id LEFT JOIN dns_lookups d ON d.node_id=n.id ORDER BY n.hostname`)
  if(name==='coverage'){
    const drift=driftSummaryByNode()
    return all(`SELECT n.id,n.hostname,n.status,COUNT(DISTINCT a.policy_id) AS policy_count,(SELECT status FROM policy_apply_runs WHERE node_id=n.id ORDER BY started_at DESC LIMIT 1) AS last_apply_status,(SELECT passed FROM verifier_results WHERE node_id=n.id ORDER BY run_at DESC LIMIT 1) AS last_verify_passed FROM nodes n LEFT JOIN policy_assignments a ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id) GROUP BY n.id ORDER BY n.hostname`).map(row=>({...row,drift_status:drift.get(row.id)||null}))
  }
  if(name==='verification')return all(`SELECT n.hostname,p.name AS policy,r.port,r.proto,r.expected,r.actual,r.status,r.reason,r.managed_rule_present,r.run_at FROM verifier_results r LEFT JOIN nodes n ON n.id=r.node_id LEFT JOIN policies p ON p.id=r.policy_id ORDER BY r.run_at DESC LIMIT 1000`)
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
for(const name of ['inventory','coverage','compliance','verification'])api.get(`/reports/${name}`,(req,res)=>exportReport(req,res,name,report(name)))
api.get('/reports/dashboard',(_req,res)=>{
  const total=one('SELECT COUNT(*) n FROM nodes').n, reachable=one("SELECT COUNT(*) n FROM nodes WHERE status='reachable'").n
  const policies=one('SELECT COUNT(*) n FROM policies').n, failed=one("SELECT COUNT(*) n FROM policy_apply_runs WHERE status='failed'").n
  const checks=one('SELECT COUNT(passed) n,COALESCE(SUM(passed),0) passed,COUNT(*)-COUNT(passed) inconclusive FROM verifier_results')
  const agentCutoff=new Date(Date.now()-120_000).toISOString()
  const agents=one('SELECT COUNT(*) total,COALESCE(SUM(CASE WHEN revoked_at IS NULL AND last_checkin_at>=? THEN 1 ELSE 0 END),0) online FROM agents',agentCutoff)
  const denied=all("SELECT dst_port,COUNT(*) count FROM log_events WHERE action='block' GROUP BY dst_port ORDER BY count DESC LIMIT 6")
  res.json({totalNodes:total,reachableNodes:reachable,agentsOnline:agents.online,agentsOffline:agents.total-agents.online,policies,failedApplies:failed,verifierPassRate:checks.n?Math.round(checks.passed/checks.n*100):null,verifierInconclusive:checks.inconclusive,deniedPorts:denied})
})

api.get('/segments',(_req,res)=>res.json(all('SELECT * FROM identity_segments ORDER BY created_at DESC')))
api.post('/segments',requireRole('admin'),(req,res)=>{
  const data=body(z.object({name:z.string().min(1),nodeId:z.string(),policyId:z.string().optional(),port:z.number().int().min(1).max(65535),accountSid:z.string().optional(),sourceIp:z.string().optional(),extraPorts:z.array(z.number().int().min(1).max(65535)).default([]),sourceProcess:z.string().optional(),fallbackToLoggedOnUser:z.boolean().default(false),failOpen:z.boolean().default(false),ttlMinutes:z.number().int().min(1).max(10080).default(240),mode:z.enum(['agentless','agent']).default('agentless')}),req)
  const segmentId=id();run('INSERT INTO identity_segments(id,name,node_id,policy_id,port,account_sid,source_ip,extra_ports,source_process,fallback_to_logged_on_user,fail_open,ttl_minutes,mode) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',segmentId,data.name,data.nodeId,data.policyId||null,data.port,data.accountSid||null,data.sourceIp||null,json(data.extraPorts),data.sourceProcess||null,Number(data.fallbackToLoggedOnUser),Number(data.failOpen),data.ttlMinutes,data.mode)
  audit(req.user.id,'segment.create','segment',segmentId,null,data);res.status(201).json(one('SELECT * FROM identity_segments WHERE id=?',segmentId))
})
api.get('/segments/:id/challenges',(req,res)=>res.json(all('SELECT * FROM mfa_challenges WHERE segment_id=? ORDER BY challenged_at DESC LIMIT 200',reqId(req))))
api.post('/segments/:id/challenges',requireRole('editor'),(req,res)=>{
  const segment=one('SELECT * FROM identity_segments WHERE id=?',reqId(req));if(!segment)return notFound(res,'Segment')
  const data=body(z.object({userUpn:z.email(),connection:z.record(z.string(),z.any()).optional()}),req),challengeId=id(),expires=new Date(Date.now()+5*60*1000).toISOString()
  run('INSERT INTO mfa_challenges(id,node_id,user_upn,segment_id,connection_5tuple,status,expires_at) VALUES(?,?,?,?,?,?,?)',challengeId,segment.node_id,data.userUpn,segment.id,json(data.connection),'pending',expires)
  audit(req.user.id,'mfa.challenge.create','challenge',challengeId,null,{segmentId:segment.id,userUpn:data.userUpn});res.status(201).json({id:challengeId,status:'pending',expiresAt:expires})
})
api.post('/segments/:id/challenges/:challengeId/resolve',requireRole('admin'),(req,res)=>{
  const challenge=one('SELECT * FROM mfa_challenges WHERE id=? AND segment_id=?',req.params.challengeId,reqId(req));if(!challenge)return notFound(res,'Challenge')
  if(challenge.status!=='pending'||challenge.expires_at<now())return res.status(409).json({error:'Challenge expired or already resolved'})
  const data=body(z.object({approved:z.boolean()}),req);run('UPDATE mfa_challenges SET status=?,resolved_at=? WHERE id=?',data.approved?'approved':'denied',now(),challenge.id);audit(req.user.id,'mfa.challenge.resolve','challenge',challenge.id,{status:'pending'},{approved:data.approved});res.json({ok:true})
})

api.get('/logon-rights',(req,res)=>res.json(all('SELECT * FROM logon_rights WHERE (? IS NULL OR node_id=?) ORDER BY at DESC LIMIT 500',req.query.nodeId||null,req.query.nodeId||null)))
api.post('/logon-rights/baseline',requireRole('admin'),wrap(async(req,res)=>{
  const {nodeId}=body(z.object({nodeId:z.string()}),req),node=getNode(nodeId);if(!node)return notFound(res,'Node')
  const raw=await remote(node,'rights'),lines=Array.isArray(raw)?raw:[raw].filter(Boolean)
  const rights=[];for(const line of lines){const [name,accounts]=String(line).split('=');for(const account of (accounts||'').split(',').map(s=>s.trim()).filter(Boolean)){const rightId=id();run('INSERT INTO logon_rights(id,node_id,account_sid,logon_type,right_assignment,source,baseline,created_by) VALUES(?,?,?,?,?,?,1,?)',rightId,node.id,account,name.trim(),'allow','secedit',req.user.id);rights.push({id:rightId,account,logonType:name.trim()})}}
  audit(req.user.id,'logon-rights.baseline','node',node.id,null,{count:rights.length});res.status(201).json(rights)
}))

api.get('/logs/search',(req,res)=>{
  const filters=[],args=[]
  for(const [query,column] of [['nodeId','node_id'],['action','action'],['direction','direction'],['program','program'],['challengeId','challenge_id']])if(req.query[query]){filters.push(`${column}=?`);args.push(req.query[query])}
  if(req.query.port){filters.push('dst_port=?');args.push(Number(req.query.port))}
  if(req.query.from){filters.push('datetime(COALESCE(event_time,received_at))>=datetime(?)');args.push(req.query.from)}
  if(req.query.to){filters.push('datetime(COALESCE(event_time,received_at))<=datetime(?)');args.push(req.query.to)}
  res.json(all(`SELECT * FROM log_events ${filters.length?'WHERE '+filters.join(' AND '):''} ORDER BY datetime(COALESCE(event_time,received_at)) DESC LIMIT 1000`,...args))
})
api.post('/logs/ingest',requireRole('editor'),(req,res)=>{
  const data=body(z.object({nodeId:z.string(),events:z.array(z.object({recordId:z.number().optional(),eventId:z.number().int(),action:z.string().optional(),protocol:z.string().optional(),srcIp:z.string().optional(),dstIp:z.string().optional(),dstPort:z.number().optional(),direction:z.string().optional(),program:z.string().optional(),accountSid:z.string().optional(),challengeId:z.string().optional()})).max(1000)}),req)
  let inserted=0;db.transaction(()=>{for(const event of data.events){const result=run('INSERT OR IGNORE INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,program,account_sid,challenge_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',id(),data.nodeId,event.recordId??null,event.eventId,event.action||null,event.protocol||null,event.srcIp||null,event.dstIp||null,event.dstPort||null,event.direction||null,event.program||null,event.accountSid||null,event.challengeId||null);inserted+=result.changes}})()
  res.status(201).json({inserted})
})

export async function pullLogs(nodeId,actorId=null,maxPages=5) {
  const node=getNode(nodeId);if(!node)throw Object.assign(new Error('Node not found'),{status:404})
  let cursor=one('SELECT MAX(record_id) n FROM log_events WHERE node_id=?',nodeId)?.n||0
  let inserted=0,pages=0
  for(;pages<maxPages;pages++){
    const raw=await remote(node,'events',{after:cursor}),events=Array.isArray(raw)?raw:[raw].filter(Boolean)
    if(!events.length)break
    db.transaction(()=>{for(const event of events){
      const item=normalizeWindowsEvent(event)
      const result=run('INSERT OR IGNORE INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,src_port,dst_ip,dst_port,direction,program,account_sid,event_time,event_type,logon_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',id(),nodeId,item.recordId,item.eventId,item.action,item.protocol,item.srcIp,item.srcPort,item.dstIp,item.dstPort,item.direction,item.program,item.accountSid,item.eventTime,item.eventType,item.logonType)
      inserted+=result.changes
    }})()
    const next=Number(events.at(-1).RecordId)
    if(next<=cursor)break
    cursor=next
    if(events.length<500){pages++;break}
  }
  audit(actorId,'logs.pull','node',nodeId,null,{inserted,pages,lastRecordId:cursor})
  return {inserted,pages,lastRecordId:cursor}
}
api.post('/logs/pull',requireRole('editor'),wrap(async(req,res)=>{
  const {nodeId}=body(z.object({nodeId:z.string()}),req)
  res.json(await pullLogs(nodeId,req.user.id))
}))
api.get('/learning-sessions',(_req,res)=>res.json(all('SELECT * FROM learning_sessions ORDER BY started_at DESC')))
api.post('/learning-sessions',requireRole('editor'),(req,res)=>{
  const {nodeId,durationHours}=body(z.object({nodeId:z.string(),durationHours:z.number().min(1).max(720).default(24)}),req),node=getNode(nodeId)
  if(!node)return notFound(res,'Node')
  if(one("SELECT id FROM learning_sessions WHERE node_id=? AND status='active'",nodeId))return res.status(409).json({error:'Node already learning'})
  const sessionId=id(),ends=new Date(Date.now()+durationHours*360e4).toISOString()
  run('INSERT INTO learning_sessions(id,node_id,ends_at,status) VALUES(?,?,?,?)',sessionId,nodeId,ends,'active')
  run('UPDATE nodes SET firewall_state=? WHERE id=?','learning',nodeId)
  audit(req.user.id,'learning.start','node',nodeId,null,{sessionId,ends});res.status(201).json({id:sessionId,nodeId,endsAt:ends})
})
export function finalizeLearning(sessionId,actorId=null) {
  const session=one('SELECT * FROM learning_sessions WHERE id=?',sessionId)
  if(!session)throw Object.assign(new Error('Learning session not found'),{status:404})
  if(!['active','expired'].includes(session.status))throw Object.assign(new Error('Session already finalized'),{status:409})
  const endAt=new Date(Math.min(Date.now(),Date.parse(session.ends_at))).toISOString()
  const observations=db.prepare("SELECT DISTINCT direction,dst_port,protocol,src_ip,dst_ip FROM log_events WHERE node_id=? AND datetime(COALESCE(event_time,received_at)) BETWEEN datetime(?) AND datetime(?) AND action='allow' AND dst_port BETWEEN 1 AND 65535 AND protocol IN ('TCP','UDP') AND direction IN ('in','out')")
  const flows=[]
  for(const event of observations.iterate(session.node_id,session.started_at,endAt)){
    const remoteAddress=event.direction==='in'?event.src_ip:event.dst_ip
    if(!isIP(remoteAddress||''))continue
    flows.push({...event,remoteAddress})
    if(flows.length>500)throw Object.assign(new Error('Learning proposal exceeds 500 distinct flows; narrow the session before finalizing'),{status:409})
  }
  if(!flows.length){
    db.transaction(()=>{run("UPDATE learning_sessions SET status='empty' WHERE id=?",session.id);run("UPDATE nodes SET firewall_state='review' WHERE id=?",session.node_id);audit(actorId,'learning.empty','node',session.node_id,null,{sessionId:session.id})})()
    return {status:'empty',ruleCount:0}
  }
  const policyId=id(),versionId=id(),nodes=flows.map((event,i)=>({id:`learned-${i}`,type:'allow',position:{x:80+(i%4)*180,y:80+Math.floor(i/4)*100},data:{name:`Learned ${event.protocol} ${event.dst_port} ${event.direction}`,localPort:event.direction==='in'?String(event.dst_port):'Any',remotePort:event.direction==='out'?String(event.dst_port):'Any',protocol:event.protocol,remoteAddress:event.remoteAddress,direction:event.direction}}))
  const graph={nodes,edges:[]},rules=compilePolicy(graph,policyId)
  db.transaction(()=>{
    run('INSERT INTO policies(id,name,description,owner_user_id,current_version_id) VALUES(?,?,?,?,?)',policyId,`Learned ${one('SELECT hostname FROM nodes WHERE id=?',session.node_id)?.hostname||'node'}`,`Generated from learning session ${session.id}`,actorId,versionId)
    run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,policyId,1,json(graph),json(rules),actorId,'Learning proposal, review before applying')
    run("UPDATE learning_sessions SET status='review',generated_policy_id=? WHERE id=?",policyId,session.id)
    run("UPDATE nodes SET firewall_state='review' WHERE id=?",session.node_id)
    audit(actorId,'learning.finalize','node',session.node_id,null,{policyId,observations:flows.length})
  })()
  return {policyId,versionId,ruleCount:rules.length,status:'review'}
}
api.post('/learning-sessions/:id/finalize',requireRole('editor'),(req,res)=>res.json(finalizeLearning(reqId(req),req.user.id)))
api.post('/learning-sessions/:id/approve',requireRole('editor'),wrap(async(req,res)=>{
  const session=one('SELECT * FROM learning_sessions WHERE id=?',reqId(req))
  if(!session)return notFound(res,'Learning session')
  if(!['review','apply-failed'].includes(session.status))return res.status(409).json({error:'Session is not awaiting approval'})
  const policy=getPolicy(session.generated_policy_id),node=getNode(session.node_id)
  if(!policy||!node)return res.status(409).json({error:'Learning proposal or node is missing'})
  const rules=parse(one('SELECT rules_compiled_json FROM policy_versions WHERE id=?',policy.current_version_id)?.rules_compiled_json)||[]
  const conflicts=assignmentConflicts(policy.id,rules,[node])
  if(conflicts.length)return rejectConflicts(res,conflicts)
  db.transaction(()=>{
    if(!one('SELECT id FROM policy_assignments WHERE policy_id=? AND node_id=?',policy.id,node.id))run('INSERT INTO policy_assignments(id,policy_id,node_id,assigned_by) VALUES(?,?,?,?)',id(),policy.id,node.id,req.user.id)
    run("UPDATE learning_sessions SET status='applying' WHERE id=?",session.id)
    audit(req.user.id,'learning.approve','node',node.id,null,{sessionId:session.id,policyId:policy.id})
  })()
  const results=await applyPolicy(policy,req.user.id)
  const status=results.every(result=>result.status==='success')?'enforced':results.some(result=>result.status==='failed')?'apply-failed':'applying'
  run('UPDATE learning_sessions SET status=? WHERE id=?',status,session.id)
  run('UPDATE nodes SET firewall_state=? WHERE id=?',status==='enforced'?'enforcing':'review',node.id)
  res.json({status,results})
}))

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
  run('UPDATE agents SET revoked_at=? WHERE id=?',now(),agent.id)
  run("UPDATE nodes SET status='unreachable' WHERE id=?",agent.node_id)
  audit(req.user.id,'agent.revoke','agent',agent.id,null,{nodeId:agent.node_id})
  res.json({revoked:true})
})
api.post('/agents/enrollment-tokens',requireRole('admin'),(req,res)=>{
  if(!agentPkiReady())return res.status(503).json({error:'Configure HTTPS and agent PKI before generating enrollment tokens'})
  const {nodeId}=body(z.object({nodeId:z.string()}),req);if(!getNode(nodeId))return notFound(res,'Node')
  const token=crypto.randomBytes(32).toString('base64url'),tokenId=id(),expires=new Date(Date.now()+15*60*1000).toISOString()
  run('INSERT INTO enrollment_tokens(id,node_id,token_hash,expires_at) VALUES(?,?,?,?)',tokenId,nodeId,hashToken(token),expires)
  audit(req.user.id,'agent.token.create','node',nodeId,null,{expires});res.status(201).json({token,expiresAt:expires})
})
api.get('/agents/:id',(req,res)=>{const agent=one('SELECT * FROM agents WHERE id=?',reqId(req));return agent?res.json(agent):notFound(res,'Agent')})

app.use((error,req,res,_next)=>{
  if(error instanceof z.ZodError)return res.status(400).json({error:'Validation failed',issues:error.issues})
  if(error?.code==='SQLITE_CONSTRAINT_UNIQUE'||error?.code==='SQLITE_CONSTRAINT_PRIMARYKEY')return res.status(409).json({error:'Record already exists'})
  if([400,401,403,404,409,413,429,503].includes(error.status))return res.status(error.status).json({error:error.message,...(error.conflicts?{conflicts:error.conflicts}:{})})
  console.error(error)
  res.status(500).json({error:'Internal server error'})
})
