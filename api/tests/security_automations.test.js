import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-security-automations-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@automation.test'
process.env.BOOTSTRAP_PASSWORD='automation-test-password-123'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {processSecurityAutomations}=await import('../src/securityAutomations.js')
const {createMfaChallenge,markVerifiedAdChallenge,resolveMfaChallenge}=await import('../src/mfaChallenges.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('destination automation previews events, alerts once, and enforces a per-subject cooldown',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@automation.test',password:'automation-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'target.example.test',ip:'192.0.2.10'}).expect(201)
  const eventTime=new Date().toISOString()
  db.prepare('INSERT INTO log_events(id,node_id,record_id,event_id,action,dst_ip,account_sid,received_at,event_time) VALUES(?,?,?,?,?,?,?,?,?)').run('event-1',node.body.id,1,5157,'blocked','192.0.2.10','S-1-5-21-100-200-300-501',eventTime,eventTime)
  const payload={name:'Watch target',triggerType:'destination',destination:'target.example.test',failureCount:3,windowMinutes:15,cooldownMinutes:60,actionType:'alert',disableMinutes:60,enabled:true}
  const preview=await auth(request.post('/api/v1/security-automations/preview')).send(payload).expect(200)
  assert.equal(preview.body.count,1)
  const policy=await auth(request.post('/api/v1/security-automations')).send(payload).expect(201)
  // A new policy begins observing after creation; insert a second event.
  db.prepare('INSERT INTO log_events(id,node_id,record_id,event_id,action,dst_ip,account_sid,received_at,event_time) VALUES(?,?,?,?,?,?,?,?,?)').run('event-2',node.body.id,2,5157,'blocked','192.0.2.10','S-1-5-21-100-200-300-501',new Date().toISOString(),eventTime)
  assert.equal(await processSecurityAutomations(),1)
  assert.equal(await processSecurityAutomations(),0)
  const incidents=await auth(request.get('/api/v1/security-automations/incidents')).expect(200)
  assert.equal(incidents.body.length,1)
  assert.equal(incidents.body[0].policy_id,policy.body.id)
  assert.equal(incidents.body[0].status,'alert')
})

test('only AD-verified authenticator failures can trigger an AD hold',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@automation.test',password:'automation-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const payload={name:'Failed MFA',triggerType:'mfa_failures',failureCount:3,windowMinutes:15,cooldownMinutes:60,actionType:'disable_ad',disableMinutes:60,enabled:true}
  const policy=(await auth(request.post('/api/v1/security-automations')).send(payload).expect(201)).body
  await auth(request.post('/api/v1/security-automations')).send({...payload,name:'Invalid logoff',actionType:'disable_ad_logoff'}).expect(400)
  const email='mfa-user@automation.test',sid='S-1-5-21-100-200-300-701',userId='mfa-verified-user',directoryId='mfa-verified-directory'
  db.prepare('INSERT INTO directory_users(id,sid,dn,sam_account_name,upn,enabled,missing,seen_at) VALUES(?,?,?,?,?,1,0,?)').run(directoryId,sid,'CN=MFA User,DC=automation,DC=test','mfa-user',email,new Date().toISOString())
  db.prepare("INSERT INTO users(id,email,password_hash,role,email_verified,auth_source,ad_guid) VALUES(?,?,?,'auditor',1,'ad',?)").run(userId,email,'unused-ad-password',directoryId)
  const user=db.prepare('SELECT * FROM users WHERE id=?').get(userId)
  for(let index=0;index<3;index++){
    const challenge=createMfaChallenge({userUpn:email,provider:'totp'})
    assert.equal(markVerifiedAdChallenge(challenge,{...user,ad_guid:'wrong-directory'},email,'ad-session'),false)
    resolveMfaChallenge(challenge,'denied',{reason:'Invalid authenticator code',failureKind:'totp'})
  }
  assert.equal(await processSecurityAutomations({writeStatus:async()=>{throw new Error('Unverified identity reached AD')}}),0)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM ad_account_holds').get().n,0)
  const credential=(await auth(request.post('/api/v1/credentials')).send({name:'MFA action test',type:'domain',username:'AUTOMATION\\action',password:'test-password-12345'}).expect(201)).body
  db.prepare("UPDATE directory_connections SET enabled=1,action_credential_id=? WHERE id='default'").run(credential.id)
  for(let index=0;index<3;index++){
    const challenge=createMfaChallenge({userUpn:email,provider:'totp'})
    assert.equal(markVerifiedAdChallenge(challenge,user,email,'ad-session'),true)
    resolveMfaChallenge(challenge,'denied',{reason:'Invalid authenticator code',failureKind:'totp'})
  }
  let writes=0
  assert.equal(await processSecurityAutomations({writeStatus:async(_settings,_credential,target,enabled)=>{writes++;assert.equal(target.id,directoryId);assert.equal(enabled,false);return {changed:true,beforeUac:512,afterUac:514}}}),1)
  assert.equal(writes,1)
  assert.equal(db.prepare('SELECT status FROM security_automation_incidents WHERE policy_id=?').get(policy.id).status,'disabled')
  assert.equal(db.prepare('SELECT status FROM ad_account_holds WHERE user_guid=?').get(directoryId).status,'active')
  db.prepare('DELETE FROM ad_account_holds WHERE user_guid=?').run(directoryId)
  db.prepare('UPDATE directory_users SET enabled=1 WHERE id=?').run(directoryId)
  const allowed=await auth(request.post('/api/v1/security-automations')).send({...payload,actionType:'alert'}).expect(201)
  assert.equal(allowed.body.action_type,'alert')
})

test('a busy event window is processed beyond one 500-row page',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@automation.test',password:'automation-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const policy=await auth(request.post('/api/v1/security-automations')).send({name:'Busy destination',triggerType:'destination',destination:'192.0.2.11',windowMinutes:15,cooldownMinutes:60,actionType:'alert',enabled:true}).expect(201)
  const node=db.prepare("SELECT id FROM nodes WHERE hostname='target.example.test'").get()
  const insert=db.prepare('INSERT INTO log_events(id,node_id,record_id,event_id,action,dst_ip,account_sid,received_at) VALUES(?,?,?,?,?,?,?,?)')
  const stamp=new Date().toISOString()
  for(let index=0;index<505;index++)insert.run(`busy-${index}`,node.id,100+index,5157,'blocked','192.0.2.11',`S-1-5-21-100-200-300-${index+1000}`,stamp)
  assert.equal(await processSecurityAutomations(),505)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM security_automation_incidents WHERE policy_id=?').get(policy.body.id).n,505)
})

test('a firewall SID without verified outbound process evidence cannot disable AD',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@automation.test',password:'automation-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const policy=await auth(request.post('/api/v1/security-automations')).send({name:'Guarded account action',triggerType:'destination',destination:'192.0.2.12',windowMinutes:15,cooldownMinutes:60,actionType:'disable_ad',disableMinutes:30,enabled:true}).expect(201)
  const node=db.prepare("SELECT id FROM nodes WHERE hostname='target.example.test'").get()
  db.prepare('INSERT INTO log_events(id,node_id,record_id,event_id,action,dst_ip,direction,account_sid,received_at,event_time) VALUES(?,?,?,?,?,?,?,?,?,?)').run('forged-sid',node.id,900,5157,'blocked','192.0.2.12','in','S-1-5-21-100-200-300-500',new Date().toISOString(),new Date().toISOString())
  let verified=false
  assert.equal(await processSecurityAutomations({verifyOwner:async()=>{verified=true;throw new Error('must not run')}}),1)
  assert.equal(verified,false)
  const incident=db.prepare('SELECT * FROM security_automation_incidents WHERE policy_id=?').get(policy.body.id)
  assert.equal(incident.status,'review')
  assert.equal(db.prepare('SELECT COUNT(*) n FROM ad_account_holds').get().n,0)
})

test('verified outbound owner can trigger the combined AD hold and client logoff with an apply run',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@automation.test',password:'automation-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=(await auth(request.post('/api/v1/credentials')).send({name:'Delegated action test',type:'domain',username:'EXAMPLE\\action',password:'test-password-12345'}).expect(201)).body
  db.prepare("UPDATE directory_connections SET enabled=1,action_credential_id=? WHERE id='default'").run(credential.id)
  const sid='S-1-5-21-100-200-300-1234',userId='verified-automation-user',stamp=new Date().toISOString()
  db.prepare('INSERT INTO directory_users(id,sid,dn,sam_account_name,enabled,missing,seen_at) VALUES(?,?,?,?,1,0,?)').run(userId,sid,'CN=Verified,DC=example,DC=test','verified',stamp)
  const policy=(await auth(request.post('/api/v1/security-automations')).send({name:'Verified logoff',triggerType:'destination',destination:'192.0.2.13',windowMinutes:15,cooldownMinutes:60,actionType:'disable_ad_logoff',disableMinutes:30,enabled:true}).expect(201)).body
  const node=db.prepare("SELECT id FROM nodes WHERE hostname='target.example.test'").get()
  db.prepare("UPDATE nodes SET transport='winrm' WHERE id=?").run(node.id)
  const eventTime=new Date().toISOString()
  db.prepare("INSERT INTO log_events(id,node_id,record_id,event_id,action,dst_ip,direction,process_id,received_at,event_time) VALUES(?,?,?,?,? ,?,?,?,?,?)").run('verified-logoff',node.id,990,5156,'allow','192.0.2.13','out',3141,eventTime,eventTime)
  let logoffCalls=0
  const triggered=await processSecurityAutomations({
    verifyOwner:async()=>({sid,createdAt:new Date(Date.parse(eventTime)-1000).toISOString(),sessionId:7}),
    writeStatus:async(_settings,_credential,user,enabled)=>{assert.equal(user.id,userId);assert.equal(enabled,false);return {changed:true,beforeUac:512,afterUac:514}},
    logoff:async(_node,args)=>{logoffCalls++;assert.equal(args.accountSid,sid);assert.equal(args.sessionId,7);return {loggedOff:true,sessionId:7}}
  })
  assert.equal(triggered,1)
  assert.equal(logoffCalls,1)
  assert.equal(db.prepare('SELECT status FROM security_automation_incidents WHERE policy_id=?').get(policy.id).status,'disabled_and_logged_off')
  assert.equal(db.prepare('SELECT status FROM ad_account_holds WHERE user_guid=?').get(userId).status,'active')
  const run=db.prepare('SELECT status,diff_json FROM policy_apply_runs WHERE node_id=? ORDER BY rowid DESC LIMIT 1').get(node.id)
  assert.equal(run.status,'success')
  assert.equal(JSON.parse(run.diff_json).operation,'security_session_logoff')
})
