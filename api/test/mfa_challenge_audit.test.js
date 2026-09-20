import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-mfa-audit-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@mfa-audit.test'
process.env.BOOTSTRAP_PASSWORD='mfa-audit-password-123'
const {app}=await import('../src/app.js')
const {bootstrap,hashToken,issueAccess,seal}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {totpCode}=await import('../src/totp.js')
const {createMfaChallenge,resolveMfaChallenge,expireMfaChallenges}=await import('../src/mfaChallenges.js')
const {revokeExpiredGrants}=await import('../src/mfaPortal.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('portal MFA records rejected, approved, replayed and expired attempts without storing a code',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@mfa-audit.test',password:'mfa-audit-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const setup=await auth(request.post('/api/v1/auth/totp/setup')).send({}).expect(200)
  const code=totpCode(setup.body.secret)
  await auth(request.post('/api/v1/auth/totp/confirm')).send({code}).expect(200)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'MFA audit test',type:'local',username:'test-admin',password:'test-password-12345'}).expect(201)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'mfa-audit-node',credentialIds:[credential.body.id]}).expect(201)
  db.prepare("UPDATE nodes SET transport='winrm',firewall_state='enforcing' WHERE id=?").run(node.body.id)
  const segment=await auth(request.post('/api/v1/segments')).send({name:'Audit RDP',nodeId:node.body.id,port:3389,extraPorts:[22],allowedUpns:['owner@mfa-audit.test'],mfaProvider:'totp',ttlMinutes:10}).expect(201)
  const invalid=code==='000000'?'111111':'000000'
  const adEmail='verified@mfa-audit.test',adSid='S-1-5-21-100-200-300-4100'
  db.prepare('INSERT INTO directory_users(id,sid,dn,sam_account_name,upn,enabled,missing,seen_at) VALUES(?,?,?,?,?,1,0,?)').run('mfa-audit-directory-user',adSid,'CN=Verified,DC=mfa-audit,DC=test','verified',adEmail,new Date().toISOString())
  db.prepare("INSERT INTO users(id,email,password_hash,role,email_verified,auth_source,ad_guid,totp_secret) VALUES(?,?,?,'auditor',1,'ad',?,?)").run('mfa-audit-ad-user',adEmail,'unused','mfa-audit-directory-user',seal({secret:setup.body.secret}))
  const adSegment=await auth(request.post('/api/v1/segments')).send({name:'Verified MFA RDP',nodeId:node.body.id,port:3389,allowedUpns:[adEmail],mfaProvider:'totp',ttlMinutes:10}).expect(201)
  const adUser=db.prepare('SELECT * FROM users WHERE id=?').get('mfa-audit-ad-user')
  await request.post(`/api/v1/segments/${adSegment.body.id}/access`).set('Authorization',`Bearer ${issueAccess(adUser)}`).send({code:invalid}).expect(401)
  const verifiedFailure=db.prepare('SELECT verified_account_sid,verified_method,failure_kind FROM mfa_challenges WHERE segment_id=?').get(adSegment.body.id)
  assert.equal(verifiedFailure.verified_account_sid,adSid)
  assert.equal(verifiedFailure.verified_method,'ad-session')
  assert.equal(verifiedFailure.failure_kind,'totp')
  await auth(request.post(`/api/v1/segments/${segment.body.id}/access`)).send({code:invalid}).expect(401)
  const rejected=db.prepare("SELECT * FROM mfa_challenges WHERE segment_id=? ORDER BY challenged_at DESC,rowid DESC LIMIT 1").get(segment.body.id)
  assert.equal(rejected.status,'denied')
  assert.equal(rejected.provider,'totp')
  assert.equal(rejected.failure_reason,'Invalid authenticator code')
  assert.equal(rejected.verified_account_sid,null)
  const stub=path.join(dir,'mfa-jit-transport'),portsReceipt=path.join(dir,'jit-ports-receipt')
  fs.writeFileSync(stub,`#!/usr/bin/env node
let data='';process.stdin.on('data',part=>data+=part);process.stdin.on('end',()=>{const request=JSON.parse(data);const responses={jit_preflight:{safe:true},jit_start:{active:true},jit_end:{revoked:true}};if(!(request.operation in responses))process.exit(2);if(request.operation==='jit_end'&&process.env.WINFIRE_TEST_JIT_END_FAIL==='1')process.exit(1);if(request.operation==='jit_start')require('fs').writeFileSync(${JSON.stringify(portsReceipt)},JSON.stringify(request.args.ports));process.stdout.write(JSON.stringify(responses[request.operation]))})
`,{mode:0o700})
  const priorPython=process.env.WINRM_PYTHON
  process.env.WINRM_PYTHON=stub
  try{
    const approved=await auth(request.post(`/api/v1/segments/${segment.body.id}/access`)).send({code}).expect(201)
    assert.deepEqual(approved.body.ports,[3389,22])
    assert.deepEqual(JSON.parse(fs.readFileSync(portsReceipt,'utf8')),[3389,22])
    const grant=db.prepare('SELECT * FROM jit_grants WHERE id=?').get(approved.body.grantId)
    assert.deepEqual(JSON.parse(grant.ports_json),[3389,22])
    const active=(await auth(request.get('/api/v1/segments/access/grants')).expect(200)).body
    assert.deepEqual(active.find(item=>item.id===grant.id).ports,[3389,22])
    const applyRun=db.prepare('SELECT status,diff_json FROM policy_apply_runs WHERE id=?').get(approved.body.applyRunId)
    assert.equal(applyRun.status,'success')
    assert.deepEqual(JSON.parse(applyRun.diff_json).ports,[3389,22])
    assert.equal(db.prepare('SELECT status FROM mfa_challenges WHERE id=?').get(grant.mfa_challenge_id).status,'approved')
    await auth(request.post(`/api/v1/segments/${segment.body.id}/access`)).send({code}).expect(401)
    assert.equal(db.prepare("SELECT COUNT(*) count FROM mfa_challenges WHERE segment_id=? AND status='denied'").get(segment.body.id).count,2)
    assert.equal(db.prepare('SELECT COUNT(*) count FROM mfa_challenges WHERE segment_id=?').get(segment.body.id).count,3)
    assert.equal(JSON.stringify(db.prepare('SELECT * FROM mfa_challenges WHERE segment_id=?').all(segment.body.id)).includes(code),false)
    const revoked=await auth(request.post(`/api/v1/segments/access/grants/${grant.id}/revoke`)).send({}).expect(200)
    assert.equal(revoked.body.revoked,true)
    assert.equal(db.prepare('SELECT status FROM policy_apply_runs WHERE id=?').get(revoked.body.runId).status,'success')
    const expiredId=crypto.randomUUID(),failedId=crypto.randomUUID()
    const addDue=db.prepare("INSERT INTO jit_grants(id,node_id,grant_type,expires_at) VALUES(?,?,'portal_firewall',?)")
    addDue.run(expiredId,node.body.id,'2020-01-01T00:00:00.000Z')
    assert.equal(await revokeExpiredGrants(),1)
    assert.ok(db.prepare('SELECT revoked_at FROM jit_grants WHERE id=?').get(expiredId).revoked_at)
    const expiryRun=db.prepare("SELECT status,diff_json FROM policy_apply_runs WHERE node_id=? AND json_extract(diff_json,'$.grantId')=? ORDER BY rowid DESC LIMIT 1").get(node.body.id,expiredId)
    assert.equal(expiryRun.status,'success')
    addDue.run(failedId,node.body.id,'2020-01-01T00:00:00.000Z')
    process.env.WINFIRE_TEST_JIT_END_FAIL='1'
    try{assert.equal(await revokeExpiredGrants(),1)}finally{delete process.env.WINFIRE_TEST_JIT_END_FAIL}
    assert.equal(db.prepare('SELECT revoked_at FROM jit_grants WHERE id=?').get(failedId).revoked_at,null)
    assert.equal(db.prepare('SELECT status FROM policy_apply_runs WHERE node_id=? ORDER BY rowid DESC LIMIT 1').get(node.body.id).status,'unknown')
  }finally{if(priorPython===undefined)delete process.env.WINRM_PYTHON;else process.env.WINRM_PYTHON=priorPython}
  const expiredId=createMfaChallenge({nodeId:node.body.id,userUpn:'owner@mfa-audit.test',segmentId:segment.body.id,provider:'entra',expiresAt:'2020-01-01T00:00:00.000Z'})
  assert.equal(resolveMfaChallenge(expiredId,'approved'),false)
  assert.equal(db.prepare('SELECT status FROM mfa_challenges WHERE id=?').get(expiredId).status,'expired')
  assert.equal(expireMfaChallenges(),0)
  const abandonedId=createMfaChallenge({nodeId:node.body.id,userUpn:'owner@mfa-audit.test',segmentId:segment.body.id,provider:'entra',expiresAt:'2020-01-01T00:00:00.000Z'})
  assert.equal(expireMfaChallenges(),1)
  assert.equal(db.prepare('SELECT status FROM mfa_challenges WHERE id=?').get(abandonedId).status,'expired')
  assert.equal(db.prepare("SELECT COUNT(*) count FROM audit_log WHERE entity_type='challenge' AND entity_id=? AND action='mfa.challenge.resolve'").get(expiredId).count,1)
  const denied=await auth(request.get('/api/v1/mfa/challenges/search').query({status:'denied',provider:'totp',userUpn:'owner@mfa-audit.test',pageSize:1})).expect(200)
  assert.equal(denied.body.total,2)
  assert.equal(denied.body.totalPages,2)
  assert.equal(denied.body.items.length,1)
  assert.equal(denied.body.items[0].segment_name,'Audit RDP')
  assert.equal(denied.body.items[0].node_name,'mfa-audit-node')
  await auth(request.get('/api/v1/mfa/challenges/search').query({status:'unknown'})).expect(400)
  const state='test-entra-state-0123456789abcdef',userId=db.prepare('SELECT id FROM users WHERE email=?').get('owner@mfa-audit.test').id
  const cancelledId=createMfaChallenge({nodeId:node.body.id,userUpn:'owner@mfa-audit.test',segmentId:segment.body.id,provider:'entra'})
  db.prepare('INSERT INTO mfa_entra_flows(state_hash,user_id,segment_id,node_id,source_ip,sealed_checks,expires_at,challenge_id) VALUES(?,?,?,?,?,?,?,?)').run(hashToken(state),userId,segment.body.id,node.body.id,'127.0.0.1','unused',new Date(Date.now()+60_000).toISOString(),cancelledId)
  await auth(request.post('/api/v1/segments/entra/cancel')).send({state,error:'access_denied'}).expect(200)
  assert.equal(db.prepare('SELECT status,failure_reason FROM mfa_challenges WHERE id=?').get(cancelledId).status,'denied')
  assert.equal(db.prepare('SELECT failure_reason FROM mfa_challenges WHERE id=?').get(cancelledId).failure_reason,'Entra sign-in returned access_denied')
  await auth(request.post('/api/v1/segments/entra/cancel')).send({state,error:'access_denied'}).expect(401)
})
