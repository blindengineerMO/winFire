import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-mfa-audit-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@mfa-audit.test'
process.env.BOOTSTRAP_PASSWORD='mfa-audit-password-123'
const {app}=await import('../src/app.js')
const {bootstrap,hashToken}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {totpCode}=await import('../src/totp.js')
const {createMfaChallenge,resolveMfaChallenge,expireMfaChallenges}=await import('../src/mfaChallenges.js')
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
  await auth(request.post(`/api/v1/segments/${segment.body.id}/access`)).send({code:invalid}).expect(401)
  const rejected=db.prepare("SELECT * FROM mfa_challenges WHERE segment_id=? ORDER BY challenged_at DESC,rowid DESC LIMIT 1").get(segment.body.id)
  assert.equal(rejected.status,'denied')
  assert.equal(rejected.provider,'totp')
  assert.equal(rejected.failure_reason,'Invalid authenticator code')
  const stub=path.join(dir,'mfa-jit-transport'),portsReceipt=path.join(dir,'jit-ports-receipt')
  fs.writeFileSync(stub,`#!/usr/bin/env node
let data='';process.stdin.on('data',part=>data+=part);process.stdin.on('end',()=>{const request=JSON.parse(data);const responses={jit_preflight:{safe:true},jit_start:{active:true},jit_end:{revoked:true}};if(!(request.operation in responses))process.exit(2);if(request.operation==='jit_start')require('fs').writeFileSync(${JSON.stringify(portsReceipt)},JSON.stringify(request.args.ports));process.stdout.write(JSON.stringify(responses[request.operation]))})
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
