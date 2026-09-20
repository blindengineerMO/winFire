import test from 'node:test'
import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-public-mfa-'))
process.env.DATA_DIR=dataDir
process.env.BOOTSTRAP_EMAIL='owner@public-mfa.test'
process.env.BOOTSTRAP_PASSWORD='public-mfa-password-123'
const {app}=await import('../src/app.js')
const {bootstrap,hashToken}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {totpCode}=await import('../src/totp.js')
const {createMfaChallenge}=await import('../src/mfaChallenges.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dataDir,{recursive:true,force:true})})

test('public prompt is source-bound, short-lived, and shows only connection context',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@public-mfa.test',password:'public-mfa-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'protected.example.test'}).expect(201)
  const segment=await auth(request.post('/api/v1/segments')).send({name:'Public prompt RDP',nodeId:node.body.id,port:3389,allowedUpns:['owner@public-mfa.test'],mfaProvider:'totp',ttlMinutes:10}).expect(201)
  const promptId=randomUUID()
  db.prepare("INSERT INTO mfa_prompt_events(id,segment_id,target_node_id,log_event_id,source_ip,status,opened_user,opened_session_id,expires_at,opened_at) VALUES(?,?,?,?,?,'opened',?,?,?,?)").run(promptId,segment.body.id,node.body.id,randomUUID(),'127.0.0.1','EXAMPLE\\owner',3,new Date(Date.now()+5*60_000).toISOString(),new Date().toISOString())
  const context=await request.get(`/api/v1/mfa/prompts/${promptId}`).expect(200)
  const spec=await request.get('/api/v1/openapi.json').expect(200)
  assert.equal(spec.body.paths['/mfa/prompts/{id}'].get.security,undefined)
  assert.equal(spec.body.paths['/mfa/prompts/{id}/totp'].post.security,undefined)
  assert.equal(spec.body.paths['/mfa/entra/complete'].post.security,undefined)
  assert.equal(context.body.provider,'totp')
  assert.equal(context.body.target,'protected.example.test')
  assert.equal(context.body.sessionUser,'EXAMPLE\\owner')
  assert.equal(context.body.protocol,'RDP')
  assert.equal(context.body.providerAvailable,false)
  assert.equal(context.headers['cache-control'],'no-store')
  assert.equal(JSON.stringify(context.body).includes('password'),false)
  await request.get(`/api/v1/mfa/prompts/${promptId}`).set('X-Forwarded-For','203.0.113.8').expect(200)
  db.prepare("UPDATE mfa_prompt_events SET source_ip='203.0.113.8' WHERE id=?").run(promptId)
  await request.get(`/api/v1/mfa/prompts/${promptId}`).expect(404)
  db.prepare("UPDATE mfa_prompt_events SET source_ip='127.0.0.1',expires_at='2020-01-01T00:00:00.000Z' WHERE id=?").run(promptId)
  await request.get(`/api/v1/mfa/prompts/${promptId}`).expect(404)
  db.prepare("UPDATE mfa_prompt_events SET expires_at=?,status='consumed' WHERE id=?").run(new Date(Date.now()+5*60_000).toISOString(),promptId)
  await request.get(`/api/v1/mfa/prompts/${promptId}`).expect(404)
  db.prepare("UPDATE mfa_prompt_events SET status='opened' WHERE id=?").run(promptId)
  const setup=await auth(request.post('/api/v1/auth/totp/setup')).send({}).expect(200)
  await auth(request.post('/api/v1/auth/totp/confirm')).send({code:totpCode(setup.body.secret)}).expect(200)
  const failed=await request.post(`/api/v1/mfa/prompts/${promptId}/totp`).send({email:'owner@public-mfa.test',password:'test-password',code:'123456'}).expect(503)
  assert.match(failed.body.error,/LDAPS/)
  const challenge=db.prepare('SELECT status,failure_reason,user_upn FROM mfa_challenges WHERE prompt_id=? ORDER BY challenged_at DESC LIMIT 1').get(promptId)
  assert.equal(challenge.status,'denied')
  assert.equal(challenge.user_upn,'owner@public-mfa.test')
  assert.equal(JSON.stringify(challenge).includes('test-password'),false)

  db.prepare("UPDATE identity_segments SET mfa_provider='entra' WHERE id=?").run(segment.body.id)
  const microsoft=await request.get(`/api/v1/mfa/prompts/${promptId}`).expect(200)
  assert.equal(microsoft.body.provider,'entra')
  assert.equal(microsoft.body.providerAvailable,false)
  await request.post(`/api/v1/mfa/prompts/${promptId}/entra/start`).send({}).expect(503)

  const state='test-public-entra-state-0123456789abcdef'
  const challengeId=createMfaChallenge({nodeId:node.body.id,userUpn:'EXAMPLE\\owner',segmentId:segment.body.id,provider:'entra',promptId})
  db.prepare('INSERT INTO mfa_public_entra_flows(state_hash,prompt_id,source_ip,sealed_checks,challenge_id,expires_at) VALUES(?,?,?,?,?,?)').run(hashToken(state),promptId,'127.0.0.1','unused',challengeId,new Date(Date.now()+60_000).toISOString())
  await request.post('/api/v1/mfa/entra/cancel').send({state,error:'access_denied'}).expect(200)
  assert.equal(db.prepare('SELECT status FROM mfa_challenges WHERE id=?').get(challengeId).status,'denied')
  await request.post('/api/v1/mfa/entra/cancel').send({state,error:'access_denied'}).expect(401)
})
