import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-internet-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='internet-owner@example.test'
process.env.BOOTSTRAP_PASSWORD='internet-owner-password-123'
process.env.AUTH_RATE_LIMIT='100'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db,run,id}=await import('../src/db.js')
const request=supertest(app)
await bootstrap()
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

async function auth(){
  const response=await request.post('/api/v1/auth/login').send({email:'internet-owner@example.test',password:'internet-owner-password-123'}).expect(200)
  return {Authorization:`Bearer ${response.body.accessToken}`}
}

test('Internet extension enrollment is one-time and event ingestion is redacted, idempotent, and queryable',async()=>{
  const headers=await auth(),nodeId=id()
  run("INSERT INTO nodes(id,hostname,ip,connection_mode,status) VALUES(?,?,?,'agentless','reachable')",nodeId,'BROWSER-01','192.0.2.44')
  const enrollment=await request.post('/api/v1/internet/enrollment').set(headers).send({nodeId,collectionLevel:'path'}).expect(201)
  assert.match(enrollment.body.token,/^[A-Za-z0-9_-]{32,}$/)
  const enrolled=await request.post('/api/v1/internet/enroll').send({token:enrollment.body.token,browser:'chrome',extensionVersion:'1.0.0',installId:'install-1234567890123456',capabilities:{webNavigation:true}}).expect(201)
  assert.ok(enrolled.body.deviceToken)
  await request.post('/api/v1/internet/enroll').send({token:enrollment.body.token,browser:'chrome',extensionVersion:'1.0.0',installId:'install-1234567890123456',capabilities:{}}).expect(401)
  const event={id:'11111111-1111-4111-8111-111111111111',url:'https://portal.example.com/accounts/view?id=42#secret',observedAt:'2026-09-21T12:00:00.000Z',tabSession:'tab-1'}
  await request.post('/api/v1/internet/events:batch').set('Authorization',`Bearer ${enrolled.body.deviceToken}`).send({events:[event]}).expect(201)
  const duplicate=await request.post('/api/v1/internet/events:batch').set('Authorization',`Bearer ${enrolled.body.deviceToken}`).send({events:[event]}).expect(201)
  assert.equal(duplicate.body.duplicates,1)
  const events=await request.get('/api/v1/internet/events').set(headers).query({q:'portal.example.com'}).expect(200)
  assert.equal(events.body.total,1)
  assert.equal(events.body.items[0].hostname,'portal.example.com')
  assert.equal(events.body.items[0].path_prefix,'/accounts/view')
  assert.equal(events.body.items[0].node_hostname,'BROWSER-01')
  assert.equal(events.body.items[0].tab_session_hash,undefined)
  const summary=await request.get('/api/v1/internet/summary').set(headers).expect(200)
  assert.deepEqual(summary.body,{events:1,domains:1,devices:1,blocked:0,unmappedUsers:1})
  await request.post('/api/v1/internet/events/cleanup').set(headers).send({confirmed:true,before:'2026-09-22T00:00:00.000Z'}).expect(200)
  assert.equal((await request.get('/api/v1/internet/summary').set(headers)).body.events,0)
})

test('administrator browser enrollment binds Internet events to a selected operator',async()=>{
  const headers=await auth(),nodeId=id(),owner=db.prepare('SELECT id,email FROM users WHERE email=?').get('internet-owner@example.test')
  run("INSERT INTO nodes(id,hostname,connection_mode,status) VALUES(?,?, 'agentless','reachable')",nodeId,'BROWSER-BOUND')
  const enrollment=await request.post('/api/v1/internet/enrollment').set(headers).send({nodeId,userId:owner.id,collectionLevel:'host'}).expect(201)
  assert.equal(enrollment.body.userEmail,owner.email)
  const enrolled=await request.post('/api/v1/internet/enroll').send({token:enrollment.body.token,browser:'edge',extensionVersion:'1.0.0',installId:'install-bound-123456789012',capabilities:{}}).expect(201)
  const devices=await request.get('/api/v1/internet/devices').set(headers).expect(200)
  const device=devices.body.find(item=>item.id===enrolled.body.deviceId)
  assert.equal(device.userEmail,owner.email)
  await request.post('/api/v1/internet/events:batch').set('Authorization',`Bearer ${enrolled.body.deviceToken}`).send({events:[{id:'33333333-3333-4333-8333-333333333333',url:'https://bound.example.test/',observedAt:'2026-09-21T13:00:00.000Z'}]}).expect(201)
  const events=await request.get('/api/v1/internet/events').set(headers).query({userId:owner.id}).expect(200)
  assert.equal(events.body.total,1)
  assert.equal(events.body.items[0].user_email,owner.email)
})

test('Internet ingestion rejects credentials, unsafe schemes, and oversized batches',async()=>{
  await request.post('/api/v1/internet/events:batch').send({events:[]}).expect(401)
  const headers=await auth(),nodeId=id()
  run("INSERT INTO nodes(id,hostname,connection_mode,status) VALUES(?,?, 'agentless','reachable')",nodeId,'BROWSER-02')
  const enrollment=await request.post('/api/v1/internet/enrollment').set(headers).send({nodeId,collectionLevel:'host'}).expect(201)
  const enrolled=await request.post('/api/v1/internet/enroll').send({token:enrollment.body.token,browser:'edge',extensionVersion:'1.0.0',installId:'install-2234567890123456',capabilities:{}}).expect(201)
  const result=await request.post('/api/v1/internet/events:batch').set('Authorization',`Bearer ${enrolled.body.deviceToken}`).send({events:[{id:'22222222-2222-4222-8222-222222222222',url:'file:///etc/passwd',observedAt:'2026-09-21T12:00:00.000Z'}]}).expect(201)
  assert.equal(result.body.rejected,1)
})

test('published browser packages declare visibility and policy permissions while excluding private browsing',()=>{
  const root=path.resolve(process.cwd(),'web/public/tools')
  for(const name of ['winfire-internet-chromium','winfire-internet-firefox']){
    const manifest=JSON.parse(fs.readFileSync(path.join(root,name,'manifest.json'),'utf8'))
    assert.equal(manifest.manifest_version,3)
    assert.ok(manifest.permissions.includes('webNavigation'))
    assert.ok(manifest.permissions.includes('declarativeNetRequestWithHostAccess'))
    assert.deepEqual(manifest.optional_host_permissions,['*://*/*'])
    assert.equal(manifest.incognito,'not_allowed')
    assert.match(fs.readFileSync(path.join(root,name,'service-worker.js'),'utf8'),/details\.incognito\)return/)
  }
})

test('Internet policies stage, publish, scope to enrolled devices, and roll back',async()=>{
  const headers=await auth(),nodeId=id()
  run("INSERT INTO nodes(id,hostname,connection_mode,status) VALUES(?,?, 'agentless','reachable')",nodeId,'BROWSER-POLICY')
  const enrollment=await request.post('/api/v1/internet/enrollment').set(headers).send({nodeId,collectionLevel:'host'}).expect(201)
  const enrolled=await request.post('/api/v1/internet/enroll').send({token:enrollment.body.token,browser:'firefox',extensionVersion:'1.0.0',installId:'install-policy-123456',capabilities:{}}).expect(201)
  const staged=await request.post('/api/v1/internet/policies').set(headers).send({failMode:'closed',comment:'Block test domain',rules:[{pattern:'BLOCKED.EXAMPLE',match:'hostname',action:'block',nodeIds:[nodeId],nodeGroupIds:[],resourceTypes:['main_frame']},{pattern:'blocked.example',match:'hostname',action:'block',nodeIds:[nodeId],nodeGroupIds:[],resourceTypes:['main_frame']}]})
  assert.equal(staged.status,201,JSON.stringify(staged.body))
  assert.equal(staged.body.rules.length,1)
  assert.equal((await request.get('/api/v1/internet/config').set('Authorization',`Bearer ${enrolled.body.deviceToken}`)).body.version,0)
  await request.post(`/api/v1/internet/policies/${staged.body.id}/publish`).set(headers).expect(200)
  const config=await request.get('/api/v1/internet/config').set('Authorization',`Bearer ${enrolled.body.deviceToken}`).expect(200)
  assert.equal(config.body.version,staged.body.versionNo)
  assert.equal(config.body.failMode,'closed')
  assert.equal(config.body.rules[0].action.type,'block')
  assert.match(config.body.rules[0].condition.urlFilter,/blocked\.example/)
  await request.post(`/api/v1/internet/policies/${staged.body.id}/rollback`).set(headers).expect(200)
  assert.equal((await request.get('/api/v1/internet/config').set('Authorization',`Bearer ${enrolled.body.deviceToken}`)).body.version,0)
})

test('Internet policy emergency rollback is separately audited and clears a published version',async()=>{
  const headers=await auth()
  const first=await request.post('/api/v1/internet/policies').set(headers).send({rules:[{pattern:'safe.example',match:'hostname',action:'allow'}]}).expect(201)
  await request.post(`/api/v1/internet/policies/${first.body.id}/publish`).set(headers).expect(200)
  const second=await request.post('/api/v1/internet/policies').set(headers).send({rules:[{pattern:'incident.example',match:'hostname',action:'block'}]}).expect(201)
  await request.post(`/api/v1/internet/policies/${second.body.id}/publish`).set(headers).expect(200)
  const rollback=await request.post(`/api/v1/internet/policies/${second.body.id}/emergency-rollback`).set(headers).expect(200)
  assert.equal(rollback.body.emergency,true)
  assert.equal(rollback.body.restoredVersion,first.body.versionNo)
  assert.equal((await request.get('/api/v1/internet/policies').set(headers)).body.find(item=>item.id===first.body.id).status,'published')
  assert.equal((await request.get('/api/v1/internet/policies').set(headers)).body.find(item=>item.id===second.body.id).status,'rolled_back')
})

test('Internet extensions retain open mode and enforce closed mode while disconnected',()=>{
  for(const name of ['winfire-internet-chromium','winfire-internet-firefox']){
    const worker=fs.readFileSync(path.join(process.cwd(),'web/public/tools',name,'service-worker.js'),'utf8')
    assert.match(worker,/applyOfflineFallback/)
    assert.match(worker,/policyFailMode!=='closed'/)
    assert.match(worker,/\|https:\/\//)
  }
})
