import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-notifications-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@notifications.test'
process.env.BOOTSTRAP_PASSWORD='notification-owner-password'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {emitNotification,deliverPendingNotifications}=await import('../src/notifications.js')
const {sweepAgentHealth}=await import('../src/agentHealth.js')
const {recordNodeTransportFailure,recordNodeSuccess}=await import('../src/connector.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('preferences control notification fanout, inbox access, and read state',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@notifications.test',password:'notification-owner-password'}).expect(200)
  const ownerAuth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const other=await ownerAuth(request.post('/api/v1/users')).send({email:'other@notifications.test',password:'notification-other-password',role:'auditor'}).expect(201)
  const otherLogin=await request.post('/api/v1/auth/login').send({email:'other@notifications.test',password:'notification-other-password'}).expect(200)
  const otherAuth=req=>req.set('Authorization',`Bearer ${otherLogin.body.accessToken}`)
  await ownerAuth(request.patch(`/api/v1/users/${owner.body.user.id}/profile`)).send({notificationPrefs:{'agent_offline.in_app':true,'agent_offline.email':true,'agent_offline.webhook':true}}).expect(200)
  await ownerAuth(request.patch(`/api/v1/users/${owner.body.user.id}/profile`)).send({notificationPrefs:{'unknown.in_app':true}}).expect(400)
  await otherAuth(request.patch(`/api/v1/users/${other.body.id}/profile`)).send({notificationPrefs:{'agent_offline.in_app':false}}).expect(200)
  emitNotification({eventKey:'offline:test-node:1',category:'agent_offline',title:'Agent offline',body:'test-node stopped checking in',entityType:'node',entityId:'test-node'})
  emitNotification({eventKey:'offline:test-node:1',category:'agent_offline',title:'Agent offline',body:'test-node stopped checking in',entityType:'node',entityId:'test-node'})
  const inbox=await ownerAuth(request.get('/api/v1/notifications')).expect(200)
  assert.equal(inbox.body.unread,1)
  assert.equal(inbox.body.items[0].title,'Agent offline')
  assert.equal((await otherAuth(request.get('/api/v1/notifications')).expect(200)).body.unread,0)
  await otherAuth(request.patch(`/api/v1/notifications/${inbox.body.items[0].id}/read`)).send({}).expect(404)
  await ownerAuth(request.patch(`/api/v1/notifications/${inbox.body.items[0].id}/read`)).send({}).expect(200)
  assert.equal((await ownerAuth(request.get('/api/v1/notifications')).expect(200)).body.unread,0)
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM notification_deliveries').get().count,2)
  assert.equal(await deliverPendingNotifications(),2)
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM notification_deliveries WHERE status='pending'").get().count,2)
  await ownerAuth(request.post('/api/v1/notifications/read-all')).send({}).expect(200)
})

test('agent offline sweep emits one alert per offline transition',async()=>{
  const nodeId='notification-agent-node',agentId='notification-agent'
  db.prepare("INSERT INTO nodes(id,hostname,connection_mode,status,agent_id) VALUES(?,?,'agent','reachable',?)").run(nodeId,'agent-host',agentId)
  db.prepare('INSERT INTO agents(id,node_id,last_checkin_at) VALUES(?,?,?)').run(agentId,nodeId,'2020-01-01T00:00:00.000Z')
  assert.equal(sweepAgentHealth(),1)
  assert.equal(sweepAgentHealth(),0)
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM notifications WHERE category='agent_offline' AND entity_id=?").get(nodeId).count,1)
})

test('agentless transport failures alert once per unreachable transition and recover',()=>{
  const nodeId='notification-winrm-node'
  db.prepare("INSERT INTO nodes(id,hostname,connection_mode,status) VALUES(?,?,'agentless','reachable')").run(nodeId,'winrm-host')
  for(let i=0;i<3;i++)recordNodeTransportFailure(nodeId)
  assert.equal(db.prepare('SELECT status,failures,next_retry_at FROM nodes WHERE id=?').get(nodeId).status,'unreachable')
  assert.equal(db.prepare("SELECT COUNT(DISTINCT event_key) count FROM notifications WHERE category='node_unreachable' AND entity_id=?").get(nodeId).count,1)
  recordNodeTransportFailure(nodeId)
  assert.equal(db.prepare("SELECT COUNT(DISTINCT event_key) count FROM notifications WHERE category='node_unreachable' AND entity_id=?").get(nodeId).count,1)
  recordNodeSuccess(nodeId)
  recordNodeTransportFailure(nodeId)
  recordNodeTransportFailure(nodeId)
  recordNodeTransportFailure(nodeId)
  assert.equal(db.prepare("SELECT COUNT(DISTINCT event_key) count FROM notifications WHERE category='node_unreachable' AND entity_id=?").get(nodeId).count,2)
})

test('HTTPS webhook deliveries retry failures and send the saved event',async()=>{
  const originalFetch=globalThis.fetch,originalUrl=process.env.NOTIFICATION_WEBHOOK_URL
  process.env.NOTIFICATION_WEBHOOK_URL='https://alerts.example.test/winfire'
  let calls=0
  globalThis.fetch=async(url,options)=>{
    calls++
    assert.equal(url.href,'https://alerts.example.test/winfire')
    assert.equal(options.redirect,'error')
    assert.equal(JSON.parse(options.body).category,'agent_offline')
    return new Response(null,{status:calls===1?503:204})
  }
  try{
    await deliverPendingNotifications()
    const failed=db.prepare("SELECT status,attempts,next_attempt_at FROM notification_deliveries WHERE channel='webhook' AND event_key='offline:test-node:1'").get()
    assert.equal(failed.status,'pending')
    assert.equal(failed.attempts,1)
    db.prepare("UPDATE notification_deliveries SET next_attempt_at=? WHERE channel='webhook' AND event_key='offline:test-node:1'").run('2020-01-01T00:00:00.000Z')
    await deliverPendingNotifications()
    assert.equal(db.prepare("SELECT status FROM notification_deliveries WHERE channel='webhook' AND event_key='offline:test-node:1'").get().status,'sent')
    assert.equal(calls,3)
  }finally{globalThis.fetch=originalFetch;if(originalUrl===undefined)delete process.env.NOTIFICATION_WEBHOOK_URL;else process.env.NOTIFICATION_WEBHOOK_URL=originalUrl}
})

test('denied MFA challenge creates a notification',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@notifications.test',password:'notification-owner-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const segment=await auth(request.post('/api/v1/segments')).send({name:'Protected RDP',nodeId:'notification-agent-node',port:3389}).expect(201)
  const challenge=await auth(request.post(`/api/v1/segments/${segment.body.id}/challenges`)).send({userUpn:'operator@example.test'}).expect(201)
  await auth(request.post(`/api/v1/segments/${segment.body.id}/challenges/${challenge.body.id}/resolve`)).send({approved:false}).expect(200)
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM notifications WHERE category='mfa_challenge_failure'").get().count,2)
})

test('queued email is cancelled when the verified address changes',async()=>{
  const owner=db.prepare("SELECT id FROM users WHERE email='owner@notifications.test'").get()
  db.prepare('UPDATE users SET email=?,email_verified=0 WHERE id=?').run('changed@notifications.test',owner.id)
  await deliverPendingNotifications()
  assert.equal(db.prepare("SELECT status FROM notification_deliveries WHERE event_key='offline:test-node:1' AND channel='email'").get().status,'cancelled')
})
