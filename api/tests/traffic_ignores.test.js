import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-traffic-ignores-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@traffic-ignores.test'
process.env.BOOTSTRAP_PASSWORD='traffic-ignores-test-password'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {compactDueEvents}=await import('../src/maintenance.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('global traffic ignore rules discard future matches and hide compacted history',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@traffic-ignores.test',password:'traffic-ignores-test-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=(await auth(request.post('/api/v1/nodes')).send({hostname:'traffic-ignore-node'}).expect(201)).body
  const common={eventId:5157,action:'block',protocol:'TCP',srcIp:'192.0.2.10',dstIp:'198.51.100.20',dstPort:3389,direction:'in',program:'C:\\Windows\\System32\\svchost.exe',accountSid:'S-1-5-21-100'}
  const first=await auth(request.post('/api/v1/logs/ingest')).send({nodeId:node.id,events:[{recordId:1,...common},{recordId:2,...common,dstPort:3390},{recordId:3,eventId:4624,action:'success',program:'C:\\Windows\\System32\\winlogon.exe'}]}).expect(201)
  assert.equal(first.body.inserted,3)
  assert.equal(compactDueEvents(),3)
  const eventId=db.prepare('SELECT id FROM log_events WHERE node_id=? AND record_id=1').get(node.id).id
  const created=await auth(request.post(`/api/v1/logs/${eventId}/ignore-traffic`)).send({}).expect(201)
  assert.equal(created.body.eventId,5157)
  assert.equal((await auth(request.get('/api/v1/settings/traffic-ignores')).expect(200)).body.length,1)
  const future=await auth(request.post('/api/v1/logs/ingest')).send({nodeId:node.id,events:[{recordId:4,...common},{recordId:5,...common,dstPort:3390},{recordId:6,eventId:5156,...common,action:'allow'}]}).expect(201)
  assert.equal(future.body.inserted,2)
  const visible=(await auth(request.get('/api/v1/logs/search').query({nodeId:node.id,hideLoopback:'false'})).expect(200)).body
  assert.equal(visible.total,4)
  assert.ok(visible.items.every(row=>row.record_id!==1&&row.record_id!==4))
  assert.ok(visible.items.some(row=>row.record_id===2))
  await auth(request.delete(`/api/v1/settings/traffic-ignores/${created.body.id}`)).expect(200)
  const restored=(await auth(request.get('/api/v1/logs/search').query({nodeId:node.id,hideLoopback:'false'})).expect(200)).body
  assert.equal(restored.total,5)
  assert.ok(restored.items.some(row=>row.record_id===1))
})

test('traffic ignore rule validation and duplicate protection are enforced',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@traffic-ignores.test',password:'traffic-ignores-test-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const body={label:'Test rule',eventId:5156,action:'allow',protocol:'TCP',srcIp:'192.0.2.1',dstIp:'198.51.100.1',dstPort:443,direction:'out',program:'C:\\app.exe'}
  await auth(request.post('/api/v1/settings/traffic-ignores')).send({...body,dstPort:70000}).expect(400)
  await auth(request.post('/api/v1/settings/traffic-ignores')).send(body).expect(201)
  await auth(request.post('/api/v1/settings/traffic-ignores')).send(body).expect(409)
})

test('account groups use wildcard traffic fields and cleanup removes retained matches',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@traffic-ignores.test',password:'traffic-ignores-test-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=(await auth(request.post('/api/v1/nodes')).send({hostname:'account-ignore-node'}).expect(201)).body
  const base={eventId:5156,action:'allow',protocol:'TCP',srcIp:'192.0.2.50',dstIp:'198.51.100.50',dstPort:443,direction:'out',program:'C:\\Apps\\client.exe'}
  await auth(request.post('/api/v1/logs/ingest')).send({nodeId:node.id,events:[{recordId:10,...base,accountSid:'S-1-5-21-100'},{recordId:11,...base,accountSid:'S-1-5-21-200'},{recordId:12,...base,accountSid:'S-1-5-21-300'}]}).expect(201)
  const created=await auth(request.post('/api/v1/settings/traffic-ignores')).send({label:'Service accounts',eventId:5156,accountSids:['S-1-5-21-100','S-1-5-21-200']}).expect(201)
  assert.equal(created.body.created,2)
  const future=await auth(request.post('/api/v1/logs/ingest')).send({nodeId:node.id,events:[{recordId:13,...base,accountSid:'S-1-5-21-100'},{recordId:14,...base,accountSid:'S-1-5-21-300'}]}).expect(201)
  assert.equal(future.body.inserted,1)
  const cleanup=await auth(request.post('/api/v1/settings/traffic-ignores/cleanup')).send({confirmed:true}).expect(200)
  assert.equal(cleanup.body.deleted,2)
  assert.equal(db.prepare('SELECT COUNT(*) count FROM log_events WHERE node_id=?').get(node.id).count,2)
  await auth(request.post('/api/v1/settings/traffic-ignores/cleanup')).send({confirmed:false}).expect(400)
})
