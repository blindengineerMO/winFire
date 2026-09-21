import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-process-exclusions-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@process-exclusions.test'
process.env.BOOTSTRAP_PASSWORD='process-exclusions-test-password'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {compactDueEvents}=await import('../src/maintenance.js')
const {isExcludedFirewallEvent}=await import('../src/processExclusions.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('global process names exclude new WFP events and hide prior compacted events',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@process-exclusions.test',password:'process-exclusions-test-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=(await auth(request.post('/api/v1/nodes')).send({hostname:'exclusion-node'}).expect(201)).body
  const old=await auth(request.post('/api/v1/logs/ingest')).send({nodeId:node.id,events:[
    {recordId:1,eventId:5156,action:'allow',program:'\\Device\\HarddiskVolume3\\Program Files\\OpenMonx\\Agent\\OpenMonX-Agent.EXE',direction:'out',protocol:'TCP',dstPort:443},
    {recordId:2,eventId:5156,action:'allow',program:'C:\\Tools\\other-openmonx-agent.exe',direction:'out',protocol:'TCP',dstPort:444},
    {recordId:3,eventId:4624,action:'success',program:'C:\\Tools\\openmonx-agent.exe'}
  ]}).expect(201)
  assert.equal(old.body.inserted,3)
  assert.equal(compactDueEvents(),3)
  const saved=await auth(request.put('/api/v1/settings/process-exclusions')).send({names:['OpenMonX-Agent.EXE','openmonx-agent.exe']}).expect(200)
  assert.deepEqual(saved.body.names,['openmonx-agent.exe'])
  assert.deepEqual((await auth(request.get('/api/v1/settings/process-exclusions')).expect(200)).body.names,['openmonx-agent.exe'])
  const newest=await auth(request.post('/api/v1/logs/ingest')).send({nodeId:node.id,events:[
    {recordId:4,eventId:5157,action:'block',program:'C:\\Program Files\\OpenMonx\\openmonx-agent.exe',direction:'out',protocol:'TCP',dstPort:445},
    {recordId:5,eventId:5157,action:'block',program:'C:\\Tools\\other-openmonx-agent.exe',direction:'out',protocol:'TCP',dstPort:446}
  ]}).expect(201)
  assert.equal(newest.body.inserted,1)
  assert.equal(db.prepare('SELECT COUNT(*) count FROM log_events WHERE node_id=?').get(node.id).count,4)
  assert.equal(isExcludedFirewallEvent({eventId:5157,program:'\\device\\harddiskvolume3\\program files\\openmonx\\agent\\openmonx-agent.exe'}),true)
  assert.equal(isExcludedFirewallEvent({eventId:5157,program:'C:\\Tools\\other-openmonx-agent.exe'}),false)
  const visible=(await auth(request.get('/api/v1/logs/search').query({nodeId:node.id,hideLoopback:'false'})).expect(200)).body
  assert.equal(visible.total,3)
  assert.ok(visible.items.every(row=>row.record_id!==1&&row.record_id!==4))
  assert.equal((await auth(request.get('/api/v1/logs/search').query({nodeId:node.id,program:'openmonx-agent.exe',eventId:5156})).expect(200)).body.total,1)
  await auth(request.put('/api/v1/settings/process-exclusions')).send({names:['C:\\Tools\\app.exe']}).expect(400)
  assert.deepEqual((await auth(request.get('/api/v1/settings/process-exclusions')).expect(200)).body.names,['openmonx-agent.exe'])
  await auth(request.put('/api/v1/settings/process-exclusions')).send({names:[]}).expect(200)
  assert.equal((await auth(request.get('/api/v1/logs/search').query({nodeId:node.id,hideLoopback:'false'})).expect(200)).body.total,4)
})
