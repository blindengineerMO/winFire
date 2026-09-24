import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-discovery-schedules-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@discovery-schedules.test'
process.env.BOOTSTRAP_PASSWORD='discovery-schedules-password'
const {diffDiscoveryResults}=await import('../src/networkDiscovery.js')
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
await bootstrap()
const request=supertest(app)

test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('scheduled discovery diffs identify new, dark, and changed hosts',()=>{
  const previous=[
    {ip:'192.168.50.10',hostname:'old-name',fqdn:'old-name.example.test',mac:'AA-BB-CC-DD-EE-10',osName:'Windows',osVersion:'10'},
    {ip:'192.168.50.11',hostname:'offline-host',mac:'aa:bb:cc:dd:ee:11'},
  ]
  const current=[
    {ip:'192.168.50.10',hostname:'new-name',fqdn:'new-name.example.test',mac:'aa:bb:cc:dd:ee:10',osName:'Windows',osVersion:'11'},
    {ip:'192.168.50.12',hostname:'new-host',livenessMethod:'arp'},
  ]
  const diff=diffDiscoveryResults(previous,current)
  assert.deepEqual(diff.summary,{new:1,gone:1,changed:1,previous:2,current:2})
  assert.equal(diff.newHosts[0].ip,'192.168.50.12')
  assert.equal(diff.goneHosts[0].hostname,'offline-host')
  assert.deepEqual(Object.keys(diff.changedHosts[0].changes).sort(),['fqdn','hostname','mac','osVersion'])
})

test('scheduled discovery diff uses a stable address identity and handles empty runs',()=>{
  const diff=diffDiscoveryResults([{ip:'10.0.0.1',hostname:'host-a'}],[{ip:'10.0.0.1',hostname:'host-a',managed:true}])
  assert.equal(diff.summary.changed,1)
  assert.equal(diff.changedHosts[0].changes.managed.after,true)
  assert.deepEqual(diffDiscoveryResults([],[]).summary,{new:0,gone:0,changed:0,previous:0,current:0})
})

test('discovery schedules can be created, paused, edited, and deleted',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@discovery-schedules.test',password:'discovery-schedules-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const created=await auth(request.post('/api/v1/discovery/schedules')).send({name:'Lab LAN',cidrs:['192.0.2.0/30'],intervalMinutes:5,enabled:true}).expect(201)
  assert.equal(created.body.name,'Lab LAN')
  assert.deepEqual(created.body.cidrs,['192.0.2.0/30'])
  assert.equal(created.body.enabled,true)
  const paused=await auth(request.patch(`/api/v1/discovery/schedules/${created.body.id}`)).send({enabled:false,cidrs:['198.51.100.0/30']}).expect(200)
  assert.equal(paused.body.enabled,false)
  assert.deepEqual(paused.body.cidrs,['198.51.100.0/30'])
  await auth(request.delete(`/api/v1/discovery/schedules/${created.body.id}`)).expect(204)
  assert.equal((await auth(request.get('/api/v1/discovery/schedules')).expect(200)).body.length,0)
})

test('unmanaged asset triage queues stale agent-required nodes and supports flagging and exclusion',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@discovery-schedules.test',password:'discovery-schedules-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const discovered=new Date(Date.now()-10*86400000).toISOString()
  db.prepare("INSERT INTO nodes(id,hostname,ip,connection_mode,status,inventory_source,agent_required,first_discovered_at,triage_status) VALUES(?,?,?,?,?,?,?,?,?)").run('triage-node','rogue-host','192.0.2.50','agentless','degraded','discovery',1,discovered,'none')
  const queued=await auth(request.get('/api/v1/nodes/triage')).expect(200)
  assert.equal(queued.body.total,1)
  assert.equal(queued.body.items[0].triageStatus,'none')
  assert.equal(queued.body.items[0].firstDiscoveredAt,discovered)
  await auth(request.post('/api/v1/nodes/triage/bulk')).send({nodeIds:['triage-node'],action:'flagged',note:'Review in bulk'}).expect(200)
  const bulkFlagged=await auth(request.get('/api/v1/nodes/triage')).query({status:'flagged'}).expect(200)
  assert.equal(bulkFlagged.body.items[0].triageNote,'Review in bulk')
  await auth(request.post('/api/v1/nodes/triage/bulk')).send({nodeIds:['triage-node'],action:'none'}).expect(200)
  await auth(request.post('/api/v1/nodes/triage/bulk')).send({nodeIds:['triage-node'],action:'assign_and_retry'}).expect(400)
  await auth(request.patch('/api/v1/nodes/triage-node/triage')).send({status:'flagged',note:'Needs owner review'}).expect(200)
  assert.equal((await auth(request.get('/api/v1/nodes/triage')).expect(200)).body.total,1)
  assert.equal((await auth(request.get('/api/v1/nodes/triage')).query({status:'flagged'}).expect(200)).body.items[0].triageNote,'Needs owner review')
  await auth(request.patch('/api/v1/nodes/triage-node/triage')).send({status:'excluded'}).expect(200)
  assert.equal((await auth(request.get('/api/v1/nodes/triage')).expect(200)).body.total,0)
  assert.equal((await auth(request.get('/api/v1/nodes/triage')).query({status:'excluded'}).expect(200)).body.total,1)
  await auth(request.patch('/api/v1/settings/discovery-triage')).send({unmanagedAssetWindowDays:30}).expect(200)
  assert.equal((await auth(request.get('/api/v1/settings/discovery-triage')).expect(200)).body.unmanagedAssetWindowDays,30)
})
