import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-observability-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@observability.test'
process.env.BOOTSTRAP_PASSWORD='observability-test-password'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {pruneOldEvents,refreshDueDns,compactDueEvents,runCompactionIfDue}=await import('../src/maintenance.js')
const {lookupDns}=await import('../src/connector.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('directory DNS lookup fills a unique address and preserves manual addresses',async()=>{
  const insert=db.prepare("INSERT INTO nodes(id,hostname,fqdn,inventory_source,ip) VALUES(?,?,?,?,?)")
  insert.run('ad-dns-node','AD-DNS','ad-dns.example.test','ad',null)
  insert.run('manual-dns-node','MANUAL-DNS','manual-dns.example.test','manual','192.0.2.10')
  const resolver={lookup:async()=>[{address:'192.0.2.20',family:4}],reverse:async()=>['ad-dns.example.test']}
  const ad=await lookupDns(db.prepare('SELECT * FROM nodes WHERE id=?').get('ad-dns-node'),resolver)
  assert.equal(ad.ip,'192.0.2.20')
  assert.equal(ad.mismatch,false)
  assert.equal(db.prepare('SELECT ip FROM nodes WHERE id=?').get('ad-dns-node').ip,'192.0.2.20')
  await lookupDns(db.prepare('SELECT * FROM nodes WHERE id=?').get('manual-dns-node'),resolver)
  assert.equal(db.prepare('SELECT ip FROM nodes WHERE id=?').get('manual-dns-node').ip,'192.0.2.10')
  db.prepare('UPDATE nodes SET ip=NULL WHERE id=?').run('ad-dns-node')
  const dualStack={lookup:async()=>[{address:'2001:db8::20',family:6},{address:'192.0.2.20',family:4}],reverse:resolver.reverse}
  assert.equal((await lookupDns(db.prepare('SELECT * FROM nodes WHERE id=?').get('ad-dns-node'),dualStack)).ip,'192.0.2.20')
  db.prepare('UPDATE nodes SET ip=NULL WHERE id=?').run('ad-dns-node')
  const ambiguous={lookup:async()=>[{address:'192.0.2.20',family:4},{address:'192.0.2.21',family:4}],reverse:resolver.reverse}
  assert.equal((await lookupDns(db.prepare('SELECT * FROM nodes WHERE id=?').get('ad-dns-node'),ambiguous)).ip,null)
})

test('log filters, retention and scheduled DNS refresh use saved settings',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@observability.test',password:'observability-test-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'localhost',ip:'127.0.0.1'}).expect(201)
  const read=await auth(request.get('/api/v1/settings/observability')).expect(200)
  assert.deepEqual(read.body,{logRetentionDays:90,dnsRefreshHours:24,eventCompactHours:24,dynamicNodeGroupsIntervalMinutes:60,hideLoopbackEvents:true,ignoreLoopbackIngest:false})
  await auth(request.patch('/api/v1/settings/observability')).send({logRetentionDays:0,dnsRefreshHours:24}).expect(400)
  await auth(request.patch('/api/v1/settings/observability')).send({logRetentionDays:30,dnsRefreshHours:12}).expect(200)
  const event=db.prepare('INSERT INTO log_events(id,node_id,record_id,event_id,action,protocol,dst_port,direction,program,challenge_id,event_time,received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
  event.run('old-log',node.body.id,1,5157,'block','TCP',3389,'in','C:\\Old.exe','old-challenge','2026-07-01T12:00:00.000Z','2026-09-19T13:00:00.000Z')
  event.run('new-log',node.body.id,2,5156,'allow','TCP',443,'out','C:\\New.exe','new-challenge','2026-09-19T12:30:00.000Z','2026-09-19T13:00:00.000Z')
  const result=await auth(request.get('/api/v1/logs/search').query({nodeId:node.body.id,action:'allow',direction:'out',program:'C:\\New.exe',challengeId:'new-challenge',port:443,from:'2026-09-19T12:00:00.000Z',to:'2026-09-19T13:00:00.000Z'})).expect(200)
  assert.deepEqual(result.body.items.map(row=>row.id),['new-log'])
  assert.equal(result.body.total,1)
  assert.equal(result.body.items[0].traffic_service,'HTTPS web traffic')
  await auth(request.get('/api/v1/logs/search').query({port:99999})).expect(400)
  await auth(request.get('/api/v1/logs/search').query({from:'2026-09-20T00:00:00.000Z',to:'2026-09-19T00:00:00.000Z'})).expect(400)
  assert.equal(pruneOldEvents(new Date('2026-09-19T13:00:00.000Z')),1)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM log_events').get().n,1)
  assert.equal(await refreshDueDns(new Date('2026-09-19T13:00:00.000Z'),1),0)
  db.prepare('UPDATE dns_lookups SET checked_at=? WHERE node_id=?').run('2026-09-18T00:00:00.000Z',node.body.id)
  assert.equal(await refreshDueDns(new Date('2026-09-19T13:00:00.000Z'),1),1)
  assert.ok(db.prepare('SELECT checked_at FROM dns_lookups WHERE node_id=?').get(node.body.id).checked_at>'2026-09-18T00:00:00.000Z')
  db.prepare('UPDATE dns_lookups SET forward_result=?,reverse_result=? WHERE node_id=?').run(JSON.stringify([{address:'192.0.2.15',family:4}]),JSON.stringify(['unrelated.example.test']),node.body.id)
  const dns=await auth(request.get('/api/v1/reports/dns')).expect(200)
  const dnsRow=dns.body.find(row=>row.id===node.body.id)
  assert.equal(dnsRow.forward_mismatch,true)
  assert.equal(dnsRow.ptr_mismatch,true)
  assert.equal(dnsRow.ptr_missing,false)
  db.prepare('INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?)').run(node.body.id,JSON.stringify({computer:{Model:'Virtual Machine',Manufacturer:'Example'},bios:{SerialNumber:'SERIAL-01'},service:{Status:'Running'},firewall:[{Name:'Domain',Enabled:true}]}),'2026-09-19T13:00:00.000Z')
  const inventory=await auth(request.get('/api/v1/reports/inventory')).expect(200)
  const inventoryRow=inventory.body.find(row=>row.id===node.body.id)
  assert.equal(inventoryRow.model,'Virtual Machine')
  assert.equal(inventoryRow.bios_serial,'SERIAL-01')
  assert.equal(inventoryRow.firewall_profiles,'Domain: on')
  assert.equal('snapshot_json' in inventoryRow,false)
})

test('firewall events paginate and sort the complete filtered result',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@observability.test',password:'observability-test-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'event-page-node'}).expect(201)
  const insert=db.prepare('INSERT INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,program,event_time) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
  for(let i=0;i<125;i++)insert.run(`page-${i}`,node.body.id,i+1,5156,i%2?'block':'allow','TCP',`192.0.2.${i%250+1}`,'198.51.100.5',1000+i,'out',i%2?'C:\\Blocked.exe':'C:\\Allowed.exe',new Date(Date.UTC(2026,8,19,12,0,i)).toISOString())
  const first=await auth(request.get('/api/v1/logs/search').query({nodeId:node.body.id})).expect(200)
  assert.equal(first.body.pageSize,100)
  assert.equal(first.body.total,125)
  assert.equal(first.body.items.length,100)
  assert.equal(first.body.items[0].id,'page-124')
  const second=await auth(request.get('/api/v1/logs/search').query({nodeId:node.body.id,page:2})).expect(200)
  assert.equal(second.body.items.length,25)
  assert.equal(second.body.items.at(-1).id,'page-0')
  const filtered=await auth(request.get('/api/v1/logs/search').query({nodeId:node.body.id,action:'block',program:'Blocked',dstIp:'198.51.100',sortBy:'port',sortDir:'asc',pageSize:25})).expect(200)
  assert.equal(filtered.body.total,62)
  assert.equal(filtered.body.items.length,25)
  assert.equal(filtered.body.items[0].dst_port,1001)
  assert.equal(filtered.body.items.at(-1).dst_port,1049)
  await auth(request.get('/api/v1/logs/search').query({sortBy:'arbitrary SQL'})).expect(400)
  await auth(request.get('/api/v1/logs/search').query({pageSize:501})).expect(400)
})

test('suspending a user invalidates access and owner deletion removes the account',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@observability.test',password:'observability-test-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const user=await auth(request.post('/api/v1/users')).send({email:'operator@observability.test',password:'operator-test-password',role:'editor'}).expect(201)
  const operator=await request.post('/api/v1/auth/login').send({email:'operator@observability.test',password:'operator-test-password'}).expect(200)
  await auth(request.patch(`/api/v1/users/${user.body.id}`)).send({suspended:true}).expect(200)
  await request.get('/api/v1/auth/me').set('Authorization',`Bearer ${operator.body.accessToken}`).expect(401)
  await auth(request.delete(`/api/v1/users/${user.body.id}`)).expect(204)
  assert.equal(db.prepare('SELECT id FROM users WHERE id=?').get(user.body.id),undefined)
})

test('dashboard reports verifier and MFA decision trends',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@observability.test',password:'observability-test-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const at=new Date().toISOString(),day=at.slice(0,10)
  db.prepare('INSERT INTO verifier_runs(id,status,started_at) VALUES(?,?,?)').run('trend-run','complete',at)
  db.prepare('INSERT INTO verifier_results(id,run_id,port,proto,expected,actual,passed,status,run_at) VALUES(?,?,?,?,?,?,?,?,?)').run('trend-check','trend-run',443,'TCP','open','open',1,'pass',at)
  db.prepare('INSERT INTO mfa_challenges(id,status,resolved_at) VALUES(?,?,?)').run('trend-mfa','approved',at)
  const dashboard=await auth(request.get('/api/v1/reports/dashboard')).expect(200)
  assert.equal(dashboard.body.verifierTrend.find(row=>row.day===day)?.passRate,100)
  assert.equal(dashboard.body.mfaTrend.find(row=>row.day===day)?.approved,1)
  assert.equal(dashboard.body.verifierPassRate,100)
})

test('self-service password changes require the current password and revoke prior sessions',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@observability.test',password:'observability-test-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  await auth(request.patch(`/api/v1/users/${owner.body.user.id}/profile`)).send({currentPassword:'wrong-password',password:'new-observability-password'}).expect(401)
  await auth(request.patch(`/api/v1/users/${owner.body.user.id}/profile`)).send({currentPassword:'observability-test-password',password:'new-observability-password'}).expect(200)
  await auth(request.get('/api/v1/auth/me')).expect(401)
  await request.post('/api/v1/auth/login').send({email:'owner@observability.test',password:'new-observability-password'}).expect(200)
})

test('node and policy inventory surface the latest verifier result',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@observability.test',password:'new-observability-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'badge-node'}).expect(201)
  const policy=await auth(request.post('/api/v1/policies')).send({name:'Badge policy'}).expect(201)
  const at=new Date().toISOString()
  db.prepare('INSERT INTO verifier_runs(id,status,started_at) VALUES(?,?,?)').run('badge-run','complete',at)
  db.prepare('INSERT INTO verifier_results(id,run_id,node_id,policy_id,port,proto,expected,actual,passed,status,reason,run_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run('badge-check','badge-run',node.body.id,policy.body.id,3389,'TCP','closed','open',0,'fail','Unexpected open port',at)
  const nodes=await auth(request.get('/api/v1/nodes')).expect(200)
  assert.equal(nodes.body.find(row=>row.id===node.body.id)?.verification?.status,'fail')
  const detail=await auth(request.get(`/api/v1/nodes/${node.body.id}`)).expect(200)
  assert.equal(detail.body.verification.reason,'Unexpected open port')
  const policies=await auth(request.get('/api/v1/policies')).expect(200)
  assert.equal(policies.body.find(row=>row.id===policy.body.id)?.verificationStatus,'fail')
})

test('credential assignment validates targets and is idempotent',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@observability.test',password:'new-observability-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Reader',type:'domain',username:'reader@example.test',password:'vault-test-secret'}).expect(201)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'credential-target'}).expect(201)
  await auth(request.post(`/api/v1/credentials/${credential.body.id}/assignments`)).send({nodeId:node.body.id,nodeGroupId:'missing'}).expect(400)
  await auth(request.post(`/api/v1/credentials/${credential.body.id}/assignments`)).send({nodeId:'missing'}).expect(404)
  await auth(request.post(`/api/v1/credentials/${credential.body.id}/assignments`)).send({nodeId:node.body.id}).expect(201)
  const repeated=await auth(request.post(`/api/v1/credentials/${credential.body.id}/assignments`)).send({nodeId:node.body.id}).expect(200)
  assert.equal(repeated.body.alreadyAssigned,true)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM credential_assignments WHERE credential_id=? AND node_id=?').get(credential.body.id,node.body.id).n,1)
})

test('loopback display and ingest controls preserve searchable compacted events',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@observability.test',password:'new-observability-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=(await auth(request.post('/api/v1/nodes')).send({hostname:'loopback-node',connectionMode:'agent'}).expect(201)).body
  const events=[
    {recordId:700,eventId:5156,action:'allow',protocol:'TCP',srcIp:'127.0.0.1',dstIp:'127.0.0.1',dstPort:8080,direction:'in',program:'C:\\loop.exe'},
    {recordId:701,eventId:5156,action:'allow',protocol:'TCP',srcIp:'192.0.2.15',dstIp:'198.51.100.5',dstPort:8443,direction:'in',program:'C:\\service.exe'}
  ]
  await auth(request.post('/api/v1/logs/ingest')).send({nodeId:node.id,events}).expect(201)
  assert.equal((await auth(request.get('/api/v1/logs/search').query({nodeId:node.id})).expect(200)).body.total,1)
  assert.equal((await auth(request.get('/api/v1/logs/search').query({nodeId:node.id,hideLoopback:'false'})).expect(200)).body.total,2)
  await auth(request.patch('/api/v1/settings/observability')).send({logRetentionDays:30,dnsRefreshHours:24,eventCompactHours:1,hideLoopbackEvents:true,ignoreLoopbackIngest:true}).expect(200)
  const ignored=await auth(request.post('/api/v1/logs/ingest')).send({nodeId:node.id,events:[{...events[0],recordId:702}]}).expect(201)
  assert.equal(ignored.body.inserted,0)
  const compacted=compactDueEvents(new Date(Date.now()+3*36e5))
  assert.ok(compacted>=2)
  assert.ok(db.prepare('SELECT pattern_id FROM log_events WHERE node_id=? AND record_id=701').get(node.id).pattern_id)
  const row=(await auth(request.get('/api/v1/logs/search').query({nodeId:node.id,srcIp:'192.0.2.15'})).expect(200)).body.items[0]
  assert.equal(row.src_ip,'192.0.2.15')
  assert.equal(row.dst_port,8443)
  assert.equal((await auth(request.get('/api/v1/logs/search').query({nodeId:node.id})).expect(200)).body.total,1)
  const cadenceStart=new Date()
  db.prepare("UPDATE app_settings SET value=? WHERE key='event_compact_last_at'").run(cadenceStart.toISOString())
  assert.equal(runCompactionIfDue(new Date(cadenceStart.getTime()+30*60_000)).due,false)
  assert.equal(runCompactionIfDue(new Date(cadenceStart.getTime()+2*36e5)).due,true)
  await auth(request.patch('/api/v1/settings/observability')).send({logRetentionDays:90,dnsRefreshHours:24,eventCompactHours:24,hideLoopbackEvents:true,ignoreLoopbackIngest:false}).expect(200)
})
