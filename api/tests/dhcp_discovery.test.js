import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-dhcp-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@dhcp.test'
process.env.BOOTSTRAP_PASSWORD='dhcp-test-password'
const {app}=await import('../src/app.js')
const {bootstrap,issueAccess}=await import('../src/security.js')
const {db,run,one}=await import('../src/db.js')
const {previewDhcpImport,importDhcpLeases}=await import('../src/dhcpDiscovery.js')
await bootstrap()
const request=supertest(app)
const login=await request.post('/api/v1/auth/login').send({email:process.env.BOOTSTRAP_EMAIL,password:process.env.BOOTSTRAP_PASSWORD})
const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
const observedAt=new Date(Date.now()-60000).toISOString(),expiry=new Date(Date.now()+86400000).toISOString()
const lease=(suffix,extra={})=>({ip:`192.168.50.${suffix}`,mac:`02-AA-BB-CC-DD-${String(suffix).padStart(2,'0')}`,hostname:`host-${suffix}.example.test`,leaseExpiry:expiry,...extra})
const payload=leases=>({source:'dhcp.example.test',observedAt,leases})
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('requires administrator and configured local CIDRs; malformed exports are rejected',async()=>{
  await request.post('/api/v1/discovery/dhcp/preview').send(payload([lease(10)])).expect(401)
  await auth(request.post('/api/v1/discovery/dhcp/preview')).send(payload([lease(10)])).expect(409)
  run("INSERT OR REPLACE INTO app_settings(key,value) VALUES('local_asset_cidrs',?)",JSON.stringify(['192.168.50.0/24']))
  run("INSERT INTO users(id,email,password_hash,role) VALUES('dhcp-reader','reader@dhcp.test','unused','viewer')")
  const token=issueAccess(one("SELECT * FROM users WHERE id='dhcp-reader'"))
  await request.post('/api/v1/discovery/dhcp/import').set('Authorization',`Bearer ${token}`).send(payload([lease(10)])).expect(403)
  for(const body of [{...payload([])},{...payload([lease(10)]),observedAt:'bad'},payload([lease(10,{leaseExpiry:'tomorrow'})])])await auth(request.post('/api/v1/discovery/dhcp/preview')).send(body).expect(400)
  await auth(request.post('/api/v1/discovery/dhcp/preview')).send({...payload([lease(10)]),observedAt:new Date(Date.now()+600000).toISOString()}).expect(400)
})

test('preview is read-only; import creates unknown unmanaged nodes without probes and is idempotent',async()=>{
  const body=payload([lease(10,{mac:'01-02-aa-bb-cc-dd-10'})])
  const preview=await auth(request.post('/api/v1/discovery/dhcp/preview')).send(body).expect(200)
  assert.equal(preview.body.summary.created,1)
  assert.equal(one('SELECT count(*) AS n FROM nodes').n,0)
  const imported=await auth(request.post('/api/v1/discovery/dhcp/import')).send(body).expect(201)
  const node=one('SELECT * FROM nodes WHERE ip=?',body.leases[0].ip)
  assert.equal(node.mac_address,'02:aa:bb:cc:dd:10')
  assert.equal(node.status,'unknown');assert.equal(node.firewall_state,'unmanaged');assert.equal(node.agent_required,1)
  assert.equal(node.last_seen_at,null);assert.equal(node.transport,null)
  assert.equal(one('SELECT count(*) AS n FROM discovery_scans').n,0)
  const detail=await auth(request.get(`/api/v1/nodes/${node.id}`)).expect(200)
  assert.equal(detail.body.dhcpLease.hostname,body.leases[0].hostname)
  assert.equal(detail.body.managementVerification.label,'Unchecked')
  const again=await auth(request.post('/api/v1/discovery/dhcp/import')).send(body).expect(201)
  assert.equal(again.body.id,imported.body.id);assert.equal(again.body.replayed,true)
  assert.equal(one('SELECT count(*) AS n FROM dhcp_lease_imports').n,1)
})

test('MAC matching moves unmanaged assets but preserves managed identity and facts',()=>{
  const newer=new Date(Date.now()-30000).toISOString()
  const moved=importDhcpLeases({...payload([lease(11,{mac:'02:aa:bb:cc:dd:10'})]),observedAt:newer},null)
  assert.equal(moved.summary.enriched,1)
  assert.equal(one("SELECT ip FROM nodes WHERE mac_address='02:aa:bb:cc:dd:10'").ip,'192.168.50.11')
  run("INSERT INTO nodes(id,hostname,ip,mac_address,status,firewall_state,agent_required,inventory_source,last_managed_at,os_name) VALUES('managed','Authoritative','192.168.50.20','02:aa:bb:cc:dd:20','reachable','learning',0,'ad',?,'Linux')",observedAt)
  const before=one("SELECT * FROM nodes WHERE id='managed'")
  const result=importDhcpLeases(payload([lease(21,{mac:'02:aa:bb:cc:dd:20'})]),null)
  assert.equal(result.summary.enriched,1)
  const after=one("SELECT * FROM nodes WHERE id='managed'")
  for(const key of ['hostname','ip','status','os_name','firewall_state','last_managed_at','agent_required'])assert.equal(after[key],before[key])
  assert.equal(JSON.parse(after.dhcp_lease_json).ip,'192.168.50.21')
  const stale=previewDhcpImport({...payload([lease(22,{mac:'02:aa:bb:cc:dd:20'})]),observedAt:new Date(Date.now()-120000).toISOString()})
  assert.equal(stale.summary.skipped,1)
})

test('external, expired, invalid MAC, nonactive and ambiguous leases never create assets',()=>{
  const result=importDhcpLeases(payload([
    lease(30,{ip:'8.8.8.8'}),lease(31,{leaseExpiry:new Date(Date.now()-1000).toISOString()}),
    lease(32,{state:'Declined'}),lease(33,{mac:'ff:ff:ff:ff:ff:ff'}),
    lease(34),lease(34,{mac:'02:aa:bb:cc:dd:35'}),lease(36,{ip:'192.168.50.20'}),
    lease(37,{mac:'02:aa:bb:cc:dd:38'}),lease(38),lease(39,{hostname:'<script>'})
  ]),null)
  assert.equal(result.summary.created,0);assert.equal(result.summary.enriched,0)
  assert.equal(result.summary.conflict,5);assert.equal(result.summary.skipped,5)
  assert.equal(one('SELECT count(*) AS n FROM nodes').n,2)
})

test('import history is paged; reports persist skipped/conflicting rows and audit records',async()=>{
  const history=await auth(request.get('/api/v1/discovery/dhcp/imports?pageSize=1&page=2')).expect(200)
  assert.equal(history.body.items.length,1);assert.ok(history.body.total>=4)
  const detail=await auth(request.get(`/api/v1/discovery/dhcp/imports/${history.body.items[0].id}`)).expect(200)
  assert.ok(detail.body.rows.length)
  assert.ok(one("SELECT count(*) AS n FROM audit_log WHERE action='discovery.dhcp.import'").n>=4)
  await auth(request.get('/api/v1/discovery/dhcp/imports?page=0')).expect(400)
  await auth(request.get('/api/v1/discovery/dhcp/imports/missing')).expect(404)
})
