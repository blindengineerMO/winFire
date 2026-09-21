import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-rpc-filter-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@rpc-filter.test'
process.env.BOOTSTRAP_PASSWORD='rpc-filter-owner-password-123'
process.env.AUTH_RATE_LIMIT='100'
const {app}=await import('../src/app.js')
const {db}=await import('../src/db.js')
const {bootstrap}=await import('../src/security.js')
const {normalizeRpcFilter}=await import('../src/rpcFilters.js')
const request=supertest(app)
await bootstrap()
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('RPC filter normalization creates bounded netsh conditions',()=>{
  const rule=normalizeRpcFilter({interfaceUuid:'e3514235-4b06-11d1-ab04-00c04fc2dcd2',opnum:3,source:'192.0.2.0/24',action:'block',audit:true,label:'DCSync'})
  assert.match(rule.filterKey,/^[0-9a-f-]{36}$/)
  assert.equal(rule.audit,false)
  assert.deepEqual(rule.conditions,[
    {field:'if_uuid',matchType:'equal',data:'e3514235-4b06-11d1-ab04-00c04fc2dcd2'},
    {field:'opnum',matchType:'equal',data:'3'},
    {field:'remote_addr_v4',matchType:'range',data:'192.0.2.0-192.0.2.255'}
  ])
  assert.throws(()=>normalizeRpcFilter({interfaceUuid:'not-a-uuid',action:'block'}),/interface UUID/)
  assert.throws(()=>normalizeRpcFilter({interfaceUuid:'e3514235-4b06-11d1-ab04-00c04fc2dcd2',source:'192.0.2.0/33',action:'block'}),/source/)
  assert.equal(normalizeRpcFilter({interfaceUuid:'e3514235-4b06-11d1-ab04-00c04fc2dcd2',source:'Any',action:'block'}).source,null)
  assert.throws(()=>normalizeRpcFilter({interfaceUuid:'e3514235-4b06-11d1-ab04-00c04fc2dcd2',source:'192.0.2.1-192.0.2.9',action:'block'}),/IPv4 or IPv6/)
})

test('RPC filters can be staged, listed, and deduplicated per node',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@rpc-filter.test',password:'rpc-filter-owner-password-123'}).expect(200)
  const authorization=`Bearer ${login.body.accessToken}`
  db.prepare("INSERT INTO nodes(id,hostname,ip,transport,status,connection_mode) VALUES(?,?,?,?,?,'agentless')").run('rpc-node','RPC-NODE','192.0.2.20','winrm','reachable')
  const body={nodeId:'rpc-node',interfaceUuid:'c681d488-d850-11d0-8c52-00c04fd90f7e',opnum:null,source:'192.0.2.0/24',action:'block',audit:true,label:'Block PetitPotam'}
  const created=await request.post('/api/v1/rpc-filters').set('Authorization',authorization).send(body).expect(201)
  assert.equal(created.body.nodeId,undefined)
  assert.equal(created.body.node_id,'rpc-node')
  assert.equal(created.body.audit,false)
  const listed=await request.get('/api/v1/rpc-filters?nodeId=rpc-node').set('Authorization',authorization).expect(200)
  assert.equal(listed.body.length,1)
  assert.equal(listed.body[0].nodeHostname,'RPC-NODE')
  await request.post('/api/v1/rpc-filters').set('Authorization',authorization).send(body).expect(409)
  db.prepare("UPDATE nodes SET status='unreachable' WHERE id='rpc-node'").run()
  await request.post(`/api/v1/rpc-filters/${created.body.id}/apply-inventory`).set('Authorization',authorization).send({}).expect(409)
})
