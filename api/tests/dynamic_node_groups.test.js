import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-dynamic-groups-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@dynamic-groups.test'
process.env.BOOTSTRAP_PASSWORD='dynamic-groups-password-123'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {refreshDynamicGroups,matchesDynamicNode}=await import('../src/dynamicNodeGroups.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('dynamic node groups validate rules and refresh membership from node attributes',async()=>{
  db.prepare('INSERT INTO nodes(id,hostname,fqdn,ip) VALUES(?,?,?,?)').run('dynamic-web','WEB-01','web-01.example.test','10.20.1.10')
  db.prepare('INSERT INTO nodes(id,hostname,fqdn,ip) VALUES(?,?,?,?)').run('dynamic-db','DB-01','db-01.example.test','10.20.2.10')
  const login=await request.post('/api/v1/auth/login').send({email:'owner@dynamic-groups.test',password:'dynamic-groups-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const created=await auth(request.post('/api/v1/node-groups')).send({name:'Web fleet',dynamic:{enabled:true,match:'all',rules:[{field:'hostname',operator:'contains',value:'web'}]}}).expect(201)
  assert.equal(created.body.dynamicEnabled,true)
  assert.equal(created.body.count,1)
  assert.deepEqual(created.body.dynamicRules,[{field:'hostname',operator:'contains',value:'web'}])
  assert.equal(db.prepare('SELECT COUNT(*) count FROM node_group_members WHERE group_id=?').get(created.body.id).count,1)
  const invalid=await auth(request.post('/api/v1/node-groups')).send({name:'Bad',dynamic:{enabled:true,rules:[{field:'hostname',operator:'cidr',value:'10.0.0.0/8'}]}}).expect(400)
  assert.match(invalid.body.error,/CIDR is only valid for IP/)
  await auth(request.patch(`/api/v1/node-groups/${created.body.id}`)).send({dynamic:{enabled:true,match:'all',rules:[{field:'ip',operator:'cidr',value:'10.20.0.0/16'}]}}).expect(200)
  assert.equal(db.prepare('SELECT COUNT(*) count FROM node_group_members WHERE group_id=?').get(created.body.id).count,2)
  const partial=await auth(request.patch(`/api/v1/node-groups/${created.body.id}`)).send({dynamic:{match:'any'}}).expect(200)
  assert.equal(partial.body.dynamicEnabled,true)
  assert.deepEqual(partial.body.dynamicRules,[{field:'ip',operator:'cidr',value:'10.20.0.0/16'}])
  await auth(request.post(`/api/v1/node-groups/${created.body.id}/members`)).send({nodeId:'dynamic-web'}).expect(409)
  db.prepare('UPDATE nodes SET ip=? WHERE id=?').run('192.0.2.10','dynamic-db')
  const refresh=await auth(request.post(`/api/v1/node-groups/${created.body.id}/refresh`)).expect(200)
  assert.equal(refresh.body.results[0].removed,1)
  assert.equal(db.prepare('SELECT COUNT(*) count FROM node_group_members WHERE group_id=?').get(created.body.id).count,1)
  assert.equal(matchesDynamicNode({hostname:'srv',fqdn:'srv.example.test',ip:'192.0.2.5'},{enabled:true,match:'any',rules:[{field:'ip',operator:'cidr',value:'192.0.2.0/24'}]}),true)
  const settings=await auth(request.get('/api/v1/settings/observability')).expect(200)
  assert.equal(settings.body.dynamicNodeGroupsIntervalMinutes,60)
  await auth(request.patch('/api/v1/settings/observability')).send({logRetentionDays:90,dnsRefreshHours:24,dynamicNodeGroupsIntervalMinutes:15}).expect(200)
  assert.equal((await auth(request.get('/api/v1/settings/observability'))).body.dynamicNodeGroupsIntervalMinutes,15)
})
