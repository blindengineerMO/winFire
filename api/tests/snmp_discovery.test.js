import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-snmp-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@snmp.test'
process.env.BOOTSTRAP_PASSWORD='snmp-test-password-123'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {normalizeSnmpSecret,normalizeArpTable,normalizeForwardingTable,pollSnmpDevice,filterSnmpCandidates}=await import('../src/snmpDiscovery.js')
const {pollSnmpDiscoveryTarget,dueSnmpTargets}=await import('../src/snmpDiscoveryService.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('SNMP credentials validate v2c and v3 secrets without exposing them',async()=>{
  assert.deepEqual(normalizeSnmpSecret('snmp-v2c',{community:'monitoring'}),{community:'monitoring'})
  assert.throws(()=>normalizeSnmpSecret('snmp-v2c',{}),/community string/)
  const v3=normalizeSnmpSecret('snmp-v3',{username:'poller',securityLevel:'authPriv',authProtocol:'sha256',authKey:'auth-secret',privProtocol:'aes',privKey:'private-secret'})
  assert.equal(v3.username,'poller')
  assert.equal(v3.authProtocol,'sha256')
  assert.throws(()=>normalizeSnmpSecret('snmp-v3',{username:'poller',securityLevel:'authPriv',authKey:'short',privKey:'private-secret'}),/authentication key/)
  const login=await request.post('/api/v1/auth/login').send({email:'owner@snmp.test',password:'snmp-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Core switch read-only',type:'snmp-v2c',community:'monitoring',visibility:'private',priority:20}).expect(201)
  assert.equal(credential.body.type,'snmp-v2c')
  const listed=await auth(request.get('/api/v1/credentials')).expect(200)
  assert.equal(listed.body.find(item=>item.id===credential.body.id).type,'snmp-v2c')
  assert.equal(JSON.stringify(listed.body).includes('monitoring'),false)
  const target=await auth(request.post('/api/v1/discovery/snmp-targets')).send({name:'Core switch',host:'192.0.2.1',cidr:'192.0.2.0/24',credentialId:credential.body.id,pollIntervalMinutes:60}).expect(201)
  assert.equal(target.body.cidr,'192.0.2.0/24')
  assert.equal((await auth(request.get('/api/v1/discovery/snmp-targets')).expect(200)).body[0].credentialName,'Core switch read-only')
  assert.deepEqual(dueSnmpTargets().map(item=>item.id),[target.body.id])
  const polled=await pollSnmpDiscoveryTarget(target.body.id,{actorId:login.body.user.id,devicePoll:async()=>({host:'192.0.2.1',arp:[{ip:'192.0.2.10',mac:'00:11:22:33:44:55'}],macPorts:[{mac:'00:11:22:33:44:55',port:12}]}),register:async(ip)=>({ip,nodeId:`node-${ip}`})})
  assert.equal(polled.status,'complete')
  assert.equal(polled.registeredCount,1)
  assert.equal(db.prepare('SELECT last_status FROM snmp_discovery_targets WHERE id=?').get(target.body.id).last_status,'complete')
  assert.deepEqual(dueSnmpTargets().map(item=>item.id),[])
  await auth(request.post('/api/v1/discovery/snmp-targets')).send({name:'bad',host:'192.0.2.2',credentialId:credential.body.id,cidr:'10.0.0.0/33'}).expect(400)
  await auth(request.delete(`/api/v1/discovery/snmp-targets/${target.body.id}`)).expect(204)
})

test('SNMP tables normalize ARP and forwarding data and scope candidates',async()=>{
  const arp=normalizeArpTable({'2.192.0.2.10':{1:2,2:Buffer.from([0,17,34,51,68,85]),4:'dynamic'},'2.192.0.2.11':{1:2,2:Buffer.from([0,0,0,0,0,0])}})
  assert.deepEqual(arp[0],{ip:'192.0.2.10',mac:'00:11:22:33:44:55',interface:'2',state:'dynamic',source:'snmp'})
  const forwarding=normalizeForwardingTable({'0.17.34.51.68.85':{2:12,3:3}})
  assert.deepEqual(forwarding,[{mac:'00:11:22:33:44:55',port:12,status:3}])
  assert.deepEqual(filterSnmpCandidates([...arp,{ip:'198.51.100.5',mac:'aa:bb:cc:dd:ee:ff'}],'192.0.2.0/24').map(row=>row.ip),['192.0.2.10'])
  const fakeSession={table(oid,_max,callback){callback(null,oid.endsWith('4.22')?{'2.192.0.2.10':{2:Buffer.from([0,17,34,51,68,85])}}:{'0.17.34.51.68.85':{2:12}})},close(){}}
  const result=await pollSnmpDevice({host:'192.0.2.1',credential:{type:'snmp-v2c',secret:{community:'monitoring'}},sessionFactory:()=>fakeSession})
  assert.equal(result.arp.length,1)
  assert.equal(result.macPorts[0].port,12)
})
