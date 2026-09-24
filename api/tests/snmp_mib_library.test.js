import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'
import snmp from 'net-snmp'
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-mib-test-'))
process.env.DATA_DIR=dir
process.env.NODE_ENV='test'
process.env.BOOTSTRAP_EMAIL='mib-owner@example.test'
process.env.BOOTSTRAP_PASSWORD='mib-test-password-123'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {importMibs,listMibs,mibDetails,updateMib,deleteMib,collectionPlan,matchMib,nodeMibFacts}=await import('../src/snmpMibLibrary.js')
const {pollSnmpDevice}=await import('../src/snmpDiscovery.js')
const {ensureSnmpNode}=await import('../src/snmpDiscoveryService.js')
const {boundedWalk,walkTable,collectMibPlan}=await import('../src/snmpMibCollector.js')
await bootstrap()
const request=supertest(app)
const files=['WINFIRE-TEST-MIB.mib','WINFIRE-TEST-SMI.mib'].map(filename=>({filename,content:fs.readFileSync(new URL(`./fixtures/mibs/${filename}`,import.meta.url),'utf8')}))
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})
const identity={sysDescr:'Example switch 2.0',sysObjectId:'1.3.6.1.4.1.424242.99',sysName:'Core switch'}
let mibId,actorId,auth

test('library routes require administration and preview does not mutate the library',async()=>{
  await request.get('/api/v1/discovery/snmp-library').expect(401)
  const login=await request.post('/api/v1/auth/login').send({email:'mib-owner@example.test',password:'mib-test-password-123'}).expect(200)
  actorId=login.body.user.id;auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const list=await auth(request.get('/api/v1/discovery/snmp-library?limit=5')).expect(200)
  assert.equal(list.body.items.length,5)
  assert.ok(list.body.total>=14)
  const before=list.body.total
  const preview=await auth(request.post('/api/v1/discovery/snmp-library/preview')).send({files}).expect(200)
  assert.equal(preview.body.modules.length,2)
  assert.equal(listMibs().total,before)
  const imported=await auth(request.post('/api/v1/discovery/snmp-library/import')).send({files}).expect(201)
  assert.equal(imported.body.modules[0].moduleName,'WINFIRE-TEST-SMI')
  const row=listMibs({search:'WINFIRE-TEST-MIB'}).items[0];mibId=row.id
  assert.equal(row.objectCount,3)
  const detail=mibDetails(mibId)
  assert.equal(detail.objects.find(o=>o.name==='modelName').oid,'1.3.6.1.4.1.424242.1.1.0')
  assert.equal(detail.objects.find(o=>o.name==='portName').kind,'column')
  assert.ok(!JSON.stringify(detail).includes('DEFINITIONS'))
  assert.equal(listMibs({source:'imported',limit:1,page:2}).page,2)
})

test('imports resolve dependencies, reject invalid data atomically, and require explicit replacement',async()=>{
  const before=listMibs().total
  await assert.rejects(importMibs({files:[{filename:'bad.mib',content:'not an ASN.1 module'}]},actorId),/complete ASN.1/)
  const changed=files[0].content.replace('WINFIRE-TEST-SMI;','MISSING-SMI;').replaceAll('WINFIRE-TEST-MIB','ANOTHER-MIB')
  await assert.rejects(importMibs({files:[{filename:'broken.mib',content:changed}]},actorId),/Missing dependency MISSING-SMI/)
  await assert.rejects(importMibs({files:[{...files[0],content:files[0].content.replace('Device model','Updated model')}]},actorId),/already exists/)
  assert.equal(listMibs().total,before)
  const duplicate=await importMibs({files},actorId)
  assert.ok(duplicate.modules.every(m=>m.action==='unchanged'))
  const replacement=await importMibs({files:[{...files[0],content:files[0].content.replace('Device model','Updated model')}],replace:true},actorId)
  assert.equal(replacement.modules[0].action,'replace')
  const dependencyId=listMibs({search:'WINFIRE-TEST-SMI'}).items[0].id
  assert.throws(()=>deleteMib(dependencyId,actorId),/Required by/)
  await auth(request.patch(`/api/v1/discovery/snmp-library/${mibId}`)).send({selectedObjects:['madeUpObject']}).expect(400)
  await auth(request.patch(`/api/v1/discovery/snmp-library/${mibId}`)).send({match:{sysObjectIdPrefixes:['1.3.6;rm'],sysDescrContains:[]}}).expect(400)
})

test('numeric OID matching is boundary-safe; disabled libraries are not collected',()=>{
  assert.equal(matchMib({sysObjectId:'1.3.6.1.4.1.99.1'},{sysObjectIdPrefixes:['1.3.6.1.4.1.9']}),null)
  assert.equal(matchMib({sysObjectId:'.1.3.6.1.4.1.9.1'},{sysObjectIdPrefixes:['1.3.6.1.4.1.9']}).method,'sysObjectID')
  assert.equal(matchMib({sysDescr:'pfSense 2.8'},{sysDescrContains:['PFSENSE']}).method,'sysDescr')
  assert.ok(collectionPlan(identity).profiles.some(p=>p.id===mibId))
  updateMib(mibId,{enabled:false},actorId)
  assert.ok(!collectionPlan(identity).profiles.some(p=>p.id===mibId))
  updateMib(mibId,{enabled:true},actorId)
})

function fakeSession(){return {
  closed:false,
  get(oids,cb){const oid=oids[0],base={'1.3.6.1.2.1.1.1.0':identity.sysDescr,'1.3.6.1.2.1.1.2.0':identity.sysObjectId,'1.3.6.1.2.1.1.5.0':identity.sysName,'1.3.6.1.4.1.424242.1.1.0':'Switch model A','1.3.6.1.4.1.424242.1.2.0':0};cb(null,[Object.hasOwn(base,oid)?{oid,type:4,value:base[oid]}:{oid,type:128,value:null}])},
  subtree(oid,_max,feed,done){if(oid==='1.3.6.1.4.1.424242.1.3.1.2')feed([{oid:oid+'.1',type:4,value:Buffer.from('uplink')}]);else if(oid==='1.3.6.1.2.1.47.1.1.1')feed([{oid:oid+'.1.11.1',type:4,value:Buffer.from('SERIAL-01')},{oid:oid+'.1.13.1',type:4,value:Buffer.from('Model A')}]);done()},
  close(){this.closed=true}
}}
test('optional table failures preserve verification, collect imported objects and persist reusable device links',async()=>{
  const session=fakeSession(),device=await pollSnmpDevice({host:'192.0.2.88',credential:{type:'snmp-v2c',secret:{community:'test'}},sessionFactory:()=>session})
  assert.equal(session.closed,true)
  assert.equal(device.arp.length,0)
  assert.equal(device.hardware[0].serialNumber,'SERIAL-01')
  const module=device.mibCollection.profiles.find(p=>p.id===mibId)
  assert.equal(module.status,'supported')
  assert.equal(module.objects.find(o=>o.name==='modelName').values[0].value,'Switch model A')
  assert.equal(module.objects.find(o=>o.name==='portName').values[0].value,'uplink')
  const nodeId=ensureSnmpNode({host:'192.0.2.88'},device,new Date().toISOString())
  const node=db.prepare('SELECT status,probe_status FROM nodes WHERE id=?').get(nodeId)
  assert.equal(node.status,'reachable');assert.equal(node.probe_status,'snmp-authenticated')
  assert.equal(collectionPlan(identity,{nodeId}).profiles.find(p=>p.id===mibId).evidence.reused,true)
  assert.equal(collectionPlan({...identity,sysObjectId:'1.3.6.1.4.1.99.1'},{nodeId}).profiles.some(p=>p.id===mibId),false)
  assert.equal(mibDetails(mibId).bindings[0].nodeId,nodeId)
  const facts=await auth(request.get(`/api/v1/nodes/${nodeId}/snmp-mibs?search=uplink&limit=1`)).expect(200)
  assert.equal(facts.body.items[0].value,'uplink');assert.equal(facts.body.total,1)
  const filtered=nodeMibFacts(nodeId,{moduleId:mibId,limit:1,page:2})
  assert.equal(filtered.page,2);assert.equal(filtered.items.length,1)
})

test('identity failure cannot mark a device as verified; bounded walks stop oversized responses',async()=>{
  const bad={get:(_oids,cb)=>cb(new Error('Timed out')),close(){this.closed=true}}
  await assert.rejects(pollSnmpDevice({host:'192.0.2.89',credential:{type:'snmp-v2c'},sessionFactory:()=>bad}),/Timed out/)
  assert.equal(bad.closed,true)
  let stopped=false
  const result=await boundedWalk({subtree(oid,_max,feed,done){stopped=feed(Array.from({length:100},(_,i)=>({oid:oid+'.1.1.'+i,type:2,value:i})));done()}},'1.3.6.1.2.1.2.2',{maxValues:3})
  assert.equal(result.values.length,3);assert.equal(result.truncated,true);assert.equal(stopped,true)
  assert.equal(Object.keys(walkTable(result,'1.3.6.1.2.1.2.2')).length,3)
  const budget=await collectMibPlan(fakeSession(),collectionPlan(identity),{maxQueries:1})
  assert.equal(budget.queryCount,1);assert.ok(budget.profiles.some(p=>p.status==='skipped'))
})

test('real UDP SNMP agent collects imported scalar and column values without ARP/bridge support',async()=>{
  // Inject an ephemeral loopback socket, avoiding privileged ports and live devices.
  const {default:dgram}=await import('node:dgram')
  const agent=snmp.createAgent({port:161,address:'127.0.0.1',disableAuthorization:true,dgramModule:{createSocket(type){const socket=dgram.createSocket(type),bind=socket.bind.bind(socket);socket.bind=(_port,address)=>bind(0,address);return socket}}},()=>{})
  const socket=Object.values(agent.listener.sockets)[0]
  await new Promise(resolve=>socket.once('listening',resolve))
  try{
    const mib=agent.getMib()
    for(const [name,oid,type,value] of [['sysDescr','1.3.6.1.2.1.1.1',snmp.ObjectType.OctetString,identity.sysDescr],['sysObjectID','1.3.6.1.2.1.1.2',snmp.ObjectType.OID,identity.sysObjectId],['modelName','1.3.6.1.4.1.424242.1.1',snmp.ObjectType.OctetString,'UDP model']]){
      mib.registerProvider({name,oid,type:snmp.MibProviderType.Scalar,scalarType:type,maxAccess:snmp.MaxAccess['read-only']});mib.setScalarValue(name,value)
    }
    mib.registerProvider({name:'ports',type:snmp.MibProviderType.Table,oid:'1.3.6.1.4.1.424242.1.3.1',maxAccess:snmp.MaxAccess['read-only'],tableColumns:[{number:1,name:'portIndex',type:snmp.ObjectType.Integer,maxAccess:snmp.MaxAccess['not-accessible']},{number:2,name:'portName',type:snmp.ObjectType.OctetString,maxAccess:snmp.MaxAccess['read-only']}],tableIndex:[1]})
    mib.addTableRow('ports',[1,'UDP uplink'])
    const device=await pollSnmpDevice({host:'127.0.0.1',credential:{type:'snmp-v2c'},sessionFactory:host=>snmp.createSession(host,'test',{port:socket.address().port,version:snmp.Version2c,timeout:500,retries:0})})
    const objects=device.mibCollection.profiles.find(p=>p.id===mibId).objects
    assert.equal(objects.find(o=>o.name==='modelName').values[0].value,'UDP model')
    assert.equal(objects.find(o=>o.name==='portName').values[0].value,'UDP uplink')
    assert.equal(device.collectionDiagnostics.arp.status,'unsupported')
  }finally{agent.close()}
})

test('auditors cannot import or configure MIBs, and writes leave source-free audit evidence',async()=>{
  db.prepare("UPDATE users SET role='auditor' WHERE id=?").run(actorId)
  try{
    await auth(request.get('/api/v1/discovery/snmp-library')).expect(403)
    await auth(request.post('/api/v1/discovery/snmp-library/import')).send({files}).expect(403)
    await auth(request.patch(`/api/v1/discovery/snmp-library/${mibId}`)).send({enabled:false}).expect(403)
    await auth(request.delete(`/api/v1/discovery/snmp-library/${mibId}`)).expect(403)
  }finally{db.prepare("UPDATE users SET role='owner' WHERE id=?").run(actorId)}
  const audits=db.prepare("SELECT after_json FROM audit_log WHERE action='snmp-mib.import'").all()
  assert.ok(audits.length)
  assert.ok(audits.every(a=>!a.after_json.includes('DEFINITIONS')))
})

test('multipart imports store source on disk and serve authenticated downloads without a catalog cap',async()=>{
  const {mibLibraryDir,sourcePath}=await import('../src/snmpMibStorage.js')
  const source=files[0].content.replaceAll('WINFIRE-TEST-MIB','WINFIRE-UPLOAD-MIB')
  const before=db.prepare('SELECT count(*) n FROM snmp_mib_library').get().n
  await auth(request.post('/api/v1/discovery/snmp-library/preview')).field('replace','false').attach('files',Buffer.from(source),'uploaded.my').expect(200)
  assert.equal(db.prepare('SELECT count(*) n FROM snmp_mib_library').get().n,before)
  await auth(request.post('/api/v1/discovery/snmp-library/import')).field('replace','false').attach('files',Buffer.from(source),'uploaded.my').expect(201)
  const row=db.prepare("SELECT * FROM snmp_mib_library WHERE module_name='WINFIRE-UPLOAD-MIB'").get()
  assert.equal(row.content,null);assert.equal(fs.readFileSync(sourcePath(row.source_path),'utf8'),source)
  await request.get(`/api/v1/discovery/snmp-library/${row.id}/download`).expect(401)
  const response=await auth(request.get(`/api/v1/discovery/snmp-library/${row.id}/download`)).expect(200)
  assert.equal(Buffer.isBuffer(response.body)?response.body.toString():response.text,source)
  const listing=await auth(request.get('/api/v1/discovery/snmp-library/files?search=uploaded')).expect(200)
  assert.equal(listing.body.items.length,1)
  await auth(request.get(`/api/v1/discovery/snmp-library/files/${listing.body.items[0].id}/download`)).expect(200)
  await auth(request.post('/api/v1/discovery/snmp-library/import')).attach('files',Buffer.from('invalid'),'invalid.my').expect(400)
  assert.deepEqual(fs.readdirSync(mibLibraryDir+'/.uploads'),[])
  assert.throws(()=>sourcePath('../../etc/passwd'))
  // Existing unrelated source files must not be reparsed when adding a new module.
  const stmt=db.prepare('INSERT INTO snmp_mib_library(id,module_name,source,metadata_json,config_json,enabled,created_at,updated_at,parse_status) VALUES(?,?,?, ?,?,0,?,?,?)')
  for(let i=0;i<105;i++)stmt.run('large:'+i,'UNRELATED-'+i,'imported',JSON.stringify({objects:[],imports:[],description:'Isolated catalog item'}),JSON.stringify({selectedObjects:[],match:{}}),'2026-01-01','2026-01-01','error')
  const second=source.replaceAll('WINFIRE-UPLOAD-MIB','WINFIRE-UPLOAD-SECOND-MIB')
  await auth(request.post('/api/v1/discovery/snmp-library/import')).attach('files',Buffer.from(second),'second.my').expect(201)
  assert.ok(listMibs().total>100)
})
