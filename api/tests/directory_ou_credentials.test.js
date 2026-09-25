import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-ou-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@ou.test'
process.env.BOOTSTRAP_PASSWORD='ou-test-password-123'
const {app,syncDirectory}=await import('../src/app.js')
const {bootstrap,issueAccess}=await import('../src/security.js')
const {db,id}=await import('../src/db.js')
const {directoryDnParts,dnWithin,validateOuHints,preferredDirectoryCredential}=await import('../src/directoryCredentials.js')
await bootstrap()
const request=supertest(app)
const owner=db.prepare("SELECT * FROM users WHERE email='owner@ou.test'").get()
const token=issueAccess(owner)
const auth=req=>req.set('Authorization',`Bearer ${token}`)
const base='DC=example,DC=test'
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('DN matching uses complete components, escaped values and most specific parent OU',()=>{
  const settings={enabled:1,base_dn:base,node_credential_id:'global'}
  const hints=[{ouDn:`OU=Servers,${base}`,credentialId:'servers'},{ouDn:`OU=Production,OU=Servers,${base}`,credentialId:'production'}]
  assert.equal(preferredDirectoryCredential(`CN=web,OU=Production,OU=Servers,${base}`,settings,hints).credentialId,'production')
  assert.equal(preferredDirectoryCredential(`CN=web,OU=Nested,OU=Servers,${base}`,settings,hints).credentialId,'servers')
  assert.equal(preferredDirectoryCredential(`CN=web,OU=OtherServers,${base}`,settings,hints).credentialId,'global')
  assert.equal(preferredDirectoryCredential('CN=web,OU=Servers,DC=other,DC=test',settings,hints),null)
  assert.equal(preferredDirectoryCredential('broken',settings,hints),null)
  assert.equal(preferredDirectoryCredential(`CN=web,OU=Servers,${base}`,{...settings,enabled:0},hints),null)
  assert.deepEqual(directoryDnParts(`OU=Sales\\, West,${base}`),directoryDnParts(`ou=Sales\\2c West, dc=EXAMPLE,dc=TEST`))
  assert.deepEqual(directoryDnParts(`OU=Caf\\c3\\a9,${base}`),directoryDnParts(`OU=Café,${base}`))
  assert.deepEqual(directoryDnParts(`OU=Sales+CN=Team,${base}`),directoryDnParts(`cn=team+ou=sales,${base}`))
  assert.equal(dnWithin(directoryDnParts(`CN=web,OU=Fake\\,OU=Servers,${base}`),directoryDnParts(`OU=Servers,${base}`)),false)
  for(const invalid of ['OU=Bad\\',`OU=Bad\\z,${base}`,`OU=,${base}`,`OU=Bad,,${base}`])assert.throws(()=>directoryDnParts(invalid))
  assert.throws(()=>validateOuHints([{ouDn:`OU=Sales\\, West,${base}`},{ouDn:`ou=sales\\2C west,${base}`}],base),/only one/)
  assert.throws(()=>validateOuHints([{ouDn:'OU=Servers,DC=other,DC=test'}],base),/inside/)
  assert.throws(()=>validateOuHints([{ouDn:`CN=Computers,${base}`}],base),/OU/)
})

test('OU settings, sync, moves, manual overrides and vault deletion integrate through the API',async()=>{
  const credential=async name=>(await auth(request.post('/api/v1/credentials')).send({name,type:'domain',username:`${name}@example.test`,password:'private-test-secret'}).expect(201)).body.id
  const global=await credential('global'),servers=await credential('servers'),prod=await credential('prod'),manual=await credential('manual')
  const snmp=(await auth(request.post('/api/v1/credentials')).send({name:'snmp',type:'snmp-v2c',community:'test-community'}).expect(201)).body.id
  const body={url:'ldaps://dc.example.test:636/',baseDn:base,bindCredentialId:global,nodeCredentialId:global,enabled:true,syncIntervalMinutes:60,ouCredentialHints:[{ouDn:`OU=Servers,${base}`,credentialId:servers},{ouDn:`OU=Prod,OU=Servers,${base}`,credentialId:prod}]}
  const saved=(await auth(request.patch('/api/v1/settings/directory')).send(body).expect(200)).body
  assert.equal(saved.ouCredentialHints.length,2)
  assert.equal(JSON.stringify(saved).includes('private-test-secret'),false)
  const bad=[{ouDn:`OU=Servers,${base}`,credentialId:snmp}]
  await auth(request.patch('/api/v1/settings/directory')).send({...body,ouCredentialHints:bad}).expect(400)
  await auth(request.patch('/api/v1/settings/directory')).send({...body,ouCredentialHints:[{...bad[0],credentialId:id()}]}).expect(400)
  await auth(request.patch('/api/v1/settings/directory')).send({...body,ouCredentialHints:[body.ouCredentialHints[0],{...body.ouCredentialHints[0],ouDn:`ou=servers,dc=example,dc=test`}]}).expect(400)
  await auth(request.patch('/api/v1/settings/directory')).send({...body,baseDn:'OU=Other,DC=example,DC=test'}).expect(400)
  // A separate real auditor is required because authentication reloads the user's role.
  const auditor=id()
  db.prepare("INSERT INTO users(id,email,password_hash,role,created_at) VALUES(?,?,?,'auditor',?)").run(auditor,'auditor@ou.test','unused',new Date().toISOString())
  const auditorAuth=issueAccess(db.prepare('SELECT * FROM users WHERE id=?').get(auditor))
  await request.patch('/api/v1/settings/directory').set('Authorization',`Bearer ${auditorAuth}`).send(body).expect(403)
  await request.get('/api/v1/settings/directory').expect(401)
  const node=id(),guid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
  db.prepare("INSERT INTO nodes(id,hostname,fqdn,ip,firewall_state) VALUES(?,'web','web.example.test','192.0.2.22','unmanaged')").run(node)
  let dn=`CN=web,OU=Prod,OU=Servers,${base}`
  const factory=()=>({async bind(){},async *searchPaginated(_base,options){yield {searchEntries:options.filter.includes('objectCategory=computer')?[{name:'web',dNSHostName:'web.example.test',objectGUID:guid,distinguishedName:dn,userAccountControl:'4098'}]:[]}},async unbind(){}})
  const assignments=()=>db.prepare('SELECT credential_id id,source,source_dn dn FROM credential_assignments WHERE node_id=? ORDER BY credential_id').all(node)
  // A CIDR discovery fallback is automatic and must yield to the trusted AD OU.
  db.prepare("INSERT INTO credential_assignments(credential_id,node_id,node_group_id,source) VALUES(?,?,NULL,'directory')").run(global,node)
  await syncDirectory(owner.id,factory)
  assert.deepEqual(assignments(),[{id:prod,source:'directory',dn:body.ouCredentialHints[1].ouDn}])
  await syncDirectory(null,factory)
  assert.equal(assignments().length,1)
  dn=`CN=web,OU=Servers,${base}`
  await syncDirectory(null,factory)
  assert.deepEqual(assignments(),[{id:servers,source:'directory',dn:body.ouCredentialHints[0].ouDn}])
  dn=`CN=web,CN=Computers,${base}`
  await syncDirectory(null,factory)
  assert.deepEqual(assignments(),[{id:global,source:'directory',dn:null}])
  // Explicit binding to the same credential converts its ownership to manual.
  await auth(request.post(`/api/v1/credentials/${global}/assignments`)).send({nodeId:node}).expect(200)
  dn=`CN=web,OU=Prod,OU=Servers,${base}`
  await syncDirectory(null,factory)
  assert.deepEqual(assignments(),[{id:global,source:'manual',dn:null}])
  db.prepare('DELETE FROM credential_assignments WHERE node_id=?').run(node)
  // A supplemental SNMP credential must not suppress Windows OU preferences.
  await auth(request.post(`/api/v1/credentials/${snmp}/assignments`)).send({nodeId:node}).expect(201)
  await syncDirectory(null,factory)
  assert.ok(assignments().some(a=>a.id===prod&&a.source==='directory'))
  const group=id()
  db.prepare("INSERT INTO node_groups(id,name) VALUES(?,'Explicit group')").run(group)
  db.prepare('INSERT INTO node_group_members(group_id,node_id) VALUES(?,?)').run(group,node)
  await auth(request.post(`/api/v1/credentials/${manual}/assignments`)).send({nodeGroupId:group}).expect(201)
  await syncDirectory(null,factory)
  assert.deepEqual(assignments(),[{id:snmp,source:'manual',dn:null}])
  db.prepare('DELETE FROM node_group_members WHERE group_id=?').run(group)
  await syncDirectory(null,factory)
  assert.ok(assignments().some(a=>a.id===prod))
  // Credential rotation keeps the hint bound by ID; deletion removes it and falls back to the parent.
  await auth(request.patch(`/api/v1/credentials/${prod}`)).send({password:'rotated-private-secret'}).expect(200)
  await syncDirectory(null,factory)
  assert.ok(assignments().some(a=>a.id===prod))
  await auth(request.delete(`/api/v1/credentials/${prod}`)).expect(204)
  await syncDirectory(null,factory)
  assert.ok(assignments().some(a=>a.id===servers))
  assert.equal((await auth(request.get('/api/v1/settings/directory')).expect(200)).body.ouCredentialHints.length,1)
  const omitted={...body};delete omitted.ouCredentialHints
  await auth(request.patch('/api/v1/settings/directory')).send(omitted).expect(200)
  assert.equal((await auth(request.get('/api/v1/settings/directory')).expect(200)).body.ouCredentialHints.length,1)
  await auth(request.patch('/api/v1/settings/directory')).send({...body,ouCredentialHints:[]}).expect(200)
  await syncDirectory(null,factory)
  assert.ok(assignments().some(a=>a.id===global&&a.source==='directory'))
  assert.equal(assignments().filter(a=>a.source==='directory').length,1)
  const audit=db.prepare("SELECT after_json FROM audit_log WHERE action='directory.credential.assign'").all()
  assert.ok(audit.length>=7)
  assert.equal(JSON.stringify(audit).includes('private-secret'),false)
})
