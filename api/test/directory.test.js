import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'
import {guidFromDirectory,sidFromDirectory,normalizeDirectoryComputer,testDirectoryConnection,directoryConnectionError,ldapFallbackUsername} from '../src/directory.js'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-directory-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@directory.test'
process.env.BOOTSTRAP_PASSWORD='directory-test-password-123'
const {app,syncDirectory}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

const guid=Buffer.from('78563412bc9af0de1122334455667788','hex')
const sid=Buffer.alloc(28)
sid[0]=1;sid[1]=5;sid[7]=5
for(const [index,value] of [21,100,200,300,400].entries())sid.writeUInt32LE(value,8+index*4)
const computer=(name,id=guid,disabled=false)=>({name,dNSHostName:`${name}.example.test`,objectGUID:id,objectSid:sid,distinguishedName:`CN=${name},OU=Servers,DC=example,DC=test`,operatingSystem:'Windows Server 2022',operatingSystemVersion:'10.0 (20348)',userAccountControl:disabled?'4098':'4096'})

test('AD binary identifiers and computer attributes normalize correctly',()=>{
  assert.equal(guidFromDirectory(guid),'12345678-9abc-def0-1122-334455667788')
  assert.equal(sidFromDirectory(sid),'S-1-5-21-100-200-300-400')
  const normalized=normalizeDirectoryComputer(computer('srv01'),'DC=example,DC=test')
  assert.equal(normalized.fqdn,'srv01.example.test')
  assert.equal(normalized.enabled,true)
  assert.equal(normalizeDirectoryComputer({...computer('srv02'),'dNSHostName':null},'DC=example,DC=test').fqdn,'srv02.example.test')
  assert.equal(ldapFallbackUsername('EXAMPLE\\reader','OU=Servers,DC=example,DC=test'),'reader@example.test')
  assert.equal(ldapFallbackUsername('reader@other.test','DC=example,DC=test'),'reader@other.test')
})

test('directory settings use vault credentials and sync AD as the first inventory source',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@directory.test',password:'directory-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'AD read account',type:'domain',username:'reader@example.test',password:'directory-secret'}).expect(201)
  const manual=await auth(request.post('/api/v1/nodes')).send({hostname:'srv01'}).expect(201)
  await auth(request.patch('/api/v1/settings/directory')).send({url:'ldap://dc.example.test',baseDn:'DC=example,DC=test',bindCredentialId:credential.body.id,enabled:true}).expect(400)
  const settings=await auth(request.patch('/api/v1/settings/directory')).send({url:'ldaps://dc.example.test:636/',baseDn:'DC=example,DC=test',bindCredentialId:credential.body.id,nodeCredentialId:credential.body.id,enabled:true,syncIntervalMinutes:60}).expect(200)
  assert.equal(settings.body.enabled,true)
  assert.equal(JSON.stringify(settings.body).includes('directory-secret'),false)
  const entries={current:[computer('srv01'),computer('srv02',Buffer.from('ffffffffffffffffffffffffffffffff','hex'),true)]}
  const seen={binds:[],options:[]}
  const factory=options=>{
    seen.options.push(options)
    return {async bind(username,password){seen.binds.push([username,password])},async search(){return {searchEntries:[{dn:'DC=example,DC=test'}]}},async *searchPaginated(){yield {searchEntries:entries.current}},async unbind(){}}
  }
  const connection=await testDirectoryConnection({url:'ldaps://dc.example.test:636/',base_dn:'DC=example,DC=test'},{username:'reader@example.test',password:'directory-secret'},factory)
  assert.equal(connection.connected,true)
  const first=await syncDirectory(login.body.user.id,factory)
  assert.deepEqual(first,{found:2,created:1,updated:1,missing:0,transport:'ldaps',fallbackUsed:false})
  assert.equal(seen.options[0].tlsOptions.minVersion,'TLSv1.2')
  assert.ok(seen.binds.every(([username,password])=>username==='reader@example.test'&&password==='directory-secret'))
  const linked=db.prepare('SELECT * FROM nodes WHERE id=?').get(manual.body.id)
  assert.equal(linked.ad_guid,'12345678-9abc-def0-1122-334455667788')
  assert.equal(linked.inventory_source,'manual+ad')
  assert.equal(linked.ad_sid,'S-1-5-21-100-200-300-400')
  const disabled=db.prepare('SELECT * FROM nodes WHERE hostname=?').get('srv02')
  assert.equal(disabled.ad_enabled,0)
  assert.equal(disabled.firewall_state,'unmanaged')
  assert.equal(db.prepare('SELECT COUNT(*) n FROM learning_sessions WHERE node_id=?').get(disabled.id).n,0)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM credential_assignments WHERE credential_id=? AND node_id=?').get(credential.body.id,disabled.id).n,1)
  entries.current=[computer('srv01-new')]
  const second=await syncDirectory(login.body.user.id,factory)
  assert.deepEqual(second,{found:1,created:0,updated:1,missing:1,transport:'ldaps',fallbackUsed:false})
  assert.equal(db.prepare('SELECT hostname FROM nodes WHERE id=?').get(manual.body.id).hostname,'srv01-new')
  assert.equal(db.prepare('SELECT ad_missing FROM nodes WHERE id=?').get(disabled.id).ad_missing,1)
  const publicSettings=await auth(request.get('/api/v1/settings/directory')).expect(200)
  assert.equal(publicSettings.body.lastSyncStatus,'success')
  assert.equal(publicSettings.body.lastSyncCount,1)
})

test('LDAPS transport failures give actionable errors and preserve sync failure status',async()=>{
  const url='ldaps://dc.example.test:636/'
  const reset=Object.assign(new Error('read ECONNRESET'),{code:'ECONNRESET'})
  const factory=()=>({async bind(){throw reset},async unbind(){}})
  await assert.rejects(testDirectoryConnection({url,base_dn:'DC=example,DC=test'},{username:'reader',password:'secret'},factory),error=>error.status===503&&/Server Authentication certificate/.test(error.message))
  assert.match(directoryConnectionError(Object.assign(new Error('certificate mismatch'),{code:'ERR_TLS_CERT_ALTNAME_INVALID'}),url).message,/certificate could not be validated/)
  assert.match(directoryConnectionError(Object.assign(new Error('lookup failed'),{code:'ENOTFOUND'}),url).message,/could not be resolved/)
  const owner=db.prepare("SELECT id FROM users WHERE email='owner@directory.test'").get()
  await assert.rejects(syncDirectory(owner.id,factory),error=>error.status===503&&/Server Authentication certificate/.test(error.message))
  const settings=db.prepare("SELECT last_sync_status,last_sync_error FROM directory_connections WHERE id='default'").get()
  assert.equal(settings.last_sync_status,'failed')
  assert.match(settings.last_sync_error,/Server Authentication certificate/)
})

test('an admin must explicitly approve LDAP 389 fallback for the directory host and bind credential',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@directory.test',password:'directory-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=db.prepare("SELECT id FROM credentials WHERE name='AD read account'").get()
  const body={url:'ldaps://dc.example.test:636/',baseDn:'DC=example,DC=test',bindCredentialId:credential.id,nodeCredentialId:credential.id,enabled:true,syncIntervalMinutes:60,allowLdapFallback:true}
  assert.equal((await auth(request.get('/api/v1/settings/directory')).expect(200)).body.allowLdapFallback,false)
  await auth(request.patch('/api/v1/settings/directory')).send(body).expect(400)
  const unapprovedUrls=[]
  await assert.rejects(testDirectoryConnection(db.prepare("SELECT * FROM directory_connections WHERE id='default'").get(),{username:'reader',password:'secret'},options=>{unapprovedUrls.push(options.url);return {async bind(){throw Object.assign(new Error('read ECONNRESET'),{code:'ECONNRESET'})},async unbind(){}}}),/LDAPS connection was reset/)
  assert.deepEqual(unapprovedUrls,['ldaps://dc.example.test:636/'])
  const approved=await auth(request.patch('/api/v1/settings/directory')).send({...body,ldapFallbackApproval:'ALLOW LDAP 389'}).expect(200)
  assert.equal(approved.body.allowLdapFallback,true)
  assert.equal(approved.body.ldapFallbackApprovedBy,login.body.user.id)
  assert.ok(approved.body.ldapFallbackApprovedAt)
  assert.equal(JSON.stringify(db.prepare("SELECT after_json FROM audit_log WHERE action='directory.ldap_fallback.approve' ORDER BY at DESC LIMIT 1").get()).includes('ALLOW LDAP 389'),false)
  const settings=db.prepare("SELECT * FROM directory_connections WHERE id='default'").get()
  const urls=[],usernames=[],clientOptions=[]
  const factory=options=>{
    urls.push(options.url)
    clientOptions.push(options)
    return {async bind(username){usernames.push(username);if(options.url.startsWith('ldaps:'))throw Object.assign(new Error('read ECONNRESET'),{code:'ECONNRESET'})},async search(){return {searchEntries:[{}]}},async *searchPaginated(){yield {searchEntries:[computer('srv01-new')]}},async unbind(){}}
  }
  const result=await testDirectoryConnection(settings,{username:'EXAMPLE\\reader',password:'secret'},factory)
  assert.equal(result.transport,'ldap')
  assert.equal(result.fallbackUsed,true)
  assert.deepEqual(urls,['ldaps://dc.example.test:636/','ldap://dc.example.test:389/'])
  assert.deepEqual(usernames,['EXAMPLE\\reader','reader@example.test'])
  assert.equal(clientOptions[0].tlsOptions.minVersion,'TLSv1.2')
  assert.equal('tlsOptions' in clientOptions[1],false)
  const synced=await syncDirectory(login.body.user.id,factory)
  assert.equal(synced.transport,'ldap')
  assert.equal(synced.fallbackUsed,true)
  assert.equal(db.prepare("SELECT last_transport FROM directory_connections WHERE id='default'").get().last_transport,'ldap')
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action='directory.sync' AND after_json LIKE '%\"transport\":\"ldap\"%'").get().n,1)
  const certUrls=[]
  await assert.rejects(testDirectoryConnection(settings,{username:'reader',password:'secret'},options=>{certUrls.push(options.url);return {async bind(){throw Object.assign(new Error('bad cert'),{code:'ERR_TLS_CERT_ALTNAME_INVALID'})},async unbind(){}}}),/certificate could not be validated/)
  assert.deepEqual(certUrls,['ldaps://dc.example.test:636/'])
  const searchUrls=[]
  await assert.rejects(testDirectoryConnection(settings,{username:'reader',password:'secret'},options=>{searchUrls.push(options.url);return {async bind(){},async search(){throw Object.assign(new Error('read ECONNRESET'),{code:'ECONNRESET'})},async unbind(){}}}),/LDAPS connection was reset/)
  assert.deepEqual(searchUrls,['ldaps://dc.example.test:636/'])
  await assert.rejects(testDirectoryConnection(settings,{username:'reader',password:'secret'},options=>({async bind(){if(options.url.startsWith('ldaps:'))throw Object.assign(new Error('read ECONNRESET'),{code:'ECONNRESET'});throw Object.assign(new Error('Strong Authentication Required'),{code:8})},async unbind(){}})),/rejected unencrypted LDAP 389/)
  await auth(request.patch('/api/v1/settings/directory')).send({...body,url:'ldaps://other.example.test:636/'}).expect(400)
  const reapproved=await auth(request.patch('/api/v1/settings/directory')).send({...body,url:'ldaps://other.example.test:636/',ldapFallbackApproval:'ALLOW LDAP 389'}).expect(200)
  assert.equal(reapproved.body.url,'ldaps://other.example.test:636/')
  const secondCredential=await auth(request.post('/api/v1/credentials')).send({name:'Other directory reader',type:'domain',username:'other@example.test',password:'other-directory-secret'}).expect(201)
  await auth(request.patch('/api/v1/settings/directory')).send({...body,url:'ldaps://other.example.test:636/',bindCredentialId:secondCredential.body.id}).expect(400)
  await auth(request.patch('/api/v1/settings/directory')).send({...body,url:'ldaps://other.example.test:636/',bindCredentialId:secondCredential.body.id,ldapFallbackApproval:'ALLOW LDAP 389'}).expect(200)
  const revoked=await auth(request.patch('/api/v1/settings/directory')).send({...body,url:'ldaps://other.example.test:636/',bindCredentialId:secondCredential.body.id,allowLdapFallback:false}).expect(200)
  assert.equal(revoked.body.allowLdapFallback,false)
  assert.equal(revoked.body.ldapFallbackApprovedAt,null)
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action='directory.ldap_fallback.revoke'").get().n,1)
  await auth(request.patch('/api/v1/settings/directory')).send({...body,url:'ldaps://other.example.test:636/',bindCredentialId:secondCredential.body.id,ldapFallbackApproval:'ALLOW LDAP 389'}).expect(200)
  await auth(request.patch(`/api/v1/credentials/${secondCredential.body.id}`)).send({username:'privileged@example.test'}).expect(200)
  const changedBind=await auth(request.get('/api/v1/settings/directory')).expect(200)
  assert.equal(changedBind.body.allowLdapFallback,true)
  assert.equal(changedBind.body.ldapFallbackApprovedAt,null)
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action='directory.ldap_fallback.revoke' AND after_json LIKE '%bind_credential_changed%'").get().n,1)
  await auth(request.patch('/api/v1/settings/directory')).send({...body,url:'ldaps://other.example.test:636/',bindCredentialId:secondCredential.body.id}).expect(400)
})
