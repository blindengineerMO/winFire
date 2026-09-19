import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'
import {guidFromDirectory,sidFromDirectory,normalizeDirectoryComputer,testDirectoryConnection} from '../src/directory.js'

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
  assert.deepEqual(first,{found:2,created:1,updated:1,missing:0})
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
  assert.deepEqual(second,{found:1,created:0,updated:1,missing:1})
  assert.equal(db.prepare('SELECT hostname FROM nodes WHERE id=?').get(manual.body.id).hostname,'srv01-new')
  assert.equal(db.prepare('SELECT ad_missing FROM nodes WHERE id=?').get(disabled.id).ad_missing,1)
  const publicSettings=await auth(request.get('/api/v1/settings/directory')).expect(200)
  assert.equal(publicSettings.body.lastSyncStatus,'success')
  assert.equal(publicSettings.body.lastSyncCount,1)
})
