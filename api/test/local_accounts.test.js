import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'
import {compilePolicy} from '@winfire/shared'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-local-accounts-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@local.test'
process.env.BOOTSTRAP_PASSWORD='local-owner-password-123'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db,run,one,all,id}=await import('../src/db.js')
const {storeAccountInventory,accountName}=await import('../src/localAccounts.js')
const {diffRules}=await import('../src/connector.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('node-local SIDs resolve after AD and remain scoped to their host',async()=>{
  const nodeId=id(),otherId=id(),sid='S-1-5-21-100-200-300-1001'
  run("INSERT INTO nodes(id,hostname,transport,connection_mode,os_version) VALUES(?,?,'winrm','agentless','10.0.20348')",nodeId,'ORLANDO')
  run("INSERT INTO nodes(id,hostname,transport,connection_mode,os_version) VALUES(?,?,'winrm','agentless','10.0.20348')",otherId,'HOUSTON')
  const result=storeAccountInventory({id:nodeId,hostname:'ORLANDO'},{computerName:'ORLANDO',domainController:false,accounts:[{sid,username:'operator',fullName:'Local Operator',description:'test account',enabled:true,locked:false,passwordRequired:true}],resolutions:[{sid,qualifiedName:'ORLANDO\\operator'},{sid:'S-1-5-32-544',qualifiedName:'BUILTIN\\Administrators'}]})
  assert.equal(result.count,1)
  assert.deepEqual(accountName(nodeId,sid),{accountName:'ORLANDO\\operator',accountSource:'local'})
  assert.equal(accountName(otherId,sid).accountName,null)
  assert.deepEqual(accountName(nodeId,'S-1-5-32-544'),{accountName:'BUILTIN\\Administrators',accountSource:'windows'})
  const login=await request.post('/api/v1/auth/login').send({email:'owner@local.test',password:'local-owner-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const directory=await auth(request.get('/api/v1/directory/accounts?source=local&q=ORLANDO&pageSize=10')).expect(200)
  assert.equal(directory.body.total,1)
  assert.equal(directory.body.items[0].sam_account_name,'ORLANDO\\operator')
  const detail=await auth(request.get(`/api/v1/directory/local-accounts/${directory.body.items[0].id}`)).expect(200)
  assert.equal(detail.body.node_id,nodeId)
  assert.equal(detail.body.source,'local')
  const rightId=id()
  run('INSERT INTO logon_rights(id,node_id,account_sid,logon_type,right_assignment,source,baseline) VALUES(?,?,?,?,?,?,1)',rightId,nodeId,sid,'Network','allow','secedit')
  const rights=await auth(request.get(`/api/v1/logon-rights?nodeId=${nodeId}`)).expect(200)
  assert.equal(rights.body[0].accountName,'ORLANDO\\operator')
  assert.equal(rights.body[0].accountSource,'local')
  run("INSERT INTO log_events(id,node_id,record_id,event_id,action,account_sid) VALUES(?,?,1,4624,'success',?)",id(),nodeId,sid)
  const events=await auth(request.get('/api/v1/logs/search?account=ORLANDO&sortBy=account&pageSize=10')).expect(200)
  assert.equal(events.body.total,1)
  assert.equal(events.body.items[0].account_name,'ORLANDO\\operator')
  const stage=await auth(request.post(`/api/v1/directory/local-accounts/${detail.body.id}/network-rule`)).send({remoteAddress:'192.0.2.10',remotePort:'3389',protocol:'TCP',reason:'Restrict this unauthorized local account'}).expect(201)
  assert.equal(stage.body.pendingSync,true)
  const version=one('SELECT rules_compiled_json FROM policy_versions WHERE id=?',stage.body.versionId)
  const rules=JSON.parse(version.rules_compiled_json)
  assert.equal(rules[0].localUserSid,sid)
  assert.equal(rules[0].direction,'out')
  assert.equal(rules[0].action,'block')
  assert.equal(all('SELECT * FROM policy_assignments WHERE policy_id=?',stage.body.policyId).length,1)
  const pending=await auth(request.get('/api/v1/policies/sync')).expect(200)
  assert.ok(pending.body.pending.some(item=>item.policy_id===stage.body.policyId&&item.node_id===nodeId))
  const duplicate=await auth(request.post(`/api/v1/directory/local-accounts/${detail.body.id}/network-rule`)).send({remoteAddress:'192.0.2.10',remotePort:'3389',protocol:'TCP',reason:'Restrict this unauthorized local account'}).expect(200)
  assert.equal(duplicate.body.duplicate,true)
  assert.equal(diffRules(rules,[{...rules[0],localUserSid:null}]).add.length,1)
  assert.throws(()=>compilePolicy({nodes:[{id:'bad',type:'deny',data:{direction:'in',localUserSid:sid}}],edges:[]},'x'),/outbound/)
  storeAccountInventory({id:nodeId,hostname:'ORLANDO'},{computerName:'ORLANDO',domainController:false,accounts:[],resolutions:[]})
  assert.equal(accountName(nodeId,sid).accountSource,'windows')
  assert.equal(one('SELECT missing FROM local_accounts WHERE node_id=? AND sid=?',nodeId,sid).missing,1)
})
