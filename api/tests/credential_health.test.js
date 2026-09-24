import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-credential-health-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@credential-health.test'
process.env.BOOTSTRAP_PASSWORD='credential-health-password'
const {db}=await import('../src/db.js')
const {bootstrap}=await import('../src/security.js')
const {app}=await import('../src/app.js')
const {recordCredentialAuthSuccess,recordCredentialAuthFailure,activeCredentialStaleNotices}=await import('../src/credentialHealth.js')
await bootstrap()
const request=supertest(app)

test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('groups repeated auth failures for a previously working credential into one stale notice',async()=>{
  db.prepare("INSERT INTO credentials(id,name,type,username,encrypted_blob) VALUES('cred-rotate','Production domain','domain','EXAMPLE\\svc','sealed')").run()
  for(let index=1;index<=3;index++)db.prepare('INSERT INTO nodes(id,hostname,ip,connection_mode,status) VALUES(?,?,?,\'agentless\',\'reachable\')').run(`rotate-node-${index}`,`rotate-${index}`,`192.0.2.${index}`)
  for(let index=1;index<=3;index++)recordCredentialAuthSuccess({credentialId:'cred-rotate',nodeId:`rotate-node-${index}`,transport:'winrm'})
  assert.deepEqual(activeCredentialStaleNotices(),[])
  for(let index=1;index<=2;index++)assert.equal(recordCredentialAuthFailure({credentialId:'cred-rotate',nodeId:`rotate-node-${index}`,error:new Error('Access is denied'),transport:'winrm',operation:'auth'}),null)
  const notice=recordCredentialAuthFailure({credentialId:'cred-rotate',nodeId:'rotate-node-3',error:new Error('invalid credentials'),transport:'winrm',operation:'auth'})
  assert.equal(notice.code,'credential_may_be_stale')
  assert.equal(notice.affectedNodeCount,3)
  assert.equal(activeCredentialStaleNotices()[0].credentialName,'Production domain')

  // A transport outage is not a rotation signal.
  recordCredentialAuthFailure({credentialId:'cred-rotate',nodeId:'rotate-node-3',error:new Error('connection refused'),transport:'winrm',operation:'auth'})
  assert.equal(activeCredentialStaleNotices()[0].affectedNodeCount,3)

  const login=await request.post('/api/v1/auth/login').send({email:'owner@credential-health.test',password:'credential-health-password'}).expect(200)
  const health=await request.get('/api/v1/credentials/health').set('Authorization',`Bearer ${login.body.accessToken}`).expect(200)
  assert.equal(health.body.notices.length,1)
  assert.equal(health.body.notices[0].credentialId,'cred-rotate')

  // A successful retry clears that node's failure and removes the aggregate once below threshold.
  recordCredentialAuthSuccess({credentialId:'cred-rotate',nodeId:'rotate-node-1',transport:'winrm'})
  assert.deepEqual(activeCredentialStaleNotices(),[])
})
