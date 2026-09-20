import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-learning-preview-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@learning-preview.test'
process.env.BOOTSTRAP_PASSWORD='learning-preview-password'
const {app,processDueTraining}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('personal policy previews live flows, progresses by version, and freezes after training',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@learning-preview.test',password:'learning-preview-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  await auth(request.patch('/api/v1/settings/training')).send({newHostTrainingDays:30,progressiveLearning:{enabled:true,startDays:15,intervalHours:12}}).expect(200)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'progressive-node',connectionMode:'agent'}).expect(201)
  const sessionId=node.body.training.id,policyId=node.body.training.generatedPolicyId
  const listed=await auth(request.get('/api/v1/policies')).expect(200)
  assert.equal(listed.body.find(policy=>policy.id===policyId).learning.status,'active')
  assert.equal(listed.body.find(policy=>policy.id===policyId).source_node_id,node.body.id)
  assert.equal((await auth(request.get(`/api/v1/policies/${policyId}/learning-preview`)).expect(200)).body.rules.length,0)
  await auth(request.post(`/api/v1/policies/${policyId}/versions`)).send({graph:{nodes:[],edges:[]}}).expect(409)

  const agentId=crypto.randomUUID()
  db.prepare('INSERT INTO agents(id,node_id,cert_thumbprint,version,last_checkin_at) VALUES(?,?,?,?,?)').run(agentId,node.body.id,'PREVIEW-TEST','test',new Date().toISOString())
  db.prepare('UPDATE nodes SET agent_id=? WHERE id=?').run(agentId,node.body.id)
  const hourAgo=new Date(Date.now()-360e4).toISOString(),yesterday=new Date(Date.now()-864e5).toISOString()
  db.prepare('UPDATE learning_sessions SET started_at=?,next_progressive_at=?,ends_at=?,last_attempt_at=NULL WHERE id=?').run(new Date(Date.now()-16*864e5).toISOString(),hourAgo,new Date(Date.now()+14*864e5).toISOString(),sessionId)
  const addEvent=db.prepare('INSERT INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,event_time) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
  addEvent.run(crypto.randomUUID(),node.body.id,1,5156,'allow','TCP','192.0.2.11','198.51.100.1',3389,'in',new Date(Date.now()-60_000).toISOString())
  const preview=await auth(request.get(`/api/v1/policies/${policyId}/learning-preview`)).expect(200)
  assert.equal(preview.body.newFlowCount,1)
  assert.equal(preview.body.rules[0].remoteAddress,'192.0.2.11')
  assert.equal(db.prepare('SELECT COUNT(*) n FROM policy_versions WHERE policy_id=?').get(policyId).n,1)
  const first=await processDueTraining()
  assert.equal(first.find(item=>item.sessionId===sessionId).status,'queued')
  assert.equal(db.prepare('SELECT COUNT(*) n FROM policy_versions WHERE policy_id=?').get(policyId).n,2)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM policy_assignments WHERE policy_id=? AND node_id=?').get(policyId,node.body.id).n,1)
  db.prepare("UPDATE agent_jobs SET status='success' WHERE agent_id=? AND type='policy.apply'").run(agentId)

  addEvent.run(crypto.randomUUID(),node.body.id,2,5156,'allow','UDP','192.0.2.12','198.51.100.1',5353,'in',new Date().toISOString())
  db.prepare('UPDATE learning_sessions SET next_progressive_at=?,last_attempt_at=? WHERE id=?').run(hourAgo,yesterday,sessionId)
  const second=await processDueTraining()
  assert.equal(second.find(item=>item.sessionId===sessionId).status,'queued')
  const version=db.prepare('SELECT v.* FROM policy_versions v JOIN policies p ON p.current_version_id=v.id WHERE p.id=?').get(policyId)
  assert.equal(version.version_no,3)
  assert.equal(JSON.parse(version.rules_compiled_json).length,2)
  db.prepare("UPDATE agent_jobs SET status='success' WHERE agent_id=? AND type='policy.apply'").run(agentId)

  const group=await auth(request.post('/api/v1/node-groups')).send({name:'Progressive group'}).expect(201)
  await auth(request.post(`/api/v1/node-groups/${group.body.id}/members`)).send({nodeId:node.body.id}).expect(200)
  const global=await auth(request.post('/api/v1/policies')).send({name:'Group DNS'}).expect(201)
  await auth(request.post(`/api/v1/policies/${global.body.id}/versions`)).send({graph:{nodes:[{id:'dns',type:'allow',data:{name:'DNS',localPort:'53',protocol:'UDP',direction:'in',remoteAddress:'Any'}}],edges:[]}}).expect(201)
  await auth(request.post(`/api/v1/policies/${global.body.id}/assignments`)).send({nodeGroupId:group.body.id}).expect(201)
  db.prepare('UPDATE learning_sessions SET ends_at=?,last_attempt_at=? WHERE id=?').run(new Date(Date.now()-1000).toISOString(),yesterday,sessionId)
  const ended=await processDueTraining()
  assert.equal(ended.find(item=>item.sessionId===sessionId).status,'applying')
  const finalJobs=db.prepare("SELECT payload_json FROM agent_jobs WHERE agent_id=? AND status='queued' AND json_extract(payload_json,'$.learningSessionId')=?").all(agentId,sessionId)
  assert.equal(finalJobs.length,2)
  assert.equal(new Set(finalJobs.map(job=>JSON.parse(job.payload_json).learningAttemptId)).size,1)
  await auth(request.get(`/api/v1/policies/${policyId}/learning-preview`)).expect(409)
  addEvent.run(crypto.randomUUID(),node.body.id,3,5156,'allow','TCP','192.0.2.13','198.51.100.1',22,'in',new Date().toISOString())
  assert.equal((await processDueTraining()).length,0)
  assert.equal(db.prepare('SELECT MAX(version_no) n FROM policy_versions WHERE policy_id=?').get(policyId).n,3)
})

test('a quiet node receives the global policy when training ends',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@learning-preview.test',password:'learning-preview-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const global=await auth(request.post('/api/v1/policies')).send({name:'Fleet policy'}).expect(201)
  await auth(request.post(`/api/v1/policies/${global.body.id}/versions`)).send({graph:{nodes:[{id:'fleet',type:'allow',data:{name:'Fleet HTTPS',localPort:'443',protocol:'TCP',direction:'in',remoteAddress:'Any'}}],edges:[]}}).expect(201)
  await auth(request.post(`/api/v1/policies/${global.body.id}/assignments`)).send({nodeGroupId:'winfire-global-all-nodes'}).expect(201)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'quiet-fleet-node',connectionMode:'agent'}).expect(201)
  assert.equal((await auth(request.get(`/api/v1/nodes/${node.body.id}`)).expect(200)).body.groups.some(group=>group.id==='winfire-global-all-nodes'),true)
  const agentId=crypto.randomUUID()
  db.prepare('INSERT INTO agents(id,node_id,cert_thumbprint,version,last_checkin_at) VALUES(?,?,?,?,?)').run(agentId,node.body.id,'QUIET-TEST','test',new Date().toISOString())
  db.prepare('UPDATE nodes SET agent_id=? WHERE id=?').run(agentId,node.body.id)
  db.prepare('UPDATE learning_sessions SET ends_at=?,last_attempt_at=NULL WHERE id=?').run(new Date(Date.now()-1000).toISOString(),node.body.training.id)
  const result=await processDueTraining()
  assert.equal(result.find(item=>item.sessionId===node.body.training.id).status,'applying')
  assert.equal(db.prepare("SELECT COUNT(*) n FROM agent_jobs WHERE agent_id=? AND type='policy.apply' AND json_extract(payload_json,'$.learningSessionId')=?").get(agentId,node.body.training.id).n,2)
})
