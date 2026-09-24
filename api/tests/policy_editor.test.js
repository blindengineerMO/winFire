import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-policy-editor-'))
process.env.DATA_DIR=dir;process.env.NODE_ENV='test';process.env.BOOTSTRAP_EMAIL='editor@policy.test';process.env.BOOTSTRAP_PASSWORD='Policy-editor-test-123'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db,run,one}=await import('../src/db.js')
const {connectionIssue}=await import('../../web/src/components/policies/model.js')
await bootstrap()
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})
const request=supertest(app)
const login=await request.post('/api/v1/auth/login').send({email:process.env.BOOTSTRAP_EMAIL,password:process.env.BOOTSTRAP_PASSWORD}).expect(200)
const auth=req=>req.set('Authorization','Bearer '+login.body.accessToken)
const graph={nodes:[{id:'address',type:'addressGroup',position:{x:40,y:20},data:{name:'Office network',addresses:'192.0.2.0/24'}},{id:'port',type:'portGroup',position:{x:350,y:20},data:{name:'Web ports',ports:'443'}},{id:'rule',type:'allow',position:{x:650,y:20},data:{name:'HTTPS',direction:'out',protocol:'TCP'}}],edges:[{id:'e1',source:'address',target:'port'},{id:'e2',source:'port',target:'rule'}]}
let policy,version
test('policy draft preview compiles scope connections without writing a version',async()=>{
 policy=(await auth(request.post('/api/v1/policies')).send({name:'Editor integration'}).expect(201)).body
 const result=await auth(request.post(`/api/v1/policies/${policy.id}/preview`)).send({graph}).expect(200)
 assert.equal(result.body.canSave,true);assert.equal(result.body.rules[0].remoteAddress,'192.0.2.0/24');assert.equal(result.body.rules[0].remotePort,'443')
 assert.equal(one('SELECT count(*) n FROM policy_versions WHERE policy_id=?',policy.id).n,0)
 version=(await auth(request.post(`/api/v1/policies/${policy.id}/versions`)).send({graph,baseVersionId:null}).expect(201)).body
 const saved=(await auth(request.get(`/api/v1/policies/${policy.id}/versions`)).expect(200)).body[0]
 assert.deepEqual(saved.graph,graph);assert.deepEqual(saved.rules,result.body.rules)
 assert.equal((await auth(request.get('/api/v1/policies')).expect(200)).body.find(p=>p.id===policy.id).canWrite,true)
})
test('stale draft saves fail without replacing the newer version',async()=>{
 await auth(request.post(`/api/v1/policies/${policy.id}/versions`)).send({graph,baseVersionId:null}).expect(409)
 assert.equal(one('SELECT current_version_id FROM policies WHERE id=?',policy.id).current_version_id,version.id)
 const second=await auth(request.post(`/api/v1/policies/${policy.id}/versions`)).send({graph,baseVersionId:version.id}).expect(201)
 assert.equal(second.body.versionNo,2)
})
test('invalid connections and fields report client errors and never create versions',async()=>{
 const before=one('SELECT count(*) n FROM policy_versions').n
 const cycle={...graph,edges:[...graph.edges,{id:'cycle',source:'rule',target:'address'}]}
 for(const path of ['preview','versions']){
  const result=await auth(request.post(`/api/v1/policies/${policy.id}/${path}`)).send({graph:cycle}).expect(400);assert.match(result.body.error,/cycle/)
  await auth(request.post(`/api/v1/policies/${policy.id}/${path}`)).send({graph:{...graph,edges:[{id:'bad',source:'missing',target:'rule'}]}}).expect(400)
 }
 assert.equal(one('SELECT count(*) n FROM policy_versions').n,before)
 const blocked={nodes:[{id:'guard',type:'deny',data:{name:'Would break management',localPort:'5985'}}],edges:[]}
 const guard=await auth(request.post(`/api/v1/policies/${policy.id}/preview`)).send({graph:blocked}).expect(200)
 assert.equal(guard.body.canSave,false);assert.match(guard.body.managementIssue,/WinRM/)
 assert.match(connectionIssue(graph.nodes,graph.edges,{source:'address',target:'address'}),/itself/)
 assert.match(connectionIssue(graph.nodes,graph.edges,{source:'address',target:'port'}),/already/)
 assert.match(connectionIssue(graph.nodes,graph.edges,{source:'port',target:'address'}),/cycle/)
 assert.equal(connectionIssue(graph.nodes,[],{source:'address',target:'rule'}),'')
})
test('auditors can inspect drafts but cannot save them, and learning remains read-only',async()=>{
 const owner=one('SELECT password_hash FROM users WHERE email=?',process.env.BOOTSTRAP_EMAIL)
 run("INSERT INTO users(id,email,password_hash,role,email_verified) VALUES('auditor','audit@policy.test',?,'auditor',1)",owner.password_hash)
 const signed=await request.post('/api/v1/auth/login').send({email:'audit@policy.test',password:process.env.BOOTSTRAP_PASSWORD}).expect(200)
 const read=req=>req.set('Authorization','Bearer '+signed.body.accessToken)
 assert.equal((await read(request.post(`/api/v1/policies/${policy.id}/preview`)).send({graph}).expect(200)).body.canSave,false)
 await read(request.post(`/api/v1/policies/${policy.id}/versions`)).send({graph}).expect(403)
 assert.equal((await read(request.get('/api/v1/policies')).expect(200)).body.find(p=>p.id===policy.id).canWrite,false)
 run("INSERT INTO nodes(id,hostname) VALUES('learning-node','Learning host')")
 run("UPDATE policies SET origin='learned' WHERE id=?",policy.id)
 run("INSERT INTO learning_sessions(id,node_id,status,started_at,ends_at,generated_policy_id) VALUES('learning-test','learning-node','active',?,?,?)",new Date().toISOString(),new Date(Date.now()+86400000).toISOString(),policy.id)
 assert.equal((await auth(request.post(`/api/v1/policies/${policy.id}/preview`)).send({graph}).expect(200)).body.canSave,false)
 await auth(request.post(`/api/v1/policies/${policy.id}/versions`)).send({graph}).expect(409)
})
