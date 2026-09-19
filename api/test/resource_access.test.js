import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-access-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@access.test'
process.env.BOOTSTRAP_PASSWORD='access-owner-password'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('role permissions and resource grants scope policy, group and vault mutations',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@access.test',password:'access-owner-password'}).expect(200)
  const asOwner=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const editorUser=await asOwner(request.post('/api/v1/users')).send({email:'editor@access.test',password:'access-editor-password',role:'editor'}).expect(201)
  const editor=await request.post('/api/v1/auth/login').send({email:'editor@access.test',password:'access-editor-password'}).expect(200)
  const asEditor=req=>req.set('Authorization',`Bearer ${editor.body.accessToken}`)
  assert.equal(db.prepare("SELECT COUNT(*) n FROM role_permissions WHERE role_id='editor' AND permission_id='portal.edit'").get().n,1)
  const policy=await asOwner(request.post('/api/v1/policies')).send({name:'Owner policy'}).expect(201)
  const group=await asOwner(request.post('/api/v1/node-groups')).send({name:'Owner group'}).expect(201)
  const node=await asOwner(request.post('/api/v1/nodes')).send({hostname:'access-node'}).expect(201)
  const credential=await asOwner(request.post('/api/v1/credentials')).send({name:'Owner credential',type:'local',username:'owner-user',password:'vault-secret'}).expect(201)
  const shareable=await asOwner(request.get('/api/v1/access/resources')).expect(200)
  assert.deepEqual(shareable.body.map(item=>item.type).sort(),['credential','node_group','policy'])
  const shareTargets=await asOwner(request.get('/api/v1/access/users')).expect(200)
  assert.equal(shareTargets.body[0].email,'editor@access.test')
  assert.equal(shareTargets.body[0].password_hash,undefined)
  assert.deepEqual((await asEditor(request.get('/api/v1/access/resources')).expect(200)).body,[])
  assert.deepEqual((await asEditor(request.get('/api/v1/policies')).expect(200)).body,[])
  assert.deepEqual((await asEditor(request.get('/api/v1/node-groups')).expect(200)).body,[])
  await asEditor(request.get(`/api/v1/policies/${policy.body.id}`)).expect(403)
  const graph={nodes:[{id:'rule',type:'allow',data:{name:'HTTPS',localPort:'443'}}],edges:[]}
  await asEditor(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph}).expect(403)
  await asEditor(request.post(`/api/v1/node-groups/${group.body.id}/members`)).send({nodeId:node.body.id}).expect(403)
  await asEditor(request.patch(`/api/v1/credentials/${credential.body.id}`)).send({password:'unauthorized'}).expect(403)
  const privateList=await asEditor(request.get('/api/v1/credentials')).expect(200)
  assert.equal(privateList.body.some(item=>item.id===credential.body.id),false)
  for(const [type,resourceId,permission] of [['policy',policy.body.id,'write'],['node_group',group.body.id,'write'],['credential',credential.body.id,'read']])await asOwner(request.post('/api/v1/access/grants')).send({type,resourceId,userId:editorUser.body.id,permission}).expect(201)
  assert.equal((await asEditor(request.get('/api/v1/access/resources')).expect(200)).body.length,2)
  assert.equal((await asEditor(request.get('/api/v1/policies')).expect(200)).body.length,1)
  assert.equal((await asEditor(request.get('/api/v1/node-groups')).expect(200)).body.length,1)
  await asEditor(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph}).expect(201)
  await asEditor(request.post(`/api/v1/node-groups/${group.body.id}/members`)).send({nodeId:node.body.id}).expect(200)
  const sharedList=await asEditor(request.get('/api/v1/credentials')).expect(200)
  assert.equal(sharedList.body.some(item=>item.id===credential.body.id),true)
  assert.equal(sharedList.body.find(item=>item.id===credential.body.id).canWrite,false)
  await asEditor(request.post(`/api/v1/credentials/${credential.body.id}/assignments`)).send({nodeId:node.body.id}).expect(403)
  await asEditor(request.patch(`/api/v1/credentials/${credential.body.id}`)).send({password:'still-unauthorized'}).expect(403)
  await asOwner(request.post('/api/v1/access/grants')).send({type:'credential',resourceId:credential.body.id,userId:editorUser.body.id,permission:'write'}).expect(201)
  assert.equal((await asEditor(request.get('/api/v1/credentials')).expect(200)).body.find(item=>item.id===credential.body.id).canWrite,true)
  await asEditor(request.post(`/api/v1/credentials/${credential.body.id}/assignments`)).send({nodeId:node.body.id}).expect(201)
  await asEditor(request.patch(`/api/v1/credentials/${credential.body.id}`)).send({password:'rotated-secret'}).expect(200)
  const grants=await asOwner(request.get('/api/v1/access/grants').query({type:'policy',resourceId:policy.body.id})).expect(200)
  assert.equal(grants.body.length,1)
  await asOwner(request.delete(`/api/v1/access/grants/${grants.body[0].id}`)).expect(204)
  await asEditor(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph}).expect(403)
})
