import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-break-glass-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@break-glass.test'
process.env.BOOTSTRAP_PASSWORD='break-glass-test-password'
const {app,processDueBreakGlass}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('admin break glass disables profiles for a bounded window and restores manually or at expiry',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@break-glass.test',password:'break-glass-test-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const editor=await auth(request.post('/api/v1/users')).send({email:'editor@break-glass.test',password:'break-glass-editor-password',role:'editor'}).expect(201)
  const editorLogin=await request.post('/api/v1/auth/login').send({email:editor.body.email,password:'break-glass-editor-password'}).expect(200)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Break glass transport',type:'local',username:'test-admin',password:'test-transport-password'}).expect(201)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'break-glass-node',ip:'127.0.0.1',credentialIds:[credential.body.id]}).expect(201)
  db.prepare("UPDATE nodes SET transport='winrm' WHERE id=?").run(node.body.id)
  const stateFile=path.join(dir,'firewall-state.json'),stub=path.join(dir,'break-glass-transport')
  fs.writeFileSync(stub,`#!/usr/bin/env node
const fs=require('fs');let input='';process.stdin.on('data',part=>input+=part);process.stdin.on('end',()=>{const data=JSON.parse(input),file=process.env.WINFIRE_BREAK_GLASS_STATE;let state=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):{enabled:true};if(data.operation==='breakglass_start'){if(process.env.WINFIRE_BREAK_GLASS_FAIL_START==='1')process.exit(1);state={enabled:false,sessionId:data.args.sessionId,expiresAt:data.args.expiresAt};fs.writeFileSync(file,JSON.stringify(state));process.stdout.write(JSON.stringify({active:true,profiles:[{Name:'Domain',Enabled:true},{Name:'Private',Enabled:false},{Name:'Public',Enabled:true}]}))}else if(data.operation==='breakglass_end'){if(process.env.WINFIRE_BREAK_GLASS_FAIL_END==='1')process.exit(1);state.enabled=true;fs.writeFileSync(file,JSON.stringify(state));process.stdout.write(JSON.stringify({restored:true,profiles:data.args.profiles}))}else process.exit(1)})
`,{mode:0o700})
  const priorPython=process.env.WINRM_PYTHON,priorState=process.env.WINFIRE_BREAK_GLASS_STATE
  process.env.WINRM_PYTHON=stub;process.env.WINFIRE_BREAK_GLASS_STATE=stateFile
  const body={durationMinutes:5,reason:'Temporary firewall troubleshooting',confirmation:'OPEN FIREWALL'}
  try{
    await request.post(`/api/v1/nodes/${node.body.id}/break-glass`).set('Authorization',`Bearer ${editorLogin.body.accessToken}`).send(body).expect(403)
    await auth(request.post(`/api/v1/nodes/${node.body.id}/break-glass`)).send({...body,durationMinutes:241}).expect(400)
    await auth(request.post(`/api/v1/nodes/${node.body.id}/break-glass`)).send({...body,confirmation:'yes'}).expect(400)
    const started=await auth(request.post(`/api/v1/nodes/${node.body.id}/break-glass`)).send(body).expect(201)
    assert.equal(started.body.session.status,'active')
    assert.equal(db.prepare('SELECT status FROM policy_apply_runs WHERE id=?').get(started.body.runId).status,'success')
    assert.equal(JSON.parse(fs.readFileSync(stateFile,'utf8')).enabled,false)
    await auth(request.post(`/api/v1/nodes/${node.body.id}/break-glass`)).send(body).expect(409)
    await auth(request.delete(`/api/v1/nodes/${node.body.id}`)).expect(409)
    const active=await auth(request.get(`/api/v1/nodes/${node.body.id}/break-glass`)).expect(200)
    assert.equal(active.body.active.id,started.body.session.id)
    assert.equal(active.body.active.profile_snapshot_json,undefined)
    const ended=await auth(request.post(`/api/v1/nodes/${node.body.id}/break-glass/end`)).send({sessionId:started.body.session.id}).expect(200)
    assert.equal(ended.body.session.status,'ended')
    assert.equal(db.prepare('SELECT status FROM policy_apply_runs WHERE id=?').get(ended.body.runId).status,'success')
    assert.equal(JSON.parse(fs.readFileSync(stateFile,'utf8')).enabled,true)

    const second=await auth(request.post(`/api/v1/nodes/${node.body.id}/break-glass`)).send(body).expect(201)
    process.env.WINFIRE_BREAK_GLASS_FAIL_END='1'
    await auth(request.post(`/api/v1/nodes/${node.body.id}/break-glass/end`)).send({sessionId:second.body.session.id}).expect(502)
    assert.equal(db.prepare('SELECT status FROM break_glass_sessions WHERE id=?').get(second.body.session.id).status,'active')
    assert.equal(db.prepare('SELECT status FROM policy_apply_runs WHERE node_id=? ORDER BY rowid DESC LIMIT 1').get(node.body.id).status,'unknown')
    delete process.env.WINFIRE_BREAK_GLASS_FAIL_END
    db.prepare('UPDATE break_glass_sessions SET expires_at=? WHERE id=?').run(new Date(Date.now()-1000).toISOString(),second.body.session.id)
    const sweep=await processDueBreakGlass()
    assert.equal(sweep.find(item=>item.sessionId===second.body.session.id).status,'expired')
    assert.equal(JSON.parse(fs.readFileSync(stateFile,'utf8')).enabled,true)
    assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action='break-glass.expired' AND entity_id=?").get(node.body.id).n,1)
  }finally{
    delete process.env.WINFIRE_BREAK_GLASS_FAIL_START;delete process.env.WINFIRE_BREAK_GLASS_FAIL_END
    if(priorPython===undefined)delete process.env.WINRM_PYTHON;else process.env.WINRM_PYTHON=priorPython
    if(priorState===undefined)delete process.env.WINFIRE_BREAK_GLASS_STATE;else process.env.WINFIRE_BREAK_GLASS_STATE=priorState
  }
})
