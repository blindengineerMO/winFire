import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-classifier-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@classifier.test'
process.env.BOOTSTRAP_PASSWORD='classifier-password-123'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {classifyNetworkFlow}=await import('../src/services/networkMapping.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('IANA catalog is available and custom classifier rules override and restore built-ins',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@classifier.test',password:'classifier-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const catalog=await auth(request.get('/api/v1/settings/classifier')).expect(200)
  assert.ok(catalog.body.total>10000)
  const https=(await auth(request.get('/api/v1/settings/classifier').query({search:'HTTPS web traffic',pageSize:500})).expect(200)).body.items
  assert.ok(https.some(rule=>rule.service==='HTTPS web traffic'))
  const created=await auth(request.post('/api/v1/settings/classifier/rules')).send({protocol:'TCP',portStart:15432,portEnd:15432,service:'Internal Billing API',description:'Customer application',priority:9000,enabled:true}).expect(201)
  assert.equal(classifyNetworkFlow({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',protocol:'TCP',destinationPort:15432}).service,'Internal Billing API')
  await auth(request.patch(`/api/v1/settings/classifier/rules/${created.body.id}`)).send({protocol:'TCP',portStart:15432,portEnd:15432,service:'Renamed Billing API',description:'Updated application',priority:9000,enabled:true}).expect(200)
  assert.equal(classifyNetworkFlow({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',protocol:'TCP',destinationPort:15432}).service,'Renamed Billing API')
  await auth(request.delete(`/api/v1/settings/classifier/rules/${created.body.id}`)).expect(204)
  assert.notEqual(classifyNetworkFlow({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',protocol:'TCP',destinationPort:15432}).service,'Renamed Billing API')
  const builtin=https.find(rule=>rule.id==='builtin-tcp-443')
  assert.ok(builtin)
  const override=await auth(request.patch(`/api/v1/settings/classifier/rules/${builtin.id}`)).send({protocol:'TCP',portStart:443,portEnd:443,service:'Corporate HTTPS',description:'Managed web gateway',priority:20,enabled:true}).expect(200)
  assert.equal(override.body.source,'custom')
  assert.equal(classifyNetworkFlow({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',protocol:'TCP',destinationPort:443}).service,'Corporate HTTPS')
  await auth(request.delete(`/api/v1/settings/classifier/rules/${override.body.id}`)).expect(204)
  assert.equal(classifyNetworkFlow({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',protocol:'TCP',destinationPort:443}).service,'HTTPS web traffic')
  await auth(request.delete('/api/v1/settings/classifier/rules/builtin-tcp-443')).expect(204)
  assert.equal(classifyNetworkFlow({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',protocol:'TCP',destinationPort:443}).service,null)
  const disabled=(await auth(request.get('/api/v1/settings/classifier').query({search:'HTTPS web traffic',enabled:'false',pageSize:500})).expect(200)).body.items.find(rule=>rule.catalogId==='builtin-tcp-443')
  assert.ok(disabled)
  await auth(request.delete(`/api/v1/settings/classifier/rules/${disabled.id}`)).expect(204)
  assert.equal(classifyNetworkFlow({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',protocol:'TCP',destinationPort:443}).service,'HTTPS web traffic')
})

test('process classifier rules can be created, changed, disabled, and restored',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@classifier.test',password:'classifier-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const builtins=(await auth(request.get('/api/v1/settings/classifier/process-rules')).expect(200)).body.items
  assert.ok(builtins.some(rule=>rule.executablePattern==='lsass.exe'&&rule.service==='Local Security Authority Subsystem Service'))
  const created=await auth(request.post('/api/v1/settings/classifier/process-rules')).send({executablePattern:'contoso-agent.exe',service:'Contoso Agent',description:'Internal endpoint agent',priority:50,enabled:true}).expect(201)
  assert.equal(classifyNetworkFlow({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',protocol:'TCP',program:'\\\\Device\\HarddiskVolume3\\Program Files\\Contoso\\contoso-agent.exe'}).service,'Contoso Agent')
  await auth(request.patch(`/api/v1/settings/classifier/process-rules/${created.body.id}`)).send({executablePattern:'contoso-agent.exe',service:'Renamed Contoso Agent',description:'Updated',priority:50,enabled:true}).expect(200)
  assert.equal(classifyNetworkFlow({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',protocol:'TCP',program:'C:\\Program Files\\Contoso\\contoso-agent.exe'}).service,'Renamed Contoso Agent')
  await auth(request.patch(`/api/v1/settings/classifier/process-rules/${created.body.id}`)).send({executablePattern:'contoso-agent.exe',service:'Renamed Contoso Agent',description:'Updated',priority:50,enabled:false}).expect(200)
  assert.notEqual(classifyNetworkFlow({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',protocol:'TCP',program:'contoso-agent.exe'}).service,'Renamed Contoso Agent')
  const lsass=builtins.find(rule=>rule.executablePattern==='lsass.exe')
  await auth(request.patch(`/api/v1/settings/classifier/process-rules/${lsass.id}`)).send({executablePattern:lsass.executablePattern,service:lsass.service,description:lsass.description,priority:lsass.priority,enabled:false}).expect(200)
  assert.notEqual(classifyNetworkFlow({sourceIp:'10.0.0.1',destinationIp:'10.0.0.2',protocol:'TCP',program:'C:\\Windows\\System32\\lsass.exe'}).service,'Local Security Authority Subsystem Service')
  await auth(request.patch(`/api/v1/settings/classifier/process-rules/${lsass.id}`)).send({executablePattern:lsass.executablePattern,service:lsass.service,description:lsass.description,priority:lsass.priority,enabled:true}).expect(200)
  await auth(request.delete(`/api/v1/settings/classifier/process-rules/${created.body.id}`)).expect(204)
})
