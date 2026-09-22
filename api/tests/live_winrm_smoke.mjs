import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const host=process.env.WINFIRE_TEST_HOST
const username=process.env.WINFIRE_TEST_USER
const password=process.env.WINFIRE_TEST_PASSWORD
if(!host||!username||!password)throw new Error('Set WINFIRE_TEST_HOST, WINFIRE_TEST_USER and WINFIRE_TEST_PASSWORD')

const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-live-smoke-'))
process.env.DATA_DIR=temporary
process.env.BOOTSTRAP_EMAIL='live-smoke@example.test'
process.env.BOOTSTRAP_PASSWORD='temporary-live-smoke-12345'
let database,nodeId,policyId,remote,one
try {
  const dbModule=await import('../src/db.js')
  database=dbModule.db;one=dbModule.one
  const {bootstrap}=await import('../src/security.js')
  const {app}=await import('../src/app.js')
  ;({remote}=await import('../src/connector.js'))
  await bootstrap()
  const request=supertest(app)
  const login=await request.post('/api/v1/auth/login').send({email:process.env.BOOTSTRAP_EMAIL,password:process.env.BOOTSTRAP_PASSWORD}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Temporary live test',type:'domain',username,password}).expect(201)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:host,ip:host,credentialIds:[credential.body.id]}).expect(201)
  nodeId=node.body.id
  const probe=await auth(request.post(`/api/v1/nodes/${nodeId}/probe`)).send({}).expect(200)
  if(!['winrm','winrms'].includes(probe.body.transport))throw new Error(`WinRM was not detected: ${probe.body.transport}`)
  const facts=await auth(request.post(`/api/v1/nodes/${nodeId}/facts/refresh`)).send({}).expect(200)
  const policy=await auth(request.post('/api/v1/policies')).send({name:'Temporary live connector smoke'}).expect(201)
  policyId=policy.body.id
  const inbound={id:'live-inbound',type:'allow',data:{name:'Temporary inbound check',localPort:'65534',remoteAddress:'192.0.2.1',protocol:'TCP',direction:'in',profile:'Any',program:'Any'}}
  const outbound={id:'live-outbound',type:'allow',data:{name:'Temporary outbound check',localPort:'Any',remotePort:'65534',remoteAddress:'192.0.2.1',protocol:'TCP',direction:'out',profile:'Any',program:'Any'}}
  const graph={nodes:[inbound,outbound],edges:[]}
  await auth(request.post(`/api/v1/policies/${policyId}/versions`)).send({graph}).expect(201)
  await auth(request.post(`/api/v1/policies/${policyId}/assignments`)).send({nodeId}).expect(201)
  const applied=await auth(request.post(`/api/v1/policies/${policyId}/apply`)).send({}).expect(200)
  if(applied.body.results?.[0]?.status!=='success'){
    const actual=await remote(one('SELECT * FROM nodes WHERE id=?',nodeId),'rules',{group:`WinFireSecure:${policyId}`})
    const expected=JSON.parse(one('SELECT rules_compiled_json FROM policy_versions WHERE policy_id=? ORDER BY version_no DESC LIMIT 1',policyId).rules_compiled_json)
    console.error(`Rule comparison: ${JSON.stringify({expected,actual})}`)
    throw new Error(`Apply failed: ${JSON.stringify(applied.body.results?.[0])}`)
  }
  const active=await remote(one('SELECT * FROM nodes WHERE id=?',nodeId),'rules',{group:`WinFireSecure:${policyId}`})
  const activeRules=Array.isArray(active)?active:[active].filter(Boolean)
  if(activeRules.length!==2)throw new Error(`Expected two temporary rules, found ${activeRules.length}`)
  if(!activeRules.some(rule=>rule.direction==='out'&&rule.remotePort==='65534'&&rule.localPort==='Any'))throw new Error(`Outbound remote-port rule was not applied: ${JSON.stringify(activeRules)}`)
  const inSync=await auth(request.post('/api/v1/drift/checks')).send({nodeId,policyId}).expect(201)
  if(inSync.body.checks?.[0]?.status!=='in-sync')throw new Error(`Expected in-sync firewall state: ${JSON.stringify(inSync.body.checks)}`)
  await auth(request.post(`/api/v1/policies/${policyId}/versions`)).send({graph:{nodes:[inbound,{...outbound,data:{...outbound.data,remotePort:'65533'}}],edges:[]}}).expect(201)
  const drifted=await auth(request.post('/api/v1/drift/checks')).send({nodeId,policyId}).expect(201)
  if(drifted.body.checks?.[0]?.status!=='drift')throw new Error(`Expected drift before applying the new version: ${JSON.stringify(drifted.body.checks)}`)
  const replaced=await auth(request.post(`/api/v1/policies/${policyId}/apply`)).send({}).expect(200)
  if(replaced.body.results?.[0]?.status!=='success')throw new Error(`Replacement failed: ${JSON.stringify(replaced.body.results?.[0])}`)
  const replacement=await remote(one('SELECT * FROM nodes WHERE id=?',nodeId),'rules',{group:`WinFireSecure:${policyId}`})
  const replacementRules=Array.isArray(replacement)?replacement:[replacement].filter(Boolean)
  if(replacementRules.length!==2||!replacementRules.some(rule=>rule.direction==='out'&&rule.remotePort==='65533')||replacementRules.some(rule=>rule.remotePort==='65534'))throw new Error(`Replacement state is wrong: ${JSON.stringify(replacementRules)}`)
  await auth(request.post(`/api/v1/policies/${policyId}/versions`)).send({graph:{nodes:[],edges:[]}}).expect(201)
  const removed=await auth(request.post(`/api/v1/policies/${policyId}/apply`)).send({}).expect(200)
  if(removed.body.results?.[0]?.status!=='success')throw new Error(`Cleanup apply failed: ${JSON.stringify(removed.body.results?.[0])}`)
  const remaining=await remote(one('SELECT * FROM nodes WHERE id=?',nodeId),'rules',{group:`WinFireSecure:${policyId}`})
  if(remaining&&(Array.isArray(remaining)?remaining.length:1))throw new Error('Temporary rule remains after cleanup')
  console.log(JSON.stringify({node:facts.computer?.Name,transport:probe.body.transport,apply:'success',observedRules:activeRules.length,driftChecks:['in-sync','drift'],replacement:'success',cleanup:'success',auditedRuns:one('SELECT COUNT(*) n FROM policy_apply_runs WHERE policy_id=?',policyId).n}))
} finally {
  if(database&&nodeId&&policyId&&remote){
    try {
      const group=`WinFireSecure:${policyId}`,node=one('SELECT * FROM nodes WHERE id=?',nodeId)
      const current=await remote(node,'rules',{group})
      const rules=Array.isArray(current)?current:[current].filter(Boolean)
      if(rules.length){await remote(node,'apply',{group,remove:rules.map(rule=>rule.name),add:[]});console.error(`Fallback cleanup removed ${rules.length} rule(s) from ${group}`)}
    } catch(error){console.error(`CHECK REMOTE GROUP WinFireSecure:${policyId}: ${error.message}`)}
  }
  database?.close()
  fs.rmSync(temporary,{recursive:true,force:true})
}
