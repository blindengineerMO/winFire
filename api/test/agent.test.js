import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import https from 'node:https'
import crypto from 'node:crypto'
import {execFileSync} from 'node:child_process'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-agent-test-'))
const file=name=>path.join(dir,name)
const openssl=(...args)=>execFileSync('openssl',args,{stdio:'ignore'})
process.env.AGENT_CA_PASSPHRASE='test-only-ca-passphrase'
process.env.TLS_KEY_PASSPHRASE='test-only-server-key-passphrase'
openssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-aes-256-cbc','-pass','env:AGENT_CA_PASSPHRASE','-out',file('ca.key'))
openssl('req','-x509','-key',file('ca.key'),'-passin','env:AGENT_CA_PASSPHRASE','-out',file('ca.crt'),'-days','10','-subj','/CN=WinFire Test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
openssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-aes-256-cbc','-pass','env:TLS_KEY_PASSPHRASE','-out',file('server.key'))
openssl('req','-new','-key',file('server.key'),'-passin','env:TLS_KEY_PASSPHRASE','-out',file('server.csr'),'-subj','/CN=localhost')
fs.writeFileSync(file('server.ext'),'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
openssl('x509','-req','-in',file('server.csr'),'-CA',file('ca.crt'),'-CAkey',file('ca.key'),'-passin','env:AGENT_CA_PASSPHRASE','-set_serial','0x01','-days','7','-extfile',file('server.ext'),'-out',file('server.crt'))
openssl('req','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',file('agent.key'),'-out',file('agent.csr'),'-subj','/CN=temporary-agent')
openssl('req','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',file('renewed.key'),'-out',file('renewed.csr'),'-subj','/CN=renewed-agent')
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@agent.test'
process.env.BOOTSTRAP_PASSWORD='agent-test-password-123'
process.env.TLS_CERT=file('server.crt')
process.env.TLS_KEY=file('server.key')
process.env.AGENT_CA_CERT=file('ca.crt')
process.env.AGENT_CA_KEY=file('ca.key')
process.env.NODE_ENV='production'
process.env.JWT_SECRET='agent-test-jwt-secret-is-at-least-32-characters'
process.env.VAULT_MASTER_KEY=crypto.randomBytes(32).toString('base64')
const {app,processDueBreakGlass,processDueTraining}=await import('../src/app.js')
const {agentTlsOptions}=await import('../src/agentPki.js')
const {bootstrap}=await import('../src/security.js')
const {one,run,db}=await import('../src/db.js')
const {sweepAgentHealth}=await import('../src/agentHealth.js')
await bootstrap()
const server=https.createServer(agentTlsOptions(),app)
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
const port=server.address().port,ca=fs.readFileSync(file('ca.crt'))

function request(method,url,body,token,client) {
  return new Promise((resolve,reject)=>{
    const data=body===undefined?null:JSON.stringify(body)
    const req=https.request({host:'127.0.0.1',port,path:`/api/v1${url}`,method,ca,
      ...(client?{cert:client.cert,key:client.key}:{}),
      headers:{...(token?{Authorization:`Bearer ${token}`}:{}) ,...(data?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)}:{})}
    },res=>{let output='';res.on('data',chunk=>output+=chunk);res.on('end',()=>resolve({status:res.statusCode,body:JSON.parse(output||'null')}))})
    req.once('error',reject)
    req.end(data)
  })
}

test.after(async()=>{await new Promise(resolve=>server.close(resolve));db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('mTLS enrollment, job polling, completion and revocation',async()=>{
  const login=await request('POST','/auth/login',{email:'owner@agent.test',password:'agent-test-password-123'})
  assert.equal(login.status,200)
  const token=login.body.accessToken
  const node=await request('POST','/nodes',{hostname:'agent-node',ip:'127.0.0.1'},token)
  assert.equal(node.status,201)
  const enrollment=await request('POST','/agents/enrollment-tokens',{nodeId:node.body.id},token)
  assert.equal(enrollment.status,201)
  const enrolled=await request('POST','/agents/enroll',{token:enrollment.body.token,csr:fs.readFileSync(file('agent.csr'),'utf8')})
  assert.equal(enrolled.status,201)
  assert.equal((await request('POST','/agents/enrollment-tokens',{nodeId:node.body.id},token)).status,409)
  assert.equal((await request('POST','/agents/enroll',{token:enrollment.body.token,csr:fs.readFileSync(file('agent.csr'),'utf8')})).status,401)
  const client={cert:enrolled.body.certificate,key:fs.readFileSync(file('agent.key'))}
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/heartbeat`,{version:'test-1'})).status,401)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/heartbeat`,{version:'test-1'},null,client)).status,200)
  const event={recordId:42,id:5157,timeCreated:new Date().toISOString(),fields:{SourceAddress:'192.0.2.20',SourcePort:'3389',DestAddress:'192.0.2.10',DestPort:'52000',Protocol:'6',Direction:'%%14592',Application:'test.exe'}}
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/events`,{events:[event]})).status,401)
  const firstEvents=await request('POST',`/agents/${enrolled.body.agentId}/events`,{events:[event]},null,client)
  assert.equal(firstEvents.status,201)
  assert.equal(firstEvents.body.inserted,1)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/events`,{events:[event]},null,client)).body.inserted,0)
  assert.deepEqual(one('SELECT event_id,action,protocol,src_ip,src_port,dst_ip,dst_port,direction,program FROM log_events WHERE node_id=? AND record_id=42',node.body.id),{event_id:5157,action:'block',protocol:'TCP',src_ip:'192.0.2.10',src_port:52000,dst_ip:'192.0.2.20',dst_port:3389,direction:'in',program:'test.exe'})
  run('UPDATE agents SET last_checkin_at=? WHERE id=?',new Date(Date.now()-300_000).toISOString(),enrolled.body.agentId)
  assert.equal(sweepAgentHealth(),1)
  assert.equal(one('SELECT status FROM nodes WHERE id=?',node.body.id).status,'unreachable')
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/heartbeat`,{version:'test-1'},null,client)).status,200)
  assert.equal(one('SELECT status FROM nodes WHERE id=?',node.body.id).status,'reachable')
  const policy=await request('POST','/policies',{name:'Agent policy'},token)
  assert.equal(policy.status,201)
  const version=await request('POST',`/policies/${policy.body.id}/versions`,{graph:{nodes:[{id:'allow-agent',type:'allow',data:{name:'HTTPS',localPort:'443'}}],edges:[]}},token)
  assert.equal(version.status,201)
  const assigned=await request('POST',`/policies/${policy.body.id}/assignments`,{nodeId:node.body.id},token)
  assert.equal(assigned.status,201)
  const applied=await request('POST',`/policies/${policy.body.id}/apply`,{},token)
  assert.equal(applied.status,200)
  assert.equal(applied.body.results[0].status,'queued')
  const jobs=await request('GET',`/agents/${enrolled.body.agentId}/jobs`,undefined,null,client)
  assert.equal(jobs.status,200)
  assert.equal(jobs.body.jobs[0].type,'policy.apply')
  const learningId=crypto.randomUUID()
  run("INSERT INTO learning_sessions(id,node_id,status,generated_policy_id) VALUES(?,?,?,?)",learningId,node.body.id,'applying',policy.body.id)
  run("UPDATE nodes SET firewall_state='review' WHERE id=?",node.body.id)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/jobs/${jobs.body.jobs[0].id}/result`,{leaseToken:'invalid-lease-token-12345',success:true},null,client)).status,409)
  const complete=await request('POST',`/agents/${enrolled.body.agentId}/jobs/${jobs.body.jobs[0].id}/result`,{leaseToken:jobs.body.jobs[0].leaseToken,success:true,diff:{add:1,remove:0}},null,client)
  assert.equal(complete.status,200)
  assert.equal(one('SELECT status FROM policy_apply_runs WHERE id=?',jobs.body.jobs[0].payload.applyRunId).status,'success')
  assert.equal(one('SELECT status FROM learning_sessions WHERE id=?',learningId).status,'enforced')
  assert.equal(one('SELECT firewall_state FROM nodes WHERE id=?',node.body.id).firewall_state,'enforcing')
  const driftRequest=await request('POST','/drift/checks',{nodeId:node.body.id,policyId:policy.body.id},token)
  assert.equal(driftRequest.status,201)
  assert.equal(driftRequest.body.checks[0].status,'pending')
  const repeated=await request('POST','/drift/checks',{nodeId:node.body.id,policyId:policy.body.id},token)
  assert.equal(repeated.body.checks[0].id,driftRequest.body.checks[0].id)
  assert.equal(one("SELECT COUNT(*) n FROM agent_jobs WHERE type='policy.read' AND agent_id=?",enrolled.body.agentId).n,1)
  const readJobs=await request('GET',`/agents/${enrolled.body.agentId}/jobs`,undefined,null,client)
  assert.equal(readJobs.body.jobs[0].type,'policy.read')
  const expectedRules=JSON.parse(one('SELECT rules_compiled_json FROM policy_versions WHERE id=?',version.body.id).rules_compiled_json)
  const readComplete=await request('POST',`/agents/${enrolled.body.agentId}/jobs/${readJobs.body.jobs[0].id}/result`,{leaseToken:readJobs.body.jobs[0].leaseToken,success:true,result:{rules:expectedRules}},null,client)
  assert.equal(readComplete.status,200)
  assert.equal(one('SELECT status FROM policy_drift_checks WHERE id=?',driftRequest.body.checks[0].id).status,'in-sync')
  const missingRequest=await request('POST','/drift/checks',{nodeId:node.body.id,policyId:policy.body.id},token)
  const missingJobs=await request('GET',`/agents/${enrolled.body.agentId}/jobs`,undefined,null,client)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/jobs/${missingJobs.body.jobs[0].id}/result`,{leaseToken:missingJobs.body.jobs[0].leaseToken,success:true,result:{rules:[]}},null,client)).status,200)
  assert.equal(one('SELECT status FROM policy_drift_checks WHERE id=?',missingRequest.body.checks[0].id).status,'drift')
  const remove=await request('DELETE',`/policies/${policy.body.id}/assignments/${assigned.body.id}`,undefined,token)
  assert.equal(remove.status,202)
  assert.equal((await request('DELETE',`/policies/${policy.body.id}/assignments/${assigned.body.id}`,undefined,token)).body.jobId,remove.body.jobId)
  assert.equal((await request('POST',`/policies/${policy.body.id}/apply`,{},token)).status,409)
  assert.equal(one('SELECT removal_job_id FROM policy_assignments WHERE id=?',assigned.body.id).removal_job_id,remove.body.jobId)
  const removalJobs=await request('GET',`/agents/${enrolled.body.agentId}/jobs`,undefined,null,client)
  assert.deepEqual(removalJobs.body.jobs[0].payload.rules,[])
  assert.equal(removalJobs.body.jobs[0].payload.removalAssignmentId,assigned.body.id)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/jobs/${remove.body.jobId}/result`,{leaseToken:removalJobs.body.jobs[0].leaseToken,success:false,error:'simulated cleanup failure'},null,client)).status,200)
  assert.equal(one('SELECT removal_job_id FROM policy_assignments WHERE id=?',assigned.body.id).removal_job_id,null)
  const retry=await request('DELETE',`/policies/${policy.body.id}/assignments/${assigned.body.id}`,undefined,token)
  assert.equal(retry.status,202)
  const retryJobs=await request('GET',`/agents/${enrolled.body.agentId}/jobs`,undefined,null,client)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/jobs/${retry.body.jobId}/result`,{leaseToken:retryJobs.body.jobs[0].leaseToken,success:true,diff:{add:[],remove:['HTTPS']}},null,client)).status,200)
  assert.equal(one('SELECT id FROM policy_assignments WHERE id=?',assigned.body.id),undefined)
  assert.equal(one('SELECT status FROM policy_apply_runs WHERE id=?',retryJobs.body.jobs[0].payload.applyRunId).status,'success')
  const renewed=await request('POST',`/agents/${enrolled.body.agentId}/renew`,{csr:fs.readFileSync(file('renewed.csr'),'utf8')},null,client)
  assert.equal(renewed.status,200)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/heartbeat`,{version:'test-1'},null,client)).status,401)
  const renewedClient={cert:renewed.body.certificate,key:fs.readFileSync(file('renewed.key'))}
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/heartbeat`,{version:'test-2'},null,renewedClient)).status,200)
  const assignedAgain=await request('POST',`/policies/${policy.body.id}/assignments`,{nodeId:node.body.id},token)
  assert.equal(assignedAgain.status,201)
  const pendingRevoke=await request('DELETE',`/policies/${policy.body.id}/assignments/${assignedAgain.body.id}`,undefined,token)
  assert.equal(pendingRevoke.status,202)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/revoke`,{},token)).status,200)
  assert.equal(one('SELECT removal_job_id FROM policy_assignments WHERE id=?',assignedAgain.body.id).removal_job_id,null)
  assert.equal(one('SELECT status FROM agent_jobs WHERE id=?',pendingRevoke.body.jobId).status,'failed')
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/heartbeat`,{version:'test-2'},null,renewedClient)).status,401)
})

test('agent break glass is queued, confirmed, restored, and expires',async()=>{
  const login=await request('POST','/auth/login',{email:'owner@agent.test',password:'agent-test-password-123'})
  const token=login.body.accessToken
  const node=await request('POST','/nodes',{hostname:'agent-break-glass'},token)
  assert.equal(node.status,201)
  const enrollment=await request('POST','/agents/enrollment-tokens',{nodeId:node.body.id},token)
  const enrolled=await request('POST','/agents/enroll',{token:enrollment.body.token,csr:fs.readFileSync(file('agent.csr'),'utf8')})
  assert.equal(enrolled.status,201)
  const client={cert:enrolled.body.certificate,key:fs.readFileSync(file('agent.key'))}
  const start=()=>request('POST',`/nodes/${node.body.id}/break-glass`,{durationMinutes:5,reason:'Agent troubleshooting window',confirmation:'OPEN FIREWALL'},token)
  const profiles=[{Name:'Domain',Enabled:true},{Name:'Private',Enabled:true},{Name:'Public',Enabled:false}]
  const first=await start()
  assert.equal(first.status,202)
  assert.equal(first.body.session.status,'activating')
  assert.equal(one('SELECT status FROM policy_apply_runs WHERE id=?',first.body.runId).status,'running')
  const startJob=(await request('GET',`/agents/${enrolled.body.agentId}/jobs`,undefined,null,client)).body.jobs[0]
  assert.equal(startJob.type,'breakglass.start')
  assert.equal(startJob.payload.applyRunId,first.body.runId)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/jobs/${startJob.id}/result`,{leaseToken:startJob.leaseToken,success:true,result:{active:true,profiles}},null,client)).status,200)
  assert.equal(one('SELECT status FROM break_glass_sessions WHERE id=?',first.body.session.id).status,'active')
  assert.equal(one('SELECT status FROM policy_apply_runs WHERE id=?',first.body.runId).status,'success')
  const end=await request('POST',`/nodes/${node.body.id}/break-glass/end`,{sessionId:first.body.session.id},token)
  assert.equal(end.status,202)
  const endJob=(await request('GET',`/agents/${enrolled.body.agentId}/jobs`,undefined,null,client)).body.jobs[0]
  assert.equal(endJob.type,'breakglass.end')
  assert.deepEqual(endJob.payload.profiles,profiles)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/jobs/${endJob.id}/result`,{leaseToken:endJob.leaseToken,success:true,result:{restored:true,profiles}},null,client)).status,200)
  assert.equal(one('SELECT status FROM break_glass_sessions WHERE id=?',first.body.session.id).status,'ended')
  assert.equal(one('SELECT status FROM policy_apply_runs WHERE id=?',end.body.runId).status,'success')

  const second=await start()
  assert.equal(second.status,202)
  const secondStart=(await request('GET',`/agents/${enrolled.body.agentId}/jobs`,undefined,null,client)).body.jobs[0]
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/jobs/${secondStart.id}/result`,{leaseToken:secondStart.leaseToken,success:true,result:{active:true,profiles}},null,client)).status,200)
  run('UPDATE break_glass_sessions SET expires_at=? WHERE id=?',new Date(Date.now()-1000).toISOString(),second.body.session.id)
  const due=await processDueBreakGlass()
  assert.equal(due.find(item=>item.sessionId===second.body.session.id).status,'ending')
  const expiryJob=(await request('GET',`/agents/${enrolled.body.agentId}/jobs`,undefined,null,client)).body.jobs[0]
  assert.equal(expiryJob.payload.finalStatus,'expired')
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/jobs/${expiryJob.id}/result`,{leaseToken:expiryJob.leaseToken,success:true,result:{restored:true,profiles}},null,client)).status,200)
  assert.equal(one('SELECT status FROM break_glass_sessions WHERE id=?',second.body.session.id).status,'expired')
  const invalid=await start()
  assert.equal(invalid.status,202)
  const invalidJob=(await request('GET',`/agents/${enrolled.body.agentId}/jobs`,undefined,null,client)).body.jobs[0]
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/jobs/${invalidJob.id}/result`,{leaseToken:invalidJob.leaseToken,success:true,result:{active:false,profiles}},null,client)).status,200)
  assert.equal(one('SELECT status FROM agent_jobs WHERE id=?',invalidJob.id).status,'failed')
  assert.equal(one('SELECT status FROM break_glass_sessions WHERE id=?',invalid.body.session.id).status,'failed')
  assert.equal(one('SELECT status FROM policy_apply_runs WHERE id=?',invalid.body.runId).status,'failed')
})

test('agent training waits for personal and global apply acknowledgements',async()=>{
  const login=await request('POST','/auth/login',{email:'owner@agent.test',password:'agent-test-password-123'})
  const token=login.body.accessToken
  const node=await request('POST','/nodes',{hostname:'agent-final-training'},token)
  const enrollment=await request('POST','/agents/enrollment-tokens',{nodeId:node.body.id},token)
  const enrolled=await request('POST','/agents/enroll',{token:enrollment.body.token,csr:fs.readFileSync(file('agent.csr'),'utf8')})
  const client={cert:enrolled.body.certificate,key:fs.readFileSync(file('agent.key'))}
  const global=await request('POST','/policies',{name:'Agent fleet baseline'},token)
  await request('POST',`/policies/${global.body.id}/versions`,{graph:{nodes:[{id:'fleet-rule',type:'allow',data:{name:'Fleet HTTPS',localPort:'443'}}],edges:[]}},token)
  assert.equal((await request('POST',`/policies/${global.body.id}/assignments`,{nodeGroupId:'winfire-global-all-nodes'},token)).status,201)
  run('UPDATE learning_sessions SET ends_at=?,last_attempt_at=NULL WHERE id=?',new Date(Date.now()-1000).toISOString(),node.body.training.id)
  const due=await processDueTraining()
  assert.equal(due.find(item=>item.sessionId===node.body.training.id).status,'applying')
  const jobs=(await request('GET',`/agents/${enrolled.body.agentId}/jobs`,undefined,null,client)).body.jobs.filter(job=>job.payload.learningSessionId===node.body.training.id)
  assert.equal(jobs.length,2)
  assert.equal(jobs.every(job=>job.payload.learningExpectedJobs===2),true)
  for(const [index,job] of jobs.entries()){
    assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/jobs/${job.id}/result`,{leaseToken:job.leaseToken,success:true,diff:{add:[],remove:[]}},null,client)).status,200)
    assert.equal(one('SELECT status FROM learning_sessions WHERE id=?',node.body.training.id).status,index===0?'applying':'enforced')
  }
})

test('remote agent installation records a verified apply run and a failed attempt',async()=>{
  const login=await request('POST','/auth/login',{email:'owner@agent.test',password:'agent-test-password-123'})
  const token=login.body.accessToken
  const credential=await request('POST','/credentials',{name:'Install test',type:'local',username:'test-admin',password:'test-only-password'},token)
  assert.equal(credential.status,201)
  const createNode=async hostname=>{
    const created=await request('POST','/nodes',{hostname,ip:'127.0.0.1',credentialIds:[credential.body.id]},token)
    assert.equal(created.status,201)
    run("UPDATE nodes SET transport='winrm' WHERE id=?",created.body.id)
    return created.body.id
  }
  const first=await createNode('install-success'),second=await createNode('install-failure')
  const packagePath=file('WinFire.Agent.exe'),stub=file('install-stub')
  fs.writeFileSync(packagePath,'signed-package-fixture')
  fs.writeFileSync(stub,`#!/usr/bin/env node
let body='';process.stdin.on('data',part=>body+=part);process.stdin.on('end',()=>{
  const input=JSON.parse(body)
  if(input.operation!=='agent_deploy')process.exit(2)
  if(process.env.WINFIRE_TEST_DEPLOY_FAIL==='1')process.exit(1)
  const crypto=require('crypto'),path=require('path'),Database=require(require.resolve('better-sqlite3',{paths:[process.cwd()]}))
  const db=new Database(path.join(process.env.DATA_DIR,'winfire.db')),agentId=crypto.randomUUID()
  db.prepare("INSERT INTO agents(id,node_id,cert_thumbprint,cert_expires_at,version,mode,last_checkin_at) VALUES(?,?,?,?,?,?,?)").run(agentId,process.env.WINFIRE_TEST_DEPLOY_NODE,'test-thumbprint',new Date(Date.now()+86400000).toISOString(),'test','pull',new Date().toISOString())
  db.close();process.stdout.write(JSON.stringify({installed:true,status:'Running'}))
})
`,{mode:0o700})
  const previous={python:process.env.WINRM_PYTHON,packagePath:process.env.AGENT_PACKAGE_PATH,base:process.env.PUBLIC_BASE_URL}
  process.env.WINRM_PYTHON=stub;process.env.AGENT_PACKAGE_PATH=packagePath;process.env.PUBLIC_BASE_URL='https://localhost'
  try{
    process.env.WINFIRE_TEST_DEPLOY_NODE=first
    const installed=await request('POST',`/nodes/${first}/deploy-agent`,{},token)
    assert.equal(installed.status,200,JSON.stringify(installed.body))
    assert.equal(one('SELECT status FROM policy_apply_runs WHERE id=?',installed.body.runId).status,'success')
    assert.equal(JSON.parse(one('SELECT diff_json FROM policy_apply_runs WHERE id=?',installed.body.runId).diff_json).operation,'agent_deploy')
    process.env.WINFIRE_TEST_DEPLOY_NODE=second;process.env.WINFIRE_TEST_DEPLOY_FAIL='1'
    const failed=await request('POST',`/nodes/${second}/deploy-agent`,{},token)
    assert.equal(failed.status,502)
    assert.equal(one('SELECT status FROM policy_apply_runs WHERE node_id=? ORDER BY rowid DESC LIMIT 1',second).status,'failed')
  }finally{
    for(const [key,value] of [['WINRM_PYTHON',previous.python],['AGENT_PACKAGE_PATH',previous.packagePath],['PUBLIC_BASE_URL',previous.base]])if(value===undefined)delete process.env[key];else process.env[key]=value
    delete process.env.WINFIRE_TEST_DEPLOY_NODE;delete process.env.WINFIRE_TEST_DEPLOY_FAIL
  }
})
