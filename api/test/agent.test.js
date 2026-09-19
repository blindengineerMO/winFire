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
openssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-aes-256-cbc','-pass','env:AGENT_CA_PASSPHRASE','-out',file('ca.key'))
openssl('req','-x509','-key',file('ca.key'),'-passin','env:AGENT_CA_PASSPHRASE','-out',file('ca.crt'),'-days','10','-subj','/CN=WinFire Test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
openssl('req','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',file('server.key'),'-out',file('server.csr'),'-subj','/CN=localhost')
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
const {app}=await import('../src/app.js')
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
  assert.equal((await request('POST','/agents/enroll',{token:enrollment.body.token,csr:fs.readFileSync(file('agent.csr'),'utf8')})).status,401)
  const client={cert:enrolled.body.certificate,key:fs.readFileSync(file('agent.key'))}
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/heartbeat`,{version:'test-1'})).status,401)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/heartbeat`,{version:'test-1'},null,client)).status,200)
  const event={recordId:42,id:5157,timeCreated:new Date().toISOString(),fields:{SourceAddress:'192.0.2.10',SourcePort:'52000',DestAddress:'192.0.2.20',DestPort:'3389',Protocol:'6',Direction:'%%14592',Application:'test.exe'}}
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
  const renewed=await request('POST',`/agents/${enrolled.body.agentId}/renew`,{csr:fs.readFileSync(file('renewed.csr'),'utf8')},null,client)
  assert.equal(renewed.status,200)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/heartbeat`,{version:'test-1'},null,client)).status,401)
  const renewedClient={cert:renewed.body.certificate,key:fs.readFileSync(file('renewed.key'))}
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/heartbeat`,{version:'test-2'},null,renewedClient)).status,200)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/revoke`,{},token)).status,200)
  assert.equal((await request('POST',`/agents/${enrolled.body.agentId}/heartbeat`,{version:'test-2'},null,renewedClient)).status,401)
})
