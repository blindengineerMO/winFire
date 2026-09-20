import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'
import {compilePolicy} from '@winfire/shared'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-sync-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@sync.test'
process.env.BOOTSTRAP_PASSWORD='sync-test-password-123'
const {app,processDuePolicySync}=await import('../src/app.js')
const {bootstrap,seal}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {ensureLoopbackBaseline,loopbackRules}=await import('../src/loopbackBaseline.js')
const {sourceMatches}=await import('../src/mfaPortal.js')
const {diffRules,remote}=await import('../src/connector.js')
const {remoteIpFromBlockedEvent,sweepMfaPrompts,processBlockedMfaEvent}=await import('../src/mfaPrompt.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('duplicate rules and like ports compile into one firewall entry',()=>{
  const graph={nodes:[
    {id:'one',type:'allow',data:{name:'Web 80',direction:'in',protocol:'TCP',localPort:'80',remoteAddress:'192.0.2.1'}},
    {id:'two',type:'allow',data:{name:'Web 443',direction:'in',protocol:'TCP',localPort:'443',remoteAddress:'192.0.2.1'}},
    {id:'three',type:'allow',data:{name:'Web 80 again',direction:'in',protocol:'TCP',localPort:'80',remoteAddress:'192.0.2.1'}}
  ],edges:[]}
  const rules=compilePolicy(graph,'dedup-test')
  assert.equal(rules.length,1)
  assert.equal(rules[0].localPort,'80,443')
  const addresses=compilePolicy({nodes:[
    {id:'a',type:'allow',data:{direction:'in',protocol:'TCP',localPort:'80',remoteAddress:'192.0.2.1'}},
    {id:'b',type:'allow',data:{direction:'in',protocol:'TCP',localPort:'80',remoteAddress:'192.0.2.2'}},
    {id:'c',type:'allow',data:{direction:'in',protocol:'TCP',localPort:'443',remoteAddress:'192.0.2.1'}}
  ],edges:[]},'dedup-address')
  assert.equal(addresses.length,2)
  assert.equal(addresses.some(rule=>rule.localPort==='80,443'&&rule.remoteAddress==='192.0.2.1'),true)
  assert.equal(addresses.some(rule=>rule.localPort==='80'&&rule.remoteAddress==='192.0.2.2'),true)
  const samePort=compilePolicy({nodes:[
    {id:'d',type:'allow',data:{direction:'in',protocol:'TCP',localPort:'80',remoteAddress:'192.0.2.1'}},
    {id:'e',type:'allow',data:{direction:'in',protocol:'TCP',localPort:'80',remoteAddress:'192.0.2.2'}}
  ],edges:[]},'dedup-address-2')
  assert.equal(samePort.length,1)
  assert.equal(samePort[0].remoteAddress,'192.0.2.1,192.0.2.2')
  const desired={...samePort[0],remoteAddress:'192.0.2.7/24'}
  const observed={...desired,remoteAddress:'192.0.2.0/255.255.255.0'}
  assert.deepEqual(diffRules([desired],[observed]),{add:[],remove:[]})
})

test('agent loopback baseline queues once and keeps scoped IPv4 rules',async()=>{
  const nodeId=crypto.randomUUID(),agentId=crypto.randomUUID()
  db.prepare("INSERT INTO nodes(id,hostname,connection_mode,agent_id) VALUES(?,?,?,?)").run(nodeId,'loopback-agent','agent',agentId)
  db.prepare('INSERT INTO agents(id,node_id,cert_thumbprint,version,last_checkin_at) VALUES(?,?,?,?,?)').run(agentId,nodeId,'LOOPBACK-TEST','test',new Date().toISOString())
  const node=db.prepare('SELECT * FROM nodes WHERE id=?').get(nodeId)
  const first=await ensureLoopbackBaseline(node)
  assert.equal(first.status,'queued')
  assert.equal((await ensureLoopbackBaseline(node)).job_id,first.jobId)
  const payload=JSON.parse(db.prepare('SELECT payload_json FROM agent_jobs WHERE id=?').get(first.jobId).payload_json)
  assert.equal(payload.group,'WinFireSecure:system-loopback')
  assert.equal(payload.rules.length,2)
  assert.deepEqual(new Set(loopbackRules.map(rule=>rule.remoteAddress)),new Set(['127.0.0.0/255.0.0.0']))
})

test('policy revisions wait for explicit or scheduled administrator sync and events stage personal rules',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@sync.test',password:'sync-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=(await auth(request.post('/api/v1/nodes')).send({hostname:'sync-node',connectionMode:'agent'}).expect(201)).body
  db.prepare("UPDATE learning_sessions SET status='enforced' WHERE node_id=?").run(node.id)
  db.prepare("UPDATE nodes SET firewall_state='enforcing' WHERE id=?").run(node.id)
  const agentId=crypto.randomUUID()
  db.prepare('INSERT INTO agents(id,node_id,cert_thumbprint,version,last_checkin_at) VALUES(?,?,?,?,?)').run(agentId,node.id,'SYNC-TEST','test',new Date().toISOString())
  db.prepare('UPDATE nodes SET agent_id=? WHERE id=?').run(agentId,node.id)
  const policy=(await auth(request.post('/api/v1/policies')).send({name:'Staged RDP'}).expect(201)).body
  const graph={nodes:[{id:'rdp',type:'allow',data:{name:'RDP',direction:'in',protocol:'TCP',localPort:'3389',remoteAddress:'192.0.2.5'}}],edges:[]}
  await auth(request.post(`/api/v1/policies/${policy.id}/versions`)).send({graph}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.id}/assignments`)).send({nodeId:node.id}).expect(201)
  let pending=(await auth(request.get('/api/v1/policies/sync')).expect(200)).body.pending
  assert.equal(pending.some(item=>item.policy_id===policy.id&&item.node_id===node.id),true)
  assert.equal(db.prepare("SELECT COUNT(*) n FROM agent_jobs WHERE type='policy.apply' AND json_extract(payload_json,'$.policyId')=?").get(policy.id).n,0)
  const schedule=(await auth(request.post('/api/v1/policies/sync')).send({executeAt:new Date(Date.now()+3600_000).toISOString()}).expect(201)).body
  assert.equal(schedule.status,'scheduled')
  assert.equal(db.prepare("SELECT COUNT(*) n FROM agent_jobs WHERE type='policy.apply' AND json_extract(payload_json,'$.policyId')=?").get(policy.id).n,0)
  db.prepare('UPDATE policy_sync_schedules SET execute_at=? WHERE id=?').run(new Date(Date.now()-1000).toISOString(),schedule.id)
  await processDuePolicySync()
  assert.equal(db.prepare('SELECT status FROM policy_sync_schedules WHERE id=?').get(schedule.id).status,'complete')
  assert.equal(db.prepare("SELECT COUNT(*) n FROM agent_jobs WHERE type='policy.apply' AND json_extract(payload_json,'$.policyId')=?").get(policy.id).n,1)
  pending=(await auth(request.get('/api/v1/policies/sync')).expect(200)).body.pending
  assert.equal(pending.some(item=>item.policy_id===policy.id),false)
  await auth(request.post(`/api/v1/policies/${policy.id}/versions`)).send({graph:{nodes:[...graph.nodes,{id:'ssh',type:'deny',data:{name:'SSH',direction:'in',protocol:'TCP',localPort:'22',remoteAddress:'192.0.2.5'}}],edges:[]}}).expect(201)
  assert.equal((await auth(request.get('/api/v1/policies/sync')).expect(200)).body.pending.some(item=>item.policy_id===policy.id),true)

  await auth(request.post('/api/v1/logs/ingest')).send({nodeId:node.id,events:[{recordId:55,eventId:5157,action:'block',protocol:'TCP',srcIp:'198.51.100.8',dstIp:'192.0.2.10',dstPort:8443,direction:'in'}]}).expect(201)
  const eventId=db.prepare('SELECT id FROM log_events WHERE node_id=? AND record_id=55').get(node.id).id
  const fromEvent=(await auth(request.post(`/api/v1/logs/${eventId}/rule`)).send({action:'allow'}).expect(201)).body
  assert.equal(fromEvent.pendingSync,true)
  assert.equal(db.prepare('SELECT node_id FROM policy_assignments WHERE policy_id=?').get(fromEvent.policyId).node_id,node.id)
  const rule=JSON.parse(db.prepare('SELECT rules_compiled_json FROM policy_versions WHERE id=?').get(fromEvent.versionId).rules_compiled_json)[0]
  assert.equal(rule.localPort,'8443')
  assert.equal(rule.remoteAddress,'198.51.100.8')
})

test('group details, group identity targets, and audit search exports resolve correctly',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@sync.test',password:'sync-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=(await auth(request.post('/api/v1/nodes')).send({hostname:'group-target',connectionMode:'agent'}).expect(201)).body
  const group=(await auth(request.post('/api/v1/node-groups')).send({name:'MFA servers'}).expect(201)).body
  await auth(request.post(`/api/v1/node-groups/${group.id}/members`)).send({nodeId:node.id}).expect(200)
  const detail=(await auth(request.get(`/api/v1/node-groups/${group.id}`)).expect(200)).body
  assert.equal(detail.count,1)
  assert.equal(detail.members[0].hostname,'group-target')
  const segment=(await auth(request.post('/api/v1/segments')).send({name:'Group RDP',nodeGroupId:group.id,port:3389}).expect(201)).body
  assert.equal(segment.node_group_id,group.id)
  await auth(request.post(`/api/v1/segments/${segment.id}/challenges`)).send({userUpn:'user@example.test',nodeId:'wrong-node'}).expect(400)
  const challenge=(await auth(request.post(`/api/v1/segments/${segment.id}/challenges`)).send({userUpn:'user@example.test',nodeId:node.id}).expect(201)).body
  assert.equal(challenge.status,'pending')
  const audit=(await auth(request.get('/api/v1/audit/search').query({q:'segment.create',pageSize:1})).expect(200)).body
  assert.ok(audit.total>=1)
  assert.equal(audit.items[0].action,'segment.create')
  for(const format of ['csv','pdf','xls']){
    const exportResponse=await auth(request.get('/api/v1/audit/search').query({q:'segment.create',export:format})).expect(200)
    assert.match(exportResponse.headers['content-disposition'],new RegExp(`audit-trail\\.${format}`))
  }
})

test('portal access is scoped to listed operators and requires an enrolled authenticator',async()=>{
  assert.equal(sourceMatches('192.0.2.7','192.0.2.0/24'),true)
  assert.equal(sourceMatches('198.51.100.7','192.0.2.0/24'),false)
  const login=await request.post('/api/v1/auth/login').send({email:'owner@sync.test',password:'sync-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=(await auth(request.post('/api/v1/nodes')).send({hostname:'portal-test',connectionMode:'agentless'}).expect(201)).body
  db.prepare("UPDATE nodes SET transport='winrm',firewall_state='enforcing' WHERE id=?").run(node.id)
  const segment=(await auth(request.post('/api/v1/segments')).send({name:'Portal SSH',nodeId:node.id,policyId:null,port:22,allowedUpns:['owner@sync.test'],mfaProvider:'totp',ttlMinutes:10}).expect(201)).body
  assert.equal((await auth(request.get('/api/v1/segments/access')).expect(200)).body.some(item=>item.id===segment.id),true)
  const policy=(await auth(request.post('/api/v1/policies')).send({name:'Portal gate policy'}).expect(201)).body
  await auth(request.patch(`/api/v1/segments/${segment.id}`)).send({policyId:policy.id}).expect(200)
  let access=await auth(request.post(`/api/v1/segments/${segment.id}/access`)).send({code:'123456'}).expect(409)
  assert.match(access.body.error,/not assigned/)
  await auth(request.post(`/api/v1/policies/${policy.id}/assignments`)).send({nodeId:node.id}).expect(201)
  access=await auth(request.post(`/api/v1/segments/${segment.id}/access`)).send({code:'123456'}).expect(409)
  assert.match(access.body.error,/Sync the linked MFA policy/)
  db.prepare('INSERT INTO policy_apply_runs(id,policy_id,version_id,node_id,status) VALUES(?,?,?,?,?)').run(crypto.randomUUID(),policy.id,db.prepare('SELECT current_version_id FROM policies WHERE id=?').get(policy.id).current_version_id,node.id,'success')
  await auth(request.post(`/api/v1/segments/${segment.id}/access`)).send({code:'123456'}).expect(409)
  await auth(request.patch(`/api/v1/segments/${segment.id}`)).send({portalEnabled:false}).expect(200)
  assert.equal((await auth(request.get('/api/v1/segments/access')).expect(200)).body.some(item=>item.id===segment.id),false)
  await auth(request.post(`/api/v1/segments/${segment.id}/access`)).send({code:'123456'}).expect(409)
  await auth(request.patch(`/api/v1/segments/${segment.id}`)).send({portalEnabled:true,mfaProvider:'entra'}).expect(200)
  await auth(request.post(`/api/v1/segments/${segment.id}/entra/start`)).send({}).expect(503)
  await auth(request.post('/api/v1/segments/entra/complete')).send({code:'dummy-code-value',state:'0123456789abcdef'}).expect(401)
})

test('administrator branding is public on the MFA portal and validates image type',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@sync.test',password:'sync-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  assert.equal((await request.get('/api/v1/portal-branding').expect(200)).body.companyName,'WinFire Secure')
  await auth(request.patch('/api/v1/settings/portal-branding')).send({companyName:'Puckett Security'}).expect(200)
  assert.equal((await request.get('/api/v1/portal-branding').expect(200)).body.companyName,'Puckett Security')
  await auth(request.put('/api/v1/settings/portal-branding/image')).send({mimeType:'image/png',base64:Buffer.from('not an image').toString('base64')}).expect(400)
  const png='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jR5cAAAAASUVORK5CYII='
  const saved=(await auth(request.put('/api/v1/settings/portal-branding/image')).send({mimeType:'image/png',base64:png}).expect(200)).body
  assert.match(saved.imageUrl,/\/api\/v1\/portal-branding\/image/)
  await request.get('/api/v1/portal-branding/image').expect('Content-Type',/image\/png/).expect(200)
  await auth(request.delete('/api/v1/settings/portal-branding/image')).expect(200)
  await request.get('/api/v1/portal-branding/image').expect(404)
})

test('policy versions reject rules that would block WinRM management',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@sync.test',password:'sync-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const policy=(await auth(request.post('/api/v1/policies')).send({name:'Management guard check'}).expect(201)).body
  const graph={nodes:[{id:'block-management',type:'deny',data:{name:'Bad WinRM block',direction:'in',protocol:'TCP',localPort:'5985',remoteAddress:'Any'}}],edges:[]}
  const response=await auth(request.post(`/api/v1/policies/${policy.id}/versions`)).send({graph}).expect(409)
  assert.match(response.body.error,/WinRM/)
})

test('blocked inbound WFP traffic prompts only from an identifiable managed workstation',async()=>{
  const local=new Set(['192.0.2.20'])
  assert.deepEqual(remoteIpFromBlockedEvent({event_id:5157,action:'block',direction:'in',protocol:'TCP',src_ip:'192.0.2.10',src_port:52000,dst_ip:'192.0.2.20'},local),{sourceIp:'192.0.2.10',targetIp:'192.0.2.20',sourcePort:52000})
  assert.equal(remoteIpFromBlockedEvent({event_id:5157,action:'block',direction:'in',protocol:'TCP',src_ip:'192.0.2.10',dst_ip:'192.0.2.30'},local),null)
  const login=await request.post('/api/v1/auth/login').send({email:'owner@sync.test',password:'sync-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const target=(await auth(request.post('/api/v1/nodes')).send({hostname:'mfa-prompt-target',ip:'192.0.2.20',connectionMode:'agentless'}).expect(201)).body
  db.prepare("UPDATE nodes SET firewall_state='enforcing',transport='winrm' WHERE id=?").run(target.id)
  const segment=(await auth(request.post('/api/v1/segments')).send({name:'Prompt RDP',nodeId:target.id,port:3389,allowedUpns:['owner@sync.test'],autoPromptEnabled:true}).expect(201)).body
  const eventId=crypto.randomUUID()
  db.prepare("INSERT INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,src_port,dst_ip,dst_port,direction,event_time) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)").run(eventId,target.id,999,5157,'block','TCP','192.0.2.10',52000,'192.0.2.20',3389,'in',new Date().toISOString())
  assert.equal((await sweepMfaPrompts()).processed,1)
  assert.equal(db.prepare('SELECT status FROM mfa_prompt_events WHERE log_event_id=?').get(eventId).status,'skipped')
  const promptId=crypto.randomUUID()
  db.prepare('INSERT INTO mfa_prompt_events(id,segment_id,target_node_id,log_event_id,source_ip,status,expires_at) VALUES(?,?,?,?,?,?,?)').run(promptId,segment.id,target.id,crypto.randomUUID(),'127.0.0.1','opened',new Date(Date.now()+120_000).toISOString())
  const prompt=(await auth(request.get(`/api/v1/segments/access/prompts/${promptId}`)).expect(200)).body
  assert.equal(prompt.segmentId,segment.id)
  await auth(request.post(`/api/v1/segments/${segment.id}/access`)).send({promptId,code:'123456'}).expect(409)
  db.prepare("UPDATE mfa_prompt_events SET status='consumed' WHERE id=?").run(promptId)
  const reused=await auth(request.post(`/api/v1/segments/${segment.id}/access`)).send({promptId,code:'123456'}).expect(409)
  assert.match(reused.body.error,/prompt is invalid or expired/)
})

test('administrator approved fail open uses a short audited grant only for an uncontrolled source',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@sync.test',password:'sync-test-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  await auth(request.patch('/api/v1/settings/mfa-prompt')).send({failureMode:'open',failOpenMinutes:3}).expect(400)
  await auth(request.patch('/api/v1/settings/mfa-prompt')).send({failureMode:'open',failOpenMinutes:3,approval:'ENABLE MFA FAIL OPEN'}).expect(200)
  const targetId=crypto.randomUUID(),segmentId=crypto.randomUUID(),credentialId=crypto.randomUUID(),eventId=crypto.randomUUID()
  db.prepare("INSERT INTO nodes(id,hostname,ip,transport,connection_mode,firewall_state) VALUES(?,?,?,'winrm','agentless','enforcing')").run(targetId,'fallback-target','192.0.2.210')
  db.prepare('INSERT INTO identity_segments(id,name,node_id,port,allowed_upns) VALUES(?,?,?,?,?)').run(segmentId,'Fallback RDP',targetId,3389,'["owner@sync.test"]')
  db.prepare("INSERT INTO credentials(id,name,type,username,encrypted_blob,owner_user_id,visibility,priority) VALUES(?,?,'domain',?,?,?,'private',100)").run(credentialId,'Fallback test','TEST\\operator',seal({password:'test-only'}),db.prepare('SELECT id FROM users WHERE email=?').get('owner@sync.test').id)
  db.prepare('INSERT INTO credential_assignments(credential_id,node_id) VALUES(?,?)').run(credentialId,targetId)
  const mock=path.join(dir,'mock-mfa-winrm')
  fs.writeFileSync(mock,`#!/usr/bin/env python3\nimport sys,json\nrequest=json.load(sys.stdin)\nprint(json.dumps({'jit_preflight':{'safe':True},'jit_start':{'active':True},'jit_end':{'revoked':True},'auth':'TEST\\\\operator'}.get(request['operation'])))\n`,{mode:0o755})
  const previous=process.env.WINRM_PYTHON
  process.env.WINRM_PYTHON=mock
  try{
    const target=db.prepare('SELECT * FROM nodes WHERE id=?').get(targetId)
    const result=await processBlockedMfaEvent({id:eventId,event_id:5157,action:'block',direction:'in',protocol:'TCP',src_ip:'192.0.2.111',src_port:51000,dst_ip:target.ip},db.prepare('SELECT * FROM identity_segments WHERE id=?').get(segmentId),target)
    assert.equal(result.status,'fallback_open')
    const grant=db.prepare('SELECT src_ip,dst_port,ttl_seconds,fallback_reason FROM jit_grants WHERE prompt_id=?').get(result.id)
    assert.equal(grant.src_ip,'192.0.2.111')
    assert.equal(grant.dst_port,3389)
    assert.equal(grant.ttl_seconds,180)
    assert.match(grant.fallback_reason,/not in managed or Active Directory inventory/)
    assert.equal(db.prepare("SELECT COUNT(*) count FROM audit_log WHERE action='mfa.prompt.fail_open' AND entity_id=?").get(result.grantId).count,1)
    const visible=(await auth(request.get('/api/v1/segments/access/grants')).expect(200)).body
    assert.equal(visible.some(item=>item.id===result.grantId&&item.fallback_reason),true)
    const adNodeId=crypto.randomUUID()
    db.prepare("INSERT INTO nodes(id,hostname,ip,transport,connection_mode,ad_guid,ad_enabled,ad_missing) VALUES(?,?,?,'winrm','agentless',?,1,0)").run(adNodeId,'directory-client','192.0.2.119',crypto.randomUUID())
    db.prepare("UPDATE directory_connections SET enabled=1,node_credential_id=? WHERE id='default'").run(credentialId)
    assert.equal(await remote(db.prepare('SELECT * FROM nodes WHERE id=?').get(adNodeId),'auth'),'TEST\\operator')
    for(let index=0;index<2;index++)db.prepare("INSERT INTO nodes(id,hostname,ip,transport,connection_mode) VALUES(?,?,?,'winrm','agentless')").run(crypto.randomUUID(),`duplicate-source-${index}`,'192.0.2.112')
    const ambiguous=await processBlockedMfaEvent({id:crypto.randomUUID(),event_id:5157,action:'block',direction:'in',protocol:'TCP',src_ip:'192.0.2.112',src_port:51001,dst_ip:target.ip},db.prepare('SELECT * FROM identity_segments WHERE id=?').get(segmentId),target)
    assert.equal(ambiguous.status,'skipped')
    assert.equal(db.prepare('SELECT COUNT(*) count FROM jit_grants WHERE prompt_id=?').get(ambiguous.id).count,0)
    const dnsNodeId=crypto.randomUUID()
    db.prepare("INSERT INTO nodes(id,hostname,fqdn,transport,connection_mode,ad_guid,ad_enabled,ad_missing) VALUES(?,?,'localhost','winrm','agentless',?,1,0)").run(dnsNodeId,'new-ad-client',crypto.randomUUID())
    const discovered=await processBlockedMfaEvent({id:crypto.randomUUID(),event_id:5157,action:'block',direction:'in',protocol:'TCP',src_ip:'127.0.0.1',src_port:51002,dst_ip:target.ip},db.prepare('SELECT * FROM identity_segments WHERE id=?').get(segmentId),target)
    assert.equal(db.prepare('SELECT source_node_id FROM mfa_prompt_events WHERE id=?').get(discovered.id).source_node_id,dnsNodeId)
    assert.equal(db.prepare('SELECT COUNT(*) count FROM jit_grants WHERE prompt_id=?').get(discovered.id).count,0)
    await auth(request.patch('/api/v1/settings/mfa-prompt')).send({failureMode:'closed',failOpenMinutes:3}).expect(200)
  }finally{
    db.prepare("UPDATE directory_connections SET enabled=0,node_credential_id=NULL WHERE id='default'").run()
    if(previous===undefined)delete process.env.WINRM_PYTHON;else process.env.WINRM_PYTHON=previous
    db.prepare("UPDATE app_settings SET value='closed' WHERE key='mfa_prompt_failure_mode'").run()
  }
})
