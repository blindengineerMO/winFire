import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import crypto from 'node:crypto'
import os from 'node:os'
import path from 'node:path'
import {createServer} from 'node:net'
import supertest from 'supertest'
import {compilePolicy,rulesConflict,validateAddressExpression,validatePortExpression,validateProgramPath} from '@winfire/shared'
import {normalizeWindowsEvent} from '../src/eventNormalizer.js'
import {parseSeceditRights} from '../src/logonRights.js'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@example.test'
process.env.BOOTSTRAP_PASSWORD='test-password-12345'
process.env.AUTH_RATE_LIMIT='100'
const {app}=await import('../src/app.js')
const {classifyVerification,findMatchingDenyEvent}=await import('../src/verifier.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {recordNodeSuccess,recordNodeTransportFailure,classifyProbe}=await import('../src/connector.js')
const {processDueTraining}=await import('../src/app.js')
const request=supertest(app)
await bootstrap()
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('policy compiler validates the graph and emits tagged rules',()=>{
  const graph={nodes:[{id:'a',type:'portGroup',data:{ports:'3389'}},{id:'b',type:'allow',data:{name:'RDP'}}],edges:[{id:'e',source:'a',target:'b'}]}
  const rules=compilePolicy(graph,'policy-1')
  assert.equal(rules.length,1)
  assert.equal(rules[0].localPort,'3389')
  assert.equal(rules[0].group,'WinFireSecure:policy-1')
  const scoped=compilePolicy({nodes:[{id:'addr',type:'addressGroup',data:{addresses:'192.0.2.0/24'}},{id:'profile',type:'profile',data:{profile:'Domain'}},{id:'scoped-rule',type:'allow',data:{name:'Scoped RDP',remoteAddress:'Any',profile:'Any'}}],edges:[{id:'addr-edge',source:'addr',target:'scoped-rule'},{id:'profile-edge',source:'profile',target:'scoped-rule'}]},'policy-scoped')
  assert.equal(scoped[0].remoteAddress,'192.0.2.0/24')
  assert.equal(scoped[0].profile,'Domain')
  assert.throws(()=>compilePolicy({nodes:graph.nodes,edges:[{id:'e1',source:'a',target:'b'},{id:'e2',source:'b',target:'a'}]},'policy-1'),/cycle/)
  assert.throws(()=>compilePolicy({nodes:[{id:'gate',type:'mfaGate',data:{localPort:'3389'}}],edges:[]},'policy-1'),/MFA Gate/)
  assert.throws(()=>compilePolicy({nodes:[{id:'timed',type:'schedule',data:{}}],edges:[]},'policy-1'),/Schedule nodes/)
  assert.throws(()=>compilePolicy({nodes:[{id:'unknown',type:'custom',data:{}}],edges:[]},'policy-1'),/Unsupported policy node type/)
  assert.throws(()=>compilePolicy({nodes:[graph.nodes[0],graph.nodes[0]],edges:[]},'policy-1'),/duplicate node IDs/)
  const outbound=compilePolicy({nodes:[{id:'ports',type:'portGroup',data:{ports:'443'}},{id:'outbound',type:'allow',data:{name:'HTTPS egress',direction:'out'}}],edges:[{id:'group',source:'ports',target:'outbound'}]},'policy-egress')
  assert.equal(outbound[0].localPort,'Any')
  assert.equal(outbound[0].remotePort,'443')
  assert.equal(rulesConflict({...outbound[0],action:'allow',remotePort:'443'},{...outbound[0],action:'block',remotePort:'3389'}),false)
  assert.equal(rulesConflict({...outbound[0],action:'allow',remotePort:'443'},{...outbound[0],action:'block',remotePort:'443'}),true)
})

test('OpenAPI lists registered control-plane and agent routes with their auth schemes',async()=>{
  const response=await request.get('/api/v1/openapi.json').expect(200)
  const spec=response.body
  assert.equal(spec.openapi,'3.1.0')
  assert.ok(Object.keys(spec.paths).length>60)
  assert.deepEqual(spec.paths['/nodes/{id}/firewall-rules'].get.security,[{bearerAuth:[]}])
  assert.deepEqual(spec.paths['/agents/{id}/events'].post.security,[{mutualTLS:[]}])
  assert.deepEqual(spec.paths['/agents/{id}/revoke'].post.security,[{bearerAuth:[]}])
  assert.ok(spec.paths['/policies/{id}/assignments/{assignmentId}'].delete.responses[202])
  assert.ok(spec.paths['/node-groups/{id}/members/{nodeId}'].delete.responses[200])
  assert.equal(spec.paths['/auth/login'].post.security,undefined)
  assert.equal(spec.paths['/auth/login'].post.requestBody.content['application/json'].schema.$ref,'#/components/schemas/LoginRequest')
})

test('policy fields reject invalid ports, addresses and program paths before apply',()=>{
  assert.equal(validatePortExpression('80,443,1000-2000'),true)
  assert.equal(validatePortExpression('2000-1000'),false)
  assert.equal(validateAddressExpression('192.0.2.0/24,2001:db8::/32'),true)
  assert.equal(validateAddressExpression('192.0.2.0/33'),false)
  assert.equal(validateAddressExpression('999.0.0.1'),false)
  assert.equal(validateProgramPath('C:\\Program Files\\Example\\app.exe'),true)
  assert.equal(validateProgramPath('app.exe'),false)
  assert.throws(()=>compilePolicy({nodes:[{id:'bad-address',type:'allow',data:{remoteAddress:'192.0.2.0/33'}}],edges:[]},'policy-invalid'),/Invalid remote address expression/)
  assert.throws(()=>compilePolicy({nodes:[{id:'bad-group',type:'addressGroup',data:{addresses:'999.0.0.1'}}],edges:[]},'policy-invalid'),/Invalid address group/)
  assert.throws(()=>compilePolicy({nodes:[{id:'bad-program',type:'program',data:{name:'Bad path',program:'app.exe'}}],edges:[]},'policy-invalid'),/absolute Windows program path/)
})

test('deny checks require managed-rule evidence',()=>{
  assert.equal(classifyVerification({action:'block'},'timeout',null).status,'inconclusive')
  assert.equal(classifyVerification({action:'block'},'refused',false).status,'inconclusive')
  assert.equal(classifyVerification({action:'block'},'timeout',true).status,'inconclusive')
  const event={record_id:44,event_id:5157,event_time:'2026-09-19T12:00:01.000Z',action:'block',direction:'in',protocol:'TCP',src_ip:'192.0.2.10',src_port:51234,dst_port:3389,filter_origin:'{WINFIRE-RULE}'}
  const probe={sourceIp:'192.0.2.10',sourcePort:51234}
  assert.equal(findMatchingDenyEvent([event],probe,3389,'2026-09-19T12:00:00.000Z','2026-09-19T12:00:02.000Z')?.record_id,44)
  assert.equal(findMatchingDenyEvent([{...event,event_time:'2026-09-19T11:55:00.000Z'}],probe,3389,'2026-09-19T12:00:00.000Z','2026-09-19T12:00:02.000Z',43)?.record_id,44)
  assert.equal(findMatchingDenyEvent([event],probe,3389,'2026-09-19T12:00:00.000Z','2026-09-19T12:00:02.000Z',44),null)
  assert.equal(classifyVerification({action:'block'},'timeout',true,event,'{WINFIRE-RULE}').status,'pass')
  assert.match(classifyVerification({action:'block'},'timeout',true,{...event,filter_origin:'Query User Default'},'{WINFIRE-RULE}').reason,/another filter/)
  assert.equal(classifyVerification({action:'block'},'timeout',true,{...event,filter_origin:null},'{WINFIRE-RULE}').status,'inconclusive')
  assert.equal(findMatchingDenyEvent([{...event,src_port:51235}],probe,3389,'2026-09-19T12:00:00.000Z','2026-09-19T12:00:02.000Z'),null)
  assert.equal(findMatchingDenyEvent([{...event,event_time:'2026-09-19T11:59:00.000Z'}],probe,3389,'2026-09-19T12:00:00.000Z','2026-09-19T12:00:02.000Z'),null)
  assert.equal(findMatchingDenyEvent([{...event,event_id:5156}],probe,3389,'2026-09-19T12:00:00.000Z','2026-09-19T12:00:02.000Z'),null)
  assert.equal(classifyVerification({action:'block'},'open',true).status,'fail')
})

test('Windows Security events retain firewall and logon meaning',()=>{
  const logon=normalizeWindowsEvent({RecordId:42,Id:4625,TimeCreated:'2026-09-19T12:00:00Z',Fields:{IpAddress:'10.2.3.4',IpPort:'49152',TargetUserSid:'S-1-5-21-123',LogonType:'10'}})
  assert.equal(logon.eventType,'logon')
  assert.equal(logon.action,'failure')
  assert.equal(logon.srcPort,49152)
  assert.equal(logon.accountSid,'S-1-5-21-123')
  const firewall=normalizeWindowsEvent({RecordId:43,Id:5157,Fields:{Protocol:'6',Direction:'%%14592',ProcessID:'4556',InterfaceIndex:'11',SourceAddress:'10.2.3.5',SourcePort:'49152',DestAddress:'10.2.3.4',DestPort:'3389',FilterOrigin:'{TEST-RULE}',FilterRTID:'123456789'}})
  assert.equal(firewall.processId,4556)
  assert.equal(firewall.eventType,'firewall')
  assert.equal(firewall.action,'block')
  assert.equal(firewall.protocol,'TCP')
  assert.equal(firewall.dstPort,3389)
  assert.equal(firewall.srcIp,'10.2.3.5')
  assert.equal(firewall.srcPort,49152)
  assert.equal(firewall.direction,'in')
  assert.equal(firewall.filterOrigin,'{TEST-RULE}')
  assert.equal(firewall.filterRuntimeId,'123456789')
  const legacy=normalizeWindowsEvent({RecordId:44,Id:5157,Fields:{Protocol:'6',Direction:'%%14592',SourceAddress:'10.2.3.4',SourcePort:'3389',DestAddress:'10.2.3.5',DestPort:'49152'}})
  assert.equal(legacy.srcIp,'10.2.3.5')
  assert.equal(legacy.srcPort,49152)
  assert.equal(legacy.dstPort,3389)
})

test('logon-rights export preserves allow and deny assignments by SID',()=>{
  const rights=parseSeceditRights([
    'SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11',
    'SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546',
    'SeNetworkLogonRight = *S-1-5-11'
  ])
  assert.deepEqual(rights,[
    {accountSid:'S-1-5-32-544',logonType:'Network',assignment:'allow'},
    {accountSid:'S-1-5-11',logonType:'Network',assignment:'allow'},
    {accountSid:'S-1-5-32-546',logonType:'RemoteInteractive',assignment:'deny'}
  ])
  assert.throws(()=>parseSeceditRights(['[Privilege Rights]']),/no usable account assignments/)
  assert.throws(()=>parseSeceditRights(['SeServiceLogonRight = PUCKNET\\service']),/unresolved account/)
})

test('authenticated RPC counts as reachable while retaining management evidence',()=>{
  assert.deepEqual(classifyProbe('wmi','srvinfo response'),{status:'reachable',probeStatus:'rpc-authenticated'})
  assert.deepEqual(classifyProbe('wmi',{error:'access denied'}),{status:'unverified',probeStatus:'rpc-unverified'})
  assert.deepEqual(classifyProbe('winrm',null,true),{status:'reachable',probeStatus:'winrm-authenticated'})
  assert.deepEqual(classifyProbe('winrms',null,true),{status:'reachable',probeStatus:'winrms-authenticated'})
  assert.deepEqual(classifyProbe('winrm',null),{status:'port-open',probeStatus:'port-open'})
  assert.deepEqual(classifyProbe(null,null),{status:'unreachable',probeStatus:'unreachable'})
})

test('repeated transport failures back off and a successful call restores node health',()=>{
  const nodeId=crypto.randomUUID()
  db.prepare('INSERT INTO nodes(id,hostname) VALUES(?,?)').run(nodeId,'health-test')
  for(let attempt=1;attempt<=3;attempt++){
    recordNodeTransportFailure(nodeId)
    const node=db.prepare('SELECT failures,status,next_retry_at FROM nodes WHERE id=?').get(nodeId)
    assert.equal(node.failures,attempt)
    assert.equal(node.status,attempt<3?'degraded':'unreachable')
    assert.ok(new Date(node.next_retry_at)>new Date())
  }
  recordNodeSuccess(nodeId)
  const restored=db.prepare('SELECT failures,status,next_retry_at,last_seen_at FROM nodes WHERE id=?').get(nodeId)
  assert.equal(restored.failures,0)
  assert.equal(restored.status,'reachable')
  assert.equal(restored.next_retry_at,null)
  assert.ok(restored.last_seen_at)
})

test('node edits clear stale facts and deletion protects managed or assigned hosts',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const created=await auth(request.post('/api/v1/nodes')).send({hostname:'editable-node',ip:'192.0.2.10'}).expect(201)
  const nodeId=created.body.id
  db.prepare('INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?)').run(nodeId,'{}',new Date().toISOString())
  await auth(request.patch(`/api/v1/nodes/${nodeId}`)).send({hostname:'renamed-node',ip:'192.0.2.11'}).expect(200)
  assert.equal(db.prepare('SELECT hostname,ip,status,transport FROM nodes WHERE id=?').get(nodeId).hostname,'renamed-node')
  assert.equal(db.prepare('SELECT node_id FROM node_facts WHERE node_id=?').get(nodeId),undefined)
  await auth(request.patch(`/api/v1/nodes/${nodeId}`)).send({ip:'not-an-ip'}).expect(400)
  db.prepare('UPDATE nodes SET ad_guid=? WHERE id=?').run(crypto.randomUUID(),nodeId)
  await auth(request.patch(`/api/v1/nodes/${nodeId}`)).send({hostname:'not-from-ad'}).expect(409)
  await auth(request.delete(`/api/v1/nodes/${nodeId}`)).expect(409)
  db.prepare('UPDATE nodes SET ad_guid=NULL WHERE id=?').run(nodeId)
  const policyId=crypto.randomUUID(),assignmentId=crypto.randomUUID()
  db.prepare('INSERT INTO policies(id,name) VALUES(?,?)').run(policyId,'Assigned policy')
  db.prepare('INSERT INTO policy_assignments(id,policy_id,node_id) VALUES(?,?,?)').run(assignmentId,policyId,nodeId)
  await auth(request.patch(`/api/v1/nodes/${nodeId}`)).send({ip:'192.0.2.12'}).expect(409)
  await auth(request.delete(`/api/v1/nodes/${nodeId}`)).expect(409)
  db.prepare('DELETE FROM policy_assignments WHERE id=?').run(assignmentId)
  const agentId=crypto.randomUUID()
  db.prepare('INSERT INTO agents(id,node_id,cert_thumbprint) VALUES(?,?,?)').run(agentId,nodeId,'test-thumbprint')
  await auth(request.delete(`/api/v1/nodes/${nodeId}`)).expect(409)
  db.prepare('UPDATE agents SET revoked_at=? WHERE id=?').run(new Date().toISOString(),agentId)
  await auth(request.delete(`/api/v1/nodes/${nodeId}`)).expect(204)
  assert.equal(db.prepare('SELECT id FROM nodes WHERE id=?').get(nodeId),undefined)
  assert.equal(db.prepare('SELECT id FROM learning_sessions WHERE node_id=?').get(nodeId),undefined)
  assert.equal(db.prepare('SELECT id FROM agents WHERE node_id=?').get(nodeId),undefined)
})

test('refresh tokens rotate once and reject replay',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const rotated=await request.post('/api/v1/auth/refresh').send({refreshToken:login.body.refreshToken}).expect(200)
  assert.notEqual(rotated.body.refreshToken,login.body.refreshToken)
  await request.post('/api/v1/auth/refresh').send({refreshToken:login.body.refreshToken}).expect(401)
  await request.post('/api/v1/auth/refresh').send({refreshToken:rotated.body.refreshToken}).expect(200)
})

test('admins cannot take over an owner and the last owner cannot be demoted',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const asOwner=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const admin=await asOwner(request.post('/api/v1/users')).send({email:'admin@example.test',password:'admin-password-12345',role:'admin'}).expect(201)
  const adminLogin=await request.post('/api/v1/auth/login').send({email:'admin@example.test',password:'admin-password-12345'}).expect(200)
  const asAdmin=req=>req.set('Authorization',`Bearer ${adminLogin.body.accessToken}`)
  await asAdmin(request.post('/api/v1/users')).send({email:'new-owner@example.test',password:'new-owner-password',role:'owner'}).expect(403)
  await asAdmin(request.patch(`/api/v1/users/${owner.body.user.id}`)).send({password:'changed-password-12345'}).expect(403)
  await asAdmin(request.patch(`/api/v1/users/${owner.body.user.id}/profile`)).send({email:'stolen@example.test'}).expect(403)
  await asAdmin(request.post(`/api/v1/users/${owner.body.user.id}/revoke-sessions`)).send({}).expect(403)
  await asOwner(request.patch(`/api/v1/users/${owner.body.user.id}`)).send({role:'admin'}).expect(400)
  assert.equal(admin.body.role,'admin')
})

test('an invitation creates a scoped user once without storing the token',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const asOwner=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const team=await asOwner(request.post('/api/v1/teams')).send({name:'Invite team'}).expect(201)
  const invite=await asOwner(request.post('/api/v1/invites')).send({email:'invited@example.test',role:'editor',teamId:team.body.id}).expect(201)
  assert.equal(invite.body.delivered,false)
  assert.ok(invite.body.inviteUrl.startsWith('/accept-invite?token='))
  const token=new URL(invite.body.inviteUrl,'http://localhost').searchParams.get('token')
  assert.ok(token)
  const accepted=await request.post('/api/v1/invites/accept').send({token,password:'invite-password-12345'}).expect(201)
  assert.equal(accepted.body.role,'editor')
  assert.equal(accepted.body.teamId,team.body.id)
  await request.post('/api/v1/invites/accept').send({token,password:'invite-password-12345'}).expect(400)
  assert.equal(db.prepare('SELECT email_verified FROM users WHERE id=?').get(accepted.body.id).email_verified,0)
  assert.equal(db.prepare('SELECT token_hash FROM invites WHERE id=?').get(invite.body.id).token_hash===token,false)
})

test('avatar upload validates image bytes and can be removed',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const userId=owner.body.user.id,asOwner=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const png='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/sN8AAAAASUVORK5CYII='
  await asOwner(request.put(`/api/v1/users/${userId}/avatar`)).send({mimeType:'image/jpeg',base64:png}).expect(400)
  const uploaded=await asOwner(request.put(`/api/v1/users/${userId}/avatar`)).send({mimeType:'image/png',base64:png}).expect(200)
  assert.ok(uploaded.body.avatarUrl.startsWith(`/api/v1/avatars/${userId}`))
  const fetched=await request.get(`/api/v1/avatars/${userId}`).expect(200)
  assert.equal(fetched.headers['content-type'],'image/png')
  assert.equal(fetched.body.subarray(0,8).toString('hex'),'89504e470d0a1a0a')
  await asOwner(request.delete(`/api/v1/users/${userId}/avatar`)).expect(204)
  await request.get(`/api/v1/avatars/${userId}`).expect(404)
})

test('team membership moves cleanly and team deletion clears references',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const user=await auth(request.post('/api/v1/users')).send({email:'team-member@example.test',password:'team-member-password',role:'auditor'}).expect(201)
  const first=await auth(request.post('/api/v1/teams')).send({name:'First team'}).expect(201)
  const second=await auth(request.post('/api/v1/teams')).send({name:'Second team'}).expect(201)
  await auth(request.patch(`/api/v1/teams/${first.body.id}`)).send({name:'Renamed team'}).expect(200)
  await auth(request.post(`/api/v1/teams/${first.body.id}/members`)).send({userId:user.body.id}).expect(200)
  await auth(request.post(`/api/v1/teams/${second.body.id}/members`)).send({userId:user.body.id}).expect(200)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM team_members WHERE user_id=?').get(user.body.id).n,1)
  assert.equal(db.prepare('SELECT team_id FROM users WHERE id=?').get(user.body.id).team_id,second.body.id)
  await auth(request.delete(`/api/v1/teams/${second.body.id}/members/${user.body.id}`)).expect(204)
  assert.equal(db.prepare('SELECT team_id FROM users WHERE id=?').get(user.body.id).team_id,null)
  await auth(request.post(`/api/v1/teams/${first.body.id}/members`)).send({userId:user.body.id}).expect(200)
  await auth(request.delete(`/api/v1/teams/${first.body.id}`)).expect(204)
  assert.equal(db.prepare('SELECT team_id FROM users WHERE id=?').get(user.body.id).team_id,null)
})

test('email changes require verification and invalidate existing sessions',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const user=await request.post('/api/v1/users').set('Authorization',`Bearer ${owner.body.accessToken}`).send({email:'email-old@example.test',password:'email-test-password',role:'auditor'}).expect(201)
  const login=await request.post('/api/v1/auth/login').send({email:'email-old@example.test',password:'email-test-password'}).expect(200)
  await request.patch(`/api/v1/users/${user.body.id}/profile`).set('Authorization',`Bearer ${login.body.accessToken}`).send({email:'email-new@example.test'}).expect(503)
  assert.equal(db.prepare('SELECT email FROM users WHERE id=?').get(user.body.id).email,'email-old@example.test')
  const token=crypto.randomBytes(32).toString('base64url')
  db.prepare('INSERT INTO email_verifications(id,user_id,new_email,token_hash,expires_at) VALUES(?,?,?,?,?)').run(crypto.randomUUID(),user.body.id,'email-new@example.test',crypto.createHash('sha256').update(token).digest('hex'),new Date(Date.now()+60_000).toISOString())
  const verified=await request.post('/api/v1/auth/verify-email').send({token}).expect(200)
  assert.equal(verified.body.email,'email-new@example.test')
  await request.post('/api/v1/auth/verify-email').send({token}).expect(400)
  await request.get('/api/v1/auth/me').set('Authorization',`Bearer ${login.body.accessToken}`).expect(401)
  await request.post('/api/v1/auth/login').send({email:'email-new@example.test',password:'email-test-password'}).expect(200)
})

test('learning proposals preserve traffic direction and require approval before application',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'learning-agent',ip:'127.0.0.1',connectionMode:'agent'}).expect(201)
  const agentId=crypto.randomUUID()
  db.prepare('INSERT INTO agents(id,node_id,cert_thumbprint,cert_expires_at,version) VALUES(?,?,?,?,?)').run(agentId,node.body.id,'TEST',new Date(Date.now()+864e5).toISOString(),'test')
  db.prepare('UPDATE nodes SET agent_id=? WHERE id=?').run(agentId,node.body.id)
  const started=await auth(request.post('/api/v1/learning-sessions')).send({nodeId:node.body.id,durationHours:24}).expect(201)
  assert.equal(started.body.mode,'manual')
  const insert=db.prepare('INSERT INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,dst_ip,dst_port,direction) VALUES(?,?,?,?,?,?,?,?,?,?)')
  insert.run(crypto.randomUUID(),node.body.id,1001,5156,'allow','TCP','10.0.0.5','192.0.2.10',443,'out')
  insert.run(crypto.randomUUID(),node.body.id,1002,5156,'allow','TCP','192.0.2.20','10.0.0.5',3389,'in')
  const timed=db.prepare('INSERT INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,event_time) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
  timed.run(crypto.randomUUID(),node.body.id,1003,5156,'allow','TCP','10.0.0.5','192.0.2.30',445,'out',new Date(Date.now()-864e5).toISOString())
  timed.run(crypto.randomUUID(),node.body.id,1004,5156,'allow','TCP','10.0.0.5','192.0.2.40',445,'out',new Date(Date.now()+48*36e5).toISOString())
  const proposal=await auth(request.post(`/api/v1/learning-sessions/${started.body.id}/finalize`)).send({}).expect(200)
  assert.equal(proposal.body.status,'review')
  assert.equal(proposal.body.ruleCount,2)
  assert.equal(db.prepare('SELECT firewall_state FROM nodes WHERE id=?').get(node.body.id).firewall_state,'review')
  const rules=JSON.parse(db.prepare('SELECT rules_compiled_json FROM policy_versions WHERE id=?').get(proposal.body.versionId).rules_compiled_json)
  assert.deepEqual(rules.map(rule=>[rule.direction,rule.localPort,rule.remotePort,rule.remoteAddress]).sort(),[['in','3389','Any','192.0.2.20'],['out','Any','443','192.0.2.10']])
  await auth(request.post(`/api/v1/policies/${proposal.body.policyId}/assignments`)).send({nodeId:node.body.id}).expect(409)
  const approved=await auth(request.post(`/api/v1/learning-sessions/${started.body.id}/approve`)).send({}).expect(200)
  assert.equal(approved.body.status,'applying')
  assert.equal(db.prepare('SELECT COUNT(*) n FROM agent_jobs WHERE agent_id=?').get(agentId).n,1)
  await auth(request.post(`/api/v1/learning-sessions/${started.body.id}/approve`)).send({}).expect(409)
})

test('new hosts train automatically, then retraining adds only unseen allow rules',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  await auth(request.patch('/api/v1/settings/training')).send({newHostTrainingDays:7}).expect(200)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'automatic-training',ip:'127.0.0.1',connectionMode:'agent'}).expect(201)
  assert.equal(node.body.firewall_state,'learning')
  assert.equal(node.body.training.mode,'auto')
  assert.ok(Math.abs(Date.parse(node.body.training.endsAt)-Date.now()-7*864e5)<60_000)
  const agentId=crypto.randomUUID()
  db.prepare('INSERT INTO agents(id,node_id,cert_thumbprint,cert_expires_at,version,last_checkin_at) VALUES(?,?,?,?,?,?)').run(agentId,node.body.id,'TRAINING-TEST',new Date(Date.now()+864e5).toISOString(),'test',new Date().toISOString())
  db.prepare('UPDATE nodes SET agent_id=? WHERE id=?').run(agentId,node.body.id)
  const firstId=node.body.training.id
  db.prepare('UPDATE learning_sessions SET started_at=?,ends_at=? WHERE id=?').run(new Date(Date.now()-60_000).toISOString(),new Date(Date.now()-1000).toISOString(),firstId)
  const event=db.prepare('INSERT INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,event_time) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
  event.run(crypto.randomUUID(),node.body.id,2001,5156,'allow','TCP','192.0.2.10','127.0.0.1',3389,'in',new Date(Date.now()-30_000).toISOString())
  const firstSweep=await processDueTraining()
  assert.ok(firstSweep.some(result=>result.sessionId===firstId&&result.status==='applying'))
  const first=db.prepare('SELECT * FROM learning_sessions WHERE id=?').get(firstId)
  assert.equal(first.status,'applying')
  assert.equal(db.prepare('SELECT COUNT(*) n FROM policy_assignments WHERE policy_id=? AND node_id=?').get(first.generated_policy_id,node.body.id).n,1)
  db.prepare("UPDATE learning_sessions SET status='enforced' WHERE id=?").run(firstId)
  db.prepare("UPDATE nodes SET firewall_state='enforcing' WHERE id=?").run(node.body.id)
  const retry=await auth(request.post(`/api/v1/nodes/${node.body.id}/training`)).send({durationDays:2}).expect(201)
  assert.equal(retry.body.mode,'auto')
  await auth(request.post(`/api/v1/nodes/${node.body.id}/training`)).send({durationDays:2}).expect(409)
  db.prepare('UPDATE learning_sessions SET started_at=?,ends_at=? WHERE id=?').run(new Date(Date.now()-60_000).toISOString(),new Date(Date.now()-1000).toISOString(),retry.body.id)
  event.run(crypto.randomUUID(),node.body.id,2002,5156,'allow','TCP','192.0.2.10','127.0.0.1',3389,'in',new Date(Date.now()-30_000).toISOString())
  event.run(crypto.randomUUID(),node.body.id,2003,5156,'allow','TCP','127.0.0.1','192.0.2.20',443,'out',new Date(Date.now()-30_000).toISOString())
  const secondSweep=await processDueTraining()
  assert.ok(secondSweep.some(result=>result.sessionId===retry.body.id&&result.status==='applying'))
  const second=db.prepare('SELECT * FROM learning_sessions WHERE id=?').get(retry.body.id)
  assert.equal(second.generated_policy_id,first.generated_policy_id)
  const rules=JSON.parse(db.prepare('SELECT v.rules_compiled_json FROM policy_versions v JOIN policies p ON p.current_version_id=v.id WHERE p.id=?').get(second.generated_policy_id).rules_compiled_json)
  assert.deepEqual(rules.map(rule=>[rule.direction,rule.remotePort,rule.remoteAddress]),[['in','Any','192.0.2.10'],['out','443','192.0.2.20']])
  assert.equal(db.prepare('SELECT COUNT(*) n FROM policy_assignments WHERE node_id=? AND policy_id=?').get(node.body.id,first.generated_policy_id).n,1)
  await auth(request.patch('/api/v1/settings/training')).send({newHostTrainingDays:30}).expect(200)
})

test('automatic training remains pending without a working log transport and ends cleanly with no traffic',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const unreachable=await auth(request.post('/api/v1/nodes')).send({hostname:'unprobed-training',ip:'127.0.0.1'}).expect(201)
  db.prepare('UPDATE learning_sessions SET ends_at=? WHERE id=?').run(new Date(Date.now()-1000).toISOString(),unreachable.body.training.id)
  const failed=await processDueTraining()
  assert.ok(failed.some(result=>result.sessionId===unreachable.body.training.id&&result.status==='failed'))
  const pending=db.prepare('SELECT status,last_error FROM learning_sessions WHERE id=?').get(unreachable.body.training.id)
  assert.equal(pending.status,'active')
  assert.match(pending.last_error,/No working event collection transport/)
  const agentNode=await auth(request.post('/api/v1/nodes')).send({hostname:'quiet-training',connectionMode:'agent'}).expect(201)
  db.prepare('UPDATE learning_sessions SET ends_at=? WHERE id=?').run(new Date(Date.now()-1000).toISOString(),agentNode.body.training.id)
  const offline=await processDueTraining()
  assert.ok(offline.some(result=>result.sessionId===agentNode.body.training.id&&result.status==='failed'))
  assert.match(db.prepare('SELECT last_error FROM learning_sessions WHERE id=?').get(agentNode.body.training.id).last_error,/Agent is not online/)
  const agentId=crypto.randomUUID()
  db.prepare('INSERT INTO agents(id,node_id,cert_thumbprint,cert_expires_at,version,last_checkin_at) VALUES(?,?,?,?,?,?)').run(agentId,agentNode.body.id,'QUIET-TEST',new Date(Date.now()+864e5).toISOString(),'test',new Date().toISOString())
  db.prepare('UPDATE nodes SET agent_id=? WHERE id=?').run(agentId,agentNode.body.id)
  db.prepare('UPDATE learning_sessions SET last_attempt_at=NULL WHERE id=?').run(agentNode.body.training.id)
  const quiet=await processDueTraining()
  assert.ok(quiet.some(result=>result.sessionId===agentNode.body.training.id&&result.status==='applying'))
  assert.equal(db.prepare('SELECT firewall_state FROM nodes WHERE id=?').get(agentNode.body.id).firewall_state,'applying')
  assert.equal(db.prepare('SELECT COUNT(*) n FROM policy_assignments WHERE node_id=?').get(agentNode.body.id).n,1)
  assert.equal(db.prepare("SELECT COUNT(*) n FROM agent_jobs WHERE agent_id=? AND type='policy.apply'").get(agentId).n,1)
})

test('due WinRM training collects logs, applies learned rules, and marks the host enforced',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Training transport',type:'local',username:'training-user',password:'transport-test-password'}).expect(201)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'training-winrm',ip:'127.0.0.1',credentialIds:[credential.body.id]}).expect(201)
  db.prepare("UPDATE nodes SET transport='winrm' WHERE id=?").run(node.body.id)
  db.prepare('UPDATE learning_sessions SET started_at=?,ends_at=? WHERE id=?').run(new Date(Date.now()-60_000).toISOString(),new Date(Date.now()-1000).toISOString(),node.body.training.id)
  db.prepare('INSERT INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,event_time) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(crypto.randomUUID(),node.body.id,3001,5156,'allow','TCP','192.0.2.50','127.0.0.1',8443,'in',new Date(Date.now()-30_000).toISOString())
  const stub=path.join(dir,'training-transport')
  const rulesFile=path.join(dir,'training-rules.json')
  fs.writeFileSync(stub,`#!/usr/bin/env node
const fs=require('fs');let text='';process.stdin.on('data',part=>text+=part);process.stdin.on('end',()=>{const input=JSON.parse(text);const file=process.env.WINFIRE_TEST_RULES_FILE;const existing=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):[];let result;if(input.operation==='audit_policy'){const enabled=process.env.WINFIRE_TEST_AUDIT_DISABLED!=='1'||fs.existsSync(file+'.audit');result={settingValue:enabled?3:0,successEnabled:enabled,failureEnabled:enabled}}else if(input.operation==='audit_policy_enable'){if(process.env.WINFIRE_TEST_AUDIT_ENABLE_FAIL==='1')process.exit(1);fs.writeFileSync(file+'.audit','enabled');result={settingValue:3,successEnabled:true,failureEnabled:true}}else if(input.operation==='events')result=[];else if(input.operation==='rules')result=existing.filter(rule=>rule.group===input.args.group);else if(input.operation==='apply'){const remove=new Set(input.args.remove);const next=existing.filter(rule=>!remove.has(rule.name)).concat(input.args.add);fs.writeFileSync(file,JSON.stringify(next));result={applied:true}}else throw Error('Unexpected operation');process.stdout.write(JSON.stringify(result))})
`,{mode:0o700})
  const priorPython=process.env.WINRM_PYTHON,priorRules=process.env.WINFIRE_TEST_RULES_FILE
  process.env.WINRM_PYTHON=stub;process.env.WINFIRE_TEST_RULES_FILE=rulesFile
  try {
    process.env.WINFIRE_TEST_AUDIT_DISABLED='1'
    assert.equal((await auth(request.get(`/api/v1/nodes/${node.body.id}/audit-policy`)).expect(200)).body.successEnabled,false)
    const blocked=await processDueTraining()
    assert.ok(blocked.some(result=>result.sessionId===node.body.training.id&&result.status==='failed'))
    assert.match(db.prepare('SELECT last_error FROM learning_sessions WHERE id=?').get(node.body.training.id).last_error,/success auditing is disabled/)
    assert.equal(db.prepare('SELECT status FROM learning_sessions WHERE id=?').get(node.body.training.id).status,'active')
    await auth(request.post(`/api/v1/nodes/${node.body.id}/audit-policy/enable`)).send({confirmation:'yes'}).expect(400)
    process.env.WINFIRE_TEST_AUDIT_ENABLE_FAIL='1'
    await auth(request.post(`/api/v1/nodes/${node.body.id}/audit-policy/enable`)).send({confirmation:'ENABLE WFP AUDITING'}).expect(500)
    assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action='node.audit-policy.enable.failed' AND entity_id=?").get(node.body.id).n,1)
    assert.equal(db.prepare("SELECT status FROM policy_apply_runs WHERE node_id=? AND policy_id IS NULL ORDER BY rowid DESC LIMIT 1").get(node.body.id).status,'failed')
    delete process.env.WINFIRE_TEST_AUDIT_ENABLE_FAIL
    const enabled=await auth(request.post(`/api/v1/nodes/${node.body.id}/audit-policy/enable`)).send({confirmation:'ENABLE WFP AUDITING'}).expect(200)
    assert.equal(enabled.body.successEnabled,true)
    assert.equal((await auth(request.get(`/api/v1/nodes/${node.body.id}/audit-policy`)).expect(200)).body.failureEnabled,true)
    assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action='node.audit-policy.enable' AND entity_id=?").get(node.body.id).n,1)
    assert.equal(db.prepare("SELECT status FROM policy_apply_runs WHERE node_id=? AND policy_id IS NULL ORDER BY rowid DESC LIMIT 1").get(node.body.id).status,'success')
    delete process.env.WINFIRE_TEST_AUDIT_DISABLED
    db.prepare('UPDATE learning_sessions SET last_attempt_at=NULL WHERE id=?').run(node.body.training.id)
    const results=await processDueTraining()
    assert.ok(results.some(result=>result.sessionId===node.body.training.id&&result.status==='enforced'))
    assert.equal(db.prepare('SELECT firewall_state FROM nodes WHERE id=?').get(node.body.id).firewall_state,'enforcing')
    const rules=JSON.parse(fs.readFileSync(rulesFile,'utf8'))
    assert.deepEqual(rules.map(rule=>[rule.direction,rule.localPort,rule.remoteAddress]),[['in','8443','192.0.2.50']])
    assert.equal(db.prepare('SELECT status FROM policy_apply_runs WHERE node_id=? ORDER BY started_at DESC LIMIT 1').get(node.body.id).status,'success')
  } finally {
    delete process.env.WINFIRE_TEST_AUDIT_DISABLED
    delete process.env.WINFIRE_TEST_AUDIT_ENABLE_FAIL
    if(priorPython===undefined)delete process.env.WINRM_PYTHON;else process.env.WINRM_PYTHON=priorPython
    if(priorRules===undefined)delete process.env.WINFIRE_TEST_RULES_FILE;else process.env.WINFIRE_TEST_RULES_FILE=priorRules
  }
})

test('group policy assignments count in coverage and compliance',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'group-coverage',ip:'127.0.0.1'}).expect(201)
  const group=await auth(request.post('/api/v1/node-groups')).send({name:'Coverage group'}).expect(201)
  await auth(request.post(`/api/v1/node-groups/${group.body.id}/members`)).send({nodeId:node.body.id}).expect(200)
  const policy=await auth(request.post('/api/v1/policies')).send({name:'Group coverage policy'}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph:{nodes:[{id:'group-rule',type:'allow',data:{name:'HTTPS',localPort:'443'}}],edges:[]}}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/assignments`)).send({nodeGroupId:group.body.id}).expect(201)
  const coverage=await auth(request.get('/api/v1/reports/coverage')).expect(200)
  const compliance=await auth(request.get('/api/v1/reports/compliance')).expect(200)
  assert.equal(coverage.body.find(row=>row.id===node.body.id).policy_count,1)
  assert.equal(compliance.body.find(row=>row.hostname==='group-coverage').policies,1)
  assert.equal((await auth(request.get(`/api/v1/nodes/${node.body.id}`)).expect(200)).body.groups.some(item=>item.id===group.body.id),true)
})

test('group member removal retains membership until its managed rules are cleared',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Member removal transport',type:'local',username:'cleanup-user',password:'transport-test-password'}).expect(201)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'member-cleanup',ip:'127.0.0.1',credentialIds:[credential.body.id]}).expect(201)
  const group=await auth(request.post('/api/v1/node-groups')).send({name:'Member cleanup group'}).expect(201)
  await auth(request.post(`/api/v1/node-groups/${group.body.id}/members`)).send({nodeId:node.body.id}).expect(200)
  const policy=await auth(request.post('/api/v1/policies')).send({name:'Member cleanup policy'}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph:{nodes:[{id:'rule',type:'allow',data:{name:'HTTPS',localPort:'443'}}],edges:[]}}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/assignments`)).send({nodeGroupId:group.body.id}).expect(201)
  const rule={name:'HTTPS',group:`WinFireSecure:${policy.body.id}`,action:'allow',direction:'in',protocol:'TCP',localPort:'443',remotePort:'Any',remoteAddress:'Any',program:'Any',profile:'Any'}
  const rulesFile=path.join(dir,'member-removal-rules.json'),stub=path.join(dir,'member-removal-transport')
  fs.writeFileSync(rulesFile,JSON.stringify([rule]))
  fs.writeFileSync(stub,`#!/usr/bin/env node
const fs=require('fs');let text='';process.stdin.on('data',part=>text+=part);process.stdin.on('end',()=>{const input=JSON.parse(text),file=process.env.WINFIRE_TEST_RULES_FILE,existing=JSON.parse(fs.readFileSync(file,'utf8'));if(input.operation==='rules')return process.stdout.write(JSON.stringify(existing.filter(rule=>rule.group===input.args.group)));if(input.operation!=='apply')throw Error('Unexpected operation');if(process.env.WINFIRE_TEST_APPLY_FAIL==='1')throw Error('simulated cleanup failure');const remove=new Set(input.args.remove);fs.writeFileSync(file,JSON.stringify(existing.filter(rule=>!remove.has(rule.name)).concat(input.args.add)));process.stdout.write('{}')})
`,{mode:0o700})
  const priorPython=process.env.WINRM_PYTHON,priorRules=process.env.WINFIRE_TEST_RULES_FILE
  process.env.WINRM_PYTHON=stub;process.env.WINFIRE_TEST_RULES_FILE=rulesFile
  db.prepare("UPDATE nodes SET transport='winrm' WHERE id=?").run(node.body.id)
  try {
    process.env.WINFIRE_TEST_APPLY_FAIL='1'
    await auth(request.delete(`/api/v1/node-groups/${group.body.id}/members/${node.body.id}`)).expect(502)
    assert.equal(db.prepare('SELECT COUNT(*) n FROM node_group_members WHERE group_id=? AND node_id=?').get(group.body.id,node.body.id).n,1)
    delete process.env.WINFIRE_TEST_APPLY_FAIL
    const removed=await auth(request.delete(`/api/v1/node-groups/${group.body.id}/members/${node.body.id}`)).expect(200)
    assert.deepEqual(removed.body.cleanedPolicies,[policy.body.id])
    assert.equal(db.prepare('SELECT COUNT(*) n FROM node_group_members WHERE group_id=? AND node_id=?').get(group.body.id,node.body.id).n,0)
    assert.deepEqual(JSON.parse(fs.readFileSync(rulesFile,'utf8')),[])
  } finally {
    delete process.env.WINFIRE_TEST_APPLY_FAIL
    if(priorPython===undefined)delete process.env.WINRM_PYTHON;else process.env.WINRM_PYTHON=priorPython
    if(priorRules===undefined)delete process.env.WINFIRE_TEST_RULES_FILE;else process.env.WINFIRE_TEST_RULES_FILE=priorRules
  }
})

test('policy unassignment removes managed rules only after successful cleanup',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Removal transport',type:'local',username:'cleanup-user',password:'transport-test-password'}).expect(201)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'cleanup-winrm',ip:'127.0.0.1',credentialIds:[credential.body.id]}).expect(201)
  const policy=await auth(request.post('/api/v1/policies')).send({name:'Removal policy'}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph:{nodes:[{id:'cleanup-rule',type:'allow',data:{name:'HTTPS',localPort:'443'}}],edges:[]}}).expect(201)
  const assignment=await auth(request.post(`/api/v1/policies/${policy.body.id}/assignments`)).send({nodeId:node.body.id}).expect(201)
  const rule={name:'HTTPS',group:`WinFireSecure:${policy.body.id}`,action:'allow',direction:'in',protocol:'TCP',localPort:'443',remotePort:'Any',remoteAddress:'Any',program:'Any',profile:'Any'}
  const rulesFile=path.join(dir,'removal-rules.json'),stub=path.join(dir,'removal-transport')
  fs.writeFileSync(rulesFile,JSON.stringify([rule]))
  fs.writeFileSync(stub,`#!/usr/bin/env node
const fs=require('fs');let text='';process.stdin.on('data',part=>text+=part);process.stdin.on('end',()=>{const input=JSON.parse(text),file=process.env.WINFIRE_TEST_RULES_FILE,existing=JSON.parse(fs.readFileSync(file,'utf8'));if(input.operation==='rules')process.stdout.write(JSON.stringify(existing.filter(rule=>rule.group===input.args.group)));else if(input.operation==='apply'){if(process.env.WINFIRE_TEST_APPLY_FAIL==='1')throw Error('simulated apply failure');const remove=new Set(input.args.remove);fs.writeFileSync(file,JSON.stringify(existing.filter(rule=>!remove.has(rule.name)).concat(input.args.add)));process.stdout.write('{}')}else throw Error('Unexpected operation')})
`,{mode:0o700})
  const priorPython=process.env.WINRM_PYTHON,priorRules=process.env.WINFIRE_TEST_RULES_FILE
  process.env.WINRM_PYTHON=stub;process.env.WINFIRE_TEST_RULES_FILE=rulesFile
  db.prepare("UPDATE nodes SET transport='winrm' WHERE id=?").run(node.body.id)
  try {
    process.env.WINFIRE_TEST_APPLY_FAIL='1'
    await auth(request.delete(`/api/v1/policies/${policy.body.id}/assignments/${assignment.body.id}`)).expect(502)
    assert.equal(db.prepare('SELECT COUNT(*) n FROM policy_assignments WHERE id=?').get(assignment.body.id).n,1)
    assert.equal(JSON.parse(fs.readFileSync(rulesFile,'utf8')).length,1)
    delete process.env.WINFIRE_TEST_APPLY_FAIL
    const result=await auth(request.delete(`/api/v1/policies/${policy.body.id}/assignments/${assignment.body.id}`)).expect(200)
    assert.deepEqual(result.body.cleanedNodes,[node.body.id])
    assert.equal(db.prepare('SELECT COUNT(*) n FROM policy_assignments WHERE id=?').get(assignment.body.id).n,0)
    assert.deepEqual(JSON.parse(fs.readFileSync(rulesFile,'utf8')),[])
    assert.equal(db.prepare('SELECT status FROM policy_apply_runs WHERE policy_id=? AND node_id=? ORDER BY rowid DESC LIMIT 1').get(policy.body.id,node.body.id).status,'success')
  } finally {
    delete process.env.WINFIRE_TEST_APPLY_FAIL
    if(priorPython===undefined)delete process.env.WINRM_PYTHON;else process.env.WINRM_PYTHON=priorPython
    if(priorRules===undefined)delete process.env.WINFIRE_TEST_RULES_FILE;else process.env.WINFIRE_TEST_RULES_FILE=priorRules
  }
})

test('unassignment retains rules covered by another assignment and blocks agent cleanup',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'overlap-agent',connectionMode:'agent'}).expect(201)
  const group=await auth(request.post('/api/v1/node-groups')).send({name:'Overlap group'}).expect(201)
  await auth(request.post(`/api/v1/node-groups/${group.body.id}/members`)).send({nodeId:node.body.id}).expect(200)
  const policy=await auth(request.post('/api/v1/policies')).send({name:'Overlap policy'}).expect(201)
  const direct=await auth(request.post(`/api/v1/policies/${policy.body.id}/assignments`)).send({nodeId:node.body.id}).expect(201)
  const grouped=await auth(request.post(`/api/v1/policies/${policy.body.id}/assignments`)).send({nodeGroupId:group.body.id}).expect(201)
  const safe=await auth(request.delete(`/api/v1/policies/${policy.body.id}/assignments/${direct.body.id}`)).expect(200)
  assert.deepEqual(safe.body.cleanedNodes,[])
  assert.equal(safe.body.retainedByOtherAssignment,1)
  await auth(request.delete(`/api/v1/policies/${policy.body.id}/assignments/${grouped.body.id}`)).expect(409)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM policy_assignments WHERE id=?').get(grouped.body.id).n,1)
})

test('group unassignment restores earlier hosts when a later host fails',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Group cleanup transport',type:'local',username:'cleanup-user',password:'transport-test-password'}).expect(201)
  const first=await auth(request.post('/api/v1/nodes')).send({hostname:'cleanup-first',ip:'127.0.0.1',credentialIds:[credential.body.id]}).expect(201)
  const second=await auth(request.post('/api/v1/nodes')).send({hostname:'cleanup-second',ip:'127.0.0.2',credentialIds:[credential.body.id]}).expect(201)
  const group=await auth(request.post('/api/v1/node-groups')).send({name:'Cleanup rollback group'}).expect(201)
  for(const node of [first,second]){
    await auth(request.post(`/api/v1/node-groups/${group.body.id}/members`)).send({nodeId:node.body.id}).expect(200)
    db.prepare("UPDATE nodes SET transport='winrm' WHERE id=?").run(node.body.id)
  }
  const policy=await auth(request.post('/api/v1/policies')).send({name:'Group cleanup rollback'}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph:{nodes:[{id:'rule',type:'allow',data:{name:'HTTPS',localPort:'443'}}],edges:[]}}).expect(201)
  const assignment=await auth(request.post(`/api/v1/policies/${policy.body.id}/assignments`)).send({nodeGroupId:group.body.id}).expect(201)
  const rule={name:'HTTPS',group:`WinFireSecure:${policy.body.id}`,action:'allow',direction:'in',protocol:'TCP',localPort:'443',remotePort:'Any',remoteAddress:'Any',program:'Any',profile:'Any'}
  const stateFile=path.join(dir,'group-removal-state.json'),stub=path.join(dir,'group-removal-transport')
  fs.writeFileSync(stateFile,JSON.stringify({hosts:{'127.0.0.1':[rule],'127.0.0.2':[rule]},applyCount:0}))
  fs.writeFileSync(stub,`#!/usr/bin/env node
const fs=require('fs');let text='';process.stdin.on('data',part=>text+=part);process.stdin.on('end',()=>{const input=JSON.parse(text),file=process.env.WINFIRE_TEST_RULES_FILE,state=JSON.parse(fs.readFileSync(file,'utf8')),old=state.hosts[input.host]||[];if(input.operation==='rules')return process.stdout.write(JSON.stringify(old.filter(rule=>rule.group===input.args.group)));if(input.operation!=='apply')throw Error('Unexpected operation');state.applyCount++;fs.writeFileSync(file,JSON.stringify(state));if(state.applyCount===2)throw Error('simulated second-host failure');const remove=new Set(input.args.remove);state.hosts[input.host]=old.filter(rule=>!remove.has(rule.name)).concat(input.args.add);fs.writeFileSync(file,JSON.stringify(state));process.stdout.write('{}')})
`,{mode:0o700})
  const priorPython=process.env.WINRM_PYTHON,priorRules=process.env.WINFIRE_TEST_RULES_FILE
  process.env.WINRM_PYTHON=stub;process.env.WINFIRE_TEST_RULES_FILE=stateFile
  try{
    const result=await auth(request.delete(`/api/v1/policies/${policy.body.id}/assignments/${assignment.body.id}`)).expect(502)
    assert.match(result.body.error,/cleanup failed/i)
    assert.equal(db.prepare('SELECT COUNT(*) n FROM policy_assignments WHERE id=?').get(assignment.body.id).n,1)
    const state=JSON.parse(fs.readFileSync(stateFile,'utf8'))
    assert.equal(state.applyCount,3)
    assert.deepEqual(state.hosts['127.0.0.1'],[rule])
    assert.deepEqual(state.hosts['127.0.0.2'],[rule])
  } finally {
    if(priorPython===undefined)delete process.env.WINRM_PYTHON;else process.env.WINRM_PYTHON=priorPython
    if(priorRules===undefined)delete process.env.WINFIRE_TEST_RULES_FILE;else process.env.WINFIRE_TEST_RULES_FILE=priorRules
  }
})

test('drift checks record unknown agent state and appear in coverage',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'drift-agent',ip:'127.0.0.1',connectionMode:'agent'}).expect(201)
  const policy=await auth(request.post('/api/v1/policies')).send({name:'Drift test policy'}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph:{nodes:[{id:'drift-rule',type:'allow',data:{name:'HTTPS',localPort:'443'}}],edges:[]}}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/assignments`)).send({nodeId:node.body.id}).expect(201)
  const checked=await auth(request.post('/api/v1/drift/checks')).send({nodeId:node.body.id,policyId:policy.body.id}).expect(201)
  assert.equal(checked.body.checks.length,1)
  assert.equal(checked.body.checks[0].status,'unknown')
  assert.match(checked.body.checks[0].error,/firewall readback/)
  const listing=await auth(request.get(`/api/v1/drift/checks?nodeId=${node.body.id}`)).expect(200)
  assert.equal(listing.body[0].status,'unknown')
  const coverage=await auth(request.get('/api/v1/reports/coverage')).expect(200)
  assert.equal(coverage.body.find(row=>row.id===node.body.id).drift_status,'unknown')
})

test('policy assignment rejects overlapping opposite rules',async()=>{
  assert.equal(rulesConflict({action:'allow',direction:'in',protocol:'TCP',localPort:'3300-3400',remoteAddress:'Any',program:'Any',profile:'Any'},{action:'block',direction:'in',protocol:'TCP',localPort:'3389',remoteAddress:'Any',program:'Any',profile:'Any'}),true)
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'conflict-local',ip:'127.0.0.1'}).expect(201)
  const allow=await auth(request.post('/api/v1/policies')).send({name:'Allow conflict test'}).expect(201)
  const block=await auth(request.post('/api/v1/policies')).send({name:'Block conflict test'}).expect(201)
  for(const [policy,type] of [[allow,'allow'],[block,'deny']])await auth(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph:{nodes:[{id:'rule',type,data:{name:'RDP',localPort:'3389'}}],edges:[]}}).expect(201)
  await auth(request.post(`/api/v1/policies/${allow.body.id}/assignments`)).send({nodeId:node.body.id}).expect(201)
  const response=await auth(request.post(`/api/v1/policies/${block.body.id}/assignments`)).send({nodeId:node.body.id}).expect(409)
  assert.equal(response.body.conflicts[0].otherPolicyId,allow.body.id)
})

test('verifier records real TCP evidence and reports it',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const listener=createServer(socket=>socket.end())
  await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve))
  const port=listener.address().port
  try {
    const node=await auth(request.post('/api/v1/nodes')).send({hostname:'verifier-local',ip:'127.0.0.1'}).expect(201)
    const policy=await auth(request.post('/api/v1/policies')).send({name:'Verifier local'}).expect(201)
    await auth(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph:{nodes:[{id:'allow-local',type:'allow',data:{name:'Test listener',localPort:String(port)}}],edges:[]}}).expect(201)
    await auth(request.post(`/api/v1/policies/${policy.body.id}/assignments`)).send({nodeId:node.body.id}).expect(201)
    const verify=await auth(request.post('/api/v1/verifier/runs')).send({nodeId:node.body.id,policyId:policy.body.id}).expect(201)
    assert.equal(verify.body.results[0].status,'pass')
    assert.equal(verify.body.results[0].probeStatus,'open')
    assert.equal(verify.body.results[0].probeSourceIp,'127.0.0.1')
    assert.ok(verify.body.results[0].probeSourcePort>0)
    assert.equal(db.prepare('SELECT probe_source_ip,probe_source_port FROM verifier_results WHERE id=?').get(verify.body.results[0].id).probe_source_port,verify.body.results[0].probeSourcePort)
    const report=await auth(request.get('/api/v1/reports/verification')).expect(200)
    assert.equal(report.body.find(row=>row.policy==='Verifier local').status,'pass')
  } finally {await new Promise(resolve=>listener.close(resolve))}
})

test('verifier can probe from a managed peer and records its vantage',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Verifier peer credential',type:'local',username:'peer-user',password:'peer-password-12345'}).expect(201)
  const peer=await auth(request.post('/api/v1/nodes')).send({hostname:'verifier-peer',ip:'127.0.0.2',credentialIds:[credential.body.id]}).expect(201)
  const target=await auth(request.post('/api/v1/nodes')).send({hostname:'verifier-target',ip:'127.0.0.3'}).expect(201)
  db.prepare("UPDATE nodes SET transport='winrm' WHERE id=?").run(peer.body.id)
  const policy=await auth(request.post('/api/v1/policies')).send({name:'Peer vantage policy'}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph:{nodes:[{id:'peer-rule',type:'allow',data:{name:'Peer path',localPort:'12345'}}],edges:[]}}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/assignments`)).send({nodeId:target.body.id}).expect(201)
  const stub=path.join(dir,'verifier-peer-transport')
  fs.writeFileSync(stub,`#!/usr/bin/env node
let input='';process.stdin.on('data',part=>input+=part);process.stdin.on('end',()=>{const request=JSON.parse(input);if(request.operation!=='tcp_probe'||request.args.host!=='127.0.0.3'||request.args.port!==12345)process.exit(2);process.stdout.write(JSON.stringify({status:'open',latencyMs:4}))})
`,{mode:0o700})
  const priorPython=process.env.WINRM_PYTHON
  process.env.WINRM_PYTHON=stub
  try{
    await auth(request.post('/api/v1/verifier/runs')).send({policyId:policy.body.id,vantageNodeId:'missing-peer'}).expect(404)
    const result=await auth(request.post('/api/v1/verifier/runs')).send({policyId:policy.body.id,nodeId:target.body.id,vantageNodeId:peer.body.id}).expect(201)
    assert.equal(result.body.results[0].status,'pass')
    assert.equal(result.body.results[0].vantageNodeId,peer.body.id)
    assert.equal(db.prepare('SELECT vantage_node_id FROM verifier_results WHERE id=?').get(result.body.results[0].id).vantage_node_id,peer.body.id)
    const report=await auth(request.get('/api/v1/reports/verification')).expect(200)
    assert.equal(report.body.find(row=>row.policy==='Peer vantage policy').vantage,'verifier-peer')
  }finally{if(priorPython===undefined)delete process.env.WINRM_PYTHON;else process.env.WINRM_PYTHON=priorPython}
})

test('deny verification requires a matching target WFP event for the probe tuple',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Deny verifier test',type:'local',username:'test-user',password:'test-password-12345'}).expect(201)
  const target=await auth(request.post('/api/v1/nodes')).send({hostname:'deny-target',ip:'192.0.2.70',credentialIds:[credential.body.id]}).expect(201)
  const peer=await auth(request.post('/api/v1/nodes')).send({hostname:'deny-peer',ip:'192.0.2.71',credentialIds:[credential.body.id]}).expect(201)
  db.prepare("UPDATE nodes SET transport='winrm' WHERE id IN (?,?)").run(target.body.id,peer.body.id)
  const policy=await auth(request.post('/api/v1/policies')).send({name:'Deny event correlation'}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph:{nodes:[{id:'deny',type:'deny',data:{name:'Test deny',localPort:'3389'}}],edges:[]}}).expect(201)
  await auth(request.post(`/api/v1/policies/${policy.body.id}/assignments`)).send({nodeId:target.body.id}).expect(201)
  const rules=JSON.parse(db.prepare('SELECT rules_compiled_json FROM policy_versions WHERE policy_id=?').get(policy.body.id).rules_compiled_json).map(rule=>({...rule,internalName:'{WINFIRE-RULE}'}))
  const stub=path.join(dir,'deny-verifier-transport')
  fs.writeFileSync(stub,`#!/usr/bin/env node
let input='';process.stdin.on('data',part=>input+=part);process.stdin.on('end',()=>{
 const request=JSON.parse(input);let result
 if(request.operation==='rules')result=JSON.parse(process.env.WINFIRE_VERIFIER_RULES)
 else if(request.operation==='event_cursor')result=9000
 else if(request.operation==='tcp_probe')result={status:'timeout',latencyMs:4,sourceIp:'192.0.2.71',sourcePort:54321}
 else if(request.operation==='events_probe')result=process.env.WINFIRE_VERIFIER_EVENT?[{RecordId:process.env.WINFIRE_VERIFIER_EVENT==='other'?9001:9002,Id:5157,TimeCreated:new Date().toISOString(),Fields:{InterfaceIndex:'11',SourceAddress:'192.0.2.71',SourcePort:'54321',DestAddress:'192.0.2.70',DestPort:'3389',Protocol:'6',Direction:'%%14592',FilterOrigin:process.env.WINFIRE_VERIFIER_EVENT==='other'?'Query User Default':'{WINFIRE-RULE}',FilterRTID:'123456'}}]:[]
 else throw Error('Unexpected operation: '+request.operation)
 process.stdout.write(JSON.stringify(result))
})
`,{mode:0o700})
  const priorPython=process.env.WINRM_PYTHON
  process.env.WINRM_PYTHON=stub
  process.env.WINFIRE_VERIFIER_RULES=JSON.stringify(rules)
  try{
    const body={policyId:policy.body.id,nodeId:target.body.id,vantageNodeId:peer.body.id}
    const missing=await auth(request.post('/api/v1/verifier/runs')).send(body).expect(201)
    assert.equal(missing.body.results[0].status,'inconclusive')
    process.env.WINFIRE_VERIFIER_EVENT='other'
    const other=await auth(request.post('/api/v1/verifier/runs')).send(body).expect(201)
    assert.equal(other.body.results[0].status,'inconclusive')
    assert.match(other.body.results[0].reason,/another filter/)
    process.env.WINFIRE_VERIFIER_EVENT='managed'
    const observed=await auth(request.post('/api/v1/verifier/runs')).send(body).expect(201)
    assert.equal(observed.body.results[0].status,'pass')
    assert.equal(observed.body.results[0].firewallEventRecordId,9002)
    const stored=db.prepare('SELECT probe_source_ip,probe_source_port,firewall_event_record_id,firewall_event_filter_origin FROM verifier_results WHERE id=?').get(observed.body.results[0].id)
    assert.deepEqual(stored,{probe_source_ip:'192.0.2.71',probe_source_port:54321,firewall_event_record_id:9002,firewall_event_filter_origin:'{WINFIRE-RULE}'})
  }finally{
    if(priorPython===undefined)delete process.env.WINRM_PYTHON;else process.env.WINRM_PYTHON=priorPython
    delete process.env.WINFIRE_VERIFIER_RULES
    delete process.env.WINFIRE_VERIFIER_EVENT
  }
})

test('auth, vault, nodes, version history and reports work together',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  assert.ok(login.body.accessToken)
  const token=login.body.accessToken
  const auth=req=>req.set('Authorization',`Bearer ${token}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Lab',type:'local',username:'Administrator',password:'secret-for-lab'}).expect(201)
  assert.equal(credential.body.password,undefined)
  const listing=await auth(request.get('/api/v1/credentials')).expect(200)
  assert.equal(listing.body[0].encrypted_blob,undefined)
  assert.equal(JSON.stringify(listing.body).includes('secret-for-lab'),false)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'localhost',credentialIds:[credential.body.id]}).expect(201)
  assert.equal(node.body.hostname,'localhost')
  const policy=await auth(request.post('/api/v1/policies')).send({name:'Lab policy'}).expect(201)
  const graph={nodes:[{id:'r1',type:'allow',position:{x:20,y:20},data:{name:'RDP',localPort:'3389'}}],edges:[]}
  const v1=await auth(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph,comment:'Initial'}).expect(201)
  assert.equal(v1.body.rules[0].localPort,'3389')
  graph.nodes[0].data.localPort='5985'
  const v2=await auth(request.post(`/api/v1/policies/${policy.body.id}/versions`)).send({graph,comment:'WinRM'}).expect(201)
  assert.equal(v2.body.versionNo,2)
  const diff=await auth(request.get(`/api/v1/policies/${policy.body.id}/diff?from=${v1.body.id}&to=${v2.body.id}`)).expect(200)
  assert.equal(diff.body.added[0].localPort,'5985')
  assert.equal(diff.body.removed[0].localPort,'3389')
  assert.equal(diff.body.graph.changedNodes[0].before.data.localPort,'3389')
  assert.equal(diff.body.graph.changedNodes[0].after.data.localPort,'5985')
  assert.equal(diff.body.graph.addedNodes.length,0)
  const recalled=await auth(request.post(`/api/v1/policies/${policy.body.id}/versions/${v1.body.id}/recall`)).send({}).expect(200)
  assert.equal(recalled.body.versionId,v1.body.id)
  const coverage=await auth(request.get('/api/v1/reports/coverage')).expect(200)
  assert.ok(coverage.body.some(row=>row.hostname==='localhost'))
  const csv=await auth(request.get('/api/v1/reports/coverage?export=csv')).expect(200)
  assert.match(csv.text,/localhost/)
  const audit=await auth(request.get('/api/v1/audit')).expect(200)
  assert.ok(audit.body.some(entry=>entry.action==='policy.recall'))
})

test('invalid login is rejected without exposing account details',async()=>{
  const response=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'wrong'}).expect(401)
  assert.equal(response.body.error,'Invalid credentials or account locked')
})

test('account changes never put submitted passwords in audit records',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const user=await auth(request.post('/api/v1/users')).send({email:'audit@example.test',password:'initial-audit-pass-123',role:'editor'}).expect(201)
  const initial=await request.post('/api/v1/auth/login').send({email:'audit@example.test',password:'initial-audit-pass-123'}).expect(200)
  await auth(request.patch(`/api/v1/users/${user.body.id}`)).send({password:'replacement-audit-pass-123'}).expect(200)
  await request.get('/api/v1/auth/me').set('Authorization',`Bearer ${initial.body.accessToken}`).expect(401)
  const replacement=await request.post('/api/v1/auth/login').send({email:'audit@example.test',password:'replacement-audit-pass-123'}).expect(200)
  await auth(request.patch(`/api/v1/users/${user.body.id}/profile`)).send({password:'profile-audit-pass-123'}).expect(200)
  await request.get('/api/v1/auth/me').set('Authorization',`Bearer ${replacement.body.accessToken}`).expect(401)
  const current=await request.post('/api/v1/auth/login').send({email:'audit@example.test',password:'profile-audit-pass-123'}).expect(200)
  await auth(request.post(`/api/v1/users/${user.body.id}/revoke-sessions`)).send({}).expect(200)
  await request.get('/api/v1/auth/me').set('Authorization',`Bearer ${current.body.accessToken}`).expect(401)
  const audit=await auth(request.get('/api/v1/audit')).expect(200)
  const records=audit.body.filter(row=>row.entity_id===user.body.id)
  assert.ok(records.some(row=>row.action==='user.update'))
  assert.ok(records.some(row=>row.action==='user.profile'))
  assert.equal(JSON.stringify(records).includes('replacement-audit-pass-123'),false)
  assert.equal(JSON.stringify(records).includes('profile-audit-pass-123'),false)
})

test('private vault credentials cannot be attached by another editor',async()=>{
  const owner=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const ownerAuth=req=>req.set('Authorization',`Bearer ${owner.body.accessToken}`)
  const secret=await ownerAuth(request.post('/api/v1/credentials')).send({name:'Owner secret',type:'domain',username:'owner',password:'top-secret',visibility:'private'}).expect(201)
  await ownerAuth(request.post('/api/v1/users')).send({email:'editor@example.test',password:'editor-password-123',role:'editor'}).expect(201)
  const editor=await request.post('/api/v1/auth/login').send({email:'editor@example.test',password:'editor-password-123'}).expect(200)
  await request.post('/api/v1/nodes').set('Authorization',`Bearer ${editor.body.accessToken}`).send({hostname:'lab-host',credentialIds:[secret.body.id]}).expect(403)
})

test('credential test authenticates only the selected direct or group credential',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const good=await auth(request.post('/api/v1/credentials')).send({name:'Good auth',type:'local',username:'good-user',password:'good-password'}).expect(201)
  const bad=await auth(request.post('/api/v1/credentials')).send({name:'Bad auth',type:'local',username:'bad-user',password:'bad-password',priority:1}).expect(201)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:'auth-test.local',credentialIds:[good.body.id]}).expect(201)
  const group=await auth(request.post('/api/v1/node-groups')).send({name:'Auth test group'}).expect(201)
  await auth(request.post(`/api/v1/node-groups/${group.body.id}/members`)).send({nodeId:node.body.id}).expect(200)
  await auth(request.post(`/api/v1/credentials/${bad.body.id}/assignments`)).send({nodeGroupId:group.body.id}).expect(201)
  db.prepare('UPDATE nodes SET transport=? WHERE id=?').run('winrm',node.body.id)
  const stub=path.join(dir,'auth-transport')
  fs.writeFileSync(stub,'#!/usr/bin/env node\nlet data="";process.stdin.on("data",x=>data+=x);process.stdin.on("end",()=>{const p=JSON.parse(data);if(p.operation!=="auth"||p.username!=="good-user"){process.stderr.write("Invalid credential");process.exitCode=1}else process.stdout.write(JSON.stringify(p.username))})\n',{mode:0o700})
  const previous=process.env.WINRM_PYTHON
  process.env.WINRM_PYTHON=stub
  try {
    const tested=await auth(request.post(`/api/v1/credentials/${good.body.id}/test`)).send({nodeId:node.body.id}).expect(200)
    assert.deepEqual(tested.body,{success:true,transport:'winrm',account:'good-user'})
    const rejected=await auth(request.post(`/api/v1/credentials/${bad.body.id}/test`)).send({nodeId:node.body.id}).expect(200)
    assert.equal(rejected.body.success,false)
    assert.match(rejected.body.error,/Invalid credential/)
  } finally {
    if(previous===undefined)delete process.env.WINRM_PYTHON
    else process.env.WINRM_PYTHON=previous
  }
  db.prepare('UPDATE nodes SET transport=? WHERE id=?').run('wmi',node.body.id)
  const wmiStub=path.join(dir,'wmi-auth-transport')
  fs.writeFileSync(wmiStub,'#!/usr/bin/env node\nlet data="";process.stdin.on("data",x=>data+=x);process.stdin.on("end",()=>{const p=JSON.parse(data);if(p.username!=="good-user"){process.stderr.write("WMI access denied");process.exitCode=1}else process.stdout.write(JSON.stringify({success:true,transport:"wmi",computerName:"AUTH-TEST"}))})\n',{mode:0o700})
  const previousWmi=process.env.WMI_PROBE_PYTHON
  process.env.WMI_PROBE_PYTHON=wmiStub
  try{
    const wmi=await auth(request.post(`/api/v1/credentials/${good.body.id}/test`)).send({nodeId:node.body.id}).expect(200)
    assert.deepEqual(wmi.body,{success:true,transport:'wmi',account:'good-user',computerName:'AUTH-TEST'})
    assert.equal(db.prepare('SELECT probe_status FROM nodes WHERE id=?').get(node.body.id).probe_status,'wmi-authenticated')
    const rejected=await auth(request.post(`/api/v1/credentials/${bad.body.id}/test`)).send({nodeId:node.body.id}).expect(200)
    assert.equal(rejected.body.success,false)
    assert.equal(rejected.body.transport,'wmi')
    assert.match(rejected.body.error,/WMI access denied/)
  }finally{if(previousWmi===undefined)delete process.env.WMI_PROBE_PYTHON;else process.env.WMI_PROBE_PYTHON=previousWmi}
})

test('TOTP enrollment gates login and can be disabled',async()=>{
  const prior=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
  const header=`Bearer ${prior.body.accessToken}`
  const setup=await request.post('/api/v1/auth/totp/setup').set('Authorization',header).send({}).expect(200)
  const {totpCode}=await import('../src/totp.js')
  await request.post('/api/v1/auth/totp/confirm').set('Authorization',header).send({code:totpCode(setup.body.secret)}).expect(200)
  await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(401)
  const verified=await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345',totp:totpCode(setup.body.secret)}).expect(200)
  assert.ok(verified.body.accessToken)
  await request.post('/api/v1/auth/totp/disable').set('Authorization',`Bearer ${verified.body.accessToken}`).send({password:'test-password-12345',code:totpCode(setup.body.secret)}).expect(200)
  await request.post('/api/v1/auth/login').send({email:'owner@example.test',password:'test-password-12345'}).expect(200)
})
