import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import supertest from 'supertest'
const dir=fs.mkdtempSync(os.tmpdir()+'/winfire-protection-');process.env.DATA_DIR=dir;process.env.NODE_ENV='test'
const {app}=await import('../src/app.js'),{db,run,one,all,id,now,json}=await import('../src/db.js'),{issueAccess,seal}=await import('../src/security.js')
const {saveServiceNow,deliverServiceNow,testServiceNow}=await import('../src/services/servicenow.js')
const {emitNotification,deliverPendingNotifications}=await import('../src/notifications.js')
const {saveDdosPolicy,runDdosCycle,ddosEvidence,releaseDdosIncident}=await import('../src/services/ddos.js')
const {linuxDdosCommand,validateDdosBlock}=await import('../src/ddosFirewall.js')
const request=supertest(app)
const owner={id:id(),email:'protection-owner@example.test',role:'owner'},auditor={id:id(),email:'protection-auditor@example.test',role:'auditor'}
for(const u of [owner,auditor]){run('INSERT INTO users(id,email,password_hash,role,email_verified) VALUES(?,?,?,?,1)',u.id,u.email,'fixture',u.role);run('INSERT INTO user_profiles(user_id,notification_prefs) VALUES(?,?)',u.id,'{}')}
const as=(u,r)=>r.set('Authorization','Bearer '+issueAccess(one('SELECT * FROM users WHERE id=?',u.id)))
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})
test('administrator routes, vault secrets, notification preferences and public contracts',async()=>{
 await as(auditor,request.get('/notifications/servicenow')).expect(404)
 await as(auditor,request.get('/api/v1/notifications/servicenow')).expect(403)
 await as(auditor,request.get('/api/v1/protection/ddos/policies')).expect(403)
 await as(auditor,request.get('/api/v1/notifications')).expect(200)
 await as(auditor,request.post('/api/v1/credentials')).send({type:'servicenow',name:'Denied',username:'svc',password:'fixture-only'}).expect(403)
 const response=await as(owner,request.post('/api/v1/credentials')).send({type:'servicenow',name:'Incident account',username:'svc',password:'fixture-only'}).expect(201)
 const credential=one("SELECT * FROM credentials WHERE type='servicenow'");assert.ok(!JSON.stringify(response.body).includes('fixture-only'));assert.ok(!credential.encrypted_blob.includes('fixture-only'))
 const config={enabled:true,baseUrl:'https://example.service-now.com',credentialId:credential.id,assignmentGroup:'',impact:2,urgency:2}
 await as(owner,request.put('/api/v1/notifications/servicenow')).send(config).expect(200)
 for(const baseUrl of ['http://bad.test','https://bad.test/other','https://svc:password@bad.test','https://bad.test/?secret=1'])await as(owner,request.put('/api/v1/notifications/servicenow')).send({...config,baseUrl}).expect(400)
 await as(owner,request.patch('/api/v1/users/'+owner.id+'/profile')).send({notificationPrefs:{'ddos_attack.servicenow':true}}).expect(200)
 const spec=(await request.get('/api/v1/openapi.json').expect(200)).body
 assert.ok(spec.paths['/notifications/servicenow']);assert.ok(spec.paths['/protection/ddos/incidents/{id}/release']);assert.equal(spec.paths['/protection/ddos/policies'].post.requestBody.content['application/json'].schema.$ref,'#/components/schemas/DdosPolicyRequest')
})
test('ServiceNow retries recover a lost create response and deduplicate multiple recipients',async()=>{
 let posted=0,stored=null;const fetcher=async(url,options)=>{assert.equal(options.redirect,'error');assert.match(options.headers.Authorization,/^Basic /);assert.match(url,/api\/now\/v1\/table\/incident/);if(options.method==='GET')return new Response(JSON.stringify({result:stored?[stored]:[]}));posted++;const body=JSON.parse(options.body);assert.match(body.correlation_id,/^winfire:/);stored={sys_id:'a'.repeat(32),number:'INC001'};throw new Error('Simulated lost HTTP response')}
 const item={event_key:'same-attack',category:'ddos_attack',title:'Suspected attack',body:'Threshold exceeded'}
 await assert.rejects(deliverServiceNow(item,fetcher),/lost HTTP/)
 assert.equal(await deliverServiceNow(item,fetcher),true)
 assert.equal(await deliverServiceNow({...item,user_id:auditor.id},fetcher),true);assert.equal(posted,1)
 assert.equal(one('SELECT number FROM servicenow_tickets').number,'INC001')
 const result=await testServiceNow(async()=>new Response(JSON.stringify({result:[]})));assert.equal(result.ok,true)
 await assert.rejects(testServiceNow(async()=>new Response('hidden-secret',{status:403})),e=>!e.message.includes('hidden-secret')&&e.status===502)
 for(const u of [owner,auditor])run('UPDATE user_profiles SET notification_prefs=? WHERE user_id=?',json({'ddos_attack.servicenow':true}),u.id)
 emitNotification({...{eventKey:'same-attack',category:'ddos_attack',title:'Suspected attack',body:'Threshold exceeded'}})
 await deliverPendingNotifications();assert.equal(one("SELECT COUNT(*) n FROM notification_deliveries WHERE channel='servicenow' AND status='sent'").n,2)
})
const nodeId='ddos-node'
run("INSERT INTO nodes(id,hostname,ip,transport,connection_mode) VALUES(?,?,'10.42.0.9','winrm','agentless')",nodeId,'Protection fixture')
run("INSERT INTO app_settings(key,value) VALUES('local_asset_cidrs','[\"10.42.0.0/24\"]') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
const node=()=>one('SELECT * FROM nodes WHERE id=?',nodeId)
const policy=(extra={})=>saveDdosPolicy({name:'Web protection',nodeIds:[nodeId],ports:[443],windowSeconds:30,observeSeconds:30,eventThreshold:10,sourceThreshold:2,perSourceThreshold:2,...extra},owner.id)
function events(at,{count=12,src='203.0.113.',eventAt=at,port=443,action='allow',direction='in'}={}){for(let n=0;n<count;n++)run('INSERT INTO log_events(id,node_id,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,event_time,received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',id(),nodeId,5156,action,'TCP',src+(n%2+1),'10.42.0.9',port,direction,new Date(eventAt).toISOString(),new Date(at).toISOString())}
function reset(){run('DELETE FROM ddos_transitions');run('DELETE FROM ddos_incidents');run('DELETE FROM ddos_policies');run('DELETE FROM log_events');run('DELETE FROM node_capability_evidence')}
test('disabled detection defaults, scope conflicts and dangerous management ports are rejected',async()=>{
 reset();const p=policy();assert.equal(p.mode,'detect');assert.equal(p.enabled,false)
 const at=Date.now()+1000;events(at);let calls=0;await runDdosCycle({at,execute:async()=>{calls++}});assert.equal(calls,0);assert.equal(one('SELECT COUNT(*) n FROM ddos_incidents').n,0)
 const enabled=saveDdosPolicy({...Object.fromEntries(Object.keys(p).filter(k=>!['id','createdAt','updatedAt'].includes(k)).map(k=>[k,p[k]])),enabled:true},owner.id,p.id)
 await runDdosCycle({at:at+1000,execute:async()=>{calls++}});assert.equal(calls,0);assert.equal(one('SELECT status FROM ddos_incidents').status,'detected')
 assert.throws(()=>policy({enabled:true}),/already has/)
 assert.throws(()=>policy({mode:'block',ports:[5985]}),/management ports/)
 run("UPDATE nodes SET transport='snmp' WHERE id=?",nodeId);assert.throws(()=>policy({mode:'block'}),/agentless WinRM or SSH/);run("UPDATE nodes SET transport='winrm' WHERE id=?",nodeId)
})
test('historical, local, excluded, outbound and other-service traffic do not trigger; compact patterns count',()=>{
 reset();const p=policy({excludedCidrs:['203.0.113.0/24']}),at=Date.now()+5000
 events(at);events(at,{src:'10.42.0.'});events(at,{src:'198.51.100.',eventAt:at-3600000});events(at,{src:'198.51.100.',direction:'out'});events(at,{src:'198.51.100.',port:80})
 assert.equal(ddosEvidence(p,node(),{at}).thresholdMet,false)
 const pattern=id();run('INSERT INTO event_patterns(id,fingerprint,action,protocol,src_ip,dst_ip,dst_port,direction) VALUES(?,?,?,?,?,?,?,?)',pattern,pattern,'allow','TCP','198.51.100.4','10.42.0.9',443,'in')
 run('INSERT INTO log_events(id,node_id,event_id,action,pattern_id,event_time,received_at) VALUES(?,?,?,?,?,?,?)',id(),nodeId,5156,'allow',pattern,new Date(at).toISOString(),new Date(at).toISOString())
 assert.equal(ddosEvidence(p,node(),{at}).events,1)
})
test('timed block, release, fresh observation, reblock, telemetry gap and quiet recovery',async()=>{
 reset();const p=policy({enabled:true,mode:'block',blockSeconds:30}),start=Date.now()+2000,calls=[]
 const execute=async(n,op,args)=>{assert.equal(n.id,nodeId);calls.push({op,args});return {active:op==='ddos_start',removed:op==='ddos_end',nativeExpiry:true}}
 events(start);await runDdosCycle({at:start+1000,execute});let i=one('SELECT * FROM ddos_incidents');assert.equal(i.status,'blocked');assert.equal(i.cycles,1)
 await runDdosCycle({at:start+2000,execute});assert.equal(calls.length,1)
 const expiry=Date.parse(i.expires_at);await runDdosCycle({at:expiry+1,execute});assert.equal(one('SELECT status FROM ddos_incidents').status,'observing');assert.equal(calls[1].op,'ddos_end')
 await runDdosCycle({at:expiry+31000,execute});assert.match(one('SELECT last_error FROM ddos_incidents').last_error,/unconfirmed/);assert.equal(calls.length,2)
 events(expiry+32000);await runDdosCycle({at:expiry+33000,execute});i=one('SELECT * FROM ddos_incidents');assert.equal(i.cycles,2);assert.equal(i.status,'blocked')
 const secondExpiry=Date.parse(i.expires_at);await runDdosCycle({at:secondExpiry+1,execute})
 run("INSERT INTO node_capability_evidence(node_id,capability,source,last_success_at) VALUES(?,'events','winrm',?)",nodeId,new Date(secondExpiry+32000).toISOString())
 await runDdosCycle({at:secondExpiry+33000,execute});i=one('SELECT * FROM ddos_incidents');assert.equal(i.status,'resolved');assert.ok(i.closed_at);assert.equal(calls.filter(c=>c.op==='ddos_start').length,2)
})
test('uncertain host failures persist intent and retry removal; manual stop disables policy',async()=>{
 reset();const p=policy({enabled:true,mode:'block',blockSeconds:30}),at=Date.now()+1000;events(at)
 await runDdosCycle({at:at+1000,execute:async()=>{throw new Error('Lost host response')}});let i=one('SELECT * FROM ddos_incidents');assert.equal(i.status,'blocking');assert.ok(i.block_json)
 await runDdosCycle({at:at+2000,execute:async()=>{throw new Error('Offline')}});i=one('SELECT * FROM ddos_incidents');assert.equal(i.status,'releasing');assert.equal(i.last_error,'Offline')
 const removed=[];await releaseDdosIncident(i.id,owner.id,{at:at+3000,execute:async(n,op,args)=>{removed.push(op);return {removed:true}}});assert.deepEqual(removed,['ddos_end']);assert.equal(JSON.parse(one('SELECT config_json FROM ddos_policies WHERE id=?',p.id).config_json).enabled,false);assert.ok(one('SELECT closed_at FROM ddos_incidents').closed_at)
})
test('Linux native timeouts and strict block validation do not change baseline rules',()=>{
 const b={id:id(),protocol:'TCP',ports:[443],sources:['203.0.113.1','2001:db8::1'],seconds:60};const command=linuxDdosCommand('ddos_start',b),encoded=command.match(/'([A-Za-z0-9+/=]+)' \| base64/)[1],script=Buffer.from(encoded,'base64').toString()
 assert.match(script,/timeout 60s/);assert.match(script,/type ipv6_addr/);assert.ok(!script.includes('flush ruleset'));assert.match(linuxDdosCommand('ddos_end',{id:b.id}),/delete table inet wfddos_/)
 assert.throws(()=>validateDdosBlock({...b,sources:['1.2.3.4; reboot']}));assert.throws(()=>validateDdosBlock({...b,ports:[22]}));assert.throws(()=>linuxDdosCommand('ddos_end',{id:'x;rm -rf /'}))
})
