import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import supertest from 'supertest'
import {spawnSync} from 'node:child_process'
const dir=fs.mkdtempSync(os.tmpdir()+'/winfire-ai-test-');process.env.DATA_DIR=dir;process.env.NODE_ENV='test';process.env.BOOTSTRAP_EMAIL='ai@test.example';process.env.BOOTSTRAP_PASSWORD='Ai-test-only-123'
const {app}=await import('../src/app.js'),{db,run,one,all}=await import('../src/db.js'),{bootstrap}=await import('../src/security.js')
const {processAiWork,pruneAi,retainObservation}=await import('../src/ai/observations.js'),{seedCatalog,matchService,registrableDomain}=await import('../src/ai/catalog.js')
await bootstrap();seedCatalog();test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})
const http=supertest(app),login=await http.post('/api/v1/auth/login').send({email:process.env.BOOTSTRAP_EMAIL,password:process.env.BOOTSTRAP_PASSWORD}).expect(200),admin=r=>r.set('Authorization','Bearer '+login.body.accessToken)
run("INSERT INTO nodes(id,hostname,ip) VALUES('ai-node','AI host','192.0.2.10'),('other-node','Other host','192.0.2.20')")
let reporter,token
const report=r=>r.set('Authorization','Bearer '+token)
const event=(extra={})=>({schemaVersion:1,eventId:crypto.randomUUID(),observedAt:new Date().toISOString(),operation:'model_request',provider:'local',model:'local-model',...extra})
test('enrollment binds node and actor; durable replay conflicts, rotation and authorization',async()=>{
 const enrolled=(await admin(http.post('/api/v1/ai/reporters')).send({name:'Test reporter',nodeIds:['ai-node'],coverage:'instrumented'}).expect(201)).body;reporter=enrolled.reporter;token=enrolled.credential
 const e=event({hostname:'https://user:password@api.anthropic.com/messages?key=SECRET#prompt'})
 const first=(await report(http.post('/api/v1/ai/usage:batch')).send({events:[e]}).expect(200)).body
 assert.equal(first.results[0].status,'accepted');const usage=one('SELECT * FROM ai_usage_events WHERE id=?',first.results[0].usageId);assert.equal(usage.node_id,'ai-node');assert.equal(usage.hostname,'api.anthropic.com');assert.equal(usage.input_tokens,null)
 const replay=(await report(http.post('/api/v1/ai/usage:batch')).send({events:[e]}).expect(200)).body;assert.equal(replay.results[0].receiptId,first.results[0].receiptId);assert.equal(replay.results[0].status,'duplicate')
 const bad=(await report(http.post('/api/v1/ai/usage:batch')).send({events:[{...e,model:'changed'},event({nodeId:'other-node'}),event({actorId:'other-user'}),event({prompt:'SECRET PROMPT'}),event({operation:'future.custom'})]}).expect(200)).body
 assert.deepEqual(bad.results.map(r=>r.status),['rejected','rejected','rejected','rejected','accepted']);assert.equal(bad.results[0].code,'conflicting_replay');assert.equal(bad.results[1].code,'node_not_authorized');assert.equal(one("SELECT original_operation FROM ai_usage_events WHERE original_operation='future.custom'").original_operation,'future.custom')
 await report(http.get('/api/v1/ai/usage')).expect(401);await admin(http.post('/api/v1/ai/usage:batch')).send({events:[e]}).expect(401)
 const old=token;token=(await admin(http.post(`/api/v1/ai/reporters/${reporter.id}/rotate`)).send({}).expect(200)).body.credential
 await http.post('/api/v1/ai/usage:batch').set('Authorization','Bearer '+old).send({events:[event()]}).expect(401)
 assert.equal((await report(http.post('/api/v1/ai/usage:batch')).send({events:[e]}).expect(200)).body.results[0].status,'duplicate')
 assert.ok(!JSON.stringify(all('SELECT * FROM ai_usage_events')).includes('SECRET'));assert.ok(!JSON.stringify(all('SELECT * FROM audit_log')).includes(token))
})
test('out-of-order lifecycle counts once; invalid batches and time bounds do not corrupt it',async()=>{
 const at=new Date(),start=new Date(at-1000).toISOString(),op=crypto.randomUUID(),end=event({operationId:op,phase:'end',observedAt:at.toISOString(),inputTokens:10,outputTokens:20})
 await report(http.post('/api/v1/ai/usage:batch')).send({events:[end]}).expect(200)
 await report(http.post('/api/v1/ai/usage:batch')).send({events:[event({operationId:op,phase:'start',observedAt:start})]}).expect(200)
 const row=one('SELECT * FROM ai_usage_events WHERE operation_id=?',op);assert.equal(row.started_at,start);assert.equal(row.duration_ms,1000);assert.equal(row.outcome,'success');assert.equal(row.input_tokens,10);assert.equal(one('SELECT count(*) n FROM ai_usage_events WHERE operation_id=?',op).n,1)
 const results=(await report(http.post('/api/v1/ai/usage:batch')).send({events:[event({operationId:op,phase:'end'}),event({observedAt:new Date(Date.now()+600000).toISOString()}),event({observedAt:'2000-01-01T00:00:00Z'})]}).expect(200)).body.results
 assert.deepEqual(results.map(r=>r.code),['operation_phase_conflict','future_timestamp','outside_retention'])
 await report(http.post('/api/v1/ai/usage:batch')).send({events:Array(101).fill(event())}).expect(400)
 const node=(await admin(http.get('/api/v1/nodes/ai-node/ai-usage')).expect(200)).body.reported, fleet=(await admin(http.get('/api/v1/ai/usage?nodeId=ai-node')).expect(200)).body
 assert.equal(node.total,fleet.total);assert.equal(fleet.limit,25);assert.equal(fleet.summary.inputTokens,10)
})
test('catalog boundary matching, roles, disabled overrides and public suffix rejection',async()=>{
 assert.equal(matchService('api.anthropic.com').provider,'anthropic');assert.equal(matchService('notopenai.com'),null);assert.equal(matchService('api.openai.com.example.org'),null);assert.equal(matchService('github.com'),null);assert.equal(matchService('auth.openai.com').role,'auth');assert.equal(registrableDomain('a.service.example.co.uk'),'example.co.uk')
 const base={hostname:'gateway.example.test',match:'exact',provider:'private',service:'Private gateway',role:'api',sourceUrl:'https://example.test/docs',reviewedAt:'2026-09-24',enabled:true}
 const rule=(await admin(http.post('/api/v1/ai/service-rules')).send(base).expect(201)).body;assert.equal(matchService(base.hostname).id,rule.id)
 await admin(http.post('/api/v1/ai/service-rules')).send(base).expect(409);await admin(http.post('/api/v1/ai/service-rules')).send({...base,hostname:'co.uk',match:'suffix'}).expect(400)
 await admin(http.patch('/api/v1/ai/service-rules/'+rule.id)).send({...base,enabled:false}).expect(200);assert.equal(matchService(base.hostname),null);assert.equal(one('SELECT count(*) n FROM ai_rule_history WHERE rule_id=?',rule.id).n,2)
})
function firewall(id,ip,action='allow',at=new Date().toISOString(),program='C:\\python.exe'){run('INSERT INTO log_events(id,node_id,event_id,event_type,action,event_time,src_ip,dst_ip,dst_port,direction,protocol,program,process_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',id,'ai-node',action==='block'?5157:5156,'firewall',action,at,'192.0.2.10',ip,443,'out','TCP',program,123)}
test('network observations retain PTR uncertainty, DNS ambiguity, blocked outcomes and source expiry',async()=>{
 const at=new Date(),dnsTime=new Date(at-1000).toISOString();run("INSERT INTO internet_peers(id,ip,resolver_context,first_seen_at,last_seen_at,names_json,status) VALUES('ai-ptr','203.0.113.20','system',?,?,?, 'resolved')",dnsTime,dnsTime,JSON.stringify(['api.anthropic.com']))
 firewall('ptr-event','203.0.113.20');firewall('dns-event','203.0.113.21');firewall('blocked-event','203.0.113.21','block')
 await report(http.post('/api/v1/ai/dns')).send({schemaVersion:1,eventId:'dns-1',hostname:'api.anthropic.com',answers:['203.0.113.21'],observedAt:dnsTime,ttlSeconds:60,processId:123,provider:'Microsoft-Windows-Sysmon',channel:'Microsoft-Windows-Sysmon/Operational'}).expect(201)
 processAiWork({limit:100});processAiWork({limit:100})
 const ptr=one("SELECT * FROM ai_network_observations WHERE source_id='ptr-event'");assert.equal(ptr.category,'suspected');assert.equal(ptr.confidence,'low')
 const dns=one("SELECT * FROM ai_network_observations WHERE source_id='dns-event'");assert.equal(dns.category,'observed');assert.equal(one("SELECT action FROM ai_network_observations WHERE source_id='blocked-event'").action,'block')
 await report(http.post('/api/v1/ai/dns')).send({schemaVersion:1,eventId:'dns-2',hostname:'non-ai.example.test',answers:['203.0.113.21'],observedAt:dnsTime,ttlSeconds:60,processId:123,provider:'Microsoft-Windows-Sysmon',channel:'Microsoft-Windows-Sysmon/Operational'}).expect(201)
 processAiWork({limit:100});processAiWork({limit:100});assert.equal(one("SELECT category FROM ai_network_observations WHERE source_id='dns-event'").category,'suspected');assert.equal(one("SELECT hostname FROM ai_network_observations WHERE source_id='dns-event'").hostname,null)
 run("DELETE FROM log_events WHERE id='ptr-event'");processAiWork({limit:100});processAiWork({limit:100});assert.equal(one('SELECT source_expired FROM ai_network_observations WHERE id=?',ptr.id).source_expired,1)
})
test('correlation retains parallel candidates without counting connections as operations',async()=>{
 const at=new Date().toISOString(),a=event({traceId:'trace-multi',hostname:'api.anthropic.com',observedAt:at}),b=event({traceId:'trace-multi',hostname:'api.anthropic.com',observedAt:at})
 await report(http.post('/api/v1/ai/usage:batch')).send({events:[a,b]}).expect(200)
 const o=retainObservation({source:'fixture',source_id:'multiplexed',node_id:'ai-node',observed_at:at,hostname:'api.anthropic.com',trace_id:'trace-multi',rule:matchService('api.anthropic.com'),category:'observed',confidence:'high'})
 assert.equal(one('SELECT count(*) n FROM ai_usage_evidence WHERE observation_id=?',o.id).n,2);assert.equal(one('SELECT count(*) n FROM ai_usage_evidence WHERE observation_id=? AND association=?',o.id,'linked').n,0)
 const total=one('SELECT count(*) n FROM ai_usage_events').n;processAiWork({limit:100});assert.equal(one('SELECT count(*) n FROM ai_usage_events').n,total)
})
test('receipts survive process restart and metadata summaries retain decimal precision',async()=>{
 const e=event({cost:{amount:'0.100000001',currency:'USD',source:'reported'}}),first=(await report(http.post('/api/v1/ai/usage:batch')).send({events:[e]}).expect(200)).body.results[0]
 const code=`const {ingestBatch}=await import('./api/src/ai/ingestion.js');const {db}=await import('./api/src/db.js');const result=ingestBatch(process.env.AI_TEST_REPORTER,JSON.parse(await new Promise(r=>{let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>r(s))})));console.log(JSON.stringify(result));db.close()`
 const restarted=spawnSync(process.execPath,['--input-type=module','-e',code],{input:JSON.stringify({events:[e]}),env:{...process.env,AI_TEST_REPORTER:reporter.id},encoding:'utf8'});assert.equal(restarted.status,0,restarted.stderr);const replay=JSON.parse(restarted.stdout).results[0];assert.equal(replay.status,'duplicate');assert.equal(replay.receiptId,first.receiptId)
 const summary=(await admin(http.get('/api/v1/ai/usage/summary')).expect(200)).body;assert.equal(summary.costs[0].amount,'0.100000001')
 await report(http.post('/api/v1/ai/usage:batch')).send({events:[event({prompt:'x'.repeat(270000)})]}).expect(413)
 const spec=(await http.get('/api/v1/openapi.json').expect(200)).body;assert.ok(spec.paths['/ai/usage:batch']);assert.deepEqual(spec.paths['/ai/usage:batch'].post.security,[{aiReporterBearer:[]}]);assert.equal(spec.components.schemas.AiUsageBatch.properties.events.maxItems,100)
})
test('PID reuse remains uncertain, stale DNS cannot identify a host, and new catalog rules backfill',async()=>{
 const at=new Date().toISOString(),e=event({processId:777,processStartedAt:new Date(Date.now()-10000).toISOString(),hostname:'api.anthropic.com',observedAt:at})
 const receipt=(await report(http.post('/api/v1/ai/usage:batch')).send({events:[e]}).expect(200)).body.results[0]
 const o=retainObservation({source:'fixture',source_id:'pid-only',node_id:'ai-node',process_id:777,observed_at:at,hostname:'api.anthropic.com',category:'observed'})
 assert.equal(one('SELECT association FROM ai_usage_evidence WHERE usage_id=? AND observation_id=?',receipt.usageId,o.id).association,'candidate')
 retainObservation({...o,process_started_at:new Date(Date.now()-5000).toISOString()});assert.equal(one('SELECT * FROM ai_usage_evidence WHERE usage_id=? AND observation_id=?',receipt.usageId,o.id),undefined)
 const staleTime=new Date(Date.now()-10000).toISOString();await report(http.post('/api/v1/ai/dns')).send({schemaVersion:1,eventId:'stale-dns',hostname:'api.openai.com',answers:['203.0.113.88'],observedAt:staleTime,ttlSeconds:1,provider:'Microsoft-Windows-Sysmon',channel:'Microsoft-Windows-Sysmon/Operational'}).expect(201)
 firewall('stale-dns-traffic','203.0.113.88');firewall('expired-source','203.0.113.20','allow','2000-01-01T00:00:00Z');processAiWork({limit:100});assert.equal(one("SELECT id FROM ai_network_observations WHERE source_id IN ('stale-dns-traffic','expired-source')"),undefined)
 run("INSERT INTO internet_peers(id,ip,resolver_context,first_seen_at,last_seen_at,names_json,status) VALUES('new-catalog-peer','203.0.113.89','system',?,?,?, 'resolved')",at,at,JSON.stringify(['new-ai.example.test']));firewall('catalog-backfill','203.0.113.89');processAiWork({limit:100});assert.equal(one("SELECT id FROM ai_network_observations WHERE source_id='catalog-backfill'"),undefined)
 await admin(http.post('/api/v1/ai/service-rules')).send({hostname:'new-ai.example.test',match:'exact',provider:'private',service:'Private API',role:'api',sourceUrl:'https://example.test/docs',reviewedAt:'2026-09-24',enabled:true}).expect(201);processAiWork({limit:100});assert.equal(one("SELECT category FROM ai_network_observations WHERE source_id='catalog-backfill'").category,'suspected')
})
test('bounded queue rejects reporting overload without acknowledging lost metadata',async()=>{
 run(`WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000) INSERT OR IGNORE INTO ai_work_queue(kind,source_id,queued_at) SELECT 'capacity-test','cap-'||x,'2026-01-01T00:00:00Z' FROM n`)
 const e=event(),response=(await report(http.post('/api/v1/ai/usage:batch')).send({events:[e]}).expect(200)).body;assert.equal(response.results[0].code,'queue_full');assert.equal(response.results[0].retryable,true);assert.equal(one('SELECT id FROM ai_receipts WHERE event_id=?',e.eventId),undefined)
 await report(http.post('/api/v1/ai/dns')).send({schemaVersion:1,eventId:'dns-capacity',hostname:'api.openai.com',answers:['203.0.113.100'],observedAt:new Date().toISOString(),provider:'Microsoft-Windows-Sysmon',channel:'Microsoft-Windows-Sysmon/Operational'}).expect(503);assert.equal(one("SELECT id FROM ai_dns_observations WHERE event_id='dns-capacity'"),undefined)
 run("DELETE FROM ai_work_queue WHERE kind='capacity-test'")
 assert.equal((await report(http.post('/api/v1/ai/usage:batch')).send({events:[e]}).expect(200)).body.results[0].status,'accepted')
})
test('auditor read access, administrative gates and retention cascading',async()=>{
 const hash=one('SELECT password_hash FROM users WHERE email=?',process.env.BOOTSTRAP_EMAIL).password_hash;run("INSERT INTO users(id,email,password_hash,role,email_verified) VALUES('ai-auditor','auditor@ai.test',?,'auditor',1)",hash)
 const signed=(await http.post('/api/v1/auth/login').send({email:'auditor@ai.test',password:process.env.BOOTSTRAP_PASSWORD}).expect(200)).body.accessToken,read=r=>r.set('Authorization','Bearer '+signed)
 await read(http.get('/api/v1/ai/usage')).expect(200);await read(http.post('/api/v1/ai/reporters')).send({name:'forbidden'}).expect(403);await read(http.patch('/api/v1/ai/settings')).send({}).expect(403)
 await admin(http.post(`/api/v1/ai/reporters/${reporter.id}/revoke`)).send({}).expect(200);await report(http.post('/api/v1/ai/usage:batch')).send({events:[event()]}).expect(401)
 const before=one('SELECT count(*) n FROM ai_usage_events').n;pruneAi(new Date(Date.now()+100*86400000));assert.ok(before>0);assert.equal(one('SELECT count(*) n FROM ai_usage_events').n,0);assert.equal(one('SELECT count(*) n FROM ai_usage_evidence').n,0)
})
