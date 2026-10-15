import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {createHmac} from 'node:crypto'
import {spawnSync} from 'node:child_process'
import supertest from 'supertest'
const root=fs.mkdtempSync(os.tmpdir()+'/winfire-operational-evidence-'),dir=path.join(root,'source')
process.env.DATA_DIR=dir;process.env.NODE_ENV='test'
const {app}=await import('../src/app.js'),{db,run,one,id,now,json,audit}=await import('../src/db.js')
const {issueAccess,seal,openSealed}=await import('../src/security.js')
const {saveEvidenceDestination,evidenceDestinations,evidenceSnapshot,queueEvidenceSnapshot,enqueueDueEvidence,deliverEvidence,evidenceDeliveries,retryEvidence}=await import('../src/services/evidenceExports.js')
const {createRecoveryBackup,verifyRecoveryBackup,restoreRecoveryBackup,acknowledgeRecovery}=await import('../src/operations/recovery.js')
const {recordCollectionHealth,collectionCoverage}=await import('../src/services/collectionCoverage.js')
const {ruleUsage}=await import('../src/services/ruleUsage.js')
const owner={id:id(),email:'ops@example.test',role:'owner'},editor={id:id(),email:'editor@example.test',role:'editor'}
for(const user of [owner,editor])run('INSERT INTO users(id,email,password_hash,role) VALUES(?,?,?,?)',user.id,user.email,'fixture',user.role)
const auth=(r,user=owner)=>r.set('Authorization','Bearer '+issueAccess(one('SELECT * FROM users WHERE id=?',user.id)))
run("INSERT INTO app_settings(key,value) VALUES('local_asset_cidrs','[\"10.42.0.0/24\"]') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
run("INSERT INTO nodes(id,hostname,ip,transport) VALUES('ops-node','Ops node','10.42.0.2','winrm')")
test.after(()=>{db.close();fs.rmSync(root,{recursive:true,force:true})})
const config={name:'SIEM evidence',endpoint:'https://receiver.example.test/winfire',enabled:true,eventTypes:['policy','connector'],intervalMinutes:60}
test('evidence destinations encrypt write-only secrets, default disabled and enforce administrator access',async()=>{
 const d=saveEvidenceDestination({...config,enabled:false},owner.id)
 assert.ok(d.oneTimeSecret.length>=32);assert.equal(d.enabled,false)
 assert.equal(JSON.stringify(evidenceDestinations()).includes(d.oneTimeSecret),false)
 assert.equal(one('SELECT secret_blob FROM evidence_destinations WHERE id=?',d.id).secret_blob.includes(d.oneTimeSecret),false)
 await auth(supertest(app).get('/api/v1/evidence-destinations'),editor).expect(403)
 await supertest(app).get('/api/v1/reports/evidence').expect(401)
 await auth(supertest(app).post('/api/v1/evidence-destinations')).send({...config,endpoint:'http://receiver.test'}).expect(400)
 await auth(supertest(app).post('/api/v1/evidence-destinations')).send({...config,endpoint:'https://user:pass@receiver.test/path'}).expect(400)
 assert.throws(()=>queueEvidenceSnapshot(d.id,owner.id),/Enable/)
})
test('snapshots match scoped capability totals and omit arbitrary diagnostic/secrets payloads',async()=>{
 run("INSERT INTO node_capability_evidence(node_id,capability,source,last_success_at,detail_json) VALUES('ops-node','events','fixture',?,?)",now(),json({password:'must-not-export'}))
 const snapshot=evidenceSnapshot();assert.equal(snapshot.total,1);assert.equal(snapshot.nodes.length,1);assert.equal(JSON.stringify(snapshot).includes('must-not-export'),false)
 const api=await auth(supertest(app).get('/api/v1/reports/evidence')).expect(200);assert.equal(api.body.total,snapshot.total)
})
test('webhook retries preserve payload and delivery ID and sign exact bytes with a fresh timestamp',async()=>{
 const d=saveEvidenceDestination(config,owner.id),key=queueEvidenceSnapshot(d.id,owner.id).id,sent=[]
 const fetchImpl=async(url,options)=>{sent.push({url,...options});return new Response('',{status:sent.length===1?503:204})}
 await deliverEvidence({fetchImpl});assert.equal(one('SELECT status FROM evidence_deliveries WHERE id=?',key).status,'pending')
 run('UPDATE evidence_deliveries SET next_attempt_at=? WHERE id=?','2000-01-01T00:00:00Z',key)
 // Response 204 must have no body; use an explicit successful receiver response.
 await deliverEvidence({fetchImpl:async(url,o)=>{sent.push({url,...o});return new Response(null,{status:204})}})
 assert.equal(one('SELECT status FROM evidence_deliveries WHERE id=?',key).status,'sent');assert.equal(sent[0].body,sent[1].body)
 for(const request of sent){assert.equal(request.headers['Idempotency-Key'],key);assert.equal(request.redirect,'error');const expected=createHmac('sha256',d.oneTimeSecret).update(request.headers['X-WinFire-Timestamp']+'.'+key+'.'+request.body).digest('hex');assert.equal(request.headers['X-WinFire-Signature'],'sha256='+expected)}
})
test('queueing is idempotent and destination edits cancel old deliveries',()=>{
 const d=saveEvidenceDestination(config,owner.id);run('UPDATE evidence_destinations SET next_run_at=? WHERE id=?','2000-01-01T00:00:00Z',d.id)
 enqueueDueEvidence();enqueueDueEvidence();assert.equal(one('SELECT count(*) n FROM evidence_deliveries WHERE destination_id=?',d.id).n,1)
 const changed=saveEvidenceDestination({...config,enabled:false},owner.id,d.id);assert.equal(changed.oneTimeSecret,undefined)
 assert.equal(one('SELECT status FROM evidence_deliveries WHERE destination_id=?',d.id).status,'cancelled')
})
test('event exports retain scope and omit audit before/after secrets',()=>{
 const d=saveEvidenceDestination({...config,eventTypes:['connector']},owner.id)
 audit(owner.id,'node.unreachable','node','ops-node',{password:'hidden'}, {credentialSecret:'hidden'})
 audit(owner.id,'node.unreachable','node','other-scope-node',null,{})
 enqueueDueEvidence();const rows=db.prepare('SELECT payload_json FROM evidence_deliveries WHERE destination_id=?').all(d.id)
 assert.equal(rows.length,1);assert.equal(rows[0].payload_json.includes('hidden'),false);assert.equal(JSON.parse(rows[0].payload_json).event.entityId,'ops-node')
})
test('failure queues stop retrying after five attempts and allow reviewed retry',async()=>{
 const d=saveEvidenceDestination(config,owner.id),key=queueEvidenceSnapshot(d.id,owner.id).id
 for(let i=0;i<5;i++){run('UPDATE evidence_deliveries SET next_attempt_at=? WHERE id=?','2000-01-01T00:00:00Z',key);await deliverEvidence({limit:25,fetchImpl:async()=>{throw Error('secret receiver failure')}})}
 const row=one('SELECT * FROM evidence_deliveries WHERE id=?',key);assert.equal(row.status,'failed');assert.equal(row.attempts,5);assert.equal(row.last_error.includes('secret receiver failure'),false)
 assert.equal(retryEvidence(key,owner.id).status,'pending');assert.ok(evidenceDeliveries({status:'pending'}).total>0)
})
test('reported collection windows never bridge outages or prove lossless telemetry',()=>{
 const start=new Date(Date.now()-600000),at=seconds=>new Date(start.getTime()+seconds*1000)
 for(const second of [0,30,60])recordCollectionHealth('ops-node','agent-fixture',true,{at:at(second)})
 recordCollectionHealth('ops-node','agent-fixture',false,{at:at(70)});recordCollectionHealth('ops-node','agent-fixture',true,{at:at(80)});recordCollectionHealth('ops-node','agent-fixture',true,{at:at(110)})
 const coverage=collectionCoverage('ops-node',at(0).toISOString(),at(120).toISOString());assert.equal(coverage.coveredMs,90000);assert.ok(coverage.gaps>0);assert.equal(coverage.losslessCaptureEstablished,false)
})
test('rule usage assessment honors resource permissions and absence remains insufficient without coverage',async()=>{
 const policy=id(),version=id(),rule={sourceNodeId:'web',name:'HTTPS',action:'allow',direction:'out',protocol:'TCP',localPort:'Any',remotePort:'443',remoteAddress:'Any',program:'Any',profile:'Any'}
 run('INSERT INTO policies(id,name,owner_user_id) VALUES(?,?,?)',policy,'Usage',owner.id);run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json) VALUES(?,?,1,?,?)',version,policy,json({nodes:[],edges:[]}),json([rule]));run('UPDATE policies SET current_version_id=? WHERE id=?',version,policy)
 run('INSERT INTO policy_assignments(id,policy_id,node_id) VALUES(?,?,?)',id(),policy,'ops-node')
 assert.equal(ruleUsage(policy,{},owner).items[0].assessment,'insufficient-evidence');assert.throws(()=>ruleUsage(policy,{},editor),/not found/)
 const event=id();run("INSERT INTO log_events(id,node_id,event_id,event_time,action,direction,protocol,src_ip,dst_ip,src_port,dst_port) VALUES(?,'ops-node',5156,?,'allow','out','TCP','10.42.0.2','8.8.8.8',50000,443)",event,now())
 const usage=ruleUsage(policy,{},owner);assert.equal(usage.items[0].assessment,'observed-match');assert.equal(usage.items[0].evidenceEventIds[0],event);assert.equal(usage.unusedConclusion,'not-established')
 await auth(supertest(app).get(`/api/v1/policies/${policy}/usage`),editor).expect(404)
})
test('backup and isolated restore preserve vault/MIB evidence and quarantine stale enforcement',async()=>{
 fs.mkdirSync(path.join(dir,'snmp-mibs'),{recursive:true});fs.writeFileSync(path.join(dir,'snmp-mibs','fixture.mib'),'MIB fixture')
 const credential=id(),secret=seal({password:'retained-secret'})
 run('INSERT INTO credentials(id,name,type,username,encrypted_blob,owner_user_id) VALUES(?,?,?,?,?,?)',credential,'Restored vault','local','fixture-user',secret,owner.id)
 run("INSERT INTO agents(id,node_id) VALUES('restore-agent','ops-node')")
 run("INSERT INTO agent_jobs(id,agent_id,type,status,payload_json) VALUES('stale-job','restore-agent','firewall.apply','queued','{}')")
 run("INSERT INTO jit_grants(id,node_id,expires_at) VALUES('expired-on-restore','ops-node','2099-01-01T00:00:00Z')")
  run("INSERT INTO break_glass_sessions(id,node_id,actor_user_id,reason,started_at,expires_at,status) VALUES('restored-breakglass','ops-node',?,'Recovery fixture',?,?,'active')",owner.id,now(),now())
 const backup=path.join(root,'backup'),target=path.join(root,'restored')
 await createRecoveryBackup({dataDir:dir,destination:backup});const manifest=await verifyRecoveryBackup(backup);assert.ok(manifest.files.some(f=>f.name==='snmp-mibs/fixture.mib'))
 await restoreRecoveryBackup({backup,destination:target})
 const Database=(await import('better-sqlite3')).default,restored=new Database(path.join(target,'winfire.db'))
 try{assert.equal(openSealed(restored.prepare('SELECT encrypted_blob FROM credentials WHERE id=?').get(credential).encrypted_blob).password,'retained-secret');assert.equal(restored.prepare("SELECT status FROM agent_jobs WHERE id='stale-job'").get().status,'cancelled');assert.equal(restored.prepare("SELECT expires_at FROM jit_grants WHERE id='expired-on-restore'").get().expires_at,'1970-01-01T00:00:00.000Z');assert.equal(restored.prepare("SELECT value FROM app_settings WHERE key='recovery_review_required'").get().value,'true');assert.equal(restored.prepare('SELECT count(*) n FROM evidence_destinations WHERE enabled=1').get().n,0)}finally{restored.close()}
  const readback=new Database(path.join(target,'winfire.db'),{readonly:true});assert.equal(readback.prepare("SELECT status FROM break_glass_sessions WHERE id='restored-breakglass'").get().status,'recovery-review');readback.close()
  assert.equal(fs.readFileSync(path.join(target,'snmp-mibs','fixture.mib'),'utf8'),'MIB fixture')
  const startup=spawnSync(process.execPath,['api/src/server.js'],{cwd:path.resolve(import.meta.dirname,'../..'),env:{...process.env,DATA_DIR:target,PORT:'0'},encoding:'utf8',timeout:10000})
  assert.notEqual(startup.status,0);assert.match(startup.stderr,/Restored data is quarantined/)
 assert.throws(()=>acknowledgeRecovery(target,'yes'),/acknowledgement/);acknowledgeRecovery(target,'REVIEWED RESTORED HOST STATE')
 assert.equal(one("SELECT status FROM agent_jobs WHERE id='stale-job'").status,'queued')
})
test('backup refuses existing destinations, nested paths, tampering and symlink traversal',async()=>{
 await assert.rejects(()=>createRecoveryBackup({dataDir:dir,destination:dir}),/outside/)
 await assert.rejects(()=>restoreRecoveryBackup({backup:path.join(root,'backup'),destination:dir}),/new, empty/)
 fs.appendFileSync(path.join(root,'backup','snmp-mibs','fixture.mib'),'tampered')
 await assert.rejects(()=>verifyRecoveryBackup(path.join(root,'backup')),/integrity mismatch/)
 fs.symlinkSync(dir,path.join(root,'alias'))
 await assert.rejects(()=>createRecoveryBackup({dataDir:dir,destination:path.join(root,'alias','nested-backup')}),/outside/)
})
