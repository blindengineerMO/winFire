import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-performance-reads-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='performance@example.test'
process.env.BOOTSTRAP_PASSWORD='performance-fixture-password'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db,run}=await import('../src/db.js')
const {dashboardTraffic,closeDashboardTraffic}=await import('../src/services/dashboardTraffic.js')
const {topologyGraph}=await import('../src/services/networkMapping.js')
await bootstrap()
const request=supertest(app)
const login=await request.post('/api/v1/auth/login').send({email:process.env.BOOTSTRAP_EMAIL,password:process.env.BOOTSTRAP_PASSWORD})
const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
test.after(async()=>{await closeDashboardTraffic();db.close();fs.rmSync(dir,{recursive:true,force:true})})
run("INSERT INTO nodes(id,hostname,ip) VALUES('perf-node','Performance fixture','10.1.0.2')")
run("INSERT INTO app_settings(key,value) VALUES('local_asset_cidrs','[\"10.0.0.0/8\"]') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
run("INSERT INTO event_patterns(id,fingerprint,action,protocol,dst_port,program,event_type) VALUES('perf-pattern','perf-pattern','block','TCP',443,'client.exe','firewall')")
const event=db.prepare("INSERT INTO log_events(id,node_id,event_id,action,pattern_id,received_at) VALUES(?,'perf-node',5157,'block','perf-pattern',datetime('now'))")
event.run('perf-event-1')

test('dashboard summary does not depend on traffic aggregation and all sections stay authenticated',async()=>{
  await request.get('/api/v1/reports/dashboard?section=summary').expect(401)
  await auth(request.get('/api/v1/reports/dashboard?section=invalid')).expect(400)
  const summary=await auth(request.get('/api/v1/reports/dashboard?section=summary')).expect(200)
  assert.equal(summary.body.totalNodes,1)
  assert.deepEqual(summary.body.coverageSummary,{assigned:0,uncovered:1,drift:0})
  assert.deepEqual(summary.body.deniedPorts,[])
  assert.equal(summary.body.trafficGeneratedAt,null)
  assert.match(summary.headers['cache-control'],/no-store/)
})

test('read-only traffic worker coalesces concurrent reads and retains compacted event semantics',async()=>{
  const results=await Promise.all(Array.from({length:5},()=>dashboardTraffic()))
  assert.ok(results.every(result=>result.generatedAt===results[0].generatedAt))
  assert.deepEqual(results[0].deniedPorts,[{dst_port:443,count:1}])
  event.run('perf-event-2')
  assert.equal((await dashboardTraffic()).deniedPorts[0].count,1)
})

test('exclusions invalidate traffic cache immediately and cannot reuse an older in-flight visibility result',async()=>{
  await closeDashboardTraffic()
  const before=dashboardTraffic()
  run("INSERT INTO process_exclusions(name,added_at) VALUES('client.exe',datetime('now'))")
  const concurrent=dashboardTraffic()
  for(const result of await Promise.all([before,concurrent]))assert.deepEqual(result.deniedPorts,[])
  run("DELETE FROM process_exclusions WHERE name='client.exe'")
  assert.equal((await dashboardTraffic()).deniedPorts[0].count,2)
  run("INSERT INTO traffic_ignore_rules(id,label,event_id,action,dst_port,fingerprint) VALUES('perf-ignore','Fixture',5157,'block',443,'perf-ignore')")
  assert.deepEqual((await dashboardTraffic()).deniedPorts,[])
  run("DELETE FROM traffic_ignore_rules WHERE id='perf-ignore'")
  assert.equal((await dashboardTraffic()).deniedPorts[0].count,2)
})

test('mapping can omit aggregation, read talkers independently, and load compact picker records',async()=>{
  run("INSERT INTO network_map_pairs(map_key,source_node_id,source_ip,destination_ip,protocol,connection_count,first_seen_at,last_seen_at,updated_at) VALUES('perf-pair','perf-node','10.1.0.2','8.8.8.8','TCP',7,datetime('now'),datetime('now'),datetime('now'))")
  const pairs=await auth(request.get('/api/v1/mapping?includeTalkers=false')).expect(200)
  assert.equal(pairs.body.total,1)
  assert.equal('topTalkers' in pairs.body,false)
  const legacy=await auth(request.get('/api/v1/mapping')).expect(200)
  const talkers=await auth(request.get('/api/v1/mapping/talkers')).expect(200)
  assert.deepEqual(talkers.body.items,legacy.body.topTalkers)
  const options=await auth(request.get('/api/v1/mapping/filter-options?includeNodes=true')).expect(200)
  assert.deepEqual(options.body.nodes,[{id:'perf-node',hostname:'Performance fixture',ip:'10.1.0.2'}])
  await auth(request.get('/api/v1/mapping/talkers?subnet=bad')).expect(400)
})

test('large snapshot windows and oversized SNMP payloads explicitly report truncation',()=>{
  run("INSERT INTO network_table_snapshots(node_id,state_json,collected_at) VALUES('perf-node',?,datetime('now'))",JSON.stringify({padding:'x'.repeat(1048577)}))
  assert.equal(topologyGraph().truncated,true)
  run("DELETE FROM network_table_snapshots WHERE node_id='perf-node'")
  const insertNode=db.prepare('INSERT INTO nodes(id,hostname) VALUES(?,?)')
  const snapshot=db.prepare("INSERT INTO network_table_snapshots(node_id,state_json,collected_at) VALUES(?,'{}',datetime('now'))")
  db.transaction(()=>{for(let i=0;i<102;i++){insertNode.run(`snapshot-${i}`,`Switch ${i}`);snapshot.run(`snapshot-${i}`)}})()
  assert.equal(topologyGraph().truncated,true)
})

test('map rank and uncompacted event reads use indexes without full temporary sorts',()=>{
  const plan=sql=>db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all().map(row=>row.detail).join('\n')
  const topology=plan('SELECT m.* FROM network_map_pairs m ORDER BY connection_count DESC,last_seen_at DESC,map_key LIMIT 3001')
  assert.match(topology,/idx_map_rank/)
  assert.doesNotMatch(topology,/TEMP B-TREE/)
  const compaction=plan('SELECT id FROM log_events INDEXED BY idx_logs_uncompacted WHERE pattern_id IS NULL ORDER BY received_at,id LIMIT 2000')
  assert.match(compaction,/idx_logs_uncompacted/)
})

test('scheduled compaction yields between bounded batches and preserves backlog progress',async()=>{
  const {runCompactionInBackground}=await import('../src/maintenance.js')
  run("DELETE FROM app_settings WHERE key='event_compact_last_at'")
  const insert=db.prepare("INSERT INTO log_events(id,node_id,event_id,action,event_type,protocol,program) VALUES(?,'perf-node',5156,'allow','firewall','TCP','fixture.exe')")
  db.transaction(()=>{for(let i=0;i<100;i++)insert.run(`compact-${i}`)})()
  let yielded=false
  setImmediate(()=>{yielded=true})
  const result=await runCompactionInBackground(new Date(),20,3)
  assert.equal(yielded,true)
  assert.deepEqual(result,{due:true,processed:60,remaining:true})
  assert.equal(db.prepare("SELECT count(*) n FROM log_events WHERE id LIKE 'compact-%' AND pattern_id IS NULL").get().n,40)
  const completed=await runCompactionInBackground(new Date(),20,3)
  assert.equal(completed.processed,40)
  assert.equal(completed.remaining,false)
})
