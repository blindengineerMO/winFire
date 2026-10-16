import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import assert from 'node:assert/strict'
import {createRequire} from 'node:module'
import supertest from 'supertest'

// Always use a disposable fixture; never opens an operator's data directory.
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-view-scale-'))
process.env.DATA_DIR=dir;process.env.NODE_ENV='test'
const rows=Number(process.env.VIEW_BENCHMARK_ROWS||1_000_000)
assert.ok(Number.isInteger(rows)&&rows>=1000)
const {db,run,all}=await import('../api/src/db.js')
const {app}=await import('../api/src/app.js')
const {issueAccess}=await import('../api/src/security.js')
const {dashboardTraffic,closeDashboardTraffic}=await import('../api/src/services/dashboardTraffic.js')
const {reportCoverage,driftSummaryByNode}=await import('../api/src/services/reportCoverage.js')
const {topologyGraph,mappingRows}=await import('../api/src/services/networkMapping.js')
const {visibleFirewallEventSql}=await import('../api/src/processExclusions.js')
const migration=createRequire(import.meta.url)('../api/migrations/122_dashboard_mapping_performance.cjs')
const measure=fn=>{const start=performance.now(),value=fn();return {ms:+(performance.now()-start).toFixed(2),value}}
const asyncMeasure=async fn=>{const start=performance.now(),value=await fn();return {ms:+(performance.now()-start).toFixed(2),value}}
try{
  for(const {name} of all("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='log_events'"))db.exec(`DROP TRIGGER "${name.replaceAll('"','""')}"`)
  run("INSERT INTO app_settings(key,value) VALUES('local_asset_cidrs','[\"10.0.0.0/8\"]') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
  run("INSERT INTO users(id,email,password_hash,role) VALUES('benchmark-owner','benchmark@example.test','fixture','owner')")
  run("INSERT INTO policies(id,name) VALUES('benchmark-policy','Benchmark policy')")
  run("INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json) VALUES('benchmark-version','benchmark-policy',1,'{}','[]')")
  run("UPDATE policies SET current_version_id='benchmark-version' WHERE id='benchmark-policy'")
  const node=db.prepare('INSERT INTO nodes(id,hostname,ip,status) VALUES(?,?,?,?)'),assign=db.prepare("INSERT INTO policy_assignments(id,policy_id,node_id) VALUES(?,'benchmark-policy',?)"),drift=db.prepare("INSERT INTO policy_drift_checks(id,policy_id,version_id,node_id,status,checked_at) VALUES(?,'benchmark-policy','benchmark-version',?,?,?)")
  db.transaction(()=>{for(let i=0;i<1000;i++){
    node.run(`node-${i}`,`Node ${i}`,`10.42.${Math.floor(i/250)}.${i%250+1}`,'reachable');assign.run(`assignment-${i}`,`node-${i}`)
    for(let j=0;j<100;j++)drift.run(`drift-${i}-${j}`,`node-${i}`,i%10===0?'drift':'in-sync',new Date(Date.UTC(2026,9,15,0,0,j)).toISOString())
  }})()
  run("INSERT INTO event_patterns(id,fingerprint,event_type,protocol,dst_port,program) VALUES('pattern','pattern','firewall','TCP',443,'client.exe')")
  const insert=measure(()=>{
    db.prepare(`WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
      INSERT INTO log_events(id,node_id,event_id,action,event_time,received_at,pattern_id)
      SELECT printf('event-%09d',x),'node-'||(x%1000),5157,CASE WHEN x%3=0 THEN 'block' ELSE 'allow' END,'2026-10-15T00:00:00.000Z','2026-10-15T00:00:00.000Z','pattern' FROM n`).run(rows)
    db.prepare(`WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
      INSERT INTO network_map_pairs(map_key,source_node_id,destination_node_id,source_ip,destination_ip,protocol,source_port,connection_count,first_seen_at,last_seen_at,updated_at)
      SELECT printf('pair-%09d',x),'node-'||(x%1000),'node-'||((x+1)%1000),'10.42.'||CAST((x%1000)/250 AS INTEGER)||'.'||(x%250+1),'10.42.'||CAST(((x+1)%1000)/250 AS INTEGER)||'.'||((x+1)%250+1),'TCP',10000+CAST(x/1000 AS INTEGER),x,'2026-10-15T00:00:00.000Z','2026-10-15T00:00:00.000Z','2026-10-15T00:00:00.000Z' FROM n`).run(rows)
  })
  await migration.down({raw:sql=>db.exec(sql)})
  const legacyTopology=measure(()=>all('SELECT m.* FROM network_map_pairs m ORDER BY m.connection_count DESC,m.map_key LIMIT 3001'))
  const legacyDrift=measure(()=>all(`SELECT d.node_id,d.policy_id,d.status FROM policy_drift_checks d JOIN policies p ON p.id=d.policy_id AND p.current_version_id=d.version_id WHERE d.rowid=(SELECT d2.rowid FROM policy_drift_checks d2 WHERE d2.node_id=d.node_id AND d2.policy_id=d.policy_id AND d2.version_id=d.version_id ORDER BY datetime(d2.checked_at) DESC,d2.rowid DESC LIMIT 1)`))
  const legacyTraffic=measure(()=>all(`SELECT COALESCE(e.dst_port,p.dst_port) dst_port,COUNT(*) count FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE e.action='block' AND ${visibleFirewallEventSql()} GROUP BY COALESCE(e.dst_port,p.dst_port) ORDER BY count DESC,dst_port LIMIT 6`))
  const indexStart=performance.now();await migration.up({raw:sql=>db.exec(sql)});db.pragma('optimize = 0x10002');const indexMs=performance.now()-indexStart
  const indexedTopology=measure(()=>all('SELECT m.* FROM network_map_pairs m ORDER BY m.connection_count DESC,m.last_seen_at DESC,m.map_key LIMIT 3001'))
  assert.deepEqual(indexedTopology.value.map(r=>r.map_key),legacyTopology.value.map(r=>r.map_key))
  const driftResult=measure(()=>driftSummaryByNode())
  assert.deepEqual(driftResult.value,new Map(legacyDrift.value.map(row=>[row.node_id,row.status])))
  const coverage=measure(()=>reportCoverage()),graph=measure(()=>topologyGraph()),page=measure(()=>mappingRows({includeTalkers:false})),filtered=measure(()=>topologyGraph({nodeId:'node-1'})),subnet=measure(()=>topologyGraph({subnet:'10.42.0.0/24'}))
  const request=supertest(app),token=issueAccess(db.prepare("SELECT * FROM users WHERE id='benchmark-owner'").get())
  const summary=await asyncMeasure(()=>request.get('/api/v1/reports/dashboard?section=summary').set('Authorization',`Bearer ${token}`).expect(200))
  assert.equal(summary.value.body.totalNodes,1000)
  let maxLoopDelay=0,last=performance.now()
  const timer=setInterval(()=>{const at=performance.now();maxLoopDelay=Math.max(maxLoopDelay,at-last-5);last=at},5)
  const trafficPromise=asyncMeasure(()=>Promise.all(Array.from({length:5},()=>dashboardTraffic())))
  const health=await asyncMeasure(()=>request.get('/api/v1/health').expect(200))
  const traffic=await trafficPromise;clearInterval(timer)
  assert.deepEqual(traffic.value[0].deniedPorts,legacyTraffic.value)
  const cached=await asyncMeasure(()=>dashboardTraffic())
  console.log(JSON.stringify({fixture:{events:rows,mappingPairs:rows,nodes:1000,driftChecks:100000},fixtureInsertMs:insert.ms,indexCreationMs:+indexMs.toFixed(2),legacy:{topologySelectMs:legacyTopology.ms,driftSummaryMs:legacyDrift.ms,blockingTrafficSummaryMs:legacyTraffic.ms},optimized:{topologySelectMs:indexedTopology.ms,driftSummaryMs:driftResult.ms,coverageReportMs:coverage.ms,topologyEndpointProjectionMs:graph.ms,focusedTopologyMs:filtered.ms,subnetTopologyMs:subnet.ms,mappingPageMs:page.ms,dashboardSummaryMs:summary.ms,trafficWorkerColdMs:traffic.ms,trafficCacheMs:cached.ms,concurrentHealthMs:health.ms,eventLoopMaxDelayDuringAnalyticsMs:+maxLoopDelay.toFixed(2)},bounds:{graphNodes:graph.value.nodeCount,graphEdges:graph.value.edgeCount,pageRows:page.value.rows.length},externalRequests:0,note:'Disposable local benchmark, not a deployment latency or sustained fleet-capacity claim.'},null,2))
  assert.ok(indexedTopology.ms<2000&&summary.ms<2000&&health.ms<1000,'Interactive read budget exceeded')
}finally{await closeDashboardTraffic();db.close();fs.rmSync(dir,{recursive:true,force:true})}
