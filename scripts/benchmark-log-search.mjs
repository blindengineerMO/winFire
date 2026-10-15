import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import assert from 'node:assert/strict'
import {createRequire} from 'node:module'
import {searchLogEvents} from '../api/src/logSearch.js'
import {visibleFirewallEventSql} from '../api/src/processExclusions.js'

// Retrieval benchmark only. Never opens the operator's database.
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-log-scale-'))
process.env.DATA_DIR=dir
const {db}=await import('../api/src/db.js')
const count=Number(process.env.LOG_BENCHMARK_ROWS||1_000_000)
assert.ok(Number.isInteger(count)&&count>=1000)
const measure=fn=>{const start=performance.now(),value=fn();return {ms:Number((performance.now()-start).toFixed(2)),value}}
try{
  // Disable background enqueue triggers in this disposable retrieval fixture.
  for(const {name} of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='log_events'").all())db.exec(`DROP TRIGGER "${name.replaceAll('"','""')}"`)
  db.exec("INSERT INTO event_patterns(id,fingerprint,event_type,protocol,src_ip,dst_ip,dst_port,direction,program) VALUES('bench-pattern','bench-pattern','firewall','TCP','192.0.2.1','198.51.100.1',443,'out','client.exe')")
  const node=db.prepare('INSERT INTO nodes(id,hostname,ip) VALUES(?,?,?)'),facts=db.prepare("INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,datetime('now'))")
  for(let i=0;i<100;i++){node.run(`node-${i}`,`Node ${i}`,'192.0.2.1');facts.run(`node-${i}`,JSON.stringify({padding:'x'.repeat(16000)}))}
  const inserted=measure(()=>db.prepare(`WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
    INSERT INTO log_events(id,node_id,record_id,event_id,action,event_time,pattern_id,event_type,protocol,src_ip,dst_ip,dst_port,direction,program)
    SELECT printf('event-%09d',x),'node-'||(x%100),x,CASE WHEN x%50=0 THEN 4624 ELSE 5156 END,CASE WHEN x%50=0 THEN 'logon' WHEN x%3=0 THEN 'block' ELSE 'allow' END,
    strftime('%Y-%m-%dT%H:%M:%fZ','2026-09-19',printf('+%f seconds',x/10.0)),CASE WHEN x%50<>0 AND x%10<>0 THEN 'bench-pattern' END,
    CASE WHEN x%50=0 THEN 'logon' WHEN x%10=0 THEN 'firewall' END,CASE WHEN x%10=0 THEN 'TCP' END,CASE WHEN x%10=0 THEN '192.0.2.1' END,CASE WHEN x%10=0 THEN '198.51.100.1' END,CASE WHEN x%10=0 THEN 443 END,CASE WHEN x%10=0 THEN 'out' END,CASE WHEN x%10=0 THEN 'client.exe' END FROM n`).run(count))
  const migration=createRequire(import.meta.url)('../api/migrations/118_event_search_indexes.cjs')
  await migration.down({raw:sql=>db.exec(sql)})
  const legacyFrom=`FROM log_events e LEFT JOIN nodes n ON n.id=e.node_id LEFT JOIN node_facts f ON f.node_id=e.node_id LEFT JOIN event_patterns p ON p.id=e.pattern_id LEFT JOIN directory_users ad ON ad.sid=e.account_sid LEFT JOIN local_accounts la ON la.node_id=e.node_id AND la.sid=e.account_sid AND la.missing=0 LEFT JOIN sid_resolutions sr ON sr.node_id=e.node_id AND sr.sid=e.account_sid WHERE ${visibleFirewallEventSql()}`
  const legacy=measure(()=>{
    const total=db.prepare(`SELECT COUNT(*) total ${legacyFrom}`).get().total
    const rows=db.prepare(`SELECT e.*,f.snapshot_json ${legacyFrom} ORDER BY julianday(COALESCE(e.event_time,e.received_at)) DESC,e.id DESC LIMIT 100`).all()
    return {total,ids:rows.map(row=>row.id)}
  })
  const start=performance.now();await migration.up({raw:sql=>db.exec(sql)});db.pragma('optimize = 0x10002');const indexMs=performance.now()-start
  const query={pagination:'cursor',includeTotal:'false',hideLoopback:'false'}
  const first=measure(()=>searchLogEvents(db,query))
  assert.deepEqual(first.value.items.map(row=>row.id),legacy.value.ids)
  const next=measure(()=>searchLogEvents(db,{...query,cursor:first.value.nextCursor}))
  assert.ok(next.value.items.every(row=>!first.value.items.some(item=>item.id===row.id)))
  const deepAnchor=db.prepare('SELECT id,COALESCE(julianday(COALESCE(event_time,received_at)),0) time FROM log_events ORDER BY COALESCE(julianday(COALESCE(event_time,received_at)),0) DESC,id DESC LIMIT 1 OFFSET ?').get(Math.floor(count*.9))
  const token=JSON.parse(Buffer.from(first.value.nextCursor,'base64url').toString());Object.assign(token,deepAnchor)
  const deep=measure(()=>searchLogEvents(db,{...query,cursor:Buffer.from(JSON.stringify(token)).toString('base64url')}))
  const filtered=measure(()=>searchLogEvents(db,{...query,nodeId:'node-1',action:'block',eventType:'firewall'}))
  console.log(JSON.stringify({rows:count,fixtureInsertMs:inserted.ms,indexCreationMs:Number(indexMs.toFixed(2)),legacyFirstPageWithTotalMs:legacy.ms,cursorFirstPageMs:first.ms,cursorNextPageMs:next.ms,cursorAt90PercentMs:deep.ms,nodeActionFilteredPageMs:filtered.ms,pageSize:first.value.items.length,speedup:Number((legacy.ms/first.ms).toFixed(1))},null,2))
  assert.equal(deep.value.items.length,100)
  assert.ok(first.ms<2000&&next.ms<2000&&deep.ms<2000,'Indexed retrieval exceeded 2 seconds')
}finally{db.close();fs.rmSync(dir,{recursive:true,force:true})}
