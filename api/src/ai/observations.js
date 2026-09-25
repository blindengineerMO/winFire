import {db,one,all,run,id,now} from '../db.js'
import {visibleFirewallEventSql} from '../processExclusions.js'
import {connectionEndpoints} from '../services/internetConnections.js'
import {configuredCidrs,canonicalIp} from '../services/networkBoundary.js'
import {matchService,seedCatalog} from './catalog.js'
import {settings} from './reporters.js'
import {queue} from './ingestion.js'
const expired=at=>Date.parse(at)<Date.now()-settings().retentionDays*86400000
const stamp=raw=>Number.isFinite(Date.parse(raw))?new Date(raw).toISOString():now()
export function retainObservation(input){
 const prior=one('SELECT * FROM ai_network_observations WHERE source=? AND source_id=?',input.source,input.source_id)
 const row={id:prior?.id||id(),source:input.source,source_id:input.source_id,node_id:input.node_id||null,collector_node_id:input.collector_node_id||null,observed_at:stamp(input.observed_at),received_at:prior?.received_at||now(),hostname:input.hostname||null,peer_ip:input.peer_ip||null,program:input.program||null,process_id:input.process_id??null,process_guid:input.process_guid||null,process_started_at:input.process_started_at||null,trace_id:input.trace_id||null,request_id:input.request_id||null,action:input.action||'observed',provider:input.rule?.provider||null,service:input.rule?.service||null,role:input.rule?.role||null,category:input.rule&&['auth','update','telemetry','shared'].includes(input.rule.role)?'supporting':input.category||'suspected',confidence:input.confidence||'low',rule_id:input.rule?.id||null,rule_version:input.rule?.version||null,evidence_json:JSON.stringify(input.evidence||{}),source_expired:0}
 // Preserve the classification originally made; enrichment is an additional evidence revision.
 if(prior){const old=JSON.parse(prior.evidence_json);row.evidence_json=JSON.stringify({...input.evidence,originalClassification:old.originalClassification||{ruleId:prior.rule_id,version:prior.rule_version,category:prior.category,hostname:prior.hostname,at:prior.received_at}})}
 const keys=Object.keys(row);run(`INSERT INTO ai_network_observations(${keys.join(',')}) VALUES(${keys.map(()=>'?').join(',')}) ON CONFLICT(id) DO UPDATE SET ${keys.filter(k=>k!=='id').map(k=>`${k}=excluded.${k}`).join(',')}`,...Object.values(row));correlateObservation(row);return row
}
function removeObservation(source,sourceId){run('DELETE FROM ai_network_observations WHERE source=? AND source_id=?',source,sourceId)}
function projectBrowser(sourceId){const e=one('SELECT e.*,d.node_id FROM internet_events e JOIN internet_extension_devices d ON d.id=e.device_id WHERE e.id=?',sourceId);if(!e)return run("UPDATE ai_network_observations SET source_expired=1 WHERE source='browser' AND source_id=?",sourceId);if(expired(e.observed_at))return removeObservation('browser',sourceId);const rule=matchService(e.hostname);if(!rule)return removeObservation('browser',sourceId);return retainObservation({source:'browser',source_id:sourceId,node_id:e.node_id,observed_at:e.observed_at,hostname:e.hostname,action:e.action,rule,category:'observed',confidence:'high',evidence:{source:'enrolled-browser-host',deviceId:e.device_id,dnsCoverage:'not-required',association:'domain-only',ruleSnapshot:rule}})}
const firewallSelect=`SELECT e.*,COALESCE(e.action,p.action) action,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,COALESCE(e.program,p.program) program,COALESCE(e.event_type,p.event_type) event_type FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id`
function projectFirewall(sourceId){
 const e=one(firewallSelect+' WHERE e.id=? AND '+visibleFirewallEventSql(),sourceId)
 if(!e){if(one('SELECT id FROM log_events WHERE id=?',sourceId))return removeObservation('firewall',sourceId);return run("UPDATE ai_network_observations SET source_expired=1 WHERE source='firewall' AND source_id=?",sourceId)}
 if(expired(e.event_time))return removeObservation('firewall',sourceId)
 if(e.event_type!=='firewall'&&![5150,5151,5156,5157].includes(e.event_id))return
 const node=one('SELECT n.*,f.snapshot_json FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id WHERE n.id=?',e.node_id)||{},endpoint=connectionEndpoints(e,node,configuredCidrs());if(!endpoint.peer)return
 const forwarded=['switch','router','firewall'].includes(node.device_type)||node.transport==='snmp',workload=forwarded?null:e.node_id
 const at=stamp(e.event_time),dns=workload?all('SELECT d.* FROM ai_dns_observations d WHERE node_id=? AND observed_at<=? AND expires_at>? AND (process_id IS NULL OR process_id=?) AND EXISTS(SELECT 1 FROM json_each(d.answers_json) j WHERE j.value=?) ORDER BY observed_at DESC LIMIT 101',workload,at,at,e.process_id??null,canonicalIp(endpoint.peer)):[]
 const names=[...new Set(dns.map(d=>d.hostname))],ptr=all('SELECT names_json,checked_at,status FROM internet_peers WHERE ip=? ORDER BY checked_at DESC LIMIT 3',canonicalIp(endpoint.peer))
 let host=null,rule=null,category='suspected',confidence='low',reason='No suitable hostname evidence'
 if(names.length===1&&dns.length<=100){host=names[0];rule=matchService(host);category='observed';confidence='medium';reason='Contemporaneous DNS answer; process lifetime not independently verified'}
 else if(names.length>1||dns.length>100){reason='Several contemporaneous DNS names share the address'}
 if(!rule&&names.length===0){for(const row of ptr){for(const name of JSON.parse(row.names_json)){const match=matchService(name);if(match){host=name;rule=match;reason='Reverse DNS only; requested hostname unknown';break}}if(rule)break}}
 const candidateRules=names.length>1?names.map(matchService).filter(Boolean):[]
 const processHint=/(?:^|[\\/])(?:claude|ollama|copilot)(?:\.exe)?$/i.test(String(e.program||''))
 if(!rule&&!processHint&&!candidateRules.length)return removeObservation('firewall',sourceId)
 if(!rule&&!candidateRules.length)reason='Known AI application name; service and operation unknown'
 return retainObservation({source:'firewall',source_id:sourceId,node_id:workload,collector_node_id:e.node_id,observed_at:at,peer_ip:endpoint.peer,program:String(e.program||'').slice(0,1024),process_id:e.process_id,hostname:host,rule,category,confidence,action:e.action, evidence:{reason,attribution:endpoint.attribution,dnsCoverage:dns.length?'available':'missing',dnsIds:dns.map(d=>d.id),dnsNames:names,candidateRules,ptr:ptr.map(p=>({names:JSON.parse(p.names_json),at:p.checked_at,status:p.status})),ruleSnapshot:rule,tuple:{source:endpoint.source,destination:endpoint.destination,sourcePort:endpoint.sourcePort,destinationPort:endpoint.destinationPort,protocol:e.protocol,direction:endpoint.direction}}})
}
export function correlateObservation(observation){
 run('DELETE FROM ai_usage_evidence WHERE observation_id=?',observation.id)
 if(!observation.node_id||observation.action==='block'||!['observed','suspected'].includes(observation.category))return
 const delta=settings().correlationWindowSeconds*1000,at=Date.parse(observation.observed_at)
 const rows=all(`SELECT * FROM ai_usage_events WHERE node_id=? AND observed_at<=? AND COALESCE(ended_at,observed_at)>=? AND ((? IS NOT NULL AND trace_id=?) OR (? IS NOT NULL AND request_id=?) OR (? IS NOT NULL AND hostname=?)) ORDER BY CASE WHEN trace_id=? OR request_id=? THEN 0 ELSE 1 END,observed_at DESC LIMIT 101`,observation.node_id,new Date(at+delta).toISOString(),new Date(at-delta).toISOString(),observation.trace_id,observation.trace_id,observation.request_id,observation.request_id,observation.hostname,observation.hostname,observation.trace_id,observation.request_id)
 const candidates=rows.filter(e=>{
  const explicit=(observation.trace_id&&e.trace_id===observation.trace_id)||(observation.request_id&&e.request_id===observation.request_id)
  const process=observation.process_guid&&observation.process_guid===e.process_guid||observation.process_id&&e.process_id===observation.process_id&&observation.process_started_at&&e.process_started_at===observation.process_started_at
  const lifetimeConflict=observation.process_started_at&&e.process_started_at&&observation.process_started_at!==e.process_started_at
  const guidConflict=observation.process_guid&&e.process_guid&&observation.process_guid!==e.process_guid
  const pid=observation.process_id!=null&&e.process_id===observation.process_id
  const missingProcess=observation.process_id==null||e.process_id==null
  return !lifetimeConflict&&!guidConflict&&(explicit||(process||pid||missingProcess)&&e.hostname&&e.hostname===observation.hostname)
 })
 const explicitMatches=candidates.filter(e=>observation.trace_id&&e.trace_id===observation.trace_id||observation.request_id&&e.request_id===observation.request_id),targets=explicitMatches.length?explicitMatches:candidates
 for(const e of targets.slice(0,100)){const explicit=!!((observation.trace_id&&e.trace_id===observation.trace_id)||(observation.request_id&&e.request_id===observation.request_id));run('INSERT OR IGNORE INTO ai_usage_evidence VALUES(?,?,?,?)',e.id,observation.id,explicit?'matching-request-or-trace':observation.process_guid||observation.process_started_at?'process-lifetime-host-and-time':observation.process_id!=null&&e.process_id!=null?'pid-host-and-time-lifetime-unknown':'node-host-time-process-unknown',rows.length<=100&&targets.length===1&&explicit?'linked':'candidate')}
}
export function processAiWork({limit=100}={}){
 if(!settings().enabled)return {paused:true};seedCatalog();const cap=Math.max(1,Math.min(1000,limit));let processed=0
 return db.transaction(()=>{
  const revision=one('SELECT COALESCE(max(id),0) n FROM ai_rule_history').n
  if(one('SELECT rule_revision FROM ai_worker_state WHERE id=1').rule_revision!==revision)run('UPDATE ai_worker_state SET rule_revision=?,firewall_cursor=0,browser_cursor=0,enrichment_cursor=0 WHERE id=1',revision)
  const jobs=all('SELECT * FROM ai_work_queue ORDER BY queued_at LIMIT ?',cap)
  for(const job of jobs){
   if(job.kind==='firewall')projectFirewall(job.source_id)
   if(job.kind==='browser')projectBrowser(job.source_id)
   if(job.kind==='usage'){const e=one('SELECT * FROM ai_usage_events WHERE id=?',job.source_id);if(e?.node_id){const w=settings().correlationWindowSeconds*1000,at=Date.parse(e.observed_at),end=Date.parse(e.ended_at||e.observed_at);for(const o of all('SELECT * FROM ai_network_observations WHERE node_id=? AND observed_at BETWEEN ? AND ? LIMIT 200',e.node_id,new Date(at-w).toISOString(),new Date(end+w).toISOString()))correlateObservation(o)}}
   if(job.kind==='dns'){const d=one('SELECT * FROM ai_dns_observations WHERE id=?',job.source_id);if(d){const first=one('SELECT min(rowid) n FROM log_events WHERE node_id=? AND event_time BETWEEN ? AND ?',d.node_id,d.observed_at,d.expires_at)?.n;if(first)run('UPDATE ai_worker_state SET firewall_cursor=min(firewall_cursor,?) WHERE id=1',first-1)}}
   run('DELETE FROM ai_work_queue WHERE kind=? AND source_id=?',job.kind,job.source_id);processed++
  }
  // Durable cursors discover retained events without scanning the entire log in a request.
  for(const [table,kind,column] of [['log_events','firewall','firewall_cursor'],['internet_events','browser','browser_cursor']]){const cursor=one(`SELECT ${column} n FROM ai_worker_state WHERE id=1`).n,rows=all(`SELECT rowid cursor,id FROM ${table} WHERE rowid>? ORDER BY rowid LIMIT ?`,cursor,cap);for(const r of rows){if(kind==='firewall')projectFirewall(r.id);else projectBrowser(r.id)}if(rows.length)run(`UPDATE ai_worker_state SET ${column}=? WHERE id=1`,rows.at(-1).cursor);processed+=rows.length}
  // Revisit retained observations in bounded slices for PTR/catalog enrichment and expiry.
  const state=one('SELECT * FROM ai_worker_state WHERE id=1'),rows=all('SELECT rowid cursor,source,source_id FROM ai_network_observations WHERE rowid>? ORDER BY rowid LIMIT ?',state.enrichment_cursor,Math.min(cap,50))
  for(const r of rows){if(r.source==='firewall')projectFirewall(r.source_id);if(r.source==='browser')projectBrowser(r.source_id)}
  run('UPDATE ai_worker_state SET enrichment_cursor=?,last_success_at=?,last_error=NULL WHERE id=1',rows.length?rows.at(-1).cursor:0,now())
  return {processed,backlog:one('SELECT count(*) n FROM ai_work_queue').n}
 }).immediate()
}
export function resetAiBackfill(){run('UPDATE ai_worker_state SET firewall_cursor=0,browser_cursor=0,enrichment_cursor=0 WHERE id=1');return {queued:true}}
export function pruneAi(at=new Date()){
 const cutoff=new Date(at.getTime()-settings().retentionDays*86400000).toISOString()
 return db.transaction(()=>{const counts={};for(const [table,column] of [['ai_usage_events','observed_at'],['ai_network_observations','observed_at'],['ai_dns_observations','observed_at'],['ai_receipts','received_at']])counts[table]=run(`DELETE FROM ${table} WHERE rowid IN (SELECT rowid FROM ${table} WHERE ${column}<? LIMIT 1000)`,cutoff).changes;return counts})()
}
