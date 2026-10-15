import {db,all,one,run,now} from '../db.js'
import {normalizeNetworkProtocol} from '../services/networkMapping.js'

const time='COALESCE(julianday(COALESCE(e.event_time,e.received_at)),0)'
// Associations preserve both sensors' observations. They never establish a unique
// connection, change a verdict, or cross an inventory site boundary.
export function correlateObservation(observationId,{windowSeconds=5}={}){
  if(!Number.isFinite(windowSeconds)||windowSeconds<0||windowSeconds>30)throw new Error('Correlation window must be 0–30 seconds')
  const source=one(`SELECT o.*,n.scope_id,e.src_port,COALESCE(e.action,p.action) action,COALESCE(e.protocol,p.protocol) protocol,
    COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port
    FROM traffic_observations o JOIN telemetry_exporters x ON x.id=o.exporter_id JOIN nodes n ON n.id=x.node_id
    LEFT JOIN log_events e ON e.id=o.event_id LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE o.id=?`,observationId)
  if(!source)return {status:'source-expired',reason:'Observation is no longer retained'}
  const stamp=Date.parse(source.observed_at),metadata=JSON.parse(source.metadata_json)
  const observedScope=typeof metadata.scopeId==='string'?metadata.scopeId:null
  const protocol=normalizeNetworkProtocol(source.protocol)
  const result=(status,reason,extra={})=>({status,reason,...extra})
  if(!observedScope||observedScope!==source.scope_id)return result('insufficient','Original observation scope is missing or the exporter has moved scope; review identity before association')
  if(!source.event_id||!source.src_ip||!source.dst_ip||source.src_port==null||source.dst_port==null||!['TCP','UDP'].includes(normalizeNetworkProtocol(source.protocol))||!Number.isFinite(stamp))return result('insufficient','Retained complete TCP/UDP five-tuple and timestamp are required')
  if(Number(metadata.samplingInterval||metadata.samplingRate||1)>1||metadata.samplingKnown===false||Object.values(metadata.nat||{}).some(v=>v!==null&&v!==undefined&&v!=='')||metadata.natSourceIp||metadata.natDestinationIp)return result('insufficient','Sampled, unknown-sampling or translated tuples require explicit sensor identity evidence')
  const rows=all(`SELECT e.id,${time} event_jd,COALESCE(e.protocol,p.protocol) protocol,e.action
    FROM log_events e JOIN nodes n ON n.id=e.node_id LEFT JOIN event_patterns p ON p.id=e.pattern_id
    WHERE ${time}>=julianday(?) AND ${time}<=julianday(?) AND n.scope_id=?
    AND e.event_id IN (5156,5157,5150,5151) AND e.src_port=?
    AND COALESCE(e.src_ip,p.src_ip)=? AND COALESCE(e.dst_ip,p.dst_ip)=? AND COALESCE(e.dst_port,p.dst_port)=?
    AND UPPER(COALESCE(e.protocol,p.protocol,'')) IN (?,?)
    AND NOT EXISTS(SELECT 1 FROM traffic_observations o WHERE o.event_id=e.id)
    ORDER BY ${time},e.id LIMIT 2`,new Date(stamp-windowSeconds*1000).toISOString(),new Date(stamp+windowSeconds*1000).toISOString(),observedScope,source.src_port,source.src_ip,source.dst_ip,source.dst_port,protocol,protocol==='TCP'?'6':'17')
  if(rows.length!==1)return result(rows.length?'ambiguous':'unmatched',rows.length?'Multiple endpoint observations match; no automatic association':'No retained endpoint observation matches this tuple and time window')
  const match=rows[0]
  if(source.action&&match.action&&source.action!==match.action)return result('conflicting','Sensor verdicts conflict; the observations remain separate')
  return result('associated','One endpoint observation matches the same scoped five-tuple within the time window; association is not proof of a unique connection',{
    endpointEventId:match.id,deltaMs:Math.round((match.event_jd-2440587.5)*86400000-stamp)
  })
}

export function processTrafficCorrelations({limit=25,at=new Date()}={}){
  limit=Math.max(1,Math.min(100,Math.floor(limit)))
  const cursor=Number(one("SELECT value FROM app_settings WHERE key='traffic_correlation_backfill'")?.value||0)
  const backfill=all('SELECT rowid sequence,id FROM traffic_observations WHERE rowid>? ORDER BY rowid LIMIT ?',cursor,limit)
  db.transaction(()=>{
    for(const row of backfill)run('INSERT OR IGNORE INTO traffic_correlations(observation_id,next_attempt_at,updated_at) VALUES(?,?,?)',row.id,at.toISOString(),at.toISOString())
    if(backfill.length)run("UPDATE app_settings SET value=? WHERE key='traffic_correlation_backfill'",String(backfill.at(-1).sequence))
  })()
  const due=all("SELECT * FROM traffic_correlations WHERE status IN ('pending','unmatched') AND attempts<6 AND next_attempt_at<=? ORDER BY next_attempt_at,observation_id LIMIT ?",at.toISOString(),limit)
  for(const row of due){
    const outcome=correlateObservation(row.observation_id),attempts=row.attempts+1
    run('UPDATE traffic_correlations SET status=?,endpoint_event_id=?,endpoint_reference=?,delta_ms=?,reason=?,attempts=?,next_attempt_at=?,updated_at=? WHERE observation_id=?',outcome.status,outcome.endpointEventId||null,outcome.endpointEventId||null,outcome.deltaMs??null,outcome.reason,attempts,new Date(at.getTime()+Math.min(3600,15*2**attempts)*1000).toISOString(),now(),row.observation_id)
  }
  return {processed:due.length,backfilled:backfill.length}
}
