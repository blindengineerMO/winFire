import crypto from 'node:crypto'
import {db,all,one,run,id,now} from './db.js'
import {lookupDns} from './connector.js'

const setting=(key,fallback)=>Number(one('SELECT value FROM app_settings WHERE key=?',key)?.value||fallback)

export function observabilitySettings() {
  return {logRetentionDays:setting('log_retention_days',90),dnsRefreshHours:setting('dns_refresh_hours',24),eventCompactHours:setting('event_compact_hours',24),hideLoopbackEvents:one("SELECT value FROM app_settings WHERE key='hide_loopback_events'")?.value!=='false',ignoreLoopbackIngest:one("SELECT value FROM app_settings WHERE key='ignore_loopback_ingest'")?.value==='true'}
}

export function compactDueEvents(at=new Date(),limit=2000){
  const events=all('SELECT id,action,protocol,src_ip,dst_ip,dst_port,direction,program,event_type FROM log_events WHERE pattern_id IS NULL ORDER BY received_at,id LIMIT ?',limit)
  db.transaction(()=>{
    for(const event of events){
      const values=[event.action,event.protocol,event.src_ip,event.dst_ip,event.dst_port,event.direction,event.program,event.event_type]
      const fingerprint=crypto.createHash('sha256').update(JSON.stringify(values)).digest('hex')
      let pattern=one('SELECT id FROM event_patterns WHERE fingerprint=?',fingerprint)
      if(!pattern){const patternId=id();run('INSERT INTO event_patterns(id,fingerprint,action,protocol,src_ip,dst_ip,dst_port,direction,program,event_type,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',patternId,fingerprint,...values,now());pattern={id:patternId}}
      run('UPDATE log_events SET pattern_id=?,protocol=NULL,src_ip=NULL,dst_ip=NULL,dst_port=NULL,direction=NULL,program=NULL,event_type=NULL WHERE id=?',pattern.id,event.id)
    }
  })()
  return events.length
}

export function runCompactionIfDue(at=new Date(),batchSize=2000,maxBatches=10){
  const last=one("SELECT value FROM app_settings WHERE key='event_compact_last_at'")?.value
  if(last&&Date.parse(last)+observabilitySettings().eventCompactHours*36e5>at.getTime())return {due:false,processed:0,remaining:false}
  let processed=0,remaining=false
  for(let batch=0;batch<maxBatches;batch++){
    const count=compactDueEvents(at,batchSize)
    processed+=count
    if(count<batchSize){remaining=false;break}
    remaining=true
  }
  if(!remaining)run("UPDATE app_settings SET value=? WHERE key='event_compact_last_at'",at.toISOString())
  return {due:true,processed,remaining}
}

export function pruneOldEvents(at=new Date()) {
  const cutoff=new Date(at.getTime()-observabilitySettings().logRetentionDays*864e5).toISOString()
  const removed=run('DELETE FROM log_events WHERE datetime(COALESCE(event_time,received_at))<datetime(?)',cutoff).changes
  run('DELETE FROM event_patterns WHERE NOT EXISTS (SELECT 1 FROM log_events e WHERE e.pattern_id=event_patterns.id)')
  return removed
}

export async function refreshDueDns(at=new Date(),limit=25) {
  const cutoff=new Date(at.getTime()-observabilitySettings().dnsRefreshHours*36e5).toISOString()
  const nodes=all('SELECT n.* FROM nodes n LEFT JOIN dns_lookups d ON d.node_id=n.id WHERE d.checked_at IS NULL OR d.checked_at<? ORDER BY COALESCE(d.checked_at,n.created_at),n.id LIMIT ?',cutoff,limit)
  for(const node of nodes)await lookupDns(node)
  return nodes.length
}
