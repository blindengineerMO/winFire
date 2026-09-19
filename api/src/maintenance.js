import {all,one,run} from './db.js'
import {lookupDns} from './connector.js'

const setting=(key,fallback)=>Number(one('SELECT value FROM app_settings WHERE key=?',key)?.value||fallback)

export function observabilitySettings() {
  return {logRetentionDays:setting('log_retention_days',90),dnsRefreshHours:setting('dns_refresh_hours',24)}
}

export function pruneOldEvents(at=new Date()) {
  const cutoff=new Date(at.getTime()-observabilitySettings().logRetentionDays*864e5).toISOString()
  return run('DELETE FROM log_events WHERE datetime(COALESCE(event_time,received_at))<datetime(?)',cutoff).changes
}

export async function refreshDueDns(at=new Date(),limit=25) {
  const cutoff=new Date(at.getTime()-observabilitySettings().dnsRefreshHours*36e5).toISOString()
  const nodes=all('SELECT n.* FROM nodes n LEFT JOIN dns_lookups d ON d.node_id=n.id WHERE d.checked_at IS NULL OR d.checked_at<? ORDER BY COALESCE(d.checked_at,n.created_at),n.id LIMIT ?',cutoff,limit)
  for(const node of nodes)await lookupDns(node)
  return nodes.length
}
