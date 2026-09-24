import {Resolver} from 'node:dns/promises'
import {createHash} from 'node:crypto'
import {db,all,one,run,now} from '../db.js'
import {visibleFirewallEventSql} from '../processExclusions.js'
import {canonicalIp} from './networkBoundary.js'

const bounded=(key,fallback,min,max)=>Math.min(max,Math.max(min,Number(process.env[key])||fallback))
export const dnsPolicy=()=>({positiveHours:bounded('INTERNET_DNS_POSITIVE_HOURS',24,1,8760),negativeHours:bounded('INTERNET_DNS_NEGATIVE_HOURS',1,1,168),timeoutMs:bounded('INTERNET_DNS_TIMEOUT_MS',3000,100,10000),concurrency:bounded('INTERNET_DNS_CONCURRENCY',4,1,16),retentionDays:bounded('INTERNET_PEER_RETENTION_DAYS',90,1,3650)})
export const resolverContext=()=>process.env.INTERNET_DNS_SERVERS?.split(',').map(s=>s.trim()).filter(Boolean).join(',')||'system'
export function retainPeer(ip,at){
  ip=canonicalIp(ip);const context=resolverContext(),id=createHash('sha256').update(context+'\0'+ip).digest('hex')
  run(`INSERT INTO internet_peers(id,ip,resolver_context,first_seen_at,last_seen_at,next_lookup_at) VALUES(?,?,?,?,?,?) ON CONFLICT(ip,resolver_context) DO UPDATE SET first_seen_at=MIN(first_seen_at,excluded.first_seen_at),last_seen_at=MAX(last_seen_at,excluded.last_seen_at)`,id,ip,context,at,at,now())
  return id
}
export function publicPeer(row){
  if(!row)return null
  const {names_json,...rest}=row
  return {...rest,names:JSON.parse(names_json),hostnameSource:'reverse-dns',stale:row.status==='stale'||!!row.checked_at&&Date.parse(row.next_lookup_at)<=Date.now(),cachePolicy:dnsPolicy()}
}
export function peerDetails(id){
  const peer=publicPeer(one('SELECT * FROM internet_peers WHERE id=?',id));if(!peer)throw Object.assign(new Error('External peer not found'),{status:404})
  return {...peer,observedNames:[],history:all('SELECT checked_at,status,names_json,error FROM internet_peer_dns_history WHERE peer_id=? ORDER BY id DESC LIMIT 100',id).map(({names_json,...r})=>({...r,names:JSON.parse(names_json)}))}
}
export function enqueuePeer(id){
  const peer=one('SELECT * FROM internet_peers WHERE id=?',id);if(!peer)throw Object.assign(new Error('External peer not found'),{status:404})
  if(peer.lease_until&&Date.parse(peer.lease_until)>Date.now()||peer.status==='pending'&&(!peer.next_lookup_at||Date.parse(peer.next_lookup_at)<=Date.now()))return {queued:true,coalesced:true}
  if(peer.checked_at&&Date.parse(peer.checked_at)>Date.now()-60000)throw Object.assign(new Error('Wait one minute before requesting another lookup'),{status:429})
  run("UPDATE internet_peers SET next_lookup_at=?,status=CASE WHEN names_json='[]' THEN 'pending' ELSE 'stale' END WHERE id=?",now(),id)
  return {queued:true,coalesced:false}
}
async function reverse(ip,context,timeoutMs){
  const resolver=new Resolver({timeout:timeoutMs,tries:1})
  if(context!=='system')resolver.setServers(context.split(','))
  let timer
  try{return await Promise.race([resolver.reverse(ip),new Promise((_,reject)=>{timer=setTimeout(()=>{reject(Object.assign(new Error('DNS lookup timed out'),{code:'ETIMEOUT'}));resolver.cancel()},timeoutMs)})])}finally{clearTimeout(timer)}
}
export async function processPeerDns({at=new Date(),limit=25,lookup=reverse}={}){
  const policy=dnsPolicy(),stamp=at.toISOString(),lease=new Date(at.getTime()+60000).toISOString()
  const peers=db.transaction(()=>{
    const rows=all(`SELECT d.* FROM internet_peers d WHERE (next_lookup_at IS NULL OR next_lookup_at<=?) AND (lease_until IS NULL OR lease_until<=?) AND EXISTS(SELECT 1 FROM internet_connections c JOIN internet_index_state s ON s.active_revision=c.revision JOIN log_events e ON e.id=c.event_id LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE c.peer_id=d.id AND c.outside=1 AND ${visibleFirewallEventSql()}) ORDER BY next_lookup_at,d.id LIMIT ?`,stamp,stamp,Math.min(100,limit))
    for(const peer of rows)run('UPDATE internet_peers SET lease_until=? WHERE id=?',lease,peer.id)
    return rows
  }).immediate()
  let cursor=0
  async function worker(){while(cursor<peers.length){
    const peer=peers[cursor++];let names=[],status='resolved',error=null,attempts=0,nextHours=policy.positiveHours
    try{names=[...new Set((await lookup(peer.ip,peer.resolver_context,policy.timeoutMs)).map(n=>String(n).toLowerCase().replace(/\.$/,'')).filter(n=>n.length>0&&n.length<=1024))].sort();if(!names.length){status='not-found';nextHours=policy.negativeHours}}
    catch(e){error=String(e.code||'DNS_ERROR').slice(0,80);if(['ENOTFOUND','ENODATA'].includes(e.code)){status='not-found';nextHours=policy.negativeHours}else{names=JSON.parse(peer.names_json);status=names.length?'stale':'error';attempts=peer.attempts+1;nextHours=attempts<=3?Math.min(policy.negativeHours,(2**(attempts-1))/60):policy.negativeHours}}
    const next=new Date(at.getTime()+nextHours*3600000).toISOString()
    db.transaction(()=>{
      // A lease may expire after restart; do not overwrite a newer worker result.
      const changed=run('UPDATE internet_peers SET names_json=?,status=?,error=?,attempts=?,checked_at=?,last_success_at=?,next_lookup_at=?,lease_until=NULL WHERE id=? AND lease_until=?',JSON.stringify(names),status,error,attempts,stamp,status==='resolved'?stamp:peer.last_success_at,next,peer.id,lease).changes
      if(changed)run('INSERT INTO internet_peer_dns_history(peer_id,checked_at,names_json,status,error) VALUES(?,?,?,?,?)',peer.id,stamp,JSON.stringify(names),status,error)
    }).immediate()
  }}
  await Promise.all(Array.from({length:Math.min(peers.length,policy.concurrency)},worker))
  return peers.length
}
export function pruneInternetPeers(at=new Date()){
  const cutoff=new Date(at.getTime()-dnsPolicy().retentionDays*86400000).toISOString()
  run('DELETE FROM internet_peer_dns_history WHERE id IN (SELECT id FROM internet_peer_dns_history WHERE checked_at<? LIMIT 2000)',cutoff)
  return run('DELETE FROM internet_peers WHERE id IN (SELECT p.id FROM internet_peers p WHERE p.last_seen_at<? AND NOT EXISTS(SELECT 1 FROM internet_connections c WHERE c.peer_id=p.id) LIMIT 1000)',cutoff).changes
}
