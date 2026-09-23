import {all,one,run,id,now,audit} from './db.js'
import {registerHost} from './networkDiscovery.js'

const MAX_BATCH=32
const RETRY_LIMIT=5
const retryAt=attempt=>new Date(Date.now()+Math.min(60,Math.max(1,2**attempt))*60_000).toISOString()

export function passiveDiscoverySummary(){
  const counts=all('SELECT status,COUNT(*) count FROM passive_discovery_candidates GROUP BY status')
  return {queued:Number(counts.find(row=>row.status==='queued')?.count||0),processing:Number(counts.find(row=>row.status==='processing')?.count||0),registered:Number(counts.find(row=>row.status==='registered')?.count||0),failed:Number(counts.find(row=>row.status==='failed')?.count||0),total:counts.reduce((sum,row)=>sum+Number(row.count),0)}
}
export function passiveDiscoveryRows({status=null,limit=100}={}){
  const safeLimit=Math.min(500,Math.max(1,Number(limit)||100))
  const where=status? 'WHERE p.status=?':'',args=status?[status]:[]
  return all(`SELECT p.*,s.hostname source_hostname,n.hostname node_hostname FROM passive_discovery_candidates p JOIN nodes s ON s.id=p.source_node_id LEFT JOIN nodes n ON n.id=p.node_id ${where} ORDER BY CASE p.status WHEN 'queued' THEN 0 WHEN 'processing' THEN 1 WHEN 'failed' THEN 2 ELSE 3 END,p.last_seen_at DESC LIMIT ?`,...args,safeLimit)
}
async function processCandidate(candidate,{register=registerHost,actorId=null}={}){
  const claimed=run("UPDATE passive_discovery_candidates SET status='processing',attempts=attempts+1,updated_at=? WHERE id=? AND status='queued' AND (next_attempt_at IS NULL OR datetime(next_attempt_at)<=datetime(?))",now(),candidate.id,now())
  if(!claimed.changes)return null
  const attempt=Number(candidate.attempts||0)+1
  try{
    const result=await register(candidate.ip,`passive:${candidate.id}`,'arp-passive',{mac:candidate.mac,hostname:candidate.hostname})
    if(result?.nodeId)run("UPDATE passive_discovery_candidates SET status='registered',node_id=?,last_error=NULL,next_attempt_at=NULL,updated_at=? WHERE id=?",result.nodeId,now(),candidate.id)
    else run("UPDATE passive_discovery_candidates SET status='failed',last_error=?,next_attempt_at=?,updated_at=? WHERE id=?",'Discovery registration returned no node',attempt>=RETRY_LIMIT?null:retryAt(attempt),now(),candidate.id)
    audit(actorId,'network-discovery.passive.register','passive-discovery',candidate.id,null,{ip:candidate.ip,nodeId:result?.nodeId||null,sourceNodeId:candidate.source_node_id,livenessMethod:'arp-passive'})
    return result
  }catch(error){
    const message=String(error.message||error).slice(0,500)
    run("UPDATE passive_discovery_candidates SET status=?,last_error=?,next_attempt_at=?,updated_at=? WHERE id=?",attempt>=RETRY_LIMIT?'failed':'queued',message,attempt>=RETRY_LIMIT?null:retryAt(attempt),now(),candidate.id)
    audit(actorId,'network-discovery.passive.failed','passive-discovery',candidate.id,null,{ip:candidate.ip,error:message,attempt})
    return {ip:candidate.ip,error:message}
  }
}
export async function processPassiveDiscovery({limit=MAX_BATCH,register=registerHost,actorId=null}={}){
  // A process restart must not strand a candidate claimed by a worker that no
  // longer exists. Ten minutes is longer than normal DNS/WinRM onboarding but
  // keeps the queue self-healing.
  const recoveryTime=now()
  run("UPDATE passive_discovery_candidates SET status='queued',next_attempt_at=NULL,updated_at=? WHERE status='processing' AND datetime(updated_at)<=datetime(?,'-10 minutes')",recoveryTime,recoveryTime)
  const rows=passiveDiscoveryRows({status:'queued',limit})
  const results=[]
  for(const candidate of rows)results.push(await processCandidate(candidate,{register,actorId}))
  return {processed:results.filter(Boolean).length,results,summary:passiveDiscoverySummary()}
}
