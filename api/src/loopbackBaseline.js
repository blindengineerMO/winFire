import {all,one,run,id,now,audit,json} from './db.js'
import {applyRules} from './connector.js'

export const loopbackPolicyId='system-loopback'
export const loopbackGroup=`WinFireSecure:${loopbackPolicyId}`
export const loopbackRules=['in','out'].map(direction=>({name:`WinFire loopback ${direction} IPv4`,remoteAddress:'127.0.0.0/255.0.0.0',group:loopbackGroup,action:'allow',direction,protocol:'Any',localPort:'Any',remotePort:'Any',program:'Any',profile:'Any'}))

export async function ensureLoopbackBaseline(node){
  const prior=one('SELECT * FROM node_loopback_baseline WHERE node_id=?',node.id)
  if(prior?.status==='applied')return prior
  if(prior?.status==='queued'){
    const job=one('SELECT status FROM agent_jobs WHERE id=?',prior.job_id)
    if(job?.status==='queued'||job?.status==='leased')return prior
  }
  run('INSERT INTO node_loopback_baseline(node_id,status,last_attempt_at) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET status=excluded.status,last_attempt_at=excluded.last_attempt_at,last_error=NULL',node.id,'running',now())
  try{
    if(node.connection_mode==='agent'){
      const agent=one('SELECT * FROM agents WHERE id=? AND revoked_at IS NULL',node.agent_id)
      if(!agent)throw new Error('No active enrolled agent')
      const jobId=id()
      run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',jobId,agent.id,'policy.apply',json({policyId:loopbackPolicyId,group:loopbackGroup,rules:loopbackRules,loopbackBaseline:true}))
      run("UPDATE node_loopback_baseline SET status='queued',job_id=? WHERE node_id=?",jobId,node.id)
      audit(null,'node.loopback.queued','node',node.id,null,{jobId})
      return {status:'queued',jobId}
    }
    const diff=await applyRules(node,loopbackPolicyId,loopbackRules)
    run("UPDATE node_loopback_baseline SET status='applied',applied_at=?,last_error=NULL WHERE node_id=?",now(),node.id)
    audit(null,'node.loopback.applied','node',node.id,null,{diff})
    return {status:'applied',diff}
  }catch(error){
    run("UPDATE node_loopback_baseline SET status='failed',last_error=? WHERE node_id=?",error.message,node.id)
    audit(null,'node.loopback.failed','node',node.id,null,{error:error.message})
    return {status:'failed',error:error.message}
  }
}

export async function sweepLoopbackBaseline(){
  const nodes=all(`SELECT n.* FROM nodes n LEFT JOIN node_loopback_baseline b ON b.node_id=n.id
    WHERE (b.node_id IS NULL OR b.status IN ('failed','queued') AND datetime(b.last_attempt_at)<=datetime('now','-15 minutes'))
      AND COALESCE(n.ad_enabled,1)=1 ORDER BY n.created_at LIMIT 5`)
  for(const node of nodes)await ensureLoopbackBaseline(node)
}
