import {db, one, all, run, id, now, audit, json, parse} from './db.js'
import {applyRules, remote} from './connector.js'

export class IFirewallConnector {
  constructor(node){this.node=node}
  get supportsLocalUserSid(){return false}
  get supportsTcpProbe(){return false}
  get readsSecurityEvents(){return false}
  get queuedReadback(){return false}
  async applyPolicy(){throw new Error('Firewall apply is unavailable for this connector')}
  async readRules(){throw new Error('Firewall readback is unavailable for this connector')}
  queueReadback(){throw new Error('Queued readback is unavailable for this connector')}
  queuePolicyRemoval(){throw new Error('Policy removal is unavailable for this connector')}
  async eventCursor(){return null}
  async probeEvents(){return []}
  async probeTcp(){throw new Error('TCP probe is unavailable for this connector')}
}

class RemoteFirewallConnector extends IFirewallConnector {
  get readsSecurityEvents(){return true}
  async applyPolicy({policyId,rules}){
    return {status:'success',diff:await applyRules(this.node,policyId,rules)}
  }
  async readRules(group){
    const response=await remote(this.node,'rules',{group})
    return Array.isArray(response)?response:response?[response]:[]
  }
  async eventCursor(){return remote(this.node,'event_cursor')}
  async probeEvents(){return remote(this.node,'events_probe')}
}

export class WinRmConnector extends RemoteFirewallConnector {
  get supportsLocalUserSid(){return !/^(?:5\.[12]\.|6\.[01]\.|windows (?:xp|vista|7\b|server 2003|server 2008))/i.test(String(this.node.os_version||''))}
  get supportsTcpProbe(){return true}
  async probeTcp(args){return remote(this.node,'tcp_probe',args)}
}

export class WmiConnector extends RemoteFirewallConnector {}

export class AgentConnector extends IFirewallConnector {
  get queuedReadback(){return true}
  agent(purpose='node'){
    const agent=one('SELECT * FROM agents WHERE id=? AND revoked_at IS NULL',this.node.agent_id)
    if(!agent)throw new Error(`No active enrolled agent for ${purpose}`)
    return agent
  }
  async applyPolicy({policyId,versionId,rules,runId,context={}}){
    const agent=this.agent(),jobId=id()
    run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',jobId,agent.id,'policy.apply',json({applyRunId:runId,policyId,versionId,group:`WinFireSecure:${policyId}`,rules,...context}))
    return {status:'queued',jobId}
  }
  async readRules(){this.agent('firewall readback');return null}
  queueReadback({driftCheckId,policyId,versionId}){
    const agent=this.agent()
    run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',id(),agent.id,'policy.read',json({driftCheckId,policyId,versionId,group:`WinFireSecure:${policyId}`}))
  }
  queuePolicyRemoval({policy,assignment,actorId}){
    const agent=this.agent('firewall cleanup')
    const pending=all("SELECT * FROM agent_jobs WHERE agent_id=? AND type='policy.apply' AND status IN ('queued','leased') AND json_extract(payload_json,'$.policyId')=?",agent.id,policy.id)
    if(pending.some(job=>job.status==='leased'))throw Object.assign(new Error('Wait for the current agent policy apply job before removing this assignment'),{status:409})
    const runId=id(),jobId=id()
    db.transaction(()=>{
      for(const job of pending){
        run("UPDATE agent_jobs SET status='failed',error='Superseded by policy unassignment',finished_at=? WHERE id=?",now(),job.id)
        const oldRunId=parse(job.payload_json)?.applyRunId
        if(oldRunId)run("UPDATE policy_apply_runs SET status='failed',error='Superseded by policy unassignment',finished_at=? WHERE id=?",now(),oldRunId)
      }
      run('INSERT INTO policy_apply_runs(id,policy_id,version_id,node_id,status) VALUES(?,?,?,?,?)',runId,policy.id,policy.current_version_id,this.node.id,'queued')
      run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',jobId,agent.id,'policy.apply',json({applyRunId:runId,policyId:policy.id,versionId:policy.current_version_id,group:`WinFireSecure:${policy.id}`,rules:[],removalAssignmentId:assignment.id}))
      run('UPDATE policy_assignments SET removal_job_id=? WHERE id=?',jobId,assignment.id)
      audit(actorId,'policy.unassign.queued','policy',policy.id,assignment,{assignmentId:assignment.id,nodeId:this.node.id,jobId})
    })()
    return {jobId,nodeId:this.node.id}
  }
}

export function firewallConnectorFor(node){
  if(node.connection_mode==='agent')return new AgentConnector(node)
  if(node.transport==='wmi')return new WmiConnector(node)
  if(!node.transport||['winrm','winrms'].includes(node.transport))return new WinRmConnector(node)
  throw new Error(`No firewall connector for ${node.hostname||node.id}`)
}

export async function applyManagedRules(node,policyId,rules){
  const result=await firewallConnectorFor(node).applyPolicy({policyId,rules})
  if(result.status!=='success')throw new Error('Firewall update requires immediate host readback')
  return result.diff
}
