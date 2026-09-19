import {all,run,now,audit} from './db.js'
import {emitNotification} from './notifications.js'

export function sweepAgentHealth(maxSilenceMs=120_000) {
  const cutoff=new Date(Date.now()-maxSilenceMs).toISOString()
  const offline=all(`SELECT n.id AS node_id,n.hostname,n.agent_id FROM nodes n LEFT JOIN agents a ON a.id=n.agent_id WHERE n.connection_mode='agent' AND n.status!='unreachable' AND (a.id IS NULL OR a.revoked_at IS NOT NULL OR a.last_checkin_at IS NULL OR a.last_checkin_at<?)`,cutoff)
  for(const node of offline){
    run("UPDATE nodes SET status='unreachable',failures=failures+1 WHERE id=?",node.node_id)
    audit(null,'agent.offline','node',node.node_id,null,{agentId:node.agent_id})
    emitNotification({eventKey:`agent-offline:${node.node_id}:${Date.now()}`,category:'agent_offline',title:'Agent offline',body:`The agent for ${node.hostname||node.node_id} stopped checking in.`,entityType:'node',entityId:node.node_id})
  }
  return offline.length
}
