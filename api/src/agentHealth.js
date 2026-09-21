import {all,run,now,audit} from './db.js'
import {emitNotification} from './notifications.js'

export function sweepAgentHealth(maxSilenceMs=120_000) {
  const candidates=all(`SELECT n.id AS node_id,n.hostname,n.agent_id,a.id agent_record_id,a.revoked_at,a.last_checkin_at,
    COALESCE((SELECT s.poll_seconds FROM agent_poll_settings s WHERE s.target_type='node' AND s.target_id=n.id),
      (SELECT MIN(s.poll_seconds) FROM agent_poll_settings s JOIN node_group_members m ON m.group_id=s.target_id WHERE s.target_type='group' AND m.node_id=n.id),30) poll_seconds
    FROM nodes n LEFT JOIN agents a ON a.id=n.agent_id WHERE n.connection_mode='agent' AND n.status!='unreachable'`)
  const offline=candidates.filter(node=>!node.agent_record_id||node.revoked_at||!node.last_checkin_at||Date.now()-Date.parse(node.last_checkin_at)>Math.max(maxSilenceMs,Number(node.poll_seconds)*2000+30_000))
  for(const node of offline){
    run("UPDATE nodes SET status='unreachable',failures=failures+1 WHERE id=?",node.node_id)
    audit(null,'agent.offline','node',node.node_id,null,{agentId:node.agent_id})
    emitNotification({eventKey:`agent-offline:${node.node_id}:${Date.now()}`,category:'agent_offline',title:'Agent offline',body:`The agent for ${node.hostname||node.node_id} stopped checking in.`,entityType:'node',entityId:node.node_id})
  }
  return offline.length
}
