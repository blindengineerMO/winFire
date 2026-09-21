import {one,all} from './db.js'

export const defaultAgentPollSeconds=30

export function effectiveAgentPollSeconds(nodeId){
  const direct=one("SELECT poll_seconds FROM agent_poll_settings WHERE target_type='node' AND target_id=?",nodeId)
  if(direct)return direct.poll_seconds
  const group=one(`SELECT MIN(s.poll_seconds) poll_seconds FROM agent_poll_settings s
    JOIN node_group_members m ON m.group_id=s.target_id
    WHERE s.target_type='group' AND m.node_id=?`,nodeId)
  return group?.poll_seconds??defaultAgentPollSeconds
}

export function agentPollSettings(){
  return {defaultPollSeconds:defaultAgentPollSeconds,overrides:all(`SELECT s.target_type targetType,s.target_id targetId,s.poll_seconds pollSeconds,
    CASE WHEN s.target_type='node' THEN n.hostname ELSE g.name END targetName
    FROM agent_poll_settings s
    LEFT JOIN nodes n ON s.target_type='node' AND n.id=s.target_id
    LEFT JOIN node_groups g ON s.target_type='group' AND g.id=s.target_id
    WHERE (s.target_type='node' AND n.id IS NOT NULL) OR (s.target_type='group' AND g.id IS NOT NULL)
    ORDER BY s.target_type,targetName`)}
}
