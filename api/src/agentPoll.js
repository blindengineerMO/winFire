import {one,all} from './db.js'

export const defaultAgentPollSeconds=30
export const defaultAgentChannelMode='pull'

export function effectiveAgentPollSeconds(nodeId){
  const direct=one("SELECT poll_seconds FROM agent_poll_settings WHERE target_type='node' AND target_id=?",nodeId)
  if(direct)return direct.poll_seconds
  const group=one(`SELECT MIN(s.poll_seconds) poll_seconds FROM agent_poll_settings s
    JOIN node_group_members m ON m.group_id=s.target_id
    WHERE s.target_type='group' AND m.node_id=?`,nodeId)
  return group?.poll_seconds??defaultAgentPollSeconds
}

export function effectiveAgentChannelMode(nodeId){
  const direct=one("SELECT channel_mode FROM agent_poll_settings WHERE target_type='node' AND target_id=?",nodeId)
  if(direct?.channel_mode==='push'||direct?.channel_mode==='pull')return direct.channel_mode
  const group=one(`SELECT CASE WHEN MAX(CASE WHEN s.channel_mode='push' THEN 1 ELSE 0 END)=1 THEN 'push' ELSE 'pull' END channel_mode
    FROM agent_poll_settings s JOIN node_group_members m ON m.group_id=s.target_id
    WHERE s.target_type='group' AND m.node_id=?`,nodeId)
  return group?.channel_mode||defaultAgentChannelMode
}

export function agentPollSettings(){
  return {defaultPollSeconds:defaultAgentPollSeconds,defaultChannelMode:defaultAgentChannelMode,overrides:all(`SELECT s.target_type targetType,s.target_id targetId,s.poll_seconds pollSeconds,s.channel_mode channelMode,
    CASE WHEN s.target_type='node' THEN n.hostname ELSE g.name END targetName
    FROM agent_poll_settings s
    LEFT JOIN nodes n ON s.target_type='node' AND n.id=s.target_id
    LEFT JOIN node_groups g ON s.target_type='group' AND g.id=s.target_id
    WHERE (s.target_type='node' AND n.id IS NOT NULL) OR (s.target_type='group' AND g.id IS NOT NULL)
    ORDER BY s.target_type,targetName`)}
}
