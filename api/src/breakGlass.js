export function normalizeProfileSnapshot(value) {
  if(!Array.isArray(value)||value.length!==3)return null
  const profiles=value.map(item=>({Name:String(item?.Name??item?.name??''),Enabled:item?.Enabled??item?.enabled}))
  if(new Set(profiles.map(item=>item.Name)).size!==3||profiles.some(item=>!['Domain','Private','Public'].includes(item.Name)||typeof item.Enabled!=='boolean'))return null
  return profiles
}

export function publicBreakGlass(session) {
  if(!session)return null
  const {profile_snapshot_json,agent_job_id,...record}=session
  return {...record,agentJobId:agent_job_id||null}
}
