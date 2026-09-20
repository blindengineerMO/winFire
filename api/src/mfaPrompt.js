import {isIP} from 'node:net'
import {all,one,run,id,now,audit,parse} from './db.js'
import {remote,tcpProbe} from './connector.js'
import {sourceMatches} from './mfaPortal.js'
import {mfaPromptSettings} from './mfaPromptSettings.js'

function addresses(node){
  const values=new Set([node.ip,node.fqdn,node.hostname])
  const facts=parse(one('SELECT snapshot_json FROM node_facts WHERE node_id=?',node.id)?.snapshot_json)||{}
  for(const adapter of facts.network||[])for(const address of adapter.ipAddresses||[])values.add(address)
  for(const item of parse(one('SELECT forward_result FROM dns_lookups WHERE node_id=?',node.id)?.forward_result)||[])values.add(item.address)
  return new Set([...values].filter(value=>isIP(value)))
}
export function remoteIpFromBlockedEvent(event,targetAddresses){
  if(Number(event.event_id)!==5157||event.action!=='block'||event.direction!=='in'||event.protocol!=='TCP')return null
  const source=String(event.src_ip||'').replace(/^::ffff:/,''),destination=String(event.dst_ip||'').replace(/^::ffff:/,'')
  if(!isIP(source)||!isIP(destination))return null
  const localSource=targetAddresses.has(source),localDestination=targetAddresses.has(destination)
  if(localSource===localDestination)return null
  const sourcePort=event.src_port==null?null:Number(event.src_port)
  return localSource?{sourceIp:destination,targetIp:source,sourcePort}:{sourceIp:source,targetIp:destination,sourcePort}
}
function sourceNodeForIp(ip,targetId){
  const matches=all("SELECT * FROM nodes WHERE id<>? AND connection_mode='agentless' AND COALESCE(ad_enabled,1)=1 AND COALESCE(ad_missing,0)=0",targetId).filter(node=>addresses(node).has(ip))
  return matches.length===1?matches[0]:null
}
async function sourceTransport(node){
  if(['winrm','winrms'].includes(node.transport))return node
  const host=node.fqdn||node.ip||node.hostname
  const [secure,plain]=await Promise.all([tcpProbe(host,5986,2000),tcpProbe(host,5985,2000)])
  if(secure.status==='open')return {...node,transport:'winrms'}
  if(plain.status==='open')return {...node,transport:'winrm'}
  throw new Error('Source workstation WinRM is unreachable')
}
async function failOpenForUncontrolledSource(promptId,segment,target,pair,reason){
  const settings=mfaPromptSettings()
  if(settings.failureMode!=='open')return null
  const grantId=id(),expiresAt=new Date(Date.now()+settings.failOpenMinutes*60_000).toISOString()
  try{
    const preflight=await remote(target,'jit_preflight',{port:segment.port})
    if(!preflight?.safe)throw new Error('Target firewall gate is not ready for a scoped fallback grant')
    await remote(target,'jit_start',{grantId,sourceIp:pair.sourceIp,port:segment.port,expiresAt})
    run('INSERT INTO jit_grants(id,segment_id,node_id,src_ip,dst_port,rule_path,grant_type,ttl_seconds,granted_at,expires_at,prompt_id,fallback_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',grantId,segment.id,target.id,pair.sourceIp,segment.port,`WinFireSecure:JIT:${grantId}`,'portal_firewall',settings.failOpenMinutes*60,now(),expiresAt,promptId,reason)
    run("UPDATE mfa_prompt_events SET status='fallback_open',error=? WHERE id=?",reason,promptId)
    audit(null,'mfa.prompt.fail_open','jit-grant',grantId,null,{segmentId:segment.id,nodeId:target.id,sourceIp:pair.sourceIp,port:segment.port,expiresAt,reason})
    return {id:promptId,status:'fallback_open',grantId,expiresAt}
  }catch(error){
    try{await remote(target,'jit_end',{grantId})}catch{}
    audit(null,'mfa.prompt.fail_open.failed','mfa-prompt',promptId,null,{reason,error:error.message})
    return null
  }
}
function promptUrl(promptId){
  const base=new URL(process.env.PUBLIC_BASE_URL||'')
  if(base.protocol!=='https:'||base.username||base.password||base.search||base.hash)throw new Error('Automatic MFA browser prompts require an HTTPS PUBLIC_BASE_URL')
  const url=new URL('/identity',base);url.searchParams.set('prompt',promptId)
  return url.href
}
export async function processBlockedMfaEvent(event,segment,target){
  const promptId=id(),expiresAt=new Date(Date.now()+5*60_000).toISOString()
  const local=addresses(target),pair=remoteIpFromBlockedEvent(event,local)
  const sourceNode=pair?sourceNodeForIp(pair.sourceIp,target.id):null
  const insert=(status,error=null)=>{
    run('INSERT OR IGNORE INTO mfa_prompt_events(id,segment_id,target_node_id,source_node_id,log_event_id,source_ip,status,error,expires_at) VALUES(?,?,?,?,?,?,?,?,?)',promptId,segment.id,target.id,sourceNode?.id||null,event.id,pair?.sourceIp||null,status,error,expiresAt)
    return {id:promptId,status,error}
  }
  if(!pair)return insert('skipped','Blocked event does not identify exactly one target-local address')
  if(!Number.isInteger(pair.sourcePort)||pair.sourcePort<1||pair.sourcePort>65535)return insert('skipped','Blocked event is missing a valid source port')
  if(!parse(segment.allowed_upns)?.length)return insert('skipped','No operators are assigned to this MFA segment')
  let inScope=false
  try{inScope=sourceMatches(pair.sourceIp,segment.source_ip)}catch(error){return insert('skipped',`Invalid segment source scope: ${error.message}`)}
  if(!inScope)return insert('skipped','Source IP is outside the segment scope')
  if(segment.policy_id){
    const policy=one('SELECT current_version_id FROM policies WHERE id=?',segment.policy_id)
    const assigned=one('SELECT id FROM policy_assignments WHERE policy_id=? AND (node_id=? OR node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?)) LIMIT 1',segment.policy_id,target.id,target.id)
    const applied=one('SELECT version_id,status FROM policy_apply_runs WHERE policy_id=? AND node_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1',segment.policy_id,target.id)
    if(!policy||!assigned||!applied||applied.version_id!==policy.current_version_id||applied.status!=='success')return insert('skipped','Linked MFA policy is not assigned and synced')
  }
  const recent=one("SELECT id FROM mfa_prompt_events WHERE segment_id=? AND target_node_id=? AND source_ip=? AND status IN ('opened','pending','failed','skipped','fallback_open','consuming','consumed') AND datetime(created_at)>datetime(?) LIMIT 1",segment.id,target.id,pair.sourceIp,new Date(Date.now()-5*60_000).toISOString())
  if(recent)return insert('suppressed','A recent prompt already covers this source and resource')
  if(!sourceNode){
    insert('skipped','Source IP does not identify one managed or AD discovered workstation')
    return await failOpenForUncontrolledSource(promptId,segment,target,pair,'Source workstation is not in managed or Active Directory inventory')||{id:promptId,status:'skipped'}
  }
  let url
  try{url=promptUrl(promptId)}catch(error){return insert('skipped',error.message)}
  insert('pending')
  try{
    const reachable=await sourceTransport(sourceNode)
    const result=await remote(reachable,'prompt_browser',{promptId,url,sourceIp:pair.sourceIp,sourcePort:pair.sourcePort,targetIp:pair.targetIp,port:segment.port})
    if(!result?.opened){
      run('UPDATE mfa_prompt_events SET status=?,error=? WHERE id=?','skipped',result?.reason||'No interactive browser session was confirmed',promptId)
      return {id:promptId,status:'skipped',error:result?.reason}
    }
    run('UPDATE mfa_prompt_events SET status=?,opened_at=?,opened_user=?,opened_session_id=?,opened_process_id=?,source_event_record_id=? WHERE id=?','opened',now(),result.user||null,result.sessionId||null,result.processId||null,result.sourceEventRecordId||null,promptId)
    audit(null,'mfa.prompt.opened','mfa-prompt',promptId,null,{segmentId:segment.id,targetNodeId:target.id,sourceNodeId:sourceNode.id,sourceIp:pair.sourceIp,sessionId:result.sessionId})
    return {id:promptId,status:'opened'}
  }catch(error){
    run('UPDATE mfa_prompt_events SET status=?,error=? WHERE id=?','failed',error.message,promptId)
    audit(null,'mfa.prompt.failed','mfa-prompt',promptId,null,{segmentId:segment.id,targetNodeId:target.id,sourceNodeId:sourceNode.id,error:error.message})
    if(/WinRM|WSMan|timed? out|timeout|connect|refused|unreachable|401|unauthorized|authentication/i.test(error.message)){
      const fallback=await failOpenForUncontrolledSource(promptId,segment,target,pair,`Source workstation cannot be controlled over WinRM: ${error.message.slice(0,180)}`)
      if(fallback)return fallback
    }
    return {id:promptId,status:'failed',error:error.message}
  }
}
let sweeping=false
export async function sweepMfaPrompts(limit=25){
  if(sweeping)return {processed:0,reason:'running'}
  sweeping=true
  let processed=0
  try{
    const threshold=new Date(Date.now()-3*60_000).toISOString()
    const rows=all(`SELECT e.id,e.node_id,e.event_id,e.action,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,e.src_port,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,e.event_time,e.received_at,
        s.id segment_id,s.port,s.source_ip,s.allowed_upns,s.portal_enabled,s.auto_prompt_enabled,s.mode,s.ttl_minutes,s.policy_id
      FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id
      JOIN nodes n ON n.id=e.node_id
      JOIN identity_segments s ON (s.node_id=e.node_id OR s.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=e.node_id))
      WHERE e.event_id=5157 AND e.action='block' AND datetime(e.received_at)>=datetime(?) AND datetime(COALESCE(e.event_time,e.received_at))>=datetime(?) AND s.portal_enabled=1 AND s.auto_prompt_enabled=1 AND s.mode='agentless'
        AND n.connection_mode='agentless' AND n.transport IN ('winrm','winrms') AND n.firewall_state<>'learning'
        AND COALESCE(e.dst_port,p.dst_port)=s.port AND NOT EXISTS(SELECT 1 FROM mfa_prompt_events m WHERE m.log_event_id=e.id AND m.segment_id=s.id)
      ORDER BY e.received_at DESC,e.id DESC LIMIT ?`,threshold,threshold,limit)
    for(const row of rows){
      const target=one('SELECT * FROM nodes WHERE id=?',row.node_id)
      if(!target)continue
      await processBlockedMfaEvent(row,{id:row.segment_id,port:row.port,source_ip:row.source_ip,allowed_upns:row.allowed_upns,policy_id:row.policy_id},target)
      processed++
    }
    return {processed}
  }finally{sweeping=false}
}
