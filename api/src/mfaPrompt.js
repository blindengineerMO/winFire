import {isIP} from 'node:net'
import dns from 'node:dns/promises'
import {all,one,run,id,now,audit,parse,json} from './db.js'
import {remote,tcpProbe} from './connector.js'
import {sourceMatches} from './mfaPortal.js'
import {mfaPromptSettings} from './mfaPromptSettings.js'
import {matchesProcess,visibleFirewallEventSql} from './processExclusions.js'
import {emitNotification} from './notifications.js'

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
function lsaDeniedPair(event,segment,targetAddresses){
  if(Number(event.event_id)!==4625||!['0xc000015b','c000015b'].includes(String(event.logon_status||event.logon_sub_status||'').toLowerCase()))return null
  if(!segment.account_sid||String(event.account_sid).toLowerCase()!==String(segment.account_sid).toLowerCase())return null
  if(Number(segment.port)===3389&&String(event.logon_type)!=='10'||Number(segment.port)===22&&String(event.logon_type)!=='3')return null
  const source=String(event.src_ip||'').replace(/^::ffff:/,''),sourcePort=Number(event.src_port)
  if(!isIP(source)||!Number.isInteger(sourcePort)||sourcePort<1||sourcePort>65535)return null
  const target=[event.dst_ip,...targetAddresses].map(value=>String(value||'').replace(/^::ffff:/,'')).find(value=>isIP(value)&&value!==source)
  return target?{sourceIp:source,targetIp:target,sourcePort,lsaDenied:true}:null
}
const adAddressCache=new Map()
async function sourceNodeForIp(ip,targetId){
  const candidates=all("SELECT * FROM nodes WHERE id<>? AND connection_mode IN ('agentless','agent') AND COALESCE(ad_enabled,1)=1 AND COALESCE(ad_missing,0)=0",targetId)
  const known=candidates.filter(node=>addresses(node).has(ip))
  if(known.length>1)return {ambiguous:true}
  if(known.length===1)return {node:known[0]}
  const adCandidates=candidates.filter(node=>node.ad_guid&&node.fqdn)
  if(adCandidates.length>500)return {unresolved:true}
  const matched=[]
  for(let offset=0;offset<adCandidates.length;offset+=32){
    const found=await Promise.all(adCandidates.slice(offset,offset+32).map(async node=>{
      const key=node.fqdn.toLowerCase(),cached=adAddressCache.get(key)
      if(cached?.expires>Date.now())return cached.ips.includes(ip)?node:null
      let ips=[]
      try{ips=(await dns.lookup(node.fqdn,{all:true})).map(item=>item.address)}catch{}
      adAddressCache.set(key,{ips,expires:Date.now()+5*60_000})
      return ips.includes(ip)?node:null
    }))
    matched.push(...found.filter(Boolean))
    if(matched.length>1)return {ambiguous:true}
  }
  return matched.length===1?{node:matched[0]}:{unknown:true}
}
async function sourceTransport(node){
  if(['winrm','winrms'].includes(node.transport))return node
  const host=node.fqdn||node.ip||node.hostname
  const [secure,plain]=await Promise.all([tcpProbe(host,5986,2000),tcpProbe(host,5985,2000)])
  if(secure.status==='open')return {...node,transport:'winrms'}
  if(plain.status==='open')return {...node,transport:'winrm'}
  throw new Error('Source workstation WinRM is unreachable')
}
function queueAgentPrompt(sourceNode,payload){
  const agent=one('SELECT id,last_checkin_at FROM agents WHERE id=? AND node_id=? AND revoked_at IS NULL',sourceNode.agent_id,sourceNode.id)
  if(!agent)throw new Error('Source agent is not enrolled')
  if(!agent.last_checkin_at||Date.parse(agent.last_checkin_at)<Date.now()-5*60_000)throw new Error('Source agent is offline')
  const jobId=id()
  run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',jobId,agent.id,'mfa.prompt',json(payload))
  return jobId
}
async function failOpenForUncontrolledSource(promptId,segment,target,pair,reason){
  const settings=mfaPromptSettings()
  if(settings.failureMode!=='open'||segment.fail_open||segment.account_sid||segment.source_process||segment.fallback_to_logged_on_user)return null
  const grantId=id(),expiresAt=new Date(Date.now()+settings.failOpenMinutes*60_000).toISOString()
  let applyRunId=null,ruleStarted=false
  try{
    const ports=[segment.port,...(parse(segment.extra_ports)||[])]
    const preflight=await remote(target,'jit_preflight',{port:segment.port,ports})
    if(!preflight?.safe)throw new Error('Target firewall gate is not ready for a scoped fallback grant')
    applyRunId=id()
    run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',applyRunId,target.id,'running')
    const started=await remote(target,'jit_start',{grantId,sourceIp:pair.sourceIp,port:segment.port,ports,expiresAt})
    if(started?.active!==true)throw new Error('The node did not confirm the fallback firewall rule')
    ruleStarted=true
    run('INSERT INTO jit_grants(id,segment_id,node_id,src_ip,dst_port,ports_json,rule_path,grant_type,ttl_seconds,granted_at,expires_at,prompt_id,fallback_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',grantId,segment.id,target.id,pair.sourceIp,segment.port,JSON.stringify(ports),`WinFireSecure:JIT:${grantId}`,'portal_firewall',settings.failOpenMinutes*60,now(),expiresAt,promptId,reason)
    run("UPDATE mfa_prompt_events SET status='fallback_open',error=? WHERE id=?",reason,promptId)
    audit(null,'mfa.prompt.fail_open','jit-grant',grantId,null,{segmentId:segment.id,nodeId:target.id,sourceIp:pair.sourceIp,ports,expiresAt,reason})
    run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',JSON.stringify({operation:'mfa_fail_open',grantId,sourceIp:pair.sourceIp,ports,expiresAt,reason}),now(),applyRunId)
    return {id:promptId,status:'fallback_open',grantId,expiresAt,applyRunId}
  }catch(error){
    let cleanupFailed=false
    if(ruleStarted||applyRunId)try{await remote(target,'jit_end',{grantId})}catch{cleanupFailed=true}
    if(applyRunId)run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?',cleanupFailed||/timed? out|timeout|connection|unreachable/i.test(error.message)?'unknown':'failed',error.message,now(),applyRunId)
    audit(null,'mfa.prompt.fail_open.failed','mfa-prompt',promptId,null,{reason,error:error.message})
    return null
  }
}
export function promptUrl(promptId){
  const base=new URL(process.env.PUBLIC_BASE_URL||'')
  if(base.protocol!=='https:'||base.username||base.password||base.search||base.hash)throw new Error('Automatic MFA browser prompts require an HTTPS PUBLIC_BASE_URL')
  const url=new URL(`/mfa/${promptId}`,base)
  return url.href
}
export async function processBlockedMfaEvent(event,segment,target){
  const promptId=id(),expiresAt=new Date(Date.now()+5*60_000).toISOString()
  const local=addresses(target),pair=remoteIpFromBlockedEvent(event,local)||lsaDeniedPair(event,segment,local)
  const sourceMatch=pair?await sourceNodeForIp(pair.sourceIp,target.id):null
  const sourceNode=sourceMatch?.node||null
  const insert=(status,error=null)=>{
    run('INSERT OR IGNORE INTO mfa_prompt_events(id,segment_id,target_node_id,source_node_id,log_event_id,source_ip,status,error,expires_at) VALUES(?,?,?,?,?,?,?,?,?)',promptId,segment.id,target.id,sourceNode?.id||null,event.id,pair?.sourceIp||null,status,error,expiresAt)
    return {id:promptId,status,error}
  }
  if(!pair)return insert('skipped','Denied event does not identify one source and target address')
  if(!Number.isInteger(pair.sourcePort)||pair.sourcePort<1||pair.sourcePort>65535)return insert('skipped','Blocked event is missing a valid source port')
  if(!parse(segment.allowed_upns)?.length&&!segment.entra_group_id)return insert('skipped','No operators or directory group are assigned to this MFA segment')
  if(segment.fail_open)return insert('skipped','This segment uses fail-open mode and does not require an MFA prompt')
  if(segment.source_process&&!matchesProcess(event.program,segment.source_process))return insert('skipped','The captured firewall process does not match this segment source-process restriction')
  if(segment.account_sid&&!one('SELECT 1 FROM segment_lsa_baselines WHERE segment_id=? AND node_id=? AND account_sid=?',segment.id,target.id,segment.account_sid))return insert('skipped','The account SID segment does not have an enforced LSA deny baseline on this target')
  let inScope=false
  try{inScope=sourceMatches(pair.sourceIp,segment.source_ip)}catch(error){return insert('skipped',`Invalid segment source scope: ${error.message}`)}
  if(!inScope)return insert('skipped','Source IP is outside the segment scope')
  if(sourceMatch?.ambiguous)return insert('skipped','Source IP matches more than one managed workstation')
  if(sourceMatch?.unresolved)return insert('skipped','AD inventory is too large to resolve this source safely during a prompt')
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
  emitNotification({eventKey:`mfa-access:${promptId}`,category:'mfa_access_request',title:`MFA access requested for ${target.hostname}`,body:`A connection from ${pair.sourceIp} to TCP ${segment.port} was denied${pair.lsaDenied?' by the Windows logon-right gate':''}. Complete MFA within five minutes to open temporary access.`,entityType:'mfa-prompt',entityId:promptId,recipientEmails:parse(segment.allowed_upns)||[]})
  const applyRunId=id()
  run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',applyRunId,sourceNode.id,'running')
  audit(null,'mfa.prompt.launch.start','node',sourceNode.id,null,{promptId,runId:applyRunId,targetNodeId:target.id})
  if(sourceNode.connection_mode==='agent'){
    try{
      const jobId=queueAgentPrompt(sourceNode,{promptId,url,sourceIp:pair.sourceIp,sourcePort:pair.sourcePort,targetIp:pair.targetIp,port:segment.port,applyRunId})
      audit(null,'mfa.prompt.queued','node',sourceNode.id,null,{promptId,runId:applyRunId,jobId,targetNodeId:target.id})
      return {id:promptId,status:'queued',jobId,runId:applyRunId}
    }catch(error){
      run('UPDATE mfa_prompt_events SET status=?,error=? WHERE id=?','failed',error.message,promptId)
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',error.message,now(),applyRunId)
      audit(null,'mfa.prompt.queue.failed','node',sourceNode.id,null,{promptId,runId:applyRunId,error:error.message})
      return {id:promptId,status:'failed',error:error.message}
    }
  }
  let attempted=false
  try{
    const reachable=await sourceTransport(sourceNode)
    attempted=true
    const result=await remote(reachable,'prompt_browser',{promptId,url,sourceIp:pair.sourceIp,sourcePort:pair.sourcePort,targetIp:pair.targetIp,port:segment.port})
    if(reachable.transport!==sourceNode.transport)run('UPDATE nodes SET transport=? WHERE id=?',reachable.transport,sourceNode.id)
    if(!result?.opened){
      run('UPDATE mfa_prompt_events SET status=?,error=? WHERE id=?','skipped',result?.reason||'No interactive browser session was confirmed',promptId)
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',result?.reason||'No interactive browser session was confirmed',now(),applyRunId)
      audit(null,'mfa.prompt.launch.failed','node',sourceNode.id,null,{promptId,runId:applyRunId,reason:result?.reason||'No interactive browser session was confirmed'})
      return {id:promptId,status:'skipped',error:result?.reason}
    }
    run('UPDATE mfa_prompt_events SET status=?,opened_at=?,opened_user=?,opened_session_id=?,opened_process_id=?,source_event_record_id=? WHERE id=?','opened',now(),result.user||null,result.sessionId||null,result.processId||null,result.sourceEventRecordId||null,promptId)
    run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json({operation:'prompt_browser',promptId,sessionId:result.sessionId,processId:result.processId}),now(),applyRunId)
    audit(null,'mfa.prompt.opened','mfa-prompt',promptId,null,{segmentId:segment.id,targetNodeId:target.id,sourceNodeId:sourceNode.id,sourceIp:pair.sourceIp,sessionId:result.sessionId,runId:applyRunId})
    return {id:promptId,status:'opened',runId:applyRunId}
  }catch(error){
    run('UPDATE mfa_prompt_events SET status=?,error=? WHERE id=?','failed',error.message,promptId)
    const status=attempted?'unknown':'failed'
    run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?',status,error.message,now(),applyRunId)
    audit(null,'mfa.prompt.failed','mfa-prompt',promptId,null,{segmentId:segment.id,targetNodeId:target.id,sourceNodeId:sourceNode.id,runId:applyRunId,error:error.message})
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
    const rows=all(`SELECT e.id,e.node_id,e.event_id,e.action,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,e.src_port,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,e.event_time,e.received_at,e.account_sid event_account_sid,e.logon_type,e.logon_status,e.logon_sub_status,
        s.id segment_id,s.port,s.source_ip,s.allowed_upns,s.entra_group_id,s.portal_enabled,s.auto_prompt_enabled,s.mode,s.ttl_minutes,s.policy_id,
        s.account_sid segment_account_sid,s.source_process,s.fallback_to_logged_on_user,s.fail_open,
        COALESCE(e.program,p.program) program
      FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id
      JOIN nodes n ON n.id=e.node_id
      JOIN identity_segments s ON (s.node_id=e.node_id OR s.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=e.node_id))
      WHERE ${visibleFirewallEventSql()} AND datetime(e.received_at)>=datetime(?) AND datetime(COALESCE(e.event_time,e.received_at))>=datetime(?) AND s.portal_enabled=1 AND s.auto_prompt_enabled=1 AND s.mode='agentless'
        AND n.connection_mode='agentless' AND n.transport IN ('winrm','winrms') AND n.firewall_state<>'learning'
        AND ((e.event_id=5157 AND e.action='block' AND COALESCE(e.dst_port,p.dst_port)=s.port)
          OR (e.event_id=4625 AND lower(COALESCE(e.logon_status,e.logon_sub_status,'')) IN ('0xc000015b','c000015b') AND e.account_sid=s.account_sid
            AND ((e.logon_type='10' AND s.port=3389) OR (e.logon_type='3' AND s.port=22))
            AND EXISTS(SELECT 1 FROM segment_lsa_baselines b WHERE b.segment_id=s.id AND b.node_id=e.node_id AND b.account_sid=e.account_sid)))
        AND NOT EXISTS(SELECT 1 FROM mfa_prompt_events m WHERE m.log_event_id=e.id AND m.segment_id=s.id)
      ORDER BY e.received_at DESC,e.id DESC LIMIT ?`,threshold,threshold,limit)
    for(const row of rows){
      const target=one('SELECT * FROM nodes WHERE id=?',row.node_id)
      if(!target)continue
      await processBlockedMfaEvent({...row,account_sid:row.event_account_sid},{id:row.segment_id,port:row.port,source_ip:row.source_ip,allowed_upns:row.allowed_upns,entra_group_id:row.entra_group_id,policy_id:row.policy_id,account_sid:row.segment_account_sid,source_process:row.source_process,fallback_to_logged_on_user:row.fallback_to_logged_on_user,fail_open:row.fail_open},target)
      processed++
    }
    return {processed}
  }finally{sweeping=false}
}
