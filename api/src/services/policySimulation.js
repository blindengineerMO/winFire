import {remote} from '../connector.js'
import {createHash} from 'node:crypto'
import {z} from 'zod'
import {compilePolicy,scheduleIsActive} from '../../../packages/shared/index.js'
import {db,all,one,run,id,now,audit} from '../db.js'
import {canWriteResource,canReadResource} from '../access.js'
import {isLocalAssetNode,subnetMatcher,canonicalIp} from './networkBoundary.js'
import {nodeCoverage} from './capabilities.js'
const digest=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex'),parse=v=>JSON.parse(v||'null'),fail=(message,status=400)=>{throw Object.assign(new Error(message),{status})}
export const simulationInput=z.object({graph:z.object({nodes:z.array(z.any()).max(1000),edges:z.array(z.any()).max(4000)}).optional(),baseVersionId:z.string().nullable(),nodeIds:z.array(z.string()).min(1).max(100),from:z.string().datetime({offset:true}),to:z.string().datetime({offset:true}),kind:z.enum(['historical','observe']).default('historical')}).strict()
export const targetsHash=nodes=>digest({memberships:all('SELECT group_id,node_id FROM node_group_members ORDER BY group_id,node_id'),assignments:all('SELECT policy_id,node_id,node_group_id FROM policy_assignments ORDER BY policy_id,node_id,node_group_id'),nodes:nodes.map(nodeId=>({nodeId,hostContext:one('SELECT captured_at FROM policy_host_context WHERE node_id=?',nodeId),node:one('SELECT scope_id,transport,platform,firewall_backend,connection_mode,ip,fqdn,agent_id FROM nodes WHERE id=?',nodeId),groups:all('SELECT group_id FROM node_group_members WHERE node_id=? ORDER BY group_id',nodeId),policies:all('SELECT DISTINCT p.id,p.current_version_id FROM policies p JOIN policy_assignments a ON a.policy_id=p.id WHERE a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?) ORDER BY p.id',nodeId,nodeId)}))})
function policyAccess(policyId,user,write=false){const p=one('SELECT * FROM policies WHERE id=?',policyId);if(!p)fail('Policy not found',404);if(!(write?canWriteResource:canReadResource)(user,'policy',p))fail('Insufficient policy permission',403);return p}
export function queueSimulation(policyId,data,user){
  const p=policyAccess(policyId,user,true),q=simulationInput.parse(data)
  if(one("SELECT count(*) n FROM policy_simulations WHERE status IN ('queued','running','observing')").n>=100)fail('The simulation queue is full; wait for an evaluation to finish or cancel an active run',429)
  if(q.baseVersionId!==p.current_version_id)fail('The policy changed. Reload the current version before simulating.',409)
  const from=Date.parse(q.from),to=Date.parse(q.to)
  if(to<=from||to-from>30*86400000||q.kind==='historical'&&to>Date.now()+60000||q.kind==='observe'&&(from<Date.now()-60000||to>Date.now()+86400000))fail('Choose at most 30 days of history, or an observe-only window starting now and ending within 24 hours')
  const nodeIds=[...new Set(q.nodeIds)].sort(),nodes=nodeIds.map(key=>one('SELECT * FROM nodes WHERE id=?',key))
  if(nodes.some(n=>!n||!isLocalAssetNode(n)))fail('Every target must be an existing asset inside its configured network scope')
  const version=p.current_version_id?one('SELECT * FROM policy_versions WHERE id=?',p.current_version_id):null,graph=q.graph||parse(version?.graph_json)||{nodes:[],edges:[]},rules=compilePolicy(graph,policyId)
  const snapshot={policyId,baseVersionId:p.current_version_id,graph,rules,baselineRules:parse(version?.rules_compiled_json)||[],nodeIds,nodes:nodes.map(n=>({id:n.id,hostname:n.hostname,firewallContext:hostContext(n.id),platform:n.platform,osName:n.os_name,transport:n.transport,coverage:nodeCoverage(n)})),mode:'policy-change-impact',modelVersion:2}
  const key=id(),high=one('SELECT COALESCE(MAX(rowid),0) n FROM log_events').n
  if(q.kind==='historical'&&one(`SELECT COUNT(*) n FROM log_events WHERE node_id IN (${nodeIds.map(()=>'?').join(',')}) AND COALESCE(event_time,received_at)>=? AND COALESCE(event_time,received_at)<=?`,...nodeIds,q.from,q.to).n>100000)fail('More than 100,000 events match. Narrow the targets or time window.',413)
  db.transaction(()=>{
  run('INSERT INTO policy_simulations(id,policy_id,kind,status,snapshot_json,snapshot_hash,target_hash,from_at,to_at,high_water,cursor,requested_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',key,policyId,q.kind,'queued',JSON.stringify(snapshot),digest(snapshot),targetsHash(nodeIds),new Date(from).toISOString(),new Date(to).toISOString(),high,q.kind==='observe'?high:0,user.id,now())
    if(q.kind==='historical'){
      const events=readEvents({nodeIds,from:new Date(from).toISOString(),to:new Date(to).toISOString(),high,limit:100001})
      if(events.length>100000)fail('More than 100,000 events match; narrow the window',413)
      const put=db.prepare('INSERT INTO policy_simulation_inputs(simulation_id,sequence,event_json) VALUES(?,?,?)')
      const hash=createHash('sha256')
      for(const event of events){const payload=JSON.stringify(event);put.run(key,event.sequence,payload);hash.update(payload)}
      run('UPDATE policy_simulations SET evidence_hash=? WHERE id=?',hash.digest('hex'),key)
    }
  })()
  audit(user.id,'policy.simulation.queue','policy-simulation',key,null,{policyId,nodeIds,kind:q.kind,from:q.from,to:q.to,snapshotHash:digest(snapshot)})
  return simulation(key,user)
}
const eventFields=['action','protocol','src_ip','dst_ip','dst_port','direction','program','event_type']
function readEvents({nodeIds,from,to,high,cursor=0,limit=250}){
  return all(`SELECT e.*,e.rowid sequence,${eventFields.map(k=>`COALESCE(e.${k},p.${k}) ${k}`).join(',')} FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE e.rowid>? AND e.rowid<=? AND e.node_id IN (${nodeIds.map(()=>'?').join(',')}) AND datetime(COALESCE(e.event_time,e.received_at))>=datetime(?) AND datetime(COALESCE(e.event_time,e.received_at))<=datetime(?) AND COALESCE(e.event_type,p.event_type)='firewall' ORDER BY e.rowid LIMIT ?`,cursor,high,...nodeIds,from,to,limit)
}
export function listSimulations(policyId,user){policyAccess(policyId,user);return all('SELECT id FROM policy_simulations WHERE policy_id=? ORDER BY created_at DESC LIMIT 100',policyId).map(r=>simulation(r.id,user))}
function portMatch(expression,value){if(!expression||expression==='Any')return true;if(value===null||value===undefined)return null;let unknown=false;for(const part of String(expression).split(',')){if(!/^\d+(?:-\d+)?$/.test(part.trim())){unknown=true;continue}const [a,b=a]=part.trim().split('-').map(Number);if(value>=a&&value<=b)return true}return unknown?null:false}
function addressMatch(expression,value){if(!expression||expression==='Any')return true;if(!canonicalIp(value))return null;let unknown=false;for(const part of String(expression).split(',')){try{if(part.includes('/')){if(subnetMatcher(part.trim())(value))return true}else if(canonicalIp(part)){if(canonicalIp(part)===canonicalIp(value))return true}else unknown=true}catch{unknown=true}}return unknown?null:false}
export function ruleMatch(rule,event){
  const missing=[],tests=[],direction=String(event.direction||'').toLowerCase(),protocol={6:'TCP',17:'UDP',1:'ICMP',58:'ICMPv6'}[event.protocol]||String(event.protocol||'').toUpperCase()
  const check=(result,reason)=>{tests.push(result);if(result===null)missing.push(reason)}
  check(!['in','out'].includes(direction)?null:direction===rule.direction,'Direction unavailable')
  const ruleProtocol=({1:'ICMP',6:'TCP',17:'UDP',58:'ICMPV6',256:'Any',ICMPV4:'ICMP'})[String(rule.protocol).toUpperCase()]||String(rule.protocol)
  check(ruleProtocol==='Any'?true:!protocol||protocol==='UNKNOWN'?null:ruleProtocol.toUpperCase()===protocol.toUpperCase(),'Protocol unavailable')
  check(portMatch(rule.localPort,direction==='in'?event.dst_port:event.src_port),'Local port unavailable')
  check(portMatch(rule.remotePort,direction==='in'?event.src_port:event.dst_port),'Remote port unavailable')
  if(rule.unsupportedQualifiers)check(null,'Host rule contains unsupported service, identity, interface or IPsec qualifiers')
  if(rule.localAddress)check(addressMatch(rule.localAddress,direction==='in'?event.dst_ip:event.src_ip),'Local address unavailable')
  check(addressMatch(rule.remoteAddress,direction==='in'?event.src_ip:event.dst_ip),'Address or address-keyword resolution unavailable')
  if(rule.program&&rule.program!=='Any')check(!event.program?null:/^\\device/i.test(event.program)&&!/^\\device/i.test(rule.program)?null:event.program.toLowerCase()===rule.program.toLowerCase(),'Program identity unavailable or device path unresolved')
  if(rule.profile&&rule.profile!=='Any')check(!event.profile?null:String(rule.profile).split(',').map(s=>s.trim().toLowerCase()).includes(String(event.profile).toLowerCase()),'Active network profile was not captured')
  if(rule.localUserSid)check(!event.account_sid?null:event.account_sid===rule.localUserSid,'Local account identity unavailable')
  if(rule.schedule){const stamp=Date.parse(event.event_time||event.received_at);check(Number.isFinite(stamp)?scheduleIsActive(rule.schedule,new Date(stamp)):null,'Event time unavailable for schedule')}
  return {match:tests.includes(false)?false:tests.includes(null)?null:true,missing}
}
function decision(rules,event){const definite=[],possible=[],missing=[];for(const r of rules){const m=ruleMatch(r,event);if(m.match===true)definite.push(r);else if(m.match===null){possible.push(r);missing.push(...m.missing)}}
  if(definite.some(r=>r.action==='block'))return {action:'block',rules:definite.filter(r=>r.action==='block').map(r=>r.sourceNodeId||r.name),missing:[]}
  if(possible.some(r=>r.action==='block')||!definite.length&&possible.length)return {action:'unknown',rules:possible.map(r=>r.sourceNodeId||r.name),missing:[...new Set(missing)]}
  return {action:definite.length?'allow':'no-match',rules:definite.map(r=>r.sourceNodeId||r.name),missing:[]}
}
function hostContext(nodeId){const r=one('SELECT * FROM policy_host_context WHERE node_id=?',nodeId);return r&&Date.now()-Date.parse(r.captured_at)<300000?parse(r.snapshot_json):null}
export async function capturePolicyContext(nodeId,user,execute=remote){
 const node=one('SELECT * FROM nodes WHERE id=?',nodeId);if(!node||!isLocalAssetNode(node))fail('Local asset not found',404)
 if(!['winrm','winrms'].includes(node.transport)||node.connection_mode==='agent')fail('Effective policy capture currently supports modern agentless Windows WinRM',409)
 const context=await execute(node,'safety_context');if(!context?.complete||!Array.isArray(context.rules)||context.rules.length>2000||!Array.isArray(context.profiles)||context.profiles.length!==3||typeof context.authenticatedBypassExcluded!=='boolean')fail('Incomplete effective host policy context',502)
 if(Buffer.byteLength(JSON.stringify(context))>4*1024*1024)fail('Host policy context is too large',413)
 run('INSERT INTO policy_host_context(node_id,captured_at,snapshot_json) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET captured_at=excluded.captured_at,snapshot_json=excluded.snapshot_json',nodeId,now(),JSON.stringify(context));audit(user.id,'policy.context.capture','node',nodeId,null,{ruleCount:context.rules.length});return {nodeId,capturedAt:now(),ruleCount:context.rules.length,authenticatedBypassExcluded:context.authenticatedBypassExcluded}
}
export function evaluatePolicyImpact(snapshot,event){
 const node=snapshot.nodes.find(n=>n.id===event.node_id),context=node?.firewallContext,foreign=context?.rules?.filter(r=>r.group!=='WinFireSecure:'+snapshot.policyId)||[],before=decision([...snapshot.baselineRules,...foreign],event),after=decision([...snapshot.rules,...foreign],event),observed=['allow','block'].includes(event.action)?event.action:'unknown'
 let outcome='indeterminate',reason='Host default policy and foreign-rule precedence were not captured'
 const windows=/windows/i.test(node?.platform||node?.osName||'')||['winrm','winrms','wmi','netsh'].includes(node?.transport)
 const profiles=context?.profiles?.filter(p=>!event.profile||p.name.toLowerCase()===String(event.profile).toLowerCase())||[]
 const effective=d=>{if(d.action!=='no-match')return d.action;const actions=profiles.map(p=>p[event.direction==='in'?'inbound':'outbound']);return actions.length&&actions.every(v=>v===actions[0])&&['allow','block'].includes(actions[0])?actions[0]:'unknown'}
 if(!windows)reason='This platform firewall precedence model is not supported by this replay'
 else if(node?.coverage&&!node.coverage.learningReady)reason='Required authentication or event coverage was missing or stale at evaluation start'
 else if(context?.complete&&context.serviceRunning&&context.authenticatedBypassExcluded&&profiles.length&&profiles.every(p=>p.enabled&&p.localRules&&(event.direction!=='in'||p.inboundRules))){
  const a=effective(before),b=effective(after)
  if(['allow','block'].includes(a)&&['allow','block'].includes(b)){outcome=a===b?'unchanged':b==='block'?'newly-blocked':'newly-allowed';reason='Counterfactual replay against pinned effective Windows rules and profile defaults; no end-to-end reachability claim'}
  else reason=[...new Set([...before.missing,...after.missing])].join('; ')||'Applicable host default profile is indeterminate'
 }else if(before.action!=='unknown'&&after.action===before.action&&JSON.stringify(before.rules)===JSON.stringify(after.rules)){outcome='unchanged';reason='The draft has the same matching policy effect as the pinned version'}

 if(windows&&after.action==='unknown')reason=after.missing.join('; ')
 return {eventId:event.id,nodeId:event.node_id,outcome,reason,observed,before,after,contextCapturedAt:context?.capturedAt||null,flow:{sourceIp:event.src_ip,destinationIp:event.dst_ip,sourcePort:event.src_port,destinationPort:event.dst_port,protocol:event.protocol,direction:event.direction,program:event.program,accountSid:event.account_sid,time:event.event_time||event.received_at},scope:'selected-policy change; not an end-to-end connectivity guarantee'}
}

export function simulation(key,user){
  const row=one('SELECT * FROM policy_simulations WHERE id=?',key);if(!row)fail('Simulation not found',404);const p=policyAccess(row.policy_id,user),snapshot=parse(row.snapshot_json)
  const stale=snapshot.baseVersionId!==p.current_version_id||row.target_hash!==targetsHash(snapshot.nodeIds)
  return {...row,snapshot,summary:parse(row.summary_json),snapshot_json:undefined,summary_json:undefined,stale,approvalValid:!!row.approved_at&&!stale,readOnly:true}
}
export function simulationResults(key,user,query={}){const {page,pageSize,outcome}=z.object({page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(250).default(25),outcome:z.enum(['unchanged','newly-allowed','newly-blocked','indeterminate']).optional()}).parse(query);simulation(key,user);const where=outcome?' AND outcome=?':'',args=outcome?[key,outcome]:[key];return {items:all(`SELECT result_json FROM policy_simulation_results WHERE simulation_id=?${where} ORDER BY event_id LIMIT ? OFFSET ?`,...args,pageSize,(page-1)*pageSize).map(r=>parse(r.result_json)),total:one(`SELECT COUNT(*) n FROM policy_simulation_results WHERE simulation_id=?${where}`,...args).n,page,pageSize}}
export function cancelSimulation(key,user){const r=simulation(key,user);policyAccess(r.policy_id,user,true);if(['queued','running','observing'].includes(r.status))run("UPDATE policy_simulations SET status='cancelled',finished_at=? WHERE id=?",now(),key);audit(user.id,'policy.simulation.cancel','policy-simulation',key,null,null);return simulation(key,user)}
export function approveSimulation(key,reason,user){const r=simulation(key,user);policyAccess(r.policy_id,user,true);if(r.stale||r.status!=='completed')fail('Only a completed simulation with unchanged policy and targets can be approved',409);if(typeof reason!=='string'||!reason.trim()||reason.length>1000)fail('A review reason is required');run('UPDATE policy_simulations SET approved_at=?,approved_by=?,approval_reason=? WHERE id=?',now(),user.id,reason,key);audit(user.id,'policy.simulation.approve','policy-simulation',key,null,{snapshotHash:r.snapshot_hash,reason,summary:r.summary});return simulation(key,user)}
export function processSimulations({limit=250}={}){
  limit=Math.max(1,Math.min(1000,Math.floor(limit)))
  const job=one("SELECT * FROM policy_simulations WHERE status IN ('queued','running','observing') ORDER BY COALESCE(last_processed_at,''),created_at,id LIMIT 1");if(!job)return
  const snapshot=parse(job.snapshot_json),high=job.kind==='observe'?one('SELECT COALESCE(MAX(rowid),0) n FROM log_events').n:job.high_water
  const events=job.kind==='historical'?all('SELECT event_json FROM policy_simulation_inputs WHERE simulation_id=? AND sequence>? ORDER BY sequence LIMIT ?',job.id,job.cursor,limit).map(r=>parse(r.event_json)):readEvents({nodeIds:snapshot.nodeIds,from:job.from_at,to:job.to_at,high,cursor:job.cursor,limit})
  return db.transaction(()=>{
    const summary={unchanged:0,'newly-allowed':0,'newly-blocked':0,indeterminate:0,...parse(job.summary_json)}
    for(const e of events){const result=evaluatePolicyImpact(snapshot,e),insert=run('INSERT OR IGNORE INTO policy_simulation_results(simulation_id,event_id,node_id,outcome,result_json) VALUES(?,?,?,?,?)',job.id,e.id,e.node_id,result.outcome,JSON.stringify(result));if(insert.changes)summary[result.outcome]++}
    const processed=Object.values(summary).reduce((a,b)=>a+b,0),done=events.length<limit&&(job.kind==='historical'||Date.now()>=Date.parse(job.to_at)),state=processed>=100000&&!done?'limited':done?'completed':job.kind==='observe'?'observing':'running'
    run('UPDATE policy_simulations SET status=?,cursor=?,high_water=?,processed=?,summary_json=?,finished_at=?,last_processed_at=? WHERE id=?',state,events.at(-1)?.sequence||high,high,processed,JSON.stringify(summary),['completed','limited'].includes(state)?now():null,now(),job.id)
    return {id:job.id,status:state,processed,summary}
  })()
}
