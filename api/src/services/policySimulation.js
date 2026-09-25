import {createHash} from 'node:crypto'
import {z} from 'zod'
import {compilePolicy,scheduleIsActive} from '../../../packages/shared/index.js'
import {db,all,one,run,id,now,audit} from '../db.js'
import {canWriteResource,canReadResource} from '../access.js'
import {isLocalAssetNode,subnetMatcher,canonicalIp} from './networkBoundary.js'
import {nodeCoverage} from './capabilities.js'
const digest=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex'),parse=v=>JSON.parse(v||'null'),fail=(message,status=400)=>{throw Object.assign(new Error(message),{status})}
const input=z.object({graph:z.object({nodes:z.array(z.any()).max(1000),edges:z.array(z.any()).max(4000)}).optional(),baseVersionId:z.string().nullable(),nodeIds:z.array(z.string()).min(1).max(100),from:z.string().datetime({offset:true}),to:z.string().datetime({offset:true}),kind:z.enum(['historical','observe']).default('historical')}).strict()
const targetsHash=nodes=>digest(nodes.map(nodeId=>({nodeId,node:one('SELECT scope_id,transport,platform,firewall_backend FROM nodes WHERE id=?',nodeId),groups:all('SELECT group_id FROM node_group_members WHERE node_id=? ORDER BY group_id',nodeId),policies:all('SELECT DISTINCT p.id,p.current_version_id FROM policies p JOIN policy_assignments a ON a.policy_id=p.id WHERE a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?) ORDER BY p.id',nodeId,nodeId)})))
function policyAccess(policyId,user,write=false){const p=one('SELECT * FROM policies WHERE id=?',policyId);if(!p)fail('Policy not found',404);if(!(write?canWriteResource:canReadResource)(user,'policy',p))fail('Insufficient policy permission',403);return p}
export function queueSimulation(policyId,data,user){
  const p=policyAccess(policyId,user,true),q=input.parse(data)
  if(q.baseVersionId!==p.current_version_id)fail('The policy changed. Reload the current version before simulating.',409)
  const from=Date.parse(q.from),to=Date.parse(q.to)
  if(to<=from||to-from>30*86400000||q.kind==='historical'&&to>Date.now()+60000||q.kind==='observe'&&(from<Date.now()-60000||to>Date.now()+86400000))fail('Choose at most 30 days of history, or an observe-only window starting now and ending within 24 hours')
  const nodeIds=[...new Set(q.nodeIds)].sort(),nodes=nodeIds.map(key=>one('SELECT * FROM nodes WHERE id=?',key))
  if(nodes.some(n=>!n||!isLocalAssetNode(n)))fail('Every target must be an existing asset inside its configured network scope')
  const version=p.current_version_id?one('SELECT * FROM policy_versions WHERE id=?',p.current_version_id):null,graph=q.graph||parse(version?.graph_json)||{nodes:[],edges:[]},rules=compilePolicy(graph,policyId)
  const snapshot={policyId,baseVersionId:p.current_version_id,graph,rules,baselineRules:parse(version?.rules_compiled_json)||[],nodeIds,nodes:nodes.map(n=>({id:n.id,platform:n.platform,osName:n.os_name,transport:n.transport,coverage:nodeCoverage(n)})),mode:'policy-change-impact',modelVersion:1}
  const key=id(),high=one('SELECT COALESCE(MAX(rowid),0) n FROM log_events').n
  if(q.kind==='historical'&&one(`SELECT COUNT(*) n FROM log_events WHERE node_id IN (${nodeIds.map(()=>'?').join(',')}) AND COALESCE(event_time,received_at)>=? AND COALESCE(event_time,received_at)<=?`,...nodeIds,q.from,q.to).n>100000)fail('More than 100,000 events match. Narrow the targets or time window.',413)
  run('INSERT INTO policy_simulations(id,policy_id,kind,status,snapshot_json,snapshot_hash,target_hash,from_at,to_at,high_water,cursor,requested_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',key,policyId,q.kind,'queued',JSON.stringify(snapshot),digest(snapshot),targetsHash(nodeIds),new Date(from).toISOString(),new Date(to).toISOString(),high,q.kind==='observe'?high:0,user.id,now())
  audit(user.id,'policy.simulation.queue','policy-simulation',key,null,{policyId,nodeIds,kind:q.kind,from:q.from,to:q.to,snapshotHash:digest(snapshot)})
  return simulation(key,user)
}
function portMatch(expression,value){if(!expression||expression==='Any')return true;if(value===null||value===undefined)return null;return String(expression).split(',').some(part=>{const [a,b=a]=part.trim().split('-').map(Number);return value>=a&&value<=b})}
function addressMatch(expression,value){if(!expression||expression==='Any')return true;if(!canonicalIp(value))return null;let unknown=false;for(const part of String(expression).split(',')){try{if(part.includes('/')){if(subnetMatcher(part.trim())(value))return true}else if(canonicalIp(part)){if(canonicalIp(part)===canonicalIp(value))return true}else unknown=true}catch{unknown=true}}return unknown?null:false}
export function ruleMatch(rule,event){
  const missing=[],tests=[],direction=String(event.direction||'').toLowerCase(),protocol={6:'TCP',17:'UDP',1:'ICMP',58:'ICMPv6'}[event.protocol]||String(event.protocol||'').toUpperCase()
  const check=(result,reason)=>{tests.push(result);if(result===null)missing.push(reason)}
  check(!['in','out'].includes(direction)?null:direction===rule.direction,'Direction unavailable')
  check(rule.protocol==='Any'?true:!protocol||protocol==='UNKNOWN'?null:rule.protocol.toUpperCase()===protocol,'Protocol unavailable')
  check(portMatch(rule.localPort,direction==='in'?event.dst_port:event.src_port),'Local port unavailable')
  check(portMatch(rule.remotePort,direction==='in'?event.src_port:event.dst_port),'Remote port unavailable')
  check(addressMatch(rule.remoteAddress,direction==='in'?event.src_ip:event.dst_ip),'Address or address-keyword resolution unavailable')
  if(rule.program&&rule.program!=='Any')check(!event.program?null:/^\\device/i.test(event.program)&&!/^\\device/i.test(rule.program)?null:event.program.toLowerCase()===rule.program.toLowerCase(),'Program identity unavailable or device path unresolved')
  if(rule.profile&&rule.profile!=='Any')check(null,'Active network profile was not captured')
  if(rule.localUserSid)check(!event.account_sid?null:event.account_sid===rule.localUserSid,'Local account identity unavailable')
  if(rule.schedule){const stamp=Date.parse(event.event_time||event.received_at);check(Number.isFinite(stamp)?scheduleIsActive(rule.schedule,new Date(stamp)):null,'Event time unavailable for schedule')}
  return {match:tests.includes(false)?false:tests.includes(null)?null:true,missing}
}
function decision(rules,event){const definite=[],possible=[],missing=[];for(const r of rules){const m=ruleMatch(r,event);if(m.match===true)definite.push(r);else if(m.match===null){possible.push(r);missing.push(...m.missing)}}
  if(definite.some(r=>r.action==='block'))return {action:'block',rules:definite.filter(r=>r.action==='block').map(r=>r.sourceNodeId||r.name),missing:[]}
  if(possible.some(r=>r.action==='block')||!definite.length&&possible.length)return {action:'unknown',rules:possible.map(r=>r.sourceNodeId||r.name),missing:[...new Set(missing)]}
  return {action:definite.length?'allow':'no-match',rules:definite.map(r=>r.sourceNodeId||r.name),missing:[]}
}
export function evaluatePolicyImpact(snapshot,event){
  const node=snapshot.nodes.find(n=>n.id===event.node_id),before=decision(snapshot.baselineRules,event),after=decision(snapshot.rules,event),observed=['allow','block'].includes(event.action)?event.action:'unknown'
  let outcome='indeterminate',reason='Host default policy and foreign-rule precedence were not captured'
  const windows=/windows/i.test(node?.platform||node?.osName||'')||['winrm','winrms','wmi','netsh'].includes(node?.transport)
  if(before.action!=='unknown'&&after.action===before.action&&JSON.stringify(before.rules)===JSON.stringify(after.rules)){outcome='unchanged';reason='The draft has the same matching policy effect as the pinned version'}
  else if(!windows)reason='This platform firewall precedence model is not supported by this replay'
  else if(after.action==='block'&&observed!=='unknown'){outcome=observed==='block'?'unchanged':'newly-blocked';reason='An explicit matching Windows block rule takes precedence over ordinary allow rules; authenticated bypass/IPsec exceptions are outside this model'}
  if(after.action==='unknown')reason=after.missing.join('; ')
  // Removing a deny or adding an allow does not prove reachability: another policy, foreign
  // rule, default block, IPsec or application state may still deny the connection.
  return {eventId:event.id,nodeId:event.node_id,outcome,reason,observed,before,after,flow:{sourceIp:event.src_ip,destinationIp:event.dst_ip,sourcePort:event.src_port,destinationPort:event.dst_port,protocol:event.protocol,direction:event.direction,program:event.program,accountSid:event.account_sid,time:event.event_time||event.received_at},scope:'selected-policy change; not an end-to-end connectivity guarantee'}
}
export function simulation(key,user){
  const row=one('SELECT * FROM policy_simulations WHERE id=?',key);if(!row)fail('Simulation not found',404);const p=policyAccess(row.policy_id,user),snapshot=parse(row.snapshot_json)
  const stale=snapshot.baseVersionId!==p.current_version_id||row.target_hash!==targetsHash(snapshot.nodeIds)
  return {...row,snapshot,summary:parse(row.summary_json),snapshot_json:undefined,summary_json:undefined,stale,approvalValid:!!row.approved_at&&!stale,readOnly:true}
}
export function simulationResults(key,user,{page=1,pageSize=25,outcome}={}){simulation(key,user);const where=outcome?' AND outcome=?':'',args=outcome?[key,outcome]:[key];return {items:all(`SELECT result_json FROM policy_simulation_results WHERE simulation_id=?${where} ORDER BY event_id LIMIT ? OFFSET ?`,...args,pageSize,(page-1)*pageSize).map(r=>parse(r.result_json)),total:one(`SELECT COUNT(*) n FROM policy_simulation_results WHERE simulation_id=?${where}`,...args).n,page,pageSize}}
export function cancelSimulation(key,user){const r=simulation(key,user);policyAccess(r.policy_id,user,true);if(['queued','running','observing'].includes(r.status))run("UPDATE policy_simulations SET status='cancelled',finished_at=? WHERE id=?",now(),key);audit(user.id,'policy.simulation.cancel','policy-simulation',key,null,null);return simulation(key,user)}
export function approveSimulation(key,reason,user){const r=simulation(key,user);policyAccess(r.policy_id,user,true);if(r.stale||r.status!=='completed')fail('Only a completed simulation with unchanged policy and targets can be approved',409);if(typeof reason!=='string'||!reason.trim()||reason.length>1000)fail('A review reason is required');run('UPDATE policy_simulations SET approved_at=?,approved_by=?,approval_reason=? WHERE id=?',now(),user.id,reason,key);audit(user.id,'policy.simulation.approve','policy-simulation',key,null,{snapshotHash:r.snapshot_hash,reason,summary:r.summary});return simulation(key,user)}
export function processSimulations({limit=250}={}){
  const job=one("SELECT * FROM policy_simulations WHERE status IN ('queued','running','observing') ORDER BY created_at LIMIT 1");if(!job)return
  const snapshot=parse(job.snapshot_json),high=job.kind==='observe'?one('SELECT COALESCE(MAX(rowid),0) n FROM log_events').n:job.high_water
  const events=all(`SELECT rowid sequence,* FROM log_events WHERE rowid>? AND rowid<=? AND node_id IN (${snapshot.nodeIds.map(()=>'?').join(',')}) AND COALESCE(event_time,received_at)>=? AND COALESCE(event_time,received_at)<=? AND event_type='firewall' ORDER BY rowid LIMIT ?`,job.cursor,high,...snapshot.nodeIds,job.from_at,job.to_at,Math.min(1000,limit))
  return db.transaction(()=>{
    const summary={unchanged:0,'newly-allowed':0,'newly-blocked':0,indeterminate:0,...parse(job.summary_json)}
    for(const e of events){const result=evaluatePolicyImpact(snapshot,e),insert=run('INSERT OR IGNORE INTO policy_simulation_results(simulation_id,event_id,node_id,outcome,result_json) VALUES(?,?,?,?,?)',job.id,e.id,e.node_id,result.outcome,JSON.stringify(result));if(insert.changes)summary[result.outcome]++}
    const processed=Object.values(summary).reduce((a,b)=>a+b,0),done=events.length<Math.min(1000,limit)&&(job.kind==='historical'||Date.now()>=Date.parse(job.to_at)),state=processed>=100000&&!done?'limited':done?'completed':job.kind==='observe'?'observing':'running'
    run('UPDATE policy_simulations SET status=?,cursor=?,high_water=?,processed=?,summary_json=?,finished_at=? WHERE id=?',state,events.at(-1)?.sequence||high,high,processed,JSON.stringify(summary),['completed','limited'].includes(state)?now():null,job.id)
    return {id:job.id,status:state,processed,summary}
  })()
}
