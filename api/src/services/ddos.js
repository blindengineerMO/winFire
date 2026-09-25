import {z} from 'zod'
import os from 'node:os'
import {db,all,one,run,id,now,json,parse,audit} from '../db.js'
import {remote} from '../connector.js'
import {emitNotification} from '../notifications.js'
import {canonicalIp,unicastIp,subnetMatcher,configuredCidrs,inLocalCidrs,assertDirectManagement} from './networkBoundary.js'
export const ddosPolicySchema=z.object({name:z.string().trim().min(1).max(100),enabled:z.boolean().default(false),mode:z.enum(['detect','block']).default('detect'),nodeIds:z.array(z.string().min(1).max(100)).min(1).max(100),protocol:z.enum(['TCP','UDP']).default('TCP'),ports:z.array(z.number().int().min(1).max(65535)).min(1).max(32),windowSeconds:z.number().int().min(30).max(3600).default(60),eventThreshold:z.number().int().min(10).max(100000).default(1000),sourceThreshold:z.number().int().min(1).max(10000).default(20),perSourceThreshold:z.number().int().min(1).max(100000).default(10),blockSeconds:z.number().int().min(30).max(86400).default(300),observeSeconds:z.number().int().min(30).max(3600).default(60),excludeLocal:z.boolean().default(true),excludedCidrs:z.array(z.string().max(100)).max(256).default([])}).strict().superRefine((v,c)=>{if(v.observeSeconds<v.windowSeconds)c.addIssue({code:'custom',message:'Observation period must be at least the detection window'});if(v.mode==='block'&&v.ports.some(p=>[22,135,139,445,3389,5985,5986].includes(p)))c.addIssue({code:'custom',message:'Automatic blocks cannot target management ports'})})
const decode=p=>({...parse(p.config_json),id:p.id,createdAt:p.created_at,updatedAt:p.updated_at})
export const ddosPolicies=()=>all('SELECT * FROM ddos_policies ORDER BY name,id').map(decode)
export function ddosSupport(node){return node.connection_mode==='agentless'&&['winrm','winrms','ssh'].includes(node.transport)&&node.manageability!=='unmanageable'}
export function saveDdosPolicy(input,actor,policyId=null){
 const data=ddosPolicySchema.parse(input);data.nodeIds=[...new Set(data.nodeIds)];data.ports=[...new Set(data.ports)]
 data.excludedCidrs.forEach(subnetMatcher)
 if(policyId&&!one('SELECT id FROM ddos_policies WHERE id=?',policyId))throw Object.assign(new Error('DDoS policy not found'),{status:404})
 for(const nodeId of data.nodeIds){const node=one('SELECT * FROM nodes WHERE id=?',nodeId);if(!node)throw Object.assign(new Error('Selected node does not exist'),{status:400});if(data.mode==='block'){assertDirectManagement(node);if(!ddosSupport(node))throw Object.assign(new Error('Automatic blocking requires an agentless WinRM or SSH node. SSH also needs nftables and passwordless sudo.'),{status:400})}}
 if(data.enabled&&ddosPolicies().some(p=>p.id!==policyId&&p.enabled&&p.nodeIds.some(n=>data.nodeIds.includes(n))))throw Object.assign(new Error('A selected node already has an enabled DDoS policy'),{status:409})
 const key=policyId||id(),stamp=now();run('INSERT INTO ddos_policies(id,name,config_json,created_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,config_json=excluded.config_json,updated_at=excluded.updated_at',key,data.name,json(data),stamp,stamp);audit(actor,'ddos.policy.save','ddos_policy',key,null,data);return decode(one('SELECT * FROM ddos_policies WHERE id=?',key))
}
export function deleteDdosPolicy(policyId,actor){
 if(one('SELECT id FROM ddos_incidents WHERE policy_id=? AND closed_at IS NULL',policyId))throw Object.assign(new Error('Disable the policy and release its active incidents before deleting it'),{status:409})
 if(!one('SELECT id FROM ddos_policies WHERE id=?',policyId))throw Object.assign(new Error('DDoS policy not found'),{status:404})
 // Retain incident history and evidence; a deleted policy is archived and no longer evaluated.
 const p=one('SELECT * FROM ddos_policies WHERE id=?',policyId),data=parse(p.config_json);data.enabled=false;data.archived=true;run('UPDATE ddos_policies SET config_json=?,updated_at=? WHERE id=?',json(data),now(),policyId);audit(actor,'ddos.policy.delete','ddos_policy',policyId,null,null)
}
function protectedSources(node,p){
 const ips=new Set([canonicalIp(node.ip),...Object.values(os.networkInterfaces()).flatMap(a=>(a||[]).map(i=>canonicalIp(i.address))),...String(process.env.WINFIRE_CONTROL_PLANE_IPS||'').split(',').map(canonicalIp)].filter(Boolean));const exclusions=p.excludedCidrs.map(subnetMatcher),local=configuredCidrs()
 return ip=>!ips.has(ip)&&unicastIp(ip,local)&&!(p.excludeLocal&&inLocalCidrs(ip,local))&&!exclusions.some(match=>match(ip))
}
export function ddosEvidence(p,node,{at=Date.now(),after=null}={}){
 const cutoff=Math.max(at-p.windowSeconds*1000,Date.parse(p.updatedAt||p.createdAt)||0,after?Date.parse(after):0),end=new Date(at).toISOString()
 // event_time excludes historical/backfilled events. received_at also bounds indexed work.
 const events=all(`SELECT COALESCE(e.src_ip,t.src_ip) source,COALESCE(e.event_time,e.received_at) observed FROM log_events e LEFT JOIN event_patterns t ON t.id=e.pattern_id WHERE e.node_id=? AND e.received_at>=? AND datetime(COALESCE(e.event_time,e.received_at))>=datetime(?) AND datetime(COALESCE(e.event_time,e.received_at))<=datetime(?) AND e.action IN ('allow','block') AND lower(COALESCE(e.direction,t.direction))='in' AND upper(COALESCE(e.protocol,t.protocol))=? AND COALESCE(e.dst_port,t.dst_port) IN (${p.ports.map(()=>'?').join(',')}) AND winfire_ip(COALESCE(e.dst_ip,t.dst_ip))=? ORDER BY e.received_at DESC LIMIT 100001`,node.id,new Date(cutoff).toISOString(),new Date(cutoff).toISOString(),end,p.protocol,...p.ports,canonicalIp(node.ip))
 const eligible=protectedSources(node,p),counts=new Map();let latest=null,total=0
 for(const e of events){const ip=canonicalIp(e.source);if(!ip||!eligible(ip))continue;counts.set(ip,(counts.get(ip)||0)+1);total++;if(!latest||e.observed>latest)latest=e.observed}
 const health=one("SELECT MAX(last_success_at) success,MAX(last_failure_at) failure FROM node_capability_evidence WHERE node_id=? AND capability='events'",node.id)
 const fresh=!!(latest&&Date.parse(latest)>=cutoff||health?.success&&Date.parse(health.success)>=cutoff&&(!health.failure||health.failure<health.success))
 return {events:total,uniqueSources:counts.size,thresholdMet:total>=p.eventThreshold&&counts.size>=p.sourceThreshold,sources:[...counts].filter(([,n])=>n>=p.perSourceThreshold).sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])).slice(0,100).map(([ip,count])=>({ip,count})),truncated:events.length>100000,fresh,windowStart:new Date(cutoff).toISOString(),windowEnd:end,latestEventAt:latest,metric:'collected inbound firewall events'}
}
const incidentDto=i=>({...i,evidence:parse(i.evidence_json),block:parse(i.block_json),evidence_json:undefined,block_json:undefined})
export function ddosIncidents(query={}){
 const q=z.object({page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(100).default(25),status:z.enum(['all','active','closed']).default('all'),q:z.string().max(200).default('')}).parse(query)
 const where=`WHERE (?='all' OR (?='active' AND i.closed_at IS NULL) OR (?='closed' AND i.closed_at IS NOT NULL)) AND (instr(lower(p.name),lower(?))>0 OR instr(lower(n.hostname),lower(?))>0)`,args=[q.status,q.status,q.status,q.q,q.q],joins='FROM ddos_incidents i JOIN ddos_policies p ON p.id=i.policy_id LEFT JOIN nodes n ON n.id=i.node_id'
 return {...q,total:one(`SELECT COUNT(*) n ${joins} ${where}`,...args).n,items:all(`SELECT i.*,p.name policyName,n.hostname ${joins} ${where} ORDER BY i.created_at DESC,i.id LIMIT ? OFFSET ?`,...args,q.pageSize,(q.page-1)*q.pageSize).map(incidentDto)}
}
export function ddosIncident(incidentId){const row=one('SELECT * FROM ddos_incidents WHERE id=?',incidentId);if(!row)throw Object.assign(new Error('DDoS incident not found'),{status:404});return {...incidentDto(row),history:all('SELECT status,detail_json,created_at FROM ddos_transitions WHERE incident_id=? ORDER BY rowid',incidentId).map(t=>({...t,detail:parse(t.detail_json),detail_json:undefined}))}}
function transition(i,status,detail={},at=Date.now()){
 if(one('SELECT status FROM ddos_transitions WHERE incident_id=? ORDER BY rowid DESC LIMIT 1',i.id)?.status===status)return
 const stamp=new Date(at).toISOString();run('UPDATE ddos_incidents SET status=?,updated_at=?,last_error=NULL WHERE id=?',status,stamp,i.id);run('INSERT INTO ddos_transitions(id,incident_id,status,detail_json,created_at) VALUES(?,?,?,?,?)',id(),i.id,status,json(detail),stamp);audit(null,'ddos.'+status,'ddos_incident',i.id,null,detail)
 emitNotification({eventKey:`ddos:${i.id}:${status}:${i.cycles||0}`,category:'ddos_attack',title:`DDoS protection: ${status}`,body:`Node ${i.node_id}: ${detail.summary||status}. Incident ${i.id}.`,entityType:'ddos_incident',entityId:i.id})
}
async function release(i,{at,execute},close=false){
 const block=parse(i.block_json),node=one('SELECT * FROM nodes WHERE id=?',i.node_id)
 if(block){transition(i,'releasing',{},at);const result=await execute(node,'ddos_end',{id:block.id});if(!result?.removed)throw new Error('Host did not confirm temporary block removal')}
 run('UPDATE ddos_incidents SET block_json=NULL,expires_at=NULL,observe_after=?,closed_at=? WHERE id=?',new Date(at).toISOString(),close?new Date(at).toISOString():null,i.id)
 transition(i,close?'closed':'observing',{summary:close?'Protection stopped; temporary rules removed':'Temporary block removed; collecting a new observation window'},at)
}
export async function releaseDdosIncident(incidentId,actor,{at=Date.now(),execute=remote}={}){
 if(running)throw Object.assign(new Error('DDoS evaluation is in progress; retry release shortly'),{status:409})
 const i=one('SELECT * FROM ddos_incidents WHERE id=?',incidentId);if(!i)throw Object.assign(new Error('DDoS incident not found'),{status:404});if(i.closed_at)return ddosIncident(i.id)
 // Disabling before release prevents a new incident from immediately recreating the block.
 const p=one('SELECT * FROM ddos_policies WHERE id=?',i.policy_id),config=parse(p.config_json);config.enabled=false;run('UPDATE ddos_policies SET config_json=?,updated_at=? WHERE id=?',json(config),new Date(at).toISOString(),p.id)
 running=true
 try{await release(i,{at,execute},true)}catch(e){run('UPDATE ddos_incidents SET last_error=? WHERE id=?',String(e.message).slice(0,500),i.id);throw Object.assign(new Error('Release not confirmed; automatic cleanup will retry. '+String(e.message).slice(0,300)),{status:502})}finally{running=false}
 audit(actor,'ddos.stop','ddos_incident',i.id,null,null);return ddosIncident(i.id)
}
let running=false
export async function runDdosCycle({at=Date.now(),execute=remote}={}){
 if(running)return;running=true
 try{
  const policies=ddosPolicies(),byId=new Map(policies.map(p=>[p.id,p]))
  for(const i of all('SELECT * FROM ddos_incidents WHERE closed_at IS NULL')){
   try{const p=byId.get(i.policy_id);if(!p?.enabled||p.archived||!p.nodeIds.includes(i.node_id)||p.mode==='detect'&&i.block_json){await release(i,{at,execute},true);continue}
    if(['blocking','releasing'].includes(i.status)||i.block_json&&Date.parse(i.expires_at)<=at){await release(i,{at,execute});continue}
   }catch(e){run('UPDATE ddos_incidents SET last_error=? WHERE id=?',String(e.message).slice(0,500),i.id)}
  }
  for(const p of policies.filter(p=>p.enabled&&!p.archived))for(const nodeId of p.nodeIds){
   const node=one('SELECT * FROM nodes WHERE id=?',nodeId);if(!node)continue
   let i=one('SELECT * FROM ddos_incidents WHERE node_id=? AND closed_at IS NULL',nodeId)
   if(i&&(i.policy_id!==p.id||i.block_json||['blocking','releasing'].includes(i.status)))continue
   if(i?.observe_after&&at-Date.parse(i.observe_after)<p.observeSeconds*1000)continue
   const evidence=ddosEvidence(p,node,{at,after:i?.observe_after});
   if(!evidence.thresholdMet){if(i){run('UPDATE ddos_incidents SET evidence_json=? WHERE id=?',json(evidence),i.id);if(evidence.fresh){run('UPDATE ddos_incidents SET closed_at=? WHERE id=?',new Date(at).toISOString(),i.id);transition(i,'resolved',{summary:'Fresh telemetry is below the configured thresholds'},at)}else run("UPDATE ddos_incidents SET last_error='Waiting for fresh firewall telemetry; attack end is unconfirmed' WHERE id=?",i.id)}continue}
   if(!i){i={id:id(),policy_id:p.id,node_id:nodeId,cycles:0};run('INSERT INTO ddos_incidents(id,policy_id,node_id,status,evidence_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',i.id,p.id,nodeId,'detected',json(evidence),new Date(at).toISOString(),new Date(at).toISOString());transition(i,'detected',{summary:`${evidence.events} events from ${evidence.uniqueSources} sources in ${p.windowSeconds} seconds`},at)}
   run('UPDATE ddos_incidents SET evidence_json=? WHERE id=?',json(evidence),i.id)
   if(p.mode!=='block')continue
   if(!ddosSupport(node)||evidence.truncated||!evidence.sources.length){run("UPDATE ddos_incidents SET last_error='Automatic block unavailable: check host support, source thresholds or event volume. Detection remains active.' WHERE id=?",i.id);continue}
   const block={id:id(),protocol:p.protocol,ports:p.ports,sources:evidence.sources.map(s=>s.ip),seconds:p.blockSeconds}
   // Persist intent before touching the host; ambiguous outcomes are released on the next pass.
   run('UPDATE ddos_incidents SET block_json=?,expires_at=?,cycles=cycles+1 WHERE id=?',json(block),new Date(at+p.blockSeconds*1000).toISOString(),i.id);i.cycles++;transition(i,'blocking',{},at)
   try{const result=await execute(node,'ddos_start',block);if(!result?.active||!result.nativeExpiry)throw new Error('Host did not confirm a block with native expiry');run('UPDATE ddos_incidents SET expires_at=? WHERE id=?',new Date(at+p.blockSeconds*1000+5000).toISOString(),i.id);transition(i,'blocked',{summary:`${block.sources.length} source addresses blocked for ${p.blockSeconds} seconds`},at)}catch(e){run('UPDATE ddos_incidents SET last_error=? WHERE id=?',String(e.message).slice(0,500),i.id);audit(null,'ddos.block.failed','ddos_incident',i.id,null,{error:String(e.message).slice(0,500)})}
  }
 }finally{running=false}
}
