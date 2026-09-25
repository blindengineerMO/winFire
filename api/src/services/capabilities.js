import {all,one,run,now,audit} from '../db.js'
import {isLocalAssetNode} from './networkBoundary.js'
const names=['discovery','authentication','facts','firewallRead','firewallWrite','policyReadback','events','flows','verification']
const defaults={discovery:168,authentication:24,facts:24,firewallRead:24,firewallWrite:168,policyReadback:24,events:2,flows:2,verification:24}
export function coverageSettings(){return {...defaults,...JSON.parse(one("SELECT value FROM app_settings WHERE key='coverage_freshness_hours'")?.value||'{}')}}
export function saveCoverageSettings(value,actor){
  for(const [key,hours] of Object.entries(value))if(!names.includes(key)||!Number.isFinite(hours)||hours<0.05||hours>8760)throw Object.assign(new Error('Freshness thresholds must be 0.05–8760 hours for known capabilities'),{status:400})
  const before=coverageSettings(),next={...before,...value};run("INSERT INTO app_settings(key,value) VALUES('coverage_freshness_hours',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",JSON.stringify(next));audit(actor,'coverage.settings','settings','coverage',before,next);return next
}
export function capabilityEvidence(nodeId,capability,source,{success=true,code=null,detail={}}={}){
  if(!names.includes(capability)||!nodeId||!one('SELECT id FROM nodes WHERE id=?',nodeId))return
  run(`INSERT INTO node_capability_evidence(node_id,capability,source,last_success_at,last_failure_at,failure_code,detail_json) VALUES(?,?,?,?,?,?,?) ON CONFLICT(node_id,capability,source) DO UPDATE SET last_success_at=COALESCE(excluded.last_success_at,last_success_at),last_failure_at=COALESCE(excluded.last_failure_at,last_failure_at),failure_code=excluded.failure_code,detail_json=excluded.detail_json`,nodeId,capability,source,success?now():null,success?null:now(),success?null:code||'operation_failed',JSON.stringify(detail))
}
export function nodeCoverage(node,{at=Date.now(),settings=coverageSettings()}={}){
  const evidence=all('SELECT * FROM node_capability_evidence WHERE node_id=?',node.id),facts=one('SELECT collected_at FROM node_facts WHERE node_id=?',node.id),cursor=one('SELECT updated_at FROM node_log_cursors WHERE node_id=?',node.id)
  const auth=one('SELECT MAX(last_success_at) success,MAX(last_auth_failure_at) failure FROM credential_auth_health WHERE node_id=?',node.id)
  const agent=node.agent_id?one('SELECT last_checkin_at,revoked_at FROM agents WHERE id=?',node.agent_id):null
  const snmp=node.transport==='snmp'||node.connection_mode==='snmp',cloud=node.inventory_source==='azure'||node.inventory_source==='azure-arc',api=node.transport==='esxi-soap'
  const host=['winrm','winrms','wmi','netsh','ssh'].includes(node.transport)||!!agent&&!agent.revoked_at
  const latest=(...values)=>values.filter(Boolean).sort((a,b)=>Date.parse(b)-Date.parse(a))[0]||null
  const raw={discovery:latest(node.first_discovered_at,node.last_seen_at,one('SELECT MAX(fetched_at) at FROM asset_sources WHERE node_id=?',node.id)?.at),authentication:latest(auth?.success,agent&&!agent.revoked_at?agent.last_checkin_at:null),facts:facts?.collected_at,events:cursor?.updated_at,verification:latest(snmp&&node.probe_status==='verified'?node.last_probe_at:null,one('SELECT MAX(run_at) at FROM verifier_results WHERE node_id=? AND passed=1',node.id)?.at)}
  const agentOnline=!!agent&&!agent.revoked_at&&!!agent.last_checkin_at&&at-Date.parse(agent.last_checkin_at)<=300000
  const supported={discovery:true,authentication:host||snmp||api,facts:host||snmp||api,firewallRead:host,firewallWrite:host&&!/^(?:5\.[12]\.|windows (?:xp|server 2003))/i.test(String(node.os_version||'')),policyReadback:host,events:host&&node.transport!=='ssh',flows:evidence.some(e=>e.capability==='flows')||!!one('SELECT id FROM telemetry_exporters WHERE node_id=? AND enabled=1 LIMIT 1',node.id),verification:host||snmp||api}
  const capabilities={}
  for(const key of names){
    const entries=evidence.filter(e=>e.capability===key),success=latest(raw[key],...entries.map(e=>e.last_success_at)),failure=latest(key==='authentication'?auth?.failure:null,...entries.map(e=>e.last_failure_at)),fresh=success&&Number.isFinite(Date.parse(success))&&Date.parse(success)<=at+60000&&at-Date.parse(success)<=settings[key]*3600000
    const state=!supported[key]?'unsupported':key==='authentication'&&agent&&!agentOnline?'stale':failure&&(!success||Date.parse(failure)>=Date.parse(success))?'failed':!success?'missing':fresh?'fresh':'stale'
    capabilities[key]={state,lastSuccessAt:success,lastFailureAt:failure,thresholdHours:settings[key],sources:entries.map(e=>e.source),evidence:entries.map(e=>({source:e.source,lastSuccessAt:e.last_success_at,lastFailureAt:e.last_failure_at,failureCode:e.failure_code,detail:JSON.parse(e.detail_json||'{}')})),remediation:state==='fresh'?null:key==='authentication'?'/admin':'/inventory?node='+node.id}
  }
  const gaps=names.filter(k=>supported[k]&&capabilities[k].state!=='fresh')
  return {nodeId:node.id,hostname:node.hostname,address:node.ip,scopeId:node.scope_id||'default',transport:node.connection_mode==='agent'?'agent':node.transport||node.connection_mode||'unknown',source:node.inventory_source,eligible:isLocalAssetNode(node),agentOnline,cloudObservationOnly:cloud&&!host&&!snmp&&!api,capabilities,gaps,learningReady:host&&(!agent||!agent.revoked_at&&!!agent.last_checkin_at&&at-Date.parse(agent.last_checkin_at)<=300000)&&['authentication','events'].every(k=>capabilities[k].state==='fresh')}
}
export function fleetCoverage({q='',scopeId,transport,source,gap,page=1,pageSize=25}={}){
  const settings=coverageSettings(),nodes=all('SELECT * FROM nodes'),eligible=nodes.filter(isLocalAssetNode),term=String(q).trim().toLowerCase()
  const rows=eligible.filter(n=>(!scopeId||n.scope_id===scopeId)&&(!transport||n.transport===transport)&&(!source||n.inventory_source===source)&&(!term||[n.hostname,n.ip,n.os_name].join(' ').toLowerCase().includes(term))).map(n=>nodeCoverage(n,{settings})).filter(n=>!gap||n.gaps.includes(gap)).sort((a,b)=>b.gaps.length-a.gaps.length||String(a.hostname||'').localeCompare(String(b.hostname||''))||a.nodeId.localeCompare(b.nodeId))
  const breakdown=key=>Object.fromEntries([...new Set(nodes.map(n=>n[key]||'unknown'))].sort().map(value=>[value,{eligible:eligible.filter(n=>(n[key]||'unknown')===value).length,excluded:nodes.filter(n=>(n[key]||'unknown')===value&&!isLocalAssetNode(n)).length}]))
  return {breakdown:{transport:breakdown('transport'),source:breakdown('inventory_source'),scope:breakdown('scope_id')},matchedDenominator:rows.length,items:rows.slice((page-1)*pageSize,page*pageSize),total:rows.length,page,pageSize,eligibleDenominator:eligible.length,excluded:nodes.length-eligible.length,summary:Object.fromEntries(names.map(k=>[k,{supported:rows.filter(n=>n.capabilities[k].state!=='unsupported').length,fresh:rows.filter(n=>n.capabilities[k].state==='fresh').length}])),thresholdHours:settings}
}
