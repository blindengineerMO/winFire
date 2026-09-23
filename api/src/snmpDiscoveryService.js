import {db,all,one,run,id,now,json,audit} from './db.js'
import {openSealed} from './security.js'
import {registerHost} from './networkDiscovery.js'
import {filterSnmpCandidates,pollSnmpDevice} from './snmpDiscovery.js'

const MAX_REGISTER=512
export function publicSnmpTarget(row){
  let result={}
  try{result=JSON.parse(row.last_result_json||'{}')||{}}catch{}
  return {id:row.id,name:row.name,host:row.host,cidr:row.cidr||null,credentialId:row.credential_id,credentialName:row.credential_name||null,enabled:!!row.enabled,pollIntervalMinutes:row.poll_interval_minutes,lastPollAt:row.last_poll_at,lastStatus:row.last_status,lastError:row.last_error,arpCount:result.arpCount||0,macPortCount:result.macPortCount||0,registeredCount:result.registeredCount||0,createdAt:row.created_at,updatedAt:row.updated_at}
}
export function snmpTargets(){
  return all(`SELECT t.*,c.name AS credential_name FROM snmp_discovery_targets t JOIN credentials c ON c.id=t.credential_id ORDER BY t.name`).map(publicSnmpTarget)
}
export function targetWithCredential(targetId){
  const row=one('SELECT t.*,c.name AS credential_name,c.type AS credential_type,c.encrypted_blob FROM snmp_discovery_targets t JOIN credentials c ON c.id=t.credential_id WHERE t.id=?',targetId)
  if(!row)return null
  return {...row,secret:openSealed(row.encrypted_blob)}
}
export function ensureSnmpNode(target,device,stamp){
  const existing=one('SELECT * FROM nodes WHERE ip=? OR lower(hostname)=lower(?) OR lower(fqdn)=lower(?) ORDER BY CASE WHEN inventory_source=\'ad\' THEN 0 ELSE 1 END LIMIT 1',target.host,target.host,target.host)
  const identity=device.identity||{},classification=device.classification||{}
  const hostname=identity.sysName||target.host,deviceType=classification.deviceType||'other',manageability=classification.manageability||'snmp'
  const esxi=classification.hypervisor==='VMware ESXi'||classification.vendor==='VMware ESXi'
  const persistedDeviceType=esxi?'esxi':deviceType
  // A successful SNMP response with an ARP table is useful for east/west
  // learning even when the vendor fingerprint is not recognized yet. Keep
  // those devices in learning so their ARP/state snapshots can train mapping.
  const firewallState=['hypervisor','esxi'].includes(persistedDeviceType)?'unmanaged':['firewall','switch','router'].includes(persistedDeviceType)||device.arp?.length?'learning':'unmanaged'
  const osName=classification.vendor||(identity.sysDescr?'SNMP network device':null),osVersion=identity.sysDescr||null
  let nodeId=existing?.id
  if(existing){
    run("UPDATE nodes SET hostname=COALESCE(NULLIF(?,''),hostname),ip=COALESCE(ip,?),connection_mode='snmp',transport='snmp',status='reachable',agent_required=0,snmp_capable=1,device_type=?,management_type=?,manageability=?,firewall_state=?,hypervisor=CASE WHEN ? IN ('hypervisor','esxi') THEN COALESCE(?,hypervisor) ELSE hypervisor END,os_name=COALESCE(NULLIF(?,''),os_name),os_version=COALESCE(NULLIF(?,''),os_version),last_seen_at=?,last_discovered_at=?,last_probe_at=?,probe_status='snmp-authenticated',discovery_source=? WHERE id=?",hostname,target.host,persistedDeviceType,esxi?'api':'snmp',manageability,firewallState,persistedDeviceType,classification.hypervisor||classification.vendor||null,osName,osVersion,stamp,stamp,stamp,target.source||`snmp:${target.id}`,existing.id)
  }else{
    nodeId=id()
    run("INSERT INTO nodes(id,hostname,fqdn,ip,connection_mode,transport,status,inventory_source,discovery_source,last_seen_at,last_discovered_at,last_probe_at,probe_status,agent_required,firewall_state,snmp_capable,device_type,management_type,manageability,hypervisor,os_name,os_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,1,?,?,?,?,?,?)",nodeId,hostname,null,target.host,'snmp','snmp','reachable','snmp',target.source||`snmp:${target.id}`,stamp,stamp,stamp,'snmp-authenticated',firewallState,persistedDeviceType,esxi?'api':'snmp',manageability,esxi?'VMware ESXi':persistedDeviceType==='hypervisor'?(classification.hypervisor||classification.vendor):null,osName,osVersion)
  }
  run("INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET snapshot_json=excluded.snapshot_json,collected_at=excluded.collected_at",nodeId,json({source:'snmp',identity,classification,arp:device.arp||[],macPorts:device.macPorts||[],routes:device.routes||{},tcpStates:device.tcpStates||{},pfStates:device.pfStates||device.firewallStates||{},firewallStates:device.firewallStates||device.pfStates||{},collectedAt:stamp}),stamp)
  run("INSERT INTO network_table_snapshots(node_id,arp_json,state_json,source,collected_at,identity_json,routes_json,tcp_states_json) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET arp_json=excluded.arp_json,state_json=excluded.state_json,source=excluded.source,collected_at=excluded.collected_at,identity_json=excluded.identity_json,routes_json=excluded.routes_json,tcp_states_json=excluded.tcp_states_json",nodeId,json(device.arp||[]),json({macPorts:device.macPorts||[],pfStates:device.pfStates||device.firewallStates||{},firewallStates:device.firewallStates||device.pfStates||{}}),'snmp',stamp,json(identity),json(device.routes||{}),json(device.tcpStates||{}))
  return nodeId
}
/** Poll one already-inventoried node with its assigned SNMP credential.
 * This is intentionally separate from discovery targets: assigning a vault
 * credential to a node must be enough to collect facts and begin ARP learning.
 */
export async function pollSnmpNode(node,{credential,actorId=null,devicePoll=pollSnmpDevice}={}){
  if(!node?.id)throw new Error('SNMP node is required')
  if(!credential?.type)throw new Error('An SNMP credential is required')
  const host=node.ip||node.fqdn||node.hostname
  const device=await devicePoll({host,credential})
  const finished=now()
  const nodeId=ensureSnmpNode({id:node.id,host,source:`snmp:node:${node.id}`},device,finished)
  audit(actorId,'snmp-node.poll.complete','node',nodeId,null,{host,arpCount:device.arp?.length||0,macPortCount:device.macPorts?.length||0})
  return {nodeId,host:device.host,identity:device.identity||{},classification:device.classification||{},arpCount:device.arp?.length||0,macPortCount:device.macPorts?.length||0,firewallStateCount:Object.keys(device.firewallStates||device.pfStates||{}).length,routeCount:Object.keys(device.routes||{}).length,tcpStateCount:Object.keys(device.tcpStates||{}).length,arp:device.arp||[],macPorts:device.macPorts||[],firewallStates:device.firewallStates||device.pfStates||{},routes:device.routes||{},tcpStates:device.tcpStates||{},status:'complete',finishedAt:finished}
}
export function dueSnmpNodes(at=now(),limit=32){
  return all(`SELECT DISTINCT n.id,n.hostname,n.fqdn,n.ip,n.transport,n.connection_mode,n.last_probe_at
    FROM nodes n JOIN credential_assignments a ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id)
    JOIN credentials c ON c.id=a.credential_id
    WHERE c.type IN ('snmp-v2c','snmp-v3') AND (n.last_probe_at IS NULL OR datetime(n.last_probe_at)<=datetime(?, '-5 minutes'))
    ORDER BY n.last_probe_at IS NOT NULL,n.last_probe_at LIMIT ?`,at,Math.max(1,Math.min(256,Number(limit)||32)))
}
export async function pollAssignedSnmpNode(nodeId,{actorId=null,devicePoll=pollSnmpDevice}={}){
  const node=one('SELECT * FROM nodes WHERE id=?',nodeId)
  if(!node)throw Object.assign(new Error('SNMP node not found'),{status:404})
  const credential=one(`SELECT c.* FROM credentials c JOIN credential_assignments a ON a.credential_id=c.id
    WHERE c.type IN ('snmp-v2c','snmp-v3') AND (a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?)) ORDER BY c.priority,c.name LIMIT 1`,node.id,node.id)
  if(!credential)throw new Error('No SNMP credential assigned to node')
  return pollSnmpNode(node,{credential:{type:credential.type,secret:openSealed(credential.encrypted_blob)},actorId,devicePoll})
}
export async function pollSnmpDiscoveryTarget(targetId,{actorId=null,devicePoll=pollSnmpDevice,register=registerHost}={}){
  const target=targetWithCredential(targetId)
  if(!target)throw Object.assign(new Error('SNMP discovery target not found'),{status:404})
  const started=now(),pollId=id()
  run('INSERT INTO snmp_discovery_polls(id,target_id,status,started_at,requested_by) VALUES(?,?,?,?,?)',pollId,target.id,'running',started,actorId)
  try{
    const device=await devicePoll({host:target.host,credential:{type:target.credential_type,secret:target.secret}})
    const targetNodeId=ensureSnmpNode(target,device,now())
    const candidates=filterSnmpCandidates(device.arp,target.cidr)
    const registrations=[]
    for(const candidate of candidates.slice(0,MAX_REGISTER)){
      try{registrations.push(await register(candidate.ip,`snmp:${target.id}`,'snmp',{mac:candidate.mac}))}
      catch(error){registrations.push({ip:candidate.ip,error:error.message,livenessMethod:'snmp'})}
    }
    const result={host:device.host,targetNodeId,identity:device.identity||{},classification:device.classification||{},arpCount:device.arp.length,macPortCount:device.macPorts.length,firewallStateCount:Object.keys(device.firewallStates||device.pfStates||{}).length,routeCount:Object.keys(device.routes||{}).length,tcpStateCount:Object.keys(device.tcpStates||{}).length,candidateCount:candidates.length,registeredCount:registrations.filter(item=>item.nodeId).length,arp:device.arp.slice(0,MAX_REGISTER),macPorts:device.macPorts.slice(0,MAX_REGISTER),firewallStates:device.firewallStates||device.pfStates||{},routes:device.routes||{},tcpStates:device.tcpStates||{},registrations}
    const finished=now()
    run('UPDATE snmp_discovery_polls SET status=?,arp_count=?,mac_port_count=?,registered_count=?,result_json=?,finished_at=? WHERE id=?','complete',device.arp.length,device.macPorts.length,result.registeredCount,json(result),finished,pollId)
    run('UPDATE snmp_discovery_targets SET last_poll_at=?,last_status=?,last_error=NULL,last_result_json=?,updated_at=? WHERE id=?',finished,'complete',json(result),finished,target.id)
    audit(actorId,'snmp-discovery.poll.complete','snmp-target',target.id,null,{pollId,arpCount:result.arpCount,macPortCount:result.macPortCount,registeredCount:result.registeredCount})
    return {...result,pollId,status:'complete',finishedAt:finished}
  }catch(error){
    const finished=now(),message=String(error.message||error).slice(0,500)
    run('UPDATE snmp_discovery_polls SET status=?,error=?,finished_at=? WHERE id=?','failed',message,finished,pollId)
    run('UPDATE snmp_discovery_targets SET last_poll_at=?,last_status=?,last_error=?,updated_at=? WHERE id=?',finished,'failed',message,finished,target.id)
    audit(actorId,'snmp-discovery.poll.failed','snmp-target',target.id,null,{pollId,error:message})
    throw error
  }
}
export function dueSnmpTargets(at=now()){
  return all(`SELECT id FROM snmp_discovery_targets WHERE enabled=1 AND (last_poll_at IS NULL OR datetime(last_poll_at)<=datetime(?, '-'||poll_interval_minutes||' minutes')) ORDER BY last_poll_at`,at)
}
