import {db,all,one,run,id,now,json,audit} from './db.js'
import {openSealed} from './security.js'
import {registerHost} from './networkDiscovery.js'
import {filterSnmpCandidates,pollSnmpDevice} from './snmpDiscovery.js'

const MAX_REGISTER=512
export function publicSnmpTarget(row){
  const result=JSON.parse(row.last_result_json||'{}')
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
function ensureSnmpNode(target,device,stamp){
  const existing=one('SELECT * FROM nodes WHERE ip=? OR lower(hostname)=lower(?) OR lower(fqdn)=lower(?) ORDER BY CASE WHEN inventory_source=\'ad\' THEN 0 ELSE 1 END LIMIT 1',target.host,target.host,target.host)
  const identity=device.identity||{},classification=device.classification||{}
  const hostname=identity.sysName||target.host,deviceType=classification.deviceType||'other',manageability=classification.manageability||'snmp'
  let nodeId=existing?.id
  if(existing){
    run("UPDATE nodes SET hostname=COALESCE(NULLIF(?,''),hostname),ip=COALESCE(ip,?),connection_mode='snmp',transport='snmp',status='reachable',agent_required=0,snmp_capable=1,device_type=?,management_type='snmp',manageability=?,hypervisor=CASE WHEN ?='hypervisor' THEN COALESCE(?,hypervisor) ELSE hypervisor END,last_seen_at=?,last_discovered_at=?,last_probe_at=?,probe_status='snmp-authenticated',discovery_source=? WHERE id=?",hostname,target.host,deviceType,manageability,deviceType,classification.vendor||null,stamp,stamp,stamp,`snmp:${target.id}`,existing.id)
  }else{
    nodeId=id()
    run("INSERT INTO nodes(id,hostname,fqdn,ip,connection_mode,transport,status,inventory_source,discovery_source,last_seen_at,last_discovered_at,last_probe_at,probe_status,agent_required,firewall_state,snmp_capable,device_type,management_type,manageability,hypervisor,os_name,os_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,'unmanaged',1,?,?,?,?,?,?)",nodeId,hostname,null,target.host,'snmp','snmp','reachable','snmp',`snmp:${target.id}`,stamp,stamp,stamp,'snmp-authenticated',deviceType,'snmp',manageability,classification.deviceType==='hypervisor'?classification.vendor:null,classification.vendor||null,identity.sysDescr||null)
  }
  run("INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET snapshot_json=excluded.snapshot_json,collected_at=excluded.collected_at",nodeId,json({source:'snmp',identity,classification,arp:device.arp||[],macPorts:device.macPorts||[],collectedAt:stamp}),stamp)
  run("INSERT INTO network_table_snapshots(node_id,arp_json,state_json,source,collected_at,identity_json,routes_json,tcp_states_json) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET arp_json=excluded.arp_json,state_json=excluded.state_json,source=excluded.source,collected_at=excluded.collected_at,identity_json=excluded.identity_json",nodeId,json(device.arp||[]),json(device.macPorts||[]),'snmp',stamp,json(identity),'{}','{}')
  return nodeId
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
      try{registrations.push(await register(candidate.ip,`snmp:${target.id}`,'snmp'))}
      catch(error){registrations.push({ip:candidate.ip,error:error.message,livenessMethod:'snmp'})}
    }
    const result={host:device.host,targetNodeId,identity:device.identity||{},classification:device.classification||{},arpCount:device.arp.length,macPortCount:device.macPorts.length,candidateCount:candidates.length,registeredCount:registrations.filter(item=>item.nodeId).length,arp:device.arp.slice(0,MAX_REGISTER),macPorts:device.macPorts.slice(0,MAX_REGISTER),registrations}
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
