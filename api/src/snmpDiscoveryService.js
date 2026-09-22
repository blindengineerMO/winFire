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
export async function pollSnmpDiscoveryTarget(targetId,{actorId=null,devicePoll=pollSnmpDevice,register=registerHost}={}){
  const target=targetWithCredential(targetId)
  if(!target)throw Object.assign(new Error('SNMP discovery target not found'),{status:404})
  const started=now(),pollId=id()
  run('INSERT INTO snmp_discovery_polls(id,target_id,status,started_at,requested_by) VALUES(?,?,?,?,?)',pollId,target.id,'running',started,actorId)
  try{
    const device=await devicePoll({host:target.host,credential:{type:target.credential_type,secret:target.secret}})
    const candidates=filterSnmpCandidates(device.arp,target.cidr)
    const registrations=[]
    for(const candidate of candidates.slice(0,MAX_REGISTER)){
      try{registrations.push(await register(candidate.ip,`snmp:${target.id}`,'snmp'))}
      catch(error){registrations.push({ip:candidate.ip,error:error.message,livenessMethod:'snmp'})}
    }
    const result={host:device.host,arpCount:device.arp.length,macPortCount:device.macPorts.length,candidateCount:candidates.length,registeredCount:registrations.filter(item=>item.nodeId).length,arp:device.arp.slice(0,MAX_REGISTER),macPorts:device.macPorts.slice(0,MAX_REGISTER),registrations}
    const finished=now()
    run('UPDATE snmp_discovery_polls SET status=?,arp_count=?,mac_port_count=?,registered_count=?,result_json=?,finished_at=? WHERE id=?','complete',device.arp.length,device.macPorts.length,result.registeredCount,json(result),finished,pollId)
    run('UPDATE snmp_discovery_targets SET last_poll_at=?,last_status=?,last_error=NULL,last_result_json=?,updated_at=? WHERE id=?',finished,'complete',json(result),finished,target.id)
    audit(actorId,'snmp-discovery.poll.complete','snmp-target',target.id,null,{pollId,arpCount:result.arpCount,macPortCount:result.macPortCount,registeredCount:result.registeredCount})
    return {...result,pollId,status:'complete',finishedAt:finished}
  }catch(error){
    const finished=now(),message=String(error.message||error).slice(0,500)
    run('UPDATE snmp_discovery_polls SET status=?,error=?,finished_at=? WHERE id=?','failed',message,finished,pollId)
    run('UPDATE snmp_discovery_targets SET last_poll_at=?,last_status=?,last_error=?,updated_at=?',finished,'failed',message,finished,target.id)
    audit(actorId,'snmp-discovery.poll.failed','snmp-target',target.id,null,{pollId,error:message})
    throw error
  }
}
export function dueSnmpTargets(at=now()){
  return all(`SELECT id FROM snmp_discovery_targets WHERE enabled=1 AND (last_poll_at IS NULL OR datetime(last_poll_at)<=datetime(?, '-'||poll_interval_minutes||' minutes')) ORDER BY last_poll_at`,at)
}
