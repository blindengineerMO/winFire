import {isIP} from 'node:net'

const firewallIds=new Set([5150,5151,5156,5157])
const fields=['eventId','action','protocol','srcIp','dstIp','dstPort','direction','program','accountSid']
let rules=[]

const text=value=>value===undefined||value===null||String(value).trim()===''?null:String(value).trim()
const number=value=>value===undefined||value===null||String(value).trim()===''?null:Number(value)
const normalizeIp=(value,label)=>{
  const result=text(value)
  if(result&&!isIP(result))throw new Error(`${label} must be an IP address`)
  return result?.toLowerCase()||null
}

export function normalizeTrafficIgnore(input){
  const eventId=Number(input.eventId??input.event_id)
  if(!firewallIds.has(eventId))throw new Error('Traffic ignore rules require a Windows firewall event (5150, 5151, 5156, or 5157)')
  const dstPort=number(input.dstPort??input.dst_port)
  if(dstPort!==null&&(!Number.isInteger(dstPort)||dstPort<1||dstPort>65535))throw new Error('Destination port must be between 1 and 65535')
  const program=text(input.program)?.toLowerCase()||null
  if(program&&program.length>1024)throw new Error('Program path is too long')
  const accountSid=text(input.accountSid??input.account_sid)?.toLowerCase()||null
  if(accountSid&&accountSid.length>184)throw new Error('Account SID is too long')
  const action=text(input.action)?.toLowerCase()||null
  if(action&&!['allow','block'].includes(action))throw new Error('Action must be allow or block')
  const protocol=text(input.protocol)?.toUpperCase()||null
  if(protocol&&!['TCP','UDP'].includes(protocol))throw new Error('Protocol must be TCP or UDP')
  const direction=text(input.direction)?.toLowerCase()||null
  if(direction&&!['in','out'].includes(direction))throw new Error('Direction must be in or out')
  return {eventId,action,protocol,srcIp:normalizeIp(input.srcIp??input.src_ip,'Source IP'),dstIp:normalizeIp(input.dstIp??input.dst_ip,'Destination IP'),dstPort,direction,program,accountSid}
}

export function trafficIgnoreFingerprint(pattern){return JSON.stringify(fields.map(field=>pattern[field]??null))}
export function trafficIgnoreFromEvent(event){return normalizeTrafficIgnore(event)}

function normalizedEvent(event){
  try{return normalizeTrafficIgnore(event)}catch{return null}
}
export function isIgnoredFirewallEvent(event){
  const candidate=normalizedEvent(event)
  if(!candidate)return false
  const fingerprint=trafficIgnoreFingerprint(candidate)
  return rules.some(rule=>rule.fingerprint===fingerprint)
}

export function refreshTrafficIgnores(db){
  rules=db.prepare('SELECT id,label,event_id eventId,action,protocol,src_ip srcIp,dst_ip dstIp,dst_port dstPort,direction,program,account_sid accountSid,fingerprint,created_by createdBy,created_at createdAt FROM traffic_ignore_rules ORDER BY created_at,id').all()
  return rules.map(publicTrafficIgnore)
}

export function publicTrafficIgnore(rule){
  return {id:rule.id,label:rule.label,eventId:Number(rule.event_id??rule.eventId),action:rule.action||null,protocol:rule.protocol||null,srcIp:rule.src_ip??rule.srcIp??null,dstIp:rule.dst_ip??rule.dstIp??null,dstPort:rule.dst_port??rule.dstPort??null,direction:rule.direction||null,program:rule.program||null,accountSid:rule.account_sid??rule.accountSid??null,createdBy:rule.created_by??null,createdAt:rule.created_at??null}
}

export function ignoredTrafficSql(eventAlias='e',patternAlias='p'){
  const value=field=>patternAlias?`COALESCE(${eventAlias}.${field},${patternAlias}.${field})`:`${eventAlias}.${field}`
  return `winfire_ignored_traffic(${eventAlias}.event_id,${value('action')},${value('protocol')},${value('src_ip')},${value('dst_ip')},${value('dst_port')},${value('direction')},${value('program')},${eventAlias}.account_sid)=0`
}

export {firewallIds}
