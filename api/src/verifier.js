import {diffRules} from './connector.js'

export function findMatchingDenyEvent(events,probe,port,startedAt,finishedAt,minRecordId=null){
  if(!probe?.sourceIp||!Number.isInteger(Number(probe.sourcePort))||Number(probe.sourcePort)<1||!Number.isInteger(Number(port)))return null
  const start=Date.parse(startedAt)-2000,end=Date.parse(finishedAt)+5000
  if(minRecordId===null&&(!Number.isFinite(start)||!Number.isFinite(end)))return null
  const normalizeIp=value=>String(value||'').toLowerCase().replace(/^::ffff:/,'')
  return (events||[]).find(event=>event.event_id===5157&&event.action==='block'&&event.direction==='in'&&event.protocol==='TCP'&&normalizeIp(event.src_ip)===normalizeIp(probe.sourceIp)&&Number(event.src_port)===Number(probe.sourcePort)&&Number(event.dst_port)===Number(port)&&(minRecordId===null?Number.isFinite(Date.parse(event.event_time))&&Date.parse(event.event_time)>=start&&Date.parse(event.event_time)<=end:Number(event.record_id)>minRecordId))||null
}

export function classifyVerification(rule, probeStatus, managedRulePresent, firewallEvent=null, managedRuleName=null) {
  if (!['allow','block'].includes(rule.action)) return {status:'inconclusive',reason:'Unsupported firewall action'}
  if (rule.action === 'allow') {
    if (probeStatus === 'open') return {status:'pass',reason:'TCP connection opened'}
    if (probeStatus === 'refused') return {status:'fail',reason:'Target refused the connection; service and firewall state need inspection'}
    return {status:'inconclusive',reason:'Target or network did not respond'}
  }
  if (probeStatus === 'open') return {status:'fail',reason:'TCP connection opened despite deny policy'}
  if (managedRulePresent === true && ['refused','timeout'].includes(probeStatus) && firewallEvent) {
    const origin=String(firewallEvent.filter_origin||'').trim().toLowerCase()
    const name=String(managedRuleName||'').trim().toLowerCase()
    if(origin&&name&&origin===name)return {status:'pass',reason:`WFP block event ${firewallEvent.record_id} identifies the managed deny rule`}
    return {status:'inconclusive',reason:origin?`WFP block event ${firewallEvent.record_id} identifies another filter: ${firewallEvent.filter_origin}`:`WFP block event ${firewallEvent.record_id} has no rule origin; the blocking rule cannot be identified`}
  }
  return {status:'inconclusive',reason:managedRulePresent === false
    ? 'Managed deny rule is missing or differs from the policy'
    : managedRulePresent === true ? 'TCP did not open, but no matching local WFP block event was collected'
      : 'TCP did not open; managed rule could not be confirmed'}
}

export function hasManagedRule(rule, actualRules) {
  const matching=(actualRules||[]).filter(actual=>actual.name===rule.name)
  return matching.length===1 && diffRules([rule],matching).add.length===0
}
