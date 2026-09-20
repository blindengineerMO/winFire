const firewallAllow=new Set([5156])
const firewallBlock=new Set([5150,5151,5157])

function intOrNull(value) {
  if(value===undefined||value===null||String(value).trim()==='')return null
  const number=Number(value)
  return Number.isInteger(number)&&number>=0?number:null
}

export function normalizeWindowsEvent(event) {
  const id=Number(event.Id??event.id),fields=event.Fields??event.fields??{}
  const eventType=firewallAllow.has(id)||firewallBlock.has(id)?'firewall':[4624,4625].includes(id)?'logon':id===5712?'rpc':'other'
  const action=firewallAllow.has(id)?'allow':firewallBlock.has(id)?'block':id===4624?'success':id===4625?'failure':null
  const rawProtocol=String(fields.Protocol||'')
  const protocol=rawProtocol==='6'?'TCP':rawProtocol==='17'?'UDP':rawProtocol||null
  const rawDirection=String(fields.Direction||'')
  const direction=rawDirection==='%%14592'||rawDirection.toLowerCase()==='inbound'?'in':rawDirection==='%%14593'||rawDirection.toLowerCase()==='outbound'?'out':rawDirection||null
  // WFP 515x names the local listener Source on inbound records. Store a
  // conventional network tuple (remote source -> local destination) instead.
  const inboundFirewall=eventType==='firewall'&&direction==='in'
  return {
    recordId:intOrNull(event.RecordId??event.recordId),eventId:id,eventTime:event.TimeCreated??event.timeCreated??null,eventType,action,protocol,
    srcIp:(inboundFirewall?fields.DestAddress:fields.SourceAddress)||fields.IpAddress||null,srcPort:intOrNull(inboundFirewall?fields.DestPort:fields.SourcePort||fields.IpPort),
    dstIp:(inboundFirewall?fields.SourceAddress:fields.DestAddress)||null,dstPort:intOrNull(inboundFirewall?fields.SourcePort:fields.DestPort),direction,
    program:fields.Application||fields.ProcessName||null,accountSid:fields.TargetUserSid||fields.SubjectUserSid||null,
    logonType:fields.LogonType||null
  }
}
