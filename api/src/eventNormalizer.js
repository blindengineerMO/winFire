const firewallAllow=new Set([5156])
const firewallBlock=new Set([5150,5151,5157])

function intOrNull(value) {
  if(value===undefined||value===null||String(value).trim()==='')return null
  const number=Number(value)
  return Number.isInteger(number)&&number>=0?number:null
}

export function normalizeWindowsEvent(event) {
  const id=Number(event.Id??event.id),fields=event.Fields??event.fields??{}
  const eventType=firewallAllow.has(id)||firewallBlock.has(id)?'firewall':[4624,4625,4634,4647].includes(id)?'logon':id===5712?'rpc':'other'
  const action=firewallAllow.has(id)?'allow':firewallBlock.has(id)?'block':id===4624?'success':id===4625?'failure':[4634,4647].includes(id)?'logoff':null
  const rawProtocol=String(fields.Protocol||'')
  const protocol=rawProtocol==='6'?'TCP':rawProtocol==='17'?'UDP':rawProtocol||null
  const rawDirection=String(fields.Direction||'')
  const direction=rawDirection==='%%14592'||rawDirection.toLowerCase()==='inbound'?'in':rawDirection==='%%14593'||rawDirection.toLowerCase()==='outbound'?'out':rawDirection||null
  // Older 515x event layouts name the local listener Source on inbound
  // records. Newer Windows events include InterfaceIndex/FilterOrigin and
  // already use the network source -> destination order.
  const modernFirewall=eventType==='firewall'&&(fields.InterfaceIndex!==undefined||fields.FilterOrigin!==undefined||fields.CurrentProfile!==undefined)
  const reverseInbound=eventType==='firewall'&&direction==='in'&&!modernFirewall
  return {
    recordId:intOrNull(event.RecordId??event.recordId),eventId:id,eventTime:event.TimeCreated??event.timeCreated??null,eventType,action,protocol,
    srcIp:(reverseInbound?fields.DestAddress:fields.SourceAddress)||fields.IpAddress||null,srcPort:intOrNull(reverseInbound?fields.DestPort:fields.SourcePort||fields.IpPort),
    dstIp:(reverseInbound?fields.SourceAddress:fields.DestAddress)||null,dstPort:intOrNull(reverseInbound?fields.SourcePort:fields.DestPort),direction,
    program:fields.Application||fields.ProcessName||null,accountSid:fields.TargetUserSid||fields.SubjectUserSid||null,
    filterOrigin:fields.FilterOrigin||null,filterRuntimeId:fields.FilterRTID||null,
    logonType:fields.LogonType||null
  }
}
