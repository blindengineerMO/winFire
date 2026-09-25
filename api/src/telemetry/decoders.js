import {isIP} from 'node:net'
import {createHash} from 'node:crypto'
const invalid=message=>{throw Object.assign(new Error(message),{status:400})}
const number=buf=>{if(![1,2,4,8].includes(buf.length))return null;const value=buf.length===8?buf.readBigUInt64BE():BigInt(buf.readUIntBE(0,buf.length));return value<=BigInt(Number.MAX_SAFE_INTEGER)?Number(value):value.toString()}
const ip=buf=>buf.length===4?[...buf].join('.'):buf.length===16?Array.from({length:8},(_,i)=>buf.readUInt16BE(i*2).toString(16)).join(':'):null
const protocol=value=>({1:'ICMP',6:'TCP',17:'UDP',58:'ICMPv6'}[value]||String(value||'unknown'))
// Cache keys include enrolled exporter, protocol and observation domain; never trust template IDs globally.
export class FlowDecoder {
 constructor({maxTemplates=4096,ttlMs=1800000}={}){this.templates=new Map();this.sessions=new Map();this.seen=new Map();this.sampling=new Map();this.maxTemplates=maxTemplates;this.ttlMs=ttlMs}
 decode(packet,exporter,options={}){
  const before={templates:new Map(this.templates),sessions:new Map(this.sessions),seen:new Map(this.seen),sampling:new Map(this.sampling)}
  try{const result=this.decodePacket(packet,exporter,options);return options.accept?options.accept(result):result}catch(error){Object.assign(this,before);throw error}
 }
 decodePacket(packet,exporter,{at=Date.now()}={}){
  if(!Buffer.isBuffer(packet)||packet.length<16||packet.length>65535)invalid('Invalid flow datagram length')
  const version=packet.readUInt16BE(0);if(![9,10].includes(version))invalid('Only NetFlow v9 and IPFIX v10 are supported')
  const header=version===9?20:16;if(packet.length<header||version===10&&packet.readUInt16BE(2)!==packet.length)invalid('Truncated flow header')
  const domain=packet.readUInt32BE(version===9?16:12),sequence=packet.readUInt32BE(version===9?12:8),seconds=packet.readUInt32BE(version===9?8:4),uptime=version===9?packet.readUInt32BE(4):null,prefix=`${exporter}:${version}:${domain}:`,previous=this.sessions.get(prefix)
  for(const [key,t] of this.templates)if(at-t.at>this.ttlMs)this.templates.delete(key)
  for(const [key,t] of this.sampling)if(at-t.at>this.ttlMs)this.sampling.delete(key)
  for(const [key,t] of this.seen)if(at-t>60000)this.seen.delete(key)
  const packetKey=prefix+createHash('sha256').update(packet).digest('hex')
  if(this.seen.has(packetKey))return {records:[],duplicate:true,missingTemplates:0,version,domain,sequence}
  // Older export times are late/reordered datagrams. Do not let them replace current templates.
  if(previous&&seconds<previous.seconds)return {records:[],late:true,missingTemplates:0,version,domain,sequence}
  const reboot=previous&&(uptime!==null&&uptime<previous.uptime&&previous.uptime-uptime<0x80000000||sequence<previous.sequence&&previous.sequence-sequence<0x80000000)
  if(reboot)for(const cache of [this.templates,this.sampling])for(const key of cache.keys())if(key.startsWith(prefix))cache.delete(key)
  const records=[];let missingTemplates=0,optionsSkipped=0,optionsRecords=0
  for(let offset=header;offset<packet.length;){
   if(offset+4>packet.length)invalid('Truncated flow set header')
   const setId=packet.readUInt16BE(offset),length=packet.readUInt16BE(offset+2),end=offset+length;if(length<4||end>packet.length)invalid('Invalid flow set length')
   let pos=offset+4
   if(setId===(version===9?0:2)||setId===(version===9?1:3)){
    const optionTemplate=setId===(version===9?1:3)
    while(pos+4<=end){
     const templateId=packet.readUInt16BE(pos);let count=packet.readUInt16BE(pos+2),scopeCount=0;pos+=4
     if(optionTemplate&&count){if(pos+2>end)invalid('Truncated options template');const extra=packet.readUInt16BE(pos);pos+=2;if(version===9){if(count%4||extra%4)invalid('Invalid options field lengths');scopeCount=count/4;count=(count+extra)/4}else scopeCount=extra;if(!scopeCount||scopeCount>count)invalid('Invalid options scope count')}
     if(templateId<256||count>128)invalid('Invalid template ID or field count')
     if(!count){this.templates.delete(prefix+templateId);for(const [k,v] of this.sampling)if(v.templateKey===prefix+templateId)this.sampling.delete(k);continue}
     const fields=[]
     for(let n=0;n<count;n++){
      if(pos+4>end)invalid('Truncated template')
      const type=packet.readUInt16BE(pos),size=packet.readUInt16BE(pos+2);pos+=4;let enterprise=null
      if(version===10&&(type&0x8000)){if(pos+4>end)invalid('Truncated enterprise field');enterprise=packet.readUInt32BE(pos);pos+=4}
      if(!size)invalid('Zero-length template field');fields.push({type:version===10?type&0x7fff:type,size,enterprise})
     }
     if(this.templates.size>=this.maxTemplates&&!this.templates.has(prefix+templateId))this.templates.delete(this.templates.keys().next().value)
     this.templates.set(prefix+templateId,{fields,at,optionTemplate,scopeCount})
    }
   if(end-pos>3||packet.subarray(pos,end).some(b=>b!==0))invalid('Invalid template padding')
   }
   else if(setId>=256){
    const template=this.templates.get(prefix+setId)
    if(!template)missingTemplates++
    else{
     const minSize=template.fields.reduce((n,f)=>n+(f.size===65535?1:f.size),0)
     while(pos+minSize<=end){
      const values={},scopes=[];let complete=true,fieldIndex=0
      for(const field of template.fields){
       let size=field.size
       if(size===65535){if(pos>=end){complete=false;break}size=packet[pos++];if(size===255){if(pos+2>end)invalid('Truncated variable field');size=packet.readUInt16BE(pos);pos+=2}}
       if(pos+size>end){complete=false;break}
       const raw=packet.subarray(pos,pos+size);if(fieldIndex++<(template.scopeCount||0))scopes.push({type:field.type,enterprise:field.enterprise,value:number(raw)});else if(field.enterprise===null)values[field.type]=raw
       pos+=size
      }
      if(!complete)invalid('Truncated data record')
      const val=k=>values[k]?number(values[k]):null,addr=k=>values[k]?ip(values[k]):null
      if(template.optionTemplate){
       optionsRecords++;const interval=val(34)??val(50),algorithm=val(35)??val(49)
       if(interval!==null){const key=prefix+JSON.stringify(scopes);this.sampling.set(key,{prefix,templateKey:prefix+setId,scopes,interval,algorithm,at});while(this.sampling.size>this.maxTemplates)this.sampling.delete(this.sampling.keys().next().value)}else optionsSkipped++;continue
      }
      const candidates=[...this.sampling.values()].filter(s=>s.prefix===prefix&&s.scopes.every(scope=>scope.enterprise===null&&(version===9?scope.type===1?true:scope.type===2?scope.value===val(10):scope.type===5?scope.value===setId:false:scope.type===149?scope.value===domain:[10,14,302].includes(scope.type)?scope.value===val(scope.type):false)))
      const mostSpecific=candidates.filter(s=>s.scopes.length===Math.max(0,...candidates.map(c=>c.scopes.length))),sampling=mostSpecific.length&&mostSpecific.every(s=>s.interval===mostSpecific[0].interval&&s.algorithm===mostSpecific[0].algorithm)?mostSpecific[0]:null
      const interval=val(34)??val(50)??sampling?.interval??null,algorithm=val(35)??val(49)??sampling?.algorithm??null
      const srcIp=addr(8)||addr(27),dstIp=addr(12)||addr(28)
      if(!isIP(srcIp||'')||!isIP(dstIp||''))continue
      const absolute=val(152)??(val(150)!==null?val(150)*1000:null),relative=uptime!==null&&val(22)!==null?seconds*1000-uptime+val(22):null
      records.push({srcIp,dstIp,srcPort:val(7),dstPort:val(11),protocol:protocol(val(4)),action:null,direction:null,eventTime:new Date(absolute??relative??seconds*1000).toISOString(),metadata:{format:version===9?'netflow-v9':'ipfix-v10',domain,sequence,templateId:setId,exportTime:new Date(seconds*1000).toISOString(),inputInterface:val(10),outputInterface:val(14),flowDirection:val(61),packets:val(2),bytes:val(1),samplingInterval:interval,samplingAlgorithm:algorithm,samplingKnown:interval!==null,samplingSource:val(34)!==null||val(50)!==null?'inline':sampling?'options':null,nat:{sourceIp:addr(225)||addr(281),destinationIp:addr(226)||addr(282),sourcePort:val(227),destinationPort:val(228)},uptime,optionsSamplingUnavailable:interval===null}})
      if(records.length>4096)invalid('Flow datagram exceeds 4096 records')
     }
     if(end-pos>3||packet.subarray(pos,end).some(b=>b!==0))invalid('Invalid flow set padding')
    }
   }
   offset=end
  }
  this.seen.set(packetKey,at);while(this.seen.size>4096)this.seen.delete(this.seen.keys().next().value)
  this.sessions.set(prefix,{seconds,sequence,uptime});while(this.sessions.size>1024)this.sessions.delete(this.sessions.keys().next().value)
  return {records,version,domain,sequence,reboot:!!reboot,missingTemplates,optionsSkipped,optionsRecords}
 }
}
export function decodeSyslog(line,format,{receivedAt=new Date().toISOString()}={}){
 if(typeof line!=='string'||Buffer.byteLength(line)>16384)invalid('Syslog record exceeds 16 KiB')
 const timestamp=line.match(/\b\d{4}-\d{2}-\d{2}T[^ ]+/)?.[0],eventTime=timestamp&&Number.isFinite(Date.parse(timestamp))?new Date(timestamp).toISOString():receivedAt
 let record=null
 if(format==='pf-filterlog'){
  const csv=line.match(/filterlog(?:\[\d+\])?:?\s+(?:\d+ - - )?(.+)$/)?.[1];if(!csv)invalid('Expected pfSense/OPNsense filterlog CSV')
  const f=csv.split(','),v=Number(f[8]),src=v===4?18:v===6?15:-1;if(src<0)invalid('Unsupported PF IP version')
  record={srcIp:f[src],dstIp:f[src+1],srcPort:Number(f[src+2])||null,dstPort:Number(f[src+3])||null,protocol:protocol(v===4?f[15]:f[13]),action:({pass:'allow',block:'block'})[f[6]]||null,direction:null,metadata:{interface:f[4],reason:f[5],originalDirection:f[7],rule:f[0],tracker:f[3]}}
 }else if(format==='mikrotik-firewall'){
  const match=line.match(/proto (TCP|UDP|ICMP|ICMPv6)(?: \([^)]*\))?,\s+(\[[^\]]+\]|[\da-f.:]+?)(?::(\d+))?->(\[[^\]]+\]|[\da-f.:]+?)(?::(\d+))?(?:,|\s|$)/i)
  if(!match)invalid('Expected RouterOS firewall connection log')
  record={srcIp:match[2].replace(/[\[\]]/g,''),dstIp:match[4].replace(/[\[\]]/g,''),srcPort:Number(match[3])||null,dstPort:Number(match[5])||null,protocol:protocol(match[1]),action:null,direction:null,metadata:{inputInterface:line.match(/in:([^ ]+)/)?.[1],outputInterface:line.match(/out:([^ ,]+)/)?.[1],verdictUnavailable:true}}
 }else if(format==='sonicwall-kv'){
  const values=Object.fromEntries([...line.matchAll(/\b([A-Za-z][\w]*)=(?:"([^"\r\n]*)"|([^ ]+))/g)].map(m=>[m[1],m[2]??m[3]]))
  const endpoint=value=>{const m=String(value||'').match(/^(\[[^\]]+\]|[^:]+)(?::(\d+))?/);return {ip:m?.[1]?.replace(/[\[\]]/g,''),port:m?.[2]?Number(m[2]):null}}
  const src=endpoint(values.src),dst=endpoint(values.dst)
  record={srcIp:src.ip,dstIp:dst.ip,srcPort:Number(values.spt)||src.port,dstPort:Number(values.dpt)||dst.port,protocol:protocol(values.proto?.split('/')[0]?.toUpperCase()),action:({allow:'allow',allowed:'allow',deny:'block',drop:'block',dropped:'block'})[values.fw_action?.toLowerCase()]||null,direction:null,metadata:{messageId:values.m,inputInterface:values.deviceInboundInterface,outputInterface:values.deviceOutboundInterface,message:values.msg,nat:{sourceIp:values.snpt?null:values.translated_src_ip,destinationIp:values.translated_dst_ip},originalFields:values}}
 }else invalid('Unsupported syslog format')
 if(!isIP(record.srcIp||'')||!isIP(record.dstIp||''))invalid('Syslog did not contain valid flow endpoints')
 if(!['TCP','UDP'].includes(record.protocol))record.srcPort=record.dstPort=null
 return {...record,eventTime,metadata:{...record.metadata,format,originalTimestamp:timestamp||null,timeSource:timestamp?'exporter':'received',raw:line}}
}
