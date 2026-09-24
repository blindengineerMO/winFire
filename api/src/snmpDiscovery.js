import snmp from 'net-snmp'
import {isIP} from 'node:net'

const ARP_TABLE_OID='1.3.6.1.2.1.4.22'
const FDB_TABLE_OID='1.3.6.1.2.1.17.4.3'
export const SNMP_IDENTITY_OIDS={sysDescr:'1.3.6.1.2.1.1.1.0',sysObjectId:'1.3.6.1.2.1.1.2.0',sysUpTime:'1.3.6.1.2.1.1.3.0',sysContact:'1.3.6.1.2.1.1.4.0',sysName:'1.3.6.1.2.1.1.5.0',sysLocation:'1.3.6.1.2.1.1.6.0',interfaceCount:'1.3.6.1.2.1.2.1.0'}
export const SNMP_VENDOR_OIDS={cisco:'1.3.6.1.4.1.9',pfsenseFreebsd:'1.3.6.1.4.1.8072',sonicwall:'1.3.6.1.4.1.8741',citrixNetscaler:'1.3.6.1.4.1.5951',vmware:'1.3.6.1.4.1.6876',mikrotik:'1.3.6.1.4.1.14988',proxmox:'1.3.6.1.4.1.8072'}
export const SNMP_TABLE_OIDS={arp:ARP_TABLE_OID,route:'1.3.6.1.2.1.4.21',tcp:'1.3.6.1.2.1.6.13',bridge:FDB_TABLE_OID,pfState:'1.3.6.1.4.1.12325.1.200'}
const MAX_REPETITIONS=25
const MAX_ARP_ROWS=4096

const clean=value=>String(value??'').trim()
const ipv4ToInt=ip=>ip.split('.').map(Number).reduce((value,octet)=>(value*256)+octet,0)>>>0
function cidrParts(cidr){
  const [address,prefixText]=clean(cidr).split('/')
  if(isIP(address)!==4)return null
  const prefix=prefixText===undefined?32:Number(prefixText)
  if(!Number.isInteger(prefix)||prefix<0||prefix>32)return null
  const mask=prefix===0?0:(0xffffffff<<(32-prefix))>>>0
  return {network:ipv4ToInt(address)&mask,mask}
}
export function ipInCidr(ip,cidr){
  const parts=cidrParts(cidr)
  return Boolean(parts&&isIP(ip)===4&&(ipv4ToInt(ip)&parts.mask)===parts.network)
}
export function validSnmpHost(value){
  const host=clean(value)
  return (isIP(host)>0||/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(host))?host:null
}
export function normalizeSnmpSecret(type,secret){
  const source=secret&&typeof secret==='object'?secret:{}
  if(type==='snmp-v2c'){
    const community=clean(source.community||source.password)
    if(!community)throw new Error('SNMP v2c requires a community string')
    return {community}
  }
  if(type!=='snmp-v3')throw new Error('Unsupported SNMP credential type')
  const username=clean(source.username)
  const level=clean(source.securityLevel||source.level||'noAuthNoPriv')
  if(!username||!Object.hasOwn(snmp.SecurityLevel,level))throw new Error('SNMP v3 requires a valid user and security level')
  const authProtocol=clean(source.authProtocol||'sha').toLowerCase()
  const privProtocol=clean(source.privProtocol||'aes').toLowerCase()
  if(level!=='noAuthNoPriv'&&!Object.hasOwn(snmp.AuthProtocols,authProtocol))throw new Error('SNMP v3 authentication protocol is invalid')
  if(level==='authPriv'&&!Object.hasOwn(snmp.PrivProtocols,privProtocol))throw new Error('SNMP v3 privacy protocol is invalid')
  const authKey=clean(source.authKey||source.password)
  const privKey=clean(source.privKey)
  if(level!=='noAuthNoPriv'&&authKey.length<8)throw new Error('SNMP v3 authentication key must contain at least 8 characters')
  if(level==='authPriv'&&privKey.length<8)throw new Error('SNMP v3 privacy key must contain at least 8 characters')
  return {username,securityLevel:level,authProtocol,privProtocol,authKey,privKey}
}

function valueToMac(value){
  if(Buffer.isBuffer(value))return [...value].map(byte=>byte.toString(16).padStart(2,'0')).join(':')
  if(value instanceof Uint8Array)return [...value].map(byte=>byte.toString(16).padStart(2,'0')).join(':')
  const text=clean(value)
  return text||null
}
function tableRequest(session,oid,maxRepetitions=MAX_REPETITIONS){
  return new Promise((resolve,reject)=>session.table(oid,maxRepetitions,(error,table)=>error?reject(error):resolve(table||{})))
}
function scalarRequest(session,oid){
  return new Promise((resolve,reject)=>{if(typeof session.get!=='function')return resolve(null);session.get([oid],(error,varbinds)=>error?reject(error):resolve(varbinds?.[0]?.value??null))})
}
const scalarText=value=>Buffer.isBuffer(value)?value.toString('utf8'):String(value??'').trim()
const boundedIdentity=value=>clean(value).slice(0,256)||null
function snmpClassificationEvidence(identity,hit,matched,confidence=null){
  const oid=boundedIdentity(identity.sysObjectId),descr=boundedIdentity(identity.sysDescr),name=boundedIdentity(identity.sysName)
  return {
    source:'snmp',
    method:hit?.method||'identity',
    matched,
    matchedOid:hit?.method==='sysObjectID'?oid:null,
    signal:hit?.method==='sysObjectID'&&hit.marker?`sysObjectID contains ${hit.marker}`:hit?.method==='sysDescr'?'sysDescr/sysName':'sysDescr/sysName/sysObjectID',
    observed:{sysName:name,sysDescr:descr,sysObjectId:oid},
    confidence:confidence|| (hit?.method==='sysObjectID'?'high':hit?.method==='sysDescr'?'medium':'low')
  }
}

/**
 * Match a device identity while optionally retaining the exact signal that
 * caused the match. The default keeps the compact legacy shape for callers
 * that only need the device type; polling requests the evidence-rich form.
 */
export function classifySnmpIdentity(identity={}, {includeEvidence=false}={}){
  const text=`${identity.sysDescr||''} ${identity.sysName||''} ${identity.sysObjectId||''}`.toLowerCase(),oid=String(identity.sysObjectId||'')
  const match=(pattern,markers=[])=>{
    if(pattern.test(text))return {method:'sysDescr',pattern:pattern.source}
    const marker=markers.find(prefix=>oid.includes(prefix))
    return marker?{method:'sysObjectID',marker}:null
  }
  const result=(vendor,deviceType,manageability,hypervisor,hit,confidence)=>{
    const value={vendor,deviceType,manageability,...(hypervisor?{hypervisor}:{})}
    return includeEvidence?{...value,classificationEvidence:snmpClassificationEvidence(identity,hit,vendor||'No vendor fingerprint',confidence)}:value
  }
  let hit
  if((hit=match(/vmware|esxi/,['.6876.'])))return result('VMware ESXi','hypervisor','unmanaged','VMware ESXi',hit,'high')
  if((hit=match(/proxmox|pve-manager/,[])))return result('Proxmox VE','hypervisor','unmanaged','Proxmox VE',hit,'high')
  if((hit=match(/xenserver|xcp-ng|citrix hypervisor/,['.6876.'])))return result('Citrix Hypervisor / XenServer','hypervisor','unmanaged','XenServer',hit,'high')
  if((hit=match(/azure local|azure stack hci|azurestack/,[])))return result('Azure Local','hypervisor','unmanaged','Azure Local',hit,'high')
  if((hit=match(/cisco ios|cisco nexus|cisco catalyst|cisco/,['.9.'])))return result('Cisco IOS/NX-OS','switch','snmp',null,hit)
  if((hit=match(/juniper|junos/,['.2636.'])))return result('Juniper Junos','router','snmp',null,hit)
  if((hit=match(/arubaos|aruba/,['.14823.'])))return result('ArubaOS','switch','snmp',null,hit)
  if((hit=match(/procurve|hpe|hewlett.packard/,['.11.'])))return result('HPE/ProCurve','switch','snmp',null,hit)
  if((hit=match(/fortios|fortinet/,['.12356.'])))return result('Fortinet FortiOS','firewall','snmp',null,hit)
  if((hit=match(/pan.?os|palo alto/,['.25461.'])))return result('Palo Alto PAN-OS','firewall','snmp',null,hit)
  if((hit=match(/sonicwall|sonicos/,['.8741.'])))return result('SonicWall SonicOS','firewall','snmp',null,hit)
  if((hit=match(/check point|gaia/,['.2620.'])))return result('Check Point Gaia','firewall','snmp',null,hit)
  if((hit=match(/big.?ip|f5 networks/,['.3375.'])))return result('F5 BIG-IP','firewall','snmp',null,hit)
  if((hit=match(/huawei|vrp/,['.2011.'])))return result('Huawei VRP','switch','snmp',null,hit)
  if((hit=match(/arista|eos/,['.30065.'])))return result('Arista EOS','switch','snmp',null,hit)
  if((hit=match(/extreme.?xos|extreme networks/,['.1916.'])))return result('ExtremeXOS','switch','snmp',null,hit)
  if((hit=match(/ubiquiti|edgeos|unifi/,['.41112.'])))return result('Ubiquiti EdgeOS/UniFi','switch','snmp',null,hit)
  if((hit=match(/netscaler|citrix adc/,['.5951.'])))return result('Citrix NetScaler','firewall','snmp',null,hit)
  if((hit=match(/mikrotik|routeros/,['.14988.'])))return result('MikroTik RouterOS','router','snmp',null,hit)
  if((hit=match(/pfsense|opnsense/,[])))return result(/opnsense/.test(text)?'OPNsense':'pfSense','firewall','snmp',null,hit)
  if((hit=match(/freebsd/,[])))return result('FreeBSD','firewall','snmp',null,hit)
  if((hit=match(/linux|unix/,[])))return result('Linux/Unix','other','snmp',null,hit)
  if((hit=match(/windows/,[])))return result('Windows','other','snmp',null,hit)
  return result(null,'other','snmp',null,null,'low')
}
function indexIp(index){
  const values=clean(index).split('.').map(Number)
  if(values.length<4||values.slice(-4).some(value=>!Number.isInteger(value)||value<0||value>255))return null
  return values.slice(-4).join('.')
}
function indexMac(index){
  const values=clean(index).split('.').map(Number)
  if(values.length<6||values.slice(-6).some(value=>!Number.isInteger(value)||value<0||value>255))return null
  return values.slice(-6).map(value=>value.toString(16).padStart(2,'0')).join(':')
}
export function normalizeArpTable(table){
  const rows=[]
  for(const [index,columns] of Object.entries(table||{})){
    const ip=indexIp(index),mac=valueToMac(columns?.[2]||columns?.['2'])
    if(!ip||!mac||mac==='00:00:00:00:00:00')continue
    rows.push({ip,mac,interface:String(columns?.[1]??columns?.['1']??'')||null,state:String(columns?.[4]??columns?.['4']??'')||null,source:'snmp'})
    if(rows.length>=MAX_ARP_ROWS)break
  }
  return rows
}
export function normalizeForwardingTable(table){
  const rows=[]
  for(const [index,columns] of Object.entries(table||{})){
    const mac=indexMac(index),port=Number(columns?.[2]??columns?.['2'])
    if(!mac||!Number.isInteger(port)||port<0||port>65535)continue
    rows.push({mac,port,status:columns?.[3]??columns?.['3']??null})
  }
  return rows.slice(0,MAX_ARP_ROWS)
}
export function createSnmpSession(host,credential,{timeoutMs=2500,retries=1,port=161}={}){
  const secret=normalizeSnmpSecret(credential.type,credential.secret||credential)
  const options={port,timeout:timeoutMs,retries,transport:'udp4'}
  if(credential.type==='snmp-v3'){
    return snmp.createV3Session(host,{name:secret.username,level:snmp.SecurityLevel[secret.securityLevel],authProtocol:snmp.AuthProtocols[secret.authProtocol],authKey:secret.authKey,privProtocol:snmp.PrivProtocols[secret.privProtocol],privKey:secret.privKey},options)
  }
  return snmp.createSession(host,secret.community,{...options,version:snmp.Version2c})
}
export async function pollSnmpDevice({host,credential,sessionFactory=createSnmpSession,maxRepetitions=MAX_REPETITIONS}={}){
  const target=validSnmpHost(host);if(!target)throw new Error('SNMP target host is invalid')
  if(!credential||!['snmp-v2c','snmp-v3'].includes(credential.type))throw new Error('An SNMP v2c or v3 credential is required')
  const session=sessionFactory(target,credential)
  try{
    const optionalTable=oid=>tableRequest(session,oid,maxRepetitions).catch(()=>({}))
    const [arpTable,forwardingTable,routeTable,tcpTable,pfStateTable]=await Promise.all([tableRequest(session,ARP_TABLE_OID,maxRepetitions),tableRequest(session,FDB_TABLE_OID,maxRepetitions),optionalTable(SNMP_TABLE_OIDS.route),optionalTable(SNMP_TABLE_OIDS.tcp),optionalTable(SNMP_TABLE_OIDS.pfState)])
    const identity={}
    for(const [name,oid] of Object.entries(SNMP_IDENTITY_OIDS)){try{identity[name]=scalarText(await scalarRequest(session,oid))||null}catch{identity[name]=null}}
    const classification=classifySnmpIdentity(identity,{includeEvidence:true})
    return {host:target,arp:normalizeArpTable(arpTable),macPorts:normalizeForwardingTable(forwardingTable),routes:routeTable,tcpStates:tcpTable,pfStates:pfStateTable,firewallStates:pfStateTable,identity,classification}
  }finally{try{session.close()}catch{}}
}

export function filterSnmpCandidates(arp,cidr){
  const seen=new Set()
  return (arp||[]).filter(row=>isIP(row.ip)===4&&(!cidr||ipInCidr(row.ip,cidr))).filter(row=>{if(seen.has(row.ip))return false;seen.add(row.ip);return true}).slice(0,MAX_ARP_ROWS)
}
