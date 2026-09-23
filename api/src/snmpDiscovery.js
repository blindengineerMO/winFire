import snmp from 'net-snmp'
import {isIP} from 'node:net'

const ARP_TABLE_OID='1.3.6.1.2.1.4.22'
const FDB_TABLE_OID='1.3.6.1.2.1.17.4.3'
export const SNMP_IDENTITY_OIDS={sysDescr:'1.3.6.1.2.1.1.1.0',sysObjectId:'1.3.6.1.2.1.1.2.0',sysUpTime:'1.3.6.1.2.1.1.3.0',sysName:'1.3.6.1.2.1.1.5.0',sysLocation:'1.3.6.1.2.1.1.6.0',interfaceCount:'1.3.6.1.2.1.2.1.0'}
export const SNMP_VENDOR_OIDS={cisco:'1.3.6.1.4.1.9',pfsenseFreebsd:'1.3.6.1.4.1.8072',sonicwall:'1.3.6.1.4.1.8741',citrixNetscaler:'1.3.6.1.4.1.5951',vmware:'1.3.6.1.4.1.6876',mikrotik:'1.3.6.1.4.1.14988',proxmox:'1.3.6.1.4.1.8072'}
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
export function classifySnmpIdentity(identity={}){
  const text=`${identity.sysDescr||''} ${identity.sysObjectId||''}`.toLowerCase()
  if(/vmware|esxi/.test(text))return {vendor:'VMware',deviceType:'hypervisor',manageability:'unmanaged'}
  if(/cisco/.test(text)||String(identity.sysObjectId||'').includes('.9.'))return {vendor:'Cisco',deviceType:'switch',manageability:'snmp'}
  if(/sonicwall/.test(text)||String(identity.sysObjectId||'').includes('.8741.'))return {vendor:'SonicWall',deviceType:'firewall',manageability:'snmp'}
  if(/netscaler|citrix adc/.test(text)||String(identity.sysObjectId||'').includes('.5951.'))return {vendor:'Citrix NetScaler',deviceType:'firewall',manageability:'snmp'}
  if(/mikrotik|routeros/.test(text)||String(identity.sysObjectId||'').includes('.14988.'))return {vendor:'MikroTik',deviceType:'router',manageability:'snmp'}
  if(/pfsense|freebsd/.test(text))return {vendor:'pfSense/FreeBSD',deviceType:'firewall',manageability:'snmp'}
  if(/proxmox/.test(text))return {vendor:'Proxmox',deviceType:'hypervisor',manageability:'unmanaged'}
  if(/linux|unix/.test(text))return {vendor:'Linux/Unix',deviceType:'other',manageability:'snmp'}
  if(/windows/.test(text))return {vendor:'Windows',deviceType:'other',manageability:'snmp'}
  return {vendor:null,deviceType:'other',manageability:'snmp'}
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
    const [arpTable,forwardingTable]=await Promise.all([tableRequest(session,ARP_TABLE_OID,maxRepetitions),tableRequest(session,FDB_TABLE_OID,maxRepetitions)])
    const identity={}
    for(const [name,oid] of Object.entries(SNMP_IDENTITY_OIDS)){try{identity[name]=scalarText(await scalarRequest(session,oid))||null}catch{identity[name]=null}}
    const classification=classifySnmpIdentity(identity)
    return {host:target,arp:normalizeArpTable(arpTable),macPorts:normalizeForwardingTable(forwardingTable),identity,classification}
  }finally{try{session.close()}catch{}}
}

export function filterSnmpCandidates(arp,cidr){
  const seen=new Set()
  return (arp||[]).filter(row=>isIP(row.ip)===4&&(!cidr||ipInCidr(row.ip,cidr))).filter(row=>{if(seen.has(row.ip))return false;seen.add(row.ip);return true}).slice(0,MAX_ARP_ROWS)
}
