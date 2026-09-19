import {Client} from 'ldapts'

const directoryAttributes=['objectGUID','objectSid','distinguishedName','name','dNSHostName','operatingSystem','operatingSystemVersion','lastLogonTimestamp','userAccountControl','whenChanged']
const first=value=>Array.isArray(value)?value[0]:value
const attribute=(entry,name)=>first(entry[Object.keys(entry).find(key=>key.toLowerCase()===name.toLowerCase())])

export function guidFromDirectory(value) {
  if(!value)return null
  if(typeof value==='string'&&/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value))return value.toLowerCase()
  const bytes=Buffer.from(value)
  if(bytes.length!==16)return null
  return `${bytes.readUInt32LE(0).toString(16).padStart(8,'0')}-${bytes.readUInt16LE(4).toString(16).padStart(4,'0')}-${bytes.readUInt16LE(6).toString(16).padStart(4,'0')}-${bytes.subarray(8,10).toString('hex')}-${bytes.subarray(10).toString('hex')}`
}

export function sidFromDirectory(value) {
  if(!value)return null
  if(typeof value==='string'&&/^S-\d+-\d+(?:-\d+)+$/i.test(value))return value
  const bytes=Buffer.from(value)
  if(bytes.length<8||bytes.length<8+bytes[1]*4)return null
  let authority=0n
  for(let i=2;i<8;i++)authority=(authority<<8n)+BigInt(bytes[i])
  const parts=[`S-${bytes[0]}-${authority}`]
  for(let i=0;i<bytes[1];i++)parts.push(String(bytes.readUInt32LE(8+i*4)))
  return parts.join('-')
}

function fileTime(value) {
  if(!value)return null
  try {
    const milliseconds=(BigInt(String(value))-116444736000000000n)/10000n
    if(milliseconds<0n||milliseconds>8640000000000000n)return null
    return new Date(Number(milliseconds)).toISOString()
  } catch{return null}
}

export function normalizeDirectoryComputer(entry,baseDn) {
  const guid=guidFromDirectory(attribute(entry,'objectGUID'))
  const name=String(attribute(entry,'name')||'').trim()
  const suffix=[...String(baseDn).matchAll(/(?:^|,)\s*DC=([^,]+)/gi)].map(match=>match[1]).join('.')
  const fqdn=String(attribute(entry,'dNSHostName')||(name&&suffix?`${name}.${suffix}`:'')).trim().toLowerCase()
  if(!guid||!name||!fqdn)return null
  const flags=Number(attribute(entry,'userAccountControl')||0)
  return {
    guid,sid:sidFromDirectory(attribute(entry,'objectSid')),dn:String(attribute(entry,'distinguishedName')||entry.dn||''),name,fqdn,
    operatingSystem:String(attribute(entry,'operatingSystem')||''),operatingSystemVersion:String(attribute(entry,'operatingSystemVersion')||''),
    lastLogonAt:fileTime(attribute(entry,'lastLogonTimestamp')),enabled:!(flags&2),changedAt:attribute(entry,'whenChanged')||null
  }
}

const defaultClientFactory=options=>new Client(options)
const makeClient=(config,clientFactory)=>clientFactory({url:config.url,connectTimeout:10000,timeout:30000,...(new URL(config.url).protocol==='ldaps:'?{tlsOptions:{minVersion:'TLSv1.2'}}:{})})
const fallbackCodes=new Set(['ECONNREFUSED','ETIMEDOUT','ECONNRESET','EPIPE','EHOSTUNREACH','ENETUNREACH'])
const ldapFallbackUrl=ldapsUrl=>{const url=new URL(ldapsUrl);url.protocol='ldap:';url.port='389';return url.toString()}
export function ldapFallbackUsername(username,baseDn){
  const separator=username.indexOf('\\')
  if(separator<1||separator===username.length-1||username.indexOf('\\',separator+1)!==-1)return username
  const suffix=[...String(baseDn).matchAll(/(?:^|,)\s*DC=([^,]+)/gi)].map(match=>match[1]).join('.')
  return suffix?`${username.slice(separator+1)}@${suffix}`:username
}
class DirectoryBindFailure extends Error {
  constructor(cause){super(cause.message,{cause});this.code=cause.code}
}

async function runWithDirectory(config,credential,operation,clientFactory){
  async function attempt(url){
    const client=makeClient({...config,url},clientFactory)
    try{
      try{await client.bind(new URL(url).protocol==='ldap:'?ldapFallbackUsername(credential.username,config.base_dn):credential.username,credential.password)}
      catch(error){throw new DirectoryBindFailure(error)}
      return await operation(client)
    }finally{try{await client.unbind()}catch{}}
  }
  try{return {value:await attempt(config.url),transport:'ldaps'}}
  catch(primaryError){
    const cause=primaryError instanceof DirectoryBindFailure?primaryError.cause:primaryError
    if(config.allow_ldap_fallback&&config.ldap_fallback_approved_at&&primaryError instanceof DirectoryBindFailure&&fallbackCodes.has(String(cause?.code||''))){
      const url=ldapFallbackUrl(config.url)
      try{return {value:await attempt(url),transport:'ldap'}}
      catch(fallbackError){throw directoryConnectionError(fallbackError instanceof DirectoryBindFailure?fallbackError.cause:fallbackError,url)}
    }
    throw directoryConnectionError(cause,config.url)
  }
}

export function directoryConnectionError(error,url) {
  const host=new URL(url).hostname
  const plain=new URL(url).protocol==='ldap:'
  const code=String(error?.code||'')
  const message=String(error?.message||'')
  const unavailable=description=>Object.assign(new Error(`${description} (${host}).`),{status:503,cause:error})
  if(['ENOTFOUND','EAI_AGAIN'].includes(code))return unavailable('The directory host could not be resolved; check the server name and DNS')
  if(['ECONNREFUSED','ETIMEDOUT','EHOSTUNREACH','ENETUNREACH'].includes(code))return unavailable(`The directory ${plain?'LDAP 389':'LDAPS'} endpoint is unreachable; check TCP ${plain?'389':'636'} and the network path`)
  if(['ECONNRESET','EPIPE'].includes(code))return unavailable(plain?'The LDAP 389 connection was reset':'The LDAPS connection was reset; check that the domain controller has a valid Server Authentication certificate with a private key and is listening on TCP 636')
  if(['UNABLE_TO_VERIFY_LEAF_SIGNATURE','SELF_SIGNED_CERT_IN_CHAIN','DEPTH_ZERO_SELF_SIGNED_CERT','CERT_HAS_EXPIRED','ERR_TLS_CERT_ALTNAME_INVALID'].includes(code)||/certificate verify failed|unable to verify|self.signed certificate|certificate has expired/i.test(message))return unavailable('The LDAPS certificate could not be validated; trust its issuing CA on the control plane and use the certificate DNS name')
  if(plain&&(code==='8'||code==='13'||/strong authentication required|confidentiality required|LDAP Result Code: (8|13)/i.test(message)))return unavailable('The domain controller rejected unencrypted LDAP 389; its signing or confidentiality policy requires a protected bind. Configure LDAPS instead')
  if(code==='49'||/invalid credentials|LDAP Result Code: 49/i.test(message))return Object.assign(new Error('The directory rejected the bind credential; check its username and password'),{status:400,cause:error})
  if(code==='52'||/LDAP Result Code: 52/i.test(message))return unavailable('The directory service is unavailable for LDAP; check Active Directory Domain Services and its LDAPS certificate')
  return error
}

export async function testDirectoryConnection(config,credential,clientFactory=defaultClientFactory) {
  const result=await runWithDirectory(config,credential,async client=>{
    const result=await client.search(config.base_dn,{scope:'base',filter:'(objectClass=*)',attributes:['distinguishedName'],sizeLimit:1})
    return result.searchEntries.length
  },clientFactory)
  return {connected:true,baseDn:config.base_dn,entries:result.value,transport:result.transport,fallbackUsed:result.transport==='ldap'}
}

export async function readDirectoryComputers(config,credential,clientFactory=defaultClientFactory) {
  const result=await runWithDirectory(config,credential,async client=>{
    const computers=[]
    for await(const page of client.searchPaginated(config.base_dn,{scope:'sub',filter:'(&(objectCategory=computer)(objectClass=computer))',attributes:directoryAttributes,explicitBufferAttributes:['objectGUID','objectSid'],paged:{pageSize:500},timeLimit:30})){
      for(const entry of page.searchEntries){
        const computer=normalizeDirectoryComputer(entry,config.base_dn)
        if(computer)computers.push(computer)
        if(computers.length>20000)throw new Error('Directory inventory exceeds 20,000 computers; narrow the search base')
      }
    }
    return computers
  },clientFactory)
  return {computers:result.value,transport:result.transport}
}
