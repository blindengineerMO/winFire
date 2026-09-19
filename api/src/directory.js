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
const makeClient=(config,clientFactory)=>clientFactory({url:config.url,connectTimeout:10000,timeout:30000,tlsOptions:{minVersion:'TLSv1.2'}})

export async function testDirectoryConnection(config,credential,clientFactory=defaultClientFactory) {
  const client=makeClient(config,clientFactory)
  try {
    await client.bind(credential.username,credential.password)
    const result=await client.search(config.base_dn,{scope:'base',filter:'(objectClass=*)',attributes:['distinguishedName'],sizeLimit:1})
    return {connected:true,baseDn:config.base_dn,entries:result.searchEntries.length}
  } finally {try{await client.unbind()}catch{}}
}

export async function readDirectoryComputers(config,credential,clientFactory=defaultClientFactory) {
  const client=makeClient(config,clientFactory),computers=[]
  try {
    await client.bind(credential.username,credential.password)
    for await(const page of client.searchPaginated(config.base_dn,{scope:'sub',filter:'(&(objectCategory=computer)(objectClass=computer))',attributes:directoryAttributes,explicitBufferAttributes:['objectGUID','objectSid'],paged:{pageSize:500},timeLimit:30})){
      for(const entry of page.searchEntries){
        const computer=normalizeDirectoryComputer(entry,config.base_dn)
        if(computer)computers.push(computer)
        if(computers.length>20000)throw new Error('Directory inventory exceeds 20,000 computers; narrow the search base')
      }
    }
    return computers
  } finally {try{await client.unbind()}catch{}}
}
