import {all,one,run,audit} from './db.js'

// Split only unescaped separators; an escaped comma belongs to the OU name.
function splitDn(value,separator){
  const parts=[];let start=0
  for(let i=0;i<value.length;i++){
    if(value[i]==='\\'){if(++i>=value.length)throw new Error('Incomplete DN escape')}
    else if(value[i]===separator){parts.push(value.slice(start,i));start=i+1}
  }
  parts.push(value.slice(start));return parts
}
export function directoryDnParts(dn){
  if(typeof dn!=='string'||!dn.trim()||dn.length>2048)throw new Error('Invalid distinguished name')
  return splitDn(dn.trim(),',').map(rdn=>JSON.stringify(splitDn(rdn,'+').map(ava=>{
    const match=ava.match(/^\s*([a-z][a-z0-9-]*|\d+(?:\.\d+)+)\s*=([\s\S]*)$/i)
    if(!match)throw new Error('Use a full distinguished name such as OU=Servers,DC=example,DC=com')
    let raw=match[2],bytes=[]
    if(!raw||raw[0]==='#')throw new Error('Use an LDAP text distinguished name')
    for(let i=0;i<raw.length;){
      if(raw[i]==='\\'){
        if(/^[0-9a-f]{2}$/i.test(raw.slice(i+1,i+3))){bytes.push(parseInt(raw.slice(i+1,i+3),16));i+=3}
        else {const char=raw[++i];if(!char||!'/ ,+"\\<>;=#'.includes(char))throw new Error('Invalid DN escape');bytes.push(...Buffer.from(char));i++}
      }else{
        const char=String.fromCodePoint(raw.codePointAt(i))
        if(/["<>;\x00-\x1f]/.test(char))throw new Error('Escape reserved DN characters')
        bytes.push(...Buffer.from(char));i+=char.length
      }
    }
    const value=new TextDecoder('utf-8',{fatal:true}).decode(new Uint8Array(bytes)).normalize('NFC').trim().replace(/ +/g,' ').toLowerCase()
    if(!value||value.includes('\0'))throw new Error('Empty or invalid DN value')
    const type=({'2.5.4.11':'ou','2.5.4.3':'cn','0.9.2342.19200300.100.1.25':'dc'})[match[1]]||match[1].toLowerCase()
    return [type,value]
  }).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)))))
}
export const dnWithin=(parts,base)=>parts.length>=base.length&&base.every((part,i)=>part===parts[parts.length-base.length+i])
export function validateOuHints(hints,baseDn){
  const base=directoryDnParts(baseDn),seen=new Set()
  return hints.map(hint=>{
    const parts=directoryDnParts(hint.ouDn)
    if(!JSON.parse(parts[0]).some(([type])=>type==='ou')||!dnWithin(parts,base))throw new Error('Each mapping must name an OU inside the directory search base')
    const key=JSON.stringify(parts)
    if(seen.has(key))throw new Error('An OU can have only one preferred credential')
    seen.add(key);return {...hint,key,parts}
  })
}
export const directoryOuHints=()=>all('SELECT ou_dn ouDn,credential_id credentialId FROM directory_ou_credentials ORDER BY ou_dn')
export function preferredDirectoryCredential(dn,settings,hints=directoryOuHints()){
  if(!settings?.enabled)return null
  let parts,base
  try{parts=directoryDnParts(dn);base=directoryDnParts(settings.base_dn)}catch{return null}
  if(!dnWithin(parts,base))return null
  let match=null,depth=0
  for(const hint of hints){
    const scope=hint.parts||directoryDnParts(hint.ouDn)
    if(scope.length>depth&&dnWithin(scope,base)&&dnWithin(parts,scope)){match=hint;depth=scope.length}
  }
  return match?{credentialId:match.credentialId,ouDn:match.ouDn}:settings.node_credential_id?{credentialId:settings.node_credential_id,ouDn:null}:null
}
export function applyDirectoryCredential(nodeId,dn,settings,actorId=null,hints=directoryOuHints()){
  const before=all("SELECT credential_id credentialId,source_dn ouDn FROM credential_assignments WHERE node_id=? AND source='directory'",nodeId)
  const explicit=one(`SELECT 1 FROM credential_assignments a JOIN credentials c ON c.id=a.credential_id
    WHERE (a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?))
    AND a.source<>'directory' AND c.type IN ('local','domain')`,nodeId,nodeId)
  const preferred=explicit?null:preferredDirectoryCredential(dn,settings,hints)
  // Never silently replace a node or group binding, including bindings predating provenance.
  const after=preferred&&one("SELECT 1 FROM credentials WHERE id=? AND type IN ('local','domain')",preferred.credentialId)?[preferred]:[]
  if(JSON.stringify(before)===JSON.stringify(after))return
  run("DELETE FROM credential_assignments WHERE node_id=? AND source='directory'",nodeId)
  if(after.length)run("INSERT INTO credential_assignments(credential_id,node_id,node_group_id,source,source_dn) VALUES(?,?,NULL,'directory',?)",after[0].credentialId,nodeId,after[0].ouDn)
  audit(actorId,'directory.credential.assign','node',nodeId,before,after)
}
