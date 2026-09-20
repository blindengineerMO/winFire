const logonRight=/^\s*Se(Deny)?(Network|RemoteInteractive|Batch|Service|Interactive)LogonRight\s*=\s*(.*)$/i

export function parseSeceditRights(lines){
  const rights=[],seen=new Set()
  for(const line of lines){
    const match=logonRight.exec(String(line))
    if(!match)continue
    const assignment=match[1]?'deny':'allow',logonType=match[2]
    for(const value of match[3].split(',')){
      const accountSid=value.trim().replace(/^\*/,'')
      if(!accountSid)continue
      if(!/^S-\d+(?:-\d+)+$/i.test(accountSid))throw new Error(`Logon-rights export contains an unresolved account in Se${match[1]||''}${logonType}LogonRight`)
      const key=`${accountSid}:${logonType}:${assignment}`
      if(seen.has(key))continue
      seen.add(key)
      rights.push({accountSid,logonType,assignment})
    }
  }
  if(!rights.length)throw new Error('Logon-rights export contained no usable account assignments; baseline was not collected')
  return rights
}
