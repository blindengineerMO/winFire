import ipaddr from 'ipaddr.js'
const portExpression=/^(Any|\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$/
const addressAliases=new Set(['any','localsubnet','dns','dhcp','wins','defaultgateway'])

export function validatePortExpression(value) {
  if(!portExpression.test(String(value)))return false
  if(value==='Any')return true
  return String(value).split(',').every(part=>{
    const ports=part.split('-').map(Number)
    return ports.every(port=>port>=1&&port<=65535)&&(ports.length===1||ports[0]<=ports[1])
  })
}

function validIp(value){return ipaddr.IPv4.isValidFourPartDecimal(value)||ipaddr.IPv6.isValid(value)}
export function validateAddressExpression(value) {
  if(typeof value!=='string'||!value.trim())return false
  return value.split(',').every(raw=>{
    const address=raw.trim()
    if(addressAliases.has(address.toLowerCase()))return value.trim().toLowerCase()===address.toLowerCase()
    if(address.includes('/')){
      const parts=address.split('/')
      if(parts.length!==2||!validIp(parts[0])||!/^\d+$/.test(parts[1]))return false
      return Number(parts[1])<=(ipaddr.IPv4.isValidFourPartDecimal(parts[0])?32:128)
    }
    if(address.includes('-')){
      const parts=address.split('-')
      if(parts.length!==2||!parts.every(validIp))return false
      const left=ipaddr.parse(parts[0]),right=ipaddr.parse(parts[1])
      if(left.kind()!==right.kind())return false
      const start=left.toByteArray(),end=right.toByteArray()
      for(let index=0;index<start.length;index++)if(start[index]!==end[index])return start[index]<end[index]
      return true
    }
    return validIp(address)
  })
}

export function validateProgramPath(value) {
  if(typeof value!=='string'||value.endsWith('\\'))return false
  return /^(?:[A-Za-z]:\\|%[A-Za-z_][A-Za-z0-9_]*%\\)[^<>:"|?*]+$/.test(value)
}

