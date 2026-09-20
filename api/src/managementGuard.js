import os from 'node:os'
import {BlockList,isIP} from 'node:net'

function managementIps(){
  const addresses=new Set()
  for(const adapters of Object.values(os.networkInterfaces()))for(const adapter of adapters||[])if(!adapter.internal&&isIP(adapter.address))addresses.add(adapter.address)
  for(const address of String(process.env.WINFIRE_CONTROL_PLANE_IPS||'').split(',').map(value=>value.trim()))if(isIP(address))addresses.add(address)
  try{const url=new URL(process.env.PUBLIC_BASE_URL);if(isIP(url.hostname))addresses.add(url.hostname)}catch{}
  return [...addresses]
}
function portMatches(expression,port){
  for(const item of String(expression||'Any').split(',').map(value=>value.trim())){
    if(item.toLowerCase()==='any'||item==='*')return true
    if(/^\d+$/.test(item)&&Number(item)===port)return true
    const range=item.match(/^(\d+)-(\d+)$/)
    if(range&&port>=Number(range[1])&&port<=Number(range[2]))return true
  }
  return false
}
function addressMatches(expression,addresses){
  if(!addresses.length)return false
  if(!expression||String(expression).toLowerCase()==='any')return true
  const list=new BlockList()
  for(const item of String(expression).split(',').map(value=>value.trim()).filter(Boolean)){
    const range=item.match(/^(.+)-(.+)$/),subnet=item.match(/^(.+)\/(\d+)$/)
    try{
      if(range&&isIP(range[1])===isIP(range[2])&&isIP(range[1]))list.addRange(range[1],range[2],isIP(range[1])===6?'ipv6':'ipv4')
      else if(subnet&&isIP(subnet[1]))list.addSubnet(subnet[1],Number(subnet[2]),isIP(subnet[1])===6?'ipv6':'ipv4')
      else if(isIP(item))list.addAddress(item,isIP(item)===6?'ipv6':'ipv4')
      else return true // Unknown Windows address alias could include the control plane.
    }catch{return true}
  }
  return addresses.some(ip=>list.check(ip,isIP(ip)===6?'ipv6':'ipv4'))
}
function publicPort(){
  try{const url=new URL(process.env.PUBLIC_BASE_URL);return Number(url.port||((url.protocol==='https:')?443:80))}catch{return Number(process.env.PORT||3000)}
}
export function managementRuleViolation(rule,{controlIps=managementIps(),controlPort=publicPort()}={}){
  if(rule.action!=='block'||!['TCP','Any'].includes(rule.protocol))return null
  const direction=rule.direction==='inbound'?'in':rule.direction==='outbound'?'out':rule.direction
  const appPorts=[...new Set([controlPort,Number(process.env.PORT||3000)].filter(port=>Number.isInteger(port)&&port>0&&port<=65535))]
  if(direction==='in'){
    if([5985,5986].some(port=>portMatches(rule.localPort,port)))return 'An inbound block rule overlaps WinRM ports 5985 or 5986'
    if(addressMatches(rule.remoteAddress,controlIps)&&appPorts.some(port=>portMatches(rule.localPort,port)))return 'An inbound block rule could stop WinFire control-plane traffic'
  }
  if(direction==='out'&&addressMatches(rule.remoteAddress,controlIps)&&[...appPorts,5985,5986].some(port=>portMatches(rule.remotePort,port)))return 'An outbound block rule could stop traffic to the WinFire control plane'
  return null
}
export function assertManagementAccess(rules,options){
  for(const rule of rules||[]){const violation=managementRuleViolation(rule,options);if(violation)throw Object.assign(new Error(`${violation}: ${rule.name||'unnamed rule'}`),{status:409})}
}
