import {z} from 'zod'
import {isIP} from 'node:net'
import {sshExec} from './sshConnector.js'
import {assertManagementAccess} from './managementGuard.js'
import {unicastIp} from './services/networkBoundary.js'
export function validateDdosBlock(input){
 const data=z.object({id:z.string().uuid(),protocol:z.enum(['TCP','UDP']),ports:z.array(z.number().int().min(1).max(65535)).min(1).max(32),sources:z.array(z.string().refine(unicastIp)).min(1).max(100),seconds:z.number().int().min(30).max(86400)}).strict().parse(input)
 if(data.ports.some(p=>[22,135,139,445,3389,5985,5986].includes(p)))throw new Error('DDoS rules cannot target management ports')
 assertManagementAccess([{name:'DDoS temporary block',action:'block',direction:'in',protocol:data.protocol,localPort:data.ports.join(','),remoteAddress:data.sources.join(',')}]);return data
}
export function linuxDdosCommand(operation,input){
 const key=z.string().uuid().parse(input.id).replaceAll('-',''),table='wfddos_'+key
 if(operation==='ddos_end')return `sudo -n sh -c 'set -eu; tables=$(nft list tables); if printf "%s\\n" "$tables" | grep -Fx "table inet ${table}" >/dev/null; then nft delete table inet ${table}; fi'`
 const data=validateDdosBlock(input),proto=data.protocol.toLowerCase(),ports=data.ports.join(', ')
 const lines=[`add table inet ${table}`,`add chain inet ${table} inbound { type filter hook input priority -20; policy accept; }`]
 for(const family of [4,6]){
  const sources=data.sources.filter(ip=>isIP(ip)===family);if(!sources.length)continue
  lines.push(`add set inet ${table} sources${family} { type ipv${family}_addr; flags timeout; timeout ${data.seconds}s; }`)
  lines.push(`add element inet ${table} sources${family} { ${sources.map(ip=>ip+' timeout '+data.seconds+'s').join(', ')} }`)
  lines.push(`add rule inet ${table} inbound ${family===4?'ip':'ip6'} saddr @sources${family} ${proto} dport { ${ports} } counter drop`)
 }
 // Atomic nft transaction; per-element kernel timeout releases even if SSH/API dies.
 const encoded=Buffer.from(lines.join('\n')+'\n').toString('base64')
 return `printf '%s' '${encoded}' | base64 -d | sudo -n nft -f -`
}
export async function linuxDdos(connection,operation,args){
 const result=await sshExec({...connection,command:linuxDdosCommand(operation,args)})
 if(result.code!==0)throw new Error('Linux DDoS operation failed; nftables and passwordless sudo are required')
 return {active:operation==='ddos_start',removed:operation==='ddos_end',nativeExpiry:operation==='ddos_start'}
}
