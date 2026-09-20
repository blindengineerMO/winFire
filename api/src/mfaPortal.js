import {BlockList,isIP} from 'node:net'
import {all,one,run,now,audit} from './db.js'
import {remote} from './connector.js'

export function normalizeSourceIp(value){
  const source=String(value||'').replace(/^::ffff:/,'')
  if(!isIP(source))throw Object.assign(new Error('A direct client IP address is required for portal access'),{status:400})
  return source
}

export function sourceMatches(source,expression){
  if(!expression)return true
  const list=new BlockList()
  for(const term of String(expression).split(',').map(item=>item.trim()).filter(Boolean)){
    const [address,prefix]=term.split('/')
    const family=isIP(address)
    if(!family)throw Object.assign(new Error('Segment source scope contains an invalid IP address'),{status:409})
    const type=family===6?'ipv6':'ipv4'
    if(prefix===undefined)list.addAddress(address,type)
    else {
      const bits=Number(prefix)
      if(!Number.isInteger(bits)||bits<0||bits>(family===4?32:128))throw Object.assign(new Error('Segment source scope contains an invalid CIDR'),{status:409})
      list.addSubnet(address,bits,type)
    }
  }
  return list.check(source,isIP(source)===6?'ipv6':'ipv4')
}

export async function revokeExpiredGrants(){
  const due=all("SELECT * FROM jit_grants WHERE grant_type='portal_firewall' AND revoked_at IS NULL AND expires_at<=? ORDER BY expires_at LIMIT 20",now())
  for(const grant of due){
    const node=one('SELECT * FROM nodes WHERE id=?',grant.node_id)
    if(!node){run('UPDATE jit_grants SET revoked_at=? WHERE id=?',now(),grant.id);continue}
    try{
      await remote(node,'jit_end',{grantId:grant.id})
      run('UPDATE jit_grants SET revoked_at=? WHERE id=?',now(),grant.id)
      audit(null,'mfa.grant.expired','jit-grant',grant.id,null,{nodeId:node.id})
    }catch(error){audit(null,'mfa.grant.revoke.failed','jit-grant',grant.id,null,{error:error.message})}
  }
  return due.length
}
