import {BlockList,isIP} from 'node:net'
import {all,one,run,now,audit,id,json,db} from './db.js'
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

export async function revokePortalGrant(grant,actorId=null,action='mfa.portal.revoked'){
  if(grant.revoked_at)return {revoked:true,alreadyRevoked:true}
  const node=one('SELECT * FROM nodes WHERE id=?',grant.node_id)
  if(!node){
    run('UPDATE jit_grants SET revoked_at=? WHERE id=?',now(),grant.id)
    audit(actorId,action,'jit-grant',grant.id,null,{nodeId:grant.node_id,nodeMissing:true})
    return {revoked:true,nodeMissing:true}
  }
  const runId=id()
  run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',runId,node.id,'running')
  audit(actorId,'mfa.grant.revoke.start','jit-grant',grant.id,null,{nodeId:node.id,runId})
  try{
    const result=await remote(node,'jit_end',{grantId:grant.id})
    if(result?.revoked!==true)throw new Error('The node did not confirm JIT firewall rule removal')
    db.transaction(()=>{
      run('UPDATE jit_grants SET revoked_at=? WHERE id=?',now(),grant.id)
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json({operation:'jit_end',grantId:grant.id,group:result.group||null}),now(),runId)
      audit(actorId,action,'jit-grant',grant.id,null,{nodeId:node.id,runId})
    })()
    return {revoked:true,runId}
  }catch(error){
    const status='unknown' // The remove command may have reached the host before transport or readback failed.
    db.transaction(()=>{
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?',status,error.message,now(),runId)
      audit(actorId,'mfa.grant.revoke.failed','jit-grant',grant.id,null,{nodeId:node.id,runId,status,error:error.message})
    })()
    throw error
  }
}

export async function revokeExpiredGrants(){
  const due=all("SELECT * FROM jit_grants WHERE grant_type='portal_firewall' AND revoked_at IS NULL AND expires_at<=? ORDER BY expires_at LIMIT 20",now())
  for(const grant of due){
    try{await revokePortalGrant(grant,null,'mfa.grant.expired')}
    catch{}
  }
  return due.length
}
