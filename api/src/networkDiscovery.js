import {spawn} from 'node:child_process'
import dns from 'node:dns/promises'
import {isIP} from 'node:net'
import {db,all,one,run,id,now,json,audit} from './db.js'
import {lookupDns,probeNode,collectFacts} from './connector.js'

const MAX_HOSTS=4096
const ipv4ToInt=ip=>ip.split('.').map(Number).reduce((n,o)=>(n*256)+o,0)>>>0
const intToIpv4=value=>[24,16,8,0].map(shift=>(value>>>shift)&255).join('.')
export function expandCidrs(cidrs){
  const output=[]
  for(const input of cidrs){
    const value=String(input||'').trim();if(!value)continue
    const [address,prefixText]=value.split('/');if(isIP(address)!==4)throw new Error(`Only IPv4 CIDRs are supported: ${value}`)
    const prefix=prefixText===undefined?32:Number(prefixText);if(!Number.isInteger(prefix)||prefix<0||prefix>32)throw new Error(`Invalid CIDR: ${value}`)
    const count=2**(32-prefix);if(count>MAX_HOSTS||output.length+count>MAX_HOSTS)throw new Error(`CIDR scan is limited to ${MAX_HOSTS} addresses`)
    const mask=prefix===0?0:(0xffffffff<<(32-prefix))>>>0,network=ipv4ToInt(address)&mask
    for(let offset=0;offset<count;offset++)output.push(intToIpv4((network+offset)>>>0))
  }
  return [...new Set(output)]
}
function ping(host){
  const args=process.platform==='win32'?['-n','1','-w','1000',host]:process.platform==='darwin'?['-c','1','-W','1000',host]:['-c','1','-W','1',host]
  return new Promise(resolve=>{const child=spawn(process.platform==='win32'?'ping':'ping',args,{stdio:'ignore'});const timer=setTimeout(()=>{child.kill('SIGKILL');resolve(false)},2500);child.once('error',()=>{clearTimeout(timer);resolve(false)});child.once('close',code=>{clearTimeout(timer);resolve(code===0)})})
}
const defaultCredential=()=>one("SELECT node_credential_id FROM directory_connections WHERE id='default' AND enabled=1")?.node_credential_id||null
function existingNode(ip,hostname){
  const lower=String(hostname||'').toLowerCase()
  return one('SELECT * FROM nodes WHERE ip=? OR lower(hostname)=? OR lower(fqdn)=? ORDER BY CASE WHEN inventory_source=\'ad\' THEN 0 ELSE 1 END LIMIT 1',ip,lower,lower)
}
async function registerHost(ip,scanId){
  let hostname=ip,fqdn=null
  try{const names=await dns.reverse(ip);if(names[0]){fqdn=names[0];hostname=fqdn.split('.')[0]}}catch{}
  const found=existingNode(ip,hostname)
  if(found){run('UPDATE nodes SET last_discovered_at=?,status=CASE WHEN status=\'unknown\' THEN \'reachable\' ELSE status END WHERE id=?',now(),found.id);return {ip,nodeId:found.id,existing:true,hostname:found.hostname}}
  const nodeId=id(),credentialId=defaultCredential()
  db.transaction(()=>{
    run("INSERT INTO nodes(id,hostname,fqdn,ip,connection_mode,status,inventory_source,discovery_source,last_discovered_at,agent_required) VALUES(?,?,?,?,?,?,?,?,?,1)",nodeId,hostname,fqdn,ip,'agentless','reachable','discovery',`icmp:${scanId}`,now())
    if(credentialId)run('INSERT OR IGNORE INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)',credentialId,nodeId)
    audit(null,'node.discovery.register','node',nodeId,null,{ip,hostname,fqdn,credentialId,scanId})
  })()
  const node=one('SELECT * FROM nodes WHERE id=?',nodeId)
  try{
    await lookupDns(node)
    const probed=await probeNode(one('SELECT * FROM nodes WHERE id=?',nodeId))
    if(probed.winrmAuthenticated){
      await collectFacts(one('SELECT * FROM nodes WHERE id=?',nodeId))
      run('UPDATE nodes SET agent_required=0,platform=COALESCE(platform,\'windows\') WHERE id=?',nodeId)
    }
    return {ip,nodeId,hostname,transport:probed.transport,managed:!!probed.winrmAuthenticated}
  }catch(error){
    run('UPDATE nodes SET agent_required=1,status=CASE WHEN status=\'reachable\' THEN \'degraded\' ELSE status END WHERE id=?',nodeId)
    return {ip,nodeId,hostname,agentRequired:true,error:error.message}
  }
}
export async function runDiscoveryScan(scanId){
  const scan=one('SELECT * FROM discovery_scans WHERE id=?',scanId);if(!scan)return
  const cidrs=JSON.parse(scan.cidrs_json),hosts=expandCidrs(cidrs)
  run("UPDATE discovery_scans SET status='running',started_at=? WHERE id=?",now(),scanId)
  const results=[],concurrency=32
  let cursor=0
  const worker=async()=>{while(cursor<hosts.length){const ip=hosts[cursor++];run('UPDATE discovery_scans SET probed=probed+1 WHERE id=?',scanId);if(!(await ping(ip)))continue;run('UPDATE discovery_scans SET alive=alive+1 WHERE id=?',scanId);try{const result=await registerHost(ip,scanId);results.push(result);run('UPDATE discovery_scans SET registered=registered+1 WHERE id=?',scanId)}catch(error){results.push({ip,error:error.message})}}}
  try{await Promise.all(Array.from({length:Math.min(concurrency,hosts.length)},worker));run("UPDATE discovery_scans SET status='complete',results_json=?,finished_at=? WHERE id=?",json(results.slice(0,MAX_HOSTS)),now(),scanId);audit(null,'network-discovery.complete','discovery-scan',scanId,null,{probed:hosts.length,alive:results.length})}
  catch(error){run("UPDATE discovery_scans SET status='failed',error=?,results_json=?,finished_at=? WHERE id=?",error.message,json(results),now(),scanId);audit(null,'network-discovery.failed','discovery-scan',scanId,null,{error:error.message})}
}
