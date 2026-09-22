import {spawn,execFile} from 'node:child_process'
import {promisify} from 'node:util'
import net from 'node:net'
import dns from 'node:dns/promises'
import {isIP} from 'node:net'
import {db,all,one,run,id,now,json,audit} from './db.js'
import {lookupDns,probeNode,collectFacts} from './connector.js'

const MAX_HOSTS=4096
const ARP_TIMEOUT_MS=1500
const TCP_TIMEOUT_MS=1200
export const DISCOVERY_TCP_PORTS=[445,3389,5985,5986]
const execFileAsync=promisify(execFile)
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
export function ping(host){
  const args=process.platform==='win32'?['-n','1','-w','1000',host]:process.platform==='darwin'?['-c','1','-W','1000',host]:['-c','1','-W','1',host]
  return new Promise(resolve=>{const child=spawn(process.platform==='win32'?'ping':'ping',args,{stdio:'ignore'});const timer=setTimeout(()=>{child.kill('SIGKILL');resolve(false)},2500);child.once('error',()=>{clearTimeout(timer);resolve(false)});child.once('close',code=>{clearTimeout(timer);resolve(code===0)})})
}
const ipv4Mac=/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/i
const zeroMac=/^(?:00[:-]){5}00$/i
export function parseNeighborTable(output,host){
  const target=String(host||'').trim()
  if(!target||isIP(target)!==4)return false
  return String(output||'').split(/\r?\n/).some(line=>{
    if(!line.includes(target))return false
    const mac=line.match(ipv4Mac)?.[0]||''
    return Boolean(mac)&&!zeroMac.test(mac)
  })
}
async function runNetworkCommand(command,args,timeoutMs=ARP_TIMEOUT_MS){
  try{
    const result=await execFileAsync(command,args,{timeout:timeoutMs,maxBuffer:64*1024,windowsHide:true})
    return {code:0,output:`${result.stdout||''}\n${result.stderr||''}`}
  }catch(error){
    return {code:typeof error.code==='number'?error.code:null,output:`${error.stdout||''}\n${error.stderr||''}`}
  }
}
/**
 * Check the local layer-2 neighbor cache and, where supported, send one ARP
 * request. ARP is intentionally an IP-only probe: it cannot discover hosts
 * across a router, but it can find Windows hosts that deliberately drop ICMP.
 */
export async function arpProbe(host,{platform=process.platform,runCommand=runNetworkCommand}={}){
  if(isIP(String(host||''))!==4)return false
  const commands=[]
  if(platform!=='win32')commands.push(['arping',['-c','1','-w','1',host]])
  if(platform==='win32')commands.push(['arp',['-a',host]])
  else commands.push(['ip',['neigh','show','to',host]],['arp',['-an',host]])
  for(const [command,args] of commands){
    const result=await runCommand(command,args,ARP_TIMEOUT_MS)
    if(command==='arping'&&result.code===0)return true
    if(parseNeighborTable(result.output,host))return true
  }
  return false
}
/**
 * A TCP SYN probe treats both an established connection and an explicit RST
 * (ECONNREFUSED/ECONNRESET) as liveness evidence. Timeouts and unreachable
 * errors are not evidence. The caller limits this to a small management-port
 * set so a scan never becomes a port scanner.
 */
export function tcpProbe(host,port,timeoutMs=TCP_TIMEOUT_MS,connect=net.createConnection){
  return new Promise(resolve=>{
    let settled=false
    const finish=value=>{if(settled)return;settled=true;resolve(value)}
    let socket
    try{socket=connect({host,port:Number(port)})}catch{finish(false);return}
    const timer=setTimeout(()=>{try{socket.destroy()}catch{};finish(false)},timeoutMs)
    socket.once('connect',()=>{clearTimeout(timer);try{socket.destroy()}catch{};finish(true)})
    socket.once('error',error=>{clearTimeout(timer);try{socket.destroy()}catch{};finish(['ECONNREFUSED','ECONNRESET','EPIPE'].includes(error?.code))})
    socket.once('close',()=>{clearTimeout(timer)})
  })
}
export async function probeHostLiveness(host,{icmpProbe=ping,arpLivenessProbe=arpProbe,tcpLivenessProbe=tcpProbe,tcpPorts=DISCOVERY_TCP_PORTS}={}){
  try{if(await icmpProbe(host))return {alive:true,method:'icmp'}}catch{}
  try{if(await arpLivenessProbe(host))return {alive:true,method:'arp'}}catch{}
  for(const port of tcpPorts){try{if(await tcpLivenessProbe(host,port))return {alive:true,method:`tcp:${port}`}}catch{}}
  return {alive:false,method:null}
}
const defaultCredential=()=>one("SELECT node_credential_id FROM directory_connections WHERE id='default' AND enabled=1")?.node_credential_id||null
function existingNode(ip,hostname){
  const lower=String(hostname||'').toLowerCase()
  return one('SELECT * FROM nodes WHERE ip=? OR lower(hostname)=? OR lower(fqdn)=? ORDER BY CASE WHEN inventory_source=\'ad\' THEN 0 ELSE 1 END LIMIT 1',ip,lower,lower)
}
async function registerHost(ip,scanId,livenessMethod='icmp'){
  let hostname=ip,fqdn=null
  try{const names=await dns.reverse(ip);if(names[0]){fqdn=names[0];hostname=fqdn.split('.')[0]}}catch{}
  const found=existingNode(ip,hostname)
  if(found){run('UPDATE nodes SET last_discovered_at=?,discovery_source=?,status=CASE WHEN status=\'unknown\' THEN \'reachable\' ELSE status END WHERE id=?',now(),`${livenessMethod}:${scanId}`,found.id);return {ip,nodeId:found.id,existing:true,hostname:found.hostname,livenessMethod}}
  const nodeId=id(),credentialId=defaultCredential()
  db.transaction(()=>{
    run("INSERT INTO nodes(id,hostname,fqdn,ip,connection_mode,status,inventory_source,discovery_source,last_discovered_at,agent_required) VALUES(?,?,?,?,?,?,?,?,?,1)",nodeId,hostname,fqdn,ip,'agentless','reachable','discovery',`${livenessMethod}:${scanId}`,now())
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
    return {ip,nodeId,hostname,transport:probed.transport,managed:!!probed.winrmAuthenticated,livenessMethod}
  }catch(error){
    run('UPDATE nodes SET agent_required=1,status=CASE WHEN status=\'reachable\' THEN \'degraded\' ELSE status END WHERE id=?',nodeId)
    return {ip,nodeId,hostname,agentRequired:true,error:error.message,livenessMethod}
  }
}
export async function runDiscoveryScan(scanId){
  const scan=one('SELECT * FROM discovery_scans WHERE id=?',scanId);if(!scan)return
  const cidrs=JSON.parse(scan.cidrs_json),hosts=expandCidrs(cidrs)
  run("UPDATE discovery_scans SET status='running',started_at=? WHERE id=?",now(),scanId)
  const results=[],concurrency=32
  let cursor=0
  const worker=async()=>{while(cursor<hosts.length){const ip=hosts[cursor++];run('UPDATE discovery_scans SET probed=probed+1 WHERE id=?',scanId);const liveness=await probeHostLiveness(ip);if(!liveness.alive)continue;run('UPDATE discovery_scans SET alive=alive+1,arp_alive=arp_alive+?,tcp_alive=tcp_alive+? WHERE id=?',liveness.method==='arp'?1:0,liveness.method?.startsWith('tcp:')?1:0,scanId);try{const result=await registerHost(ip,scanId,liveness.method);results.push(result);run('UPDATE discovery_scans SET registered=registered+1 WHERE id=?',scanId)}catch(error){results.push({ip,error:error.message,livenessMethod:liveness.method})}}}
  try{await Promise.all(Array.from({length:Math.min(concurrency,hosts.length)},worker));run("UPDATE discovery_scans SET status='complete',results_json=?,finished_at=? WHERE id=?",json(results.slice(0,MAX_HOSTS)),now(),scanId);audit(null,'network-discovery.complete','discovery-scan',scanId,null,{probed:hosts.length,alive:results.length,arpAlive:one('SELECT arp_alive FROM discovery_scans WHERE id=?',scanId)?.arp_alive||0,tcpAlive:one('SELECT tcp_alive FROM discovery_scans WHERE id=?',scanId)?.tcp_alive||0})}
  catch(error){run("UPDATE discovery_scans SET status='failed',error=?,results_json=?,finished_at=? WHERE id=?",error.message,json(results),now(),scanId);audit(null,'network-discovery.failed','discovery-scan',scanId,null,{error:error.message})}
}
