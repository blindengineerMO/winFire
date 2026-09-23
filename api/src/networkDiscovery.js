import {spawn,execFile} from 'node:child_process'
import {promisify} from 'node:util'
import net from 'node:net'
import dns from 'node:dns/promises'
import {isIP} from 'node:net'
import {db,all,one,run,id,now,json,parse,audit} from './db.js'
import {lookupDns,probeNode,collectFacts} from './connector.js'

const MAX_HOSTS=4096
const ARP_TIMEOUT_MS=1500
const TCP_TIMEOUT_MS=1200
export const DISCOVERY_TCP_PORTS=[445,3389,5985,5986]
export const DISCOVERY_MIN_INTERVAL_MINUTES=5
export const DISCOVERY_MAX_INTERVAL_MINUTES=10080
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
export function normalizeMac(value){const raw=String(value||'').trim().toLowerCase().replaceAll('-',':');return /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(raw)&&!zeroMac.test(raw)?raw:null}
const neighborMac=(output,host)=>normalizeMac((String(output||'').split(/\r?\n/).find(line=>line.includes(host))||'').match(ipv4Mac)?.[0])
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
    if(command==='arping'&&result.code===0)return {alive:true,mac:neighborMac(result.output,host)}
    if(parseNeighborTable(result.output,host))return {alive:true,mac:neighborMac(result.output,host)}
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
  try{const arp=await arpLivenessProbe(host),details=typeof arp==='object'&&arp!==null?arp:{alive:Boolean(arp)};if(details.alive!==false&&details.alive!==undefined)return {alive:true,method:'arp',...(details.mac?{mac:details.mac}:{})}}catch{}
  for(const port of tcpPorts){try{if(await tcpLivenessProbe(host,port))return {alive:true,method:`tcp:${port}`}}catch{}}
  return {alive:false,method:null}
}
const discoveryIdentity=result=>String(result?.ip||result?.fqdn||result?.hostname||'').trim().toLowerCase()
const discoveryComparableFields=['hostname','fqdn','mac','hypervisor','osName','osVersion','livenessMethod','transport','managed']
function discoverySnapshot(result){
  const snapshot={ip:result?.ip||null,hostname:result?.hostname||null,fqdn:result?.fqdn||null,mac:result?.mac||result?.macAddress||null,hypervisor:result?.hypervisor||null,osName:result?.osName||result?.platform||null,osVersion:result?.osVersion||null,livenessMethod:result?.livenessMethod||null,transport:result?.transport||null,managed:result?.managed===true||result?.managed===1}
  return snapshot
}
export function diffDiscoveryResults(previousResults=[],currentResults=[]){
  const previous=new Map((Array.isArray(previousResults)?previousResults:[]).map(discoverySnapshot).map(item=>[discoveryIdentity(item),item]).filter(([key])=>key))
  const current=new Map((Array.isArray(currentResults)?currentResults:[]).map(discoverySnapshot).map(item=>[discoveryIdentity(item),item]).filter(([key])=>key))
  const newHosts=[],goneHosts=[],changedHosts=[]
  for(const [key,item] of current){if(!previous.has(key))newHosts.push(item);else{const before=previous.get(key),changes={};for(const field of discoveryComparableFields)if((before[field]??null)!==(item[field]??null))changes[field]={before:before[field]??null,after:item[field]??null};if(Object.keys(changes).length)changedHosts.push({before,after:item,changes})}}
  for(const [key,item] of previous)if(!current.has(key))goneHosts.push(item)
  return {newHosts,goneHosts,changedHosts,summary:{new:newHosts.length,gone:goneHosts.length,changed:changedHosts.length,previous:previous.size,current:current.size}}
}
function normalizeDiscoveryInterval(value){
  const interval=Number(value)
  if(!Number.isInteger(interval)||interval<DISCOVERY_MIN_INTERVAL_MINUTES||interval>DISCOVERY_MAX_INTERVAL_MINUTES)throw Object.assign(new Error(`Discovery interval must be between ${DISCOVERY_MIN_INTERVAL_MINUTES} minutes and ${DISCOVERY_MAX_INTERVAL_MINUTES} minutes`),{status:400})
  return interval
}
export function publicDiscoverySchedule(schedule){
  if(!schedule)return null
  return {...schedule,cidrs:parse(schedule.cidrs_json)||[],enabled:!!schedule.enabled,intervalMinutes:schedule.interval_minutes,status:schedule.status,lastScanId:schedule.last_scan_id||null,lastError:schedule.last_error||null}
}
export function queueDiscoveryScan({cidrs,requestedBy=null,scheduleId=null}={}){
  const scanId=id(),stamp=now()
  run('INSERT INTO discovery_scans(id,cidrs_json,status,created_at,requested_by,schedule_id) VALUES(?,?,\'queued\',?,?,?)',scanId,json(cidrs),stamp,requestedBy,scheduleId)
  audit(requestedBy,'network-discovery.start','discovery-scan',scanId,null,{cidrs,scheduleId})
  return scanId
}
function finishDiscoverySchedule(scheduleId,status,error=null){
  if(!scheduleId)return
  const schedule=one('SELECT enabled FROM discovery_scan_schedules WHERE id=?',scheduleId)
  if(!schedule)return
  run('UPDATE discovery_scan_schedules SET status=?,running_since=NULL,last_error=?,updated_at=? WHERE id=?',schedule.enabled?'enabled':'paused',error,now(),scheduleId)
}
export async function processDueDiscoverySchedules({actorId=null,at=new Date(),limit=5}={}){
  const timestamp=at instanceof Date?at:new Date(at),atIso=timestamp.toISOString(),rows=all("SELECT * FROM discovery_scan_schedules WHERE enabled=1 AND status='enabled' AND next_run_at<=? ORDER BY next_run_at LIMIT ?",atIso,Math.max(1,Math.min(25,Number(limit)||5)))
  const queued=[]
  for(const schedule of rows){
    const claimed=run("UPDATE discovery_scan_schedules SET status='running',running_since=?,next_run_at=?,updated_at=? WHERE id=? AND enabled=1 AND status='enabled' AND next_run_at<=?",atIso,new Date(timestamp.getTime()+schedule.interval_minutes*60_000).toISOString(),atIso,schedule.id,atIso)
    if(!claimed.changes)continue
    try{
      const scanId=queueDiscoveryScan({cidrs:parse(schedule.cidrs_json)||[],requestedBy:actorId,scheduleId:schedule.id})
      run('UPDATE discovery_scan_schedules SET last_scan_id=?,last_run_at=?,last_error=NULL,updated_at=? WHERE id=?',scanId,atIso,atIso,schedule.id)
      queued.push({scheduleId:schedule.id,scanId})
      setImmediate(()=>runDiscoveryScan(scanId).catch(error=>console.error(`Scheduled discovery scan failed for ${schedule.id}:`,error)))
    }catch(error){finishDiscoverySchedule(schedule.id,'failed',error.message);audit(actorId,'network-discovery.schedule.failed','discovery-schedule',schedule.id,null,{error:error.message})}
  }
  return queued
}
export async function runDiscoveryScheduleNow(scheduleId,{actorId=null}={}){
  const schedule=one('SELECT * FROM discovery_scan_schedules WHERE id=?',scheduleId)
  if(!schedule)throw Object.assign(new Error('Discovery schedule not found'),{status:404})
  if(!schedule.enabled)throw Object.assign(new Error('Enable the discovery schedule before running it'),{status:409})
  const claimed=run("UPDATE discovery_scan_schedules SET status='running',running_since=?,next_run_at=?,updated_at=? WHERE id=? AND enabled=1 AND status='enabled'",now(),new Date(Date.now()+schedule.interval_minutes*60_000).toISOString(),now(),scheduleId)
  if(!claimed.changes)throw Object.assign(new Error('This discovery schedule is already running'),{status:409})
  try{
    const scanId=queueDiscoveryScan({cidrs:parse(schedule.cidrs_json)||[],requestedBy:actorId,scheduleId})
    run('UPDATE discovery_scan_schedules SET last_scan_id=?,last_run_at=?,last_error=NULL,updated_at=? WHERE id=?',scanId,now(),now(),scheduleId)
    setImmediate(()=>runDiscoveryScan(scanId).catch(error=>console.error(`Scheduled discovery scan failed for ${scheduleId}:`,error)))
    return {scheduleId,scanId,status:'queued'}
  }catch(error){finishDiscoverySchedule(scheduleId,'failed',error.message);throw error}
}
const defaultCredential=()=>one("SELECT node_credential_id FROM directory_connections WHERE id='default' AND enabled=1")?.node_credential_id||null
function existingNode(ip,hostname,mac=null){
  const normalizedMac=normalizeMac(mac)
  if(normalizedMac){const byMac=one("SELECT * FROM nodes WHERE lower(mac_address)=? ORDER BY CASE WHEN inventory_source='ad' THEN 0 ELSE 1 END,created_at LIMIT 1",normalizedMac);if(byMac)return byMac}
  const lower=String(hostname||'').toLowerCase()
  return one('SELECT * FROM nodes WHERE ip=? OR lower(hostname)=? OR lower(fqdn)=? ORDER BY CASE WHEN inventory_source=\'ad\' THEN 0 ELSE 1 END LIMIT 1',ip,lower,lower)
}
export async function registerHost(ip,scanId,livenessMethod='icmp',livenessMeta={}){
  let hostname=ip,fqdn=null
  try{const names=await dns.reverse(ip);if(names[0]){fqdn=names[0];hostname=fqdn.split('.')[0]}}catch{}
  const candidateMac=normalizeMac(livenessMeta?.mac),found=existingNode(ip,hostname,candidateMac)
  if(found){run('UPDATE nodes SET last_discovered_at=?,discovery_source=?,status=CASE WHEN status=\'unknown\' THEN \'reachable\' ELSE status END,mac_address=COALESCE(?,mac_address) WHERE id=?',now(),`${livenessMethod}:${scanId}`,candidateMac,found.id);return {ip,nodeId:found.id,existing:true,hostname:found.hostname,fqdn:found.fqdn||null,mac:candidateMac||found.mac_address||null,osName:found.os_name||found.platform||null,osVersion:found.os_version||null,hypervisor:found.hypervisor||null,managed:found.agent_required===0,livenessMethod}}
  const nodeId=id(),credentialId=defaultCredential()
  db.transaction(()=>{
    run("INSERT INTO nodes(id,hostname,fqdn,ip,connection_mode,status,inventory_source,discovery_source,last_discovered_at,agent_required,mac_address,os_name) VALUES(?,?,?,?,?,?,?,?,?,1,?,?)",nodeId,hostname,fqdn,ip,'agentless','reachable','discovery',`${livenessMethod}:${scanId}`,now(),candidateMac,livenessMeta.osHint||null)
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
    const current=one('SELECT * FROM nodes WHERE id=?',nodeId)
    return {ip,nodeId,hostname:current?.hostname||hostname,fqdn:current?.fqdn||fqdn,mac:current?.mac_address||null,osName:current?.os_name||current?.platform||null,osVersion:current?.os_version||null,hypervisor:current?.hypervisor||null,transport:probed.transport,managed:!!probed.winrmAuthenticated,livenessMethod}
  }catch(error){
    run('UPDATE nodes SET agent_required=1,status=CASE WHEN status=\'reachable\' THEN \'degraded\' ELSE status END WHERE id=?',nodeId)
    const current=one('SELECT * FROM nodes WHERE id=?',nodeId)
    return {ip,nodeId,hostname:current?.hostname||hostname,fqdn:current?.fqdn||fqdn,mac:current?.mac_address||null,osName:current?.os_name||current?.platform||null,osVersion:current?.os_version||null,hypervisor:current?.hypervisor||null,agentRequired:true,managed:false,error:error.message,livenessMethod}
  }
}
export async function runDiscoveryScan(scanId){
  const scan=one('SELECT * FROM discovery_scans WHERE id=?',scanId);if(!scan)return
  const cidrs=JSON.parse(scan.cidrs_json),hosts=expandCidrs(cidrs)
  const claimed=run("UPDATE discovery_scans SET status='running',started_at=? WHERE id=? AND status='queued'",now(),scanId)
  if(!claimed.changes)return one('SELECT * FROM discovery_scans WHERE id=?',scanId)
  const results=[],concurrency=32
  let cursor=0
  const worker=async()=>{while(cursor<hosts.length){const ip=hosts[cursor++];run('UPDATE discovery_scans SET probed=probed+1 WHERE id=?',scanId);const liveness=await probeHostLiveness(ip);if(!liveness.alive)continue;run('UPDATE discovery_scans SET alive=alive+1,arp_alive=arp_alive+?,tcp_alive=tcp_alive+? WHERE id=?',liveness.method==='arp'?1:0,liveness.method?.startsWith('tcp:')?1:0,scanId);try{const result=await registerHost(ip,scanId,liveness.method,liveness);results.push(result);run('UPDATE discovery_scans SET registered=registered+1 WHERE id=?',scanId)}catch(error){results.push({ip,error:error.message,livenessMethod:liveness.method})}}}
  try{
    await Promise.all(Array.from({length:Math.min(concurrency,hosts.length)},worker))
    const limited=results.slice(0,MAX_HOSTS),previousScan=scan.schedule_id?one("SELECT results_json FROM discovery_scans WHERE schedule_id=? AND status='complete' AND id<>? ORDER BY finished_at DESC,rowid DESC LIMIT 1",scan.schedule_id,scan.id):null
    const diff=scan.schedule_id?diffDiscoveryResults(parse(previousScan?.results_json)||[],limited):{}
    run("UPDATE discovery_scans SET status='complete',results_json=?,diff_json=?,finished_at=? WHERE id=?",json(limited),json(diff),now(),scanId)
    finishDiscoverySchedule(scan.schedule_id,'complete',null)
    audit(null,'network-discovery.complete','discovery-scan',scanId,null,{probed:hosts.length,alive:results.length,arpAlive:one('SELECT arp_alive FROM discovery_scans WHERE id=?',scanId)?.arp_alive||0,tcpAlive:one('SELECT tcp_alive FROM discovery_scans WHERE id=?',scanId)?.tcp_alive||0,diff:diff.summary||null})
  }
  catch(error){run("UPDATE discovery_scans SET status='failed',error=?,results_json=?,finished_at=? WHERE id=?",error.message,json(results),now(),scanId);finishDiscoverySchedule(scan.schedule_id,'failed',error.message);audit(null,'network-discovery.failed','discovery-scan',scanId,null,{error:error.message})}
}
