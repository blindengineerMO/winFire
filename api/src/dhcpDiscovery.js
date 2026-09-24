import {configuredCidrs,inLocalCidrs} from './services/networkBoundary.js'
import {BlockList, isIPv4} from 'node:net'
import {createHash} from 'node:crypto'
import {z} from 'zod'
import {db, all, one, run, id, now, audit} from './db.js'

const timestamp = z.string().datetime({offset:true})
const leaseSchema = z.object({
  ip:z.string().max(45), mac:z.string().max(100), hostname:z.string().max(253).default(''),
  leaseExpiry:timestamp, state:z.string().max(40).default('Active')
}).strict()
export const dhcpImportSchema = z.object({
  source:z.string().trim().min(1).max(253), observedAt:timestamp,
  leases:z.array(leaseSchema).min(1).max(2000)
}).strict()
const error = (message, status=400) => Object.assign(new Error(message), {status})
const macKey = value => String(value||'').toLowerCase().replace(/[:-]/g,'')
function normalizeMac(value) {
  let raw=macKey(value)
  // Windows Ethernet client IDs may include the hardware-type byte.
  if(/^01[0-9a-f]{12}$/.test(raw))raw=raw.slice(2)
  if(!/^[0-9a-f]{12}$/.test(raw)||/^0{12}$/.test(raw)||(parseInt(raw.slice(0,2),16)&1))return null
  return raw.match(/../g).join(':')
}
function localScope() {
  const entries=configuredCidrs()
  if(!entries.length)throw error('Configure Local asset CIDRs in Administration → Server config before importing DHCP leases.',409)
  return {check:ip=>inLocalCidrs(ip,entries)}
}
const hostKey = value => String(value||'').toLowerCase().replace(/\.$/,'').split('.')[0]
const placeholderName = node => !node.hostname||node.hostname===node.ip||/^unknown$/i.test(node.hostname)
function planImport(input) {
  const data=dhcpImportSchema.parse(input), at=now(), scope=localScope()
  if(Date.parse(data.observedAt)>Date.parse(at)+300000)throw error('Observation time cannot be more than five minutes in the future.')
  const nodes=all('SELECT * FROM nodes'), seenIps=new Map(), seenMacs=new Map()
  const leases=data.leases.map(lease=>({...lease,hostname:lease.hostname.trim().replace(/\.$/,''),mac:normalizeMac(lease.mac),leaseExpiry:new Date(lease.leaseExpiry).toISOString()}))
  for(const lease of leases){seenIps.set(lease.ip,(seenIps.get(lease.ip)||0)+1);if(lease.mac)seenMacs.set(lease.mac,(seenMacs.get(lease.mac)||0)+1)}
  const rows=leases.map((lease,index)=>{
    const row={...lease,row:index+1,action:'skipped',reason:'',nodeId:null}
    if(!isIPv4(lease.ip)||!lease.mac)return {...row,reason:'Invalid IPv4 address or Ethernet MAC/client ID'}
    if(lease.hostname&&!/^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?$/i.test(lease.hostname))return {...row,reason:'Invalid hostname'}
    if(!scope.check(lease.ip,'ipv4'))return {...row,reason:'Outside configured local asset CIDRs'}
    if(!['active','activereservation'].includes(lease.state.toLowerCase()))return {...row,reason:'Lease is not active'}
    if(lease.leaseExpiry<=at||Date.parse(lease.leaseExpiry)<=Date.parse(data.observedAt))return {...row,reason:'Lease has expired'}
    if(seenIps.get(lease.ip)>1||seenMacs.get(lease.mac)>1)return {...row,action:'conflict',reason:'Duplicate IP or MAC in this import; export one current lease per device'}
    const byMac=nodes.filter(node=>macKey(node.mac_address)===macKey(lease.mac)), byIp=nodes.filter(node=>node.ip===lease.ip)
    if(byMac.length>1||byIp.length>1||(byMac.length&&byIp.some(node=>node.id!==byMac[0].id)))return {...row,action:'conflict',reason:'MAC and IP match different inventory identities'}
    const node=byMac[0]||byIp[0]
    if(!node)return {...row,action:'created',reason:'New local unmanaged asset'}
    row.nodeId=node.id
    if(node.mac_address&&macKey(node.mac_address)!==macKey(lease.mac))return {...row,action:'conflict',reason:'IP belongs to an asset with a different MAC'}
    if(!byMac.length&&!placeholderName(node)&&lease.hostname&&![node.hostname,node.fqdn].some(name=>hostKey(name)===hostKey(lease.hostname)))return {...row,action:'conflict',reason:'IP matches but hostname differs; verify identity before merging'}
    const previous=node.dhcp_lease_json?JSON.parse(node.dhcp_lease_json):null
    if(previous&&Date.parse(previous.observedAt)>=Date.parse(data.observedAt))return {...row,reason:'An equal or newer DHCP observation is already retained'}
    const move=node.ip!==lease.ip
    // A lease is advisory. Never redirect authenticated management to a new address.
    const canMove=node.inventory_source==='discovery'&&node.agent_required!==0&&!node.last_managed_at&&node.firewall_state==='unmanaged'
    return {...row,action:'enriched',updateAddress:move&&canMove,reason:move?(canMove?'Same MAC; update unmanaged asset address':'Same MAC; retain managed address and attach lease evidence'):'Existing asset enriched'}
  })
  const summary={created:0,enriched:0,skipped:0,conflict:0,total:rows.length}
  for(const row of rows)summary[row.action]++
  return {source:data.source,observedAt:new Date(data.observedAt).toISOString(),summary,rows}
}
export const previewDhcpImport = input => planImport(input)
export function importDhcpLeases(input, actorId) {
  // Re-evaluate in the transaction: preview is advisory and inventory may have changed.
  return db.transaction(()=>{
    const result=planImport(input)
    const fingerprint=createHash('sha256').update(JSON.stringify(dhcpImportSchema.parse(input))).digest('hex')
    const existing=one('SELECT * FROM dhcp_lease_imports WHERE fingerprint=?',fingerprint)
    if(existing)return {...publicImport(existing),replayed:true}
    const importId=id(),importedAt=now()
    for(const row of result.rows){
      if(!['created','enriched'].includes(row.action))continue
      const evidence={source:result.source,observedAt:result.observedAt,importedAt,importId,ip:row.ip,mac:row.mac,hostname:row.hostname,leaseExpiry:row.leaseExpiry,state:row.state}
      if(row.action==='created'){
        row.nodeId=id()
        run(`INSERT INTO nodes(id,hostname,fqdn,ip,mac_address,inventory_source,discovery_source,first_discovered_at,last_discovered_at,connection_mode,status,agent_required,firewall_state,dhcp_lease_json)
          VALUES(?,?,?,?,?,'discovery',?,?,?,'agentless','unknown',1,'unmanaged',?)`,row.nodeId,row.hostname||row.ip,row.hostname.includes('.')?row.hostname:null,row.ip,row.mac,`dhcp:${importId}`,result.observedAt,result.observedAt,JSON.stringify(evidence))
      }else{
        const node=one('SELECT * FROM nodes WHERE id=?',row.nodeId)
        const name=placeholderName(node)&&row.hostname?row.hostname:node.hostname
        run('UPDATE nodes SET dhcp_lease_json=?,mac_address=COALESCE(NULLIF(mac_address,\'\'),?),hostname=?,ip=? WHERE id=?',JSON.stringify(evidence),row.mac,name,row.updateAddress?row.ip:node.ip,node.id)
      }
    }
    run('INSERT INTO dhcp_lease_imports(id,fingerprint,source,observed_at,imported_at,summary_json,rows_json) VALUES(?,?,?,?,?,?,?)',importId,fingerprint,result.source,result.observedAt,importedAt,JSON.stringify(result.summary),JSON.stringify(result.rows))
    audit(actorId,'discovery.dhcp.import','dhcp-import',importId,null,{source:result.source,observedAt:result.observedAt,...result.summary})
    return {...result,id:importId,importedAt,replayed:false}
  })()
}
const publicImport = row => ({id:row.id,source:row.source,observedAt:row.observed_at,importedAt:row.imported_at,summary:JSON.parse(row.summary_json),...(row.rows_json?{rows:JSON.parse(row.rows_json)}:{})})
export function dhcpImportHistory({page=1,pageSize=25}={}) {
  const query=z.object({page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(100).default(25)}).parse({page,pageSize})
  const total=one('SELECT count(*) AS count FROM dhcp_lease_imports').count
  return {...query,total,totalPages:Math.max(1,Math.ceil(total/query.pageSize)),items:all('SELECT id,source,observed_at,imported_at,summary_json FROM dhcp_lease_imports ORDER BY imported_at DESC,rowid DESC LIMIT ? OFFSET ?',query.pageSize,(query.page-1)*query.pageSize).map(publicImport)}
}
export function dhcpImportById(importId) {
  const row=one('SELECT * FROM dhcp_lease_imports WHERE id=?',importId)
  if(!row)throw error('DHCP import not found',404)
  return publicImport(row)
}
