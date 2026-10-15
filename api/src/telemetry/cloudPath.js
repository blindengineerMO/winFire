import {z} from 'zod'
import {all,one} from '../db.js'
import {canonicalIp,subnetMatcher} from '../services/networkBoundary.js'

const lower=v=>String(v||'').toLowerCase()
const fail=(message,status=400)=>{throw Object.assign(new Error(message),{status})}
function addressMatch(values,ip){
  if(!values.length)return null
  let unknown=false
  for(const value of values){
    if(value==='*')return true
    try{if(value.includes('/')){if(subnetMatcher(value)(ip))return true}else if(canonicalIp(value)){if(canonicalIp(value)===ip)return true}else unknown=true}catch{unknown=true}
  }
  return unknown?null:false
}
function portMatch(values,port){
  if(!values.length)return null
  let unknown=false
  for(const value of values){if(value==='*')return true;if(!/^\d+(?:-\d+)?$/.test(String(value))){unknown=true;continue}const [a,b=a]=String(value).split('-').map(Number);if(a>65535||b>65535||b<a){unknown=true;continue}if(port>=a&&port<=b)return true}
  return unknown?null:false
}
const values=(p,singular,plural)=>Array.isArray(p[plural])&&p[plural].length?p[plural]:p[singular]!=null?[p[singular]]:[]
export function evaluateNsg(snapshot,flow,direction){
  const p=snapshot?.properties
  if(!p||!Array.isArray(p.securityRules)||!Array.isArray(p.defaultSecurityRules))return {decision:'indeterminate',reason:'Complete custom and default NSG rules were not retained'}
  const rules=[...p.securityRules,...p.defaultSecurityRules].filter(r=>lower(r.properties?.direction)===direction.toLowerCase())
  if(rules.length>2000||rules.some(r=>!Number.isInteger(r.properties.priority)||r.properties.priority<1||r.properties.priority>65535)||new Set(rules.map(r=>r.properties.priority)).size!==rules.length)return {decision:'indeterminate',reason:'NSG priorities are missing, duplicated or exceed the evaluation budget'}
  rules.sort((a,b)=>a.properties.priority-b.properties.priority)
  for(const rule of rules){
    const r=rule.properties,protocol=lower(r.protocol)
    const tests=[protocol==='*'?true:['tcp','udp'].includes(protocol)?protocol===flow.protocol.toLowerCase():null,
      r.sourceApplicationSecurityGroups?.length?null:addressMatch(values(r,'sourceAddressPrefix','sourceAddressPrefixes'),flow.sourceIp),
      r.destinationApplicationSecurityGroups?.length?null:addressMatch(values(r,'destinationAddressPrefix','destinationAddressPrefixes'),flow.destinationIp),
      portMatch(values(r,'sourcePortRange','sourcePortRanges'),flow.sourcePort),portMatch(values(r,'destinationPortRange','destinationPortRanges'),flow.destinationPort)]
    if(tests.includes(false))continue
    if(tests.includes(null))return {decision:'indeterminate',rule:rule.name,priority:r.priority,reason:'A higher-priority rule has unresolved service tags, application groups, ports or protocol'}
    return {decision:lower(r.access)==='allow'?'allow':lower(r.access)==='deny'?'block':'indeterminate',rule:rule.name,priority:r.priority,reason:'First matching configured NSG rule; applies to new flows only'}
  }
  return {decision:'indeterminate',reason:'No decisive retained rule; effective rules were not queried'}
}

export function cloudPath(input){
  const q=z.object({connectionId:z.string().min(1).max(200),sourceIp:z.string().transform(canonicalIp),destinationIp:z.string().transform(canonicalIp),sourcePort:z.coerce.number().int().min(0).max(65535),destinationPort:z.coerce.number().int().min(0).max(65535),protocol:z.enum(['TCP','UDP'])}).strict().parse(input)
  if(!q.sourceIp||!q.destinationIp)fail('Valid source and destination IPs are required')
  if(!one('SELECT id FROM azure_connections WHERE id=?',q.connectionId))fail('Azure connection not found',404)
  const rows=all('SELECT * FROM cloud_network_context WHERE connection_id=? ORDER BY resource_id LIMIT 10001',q.connectionId)
  if(rows.length>10000)fail('Cloud context exceeds the 10,000-resource evaluation budget',413)
  const resources=new Map(rows.map(r=>[lower(r.resource_id),{...r,snapshot:JSON.parse(r.snapshot_json)}]))
  const gaps=[],steps=[],routes=[],networks=[]
  const current=row=>row&&Number.isFinite(Date.parse(row.observed_at))&&Date.parse(row.observed_at)<=Date.now()+60000&&Date.now()-Date.parse(row.observed_at)<15*60000
  for(const [ip,direction] of [[q.sourceIp,'Outbound'],[q.destinationIp,'Inbound']]){
    const matches=rows.filter(r=>r.kind==='networkInterfaces'&&JSON.parse(r.snapshot_json).properties?.ipConfigurations?.some(c=>canonicalIp(c.properties?.privateIPAddress)===ip))
    if(matches.length!==1){gaps.push(`${direction}: ${matches.length?'ambiguous':'missing'} NIC identity inside this connection`);continue}
    const nic=resources.get(lower(matches[0].resource_id)),np=nic.snapshot.properties
    if(!current(nic)){gaps.push(`${direction}: NIC snapshot is stale or has an invalid timestamp`);continue}
    const configs=np.ipConfigurations.filter(c=>canonicalIp(c.properties?.privateIPAddress)===ip)
    if(configs.length!==1){gaps.push(`${direction}: NIC IP configuration is ambiguous`);continue}
    const config=configs[0].properties,subnetId=lower(config.subnet?.id),vnetId=subnetId.split('/subnets/')[0],vnet=resources.get(vnetId)
    const subnet=current(vnet)&&vnet.snapshot.properties?.subnets?.find(s=>lower(s.id)===subnetId)
    if(!subnet){gaps.push(`${direction}: current subnet/VNet configuration is missing`);continue}
    networks.push(vnetId)
    if(config.publicIPAddress||np.privateEndpoint||np.enableIPForwarding)gaps.push(`${direction}: public NAT, private endpoints or forwarded paths need effective-path evidence`)
    for(const [level,nsgId] of [['NIC',np.networkSecurityGroup?.id],['subnet',subnet.properties?.networkSecurityGroup?.id]]){
      if(!nsgId){steps.push({direction,level,decision:'no-nsg',reason:'No NSG association in this configuration snapshot'});continue}
      const nsg=resources.get(lower(nsgId))
      steps.push({direction,level,resourceId:nsgId,...(current(nsg)?evaluateNsg(nsg.snapshot,q,direction):{decision:'indeterminate',reason:'Associated NSG is missing or stale'})})
    }
    if(direction==='Outbound'&&subnet.properties?.routeTable?.id){
      const table=resources.get(lower(subnet.properties.routeTable.id))
      if(!current(table)||!Array.isArray(table.snapshot.properties?.routes)){gaps.push('Current source subnet route table is missing');continue}
      const candidates=[]
      for(const route of table.snapshot.properties.routes){const prefix=route.properties?.addressPrefix;try{if(!prefix?.includes('/')){gaps.push('Service-tag route requires effective routing evidence');continue}if(subnetMatcher(prefix)(q.destinationIp))candidates.push(route)}catch{gaps.push('Unsupported route prefix')}}
      candidates.sort((a,b)=>Number(b.properties.addressPrefix.split('/')[1])-Number(a.properties.addressPrefix.split('/')[1]))
      if(candidates[0]){const r=candidates[0];routes.push({resourceId:table.resource_id,name:r.name,...r.properties});if(r.properties.nextHopType==='None')steps.push({direction,level:'route',decision:'block',reason:'Selected configured route drops this destination'});else gaps.push('Configured routes do not include complete effective BGP/system routing, peering or appliance behavior')}
    }
    if(vnet.snapshot.properties?.virtualNetworkPeerings?.length)gaps.push('Peering configuration does not establish an effective or symmetric path')
  }
  if(new Set(networks).size>1)gaps.push('Endpoints span VNets; retained NSGs alone do not establish an effective cross-VNet route')
  const configurationDecision=gaps.length||steps.some(s=>s.decision==='indeterminate')?'indeterminate':steps.some(s=>s.decision==='block')?'block':steps.length?'allow':'indeterminate'
  return {flow:q,configurationDecision,reachability:'indeterminate',activelyVerified:false,steps,routes,gaps:[...new Set(gaps)],limitations:['Read-only analysis of retained NSG/route configuration for new TCP/UDP flows','Host firewalls, Azure security-admin rules, load balancers, NAT, service tags and effective BGP/system routes can change the outcome','No cloud resource or paid service is enabled or modified']}
}
