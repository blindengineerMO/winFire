import {isIP} from 'node:net'
import {db,one,run,now} from '../db.js'

export function canonicalIp(value){
  const raw=String(value||'').trim().split('%')[0]
  if(isIP(raw)===4)return raw
  if(isIP(raw)!==6)return null
  const ip=new URL(`http://[${raw}]/`).hostname.slice(1,-1)
  if(ip.startsWith('::ffff:')){
    const tail=ip.slice(7).split(':');if(tail.length===2){const n=parseInt(tail[0],16)*65536+parseInt(tail[1],16);return [24,16,8,0].map(s=>(n>>>s)&255).join('.')}
  }
  return ip
}
function number(ip){
  if(isIP(ip)===4)return ip.split('.').reduce((n,p)=>(n<<8n)+BigInt(p),0n)
  const [left,right]=ip.split('::'),a=left?left.split(':'):[],b=right?right.split(':'):[]
  const parts=right!==undefined?[...a,...Array(8-a.length-b.length).fill('0'),...b]:a
  return parts.reduce((n,p)=>(n<<16n)+BigInt('0x'+p),0n)
}
const cache=new Map()
export function subnetMatcher(value){
  const cidr=String(value||'').trim();if(cache.has(cidr))return cache.get(cidr)
  const [raw,prefix,...rest]=cidr.split('/'),ip=canonicalIp(raw),family=isIP(ip||'');let bits=Number(prefix)
  if(isIP(raw)===6&&family===4)bits-=96
  if(rest.length||!isIP(raw)||!ip||!/^\d+$/.test(prefix||'')||bits<0||bits>(family===4?32:128))throw Object.assign(new Error('Enter a valid IPv4 or IPv6 CIDR'),{status:400})
  const shift=BigInt((family===4?32:128)-bits),network=number(ip)>>shift
  const match=value=>{const candidate=canonicalIp(value);return !!candidate&&isIP(candidate)===family&&(number(candidate)>>shift)===network}
  match.family=family;match.bits=bits;match.network=network;match.shift=shift
  if(cache.size>1024)cache.clear();cache.set(cidr,match);return match
}
export function normalizeCidrs(values){
  const entries=(Array.isArray(values)?values:[values]).flatMap(v=>String(v||'').split(/\\n|[\r\n,]/)).map(v=>v.trim()).filter(Boolean)
  if(entries.length>256)throw Object.assign(new Error('Provide at most 256 local CIDRs'),{status:400})
  return [...new Set(entries.map(c=>{subnetMatcher(c);return c.toLowerCase()}))].sort()
}
export function configuredCidrs(){
  const raw=one("SELECT value FROM app_settings WHERE key='local_asset_cidrs'")?.value||'[]'
  let value;try{value=JSON.parse(raw)}catch{value=raw}
  return normalizeCidrs(value)
}
export const inLocalCidrs=(ip,cidrs=configuredCidrs())=>cidrs.some(c=>subnetMatcher(c)(ip))
export function addressCategory(value,cidrs=[]){
  const ip=canonicalIp(value);if(!ip)return 'invalid'
  const inside=c=>subnetMatcher(c)(ip)
  if(ip==='0.0.0.0'||ip==='::')return 'unspecified'
  if(inside('127.0.0.0/8')||ip==='::1')return 'loopback'
  if(inside('169.254.0.0/16')||inside('fe80::/10'))return 'link-local'
  if(ip==='255.255.255.255')return 'broadcast'
  if(isIP(ip)===4&&cidrs.some(c=>{const m=subnetMatcher(c);return m.family===4&&m.bits<=30&&m(ip)&&number(ip)===((m.network+1n)<<m.shift)-1n}))return 'broadcast'
  if(inside('224.0.0.0/4')||inside('ff00::/8'))return 'multicast'
  if(inside('240.0.0.0/4')||inside('0.0.0.0/8'))return 'reserved'
  if(inside('10.0.0.0/8')||inside('172.16.0.0/12')||inside('192.168.0.0/16')||inside('fc00::/7'))return 'private'
  if(inside('100.64.0.0/10'))return 'shared'
  if(inside('192.0.2.0/24')||inside('198.51.100.0/24')||inside('203.0.113.0/24')||inside('2001:db8::/32'))return 'documentation'
  return 'public'
}
export const unicastIp=(ip,cidrs=[])=>['public','private','shared','documentation'].includes(addressCategory(ip,cidrs))
export const outsideLocal=(ip,cidrs)=>cidrs.length>0&&unicastIp(ip,cidrs)&&!inLocalCidrs(ip,cidrs)
export const inventoryEligibleIp=ip=>{const scopes=configuredCidrs();return unicastIp(ip,scopes)&&(!scopes.length||inLocalCidrs(ip,scopes))}
export const scopeCidrs=scopeId=>!scopeId||scopeId==='default'?configuredCidrs():JSON.parse(one('SELECT cidrs_json FROM inventory_scopes WHERE id=?',scopeId)?.cidrs_json||'[]')
export const isLocalAssetNode=node=>{const cidrs=scopeCidrs(node?.scope_id);return !node?.scope_id||node.scope_id==='default'?(!node?.ip||!cidrs.length||inLocalCidrs(node.ip,cidrs)):!!node.ip&&inLocalCidrs(node.ip,cidrs)}
export function assertDirectManagement(node){
  if(node?.scope_id&&node.scope_id!=='default'&&!one('SELECT direct_management FROM inventory_scopes WHERE id=?',node.scope_id)?.direct_management)throw Object.assign(new Error('This network scope is inventory-only; configure a verified management path before host operations'),{status:409})
}


export function boundaryState(){
  const cidrs=configuredCidrs(),serialized=JSON.stringify(cidrs)
  let state=one('SELECT * FROM internet_index_state WHERE id=1')
  const desired=state.desired_revision?one('SELECT * FROM network_boundaries WHERE revision=?',state.desired_revision):null
  if(desired?.cidrs_json!==serialized){
    db.transaction(()=>{
      // Serialize revision creation with both ingestion and other API requests.
      const current=one('SELECT b.* FROM network_boundaries b JOIN internet_index_state s ON s.desired_revision=b.revision WHERE s.id=1')
      if(current?.cidrs_json===serialized)return
      const revision=run('INSERT INTO network_boundaries(cidrs_json,created_at) VALUES(?,?)',serialized,now()).lastInsertRowid
      run('UPDATE internet_index_state SET desired_revision=?,cursor=0,high_water=?,updated_at=? WHERE id=1',revision,one('SELECT COALESCE(MAX(rowid),0) n FROM log_events').n,now())
    }).immediate()
    state=one('SELECT * FROM internet_index_state WHERE id=1')
  }
  const effective=state.active_revision?JSON.parse(one('SELECT cidrs_json FROM network_boundaries WHERE revision=?',state.active_revision).cidrs_json):cidrs
  return {...state,cidrs,effectiveCidrs:effective,pending:state.active_revision!==state.desired_revision,configurationNeeded:cidrs.length===0,missingFamilies:[4,6].filter(f=>!cidrs.some(c=>subnetMatcher(c).family===f))}
}
export const effectiveCidrs=()=>boundaryState().effectiveCidrs
db.function('winfire_ip',{deterministic:true},canonicalIp)
db.function('winfire_subnet',{deterministic:true},(ip,cidr)=>Number(subnetMatcher(cidr)(ip)))
db.function('winfire_outside',{deterministic:true},(ip,cidrs)=>Number(outsideLocal(ip,JSON.parse(cidrs))))
