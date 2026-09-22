import {isIP} from 'node:net'
import {db,all,one,run,id,now,json,parse,audit} from './db.js'

const DEFAULT_INTERVAL_MINUTES=60
const MAX_INTERVAL_MINUTES=10080
const FIELD_NAMES=new Set(['hostname','fqdn','ip'])
const OPERATORS=new Set(['contains','equals','cidr'])

function fail(message){throw Object.assign(new Error(message),{status:400})}
function normalizeAddress(value){return String(value||'').trim().toLowerCase().replace(/^\[|\]$/g,'')}
function parseCidr(value){
  const [address,prefixText]=normalizeAddress(value).split('/')
  const version=isIP(address)
  if(!version||prefixText===''||prefixText===undefined)fail('CIDR conditions require an address and prefix length')
  const prefix=Number(prefixText),bits=version===4?32:128
  if(!Number.isInteger(prefix)||prefix<0||prefix>bits)fail(`CIDR prefix must be between 0 and ${bits}`)
  return {address,prefix,version,bits}
}
function ipv4BigInt(value){return value.split('.').reduce((result,part)=>result*256n+BigInt(Number(part)),0n)}
function ipv6BigInt(value){
  const normalized=value.toLowerCase()
  const pieces=normalized.includes('::')?(()=>{const [left,right]=normalized.split('::');const a=left?left.split(':'):[],b=right?right.split(':'):[];return [...a,...Array(8-a.length-b.length).fill('0'),...b]})():normalized.split(':')
  if(pieces.length!==8)return null
  return pieces.reduce((result,part)=>result*65536n+BigInt(parseInt(part||'0',16)),0n)
}
function addressBigInt(value,version){return version===4?ipv4BigInt(value):ipv6BigInt(value)}
function matchesCidr(address,cidr){
  const parsed=parseCidr(cidr),candidate=normalizeAddress(address)
  if(isIP(candidate)!==parsed.version)return false
  const target=addressBigInt(parsed.address,parsed.version),actual=addressBigInt(candidate,parsed.version)
  if(target===null||actual===null)return false
  if(parsed.prefix===0)return true
  const shift=BigInt(parsed.bits-parsed.prefix)
  return (target>>shift)===(actual>>shift)
}

export function normalizeDynamicRules(input={}){
  const enabled=input.enabled===true||input.enabled===1||input.enabled==='true'
  const match=input.match==='any'?'any':'all'
  const rules=Array.isArray(input.rules)?input.rules.slice(0,25).map((raw,index)=>{
    const field=raw?.field==='name'?'hostname':String(raw?.field||'hostname').toLowerCase()
    const operator=String(raw?.operator||'contains').toLowerCase()
    const value=String(raw?.value||'').trim()
    if(!FIELD_NAMES.has(field))fail(`Dynamic rule ${index+1} has an unsupported field`)
    if(!OPERATORS.has(operator))fail(`Dynamic rule ${index+1} has an unsupported operator`)
    if(!value||value.length>255)fail(`Dynamic rule ${index+1} must have a value up to 255 characters`)
    if(operator==='cidr'){if(field!=='ip')fail(`Dynamic rule ${index+1}: CIDR is only valid for IP address`);parseCidr(value)}
    if(operator==='equals'&&field==='ip'&&isIP(normalizeAddress(value))===0)fail(`Dynamic rule ${index+1}: IP equality requires an IP address`)
    return {field,operator,value:operator==='contains'&&field!=='ip'?value.toLowerCase():normalizeAddress(value)}
  }):[]
  if(enabled&&!rules.length)fail('A dynamic group needs at least one matching rule')
  return {enabled,match,rules}
}

export function dynamicNodeGroupIntervalMinutes(){
  const value=Number(one("SELECT value FROM app_settings WHERE key='dynamic_node_groups_interval_minutes'")?.value||DEFAULT_INTERVAL_MINUTES)
  return Math.min(MAX_INTERVAL_MINUTES,Math.max(5,Number.isFinite(value)?value:DEFAULT_INTERVAL_MINUTES))
}

export function dynamicNodeGroupSettings(){return {intervalMinutes:dynamicNodeGroupIntervalMinutes(),minIntervalMinutes:5,maxIntervalMinutes:MAX_INTERVAL_MINUTES}}

function nodeMatchesRule(node,rule){
  const value=String(node?.[rule.field]||'').trim()
  if(!value)return false
  if(rule.operator==='contains')return value.toLowerCase().includes(rule.value.toLowerCase())
  if(rule.operator==='equals')return rule.field==='ip'?normalizeAddress(value)===normalizeAddress(rule.value):value.toLowerCase()===rule.value.toLowerCase()
  if(rule.operator==='cidr')return matchesCidr(value,rule.value)
  return false
}
export function matchesDynamicNode(node,config){
  const rules=config?.rules||[];if(!config?.enabled||!rules.length)return false
  return config.match==='any'?rules.some(rule=>nodeMatchesRule(node,rule)):rules.every(rule=>nodeMatchesRule(node,rule))
}

export function publicDynamicGroup(group){
  const rules=parse(group?.dynamic_rules_json)||[]
  return {dynamicEnabled:Number(group?.dynamic_enabled||0)===1,dynamicMatch:group?.dynamic_match==='any'?'any':'all',dynamicRules:rules,dynamicLastEvaluatedAt:group?.dynamic_last_evaluated_at||null,dynamicNextEvaluationAt:group?.dynamic_next_evaluation_at||null}
}

export function updateDynamicGroup(groupId,input,actorId=null){
  const current=one('SELECT * FROM node_groups WHERE id=?',groupId)
  if(!current)throw Object.assign(new Error('Node group not found'),{status:404})
  if(groupId==='winfire-global-all-nodes'&&input?.enabled)return fail('The global all-nodes group cannot use dynamic membership')
  const previous=publicDynamicGroup(current)
  const config=normalizeDynamicRules({
    enabled:input?.enabled===undefined?previous.dynamicEnabled:input.enabled,
    match:input?.match===undefined?previous.dynamicMatch:input.match,
    rules:input?.rules===undefined?previous.dynamicRules:input.rules
  })
  const next=config.enabled?new Date(Date.now()+dynamicNodeGroupIntervalMinutes()*60_000).toISOString():null
  run('UPDATE node_groups SET dynamic_enabled=?,dynamic_match=?,dynamic_rules_json=?,dynamic_last_evaluated_at=NULL,dynamic_next_evaluation_at=? WHERE id=?',Number(config.enabled),config.match,json(config.rules),next,groupId)
  audit(actorId,'node-group.dynamic.update','node-group',groupId,previous,{...config,dynamicNextEvaluationAt:next})
  return one('SELECT * FROM node_groups WHERE id=?',groupId)
}

export function refreshDynamicGroups({groupId=null,force=false,at=new Date()}={}){
  const timestamp=at instanceof Date?at:new Date(at)
  const groups=groupId?[one('SELECT * FROM node_groups WHERE id=? AND dynamic_enabled=1',groupId)]:all("SELECT * FROM node_groups WHERE dynamic_enabled=1 AND (dynamic_next_evaluation_at IS NULL OR dynamic_next_evaluation_at<=?) ORDER BY dynamic_next_evaluation_at",timestamp.toISOString())
  const nodes=all('SELECT id,hostname,fqdn,ip FROM nodes')
  const results=[]
  db.transaction(()=>{
    for(const group of groups.filter(Boolean)){
      if(!force&&!groupId&&group.dynamic_next_evaluation_at&&Date.parse(group.dynamic_next_evaluation_at)>timestamp.getTime())continue
      const config={enabled:true,match:group.dynamic_match,rules:parse(group.dynamic_rules_json)||[]}
      const desired=new Set(nodes.filter(node=>matchesDynamicNode(node,config)).map(node=>node.id))
      const existing=new Set(all('SELECT node_id FROM node_group_members WHERE group_id=?',group.id).map(row=>row.node_id))
      const added=[...desired].filter(nodeId=>!existing.has(nodeId)),removed=[...existing].filter(nodeId=>!desired.has(nodeId))
      for(const nodeId of added)run('INSERT OR IGNORE INTO node_group_members(group_id,node_id) VALUES(?,?)',group.id,nodeId)
      for(const nodeId of removed)run('DELETE FROM node_group_members WHERE group_id=? AND node_id=?',group.id,nodeId)
      const next=new Date(timestamp.getTime()+dynamicNodeGroupIntervalMinutes()*60_000).toISOString()
      run('UPDATE node_groups SET dynamic_last_evaluated_at=?,dynamic_next_evaluation_at=? WHERE id=?',timestamp.toISOString(),next,group.id)
      if(added.length||removed.length)audit(null,'node-group.dynamic.refresh','node-group',group.id,{added:0,removed:0},{added:added.length,removed:removed.length,matched:desired.size})
      results.push({groupId:group.id,added:added.length,removed:removed.length,matched:desired.size,evaluatedAt:timestamp.toISOString(),nextEvaluationAt:next})
    }
  })()
  return results
}
