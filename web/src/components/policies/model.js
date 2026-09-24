import {validateAddressExpression,validatePortExpression,validateProgramPath,normalizeSchedule,normalizeMfaGate} from '@winfire/shared'
export const types=[['allow','check-circle-outline','Allow rule'],['deny','cancel','Reject rule'],['program','application-outline','Program rule'],['portGroup','numeric','Port group'],['addressGroup','ip-network','Address group'],['profile','shield-outline','Profile scope'],['schedule','clock-outline','Schedule'],['mfaGate','shield-account','MFA gate']]
export const ruleTypes=['allow','deny','program']
export const scopeTypes=['portGroup','addressGroup','profile','schedule']
export const nodeLabel=node=>node.data?.name||types.find(t=>t[0]===node.type)?.[2]||node.type
export function graphDocument(nodes,edges){return {nodes:nodes.map(n=>({id:n.id,type:n.type,position:{x:n.position?.x||0,y:n.position?.y||0},data:Object.fromEntries(Object.entries(n.data||{}).filter(([key])=>key!=='label'))})),edges:edges.map(e=>({id:e.id,source:e.source,target:e.target}))}}
export function newNode(type,index=0){
 const data={name:types.find(t=>t[0]===type)?.[2]||type,direction:'in',protocol:'TCP',localPort:'Any',remotePort:'Any',remoteAddress:'Any',profile:'Any',program:'Any'}
 if(type==='portGroup')data.ports='443'
 if(type==='addressGroup')data.addresses='Any'
 if(type==='schedule')Object.assign(data,{days:'1,2,3,4,5',startTime:'09:00',endTime:'17:00',timezone:'UTC'})
 if(type==='mfaGate')Object.assign(data,{localPort:'3389',sourceAssetScope:'Any',destinationAssetScope:'Any',sourceProcess:'Any',extraPorts:'',fallbackToLoggedOnUser:false,failMode:'closed',sessionTtlMinutes:480,reactiveTtlMinutes:240,entraGroupId:''})
 return {id:crypto.randomUUID(),type,position:{x:60+(index%3)*310,y:60+Math.floor(index/3)*180},data}
}
export function connectionIssue(nodes,edges,{source,target}){
 if(!source||!target)return 'Choose a source scope and a target.'
 if(source===target)return 'A node cannot connect to itself.'
 const from=nodes.find(n=>n.id===source),to=nodes.find(n=>n.id===target)
 if(!from||!to)return 'Both nodes must exist.'
 if(!scopeTypes.includes(from.type)||![...scopeTypes,...ruleTypes].includes(to.type))return 'Connect a scope to another scope or a firewall rule. MFA gates are standalone metadata.'
 if(edges.some(e=>e.source===source&&e.target===target))return 'These nodes are already connected.'
 const seen=new Set(),visit=id=>{if(id===source)return true;if(seen.has(id))return false;seen.add(id);return edges.filter(e=>e.source===id).some(e=>visit(e.target))}
 return visit(target)?'This connection would create a cycle.':''
}
export function nodeIssue(node){
  const data=node.data||{}
  if(node.type==='portGroup'&&!validatePortExpression(data.ports))return 'Enter ports from 1 to 65535, separated by commas.'
  if(node.type==='addressGroup'&&!validateAddressExpression(data.addresses))return 'Enter valid IP addresses, CIDRs, or ranges.'
  if(['allow','deny','program'].includes(node.type)){
    if(!validatePortExpression(data.localPort||'Any')||!validatePortExpression(data.remotePort||'Any'))return 'Use valid local and remote ports from 1 to 65535.'
    if(data.protocol==='Any'&&((data.localPort||'Any')!=='Any'||(data.remotePort||'Any')!=='Any'))return 'Specific ports require TCP or UDP.'
    if(!validateAddressExpression(data.remoteAddress||'Any'))return 'Enter a valid remote IP address or CIDR.'
    if(node.type==='program'&&!validateProgramPath(data.program))return 'Enter an absolute Windows program path.'
    if(data.localUserSid&&(!/^S-1-\d+-\d+(?:-\d+)+$/.test(data.localUserSid)||node.type!=='deny'||data.direction!=='out'))return 'Account SID restrictions require an outbound reject rule and a valid SID.'
  }
  if(node.type==='schedule'){try{normalizeSchedule(data)}catch(error){return error.message}}
  if(node.type==='mfaGate'){try{normalizeMfaGate(data)}catch(error){return error.message}}
  return ''
}
