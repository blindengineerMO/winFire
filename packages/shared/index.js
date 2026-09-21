import { z } from 'zod'
import {validateAddressExpression,validatePortExpression,validateProgramPath} from './validation.js'
export {validateAddressExpression,validatePortExpression,validateProgramPath} from './validation.js'
export {findRuleConflicts,rulesConflict} from './conflicts.js'
export const firewallRule = z.object({
  name: z.string().min(1),
  action: z.enum(['allow', 'block']),
  direction: z.enum(['in', 'out']).default('in'),
  protocol: z.enum(['TCP', 'UDP', 'Any']).default('TCP'),
  localPort: z.string().refine(validatePortExpression,'Invalid local port expression').default('Any'),
  remotePort: z.string().refine(validatePortExpression,'Invalid remote port expression').default('Any'),
  remoteAddress: z.string().refine(validateAddressExpression,'Invalid remote address expression').default('Any'),
  program: z.string().refine(value=>value==='Any'||validateProgramPath(value),'Invalid program path').default('Any'),
  profile: z.enum(['Any', 'Domain', 'Private', 'Public']).default('Any'),
  localUserSid: z.string().regex(/^S-1-\d+-\d+(?:-\d+)+$/).nullable().default(null),
  schedule: z.object({
    days: z.array(z.number().int().min(0).max(6)).min(1),
    start: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/),
    end: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/),
    timezone: z.string().min(1).max(80)
  }).optional()
})

export const graphSchema = z.object({
  nodes: z.array(z.object({id:z.string(),type:z.string(),position:z.object({x:z.number(),y:z.number()}).optional(),data:z.record(z.string(),z.any()).default({})})),
  edges: z.array(z.object({id:z.string(),source:z.string(),target:z.string()})).default([])
})

// Merge along one match dimension at a time. Every other dimension must be
// identical, so a merged rule represents exactly the union of its inputs.
export function dedupeRules(input) {
  const matchFields=['action','direction','protocol','localPort','remotePort','remoteAddress','program','profile','group','localUserSid','schedule']
  const mergeValue=(left,right,dimension)=>{
    const parts=new Set([...String(left).split(','),...String(right).split(',')].map(value=>value.trim()).filter(Boolean))
    if(parts.has('Any'))return 'Any'
    return [...parts].sort(dimension==='remoteAddress'?(a,b)=>a.localeCompare(b):(a,b)=>Number(a)-Number(b)||a.localeCompare(b)).join(',')
  }
  let rules=input.map(rule=>({...rule}))
  let changed=true
  while(changed){
    changed=false
    for(const dimension of ['localPort','remotePort','remoteAddress']){
      const byMatch=new Map(),merged=[]
      for(const rule of rules){
        const key=JSON.stringify(matchFields.filter(field=>field!==dimension).map(field=>rule[field]))
        const existing=byMatch.get(key)
        if(existing){existing[dimension]=mergeValue(existing[dimension],rule[dimension],dimension);changed=true}
        else{byMatch.set(key,rule);merged.push(rule)}
      }
      rules=merged
    }
  }
  return rules
}

const dayNames={sun:0,sunday:0,mon:1,monday:1,tue:2,tuesday:2,wed:3,wednesday:3,thu:4,thursday:4,fri:5,friday:5,sat:6,saturday:6}
function scheduleDays(value){
  const values=Array.isArray(value)?value:String(value??'').split(',').map(item=>item.trim()).filter(Boolean)
  const days=values.map(item=>{
    if(/^\d$/.test(String(item)))return Number(item)
    return dayNames[String(item).toLowerCase()]
  })
  if(!days.length||days.some(day=>!Number.isInteger(day)||day<0||day>6))throw new Error('Schedule days must be a comma-separated list from Sunday (0) through Saturday (6)')
  return [...new Set(days)].sort((a,b)=>a-b)
}
function scheduleTime(value,label){
  const result=String(value??'').trim()
  if(!/^([01]\d|2[0-3]):[0-5]\d$/.test(result))throw new Error(`Schedule ${label} must use HH:MM (24-hour) time`)
  return result
}
export function normalizeSchedule(data={}){
  const timezone=String(data.timezone||'UTC').trim()
  try{new Intl.DateTimeFormat('en-US',{timeZone:timezone}).format()}catch{throw new Error(`Invalid schedule timezone: ${timezone}`)}
  return {days:scheduleDays(data.days??data.dayOfWeek),start:scheduleTime(data.start??data.startTime,'start'),end:scheduleTime(data.end??data.endTime,'end'),timezone}
}
export function scheduleIsActive(schedule,date=new Date()){
  if(!schedule)return true
  const normalized=normalizeSchedule(schedule)
  const parts=new Intl.DateTimeFormat('en-US',{timeZone:normalized.timezone,weekday:'short',hour:'2-digit',minute:'2-digit',hour12:false}).formatToParts(date)
  const day=dayNames[String(parts.find(part=>part.type==='weekday')?.value||'').toLowerCase()]
  const hour=Number(parts.find(part=>part.type==='hour')?.value||0)%24
  const minute=Number(parts.find(part=>part.type==='minute')?.value||0)
  const current=hour*60+minute,start=Number(normalized.start.slice(0,2))*60+Number(normalized.start.slice(3)),end=Number(normalized.end.slice(0,2))*60+Number(normalized.end.slice(3))
  if(start===end)return normalized.days.includes(day)
  if(start<end)return normalized.days.includes(day)&&current>=start&&current<end
  return current>=start?normalized.days.includes(day):current<end&&normalized.days.includes((day+6)%7)
}
export function activePolicyRules(rules,date=new Date()){return (rules||[]).filter(rule=>scheduleIsActive(rule.schedule,date))}
export function scheduleStateKey(rules,date=new Date()){
  return JSON.stringify((rules||[]).filter(rule=>rule.schedule).map(rule=>[rule.sourceNodeId||rule.name,scheduleIsActive(rule.schedule,date)]).sort((left,right)=>String(left[0]).localeCompare(String(right[0]))))
}

export function compilePolicy(graph, policyId) {
  const doc = graphSchema.parse(graph)
  const supportedTypes=new Set(['allow','deny','program','portGroup','addressGroup','profile','schedule','mfaGate'])
  for(const node of doc.nodes)if(!supportedTypes.has(node.type))throw new Error(`Unsupported policy node type: ${node.type}`)
  for(const node of doc.nodes){
    if(node.type==='portGroup'&&!validatePortExpression(node.data.ports))throw new Error(`Invalid port group: ${node.data.name||node.id}`)
    if(node.type==='addressGroup'&&!validateAddressExpression(node.data.addresses))throw new Error(`Invalid address group: ${node.data.name||node.id}`)
    if(node.type==='profile'&&!['Any','Domain','Private','Public'].includes(node.data.profile))throw new Error(`Invalid profile scope: ${node.data.name||node.id}`)
  }
  const byId = new Map(doc.nodes.map(n => [n.id, n]))
  if(byId.size!==doc.nodes.length)throw new Error('Policy graph contains duplicate node IDs')
  const groups = new Map(doc.nodes.map(n => [n.id, new Set()]))
  for (const edge of doc.edges) {
    if (!byId.has(edge.source) || !byId.has(edge.target)) throw new Error('Edge references a missing node')
    groups.get(edge.target).add(edge.source)
  }
  const visiting = new Set(), visited = new Set(), order = []
  function visit(id) {
    if (visiting.has(id)) throw new Error('Policy graph contains a cycle')
    if (visited.has(id)) return
    visiting.add(id)
    for (const parent of groups.get(id)) visit(parent)
    visiting.delete(id); visited.add(id); order.push(byId.get(id))
  }
  for (const node of doc.nodes) visit(node.id)
  const rules = []
  for (const node of order) {
    if (node.type === 'schedule') {
      try { normalizeSchedule(node.data) } catch(error) { throw new Error(`Invalid schedule node ${node.data.name||node.id}: ${error.message}`) }
      continue
    }
    if (node.type === 'mfaGate') throw new Error('MFA Gate nodes require an enrolled agent or configured Entra integration')
    if (!['allow', 'deny', 'program'].includes(node.type)) continue
    if(node.type==='program'&&!validateProgramPath(node.data.program))throw new Error(`Program rule requires an absolute Windows program path: ${node.data.name||node.id}`)
    const ancestorIds = new Set()
    function collectParents(id) { for (const parent of groups.get(id)) { if (!ancestorIds.has(parent)) { ancestorIds.add(parent); collectParents(parent) } } }
    collectParents(node.id)
    const ancestors = [...ancestorIds].map(id => byId.get(id)).filter(Boolean)
    const scheduleAncestors=ancestors.filter(ancestor=>ancestor.type==='schedule')
    if(scheduleAncestors.length>1)throw new Error(`Rule ${node.data.name||node.id} cannot have more than one schedule window`)
    const data = {...node.data}
    for (const ancestor of ancestors) {
      if (ancestor.type === 'portGroup') {
        const field=data.direction==='out'?'remotePort':'localPort'
        if(!data[field]||data[field]==='Any')data[field]=ancestor.data.ports
      }
      if (ancestor.type === 'addressGroup' && (!data.remoteAddress || data.remoteAddress === 'Any')) data.remoteAddress = ancestor.data.addresses
      if (ancestor.type === 'profile' && (!data.profile || data.profile === 'Any')) data.profile = ancestor.data.profile
    }
    const rule = firewallRule.parse({
      name: `${data.name || node.type} [${node.id.slice(0,8)}]`,
      action: node.type === 'deny' ? 'block' : 'allow',
      direction: data.direction || 'in', protocol: data.protocol || 'TCP',
      localPort: String(data.localPort || 'Any'), remotePort:String(data.remotePort||'Any'),remoteAddress: data.remoteAddress || 'Any',
      program: node.type === 'program' ? data.program : data.program || 'Any',
      profile: data.profile || 'Any',localUserSid:data.localUserSid||null,
      schedule:scheduleAncestors.length?normalizeSchedule(scheduleAncestors[0].data):undefined
    })
    if(rule.localUserSid&&(rule.direction!=='out'||rule.action!=='block'))throw new Error('Local account rules must be outbound block rules on the account source node')
    if(rule.protocol==='Any'&&(rule.localPort!=='Any'||rule.remotePort!=='Any'))throw new Error('Specific ports require TCP or UDP protocol')
    rules.push({...rule, group: `WinFireSecure:${policyId}`, sourceNodeId:node.id})
  }
  return dedupeRules(rules)
}
