import {z} from 'zod'
import {db,all,one,run,now} from '../db.js'
import {visibleFirewallEventSql} from '../processExclusions.js'
import {trafficIgnoreFromEvent} from '../trafficIgnores.js'
import {boundaryState,canonicalIp,inLocalCidrs,outsideLocal,addressCategory,subnetMatcher} from './networkBoundary.js'
import {normalizeNetworkProtocol} from './networkMapping.js'
import {retainPeer,publicPeer} from './internetPeers.js'

const port=v=>v!==null&&v!==''&&Number.isInteger(Number(v))&&+v>=0&&+v<=65535?+v:null
const protocol=normalizeNetworkProtocol
export function connectionEndpoints(event,node,cidrs){
  let direction=({inbound:'in',outbound:'out','%%14592':'in','%%14593':'out'})[event.direction]||event.direction
  if(!['in','out'].includes(direction))direction='unknown'
  let source=canonicalIp(event.src_ip)||(direction==='out'?canonicalIp(node.ip):null),destination=canonicalIp(event.dst_ip)||(direction==='in'?canonicalIp(node.ip):null)
  let sourcePort=port(event.src_port),destinationPort=port(event.dst_port)
  const own=new Set([canonicalIp(node.ip)])
  let facts={};try{facts=JSON.parse(node.snapshot_json||'{}')}catch{}
  for(const adapter of (Array.isArray(facts.adapters)?facts.adapters:Array.isArray(facts.networkAdapters)?facts.networkAdapters:[]))for(const ip of (Array.isArray(adapter.ipAddresses)?adapter.ipAddresses:[]))own.add(canonicalIp(ip))
  const sourceOwn=!!source&&own.has(source),destinationOwn=!!destination&&own.has(destination)
  let local=null,peer=null,attribution='ambiguous'
  if(sourceOwn!==destinationOwn){
    if(sourceOwn&&direction==='in'&&[5150,5151,5156,5157].includes(event.event_id)){
      [source,destination]=[destination,source];[sourcePort,destinationPort]=[destinationPort,sourcePort]
      local=destination;peer=source;attribution='legacy-inbound-corrected'
    }else{local=sourceOwn?source:destination;peer=sourceOwn?destination:source;direction=sourceOwn?'out':'in';attribution='reporting-node-address'}
  }else if(source&&destination){
    const localSource=inLocalCidrs(source,cidrs),localDestination=inLocalCidrs(destination,cidrs)
    const collector=['switch','router','firewall'].includes(node.device_type)||node.transport==='snmp'
    if(localSource!==localDestination){local=localSource?source:destination;peer=localSource?destination:source;direction=localSource?'out':'in';attribution=collector?'forwarded-local-endpoint':'cidr-endpoint'}
    else if(direction!=='unknown'&&!collector){local=direction==='out'?source:destination;peer=direction==='out'?destination:source;attribution='reported-direction-roaming'}
    else {peer=direction==='in'?source:destination;direction='unknown'}
  }
  const category=addressCategory(peer,cidrs)
  return {source,destination,sourcePort,destinationPort,local,peer,direction,attribution,category,outside:Number(outsideLocal(peer,cidrs))}
}
const eventSelect=`SELECT e.*,COALESCE(e.action,p.action) action,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,COALESCE(e.program,p.program) program,COALESCE(e.event_type,p.event_type) event_type FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id`
function project(event,revision,cidrs,nodes){
  if(!event)return
  if(![5150,5151,5156,5157].includes(event.event_id)&&event.event_type!=='firewall'){run('DELETE FROM internet_connections WHERE event_id=? AND revision=?',event.id,revision);return}
  const node=nodes.get(event.node_id)||{},endpoint=connectionEndpoints(event,node,cidrs)
  if(!endpoint.source||!endpoint.destination){run('DELETE FROM internet_connections WHERE event_id=? AND revision=?',event.id,revision);return}
  const eventAt=Date.parse(event.event_time||''),receivedAt=Date.parse(event.received_at||'');const observed=new Date(Number.isFinite(eventAt)?eventAt:Number.isFinite(receivedAt)?receivedAt:Date.now()).toISOString()
  const prior=one('SELECT original_revision,original_scope FROM internet_connections WHERE event_id=? ORDER BY revision LIMIT 1',event.id)
  const peerId=endpoint.outside?retainPeer(endpoint.peer,observed):null
  run(`INSERT INTO internet_connections(event_id,revision,original_revision,original_scope,node_id,observed_at,source_ip,destination_ip,source_port,destination_port,local_ip,peer_ip,peer_id,direction,attribution,action,protocol,program,category,outside) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(revision,event_id) DO UPDATE SET node_id=excluded.node_id,observed_at=excluded.observed_at,source_ip=excluded.source_ip,destination_ip=excluded.destination_ip,source_port=excluded.source_port,destination_port=excluded.destination_port,local_ip=excluded.local_ip,peer_ip=excluded.peer_ip,peer_id=excluded.peer_id,direction=excluded.direction,attribution=excluded.attribution,action=excluded.action,protocol=excluded.protocol,program=excluded.program,category=excluded.category,outside=excluded.outside`,event.id,revision,prior?.original_revision||revision,prior?.original_scope||(endpoint.outside?'outside':'not-outside'),event.node_id,observed,endpoint.source,endpoint.destination,endpoint.sourcePort,endpoint.destinationPort,endpoint.local,endpoint.peer,peerId,endpoint.direction,endpoint.attribution,event.action,protocol(event.protocol),event.program,endpoint.category,endpoint.outside)
}
export function processInternetIndex({limit=1000}={}){
  const state=boundaryState()
  if(!state.pending&&!one('SELECT event_id FROM internet_event_queue LIMIT 1')&&!one('SELECT event_id FROM internet_connections WHERE revision<>? LIMIT 1',state.active_revision))return {processed:0,pending:false}
  const nodes=new Map(all("SELECT n.id,n.ip,n.device_type,n.transport,CASE WHEN json_valid(f.snapshot_json) THEN json_object('adapters',COALESCE(json_extract(f.snapshot_json,'$.adapters'),json_extract(f.snapshot_json,'$.networkAdapters'),json('[]'))) ELSE '{}' END snapshot_json FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id").map(n=>[n.id,n]))
  return db.transaction(()=>{
    const current=one('SELECT * FROM internet_index_state WHERE id=1')
    if(current.desired_revision!==state.desired_revision)return {processed:0,pending:true}
    const queued=all(`SELECT q.event_id FROM internet_event_queue q LIMIT ?`,limit)
    for(const q of queued){const event=one(eventSelect+' WHERE e.id=?',q.event_id);if(current.active_revision)project(event,current.active_revision,state.effectiveCidrs,nodes);if(current.desired_revision!==current.active_revision)project(event,current.desired_revision,state.cidrs,nodes);run('DELETE FROM internet_event_queue WHERE event_id=?',q.event_id)}
    let count=0
    if(current.active_revision!==current.desired_revision){
      const events=all(eventSelect+' WHERE e.rowid>? AND e.rowid<=? ORDER BY e.rowid LIMIT ?',current.cursor,current.high_water,limit)
      for(const e of events)project(e,current.desired_revision,state.cidrs,nodes)
      count=events.length
      if(count){const cursor=one('SELECT rowid n FROM log_events WHERE id=?',events.at(-1).id).n;run('UPDATE internet_index_state SET cursor=?,updated_at=? WHERE id=1',cursor,now())}
      // New and corrected events must reach the candidate revision before publishing it.
      if(count<limit&&!one('SELECT event_id FROM internet_event_queue LIMIT 1'))run('UPDATE internet_index_state SET active_revision=desired_revision,cursor=high_water,updated_at=? WHERE id=1',now())
    }
    run('DELETE FROM internet_connections WHERE rowid IN (SELECT rowid FROM internet_connections WHERE revision NOT IN (SELECT active_revision FROM internet_index_state UNION SELECT desired_revision FROM internet_index_state) LIMIT ?)',limit)
    return {processed:count+queued.length,pending:one('SELECT active_revision IS NOT desired_revision pending FROM internet_index_state WHERE id=1').pending===1}
  }).immediate()
}
export const connectionQuery=z.object({
  q:z.string().trim().max(200).default(''),nodeId:z.string().max(200).optional(),groupId:z.string().max(200).optional(),ip:z.string().max(64).refine(v=>v.includes('/')?(()=>{try{subnetMatcher(v);return true}catch{return false}})():!!canonicalIp(v),'Enter a valid peer IP or CIDR').optional(),hostname:z.string().trim().max(253).optional(),program:z.string().max(1024).optional(),protocol:z.string().max(32).optional(),port:z.coerce.number().int().min(1).max(65535).optional(),direction:z.enum(['out','in','unknown','all']).default('out'),action:z.enum(['allow','block']).optional(),dnsState:z.enum(['pending','resolved','not-found','error','stale']).optional(),from:z.iso.datetime({offset:true}).optional(),to:z.iso.datetime({offset:true}).optional(),page:z.coerce.number().int().min(1).default(1),limit:z.coerce.number().int().min(1).max(100).default(25),sort:z.enum(['time','node','peer','hostname','program','protocol','port','action','direction']).default('time'),order:z.enum(['asc','desc']).default('desc')
}).refine(q=>!q.from||!q.to||Date.parse(q.from)<=Date.parse(q.to),{message:'From must be before To'})
function selection(input){
  const query=connectionQuery.parse(input),state=boundaryState(),clauses=['c.revision=?','c.outside=1',visibleFirewallEventSql()],args=[state.active_revision||0]
  for(const [key,column] of [['nodeId','c.node_id'],['action','c.action'],['port','c.destination_port']])if(query[key]!==undefined){clauses.push(`${column}=?`);args.push(query[key])}
  if(query.direction!=='all'){clauses.push('c.direction=?');args.push(query.direction)}
  if(query.protocol){clauses.push('c.protocol=?');args.push(protocol(query.protocol))}
  if(query.groupId){clauses.push('EXISTS(SELECT 1 FROM node_group_members gm WHERE gm.node_id=c.node_id AND gm.group_id=?)');args.push(query.groupId)}
  if(query.ip){clauses.push(query.ip.includes('/')?'winfire_subnet(c.peer_ip,?)=1':'c.peer_ip=?');args.push(query.ip.includes('/')?query.ip:canonicalIp(query.ip))}
  const like=(column,value)=>{clauses.push(`${column} LIKE ? ESCAPE '\\'`);args.push('%'+value.replace(/[\\%_]/g,'\\$&')+'%')}
  if(query.hostname)like('d.names_json',query.hostname)
  if(query.program)like('c.program',query.program)
  if(query.q){const term='%'+query.q.replace(/[\\%_]/g,'\\$&')+'%';clauses.push("(n.hostname LIKE ? ESCAPE '\\' OR c.local_ip LIKE ? ESCAPE '\\' OR c.peer_ip LIKE ? ESCAPE '\\' OR d.names_json LIKE ? ESCAPE '\\' OR c.program LIKE ? ESCAPE '\\')");args.push(...Array(5).fill(term))}
  if(query.from){clauses.push('c.observed_at>=?');args.push(new Date(query.from).toISOString())}
  if(query.to){clauses.push('c.observed_at<=?');args.push(new Date(query.to).toISOString())}
  if(query.dnsState){clauses.push("(CASE WHEN d.names_json<>'[]' AND (d.status='stale' OR d.next_lookup_at<=?) THEN 'stale' ELSE d.status END)=?");args.push(now(),query.dnsState)}
  return {query,state,args,from:`FROM internet_connections c JOIN log_events e ON e.id=c.event_id LEFT JOIN event_patterns p ON p.id=e.pattern_id LEFT JOIN nodes n ON n.id=c.node_id LEFT JOIN internet_peers d ON d.id=c.peer_id WHERE ${clauses.join(' AND ')}`}
}
const scope=s=>({revision:s.active_revision,desiredRevision:s.desired_revision,pending:s.pending,cursor:s.cursor,highWater:s.high_water,cidrs:s.effectiveCidrs,configuredCidrs:s.cidrs,configurationNeeded:s.configurationNeeded,missingFamilies:s.missingFamilies})
const summary=s=>({...one(`SELECT count(*) events,count(DISTINCT c.peer_ip) peers,COALESCE(sum(c.action='allow'),0) allowed,COALESCE(sum(c.action='block'),0) blocked ${s.from}`,...s.args),scope:scope(s.state)})
export const connectionSummary=input=>summary(selection(input))
const rowSelect=`SELECT c.*,n.hostname AS node_hostname,e.event_id AS windows_event_id,d.names_json,d.status AS dns_status,d.checked_at AS dns_checked_at,d.next_lookup_at AS dns_next_lookup_at,d.error AS dns_error`
const publicConnection=({names_json,dns_next_lookup_at,...row})=>({...row,id:row.event_id,ptrNames:JSON.parse(names_json||'[]'),hostnameSource:'reverse-dns',dnsStale:row.dns_status==='stale'||!!row.dns_checked_at&&Date.parse(dns_next_lookup_at)<=Date.now(),observation:row.action==='block'?'Blocked attempt':row.action==='allow'?'Allowed observation':'Connection observation',provenance:'firewall-event',activitiesUrl:`/logs?event=${encodeURIComponent(row.event_id)}`,mappingUrl:`/mapping?nodeId=${encodeURIComponent(row.node_id||'')}`})
export function listConnections(input){
  const s=selection(input),stats=summary(s),page=Math.min(s.query.page,Math.max(1,Math.ceil(stats.events/s.query.limit)))
  const sort={time:'c.observed_at',node:'n.hostname',peer:'c.peer_ip',hostname:'d.names_json',program:'c.program',protocol:'c.protocol',port:'c.destination_port',action:'c.action',direction:'c.direction'}[s.query.sort]
  const items=all(`${rowSelect} ${s.from} ORDER BY ${sort} ${s.query.order},c.event_id LIMIT ? OFFSET ?`,...s.args,s.query.limit,(page-1)*s.query.limit).map(publicConnection)
  return {items,total:stats.events,page,limit:s.query.limit,pages:Math.max(1,Math.ceil(stats.events/s.query.limit)),summary:stats}
}
export function connectionDetails(eventId){
  const s=selection({direction:'all'}),row=one(`${rowSelect} ${s.from} AND c.event_id=?`,...s.args,eventId)
  if(!row)throw Object.assign(new Error('Internet connection not found'),{status:404})
  const event=one(eventSelect+' WHERE e.id=?',eventId),peer=publicPeer(one('SELECT * FROM internet_peers WHERE id=?',row.peer_id))
  const ruleEligible=['reporting-node-address','reported-direction-roaming'].includes(row.attribution)&&['in','out'].includes(row.direction)&&['TCP','UDP'].includes(row.protocol)&&row.destination_port>0&&event.direction===row.direction
  let ignoreEligible=false;try{trafficIgnoreFromEvent(event);ignoreEligible=true}catch{}
  return {...publicConnection(row),scope:scope(s.state),peer,event,observedNames:[],ruleEligible,ignoreEligible,mappingReferences:all('SELECT map_key FROM network_map_pairs WHERE source_ip=? AND destination_ip=? AND protocol=? LIMIT 20',row.source_ip,row.destination_ip,row.protocol).map(x=>x.map_key)}
}
export function exportConnections(input){
  return db.transaction(()=>{
    const s=selection(input),stats=summary(s)
    if(stats.events>10000)throw Object.assign(new Error('Narrow filters to at most 10,000 observations for export'),{status:400})
    const sort={time:'c.observed_at',node:'n.hostname',peer:'c.peer_ip',hostname:'d.names_json',program:'c.program',protocol:'c.protocol',port:'c.destination_port',action:'c.action',direction:'c.direction'}[s.query.sort]
    return {scope:stats.scope,total:stats.events,items:all(`${rowSelect} ${s.from} ORDER BY ${sort} ${s.query.order},c.event_id LIMIT 10000`,...s.args).map(publicConnection)}
  })()
}
