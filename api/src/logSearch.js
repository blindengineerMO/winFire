import crypto from 'node:crypto'
import {z} from 'zod'
import {visibleFirewallEventSql} from './processExclusions.js'

// Kept independent of the application connection for scale benchmarks and query-plan tests.
export function searchLogEvents(db,input,{hideLoopback=true}={}){
  const query=z.object({id:z.string().max(200).optional(),
    nodeId:z.string().optional(),action:z.enum(['allow','block','success','failure','logon','logoff']).optional(),direction:z.enum(['in','out']).optional(),
    program:z.string().max(1024).optional(),challengeId:z.string().max(128).optional(),
    eventId:z.coerce.number().int().min(0).optional(),protocol:z.string().max(32).optional(),srcIp:z.string().max(128).optional(),dstIp:z.string().max(128).optional(),
    port:z.coerce.number().int().min(1).max(65535).optional(),from:z.iso.datetime({local:true,offset:true}).optional(),to:z.iso.datetime({local:true,offset:true}).optional(),
    eventType:z.enum(['firewall','logon','all']).default('all'),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(500).default(100),
    pagination:z.enum(['offset','cursor']).default('offset'),cursor:z.string().min(1).max(2048).optional(),includeTotal:z.enum(['true','false']).default('true'),
    sortBy:z.enum(['time','node','eventId','action','direction','srcIp','dstIp','port','program','account']).default('time'),sortDir:z.enum(['asc','desc']).default('desc'),hideLoopback:z.enum(['true','false']).optional(),account:z.string().max(200).default('')
  }).parse(input)
  if(query.from&&query.to&&new Date(query.from)>new Date(query.to))throw Object.assign(new Error('From must be earlier than To'),{status:400})
  if(query.pagination==='cursor'&&query.sortBy!=='time')throw Object.assign(new Error('Cursor pagination requires time sorting'),{status:400})
  if(query.cursor&&query.pagination!=='cursor')throw Object.assign(new Error('Cursor requires cursor pagination'),{status:400})
  const filters=[visibleFirewallEventSql()],args=[]
  if(query.id){filters.push('e.id=?');args.push(query.id)}
  if(query.eventType==='logon')filters.push("(COALESCE(e.event_type,p.event_type)='logon' OR e.event_id IN (4624,4634))")
  if(query.eventType==='firewall')filters.push("COALESCE(e.event_type,p.event_type,'firewall')<>'logon' AND (e.event_id IS NULL OR e.event_id NOT IN (4624,4634))")
  for(const [key,column] of [['nodeId','e.node_id'],['direction','COALESCE(e.direction,p.direction)'],['challengeId','e.challenge_id'],['eventId','e.event_id'],['port','COALESCE(e.dst_port,p.dst_port)']])if(query[key]!==undefined){filters.push(`${column}=?`);args.push(query[key])}
  if(query.action){if(query.action==='logon')filters.push('e.event_id=4624');else if(query.action==='logoff')filters.push('e.event_id=4634');else{filters.push('e.action=?');args.push(query.action)}}
  for(const [key,column] of [['program','COALESCE(e.program,p.program)'],['protocol','COALESCE(e.protocol,p.protocol)'],['srcIp','COALESCE(e.src_ip,p.src_ip)'],['dstIp','COALESCE(e.dst_ip,p.dst_ip)']])if(query[key]){filters.push(`${column} LIKE ? ESCAPE '\\'`);args.push(`%${query[key].replace(/[\\%_]/g,'\\$&')}%`)}
  if(query.account.trim()){const term=`%${query.account.trim().replace(/[\\%_]/g,'\\$&')}%`;filters.push("(e.account_sid LIKE ? ESCAPE '\\' OR COALESCE(ad.sam_account_name,ad.upn,'') LIKE ? ESCAPE '\\' OR COALESCE(la.qualified_name,'') LIKE ? ESCAPE '\\' OR COALESCE(sr.qualified_name,'') LIKE ? ESCAPE '\\')");args.push(term,term,term,term)}
  if(query.from){filters.push('COALESCE(julianday(COALESCE(e.event_time,e.received_at)),0)>=julianday(?)');args.push(query.from)}
  if(query.to){filters.push('COALESCE(julianday(COALESCE(e.event_time,e.received_at)),0)<=julianday(?)');args.push(query.to)}
  query.hideLoopback=query.hideLoopback===undefined?hideLoopback:query.hideLoopback==='true'
  if(query.hideLoopback)filters.push("NOT ((COALESCE(e.src_ip,p.src_ip,'') LIKE '127.%' OR COALESCE(e.src_ip,p.src_ip,'') IN ('::1','0:0:0:0:0:0:0:1')) AND (COALESCE(e.dst_ip,p.dst_ip,'') LIKE '127.%' OR COALESCE(e.dst_ip,p.dst_ip,'') IN ('::1','0:0:0:0:0:0:0:1')))")
  const time='COALESCE(julianday(COALESCE(e.event_time,e.received_at)),0)'
  const sortColumns={time,node:'n.hostname COLLATE NOCASE',eventId:'e.event_id',action:'e.action COLLATE NOCASE',direction:'COALESCE(e.direction,p.direction) COLLATE NOCASE',srcIp:'COALESCE(e.src_ip,p.src_ip) COLLATE NOCASE',dstIp:'COALESCE(e.dst_ip,p.dst_ip) COLLATE NOCASE',port:'COALESCE(e.dst_port,p.dst_port)',program:'COALESCE(e.program,p.program) COLLATE NOCASE',account:'COALESCE(ad.sam_account_name,ad.upn,la.qualified_name,sr.qualified_name,e.account_sid) COLLATE NOCASE'}
  const accounts=`LEFT JOIN directory_users ad ON ad.sid=e.account_sid LEFT JOIN local_accounts la ON la.node_id=e.node_id AND la.sid=e.account_sid AND la.missing=0 LEFT JOIN sid_resolutions sr ON sr.node_id=e.node_id AND sr.sid=e.account_sid`
  const baseFrom=`FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id ${query.account.trim()?accounts:''}`
  const where=()=>`WHERE ${filters.join(' AND ')}`
  const total=query.includeTotal==='true'?db.prepare(`SELECT COUNT(*) count ${baseFrom} ${where()}`).get(...args).count:null
  const {cursor:_cursor,page:_page,pagination:_pagination,includeTotal:_total,...scope}=query
  const fingerprint=crypto.createHash('sha256').update(JSON.stringify(scope)).digest('base64url')
  if(query.cursor){
    let cursor
    try{cursor=JSON.parse(Buffer.from(query.cursor,'base64url').toString('utf8'))}catch{}
    if(!cursor||cursor.v!==1||cursor.scope!==fingerprint||!Number.isFinite(cursor.time)||typeof cursor.id!=='string'||!cursor.id||cursor.id.length>200)throw Object.assign(new Error('Invalid cursor or changed search filters'),{status:400})
    // SQLite does not derive a seek bound from a tuple whose first term is an
    // expression. Supply it explicitly so deep pages start at the cursor time.
    filters.push(`${time} ${query.sortDir==='asc'?'>=':'<='} ?`);args.push(cursor.time)
    filters.push(`(${time},e.id) ${query.sortDir==='asc'?'>':'<'} (?,?)`);args.push(cursor.time,cursor.id)
  }
  const direction=query.sortDir.toUpperCase(),idDirection=query.pagination==='cursor'?direction:'DESC'
  const selectionFrom=`${baseFrom} ${query.sortBy==='node'?'LEFT JOIN nodes n ON n.id=e.node_id':''} ${query.sortBy==='account'&&!query.account.trim()?accounts:''}`
  const offset=query.pagination==='cursor'?0:(query.page-1)*query.pageSize
  // Materialize only the requested IDs before fetching facts/account details.
  // In particular, never carry large snapshot_json values through a global sort.
  const sql=`WITH page AS MATERIALIZED (
    SELECT e.id,${sortColumns[query.sortBy]} sort_value ${selectionFrom} ${where()}
    ORDER BY sort_value ${direction},e.id ${idDirection} LIMIT ? OFFSET ?
  ) SELECT e.*,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,COALESCE(e.program,p.program) program,COALESCE(e.event_type,p.event_type) event_type,n.ip node_ip,f.snapshot_json node_snapshot_json,COALESCE(ad.sam_account_name,ad.upn,la.qualified_name,sr.qualified_name) account_name,page.sort_value _sort_value
    FROM page JOIN log_events e ON e.id=page.id LEFT JOIN event_patterns p ON p.id=e.pattern_id LEFT JOIN nodes n ON n.id=e.node_id LEFT JOIN node_facts f ON f.node_id=e.node_id ${accounts}
    ORDER BY page.sort_value ${direction},e.id ${idDirection}`
  const rows=db.prepare(sql).all(...args,query.pageSize+1,offset)
  const hasMore=rows.length>query.pageSize,items=rows.slice(0,query.pageSize)
  const last=items.at(-1)
  const nextCursor=query.pagination==='cursor'&&hasMore&&last?Buffer.from(JSON.stringify({v:1,scope:fingerprint,time:last._sort_value,id:last.id})).toString('base64url'):null
  return {items:items.map(({_sort_value,...item})=>item),total,page:query.page,pageSize:query.pageSize,totalPages:total===null?null:Math.ceil(total/query.pageSize),hasMore,nextCursor}
}
