import crypto from 'node:crypto'
import {canonicalIp} from '../services/networkBoundary.js'
import {db,one,all,run,id,now} from '../db.js'
import {eventSchema,batchSchema,dnsSchema,canonical,failure} from './schemas.js'
import {activeReporter,boundNode,settings} from './reporters.js'
const digest=v=>crypto.createHash('sha256').update(canonical(v)).digest('hex')
const categories=new Set(['search','research','browse','model_request','tool_call','embedding','other'])
export function queue(kind,sourceId){if(one('SELECT count(*) n FROM ai_work_queue').n>=100000){run('UPDATE ai_worker_state SET dropped=dropped+1 WHERE id=1');return false}run('INSERT OR IGNORE INTO ai_work_queue(kind,source_id,queued_at) VALUES(?,?,?)',kind,sourceId,now());return true}
function checkTime(e){const cfg=settings(),times=[e.observedAt,e.startedAt,e.endedAt].filter(Boolean).map(Date.parse);if(times.some(t=>t>Date.now()+300000))throw failure(400,'future_timestamp');if(times.some(t=>t<Date.now()-cfg.retentionDays*86400000))throw failure(400,'outside_retention');if(e.processStartedAt&&e.processStartedAt>e.observedAt)throw failure(400,'invalid_process_lifetime')}
function ingestOne(reporter,raw){
 const result=eventSchema.safeParse(raw);if(!result.success)throw failure(400,'invalid_event_schema')
 const e=result.data;checkTime(e);const nodeId=boundNode(reporter,e.nodeId),hash=digest(e)
 const prior=one('SELECT * FROM ai_receipts WHERE reporter_id=? AND event_id=?',reporter.id,e.eventId)
 if(prior){if(prior.payload_hash!==hash)throw failure(409,'conflicting_replay');return {eventId:e.eventId,status:'duplicate',receiptId:prior.id,usageId:prior.usage_id}}
 if(one('SELECT count(*) n FROM ai_work_queue').n>=100000)throw failure(503,'queue_full')
 const operationId=e.operationId||e.eventId,existing=one('SELECT * FROM ai_usage_events WHERE reporter_id=? AND operation_id=?',reporter.id,operationId)
 const values={node_id:nodeId,actor_id:reporter.actor_id,operation:categories.has(e.operation)?e.operation:'other',original_operation:categories.has(e.operation)?null:e.operation,tool:e.tool||null,provider:e.provider||null,model:e.model||null,response_model:e.responseModel||null,hostname:e.hostname||null,session_id:e.sessionId||null,trace_id:e.traceId||null,span_id:e.spanId||null,parent_span_id:e.parentSpanId||null,request_id:e.requestId||null,process_id:e.processId??null,process_guid:e.processGuid||null,process_started_at:e.processStartedAt||null}
 if(existing){
  if(existing.node_id!==nodeId||existing.actor_id!==reporter.actor_id)throw failure(409,'operation_binding_conflict')
  for(const key of Object.keys(values))if(existing[key]!=null&&values[key]!=null&&existing[key]!==values[key])throw failure(409,'operation_identity_conflict')
  if(e.phase==='start'?existing.started_receipt:existing.ended_receipt)throw failure(409,'operation_phase_conflict')
 }
 const stamp=now(),usageId=existing?.id||id(),receiptId=id(),terminal=e.phase!=='start'
 const start=e.startedAt||(e.phase==='start'||e.phase==='complete'?e.observedAt:null),end=terminal?(e.endedAt||e.observedAt):null
 const mergedStart=existing?.started_at||start,mergedEnd=existing?.ended_at||end
 if(mergedStart&&mergedEnd&&mergedStart>mergedEnd)throw failure(400,'invalid_operation_lifecycle')
 const row={id:usageId,reporter_id:reporter.id,operation_id:operationId,...values,outcome:terminal?e.outcome:existing?.outcome||'incomplete',error_code:terminal?e.errorCode||null:existing?.error_code||null,coverage:existing?.coverage||reporter.coverage,started_at:mergedStart,ended_at:mergedEnd,observed_at:mergedStart||mergedEnd||e.observedAt,received_at:existing?.received_at||stamp,duration_ms:terminal?e.durationMs??(mergedStart&&mergedEnd?Date.parse(mergedEnd)-Date.parse(mergedStart):null):existing?.duration_ms??(mergedStart&&mergedEnd?Date.parse(mergedEnd)-Date.parse(mergedStart):null),input_tokens:terminal?e.inputTokens??null:existing?.input_tokens??null,output_tokens:terminal?e.outputTokens??null:existing?.output_tokens??null,cost_amount:terminal?e.cost?.amount||null:existing?.cost_amount||null,currency:terminal?e.cost?.currency||null:existing?.currency||null,cost_source:terminal?e.cost?.source||null:existing?.cost_source||null,adapter_version:e.adapterVersion||existing?.adapter_version||null,started_receipt:e.phase==='start'||e.phase==='complete'?receiptId:existing?.started_receipt||null,ended_receipt:terminal?receiptId:existing?.ended_receipt||null}
 if(existing)for(const key of Object.keys(values))row[key]=existing[key]??values[key]
 const columns=Object.keys(row);run(`INSERT INTO ai_usage_events(${columns.join(',')}) VALUES(${columns.map(()=>'?').join(',')}) ON CONFLICT(id) DO UPDATE SET ${columns.filter(k=>k!=='id').map(k=>`${k}=excluded.${k}`).join(',')}`,...Object.values(row))
 run('INSERT INTO ai_receipts VALUES(?,?,?,?,?,?)',receiptId,reporter.id,e.eventId,hash,usageId,stamp);queue('usage',usageId)
 return {eventId:e.eventId,status:'accepted',receiptId,usageId,mapped:!!nodeId}
}
export function ingestBatch(reporterId,input){
 const {events}=batchSchema.parse(input),reporter=activeReporter(reporterId);if(!settings().enabled)throw failure(503,'collection_paused')
 return db.transaction(()=>{
  const results=events.map(raw=>{try{return db.transaction(()=>ingestOne(reporter,raw))()}catch(e){if(!Number.isInteger(e.status)&&!e.issues)throw e;return {eventId:typeof raw?.eventId==='string'&&/^[\w.:-]{1,160}$/.test(raw.eventId)?raw.eventId:null,status:'rejected',code:e.code||'invalid_event_schema',retryable:e.status===503}}})
  const counts=Object.fromEntries(['accepted','duplicate','rejected'].map(key=>[key,results.filter(r=>r.status===key).length]))
  run('UPDATE ai_reporters SET accepted=accepted+?,duplicates=duplicates+?,rejected=rejected+?,last_report_at=?,last_heartbeat_at=? WHERE id=?',counts.accepted,counts.duplicate,counts.rejected,counts.accepted?now():reporter.last_report_at,now(),reporterId)
  run('UPDATE ai_worker_state SET schema_errors=schema_errors+? WHERE id=1',results.filter(r=>r.code==='invalid_event_schema').length)
  return {schemaVersion:1,results,counts}
 }).immediate()
}
export function ingestDns(reporterId,input){
 const reporter=activeReporter(reporterId);if(!settings().enabled)throw failure(503,'collection_paused');const e=dnsSchema.parse(input);checkTime(e);const nodeId=boundNode(reporter,e.nodeId);if(!nodeId)throw failure(400,'dns_requires_node_binding');const hash=digest(e)
 return db.transaction(()=>{const prior=one('SELECT id,payload_hash FROM ai_dns_observations WHERE reporter_id=? AND event_id=?',reporterId,e.eventId);if(prior){if(prior.payload_hash!==hash)throw failure(409,'conflicting_replay');return {id:prior.id,status:'duplicate'}}
 const dnsId=id(),ttl=Math.min(e.ttlSeconds??settings().dnsWindowSeconds,settings().dnsWindowSeconds)
 run('INSERT INTO ai_dns_observations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',dnsId,reporterId,e.eventId,hash,nodeId,e.hostname,JSON.stringify(e.answers.map(canonicalIp)),e.processGuid||null,e.processId??null,e.processStartedAt||null,e.observedAt,new Date(Date.parse(e.observedAt)+ttl*1000).toISOString(),Number(e.ttlSeconds!==undefined),e.channel,e.provider)
 if(!queue('dns',dnsId))throw failure(503,'queue_full');return {id:dnsId,status:'accepted'}
 }).immediate()
}
