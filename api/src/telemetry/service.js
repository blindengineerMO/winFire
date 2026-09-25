import {createHash} from 'node:crypto'
import {z} from 'zod'
import {db,one,all,run,id,now,json,audit} from '../db.js'
import {canonicalIp,isLocalAssetNode} from '../services/networkBoundary.js'
import {recordNetworkFlow} from '../services/networkMapping.js'
import {capabilityEvidence} from '../services/capabilities.js'
import {FlowDecoder,decodeSyslog} from './decoders.js'
const fail=(message,status=400)=>{throw Object.assign(new Error(message),{status})}
const hash=value=>createHash('sha256').update(value).digest('hex')
export const exporterSchema=z.object({name:z.string().trim().min(1).max(120),nodeId:z.string().max(200),format:z.enum(['netflow-v9','ipfix-v10','pf-filterlog','mikrotik-firewall','sonicwall-kv','azure-vnet']),sourceIp:z.string().refine(v=>!v||!!canonicalIp(v)).default(''),tlsFingerprint:z.string().regex(/^(?:[A-Fa-f0-9]{64})?$/).default(''),enabled:z.boolean().default(false)}).strict()
export const exporters=()=>all('SELECT e.*,n.hostname FROM telemetry_exporters e JOIN nodes n ON n.id=e.node_id ORDER BY e.name').map(e=>({...e,enabled:!!e.enabled}))
export function saveExporter(input,actor,key=null){const q=exporterSchema.parse(input),node=one('SELECT * FROM nodes WHERE id=?',q.nodeId);if(!node||!isLocalAssetNode(node))fail('Choose an existing asset in a configured local scope');const previous=key?one('SELECT * FROM telemetry_exporters WHERE id=?',key):null;if(key&&!previous)fail('Exporter not found',404);key||=id();if(previous&&(previous.node_id!==q.nodeId||previous.format!==q.format))fail('Create a new exporter to change its asset or format; existing provenance is retained',409);if(one('SELECT id FROM telemetry_exporters WHERE source_ip=? AND format=? AND id<>?',q.sourceIp||null,q.format,key))fail('An exporter with that source address and format already exists',409)
 run('INSERT INTO telemetry_exporters(id,name,node_id,format,source_ip,tls_fingerprint,enabled,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,source_ip=excluded.source_ip,tls_fingerprint=excluded.tls_fingerprint,enabled=excluded.enabled',key,q.name,q.nodeId,q.format,q.sourceIp?canonicalIp(q.sourceIp):null,q.tlsFingerprint.toLowerCase()||null,Number(q.enabled),now());audit(actor,'telemetry.exporter.save','telemetry-exporter',key,previous,q);return exporters().find(e=>e.id===key)}
export function getExporter(key){const e=one('SELECT * FROM telemetry_exporters WHERE id=?',key);if(!e)fail('Exporter not found',404);if(!e.enabled)fail('Exporter is disabled',409);return e}
export function saveObservations(exporter,records,captureKey){
 if(records.length>10000)fail('At most 10,000 observations per batch',413)
 const node=one('SELECT * FROM nodes WHERE id=?',exporter.node_id);if(!node||!isLocalAssetNode(node))fail('Exporter asset is no longer eligible in its network scope',409)
 let accepted=0,duplicates=0
 return db.transaction(()=>{
  for(let index=0;index<records.length;index++){
   const record=records[index],key=record.captureKey||`${captureKey}:${index}`
   if(one('SELECT id FROM traffic_observations WHERE exporter_id=? AND capture_key=?',exporter.id,key)){duplicates++;continue}
   const source=canonicalIp(record.srcIp),destination=canonicalIp(record.dstIp);if(!source||!destination)fail('Invalid observation endpoints')
   for(const p of [record.srcPort,record.dstPort])if(p!=null&&(!Number.isInteger(p)||p<0||p>65535))fail('Invalid observation port')
   const eventTime=new Date(record.eventTime).toISOString(),eventId=id(),action=['allow','block'].includes(record.action)?record.action:null,direction=['in','out'].includes(record.direction)?record.direction:null
   run('INSERT INTO log_events(id,node_id,event_id,event_type,action,protocol,src_ip,src_port,dst_ip,dst_port,direction,event_time,received_at) VALUES(?,?,NULL,?,?,?,?,?,?,?,?,?,?)',eventId,node.id,'firewall',action,record.protocol||null,source,record.srcPort??null,destination,record.dstPort??null,direction,eventTime,now())
   run('INSERT INTO traffic_observations(id,exporter_id,event_id,capture_key,metadata_json,observed_at,received_at) VALUES(?,?,?,?,?,?,?)',id(),exporter.id,eventId,key,json({...record.metadata,exporterId:exporter.id,scopeId:node.scope_id,observationKind:exporter.format==='azure-vnet'?'cloud-flow':'network-device',verdictSupplied:action!==null}),eventTime,now())
   recordNetworkFlow(node.id,{srcIp:source,dstIp:destination,srcPort:record.srcPort,dstPort:record.dstPort,protocol:record.protocol,eventType:'firewall',action,direction,eventTime},eventTime);accepted++
  }
  run('UPDATE telemetry_exporters SET accepted=accepted+?,duplicates=duplicates+?,last_seen_at=?,last_error=NULL WHERE id=?',accepted,duplicates,now(),exporter.id)
  if(accepted)capabilityEvidence(node.id,'flows',exporter.format,{detail:{exporterId:exporter.id,observationOnly:true,verdictComplete:false}})
  return {accepted,duplicates}
 })()
}
export const decoder=new FlowDecoder()
export function ingestDatagram(key,packet){
 const e=getExporter(key);if(!['netflow-v9','ipfix-v10'].includes(e.format))fail('Exporter is not enrolled for binary flows')
 try{
  const expected=e.format==='netflow-v9'?9:10;if(packet.length<2||packet.readUInt16BE()!==expected)fail('Flow protocol does not match enrollment')
  return decoder.decode(packet,e.id,{accept:result=>db.transaction(()=>{
   run('UPDATE telemetry_exporters SET missing_templates=missing_templates+? WHERE id=?',result.missingTemplates,e.id)
   if(result.duplicate){run('UPDATE telemetry_exporters SET duplicates=duplicates+1 WHERE id=?',e.id);return {...result,accepted:0}}
   return {...result,records:undefined,...saveObservations(e,result.records,hash(packet))}
  })()})
 }catch(error){recordRejected(e.id,error);throw error}
}
export function recordRejected(key,error){run('UPDATE telemetry_exporters SET rejected=rejected+1,last_error=? WHERE id=?',String(error.message).slice(0,300),key)}
export function importSyslog(key,input,actor){const q=z.object({captureKey:z.string().min(1).max(300),lines:z.array(z.string().max(16384)).min(1).max(10000)}).strict().parse(input),e=getExporter(key),contentHash=hash(json(q.lines)),previous=one('SELECT * FROM traffic_imports WHERE exporter_id=? AND capture_key=?',key,q.captureKey);if(previous){if(previous.content_hash!==contentHash)fail('This capture key already identifies different content',409);return {accepted:0,duplicates:previous.accepted}}
 try{const records=q.lines.map(line=>decodeSyslog(line,e.format));return db.transaction(()=>{const result=saveObservations(e,records,q.captureKey);run('INSERT INTO traffic_imports(exporter_id,capture_key,content_hash,accepted,created_at) VALUES(?,?,?,?,?)',key,q.captureKey,contentHash,result.accepted,now());audit(actor,'telemetry.import','telemetry-exporter',key,null,{captureKey:q.captureKey,...result});return result})()}catch(error){recordRejected(key,error);throw error}}
export function observationRows(input={}){const q=z.object({exporterId:z.string().optional(),q:z.string().max(200).default(''),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(250).default(25)}).parse(input),args=[],where=[];if(q.exporterId){where.push('o.exporter_id=?');args.push(q.exporterId)}if(q.q){where.push('(COALESCE(e.src_ip,p.src_ip) LIKE ? OR COALESCE(e.dst_ip,p.dst_ip) LIKE ? OR x.name LIKE ?)');args.push(...Array(3).fill('%'+q.q+'%'))}const from='FROM traffic_observations o JOIN telemetry_exporters x ON x.id=o.exporter_id LEFT JOIN log_events e ON e.id=o.event_id LEFT JOIN event_patterns p ON p.id=e.pattern_id'+(where.length?' WHERE '+where.join(' AND '):'');return {items:all('SELECT o.*,x.name exporter_name,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.action,p.action) action '+from+' ORDER BY o.observed_at DESC,o.id LIMIT ? OFFSET ?',...args,q.pageSize,(q.page-1)*q.pageSize).map(r=>({...r,metadata:JSON.parse(r.metadata_json),metadata_json:undefined})),total:one('SELECT count(*) n '+from,...args).n,page:q.page,pageSize:q.pageSize}}

export function pruneTelemetry(){
 const days=Math.max(1,Math.min(3650,Number(one("SELECT value FROM app_settings WHERE key='log_retention_days'")?.value)||90)),cutoff=new Date(Date.now()-days*86400000).toISOString()
 const observations=run('DELETE FROM traffic_observations WHERE rowid IN (SELECT rowid FROM traffic_observations WHERE received_at<? LIMIT 1000)',cutoff).changes
 const imports=run('DELETE FROM traffic_imports WHERE rowid IN (SELECT rowid FROM traffic_imports WHERE created_at<? LIMIT 1000)',cutoff).changes
 return {days,observations,imports}
}
