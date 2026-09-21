import express from 'express'
import crypto from 'node:crypto'
import {rateLimit} from 'express-rate-limit'
import {z} from 'zod'
import {db,all,one,run,id,now,audit,json,parse} from './db.js'
import {auth,hashToken,requireRole} from './security.js'

export const internetRoutes=express.Router()
const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next)
const internetEnrollLimit=rateLimit({windowMs:15*60*1000,limit:20,standardHeaders:'draft-8',legacyHeaders:false})
const internetIngestLimit=rateLimit({windowMs:60*1000,limit:120,standardHeaders:'draft-8',legacyHeaders:false})
const browserSchema=z.enum(['chrome','edge','firefox'])
const collectionSchema=z.enum(['host','path']).default('host')
const internetRuleSchema=z.object({pattern:z.string().trim().min(1).max(500),match:z.enum(['hostname','domain','prefix']).default('hostname'),action:z.enum(['allow','block']),nodeIds:z.array(z.string().min(1)).max(500).default([]),nodeGroupIds:z.array(z.string().min(1)).max(500).default([]),resourceTypes:z.array(z.enum(['main_frame','sub_frame','script','image','stylesheet','font','object','xmlhttprequest','other'])).min(1).max(20).default(['main_frame'])})
const publicBase=req=>String(process.env.PUBLIC_BASE_URL||`${req.protocol}://${req.get('host')}`).replace(/\/$/,'')

function registrableDomain(hostname){
  const labels=String(hostname).split('.').filter(Boolean)
  return labels.length>2?labels.slice(-2).join('.'):labels.join('.')
}

function normalizeUrl(raw,collectionLevel){
  let parsed
  try{parsed=new URL(raw)}catch{throw Object.assign(new Error('Internet events require a valid URL'),{status:400})}
  if(!['http:','https:'].includes(parsed.protocol))throw Object.assign(new Error('Only HTTP and HTTPS navigations are collected'),{status:400})
  const hostname=parsed.hostname.toLowerCase().replace(/\.$/,'')
  if(!hostname||hostname.length>253)throw Object.assign(new Error('Navigation hostname is invalid'),{status:400})
  let pathPrefix=null
  if(collectionLevel==='path'){
    const pathname=parsed.pathname||'/'
    pathPrefix=pathname.length>240?pathname.slice(0,240):pathname
    if(!pathPrefix.startsWith('/'))pathPrefix='/'+pathPrefix
  }
  const scheme=parsed.protocol.slice(0,-1)
  const registrable=registrableDomain(hostname)
  const fingerprint=crypto.createHash('sha256').update([scheme,hostname,pathPrefix||''].join('\0')).digest('hex')
  return {scheme,hostname,registrableDomain:registrable,pathPrefix,fingerprint}
}

function publicDevice(row){
  return {id:row.id,nodeId:row.node_id||null,nodeGroupId:row.node_group_id||null,userId:row.user_id||null,browser:row.browser,extensionVersion:row.extension_version,status:row.status,capabilities:parse(row.capabilities_json)||{},lastSeenAt:row.last_seen_at,enrolledAt:row.enrolled_at,revokedAt:row.revoked_at||null}
}

function requireDevice(req,res,next){
  const token=req.headers.authorization?.replace(/^Bearer\s+/i,'')||req.headers['x-winfire-device-token']
  if(!token)return res.status(401).json({error:'Extension device credential required'})
  const device=one('SELECT * FROM internet_extension_devices WHERE token_hash=? AND status=? AND revoked_at IS NULL',hashToken(String(token)),'active')
  if(!device)return res.status(401).json({error:'Extension device credential is invalid or revoked'})
  req.internetDevice=device
  next()
}

function policySignature(payload){
  return crypto.createHmac('sha256',process.env.INTERNET_POLICY_SIGNING_SECRET||process.env.JWT_SECRET||'winfire-internet-policy').update(JSON.stringify(payload)).digest('hex')
}

function scopedForDevice(rule,device){
  const nodeIds=rule.nodeIds||[],groupIds=rule.nodeGroupIds||[]
  if(!nodeIds.length&&!groupIds.length)return true
  if(device.node_id&&nodeIds.includes(device.node_id))return true
  if(device.node_id&&groupIds.length&&all('SELECT group_id FROM node_group_members WHERE node_id=?',device.node_id).some(item=>groupIds.includes(item.group_id)))return true
  return false
}

function compileInternetRules(rules){
  return rules.map((rule,index)=>{
    // declarativeNetRequest uses its own URL-filter grammar; a literal dot is
    // already treated as a literal and must not be converted to a regex escape.
    const pattern=rule.pattern.replace(/[\r\n]/g,'')
    const urlFilter=rule.match==='domain'?`||${pattern}`:rule.match==='prefix'?pattern:`||${pattern}^`
    return {id:index+1,priority:100000-index,action:{type:rule.action},condition:{urlFilter,resourceTypes:rule.resourceTypes||['main_frame']}}
  })
}

function deduplicateRules(rules){
  const seen=new Map()
  for(const rule of rules){
    const normalized={...rule,pattern:rule.pattern.toLowerCase().replace(/\/+$/,'')||'/',nodeIds:[...new Set(rule.nodeIds||[])].sort(),nodeGroupIds:[...new Set(rule.nodeGroupIds||[])].sort(),resourceTypes:[...new Set(rule.resourceTypes||['main_frame'])].sort()}
    const key=JSON.stringify([normalized.pattern,normalized.match,normalized.action,normalized.nodeIds,normalized.nodeGroupIds,normalized.resourceTypes])
    if(!seen.has(key))seen.set(key,normalized)
  }
  return [...seen.values()]
}

internetRoutes.post('/enrollment',auth,requireRole('editor'),wrap(async(req,res)=>{
  const data=z.object({nodeId:z.string().min(1).optional(),nodeGroupId:z.string().min(1).optional(),collectionLevel:collectionSchema}).refine(value=>Number(!!value.nodeId)+Number(!!value.nodeGroupId)===1,{message:'Choose exactly one node or node group'}).parse(req.body)
  const node=data.nodeId?one('SELECT id,hostname FROM nodes WHERE id=?',data.nodeId):null
  const group=data.nodeGroupId?one('SELECT id,name FROM node_groups WHERE id=?',data.nodeGroupId):null
  if(data.nodeId&&!node)return res.status(404).json({error:'Node not found'})
  if(data.nodeGroupId&&!group)return res.status(404).json({error:'Node group not found'})
  const raw=crypto.randomBytes(32).toString('base64url'),enrollmentId=id(),createdAt=now(),expiresAt=new Date(Date.now()+15*60_000).toISOString()
  run('INSERT INTO internet_enrollment_tokens(id,token_hash,node_id,node_group_id,collection_level,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)',enrollmentId,hashToken(raw),data.nodeId||null,data.nodeGroupId||null,data.collectionLevel,req.user.id,createdAt,expiresAt)
  audit(req.user.id,'internet.enrollment.create','internet-enrollment',enrollmentId,null,{nodeId:data.nodeId||null,nodeGroupId:data.nodeGroupId||null,collectionLevel:data.collectionLevel,expiresAt})
  res.status(201).json({id:enrollmentId,token:raw,expiresAt,collectionLevel:data.collectionLevel,installUrl:`${publicBase(req)}/tools`})
}))

internetRoutes.post('/enroll',internetEnrollLimit,wrap(async(req,res)=>{
  const data=z.object({token:z.string().min(32).max(128),browser:browserSchema,extensionVersion:z.string().trim().min(1).max(100),installId:z.string().trim().min(16).max(200),capabilities:z.record(z.string(),z.boolean()).default({})}).parse(req.body)
  const enrollment=one('SELECT * FROM internet_enrollment_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?',hashToken(data.token),now())
  if(!enrollment)return res.status(401).json({error:'Internet enrollment token is invalid, expired, or already used'})
  const rawDeviceToken=crypto.randomBytes(48).toString('base64url'),deviceId=id(),stamp=now()
  db.transaction(()=>{
    const consumed=run('UPDATE internet_enrollment_tokens SET used_at=? WHERE id=? AND used_at IS NULL',stamp,enrollment.id)
    if(consumed.changes!==1)throw Object.assign(new Error('Internet enrollment token was already used'),{status:409})
    run('INSERT INTO internet_extension_devices(id,node_id,node_group_id,browser,extension_version,install_id_hash,token_hash,collection_level,status,capabilities_json,last_seen_at,enrolled_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',deviceId,enrollment.node_id,enrollment.node_group_id,data.browser,data.extensionVersion,hashToken(data.installId),hashToken(rawDeviceToken),enrollment.collection_level,'active',json(data.capabilities),stamp,stamp)
    audit(enrollment.created_by,'internet.device.enroll','internet-device',deviceId,null,{nodeId:enrollment.node_id,nodeGroupId:enrollment.node_group_id,browser:data.browser,extensionVersion:data.extensionVersion})
  })()
  res.set('Cache-Control','no-store').status(201).json({deviceId,deviceToken:rawDeviceToken,serverUrl:publicBase(req),collectionLevel:enrollment.collection_level,heartbeatSeconds:300})
}))

internetRoutes.get('/policies',auth,requireRole('auditor'),(req,res)=>{
  res.json(all('SELECT id,version_no,status,fail_mode,rules_json,comment,created_by,created_at,published_at,rolled_back_at FROM internet_policy_versions ORDER BY version_no DESC').map(row=>({...row,rules:parse(row.rules_json)||[],rules_json:undefined})))
})

internetRoutes.post('/policies',auth,requireRole('editor'),wrap(async(req,res)=>{
  const data=z.object({rules:z.array(internetRuleSchema).max(5000),failMode:z.enum(['open','closed']).default('open'),comment:z.string().max(500).default('')}).parse(req.body)
  const invalidNodes=data.rules.flatMap(rule=>rule.nodeIds),invalidGroups=data.rules.flatMap(rule=>rule.nodeGroupIds)
  const uniqueNodes=[...new Set(invalidNodes)],uniqueGroups=[...new Set(invalidGroups)]
  if(uniqueNodes.length&&all(`SELECT id FROM nodes WHERE id IN (${uniqueNodes.map(()=>'?').join(',')})`,...uniqueNodes).length!==uniqueNodes.length)return res.status(404).json({error:'One or more Internet policy nodes were not found'})
  if(uniqueGroups.length&&all(`SELECT id FROM node_groups WHERE id IN (${uniqueGroups.map(()=>'?').join(',')})`,...uniqueGroups).length!==uniqueGroups.length)return res.status(404).json({error:'One or more Internet policy groups were not found'})
  const version=Number(one('SELECT COALESCE(MAX(version_no),0)+1 next FROM internet_policy_versions')?.next||1),versionId=id(),rules=deduplicateRules(data.rules)
  run('INSERT INTO internet_policy_versions(id,version_no,status,rules_json,fail_mode,comment,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)',versionId,version,'staged',json(rules),data.failMode,data.comment,req.user.id,now())
  audit(req.user.id,'internet.policy.stage','internet-policy',versionId,null,{version,ruleCount:rules.length,failMode:data.failMode})
  res.status(201).json({id:versionId,versionNo:version,status:'staged',rules,failMode:data.failMode})
}))

internetRoutes.post('/policies/:id/publish',auth,requireRole('admin'),(req,res)=>{
  const target=one('SELECT * FROM internet_policy_versions WHERE id=?',req.params.id)
  if(!target)return res.status(404).json({error:'Internet policy version not found'})
  db.transaction(()=>{
    run("UPDATE internet_policy_versions SET status='superseded' WHERE status='published'")
    run("UPDATE internet_policy_versions SET status='published',published_at=?,rolled_back_at=NULL WHERE id=?",now(),target.id)
    audit(req.user.id,'internet.policy.publish','internet-policy',target.id,{status:target.status},{status:'published',version:target.version_no})
  })()
  res.json({id:target.id,status:'published',versionNo:target.version_no})
})

internetRoutes.post('/policies/:id/rollback',auth,requireRole('admin'),(req,res)=>{
  const target=one('SELECT * FROM internet_policy_versions WHERE id=?',req.params.id)
  if(!target)return res.status(404).json({error:'Internet policy version not found'})
  const previous=one("SELECT * FROM internet_policy_versions WHERE version_no<? AND status IN ('superseded','published') ORDER BY version_no DESC LIMIT 1",target.version_no)
  db.transaction(()=>{
    run("UPDATE internet_policy_versions SET status='rolled_back',rolled_back_at=? WHERE id=?",now(),target.id)
    if(previous)run("UPDATE internet_policy_versions SET status='published',published_at=?,rolled_back_at=NULL WHERE id=?",now(),previous.id)
    audit(req.user.id,'internet.policy.rollback','internet-policy',target.id,{status:target.status},{status:'rolled_back',restoredVersion:previous?.version_no||null})
  })()
  res.json({id:target.id,status:'rolled_back',restoredVersion:previous?.version_no||null})
})

// Emergency rollback is intentionally a separate audited action so an on-call
// administrator can distinguish an incident response from routine version
// management in the audit trail. It restores the same prior published version
// as the normal rollback endpoint.
internetRoutes.post('/policies/:id/emergency-rollback',auth,requireRole('admin'),(req,res)=>{
  const target=one('SELECT * FROM internet_policy_versions WHERE id=?',req.params.id)
  if(!target)return res.status(404).json({error:'Internet policy version not found'})
  const previous=one("SELECT * FROM internet_policy_versions WHERE version_no<? AND status IN ('superseded','published') ORDER BY version_no DESC LIMIT 1",target.version_no)
  db.transaction(()=>{
    run("UPDATE internet_policy_versions SET status='rolled_back',rolled_back_at=? WHERE id=?",now(),target.id)
    if(previous)run("UPDATE internet_policy_versions SET status='published',published_at=?,rolled_back_at=NULL WHERE id=?",now(),previous.id)
    audit(req.user.id,'internet.policy.emergency-rollback','internet-policy',target.id,{status:target.status},{status:'rolled_back',restoredVersion:previous?.version_no||null})
  })()
  res.json({id:target.id,status:'rolled_back',restoredVersion:previous?.version_no||null,emergency:true})
})

internetRoutes.get('/config',requireDevice,(req,res)=>{
  const current=one("SELECT * FROM internet_policy_versions WHERE status='published' ORDER BY version_no DESC LIMIT 1")
  const rules=current?parse(current.rules_json)||[]:[]
  const scoped=rules.filter(rule=>scopedForDevice(rule,req.internetDevice))
  const compiled=compileInternetRules(scoped),payload={version:current?.version_no||0,failMode:current?.fail_mode||'open',rules:compiled,issuedAt:now()}
  run('UPDATE internet_extension_devices SET last_seen_at=? WHERE id=?',now(),req.internetDevice.id)
  res.set('Cache-Control','no-store').json({...payload,signature:policySignature(payload)})
})

internetRoutes.post('/events:batch',internetIngestLimit,requireDevice,wrap(async(req,res)=>{
  const data=z.object({events:z.array(z.object({id:z.string().uuid(),url:z.string().url().max(4096),observedAt:z.string().datetime({offset:true}),action:z.enum(['observed','allowed','blocked']).default('observed'),tabSession:z.string().max(200).optional()})).min(1).max(500)}).parse(req.body)
  const device=req.internetDevice
  let inserted=0,duplicates=0,rejected=0
  db.transaction(()=>{
    for(const event of data.events){
      let normalized
      try{normalized=normalizeUrl(event.url,device.collection_level||'host')}catch{rejected++;continue}
      const duplicate=one('SELECT id FROM internet_events WHERE device_id=? AND client_event_id=?',device.id,event.id)
      if(duplicate){duplicates++;continue}
      let pattern=one('SELECT * FROM internet_url_patterns WHERE fingerprint=?',normalized.fingerprint)
      if(!pattern){
        const patternId=id()
        run('INSERT INTO internet_url_patterns(id,fingerprint,scheme,hostname,registrable_domain,path_prefix,reference_count,created_at) VALUES(?,?,?,?,?,?,?,?)',patternId,normalized.fingerprint,normalized.scheme,normalized.hostname,normalized.registrableDomain,normalized.pathPrefix,1,now())
        pattern=one('SELECT * FROM internet_url_patterns WHERE id=?',patternId)
      }else run('UPDATE internet_url_patterns SET reference_count=reference_count+1 WHERE id=?',pattern.id)
      run('INSERT INTO internet_events(id,device_id,client_event_id,observed_at,received_at,browser,hostname,registrable_domain,path_prefix,pattern_id,action,tab_session_hash,redaction_level,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',id(),device.id,event.id,event.observedAt,now(),device.browser,normalized.hostname,normalized.registrableDomain,normalized.pathPrefix,pattern.id,event.action,event.tabSession?hashToken(`${device.id}:${event.tabSession}`):null,'query-stripped',now())
      inserted++
    }
    run('UPDATE internet_extension_devices SET last_seen_at=?,extension_version=COALESCE(extension_version,?) WHERE id=?',now(),device.extension_version,device.id)
  })()
  res.status(201).json({received:data.events.length,inserted,duplicates,rejected})
}))

internetRoutes.get('/summary',auth,requireRole('auditor'),(req,res)=>{
  const row=one("SELECT COUNT(*) events,COUNT(DISTINCT registrable_domain) domains,COUNT(DISTINCT device_id) devices,SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) blocked FROM internet_events")||{}
  res.json({events:Number(row.events||0),domains:Number(row.domains||0),devices:Number(row.devices||0),blocked:Number(row.blocked||0),unmappedUsers:0})
})

internetRoutes.get('/devices',auth,requireRole('auditor'),(req,res)=>res.json(all(`SELECT d.*,n.hostname node_hostname,g.name group_name FROM internet_extension_devices d LEFT JOIN nodes n ON n.id=d.node_id LEFT JOIN node_groups g ON g.id=d.node_group_id ORDER BY d.last_seen_at DESC,d.id`).map(row=>({...publicDevice(row),nodeHostname:row.node_hostname||null,nodeGroupName:row.group_name||null}))))

internetRoutes.post('/devices/:id/revoke',auth,requireRole('admin'),(req,res)=>{
  const device=one('SELECT * FROM internet_extension_devices WHERE id=?',req.params.id)
  if(!device)return res.status(404).json({error:'Internet device not found'})
  run("UPDATE internet_extension_devices SET status='revoked',revoked_at=? WHERE id=? AND revoked_at IS NULL",now(),device.id)
  audit(req.user.id,'internet.device.revoke','internet-device',device.id,{status:device.status},{status:'revoked'})
  res.json({ok:true,id:device.id,status:'revoked'})
})

internetRoutes.get('/events',auth,requireRole('auditor'),(req,res)=>{
  const query=z.object({q:z.string().max(200).optional(),domain:z.string().max(253).optional(),path:z.string().max(240).optional(),browser:browserSchema.optional(),action:z.enum(['observed','allowed','blocked']).optional(),deviceId:z.string().optional(),nodeId:z.string().optional(),from:z.string().datetime({offset:true}).optional(),to:z.string().datetime({offset:true}).optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(500).default(100),sortBy:z.enum(['time','domain','hostname','browser','action']).default('time'),sortDir:z.enum(['asc','desc']).default('desc')}).parse(req.query)
  const where=[],values=[]
  if(query.q){where.push('(e.hostname LIKE ? OR e.registrable_domain LIKE ? OR COALESCE(e.path_prefix,\'\') LIKE ?)');values.push(`%${query.q}%`,`%${query.q}%`,`%${query.q}%`)}
  if(query.domain){where.push('(e.hostname=? OR e.registrable_domain=?)');values.push(query.domain.toLowerCase(),query.domain.toLowerCase())}
  if(query.path){where.push('e.path_prefix LIKE ?');values.push(`${query.path}%`)}
  for(const [key,column] of [['browser','e.browser'],['action','e.action'],['deviceId','e.device_id'],['nodeId','d.node_id']])if(query[key]){where.push(`${column}=?`);values.push(query[key])}
  if(query.from){where.push('e.observed_at>=?');values.push(query.from)}
  if(query.to){where.push('e.observed_at<=?');values.push(query.to)}
  const condition=where.length?`WHERE ${where.join(' AND ')}`:''
  const fromSql=`FROM internet_events e JOIN internet_extension_devices d ON d.id=e.device_id LEFT JOIN nodes n ON n.id=d.node_id LEFT JOIN node_groups g ON g.id=d.node_group_id ${condition}`
  const total=Number(one(`SELECT COUNT(*) count ${fromSql}`,...values)?.count||0)
  const sortColumn={time:'e.observed_at',domain:'e.registrable_domain',hostname:'e.hostname',browser:'e.browser',action:'e.action'}[query.sortBy]
  const items=all(`SELECT e.id,e.client_event_id,e.observed_at,e.received_at,e.browser,e.hostname,e.registrable_domain,e.path_prefix,e.action,e.redaction_level,d.id device_id,d.node_id,d.node_group_id,n.hostname node_hostname,g.name node_group_name FROM ${fromSql.replace(/^FROM /,'')} ORDER BY ${sortColumn} ${query.sortDir.toUpperCase()},e.id DESC LIMIT ? OFFSET ?`,...values,query.pageSize,(query.page-1)*query.pageSize)
  res.json({items,total,page:query.page,pageSize:query.pageSize,totalPages:Math.ceil(total/query.pageSize)})
})

internetRoutes.post('/events/cleanup',auth,requireRole('admin'),(req,res)=>{
  const data=z.object({confirmed:z.literal(true),before:z.string().datetime({offset:true}).optional(),domain:z.string().max(253).optional()}).parse(req.body)
  const where=[],values=[]
  if(data.before){where.push('observed_at<?');values.push(data.before)}
  if(data.domain){where.push('(hostname=? OR registrable_domain=?)');values.push(data.domain.toLowerCase(),data.domain.toLowerCase())}
  if(!where.length)return res.status(400).json({error:'Specify a cleanup cutoff or domain'})
  const condition=where.join(' AND '),count=Number(one(`SELECT COUNT(*) count FROM internet_events WHERE ${condition}`,...values)?.count||0)
  db.transaction(()=>{
    run(`DELETE FROM internet_events WHERE ${condition}`,...values)
    run('UPDATE internet_url_patterns SET reference_count=(SELECT COUNT(*) FROM internet_events WHERE pattern_id=internet_url_patterns.id)')
    run('DELETE FROM internet_url_patterns WHERE reference_count=0')
  })()
  audit(req.user.id,'internet.events.cleanup','internet-events','global',{matching:count},{deleted:count,before:data.before||null,domain:data.domain||null})
  res.json({deleted:count})
})
