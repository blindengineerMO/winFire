import express from 'express'
import fs from 'node:fs'
import path from 'node:path'
import cors from 'cors'
import helmet from 'helmet'
import {rateLimit} from 'express-rate-limit'
import argon2 from 'argon2'
import crypto from 'node:crypto'
import {isIP} from 'node:net'
import PDFDocument from 'pdfkit'
import {z} from 'zod'
import {compilePolicy, graphSchema, findRuleConflicts,validateAddressExpression,validatePortExpression,validateProgramPath,activePolicyRules,scheduleStateKey,extractMfaGates} from '@winfire/shared'
import {db, all, one, run, id, now, audit, json, parse} from './db.js'
import {auth, requireRole, publicUser, issueAccess, issueRefresh, rotateRefresh, hashToken, seal, openSealed} from './security.js'
import {probeNode, collectFacts, enrichNode, lookupDns, remote, diffRules, tcpProbe,testNodeCredential,preflightCredential} from './connector.js'
import {firewallConnectorFor,applyManagedRules} from './firewallConnectors.js'
import {classifyVerification,findMatchingDenyEvent,hasManagedRule} from './verifier.js'
import {makeTotpSecret,verifyTotp,matchingTotpCounter} from './totp.js'
import {agentRoutes} from './routes/agents.js'
import {agentPkiReady,tlsMaterialPaths} from './agentPki.js'
import {agentBootstrapScript,normalizeSignerThumbprint} from './agentBootstrap.js'
import {agentPollSettings,effectiveAgentChannelMode} from './agentPoll.js'
import {normalizeWindowsEvent} from './eventNormalizer.js'
import {isLoopbackEvent} from './eventPattern.js'
import {deliverInvite,deliverVerification,inviteLink} from './mailer.js'
import {saveAvatar,readAvatar,removeAvatar} from './avatar.js'
import {readDirectoryComputers,readDirectoryUsers,testDirectoryConnection,authenticateDirectoryUser,writeDirectoryUserStatus} from './directory.js'
import {observabilitySettings} from './maintenance.js'
import {resourceRecord,canReadResource,canWriteResource} from './access.js'
import {emitNotification,notificationSummary,preferenceKeys} from './notifications.js'
import {buildOpenApi} from './openapi.js'
import {parseSeceditRights,suggestedRightForLogonType,denyRightForAllow,segmentRightsForPort,hasDirectRight} from './logonRights.js'
import {normalizeProfileSnapshot,publicBreakGlass} from './breakGlass.js'
import {normalizeSourceIp,sourceMatches,revokePortalGrant} from './mfaPortal.js'
import {entraConfigured,startEntraAuthentication,completeEntraAuthentication} from './entraPortal.js'
import {publicEntraSettings,saveEntraSettings} from './entraSettings.js'
import {portalBranding,setPortalCompanyName,savePortalImage,readPortalImage,removePortalImage} from './portalBranding.js'
import {assertManagementAccess} from './managementGuard.js'
import {mfaPromptSettings} from './mfaPromptSettings.js'
import {createMfaChallenge,markVerifiedAdChallenge,resolveMfaChallenge} from './mfaChallenges.js'
import {beginAdAuthenticatorEnrollment,confirmAdAuthenticatorEnrollment} from './adAuthenticatorEnrollment.js'
import {validateExportDestination,exportSelectedEvents} from './eventExport.js'
import {previewSecurityAutomation} from './securityAutomations.js'
import {collectAccountInventory,accountName} from './localAccounts.js'
import {normalizeProcessExclusions,refreshProcessExclusions,isExcludedFirewallEvent,visibleFirewallEventSql} from './processExclusions.js'
import {normalizeTrafficIgnore,trafficIgnoreFingerprint,trafficIgnoreFromEvent,refreshTrafficIgnores,publicTrafficIgnore,isIgnoredFirewallEvent,trafficIgnoreMatchSql} from './trafficIgnores.js'
import {normalizeRpcFilter,publicRpcFilter} from './rpcFilters.js'
import {segmentAllowsOperatorAsync} from './segmentAccess.js'
import {syncEntraGroup,cachedEntraGroupMembers} from './entraGraph.js'
import {parseWefEvents,timingSafeSecret,wefNodeToken,wefSubscriptionUrl,publicWefSettings} from './wefReceiver.js'
import {internetRoutes} from './routes/internet.js'
import {classifyNetworkFlow,normalizeNetworkProtocol,recordNetworkFlow} from './services/networkMapping.js'
import {classifierRuleRows,classifierRuleById,createClassifierRule,updateClassifierRule,deleteClassifierRule,processRuleRows,processRuleById,createProcessRule,updateProcessRule,deleteProcessRule} from './services/classifierRules.js'
import {mappingRoutes} from './routes/mapping.js'
import {expandCidrs,runDiscoveryScan,queueDiscoveryScan,publicDiscoverySchedule,runDiscoveryScheduleNow,persistHypervisor,DISCOVERY_MIN_INTERVAL_MINUTES,DISCOVERY_MAX_INTERVAL_MINUTES} from './networkDiscovery.js'
import {validSnmpHost,normalizeSnmpSecret,ipInCidr} from './snmpDiscovery.js'
import {snmpTargets,pollSnmpDiscoveryTarget,pollSnmpNode} from './snmpDiscoveryService.js'
import {passiveDiscoveryRows,passiveDiscoverySummary,processPassiveDiscovery} from './passiveDiscovery.js'
import {asyncHandler} from './middleware/asyncHandler.js'
import {normalizeDynamicRules,dynamicNodeGroupSettings,publicDynamicGroup,updateDynamicGroup,refreshDynamicGroups} from './dynamicNodeGroups.js'
import {identifyHypervisor} from './esxiDiscovery.js'
import {detectInfrastructureHost} from './infrastructureDiscovery.js'

export const app=express()
app.disable('x-powered-by')
if(process.env.TRUST_PROXY_CIDRS)app.set('trust proxy',process.env.TRUST_PROXY_CIDRS.split(',').map(item=>item.trim()).filter(Boolean))
app.use(helmet({contentSecurityPolicy:{directives:{
  defaultSrc:["'self'"],
  baseUri:["'self'"],
  objectSrc:["'none'"],
  scriptSrc:["'self'"],
  styleSrc:["'self'","'unsafe-inline'",'https://fonts.googleapis.com'],
  imgSrc:["'self'",'data:','blob:'],
  fontSrc:["'self'",'data:','https://fonts.gstatic.com'],
  connectSrc:["'self'",'https://login.microsoftonline.com'],
  frameAncestors:["'none'"],
  formAction:["'self'","https://login.microsoftonline.com"]
}}}))
app.use(cors({origin:(origin,cb)=>{
  const allowed=[...(process.env.CORS_ORIGIN||'').split(','),...(process.env.EXTENSION_ORIGINS||'').split(',')].map(value=>value.trim()).filter(Boolean)
  cb(null,!origin||allowed.includes(origin))
}}))
app.use(express.json({limit:'2mb'}))
const api=express.Router()
app.use('/api/v1',api)
api.use('/internet',internetRoutes)
const wrap=asyncHandler
const body=(schema,req)=>schema.parse(req.body)
const reqId=req=>String(req.params.id)
const notFound=(res,label='Record')=>res.status(404).json({error:`${label} not found`})
const latestTraining=nodeId=>one('SELECT id,mode,status,started_at,ends_at,generated_policy_id,last_error,progressive_enabled,progressive_start_at,progressive_interval_hours,next_progressive_at,last_progressive_at FROM learning_sessions WHERE node_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1',nodeId)
const latestVerification=nodeId=>one('SELECT status,reason,run_at FROM verifier_results WHERE node_id=? ORDER BY run_at DESC,rowid DESC LIMIT 1',nodeId)||null
const managementVerification=node=>{
  const probe=String(node?.probe_status||'').toLowerCase()
  const hasFacts=!!node?.snapshot_json
  if((node?.transport==='snmp'||node?.connection_mode==='snmp')&&node?.status==='reachable')return {status:'reachable',label:'Verified',reason:'SNMP poll completed successfully',transport:'snmp',checkedAt:node.last_probe_at||node.last_seen_at||null}
  if((probe==='winrm-authenticated'||probe==='winrms-authenticated')&&hasFacts)return {status:'reachable',label:'Verified',reason:'WinRM credentials authenticated and host facts collected',transport:node.transport,checkedAt:node.last_probe_at||node.last_seen_at||null}
  if(probe==='wmi-authenticated')return {status:'reachable',label:'WMI authenticated',reason:'Credentialed WMI facts collected; WinRM is not active',transport:node.transport,checkedAt:node.last_probe_at||node.last_seen_at||null}
  if(probe==='rpc-authenticated')return {status:'pending',label:'RPC authenticated',reason:'RPC sign-in passed; credentialed host verification is still required',transport:node.transport,checkedAt:node.last_probe_at||node.last_seen_at||null}
  if(probe==='netsh-authenticated')return {status:'reachable',label:'Verified',reason:'SMB/netsh credentials authenticated and host facts collected',transport:node.transport,checkedAt:node.last_probe_at||node.last_seen_at||null}
  if(node?.status==='unreachable')return {status:'unreachable',label:'Unreachable',reason:'The management connection is unavailable',transport:node.transport,checkedAt:node.last_probe_at||node.last_seen_at||null}
  if(node?.status==='reachable')return {status:'pending',label:'Reachable',reason:'A management endpoint responded, but credentials have not been verified',transport:node.transport,checkedAt:node.last_probe_at||node.last_seen_at||null}
  return {status:'unknown',label:'Unchecked',reason:'No authenticated management check has completed',transport:node?.transport||null,checkedAt:node?.last_probe_at||null}
}
function policyVerification(policyId){
  const latest=one('SELECT run_id FROM verifier_results WHERE policy_id=? ORDER BY run_at DESC,rowid DESC LIMIT 1',policyId)
  if(!latest)return null
  const checks=all('SELECT status FROM verifier_results WHERE policy_id=? AND run_id=?',policyId,latest.run_id)
  return checks.some(check=>check.status==='fail')?'fail':checks.some(check=>check.status==='inconclusive')?'inconclusive':checks.length?'pass':null
}
function normalizedNodeOs(node){
  if(!node)return {}
  let name=String(node.os_name||node.platform||'').trim(),version=String(node.os_version||'').trim(),build=String(node.os_build||'').trim()
  if(/^pfsense(?:\/freebsd)?$/i.test(name)){
    name='pfSense'
    version=version.replace(/^pfSense\s*/i,'').replace(new RegExp(`^${String(node.hostname||'').replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}\s*`,'i'),'').trim()
  }
  if(name&&version&&name.toLowerCase()===version.toLowerCase())version=build&&build.toLowerCase()!==name.toLowerCase()?build:''
  if(name&&version&&version.toLowerCase().startsWith(`${name.toLowerCase()} `))version=version.slice(name.length).trim()
  const windowsVersion=version.match(/^(\d+\.\d+)\s*\((\d+)\)$/)
  if(windowsVersion)version=`${windowsVersion[1]}.${windowsVersion[2]}`
  const windowsBuild=build.match(/^(\d+\.\d+)\s*\((\d+)\)$/)
  if(windowsBuild&&`${windowsBuild[1]}.${windowsBuild[2]}`===version)build=''
  if(build&&(build.toLowerCase()===version.toLowerCase()||build.toLowerCase()===name.toLowerCase()))build=''
  if(name==='pfSense'&&/^\d+(?:\.\d+)+$/.test(build))build=''
  let hypervisor=String(node.hypervisor||'').trim()
  if(/^vmware$/i.test(hypervisor)&&/esxi/i.test(`${name} ${version}`))hypervisor='VMware ESXi'
  if(/^xenserver$/i.test(hypervisor))hypervisor='Citrix Hypervisor / XenServer'
  return {os_name:name||null,os_version:version||null,os_build:build||null,hypervisor:hypervisor||null}
}
const safeJson=value=>{try{return parse(value)}catch{return null}}
const publicNode=node=>node && ({...node,...normalizedNodeOs(node),failures:Number(node.failures),virtualMachine:!!Number(node.virtual_machine),virtualMachineHostId:node.virtual_machine_host_id||null,virtualMachineDetails:safeJson(node.virtual_machine_details_json),facts:safeJson(node.snapshot_json),ad:safeJson(node.ad_snapshot_json),training:latestTraining(node.id)||null,verification:latestVerification(node.id),managementVerification:managementVerification(node)})
const canUseCredential=(user,credential)=>credential&&(user.role==='owner'||user.role==='admin'||credential.owner_user_id===user.id||credential.visibility==='team'&&credential.team_id&&credential.team_id===user.team_id||canWriteResource(user,'credential',credential))
const assignedNodeCredentials=nodeId=>all(`SELECT DISTINCT c.* FROM credentials c JOIN credential_assignments a ON a.credential_id=c.id WHERE a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?) ORDER BY c.priority`,nodeId,nodeId)
const assignedSnmpCredential=(nodeId,user)=>assignedNodeCredentials(nodeId).filter(credential=>['snmp-v2c','snmp-v3'].includes(credential.type)&&canUseCredential(user,credential))[0]||null
const assignedEsxiCredentials=(nodeId,user)=>assignedNodeCredentials(nodeId).filter(credential=>credential.type==='esxi'&&canUseCredential(user,credential))
const accessibleEsxiCredentials=(node,user)=>{
  const assigned=assignedEsxiCredentials(node.id,user)
  const available=all("SELECT c.* FROM credentials c WHERE c.type='esxi' AND (c.owner_user_id=? OR c.visibility='team' OR c.visibility='private' OR EXISTS (SELECT 1 FROM credential_assignments a WHERE a.credential_id=c.id AND (a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?))))",user.id,node.id,node.id).filter(credential=>canUseCredential(user,credential))
  return node.device_type==='esxi'?assigned:[...assigned,...available.filter(credential=>!assigned.some(item=>item.id===credential.id))]
}
const openedCredential=credential=>({type:credential.type,secret:openSealed(credential.encrypted_blob)})
function getNode(idValue) {return one('SELECT * FROM nodes WHERE id=?',idValue)}
function getPolicy(idValue) {return one('SELECT * FROM policies WHERE id=?',idValue)}
function hasActiveLearning(policyId) {return !!one("SELECT id FROM learning_sessions WHERE generated_policy_id=? AND status='active'",policyId)}
function readablePolicyIds(user) {return new Set(all('SELECT * FROM policies').filter(policy=>canReadResource(user,'policy',policy)).map(policy=>policy.id))}
function trainingDays() {return Number(one("SELECT value FROM app_settings WHERE key='new_host_training_days'")?.value||30)}
function progressiveSettings() {return {
  enabled:one("SELECT value FROM app_settings WHERE key='progressive_learning_enabled'")?.value==='true',
  startDays:Number(one("SELECT value FROM app_settings WHERE key='progressive_learning_start_days'")?.value||15),
  intervalHours:Number(one("SELECT value FROM app_settings WHERE key='progressive_learning_interval_hours'")?.value||24)
}}
const directorySettings=()=>one("SELECT * FROM directory_connections WHERE id='default'")
const wefPath=()=>one("SELECT value FROM app_settings WHERE key='wef_path'")?.value||'/api/v1/wef/wsman'
const wefEnabled=()=>one("SELECT value FROM app_settings WHERE key='wef_enabled'")?.value==='true'
const savedSetting=key=>String(one('SELECT value FROM app_settings WHERE key=?',key)?.value||'').trim()
const normalizeLogAction=(eventId,action)=>Number(eventId)===4624?'logon':Number(eventId)===4634?'logoff':action||null
const serverFqdn=()=>savedSetting('server_fqdn')
const serverPublicBaseUrl=()=>savedSetting('server_public_base_url')
const localAssetCidrs=()=>{
  const value=parse(savedSetting('local_asset_cidrs'))
  const entries=Array.isArray(value)?value:[savedSetting('local_asset_cidrs')]
  // Older settings could contain literal "\\n" separators. Normalize those
  // on read so inventory filtering and the administration editor agree.
  return entries.flatMap(item=>String(item||'').split(/(?:\\n|\r?\n|,)/)).map(item=>item.trim()).filter(Boolean)
}
const localAssetCidrSchema=z.string().trim().max(43).refine(value=>{const [address,prefix]=value.split('/');const size=Number(prefix);return isIP(address)===4&&Number.isInteger(size)&&size>=0&&size<=32},{message:'Local asset scopes must be IPv4 CIDRs'})
const isLocalAssetNode=node=>{const scopes=localAssetCidrs();return !scopes.length||!node?.ip||scopes.some(scope=>ipInCidr(node.ip,scope))}
const savedWefSecret=()=>{
  const value=savedSetting('wef_shared_secret_sealed')
  if(!value)return ''
  try{return String(openSealed(value)?.secret||'').trim()}catch{return ''}
}
const wefSecret=()=>String(process.env.WEF_SHARED_SECRET||'').trim()||savedWefSecret()
const wefSecretSource=()=>process.env.WEF_SHARED_SECRET?'environment':savedWefSecret()?'administration':'unset'
const effectiveServerFqdn=()=>String(process.env.SERVER_FQDN||serverFqdn()).trim()
const effectivePublicBaseUrl=req=>String(process.env.PUBLIC_BASE_URL||serverPublicBaseUrl()||`${req.protocol}://${effectiveServerFqdn()||req.get('host')}`).replace(/\/$/,'')
function publicWef(req){
  return {...publicWefSettings({enabled:wefEnabled(),secretConfigured:!!wefSecret(),baseUrl:effectivePublicBaseUrl(req),path:wefPath()}),secretSource:wefSecretSource(),baseUrlSource:process.env.PUBLIC_BASE_URL?'environment':serverPublicBaseUrl()?'administration':'request'}
}
const publicDirectory=settings=>settings&&({url:settings.url||'',baseDn:settings.base_dn||'',bindCredentialId:settings.bind_credential_id||null,nodeCredentialId:settings.node_credential_id||null,actionCredentialId:settings.action_credential_id||null,enabled:!!settings.enabled,syncIntervalMinutes:settings.sync_interval_minutes,allowLdapFallback:!!settings.allow_ldap_fallback,ldapFallbackApprovedBy:settings.ldap_fallback_approved_by||null,ldapFallbackApprovedAt:settings.ldap_fallback_approved_at||null,lastTransport:settings.last_transport||null,lastSyncedAt:settings.last_synced_at,lastSyncAttemptAt:settings.last_sync_attempt_at,lastSyncStatus:settings.last_sync_status,lastSyncError:settings.last_sync_error,lastSyncCount:settings.last_sync_count})
function directoryCredential(settings) {
  const credential=one('SELECT * FROM credentials WHERE id=?',settings.bind_credential_id)
  if(!credential)throw Object.assign(new Error('Directory bind credential is missing'),{status:400})
  return {username:credential.username,password:openSealed(credential.encrypted_blob).password}
}
function directoryActionCredential(settings){
  const credential=settings?.action_credential_id?one('SELECT * FROM credentials WHERE id=?',settings.action_credential_id):null
  if(!credential)throw Object.assign(new Error('Configure a separate AD account-control credential in Administration → Directory'),{status:503})
  return {username:credential.username,password:openSealed(credential.encrypted_blob).password}
}
function startTraining(node,days,mode,actorId=null) {
  if(/^(?:5\.[12]\.|windows (?:xp|server 2003))/i.test(String(node.os_version||''))){
    run("UPDATE nodes SET firewall_state='unmanaged' WHERE id=?",node.id)
    audit(actorId,'learning.unsupported','node',node.id,null,{osVersion:node.os_version,reason:'XP/Server 2003 firewall enforcement is unavailable'})
    return null
  }
  if(one("SELECT id FROM learning_sessions WHERE node_id=? AND status IN ('active','review','applying','apply-failed')",node.id))throw Object.assign(new Error('Finish the current learning session before starting another'),{status:409})
  const sessionId=id(),endsAt=new Date(Date.now()+days*864e5).toISOString(),policy=ensurePersonalPolicy(node,actorId)
  const progressive=progressiveSettings(),progressiveEnabled=mode==='auto'&&progressive.enabled&&days>progressive.startDays
  const progressiveStartAt=progressiveEnabled?new Date(Date.now()+progressive.startDays*864e5).toISOString():null
  run('INSERT INTO learning_sessions(id,node_id,ends_at,status,mode,generated_policy_id,progressive_enabled,progressive_start_at,progressive_interval_hours,next_progressive_at) VALUES(?,?,?,?,?,?,?,?,?,?)',sessionId,node.id,endsAt,'active',mode,policy.id,Number(progressiveEnabled),progressiveStartAt,progressiveEnabled?progressive.intervalHours:null,progressiveStartAt)
  run("UPDATE nodes SET firewall_state='learning' WHERE id=?",node.id)
  audit(actorId,'learning.start','node',node.id,null,{sessionId,endsAt,days,mode,policyId:policy.id,progressiveEnabled})
  return {id:sessionId,nodeId:node.id,endsAt,days,mode,status:'active',generatedPolicyId:policy.id,progressiveEnabled}
}
function ensurePersonalPolicy(node,actorId=null) {
  const existing=one("SELECT * FROM policies WHERE origin='learned' AND source_node_id=?",node.id)
  if(existing)return existing
  const policyId=id(),versionId=id(),empty={nodes:[],edges:[]}
  run("INSERT INTO policies(id,name,description,owner_user_id,current_version_id,origin,source_node_id) VALUES(?,?,?,?,?,'learned',?)",policyId,`Learned ${node.hostname}`,`Personal learned firewall policy for ${node.hostname}`,actorId,versionId,node.id)
  run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,policyId,1,json(empty),json([]),actorId,'Learning started')
  return getPolicy(policyId)
}
async function requestEmailVerification(user,email,actorId) {
  if(!process.env.SMTP_HOST)throw Object.assign(new Error('Email verification requires SMTP configuration'),{status:503})
  if(email!==user.email&&one('SELECT id FROM users WHERE email=?',email))throw Object.assign(new Error('An account already uses this email'),{status:409})
  const token=crypto.randomBytes(32).toString('base64url'),verificationId=id(),expiresAt=new Date(Date.now()+864e5).toISOString()
  run('INSERT INTO email_verifications(id,user_id,new_email,token_hash,expires_at) VALUES(?,?,?,?,?)',verificationId,user.id,email,hashToken(token),expiresAt)
  try {await deliverVerification(email,token)}
  catch(error){run('DELETE FROM email_verifications WHERE id=?',verificationId);throw error}
  audit(actorId,'user.email.verification.request','user',user.id,null,{email,expiresAt})
  return {sent:true,expiresAt}
}
function assignedNodes(policyId) {
  return all(`SELECT DISTINCT n.* FROM nodes n JOIN policy_assignments a ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id) WHERE a.policy_id=?`,policyId)
}
function pendingPolicySync(){
  const pairs=all(`SELECT DISTINCT p.id policy_id,p.name policy_name,p.current_version_id version_id,n.id node_id,n.hostname
    FROM policies p JOIN policy_assignments a ON a.policy_id=p.id
    JOIN nodes n ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id)
    WHERE p.current_version_id IS NOT NULL AND NOT EXISTS
      (SELECT 1 FROM learning_sessions s WHERE s.node_id=n.id AND s.status IN ('active','review','applying'))`)
  return pairs.filter(pair=>{
    const applied=one('SELECT version_id,status FROM policy_apply_runs WHERE policy_id=? AND node_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1',pair.policy_id,pair.node_id)
    return applied?.version_id!==pair.version_id||!['success','queued','running'].includes(applied.status)
  })
}
let policySyncRunning=false
async function performPolicySync(actorId){
  if(policySyncRunning)throw Object.assign(new Error('A policy sync is already running'),{status:409})
  policySyncRunning=true
  try{
    const results=[]
    for(const pair of pendingPolicySync()){
      const policy=getPolicy(pair.policy_id),node=getNode(pair.node_id)
      if(!policy||!node)continue
      try{results.push(...await applyPolicy(policy,actorId,[node]))}
      catch(error){results.push({nodeId:node.id,policyId:policy.id,status:'failed',error:error.message});audit(actorId,'policy.sync.failed','node',node.id,null,{policyId:policy.id,error:error.message})}
    }
    audit(actorId,'policy.sync','policy',null,null,{count:results.length,failed:results.filter(item=>item.status==='failed').length})
    return results
  }finally{policySyncRunning=false}
}
export async function processDuePolicySync(){
  const schedules=all("SELECT * FROM policy_sync_schedules WHERE status='scheduled' AND execute_at<=? ORDER BY execute_at LIMIT 5",now())
  for(const schedule of schedules){
    if(policySyncRunning)break
    run("UPDATE policy_sync_schedules SET status='running' WHERE id=? AND status='scheduled'",schedule.id)
    try{const results=await performPolicySync(schedule.requested_by);run('UPDATE policy_sync_schedules SET status=?,result_json=?,finished_at=? WHERE id=?','complete',json(results),now(),schedule.id)}
    catch(error){run('UPDATE policy_sync_schedules SET status=?,result_json=?,finished_at=? WHERE id=?','failed',json({error:error.message}),now(),schedule.id)}
  }
}
export async function processDuePolicySchedules(actorId=null,date=new Date()){
  if(policySyncRunning)return
  policySyncRunning=true
  try{
  const policies=all('SELECT p.*,v.rules_compiled_json FROM policies p JOIN policy_versions v ON v.id=p.current_version_id WHERE p.current_version_id IS NOT NULL')
  for(const policy of policies){
    const compiled=parse(policy.rules_compiled_json)||[]
    if(!compiled.some(rule=>rule.schedule))continue
    const targets=assignedNodes(policy.id)
    for(const node of targets){
      const stateKey=scheduleStateKey(compiled,date)
      const previous=one('SELECT state_key FROM policy_schedule_state WHERE policy_id=? AND node_id=?',policy.id,node.id)
      if(previous?.state_key===stateKey)continue
      try{
        const results=await applyPolicy(policy,actorId,[node],{scheduleTransition:true,scheduleAt:date})
        if(results.every(result=>['success','queued'].includes(result.status)))run('INSERT INTO policy_schedule_state(policy_id,node_id,state_key,last_applied_at) VALUES(?,?,?,?) ON CONFLICT(policy_id,node_id) DO UPDATE SET state_key=excluded.state_key,last_applied_at=excluded.last_applied_at',policy.id,node.id,stateKey,now())
      }catch(error){audit(actorId,'policy.schedule.failed','node',node.id,null,{policyId:policy.id,error:error.message})}
    }
  }
  }finally{policySyncRunning=false}
}
function assignmentConflicts(policyId,rules,nodes) {
  const conflicts=[]
  if(!rules.length)return conflicts
  for(const node of nodes) {
    const others=all(`SELECT DISTINCT p.id,p.name,v.rules_compiled_json FROM policies p JOIN policy_versions v ON v.id=p.current_version_id JOIN policy_assignments a ON a.policy_id=p.id WHERE p.id<>? AND (a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?))`,policyId,node.id,node.id)
    for(const other of others)for(const match of findRuleConflicts(rules,parse(other.rules_compiled_json)||[]))conflicts.push({nodeId:node.id,hostname:node.hostname,otherPolicyId:other.id,otherPolicy:other.name,...match})
  }
  return conflicts
}
function rejectConflicts(res,conflicts) {return res.status(409).json({error:'Conflicting firewall rules on assigned nodes',conflicts})}
async function applyPolicy(policy,actorId=null,targetNodes=null,context={}) {
  if(one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id))throw Object.assign(new Error('Wait for pending agent firewall cleanup before applying this policy'),{status:409})
  const version=one('SELECT * FROM policy_versions WHERE id=? AND policy_id=?',policy.current_version_id,policy.id)
  if (!version) throw Object.assign(new Error('Policy has no version'),{status:400})
  const graph=parse(version.graph_json)||{nodes:[],edges:[]},mfaGates=extractMfaGates(graph)
  if(mfaGates.length)throw Object.assign(new Error('This policy contains MFA Gate nodes. Runtime gate deployment requires the Windows agent challenge broker and is not available yet.'),{status:409})
  const compiledRules=parse(version.rules_compiled_json)||[], rules=activePolicyRules(compiledRules,context.scheduleAt||new Date()), results=[]
  assertManagementAccess(rules)
  const targets=targetNodes||assignedNodes(policy.id)
  for(const node of targets)for(const rule of rules)if(rule.localUserSid){
    if(!firewallConnectorFor(node).supportsLocalUserSid)throw Object.assign(new Error('Local account firewall rules require a modern agentless WinRM source node'),{status:409})
    if(!one('SELECT id FROM local_accounts WHERE node_id=? AND sid=? AND missing=0',node.id,rule.localUserSid))throw Object.assign(new Error(`Local account ${rule.localUserSid} is not present on ${node.hostname}`),{status:409})
  }
  const conflicts=assignmentConflicts(policy.id,rules,targets)
  if(conflicts.length)throw Object.assign(new Error('Conflicting firewall rules on assigned nodes'),{status:409,conflicts})
  for (const node of targets) {
    const runId=id()
    run('INSERT INTO policy_apply_runs(id,policy_id,version_id,node_id,status) VALUES(?,?,?,?,?)',runId,policy.id,version.id,node.id,'running')
    try {
      const applied=await firewallConnectorFor(node).applyPolicy({policyId:policy.id,versionId:version.id,rules,runId,context})
      if(applied.status==='queued'){
        run("UPDATE policy_apply_runs SET status='queued' WHERE id=?",runId)
        audit(actorId,'policy.apply.queued','node',node.id,null,{policyId:policy.id,versionId:version.id,jobId:applied.jobId})
        results.push({nodeId:node.id,status:'queued',jobId:applied.jobId})
        continue
      }
      const diff=applied.diff
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json(diff),now(),runId)
      audit(actorId,'policy.apply','node',node.id,null,{policyId:policy.id,versionId:version.id,diff})
      results.push({nodeId:node.id,status:'success',diff})
    } catch(error) {
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',error.message,now(),runId)
      audit(actorId,'policy.apply.failed','node',node.id,null,{policyId:policy.id,error:error.message})
      results.push({nodeId:node.id,status:'failed',error:error.message})
    }
  }
  return results
}

api.get('/health',(req,res)=>res.json({status:'ok',service:'winfire',time:now()}))
api.get('/agent-package/WinFire.Agent.exe',(req,res)=>{
  if(!req.secure||!agentPkiReady()||!process.env.AGENT_PACKAGE_PATH)return res.status(503).json({error:'Signed agent package requires HTTPS and configured agent PKI'})
  const packagePath=path.resolve(process.env.AGENT_PACKAGE_PATH)
  if(!fs.existsSync(packagePath)||!fs.statSync(packagePath).isFile())return notFound(res,'Agent package')
  res.set('Cache-Control','private, no-store').type('application/octet-stream').sendFile(packagePath)
})
api.get('/agent-package/WinFire.Agent.msi',(req,res)=>{
  if(!req.secure||!agentPkiReady()||!process.env.AGENT_MSI_PATH)return res.status(503).json({error:'Signed agent MSI requires HTTPS, configured agent PKI, and AGENT_MSI_PATH'})
  const packagePath=path.resolve(process.env.AGENT_MSI_PATH)
  if(!fs.existsSync(packagePath)||!fs.statSync(packagePath).isFile())return notFound(res,'Agent MSI')
  res.set('Cache-Control','private, no-store').type('application/x-msi').attachment('WinFire.Agent.msi').sendFile(packagePath)
})
api.get('/agent-package/enroll.ps1',wrap(async(req,res)=>{
  if(!req.secure||!agentPkiReady()||!process.env.AGENT_PACKAGE_PATH)return res.status(503).json({error:'Agent bootstrap requires HTTPS, PKI, and a configured package'})
  const base=effectivePublicBaseUrl(req)
  if(!base.startsWith('https://'))return res.status(503).json({error:'Configure an HTTPS public base URL in Server config or PUBLIC_BASE_URL'})
  const packagePath=path.resolve(process.env.AGENT_PACKAGE_PATH)
  if(!fs.existsSync(packagePath)||!fs.statSync(packagePath).isFile())return notFound(res,'Agent package')
  let script
  try{script=await agentBootstrapScript(packagePath,base,process.env.AGENT_SIGNER_THUMBPRINT)}
  catch(error){return res.status(503).json({error:error.message})}
  res.set('Cache-Control','private, no-store').type('text/plain').send(script)
}))
api.get('/openapi.json',(_req,res)=>res.json(buildOpenApi(api,agentRoutes,{internet:internetRoutes,mapping:mappingRoutes})))
const loginLimit=rateLimit({windowMs:15*60*1000,limit:Number(process.env.AUTH_RATE_LIMIT||20),standardHeaders:'draft-8',legacyHeaders:false})
const publicMfaLimit=rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:'draft-8',legacyHeaders:false})
api.post('/auth/login',loginLimit,wrap(async(req,res)=>{
  const {email,password,totp}=body(z.object({email:z.email(),password:z.string().min(1),totp:z.string().optional()}),req)
  const user=one('SELECT * FROM users WHERE email=?',email.toLowerCase())
  if (!user || user.directory_only || user.auth_source==='ad' || user.suspended || user.locked_until && user.locked_until>now() || !await argon2.verify(user.password_hash,password)) {
    if(user && !user.directory_only && !user.suspended) {
      const attempts=user.failed_attempts+1
      run('UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?',attempts,attempts>=5?new Date(Date.now()+15*60*1000).toISOString():null,user.id)
    }
    return res.status(401).json({error:'Invalid credentials or account locked'})
  }
  if(user.totp_secret&&!verifyTotp(openSealed(user.totp_secret).secret,totp)){
    const attempts=user.failed_attempts+1
    run('UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?',attempts,attempts>=5?new Date(Date.now()+15*60*1000).toISOString():null,user.id)
    return res.status(401).json({error:'TOTP code required or invalid',totpRequired:true})
  }
  run('UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?',user.id)
  audit(user.id,'auth.login','user',user.id,null,null)
  res.json({accessToken:issueAccess(user),refreshToken:issueRefresh(user.id),user:publicUser(user)})
}))
api.post('/auth/refresh',loginLimit,(req,res)=>{const tokens=rotateRefresh(req.body?.refreshToken);return tokens?res.json(tokens):res.status(401).json({error:'Invalid refresh token'})})
api.post('/auth/logout',auth,(req,res)=>{if(req.body?.refreshToken)run('UPDATE refresh_tokens SET revoked_at=? WHERE token_hash=?',now(),hashToken(req.body.refreshToken));audit(req.user.id,'auth.logout','user',req.user.id,null,null);res.json({ok:true})})
api.get('/auth/me',auth,(req,res)=>res.json({...publicUser(req.user),totpEnabled:!!req.user.totp_secret,emailVerified:!!req.user.email_verified,profile:one('SELECT avatar_url,theme,notification_prefs FROM user_profiles WHERE user_id=?',req.user.id)}))

const enrollmentLimit=rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:'draft-8',legacyHeaders:false})
function requireEnrollmentHttps(req,res,next){
  if(process.env.NODE_ENV==='production'&&!req.secure&&!['127.0.0.1','::1'].includes(req.ip))return res.status(426).json({error:'Authenticator enrollment requires HTTPS'})
  next()
}
api.post('/auth/ad/login',loginLimit,requireEnrollmentHttps,wrap(async(req,res)=>{
  const {email,password,totp}=body(z.object({email:z.email(),password:z.string().min(1).max(512),totp:z.string().optional()}),req)
  const user=one("SELECT u.*,d.upn,d.enabled ad_enabled,d.missing ad_missing FROM users u LEFT JOIN directory_users d ON d.id=u.ad_guid WHERE u.email=? AND u.auth_source='ad'",email.toLowerCase())
  if(!user||user.suspended||user.locked_until&&user.locked_until>now()||!user.ad_enabled||user.ad_missing||!user.upn)return res.status(401).json({error:'Invalid credentials or account locked'})
  try{await authenticateDirectoryUser(directorySettings(),user.upn,password)}
  catch(error){
    if(error.status!==401)throw error
    const attempts=user.failed_attempts+1
    run('UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?',attempts,attempts>=5?new Date(Date.now()+15*60*1000).toISOString():null,user.id)
    return res.status(401).json({error:'Invalid credentials or account locked'})
  }
  if(user.totp_secret&&!verifyTotp(openSealed(user.totp_secret).secret,totp)){
    const attempts=user.failed_attempts+1
    run('UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?',attempts,attempts>=5?new Date(Date.now()+15*60*1000).toISOString():null,user.id)
    return res.status(401).json({error:'TOTP code required or invalid',totpRequired:true})
  }
  run('UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?',user.id)
  audit(user.id,'auth.ad.login','user',user.id,null,{directoryGuid:user.ad_guid})
  res.set('Cache-Control','no-store').json({accessToken:issueAccess(user),refreshToken:issueRefresh(user.id),user:publicUser(user)})
}))
api.post('/auth/ad-totp/enroll',enrollmentLimit,requireEnrollmentHttps,wrap(async(req,res)=>{
  const {email,password}=body(z.object({email:z.email(),password:z.string().min(1).max(512)}),req)
  const result=await beginAdAuthenticatorEnrollment({settings:directorySettings(),email,password,sourceIp:normalizeSourceIp(req.ip)})
  res.set('Cache-Control','no-store').json(result)
}))
api.post('/auth/ad-totp/confirm',enrollmentLimit,requireEnrollmentHttps,wrap(async(req,res)=>{
  const {token,code}=body(z.object({token:z.string().min(32).max(128),code:z.string().regex(/^\d{6}$/)}),req)
  const result=await confirmAdAuthenticatorEnrollment({token,code,sourceIp:normalizeSourceIp(req.ip)})
  res.set('Cache-Control','no-store').json(result)
}))

api.post('/invites/accept',loginLimit,wrap(async(req,res)=>{
  const {token,password}=body(z.object({token:z.string().min(32),password:z.string().min(12)}),req)
  const invitation=one('SELECT * FROM invites WHERE token_hash=? AND accepted_at IS NULL AND expires_at>?',hashToken(token),now())
  if(!invitation)return res.status(400).json({error:'Invitation is invalid or expired'})
  if(one('SELECT id FROM users WHERE email=?',invitation.email))return res.status(409).json({error:'An account already uses this email'})
  const passwordHash=await argon2.hash(password),userId=id()
  db.transaction(()=>{
    const consumed=run('UPDATE invites SET accepted_at=? WHERE id=? AND accepted_at IS NULL',now(),invitation.id)
    if(consumed.changes!==1)throw Object.assign(new Error('Invitation was already accepted'),{status:409})
    run('INSERT INTO users(id,email,password_hash,role,team_id,email_verified) VALUES(?,?,?,?,?,?)',userId,invitation.email,passwordHash,invitation.role,invitation.team_id||null,invitation.delivered_at?1:0)
    run('INSERT INTO user_profiles(user_id) VALUES(?)',userId)
    if(invitation.team_id)run('INSERT INTO team_members(team_id,user_id) VALUES(?,?)',invitation.team_id,userId)
    audit(userId,'invite.accept','user',userId,null,{invitationId:invitation.id,email:invitation.email})
  })()
  res.status(201).json(publicUser(one('SELECT * FROM users WHERE id=?',userId)))
}))
api.post('/auth/verify-email',loginLimit,(req,res)=>{
  const {token}=body(z.object({token:z.string().min(32)}),req)
  const verification=one('SELECT * FROM email_verifications WHERE token_hash=? AND used_at IS NULL AND expires_at>?',hashToken(token),now())
  if(!verification)return res.status(400).json({error:'Verification link is invalid or expired'})
  const user=one('SELECT * FROM users WHERE id=?',verification.user_id)
  if(!user)return notFound(res,'User')
  db.transaction(()=>{
    const consumed=run('UPDATE email_verifications SET used_at=? WHERE id=? AND used_at IS NULL',now(),verification.id)
    if(consumed.changes!==1)throw Object.assign(new Error('Verification link already used'),{status:409})
    run('UPDATE users SET email=?,email_verified=1,session_version=session_version+1 WHERE id=?',verification.new_email,user.id)
    run('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=?',now(),user.id)
    audit(user.id,'user.email.verified','user',user.id,{email:user.email},{email:verification.new_email})
  })()
  res.json({verified:true,email:verification.new_email})
})
api.get('/avatars/:id',(req,res)=>{
  const avatar=readAvatar(reqId(req))
  if(!avatar)return notFound(res,'Avatar')
  res.set('Cache-Control','private, max-age=300').type(avatar.mimeType).send(avatar.bytes)
})
api.get('/portal-branding',(_req,res)=>res.json(portalBranding()))
api.get('/portal-branding/image',(_req,res)=>{
  const image=readPortalImage()
  if(!image)return notFound(res,'Portal image')
  res.set('Cache-Control','public, max-age=300').type(image.mimeType).send(image.bytes)
})

function livePublicPrompt(req,promptId){
  if(!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(promptId))throw Object.assign(new Error('MFA request is unavailable or expired'),{status:404})
  const prompt=one('SELECT * FROM mfa_prompt_events WHERE id=?',promptId)
  if(!prompt||prompt.status!=='opened'||prompt.expires_at<=now()||prompt.source_ip!==normalizeSourceIp(req.ip))throw Object.assign(new Error('MFA request is unavailable or expired'),{status:404})
  const segment=one('SELECT * FROM identity_segments WHERE id=?',prompt.segment_id)
  if(!segment?.portal_enabled||segment.mode!=='agentless')throw Object.assign(new Error('MFA request is unavailable or expired'),{status:404})
  return {prompt,segment}
}
async function portalIdentity(email,segment){
  const user=one('SELECT * FROM users WHERE email=?',email.toLowerCase())
  if(!user||user.suspended||!user.email_verified||user.locked_until&&user.locked_until>now()||!await segmentAllowsOperatorAsync(segment,email))throw Object.assign(new Error('This account cannot authorize the request'),{status:403})
  return user
}
api.get('/mfa/prompts/:id',(req,res)=>{
  const {prompt,segment}=livePublicPrompt(req,req.params.id)
  const target=one('SELECT hostname FROM nodes WHERE id=?',prompt.target_node_id)
  const source=prompt.source_node_id?one('SELECT hostname FROM nodes WHERE id=?',prompt.source_node_id):null
  const sourceEvent=prompt.source_node_id&&prompt.source_event_record_id?one('SELECT program FROM log_events WHERE node_id=? AND record_id=?',prompt.source_node_id,prompt.source_event_record_id):null
  const directory=directorySettings()
  res.set('Cache-Control','no-store').json({id:prompt.id,target:target?.hostname||'Protected resource',source:source?.hostname||prompt.source_ip,sourceIp:prompt.source_ip,sessionUser:prompt.opened_user||null,sessionId:prompt.opened_session_id??null,program:sourceEvent?.program?.slice(0,512)||null,port:segment.port,protocol:segment.port===3389?'RDP':segment.port===22?'SSH':'TCP',provider:segment.mfa_provider,providerAvailable:segment.mfa_provider==='entra'?entraConfigured():!!(directory?.enabled&&String(directory.url||'').startsWith('ldaps://')),expiresAt:prompt.expires_at,ttlMinutes:segment.ttl_minutes,branding:portalBranding()})
})
api.post('/mfa/prompts/:id/totp',publicMfaLimit,wrap(async(req,res)=>{
  const {prompt,segment}=livePublicPrompt(req,req.params.id)
  if(segment.mfa_provider!=='totp')return res.status(409).json({error:'This request uses Microsoft sign-in'})
  const {email,password,code}=body(z.object({email:z.email(),password:z.string().min(1).max(512),code:z.string().regex(/^\d{6}$/)}),req)
  const challengeId=createMfaChallenge({nodeId:prompt.target_node_id,userUpn:email.toLowerCase(),segmentId:segment.id,connection:{srcIp:prompt.source_ip,dstPort:segment.port,protocol:'TCP'},provider:'totp',promptId:prompt.id})
  let user=null
  let totpFailure=false
  try{
    user=await portalIdentity(email,segment)
    if(!user.totp_secret)throw Object.assign(new Error('Enroll an authenticator at /enroll-authenticator before using this request'),{status:403})
    await authenticateDirectoryUser(directorySettings(),email,password)
    markVerifiedAdChallenge(challengeId,user,email,'ldaps-bind')
    const counter=matchingTotpCounter(openSealed(user.totp_secret).secret,code)
    if(counter===null){totpFailure=true;throw Object.assign(new Error('Invalid directory credentials or authenticator code'),{status:401})}
    const consumed=run('INSERT INTO mfa_totp_replay(user_id,last_counter) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET last_counter=excluded.last_counter WHERE excluded.last_counter>mfa_totp_replay.last_counter',user.id,counter)
    if(consumed.changes!==1){totpFailure=true;throw Object.assign(new Error('Authenticator code was already used; wait for a new code'),{status:401})}
    run('UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?',user.id)
    req.user=user
    const {node,sourceIp}=portalTarget(req,segment,prompt.target_node_id)
    res.status(201).json(await grantPortalAccess(req,segment,node,sourceIp,'totp',prompt.id,challengeId))
  }catch(error){
    if(user&&error.status===401){const attempts=user.failed_attempts+1;run('UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?',attempts,attempts>=5?new Date(Date.now()+15*60_000).toISOString():null,user.id)}
    resolveMfaChallenge(challengeId,'denied',{actorId:user?.id||null,reason:error.status===401?'Invalid directory credentials or authenticator code':error.message,failureKind:totpFailure?'totp':null})
    throw error
  }
}))
api.post('/mfa/prompts/:id/entra/start',publicMfaLimit,wrap(async(req,res)=>{
  const {prompt,segment}=livePublicPrompt(req,req.params.id)
  if(segment.mfa_provider!=='entra')return res.status(409).json({error:'This request uses an authenticator code'})
  if(!entraConfigured())return res.status(503).json({error:'Microsoft sign-in is not configured'})
  const flow=await startEntraAuthentication({redirectPath:'/mfa/callback'})
  livePublicPrompt(req,prompt.id)
  const expiresAt=new Date(Math.min(Date.now()+5*60_000,Date.parse(prompt.expires_at))).toISOString()
  db.transaction(()=>{
    const challengeId=createMfaChallenge({nodeId:prompt.target_node_id,userUpn:prompt.opened_user||'Unverified Microsoft user',segmentId:segment.id,connection:{srcIp:prompt.source_ip,dstPort:segment.port,protocol:'TCP'},provider:'entra',promptId:prompt.id,expiresAt})
    run('INSERT INTO mfa_public_entra_flows(state_hash,prompt_id,source_ip,sealed_checks,challenge_id,expires_at) VALUES(?,?,?,?,?,?)',hashToken(flow.state),prompt.id,prompt.source_ip,seal({verifier:flow.verifier,nonce:flow.nonce}),challengeId,expiresAt)
  })()
  res.set('Cache-Control','no-store').json({authorizationUrl:flow.url})
}))
api.post('/mfa/entra/complete',publicMfaLimit,wrap(async(req,res)=>{
  const {code,state}=body(z.object({code:z.string().min(8).max(4096),state:z.string().min(16).max(512)}),req)
  const flow=one('SELECT * FROM mfa_public_entra_flows WHERE state_hash=?',hashToken(state))
  if(!flow||flow.used_at||flow.expires_at<=now()||flow.source_ip!==normalizeSourceIp(req.ip))return res.status(401).json({error:'Microsoft sign-in expired or was already used'})
  const reserved=run('UPDATE mfa_public_entra_flows SET used_at=? WHERE state_hash=? AND used_at IS NULL',now(),flow.state_hash)
  if(reserved.changes!==1)return res.status(401).json({error:'Microsoft sign-in was already used'})
  try{
    const {prompt,segment}=livePublicPrompt(req,flow.prompt_id)
    const identity=await completeEntraAuthentication({code,state,...openSealed(flow.sealed_checks),redirectPath:'/mfa/callback'})
    run('UPDATE mfa_challenges SET user_upn=? WHERE id=?',identity.email,flow.challenge_id)
    const user=await portalIdentity(identity.email,segment)
    req.user=user
    const {node,sourceIp}=portalTarget(req,segment,prompt.target_node_id)
    res.status(201).json(await grantPortalAccess(req,segment,node,sourceIp,'entra',prompt.id,flow.challenge_id))
  }catch(error){resolveMfaChallenge(flow.challenge_id,'denied',{reason:'Microsoft sign-in or access authorization failed'});throw error}
}))
api.post('/mfa/entra/cancel',publicMfaLimit,(req,res)=>{
  const {state,error}=body(z.object({state:z.string().min(16).max(512),error:z.string().regex(/^[A-Za-z0-9_]{1,64}$/)}),req)
  const flow=one('SELECT * FROM mfa_public_entra_flows WHERE state_hash=?',hashToken(state))
  if(!flow||flow.used_at||flow.expires_at<=now()||flow.source_ip!==normalizeSourceIp(req.ip))return res.status(401).json({error:'Microsoft sign-in expired or was already used'})
  const reserved=run('UPDATE mfa_public_entra_flows SET used_at=? WHERE state_hash=? AND used_at IS NULL',now(),flow.state_hash)
  if(reserved.changes!==1)return res.status(401).json({error:'Microsoft sign-in was already used'})
  resolveMfaChallenge(flow.challenge_id,'denied',{reason:`Microsoft sign-in returned ${error}`})
  res.json({ok:true})
})

api.use('/agents',agentRoutes)
const wefSoapResponse=()=>`<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><w:EventsResponse xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman"/></s:Body></s:Envelope>`
api.post('/wef/wsman',express.raw({type:['application/soap+xml','text/xml','application/xml'],limit:'2mb'}),wrap(async(req,res)=>{
  if(!wefEnabled())return res.status(404).json({error:'WEF push receiver is disabled'})
  const secret=wefSecret();if(!secret)return res.status(503).json({error:'WEF_SHARED_SECRET is not configured'})
  const node=wefNodeForRequest(req)
  const token=String(req.get('x-winfire-wef-token')||req.query.token||'')
  if(!timingSafeSecret(token,wefNodeToken(secret,node.id)))return res.status(401).json({error:'WEF source authentication failed'})
  const bodyBuffer=Buffer.isBuffer(req.body)?req.body:Buffer.from(String(req.body||''))
  const events=parseWefEvents(bodyBuffer.toString('utf8'))
  const inserted=insertCollectedEvents(node.id,events,observabilitySettings().ignoreLoopbackIngest)
  run("UPDATE nodes SET status='reachable',last_seen_at=?,failures=0,next_retry_at=NULL WHERE id=?",now(),node.id)
  audit(null,'logs.push.wef','node',node.id,null,{received:events.length,inserted,lastRecordId:events.at(-1)?.RecordId||null})
  res.status(200).type('application/soap+xml').send(wefSoapResponse())
}))
api.use(auth)
api.use('/mapping',mappingRoutes)
api.get('/settings/tls',requireRole('admin'),(_req,res)=>{
  const paths=tlsMaterialPaths(),files=Object.fromEntries(Object.entries(paths).map(([name,file])=>[name,{configured:fs.existsSync(file),source:process.env[name]?'environment':'administration',path:process.env[name]?null:file}]))
  res.json({httpsEnabled:Object.values(files).every(item=>item.configured),files,restartRequired:true})
})
api.put('/settings/tls/:kind',requireRole('admin'),(req,res)=>{
  const kinds={serverCert:{key:'TLS_CERT',file:'server.crt',begin:'CERTIFICATE'},serverKey:{key:'TLS_KEY',file:'server.key',begin:'(?:RSA )?PRIVATE KEY'},agentCaCert:{key:'AGENT_CA_CERT',file:'agent-ca.crt',begin:'CERTIFICATE'},agentCaKey:{key:'AGENT_CA_KEY',file:'agent-ca.key',begin:'(?:RSA )?PRIVATE KEY'}}
  const target=kinds[req.params.kind]
  if(!target)return res.status(400).json({error:'Unknown TLS material type'})
  const data=body(z.object({base64:z.string().min(1).max(4_000_000)}),req)
  let pem
  try{pem=Buffer.from(data.base64,'base64').toString('utf8')}catch{ return res.status(400).json({error:'Invalid base64 TLS material'}) }
  const pemPattern=target.begin==='CERTIFICATE'?/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/:/-----BEGIN (?:RSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]+-----END (?:RSA |ENCRYPTED )?PRIVATE KEY-----/
  if(!pemPattern.test(pem))return res.status(400).json({error:'Uploaded material is not a valid PEM certificate or private key'})
  if(process.env[target.key])return res.status(409).json({error:`${target.key} is configured by the deployment environment; change that path instead of uploading through the control plane`})
  try{if(target.begin==='CERTIFICATE')new crypto.X509Certificate(pem);else crypto.createPrivateKey({key:pem,format:'pem',passphrase:process.env[target.key==='TLS_KEY'?'TLS_KEY_PASSPHRASE':'AGENT_CA_PASSPHRASE']||undefined})}catch(error){return res.status(400).json({error:`TLS material could not be parsed: ${error.message}`})}
  const file=tlsMaterialPaths()[target.key];fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});fs.writeFileSync(file,pem,{mode:0o600});audit(req.user.id,'tls.material.upload','app-settings',target.key,null,{bytes:Buffer.byteLength(pem)})
  res.json({ok:true,kind:req.params.kind,restartRequired:true})
})
const publicDiscoveryScan=scan=>({...scan,cidrs:parse(scan.cidrs_json)||[],results:parse(scan.results_json)||[],diff:parse(scan.diff_json)||{}})
api.get('/discovery/scans',requireRole('admin'),(_req,res)=>res.json(all('SELECT * FROM discovery_scans ORDER BY created_at DESC LIMIT 100').map(publicDiscoveryScan)))
api.get('/discovery/scans/:id',requireRole('admin'),(req,res)=>{const scan=one('SELECT * FROM discovery_scans WHERE id=?',reqId(req));if(!scan)return notFound(res,'Discovery scan');res.json(publicDiscoveryScan(scan))})
api.post('/discovery/scans',requireRole('admin'),(req,res)=>{
  const data=body(z.object({cidrs:z.array(z.string().trim().min(1).max(64)).min(1).max(32)}),req)
  let hosts;try{hosts=expandCidrs(data.cidrs)}catch(error){return res.status(400).json({error:error.message})}
  const scanId=queueDiscoveryScan({cidrs:data.cidrs,requestedBy:req.user.id})
  setImmediate(()=>runDiscoveryScan(scanId).catch(error=>console.error('Discovery scan failed:',error)))
  res.status(202).json({id:scanId,status:'queued',addresses:hosts.length})
})
const discoveryScheduleInput=z.object({name:z.string().trim().min(1).max(120).default('CIDR discovery schedule'),cidrs:z.array(z.string().trim().min(1).max(64)).min(1).max(32),intervalMinutes:z.number().int().min(DISCOVERY_MIN_INTERVAL_MINUTES).max(DISCOVERY_MAX_INTERVAL_MINUTES).default(60),enabled:z.boolean().default(true)})
const discoveryScheduleUpdate=z.object({name:z.string().trim().min(1).max(120).optional(),cidrs:z.array(z.string().trim().min(1).max(64)).min(1).max(32).optional(),intervalMinutes:z.number().int().min(DISCOVERY_MIN_INTERVAL_MINUTES).max(DISCOVERY_MAX_INTERVAL_MINUTES).optional(),enabled:z.boolean().optional()})
api.get('/discovery/schedules',requireRole('admin'),(_req,res)=>res.json(all('SELECT * FROM discovery_scan_schedules ORDER BY created_at DESC').map(publicDiscoverySchedule)))
api.post('/discovery/schedules',requireRole('admin'),(req,res)=>{
  const data=body(discoveryScheduleInput,req);let addresses
  try{addresses=expandCidrs(data.cidrs)}catch(error){return res.status(400).json({error:error.message})}
  const scheduleId=id(),stamp=now(),next=new Date(Date.now()+data.intervalMinutes*60_000).toISOString()
  run('INSERT INTO discovery_scan_schedules(id,name,cidrs_json,enabled,interval_minutes,status,next_run_at,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?, ?,?,?)',scheduleId,data.name,json(data.cidrs),Number(data.enabled),data.intervalMinutes,data.enabled?'enabled':'paused',next,req.user.id,stamp,stamp)
  audit(req.user.id,'network-discovery.schedule.create','discovery-schedule',scheduleId,null,{...data,addresses})
  res.status(201).json(publicDiscoverySchedule(one('SELECT * FROM discovery_scan_schedules WHERE id=?',scheduleId)))
})
api.patch('/discovery/schedules/:id',requireRole('admin'),(req,res)=>{
  const before=one('SELECT * FROM discovery_scan_schedules WHERE id=?',reqId(req));if(!before)return notFound(res,'Discovery schedule')
  const data=body(discoveryScheduleUpdate,req),name=data.name===undefined?before.name:data.name,cidrs=data.cidrs===undefined?parse(before.cidrs_json)||[]:data.cidrs,intervalMinutes=data.intervalMinutes===undefined?before.interval_minutes:data.intervalMinutes,enabled=data.enabled===undefined?!!before.enabled:data.enabled
  let addresses;try{addresses=expandCidrs(cidrs)}catch(error){return res.status(400).json({error:error.message})}
  const status=enabled?(before.status==='running'?'running':'enabled'):'paused',next=data.intervalMinutes===undefined&&before.next_run_at?before.next_run_at:new Date(Date.now()+intervalMinutes*60_000).toISOString()
  run('UPDATE discovery_scan_schedules SET name=?,cidrs_json=?,enabled=?,interval_minutes=?,status=?,next_run_at=?,last_error=NULL,updated_at=? WHERE id=?',name,json(cidrs),Number(enabled),intervalMinutes,status,next,now(),before.id)
  const after=one('SELECT * FROM discovery_scan_schedules WHERE id=?',before.id)
  audit(req.user.id,'network-discovery.schedule.update','discovery-schedule',before.id,{...publicDiscoverySchedule(before)},{...publicDiscoverySchedule(after),addresses})
  res.json(publicDiscoverySchedule(after))
})
api.delete('/discovery/schedules/:id',requireRole('admin'),(req,res)=>{const schedule=one('SELECT * FROM discovery_scan_schedules WHERE id=?',reqId(req));if(!schedule)return notFound(res,'Discovery schedule');run('DELETE FROM discovery_scan_schedules WHERE id=?',schedule.id);audit(req.user.id,'network-discovery.schedule.delete','discovery-schedule',schedule.id,publicDiscoverySchedule(schedule),null);res.status(204).end()})
const runDiscoveryScheduleRoute=wrap(async(req,res)=>{const result=await runDiscoveryScheduleNow(reqId(req),{actorId:req.user.id});const scan=one('SELECT cidrs_json FROM discovery_scans WHERE id=?',result.scanId);res.status(202).json({...result,addresses:expandCidrs(parse(scan?.cidrs_json)||[]).length})})
api.post('/discovery/schedules/:id/run-now',requireRole('admin'),runDiscoveryScheduleRoute)
api.post('/discovery/schedules/:id/run',requireRole('admin'),runDiscoveryScheduleRoute)
const snmpCidr=value=>{
  const [address,prefixText]=String(value||'').trim().split('/')
  const prefix=prefixText===undefined?32:Number(prefixText)
  return isIP(address)===4&&Number.isInteger(prefix)&&prefix>=0&&prefix<=32?`${address}/${prefix}`:null
}
api.get('/discovery/snmp-targets',requireRole('admin'),(_req,res)=>res.json(snmpTargets()))
api.post('/discovery/snmp-targets',requireRole('admin'),(req,res)=>{
  const data=body(z.object({name:z.string().trim().min(1).max(120),host:z.string().trim().min(1).max(253),cidr:z.string().trim().max(32).optional(),credentialId:z.string().min(1),enabled:z.boolean().default(true),pollIntervalMinutes:z.number().int().min(5).max(10080).default(60)}),req)
  const host=validSnmpHost(data.host),cidr=data.cidr?snmpCidr(data.cidr):null
  if(!host)return res.status(400).json({error:'SNMP target host must be an IP address or DNS hostname'})
  if(data.cidr&&!cidr)return res.status(400).json({error:'SNMP discovery scope must be an IPv4 CIDR'})
  const credential=one('SELECT * FROM credentials WHERE id=?',data.credentialId)
  if(!credential)return notFound(res,'Credential')
  if(!['snmp-v2c','snmp-v3'].includes(credential.type))return res.status(400).json({error:'Select an SNMP v2c or SNMP v3 credential'})
  if(!canUseCredential(req.user,credential))return res.status(403).json({error:'Insufficient permission'})
  if(one('SELECT id FROM snmp_discovery_targets WHERE lower(host)=lower(?) AND COALESCE(cidr,\'\')=COALESCE(?,\'\')',host,cidr))return res.status(409).json({error:'An SNMP target already exists for this host and scope'})
  const targetId=id(),stamp=now()
  run('INSERT INTO snmp_discovery_targets(id,name,host,cidr,credential_id,enabled,poll_interval_minutes,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)',targetId,data.name,host,cidr,data.credentialId,Number(data.enabled),data.pollIntervalMinutes,req.user.id,stamp,stamp)
  audit(req.user.id,'snmp-discovery.target.create','snmp-target',targetId,null,{name:data.name,host,cidr,credentialId:data.credentialId,pollIntervalMinutes:data.pollIntervalMinutes})
  res.status(201).json(snmpTargets().find(item=>item.id===targetId))
})
api.patch('/discovery/snmp-targets/:id',requireRole('admin'),(req,res)=>{
  const target=one('SELECT * FROM snmp_discovery_targets WHERE id=?',reqId(req));if(!target)return notFound(res,'SNMP target')
  const data=body(z.object({name:z.string().trim().min(1).max(120).optional(),host:z.string().trim().min(1).max(253).optional(),cidr:z.string().trim().max(32).nullable().optional(),credentialId:z.string().min(1).optional(),enabled:z.boolean().optional(),pollIntervalMinutes:z.number().int().min(5).max(10080).optional()}),req)
  const host=data.host===undefined?target.host:validSnmpHost(data.host),cidr=data.cidr===undefined?target.cidr:(data.cidr?snmpCidr(data.cidr):null)
  if(!host)return res.status(400).json({error:'SNMP target host must be an IP address or DNS hostname'})
  if(data.cidr&&!cidr)return res.status(400).json({error:'SNMP discovery scope must be an IPv4 CIDR'})
  const credentialId=data.credentialId||target.credential_id,credential=one('SELECT * FROM credentials WHERE id=?',credentialId)
  if(!credential)return notFound(res,'Credential')
  if(!['snmp-v2c','snmp-v3'].includes(credential.type))return res.status(400).json({error:'Select an SNMP v2c or SNMP v3 credential'})
  if(!canUseCredential(req.user,credential))return res.status(403).json({error:'Insufficient permission'})
  const stamp=now()
  run('UPDATE snmp_discovery_targets SET name=?,host=?,cidr=?,credential_id=?,enabled=?,poll_interval_minutes=?,updated_at=? WHERE id=?',data.name||target.name,host,cidr,credentialId,data.enabled===undefined?target.enabled:Number(data.enabled),data.pollIntervalMinutes||target.poll_interval_minutes,stamp,target.id)
  audit(req.user.id,'snmp-discovery.target.update','snmp-target',target.id,target,{name:data.name||target.name,host,cidr,credentialId})
  res.json(snmpTargets().find(item=>item.id===target.id))
})
api.delete('/discovery/snmp-targets/:id',requireRole('admin'),(req,res)=>{const target=one('SELECT * FROM snmp_discovery_targets WHERE id=?',reqId(req));if(!target)return notFound(res,'SNMP target');run('DELETE FROM snmp_discovery_targets WHERE id=?',target.id);audit(req.user.id,'snmp-discovery.target.delete','snmp-target',target.id,target,null);res.status(204).end()})
api.post('/discovery/snmp-targets/:id/poll',requireRole('admin'),wrap(async(req,res)=>{
  const result=await pollSnmpDiscoveryTarget(reqId(req),{actorId:req.user.id})
  res.json(result)
}))
api.get('/discovery/passive-candidates',requireRole('admin'),(req,res)=>res.json({summary:passiveDiscoverySummary(),items:passiveDiscoveryRows({status:req.query.status||null,limit:req.query.limit})}))
api.post('/discovery/passive-candidates/process',requireRole('admin'),wrap(async(req,res)=>res.json(await processPassiveDiscovery({limit:32,actorId:req.user.id}))))
api.post('/nodes/:id/arp/collect',requireRole('editor'),(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  if(!node.agent_id)return res.status(409).json({error:'ARP collection requires an enrolled agent on this node'})
  const agent=one('SELECT id,last_checkin_at FROM agents WHERE id=? AND revoked_at IS NULL',node.agent_id)
  if(!agent||!agent.last_checkin_at||Date.parse(agent.last_checkin_at)<Date.now()-5*60_000)return res.status(409).json({error:'Agent is offline'})
  const jobId=id();run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',jobId,agent.id,'arp.collect',json({nodeId:node.id}))
  audit(req.user.id,'network-mapping.arp.collect','node',node.id,null,{jobId})
  res.status(202).json({queued:true,jobId})
})
const securityAutomationSchema=z.object({name:z.string().trim().min(3).max(120),triggerType:z.enum(['destination','mfa_failures']),destination:z.string().trim().max(255).default(''),failureCount:z.number().int().min(2).max(100).default(3),windowMinutes:z.number().int().min(1).max(1440).default(15),cooldownMinutes:z.number().int().min(1).max(10080).default(60),actionType:z.enum(['alert','disable_ad','disable_ad_logoff']).default('alert'),disableMinutes:z.number().int().min(5).max(10080).default(60),enabled:z.boolean().default(false)})
function validAutomation(data){
  if(data.triggerType==='destination'&&!data.destination)return 'A destination IP address or hostname is required'
  if(data.triggerType==='mfa_failures'&&data.actionType==='disable_ad_logoff')return 'Failed MFA challenges do not identify a verified client session for logoff'
  return null
}
api.get('/security-automations',requireRole('admin'),(_req,res)=>res.json(all('SELECT * FROM security_automations ORDER BY created_at DESC')))
api.post('/security-automations',requireRole('admin'),(req,res)=>{
  const data=body(securityAutomationSchema,req),error=validAutomation(data)
  if(error)return res.status(400).json({error})
  const policyId=id(),stamp=now()
  run('INSERT INTO security_automations(id,name,trigger_type,destination,failure_count,window_minutes,cooldown_minutes,action_type,disable_minutes,enabled,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',policyId,data.name,data.triggerType,data.destination.toLowerCase(),data.failureCount,data.windowMinutes,data.cooldownMinutes,data.actionType,data.disableMinutes,Number(data.enabled),req.user.id,stamp,stamp)
  audit(req.user.id,'security.automation.create','security_automation',policyId,null,data)
  res.status(201).json(one('SELECT * FROM security_automations WHERE id=?',policyId))
})
api.patch('/security-automations/:id',requireRole('admin'),(req,res)=>{
  const before=one('SELECT * FROM security_automations WHERE id=?',reqId(req));if(!before)return notFound(res,'Security policy')
  const data=body(securityAutomationSchema,req),error=validAutomation(data)
  if(error)return res.status(400).json({error})
  run('UPDATE security_automations SET name=?,trigger_type=?,destination=?,failure_count=?,window_minutes=?,cooldown_minutes=?,action_type=?,disable_minutes=?,enabled=?,updated_at=? WHERE id=?',data.name,data.triggerType,data.destination.toLowerCase(),data.failureCount,data.windowMinutes,data.cooldownMinutes,data.actionType,data.disableMinutes,Number(data.enabled),now(),before.id)
  const after=one('SELECT * FROM security_automations WHERE id=?',before.id)
  audit(req.user.id,'security.automation.update','security_automation',before.id,before,after)
  res.json(after)
})
api.post('/security-automations/preview',requireRole('admin'),(req,res)=>{
  const data=body(securityAutomationSchema,req),error=validAutomation(data)
  if(error)return res.status(400).json({error})
  res.json(previewSecurityAutomation({trigger_type:data.triggerType,destination:data.destination,failure_count:data.failureCount,window_minutes:data.windowMinutes,created_at:new Date(Date.now()-data.windowMinutes*60_000).toISOString()}))
})
api.get('/security-automations/incidents',requireRole('admin'),(_req,res)=>res.json(all('SELECT i.*,p.name policy_name FROM security_automation_incidents i JOIN security_automations p ON p.id=i.policy_id ORDER BY i.created_at DESC LIMIT 100')))
api.get('/settings/entra',requireRole('admin'),(_req,res)=>res.json(publicEntraSettings()))
api.patch('/settings/entra',requireRole('admin'),(req,res)=>{
  const data=body(z.object({tenantId:z.uuid(),clientId:z.uuid(),clientAuthMethod:z.enum(['secret','certificate']).optional(),clientSecret:z.string().min(8).max(4096).optional(),clientCertificate:z.string().max(30000).optional(),clientPrivateKey:z.string().max(30000).optional(),enabled:z.boolean()}),req)
  res.json(saveEntraSettings(data,req.user.id))
})
api.get('/settings/mfa-prompt',requireRole('admin'),(_req,res)=>res.json(mfaPromptSettings()))
api.patch('/settings/mfa-prompt',requireRole('admin'),(req,res)=>{
  const data=body(z.object({failureMode:z.enum(['closed','open']),failOpenMinutes:z.number().int().min(2).max(15),confirmed:z.boolean().optional(),approval:z.string().optional()}),req)
  const before=mfaPromptSettings()
  if(data.failureMode==='open'&&before.failureMode!=='open'&&!data.confirmed&&data.approval!=='ENABLE MFA FAIL OPEN')return res.status(400).json({error:'Administrator confirmation is required before enabling fail-open MFA fallback'})
  db.transaction(()=>{
    run("UPDATE app_settings SET value=? WHERE key='mfa_prompt_failure_mode'",data.failureMode)
    run("UPDATE app_settings SET value=? WHERE key='mfa_prompt_fail_open_minutes'",String(data.failOpenMinutes))
    audit(req.user.id,'mfa.prompt.settings.update','app-settings','mfa-prompt',before,{failureMode:data.failureMode,failOpenMinutes:data.failOpenMinutes})
  })()
  res.json(mfaPromptSettings())
})
api.patch('/settings/portal-branding',requireRole('admin'),(req,res)=>{
  const {companyName}=body(z.object({companyName:z.string().trim().min(1).max(80)}),req)
  const before=portalBranding(),after=setPortalCompanyName(companyName)
  audit(req.user.id,'portal.branding.name','settings',null,before,after)
  res.json(after)
})
api.put('/settings/portal-branding/image',requireRole('admin'),(req,res)=>{
  const {mimeType,base64}=body(z.object({mimeType:z.string(),base64:z.string()}),req)
  const after=savePortalImage(mimeType,base64)
  audit(req.user.id,'portal.branding.image','settings',null,null,{mimeType})
  res.json(after)
})
api.delete('/settings/portal-branding/image',requireRole('admin'),(_req,res)=>{
  const after=removePortalImage()
  audit(_req.user.id,'portal.branding.image.delete','settings',null,null,null)
  res.json(after)
})
api.get('/notifications',(req,res)=>res.json(notificationSummary(req.user.id)))
api.patch('/notifications/:id/read',(req,res)=>{
  const result=run('UPDATE notifications SET read_at=COALESCE(read_at,?) WHERE id=? AND user_id=?',now(),reqId(req),req.user.id)
  return result.changes?res.json({ok:true}):notFound(res,'Notification')
})
api.post('/notifications/read-all',(req,res)=>{
  run('UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL',now(),req.user.id)
  res.json(notificationSummary(req.user.id))
})
api.post('/auth/email-verification/request',wrap(async(req,res)=>{
  if(req.user.email_verified)return res.status(409).json({error:'Email is already verified'})
  res.json(await requestEmailVerification(req.user,req.user.email,req.user.id))
}))
api.post('/auth/totp/setup',(req,res)=>{
  if(req.user.totp_secret)return res.status(409).json({error:'TOTP is already enabled'})
  const secret=makeTotpSecret()
  run('UPDATE users SET totp_pending=? WHERE id=?',seal({secret}),req.user.id)
  audit(req.user.id,'auth.totp.setup','user',req.user.id,null,null)
  res.json({secret,uri:`otpauth://totp/WinFire:${encodeURIComponent(req.user.email)}?secret=${secret}&issuer=WinFire&algorithm=SHA1&digits=6&period=30`})
})
api.post('/auth/totp/confirm',(req,res)=>{
  const {code}=body(z.object({code:z.string().regex(/^\d{6}$/)}),req)
  const pending=one('SELECT totp_pending FROM users WHERE id=?',req.user.id)?.totp_pending
  if(!pending||!verifyTotp(openSealed(pending).secret,code))return res.status(400).json({error:'Invalid TOTP code'})
  run('UPDATE users SET totp_secret=?,totp_pending=NULL WHERE id=?',pending,req.user.id)
  audit(req.user.id,'auth.totp.enable','user',req.user.id,null,null)
  res.json({enabled:true})
})
api.post('/auth/totp/disable',wrap(async(req,res)=>{
  const {password,code}=body(z.object({password:z.string(),code:z.string()}),req)
  if(!req.user.totp_secret||!await argon2.verify(req.user.password_hash,password)||!verifyTotp(openSealed(req.user.totp_secret).secret,code))return res.status(401).json({error:'Invalid credentials'})
  run('UPDATE users SET totp_secret=NULL WHERE id=?',req.user.id)
  audit(req.user.id,'auth.totp.disable','user',req.user.id,null,null)
  res.json({enabled:false})
}))
api.get('/users',requireRole('admin'),(req,res)=>res.json(all('SELECT id,email,role,team_id,suspended,created_at FROM users ORDER BY created_at DESC')))
api.get('/invites',requireRole('admin'),(_req,res)=>res.json(all('SELECT id,email,team_id,role,expires_at,accepted_at,delivered_at,created_by FROM invites ORDER BY expires_at DESC LIMIT 200')))
api.post('/invites',requireRole('admin'),wrap(async(req,res)=>{
  const data=body(z.object({email:z.email(),role:z.enum(['owner','admin','editor','auditor']).default('auditor'),teamId:z.string().optional()}),req)
  const email=data.email.toLowerCase()
  if(data.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can invite another owner'})
  if(one('SELECT id FROM users WHERE email=?',email))return res.status(409).json({error:'An account already uses this email'})
  if(data.teamId&&!one('SELECT id FROM teams WHERE id=?',data.teamId))return notFound(res,'Team')
  const token=crypto.randomBytes(32).toString('base64url'),invitationId=id(),expiresAt=new Date(Date.now()+7*864e5).toISOString()
  run('INSERT INTO invites(id,email,team_id,role,token_hash,expires_at,created_by) VALUES(?,?,?,?,?,?,?)',invitationId,email,data.teamId||null,data.role,hashToken(token),expiresAt,req.user.id)
  let delivered
  try {delivered=await deliverInvite(email,token)}
  catch(error){run('DELETE FROM invites WHERE id=?',invitationId);throw error}
  if(delivered)run('UPDATE invites SET delivered_at=? WHERE id=?',now(),invitationId)
  audit(req.user.id,'invite.create','invite',invitationId,null,{email,role:data.role,teamId:data.teamId||null,delivered})
  res.status(201).json({id:invitationId,email,role:data.role,teamId:data.teamId||null,expiresAt,delivered,inviteUrl:delivered?undefined:inviteLink(token)})
}))
api.delete('/invites/:id',requireRole('admin'),(req,res)=>{
  const invitation=one('SELECT * FROM invites WHERE id=?',reqId(req));if(!invitation)return notFound(res,'Invitation')
  if(invitation.accepted_at)return res.status(409).json({error:'Accepted invitations cannot be canceled'})
  run('DELETE FROM invites WHERE id=?',invitation.id)
  audit(req.user.id,'invite.cancel','invite',invitation.id,null,{email:invitation.email})
  res.status(204).end()
})
api.post('/users',requireRole('admin'),wrap(async(req,res)=>{
  const data=body(z.object({email:z.email(),password:z.string().min(12),role:z.enum(['owner','admin','editor','auditor']).default('auditor'),teamId:z.string().optional()}),req)
  if(data.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can create another owner'})
  const uid=id();run('INSERT INTO users(id,email,password_hash,role,team_id) VALUES(?,?,?,?,?)',uid,data.email.toLowerCase(),await argon2.hash(data.password),data.role,data.teamId||null)
  run('INSERT INTO user_profiles(user_id) VALUES(?)',uid);audit(req.user.id,'user.create','user',uid,null,{email:data.email,role:data.role});res.status(201).json(publicUser(one('SELECT * FROM users WHERE id=?',uid)))
}))
api.patch('/users/:id',requireRole('admin'),wrap(async(req,res)=>{
  const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res)
  const data=body(z.object({role:z.enum(['owner','admin','editor','auditor']).optional(),suspended:z.boolean().optional(),password:z.string().min(12).optional()}),req)
  if(user.auth_source==='ad'&&data.password)return res.status(409).json({error:'Active Directory operators must change their password in Active Directory'})
  if((user.role==='owner'||data.role==='owner')&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can manage owner accounts'})
  if(user.id===req.user.id && data.suspended) return res.status(400).json({error:'Cannot suspend yourself'})
  if(user.role==='owner'&&!user.suspended&&(data.role&&data.role!=='owner'||data.suspended)&&!one("SELECT id FROM users WHERE role='owner' AND suspended=0 AND id<>? LIMIT 1",user.id))return res.status(400).json({error:'At least one active owner is required'})
  run('UPDATE users SET role=?,suspended=?,password_hash=?,session_version=? WHERE id=?',data.role||user.role,data.suspended===undefined?user.suspended:Number(data.suspended),data.password?await argon2.hash(data.password):user.password_hash,user.session_version+(data.password?1:0),user.id)
  if(data.suspended||data.password)run('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=?',now(),user.id)
  audit(req.user.id,'user.update','user',user.id,publicUser(user),{role:data.role,suspended:data.suspended,passwordChanged:!!data.password});res.json(publicUser(one('SELECT * FROM users WHERE id=?',user.id)))
}))
api.delete('/users/:id',requireRole('owner'),(req,res)=>{if(reqId(req)===req.user.id)return res.status(400).json({error:'Cannot delete yourself'});const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res);removeAvatar(user.id);run('DELETE FROM users WHERE id=?',user.id);audit(req.user.id,'user.delete','user',user.id,publicUser(user),null);res.status(204).end()})
api.post('/users/:id/revoke-sessions',requireRole('admin'),(req,res)=>{
  const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res)
  if(user.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can manage owner accounts'})
  db.transaction(()=>{run('UPDATE users SET session_version=session_version+1 WHERE id=?',user.id);run('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=?',now(),user.id);audit(req.user.id,'user.sessions.revoke','user',user.id,null,null)})()
  res.json({revoked:true})
})
api.patch('/users/:id/profile',wrap(async(req,res)=>{
  if(reqId(req)!==req.user.id && !['owner','admin'].includes(req.user.role))return res.status(403).json({error:'Insufficient permission'})
  const data=body(z.object({theme:z.enum(['system','hacker','enterprise','dark','light']).optional(),notificationPrefs:z.record(z.string(),z.boolean()).refine(value=>Object.keys(value).every(key=>preferenceKeys.includes(key)),'Unknown notification preference').optional(),email:z.email().optional(),password:z.string().min(12).optional(),currentPassword:z.string().optional()}),req)
  const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res)
  if(user.auth_source==='ad'&&(data.password||data.email))return res.status(409).json({error:'Active Directory manages this operator’s email and password'})
  if(user.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can manage owner accounts'})
  if(data.password&&user.id===req.user.id&&(!data.currentPassword||!await argon2.verify(user.password_hash,data.currentPassword)))return res.status(401).json({error:'Current password is incorrect'})
  const emailChangeRequested=!!(data.email&&data.email.toLowerCase()!==user.email)
  if(emailChangeRequested)await requestEmailVerification(user,data.email.toLowerCase(),req.user.id)
  if(data.password){run('UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?',await argon2.hash(data.password),user.id);run('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=?',now(),user.id)}
  const prior=one('SELECT * FROM user_profiles WHERE user_id=?',user.id)
  run('UPDATE user_profiles SET theme=?,notification_prefs=? WHERE user_id=?',data.theme||prior.theme,data.notificationPrefs?json(data.notificationPrefs):prior.notification_prefs,user.id)
  audit(req.user.id,'user.profile','user',user.id,null,{theme:data.theme,emailChangeRequested,passwordChanged:!!data.password,notificationPrefsChanged:!!data.notificationPrefs});res.json({...one('SELECT avatar_url,theme,notification_prefs FROM user_profiles WHERE user_id=?',user.id),emailChangeRequested})
}))
api.put('/users/:id/avatar',(req,res)=>{
  const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res,'User')
  if(user.id!==req.user.id&&req.user.role!=='owner'&&req.user.role!=='admin')return res.status(403).json({error:'Insufficient permission'})
  if(user.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can manage owner accounts'})
  const data=body(z.object({mimeType:z.string(),base64:z.string()}),req)
  const avatarUrl=saveAvatar(user.id,data.mimeType,data.base64)
  audit(req.user.id,'user.avatar.update','user',user.id,null,{avatarUrl})
  res.json({avatarUrl})
})
api.delete('/users/:id/avatar',(req,res)=>{
  const user=one('SELECT * FROM users WHERE id=?',reqId(req));if(!user)return notFound(res,'User')
  if(user.id!==req.user.id&&req.user.role!=='owner'&&req.user.role!=='admin')return res.status(403).json({error:'Insufficient permission'})
  if(user.role==='owner'&&req.user.role!=='owner')return res.status(403).json({error:'Only an owner can manage owner accounts'})
  removeAvatar(user.id);audit(req.user.id,'user.avatar.delete','user',user.id,null,null);res.status(204).end()
})
api.get('/teams',(_req,res)=>res.json(all('SELECT * FROM teams ORDER BY name')))
api.post('/teams',requireRole('admin'),(req,res)=>{const data=body(z.object({name:z.string().min(1)}),req),teamId=id();run('INSERT INTO teams(id,name) VALUES(?,?)',teamId,data.name);audit(req.user.id,'team.create','team',teamId,null,data);res.status(201).json(one('SELECT * FROM teams WHERE id=?',teamId))})
api.patch('/teams/:id',requireRole('admin'),(req,res)=>{
  const team=one('SELECT * FROM teams WHERE id=?',reqId(req));if(!team)return notFound(res,'Team')
  const {name}=body(z.object({name:z.string().trim().min(1)}),req)
  run('UPDATE teams SET name=? WHERE id=?',name,team.id)
  audit(req.user.id,'team.update','team',team.id,team,{name})
  res.json(one('SELECT * FROM teams WHERE id=?',team.id))
})
api.delete('/teams/:id',requireRole('admin'),(req,res)=>{
  const team=one('SELECT * FROM teams WHERE id=?',reqId(req));if(!team)return notFound(res,'Team')
  db.transaction(()=>{
    run('UPDATE users SET team_id=NULL WHERE team_id=?',team.id)
    run("UPDATE credentials SET visibility='private',team_id=NULL WHERE team_id=?",team.id)
    run('UPDATE invites SET team_id=NULL WHERE team_id=?',team.id)
    run('DELETE FROM teams WHERE id=?',team.id)
    audit(req.user.id,'team.delete','team',team.id,team,null)
  })()
  res.status(204).end()
})
api.post('/teams/:id/members',requireRole('admin'),(req,res)=>{
  const data=body(z.object({userId:z.string()}),req)
  if(!one('SELECT id FROM teams WHERE id=?',reqId(req)))return notFound(res,'Team')
  if(!one('SELECT id FROM users WHERE id=?',data.userId))return notFound(res,'User')
  db.transaction(()=>{
    run('DELETE FROM team_members WHERE user_id=?',data.userId)
    run('INSERT INTO team_members(team_id,user_id) VALUES(?,?)',reqId(req),data.userId)
    run('UPDATE users SET team_id=? WHERE id=?',reqId(req),data.userId)
    audit(req.user.id,'team.member.add','team',reqId(req),null,data)
  })()
  res.json({ok:true})
})
api.delete('/teams/:id/members/:userId',requireRole('admin'),(req,res)=>{
  const team=one('SELECT * FROM teams WHERE id=?',reqId(req));if(!team)return notFound(res,'Team')
  const membership=one('SELECT 1 FROM team_members WHERE team_id=? AND user_id=?',team.id,req.params.userId)
  if(!membership)return notFound(res,'Membership')
  db.transaction(()=>{
    run('DELETE FROM team_members WHERE team_id=? AND user_id=?',team.id,req.params.userId)
    run('UPDATE users SET team_id=NULL WHERE id=? AND team_id=?',req.params.userId,team.id)
    audit(req.user.id,'team.member.remove','team',team.id,null,{userId:req.params.userId})
  })()
  res.status(204).end()
})
api.get('/roles',(_req,res)=>res.json([{id:'owner',name:'Owner'},{id:'admin',name:'Admin'},{id:'editor',name:'Policy Editor'},{id:'auditor',name:'Auditor'}]))
api.get('/access/users',requireRole('editor'),(req,res)=>res.json(all('SELECT id,email,role FROM users WHERE suspended=0 AND id<>? ORDER BY email',req.user.id)))
api.get('/access/resources',requireRole('editor'),(req,res)=>{
  const resources=[
    ...all('SELECT id,name,owner_user_id FROM policies').map(item=>({...item,type:'policy'})),
    ...all("SELECT id,name,owner_user_id FROM node_groups WHERE id<>'winfire-global-all-nodes'").map(item=>({...item,type:'node_group'})),
    ...all('SELECT id,name,owner_user_id FROM credentials').map(item=>({...item,type:'credential'}))
  ]
  res.json(resources.filter(item=>canWriteResource(req.user,item.type,item)).map(({id,name,type})=>({id,name,type})).sort((a,b)=>a.type.localeCompare(b.type)||a.name.localeCompare(b.name)))
})
const resourceType=z.enum(['policy','node_group','credential'])
api.get('/access/grants',requireRole('editor'),(req,res)=>{
  const {type,resourceId}=z.object({type:resourceType,resourceId:z.string().min(1)}).parse(req.query)
  const resource=resourceRecord(type,resourceId);if(!resource)return notFound(res,'Resource')
  if(!canWriteResource(req.user,type,resource))return res.status(403).json({error:'Insufficient permission'})
  res.json(all('SELECT g.id,g.grantee_user_id,g.permission,g.created_at,u.email FROM resource_grants g JOIN users u ON u.id=g.grantee_user_id WHERE g.resource_type=? AND g.resource_id=? ORDER BY u.email',type,resourceId))
})
api.post('/access/grants',requireRole('editor'),(req,res)=>{
  const data=body(z.object({type:resourceType,resourceId:z.string().min(1),userId:z.string().min(1),permission:z.enum(['read','write'])}),req)
  if(data.type==='node_group'&&data.resourceId==='winfire-global-all-nodes')return res.status(409).json({error:'Global policy scope is managed by administrators'})
  const resource=resourceRecord(data.type,data.resourceId);if(!resource)return notFound(res,'Resource')
  if(!canWriteResource(req.user,data.type,resource))return res.status(403).json({error:'Insufficient permission'})
  const grantee=one('SELECT id,role,suspended FROM users WHERE id=?',data.userId);if(!grantee)return notFound(res,'User')
  if(grantee.suspended)return res.status(400).json({error:'Cannot grant access to a suspended user'})
  if(data.permission==='write'&&grantee.role==='auditor')return res.status(400).json({error:'Auditors cannot receive write grants'})
  const grantId=id()
  db.transaction(()=>{
    run('INSERT INTO resource_grants(id,resource_type,resource_id,grantee_user_id,permission,created_by) VALUES(?,?,?,?,?,?) ON CONFLICT(resource_type,resource_id,grantee_user_id) DO UPDATE SET permission=excluded.permission,created_by=excluded.created_by',grantId,data.type,data.resourceId,data.userId,data.permission,req.user.id)
    audit(req.user.id,'resource.grant','resource',data.resourceId,null,{type:data.type,userId:data.userId,permission:data.permission})
  })()
  res.status(201).json({type:data.type,resourceId:data.resourceId,userId:data.userId,permission:data.permission})
})
api.delete('/access/grants/:id',requireRole('editor'),(req,res)=>{
  const grant=one('SELECT * FROM resource_grants WHERE id=?',reqId(req));if(!grant)return notFound(res,'Grant')
  const resource=resourceRecord(grant.resource_type,grant.resource_id);if(!resource)return notFound(res,'Resource')
  if(!canWriteResource(req.user,grant.resource_type,resource))return res.status(403).json({error:'Insufficient permission'})
  db.transaction(()=>{run('DELETE FROM resource_grants WHERE id=?',grant.id);audit(req.user.id,'resource.grant.revoke','resource',grant.resource_id,{type:grant.resource_type,userId:grant.grantee_user_id,permission:grant.permission},null)})()
  res.status(204).end()
})
api.get('/audit',requireRole('auditor'),(req,res)=>res.json(all('SELECT * FROM audit_log ORDER BY at DESC LIMIT 500')))
api.get('/audit/search',requireRole('auditor'),(req,res)=>{
  const query=z.object({q:z.string().max(200).optional(),action:z.string().max(100).optional(),entityType:z.string().max(100).optional(),actor:z.string().max(200).optional(),from:z.iso.datetime({offset:true}).optional(),to:z.iso.datetime({offset:true}).optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(500).default(100),sortBy:z.enum(['time','action','entity','actor']).default('time'),sortDir:z.enum(['asc','desc']).default('desc'),export:z.enum(['csv','pdf','xls']).optional()}).parse(req.query)
  const conditions=[],values=[]
  for(const [field,column] of [['action','a.action'],['entityType','a.entity_type']])if(query[field]){conditions.push(`${column}=?`);values.push(query[field])}
  if(query.actor){conditions.push('(u.email LIKE ? OR a.actor_user_id LIKE ?)');values.push(`%${query.actor}%`,`%${query.actor}%`)}
  if(query.q){conditions.push('(a.action LIKE ? OR a.entity_type LIKE ? OR a.entity_id LIKE ? OR u.email LIKE ?)');values.push(...Array(4).fill(`%${query.q}%`))}
  if(query.from){conditions.push('a.at>=?');values.push(query.from)}
  if(query.to){conditions.push('a.at<=?');values.push(query.to)}
  const where=conditions.length?'WHERE '+conditions.join(' AND '):''
  const fromSql=`FROM audit_log a LEFT JOIN users u ON u.id=a.actor_user_id ${where}`
  const sortColumn={time:'a.at',action:'a.action',entity:'a.entity_type',actor:'u.email'}[query.sortBy]
  const total=one(`SELECT COUNT(*) count ${fromSql}`,...values).count
  const limit=query.export?50000:query.pageSize,offset=query.export?0:(query.page-1)*query.pageSize
  const items=all(`SELECT a.id,a.at,a.action,a.entity_type,a.entity_id,a.actor_user_id,u.email actor_email ${fromSql} ORDER BY ${sortColumn} ${query.sortDir.toUpperCase()},a.id DESC LIMIT ? OFFSET ?`,...values,limit,offset)
  if(!query.export)return res.json({items,total,page:query.page,pageSize:query.pageSize,totalPages:Math.ceil(total/query.pageSize)})
  const fields=['at','action','entity_type','entity_id','actor_email','actor_user_id']
  if(query.export==='csv'){
    const cell=value=>`"${String(value??'').replace(/^[=+\-@]/,"'$&").replaceAll('"','""')}"`
    return res.type('text/csv').attachment('audit-trail.csv').send([fields.join(','),...items.map(row=>fields.map(key=>cell(row[key])).join(','))].join('\n'))
  }
  if(query.export==='xls'){
    const xml=value=>String(value??'').replace(/[<>&"']/g,char=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&apos;'}[char]))
    const row=values=>`<Row>${values.map(value=>`<Cell><Data ss:Type="String">${xml(value)}</Data></Cell>`).join('')}</Row>`
    const sheet=`<?xml version="1.0"?><Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"><Worksheet ss:Name="Audit trail"><Table>${row(fields)}${items.map(item=>row(fields.map(key=>item[key]))).join('')}</Table></Worksheet></Workbook>`
    return res.type('application/vnd.ms-excel').attachment('audit-trail.xls').send(sheet)
  }
  res.type('application/pdf').attachment('audit-trail.pdf')
  const pdf=new PDFDocument({margin:38});pdf.pipe(res);pdf.fontSize(16).text('WinFire audit trail');pdf.fontSize(8).text(`Generated ${now()} · ${items.length} of ${total} matching records`);pdf.moveDown()
  for(const item of items){pdf.fontSize(8).text(`${item.at}  ${item.action}  ${item.entity_type}/${item.entity_id||'—'}  ${item.actor_email||'system'}`,{width:520});pdf.moveDown(.25)}
  pdf.end()
})
const publicTrainingSettings=()=>({newHostTrainingDays:trainingDays(),progressiveLearning:progressiveSettings()})
api.get('/settings/training',(_req,res)=>res.json(publicTrainingSettings()))
api.get('/settings/agent-poll',requireRole('admin'),(_req,res)=>res.json(agentPollSettings()))
api.put('/settings/agent-poll',requireRole('admin'),(req,res)=>{
  const data=body(z.object({targetType:z.enum(['node','group']),targetId:z.string().min(1),pollSeconds:z.number().int().min(15).max(300).nullable(),channelMode:z.enum(['pull','push']).default('pull')}),req)
  const target=data.targetType==='node'?one('SELECT id FROM nodes WHERE id=?',data.targetId):one('SELECT id FROM node_groups WHERE id=?',data.targetId)
  if(!target)return notFound(res,data.targetType==='node'?'Node':'Node group')
  const before=one('SELECT poll_seconds,channel_mode FROM agent_poll_settings WHERE target_type=? AND target_id=?',data.targetType,data.targetId)||null
  db.transaction(()=>{
    if(data.pollSeconds===null&&data.channelMode==='pull')run('DELETE FROM agent_poll_settings WHERE target_type=? AND target_id=?',data.targetType,data.targetId)
    else run(`INSERT INTO agent_poll_settings(target_type,target_id,poll_seconds,channel_mode,updated_at) VALUES(?,?,?,?,?)
      ON CONFLICT(target_type,target_id) DO UPDATE SET poll_seconds=excluded.poll_seconds,channel_mode=excluded.channel_mode,updated_at=excluded.updated_at`,data.targetType,data.targetId,data.pollSeconds??30,data.channelMode,now())
    audit(req.user.id,'agent.poll.configure',data.targetType,data.targetId,before,{pollSeconds:data.pollSeconds,channelMode:data.channelMode})
  })()
  res.json(agentPollSettings())
})
api.patch('/settings/training',requireRole('admin'),(req,res)=>{
  const data=body(z.object({newHostTrainingDays:z.number().int().min(1).max(365),progressiveLearning:z.object({enabled:z.boolean(),startDays:z.number().int().min(1).max(364),intervalHours:z.number().int().min(1).max(168)}).optional()}),req)
  const before=publicTrainingSettings()
  if(data.progressiveLearning?.enabled&&data.progressiveLearning.startDays>=data.newHostTrainingDays)return res.status(400).json({error:'Progressive learning must start before the training period ends'})
  db.transaction(()=>{
    run("UPDATE app_settings SET value=? WHERE key='new_host_training_days'",String(data.newHostTrainingDays))
    if(data.progressiveLearning){
      for(const [key,value] of [['progressive_learning_enabled',data.progressiveLearning.enabled],['progressive_learning_start_days',data.progressiveLearning.startDays],['progressive_learning_interval_hours',data.progressiveLearning.intervalHours]])run('UPDATE app_settings SET value=? WHERE key=?',String(value),key)
    }
    audit(req.user.id,'training.settings.update','app-settings','training',before,{newHostTrainingDays:data.newHostTrainingDays,progressiveLearning:data.progressiveLearning||before.progressiveLearning})
  })()
  res.json(publicTrainingSettings())
})
api.get('/settings/observability',requireRole('admin'),(_req,res)=>res.json(observabilitySettings()))
const serverFqdnSchema=z.string().trim().max(253).refine(value=>!value||/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(value),{message:'FQDN may contain letters, numbers, dots, and hyphens'})
const serverPublicUrlSchema=z.string().trim().max(2048).refine(value=>{
  if(!value)return true
  try{const parsed=new URL(value);return ['http:','https:'].includes(parsed.protocol)&&!parsed.username&&!parsed.password&&!parsed.hash&&!parsed.search}catch{return false}
},{message:'Public base URL must be an absolute HTTP or HTTPS URL without credentials, query, or fragment'})
api.get('/settings/server',requireRole('admin'),(req,res)=>res.json({
  fqdn:effectiveServerFqdn()||null,
  configuredFqdn:serverFqdn()||null,
  fqdnSource:process.env.SERVER_FQDN?'environment':serverFqdn()?'administration':'unset',
  publicBaseUrl:effectivePublicBaseUrl(req),
  configuredPublicBaseUrl:serverPublicBaseUrl()||null,
  publicBaseUrlConfigured:!!(process.env.PUBLIC_BASE_URL||serverPublicBaseUrl()),
  publicBaseUrlSource:process.env.PUBLIC_BASE_URL?'environment':serverPublicBaseUrl()?'administration':'request',
  localCidrs:localAssetCidrs(),
  environmentOverrides:{fqdn:!!process.env.SERVER_FQDN,publicBaseUrl:!!process.env.PUBLIC_BASE_URL},
}))
api.patch('/settings/server',requireRole('admin'),(req,res)=>{
  const data=body(z.object({fqdn:serverFqdnSchema,publicBaseUrl:serverPublicUrlSchema,localCidrs:z.array(localAssetCidrSchema).max(256).default([])}),req)
  if(process.env.SERVER_FQDN&&data.fqdn&&data.fqdn!==process.env.SERVER_FQDN.trim())return res.status(409).json({error:'SERVER_FQDN is configured by the deployment environment; change that value instead'})
  if(process.env.PUBLIC_BASE_URL&&data.publicBaseUrl&&data.publicBaseUrl!==process.env.PUBLIC_BASE_URL.trim())return res.status(409).json({error:'PUBLIC_BASE_URL is configured by the deployment environment; change that value instead'})
  const before={fqdn:serverFqdn()||null,publicBaseUrl:serverPublicBaseUrl()||null,localCidrs:localAssetCidrs()}
  const next={fqdn:data.fqdn||'',publicBaseUrl:data.publicBaseUrl||'',localCidrs:data.localCidrs}
  db.transaction(()=>{
    if(!process.env.SERVER_FQDN)run("INSERT INTO app_settings(key,value) VALUES('server_fqdn',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",next.fqdn)
    if(!process.env.PUBLIC_BASE_URL)run("INSERT INTO app_settings(key,value) VALUES('server_public_base_url',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",next.publicBaseUrl)
    run("INSERT INTO app_settings(key,value) VALUES('local_asset_cidrs',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",json(next.localCidrs))
    audit(req.user.id,'server.settings.update','app-settings','server',before,next)
  })()
  res.json({fqdn:process.env.SERVER_FQDN||next.fqdn||null,configuredFqdn:next.fqdn||null,fqdnSource:process.env.SERVER_FQDN?'environment':next.fqdn?'administration':'unset',publicBaseUrl:effectivePublicBaseUrl(req),configuredPublicBaseUrl:next.publicBaseUrl||null,publicBaseUrlConfigured:!!(process.env.PUBLIC_BASE_URL||next.publicBaseUrl),publicBaseUrlSource:process.env.PUBLIC_BASE_URL?'environment':next.publicBaseUrl?'administration':'request',localCidrs:next.localCidrs,environmentOverrides:{fqdn:!!process.env.SERVER_FQDN,publicBaseUrl:!!process.env.PUBLIC_BASE_URL}})
})
api.get('/settings/wef',requireRole('admin'),(req,res)=>res.json(publicWef(req)))
api.patch('/settings/wef',requireRole('admin'),(req,res)=>{
  const data=body(z.object({enabled:z.boolean(),sharedSecret:z.string().trim().min(8).max(512).optional(),clearSecret:z.boolean().optional()}),req)
  if(process.env.WEF_SHARED_SECRET&&(data.sharedSecret!==undefined||data.clearSecret))return res.status(409).json({error:'WEF_SHARED_SECRET is configured by the deployment environment; change that value instead'})
  const nextSecret=data.clearSecret?'':data.sharedSecret??wefSecret()
  if(data.enabled&&!nextSecret)return res.status(503).json({error:'Configure a WEF shared secret before enabling WEF push'})
  const before=wefEnabled()
  db.transaction(()=>{
    if(!process.env.WEF_SHARED_SECRET&&(data.sharedSecret!==undefined||data.clearSecret))run("INSERT INTO app_settings(key,value) VALUES('wef_shared_secret_sealed',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",nextSecret?seal({secret:nextSecret}):'')
    run("UPDATE app_settings SET value=? WHERE key='wef_enabled'",String(data.enabled))
    audit(req.user.id,'wef.settings.update','app-settings','wef',{enabled:before,secretConfigured:!!wefSecret()},{enabled:data.enabled,secretConfigured:!!nextSecret,secretSource:process.env.WEF_SHARED_SECRET?'environment':data.sharedSecret!==undefined||data.clearSecret?'administration':wefSecretSource()})
  })()
  res.json(publicWef(req))
})
api.get('/settings/process-exclusions',requireRole('admin'),(_req,res)=>res.json({names:all('SELECT name FROM process_exclusions ORDER BY name').map(row=>row.name)}))
api.put('/settings/process-exclusions',requireRole('admin'),(req,res)=>{
  const {names:rawNames}=body(z.object({names:z.array(z.string()).max(200)}),req)
  let names
  try{names=normalizeProcessExclusions(rawNames)}catch(error){return res.status(400).json({error:error.message})}
  const before=all('SELECT name FROM process_exclusions ORDER BY name').map(row=>row.name)
  db.transaction(()=>{
    run('DELETE FROM process_exclusions')
    for(const name of names)run('INSERT INTO process_exclusions(name,added_at) VALUES(?,?)',name,now())
    audit(req.user.id,'process-exclusions.update','settings','global',{names:before},{names})
  })()
  refreshProcessExclusions(db)
  res.json({names})
})
const classifierProtocol=z.enum(['ANY','TCP','UDP','SCTP','DCCP','ICMP','ICMPv6','IGMP','IPv6-in-IPv4','GRE','ESP','AH','OSPF'])
const classifierRuleBody=z.object({
  protocol:classifierProtocol,
  portStart:z.number().int().min(1).max(65535).nullable().optional(),
  portEnd:z.number().int().min(1).max(65535).nullable().optional(),
  service:z.string().trim().min(1).max(160),
  description:z.string().trim().max(500).optional().default(''),
  priority:z.number().int().min(1).max(10000).default(10),
  enabled:z.boolean().default(true),
}).superRefine((value,ctx)=>{
  const start=value.portStart??null,end=value.portEnd??null
  if((start===null)!==(end===null))ctx.addIssue({code:'custom',path:['portStart'],message:'Provide both port bounds or leave both empty for a protocol rule'})
  if(start!==null&&end!==null&&start>end)ctx.addIssue({code:'custom',path:['portEnd'],message:'Port end must be greater than or equal to port start'})
  if((value.protocol==='ICMP'||value.protocol==='ICMPv6'||value.protocol==='IGMP')&&(start!==null||end!==null))ctx.addIssue({code:'custom',path:['portStart'],message:'ICMP and IGMP rules do not use ports'})
})
api.get('/settings/classifier',requireRole('admin'),(req,res)=>{
  const query=z.object({search:z.string().max(200).optional(),protocol:z.string().max(32).optional(),source:z.enum(['built-in','iana','custom']).optional(),enabled:z.enum(['true','false']).optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(10).max(500).default(100),sortBy:z.enum(['port','protocol','service','source','priority','enabled']).default('port'),sortDir:z.enum(['asc','desc']).default('asc')}).parse(req.query)
  res.json(classifierRuleRows(query))
})
api.post('/settings/classifier/rules',requireRole('admin'),(req,res)=>{
  const data=body(classifierRuleBody,req),rule=createClassifierRule(data,req.user.id)
  audit(req.user.id,'classifier-rule.create','classifier-rule',rule.id,null,rule)
  res.status(201).json(rule)
})
api.patch('/settings/classifier/rules/:id',requireRole('admin'),(req,res)=>{
  const data=body(classifierRuleBody,req),before=classifierRuleById(req.params.id)
  const rule=updateClassifierRule(req.params.id,data,req.user.id)
  if(!rule)return notFound(res,'Classifier rule')
  audit(req.user.id,'classifier-rule.update','classifier-rule',rule.id,before,rule)
  res.json(rule)
})
api.delete('/settings/classifier/rules/:id',requireRole('admin'),(req,res)=>{
  const before=classifierRuleById(req.params.id)
  if(!deleteClassifierRule(req.params.id,req.user.id))return notFound(res,'Classifier rule')
  audit(req.user.id,'classifier-rule.delete','classifier-rule',req.params.id,before,null)
  res.status(204).end()
})
const classifierProcessRuleBody=z.object({
  executablePattern:z.string().trim().min(1).max(512),
  service:z.string().trim().min(1).max(160),
  description:z.string().trim().max(500).optional().default(''),
  priority:z.number().int().min(1).max(10000).default(10),
  enabled:z.boolean().default(true),
})
api.get('/settings/classifier/process-rules',requireRole('admin'),(req,res)=>{
  const query=z.object({search:z.string().max(200).optional(),source:z.enum(['built-in','custom']).optional(),enabled:z.enum(['true','false']).optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(10).max(500).default(100),sortBy:z.enum(['pattern','service','source','priority','enabled']).default('priority'),sortDir:z.enum(['asc','desc']).default('asc')}).parse(req.query)
  res.json(processRuleRows(query))
})
api.post('/settings/classifier/process-rules',requireRole('admin'),(req,res)=>{
  const data=body(classifierProcessRuleBody,req),rule=createProcessRule(data,req.user.id)
  audit(req.user.id,'classifier-process-rule.create','classifier-process-rule',rule.id,null,rule)
  res.status(201).json(rule)
})
api.patch('/settings/classifier/process-rules/:id',requireRole('admin'),(req,res)=>{
  const data=body(classifierProcessRuleBody,req),before=processRuleById(req.params.id)
  const rule=updateProcessRule(req.params.id,data,req.user.id)
  if(!rule)return notFound(res,'Classifier process rule')
  audit(req.user.id,'classifier-process-rule.update','classifier-process-rule',rule.id,before,rule)
  res.json(rule)
})
api.delete('/settings/classifier/process-rules/:id',requireRole('admin'),(req,res)=>{
  const before=processRuleById(req.params.id)
  if(!deleteProcessRule(req.params.id,req.user.id))return notFound(res,'Classifier process rule')
  audit(req.user.id,'classifier-process-rule.disable','classifier-process-rule',req.params.id,before,null)
  res.status(204).end()
})
api.get('/settings/traffic-ignores',requireRole('admin'),(_req,res)=>res.json(all('SELECT * FROM traffic_ignore_rules ORDER BY created_at DESC,id DESC').map(publicTrafficIgnore)))
api.post('/settings/traffic-ignores',requireRole('admin'),(req,res)=>{
  const data=body(z.object({label:z.string().trim().min(1).max(120),eventId:z.number().int(),action:z.string().nullable().optional(),protocol:z.string().nullable().optional(),srcIp:z.string().nullable().optional(),dstIp:z.string().nullable().optional(),dstPort:z.number().int().nullable().optional(),direction:z.string().nullable().optional(),program:z.string().nullable().optional(),accountSid:z.string().nullable().optional(),accountSids:z.array(z.string().trim().min(1).max(184)).max(200).optional()}),req)
  const accountSids=[...new Set([...(data.accountSids||[]),...(data.accountSid?[data.accountSid]:[])])]
  const candidates=accountSids.length?accountSids:[null]
  const patterns=[]
  try{for(const accountSid of candidates)patterns.push(normalizeTrafficIgnore({...data,accountSid}))}catch(error){return res.status(400).json({error:error.message})}
  const uniquePatterns=[...new Map(patterns.map(pattern=>[trafficIgnoreFingerprint(pattern),pattern])).values()]
  const existing=new Set(all(`SELECT fingerprint FROM traffic_ignore_rules WHERE fingerprint IN (${uniquePatterns.map(()=>'?').join(',')})`,...uniquePatterns.map(trafficIgnoreFingerprint)).map(row=>row.fingerprint))
  const pending=uniquePatterns.filter(pattern=>!existing.has(trafficIgnoreFingerprint(pattern)))
  if(!pending.length)return res.status(409).json({error:'All requested traffic ignore rules already exist'})
  const createdIds=[]
  db.transaction(()=>{
    for(const pattern of pending){
      const ruleId=id();createdIds.push(ruleId)
      run('INSERT INTO traffic_ignore_rules(id,label,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,program,account_sid,fingerprint,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',ruleId,data.label,pattern.eventId,pattern.action,pattern.protocol,pattern.srcIp,pattern.dstIp,pattern.dstPort,pattern.direction,pattern.program,pattern.accountSid,trafficIgnoreFingerprint(pattern),req.user.id,now())
      audit(req.user.id,'traffic-ignore.create','settings',ruleId,null,{...publicTrafficIgnore(one('SELECT * FROM traffic_ignore_rules WHERE id=?',ruleId)),accountGroup:accountSids.length>1})
    }
  })()
  refreshTrafficIgnores(db)
  const created=createdIds.map(ruleId=>publicTrafficIgnore(one('SELECT * FROM traffic_ignore_rules WHERE id=?',ruleId)))
  res.status(201).json({rules:created,created:created.length,skipped:uniquePatterns.length-pending.length})
})
api.delete('/settings/traffic-ignores/:id',requireRole('admin'),(req,res)=>{
  const before=one('SELECT * FROM traffic_ignore_rules WHERE id=?',reqId(req));if(!before)return notFound(res,'Traffic ignore rule')
  run('DELETE FROM traffic_ignore_rules WHERE id=?',before.id)
  refreshTrafficIgnores(db)
  audit(req.user.id,'traffic-ignore.delete','settings',before.id,publicTrafficIgnore(before),null)
  res.json({ok:true})
})
api.post('/settings/traffic-ignores/cleanup',requireRole('admin'),(req,res)=>{
  const data=body(z.object({confirmed:z.literal(true)}),req)
  if(!data.confirmed)return res.status(400).json({error:'Cleanup confirmation is required'})
  const loopback=observabilitySettings().ignoreLoopbackIngest
  const firewall=`(e.event_id IN (5150,5151,5156,5157) OR COALESCE(e.event_type,p.event_type)='firewall')`
  const process=`(${firewall} AND winfire_excluded_process(COALESCE(e.program,p.program)))`
  const traffic=`(${trafficIgnoreMatchSql()}=1)`
  const local=loopback?`((COALESCE(e.src_ip,p.src_ip,'') LIKE '127.%' OR COALESCE(e.src_ip,p.src_ip,'') IN ('::1','0:0:0:0:0:0:0:1')) AND (COALESCE(e.dst_ip,p.dst_ip,'') LIKE '127.%' OR COALESCE(e.dst_ip,p.dst_ip,'') IN ('::1','0:0:0:0:0:0:0:1')))`:'0'
  const before=one('SELECT COUNT(*) count FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE '+`(${process} OR ${traffic} OR ${local})`).count
  const deleted=db.transaction(()=>{
    const result=run(`DELETE FROM log_events WHERE id IN (SELECT e.id FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE (${process} OR ${traffic} OR ${local}))`)
    run('DELETE FROM event_patterns WHERE NOT EXISTS (SELECT 1 FROM log_events e WHERE e.pattern_id=event_patterns.id)')
    return result.changes
  })()
  audit(req.user.id,'traffic-ignore.cleanup','settings','global',{matching:Number(before)},{deleted,loopbackIncluded:loopback})
  res.json({deleted,loopbackIncluded:loopback})
})
api.get('/settings/logs-display',(_req,res)=>res.json({hideLoopbackEvents:observabilitySettings().hideLoopbackEvents}))
api.patch('/settings/observability',requireRole('admin'),(req,res)=>{
  const data=body(z.object({logRetentionDays:z.number().int().min(1).max(3650),dnsRefreshHours:z.number().int().min(1).max(720),eventCompactHours:z.number().int().min(1).max(720).optional(),dynamicNodeGroupsIntervalMinutes:z.number().int().min(5).max(10080).optional(),hideLoopbackEvents:z.boolean().optional(),ignoreLoopbackIngest:z.boolean().optional()}),req)
  const before=observabilitySettings()
  db.transaction(()=>{
    run("UPDATE app_settings SET value=? WHERE key='log_retention_days'",String(data.logRetentionDays))
    run("UPDATE app_settings SET value=? WHERE key='dns_refresh_hours'",String(data.dnsRefreshHours))
    if(data.eventCompactHours!==undefined)run("UPDATE app_settings SET value=? WHERE key='event_compact_hours'",String(data.eventCompactHours))
    if(data.dynamicNodeGroupsIntervalMinutes!==undefined)run("UPDATE app_settings SET value=? WHERE key='dynamic_node_groups_interval_minutes'",String(data.dynamicNodeGroupsIntervalMinutes))
    if(data.dynamicNodeGroupsIntervalMinutes!==undefined)run("UPDATE node_groups SET dynamic_next_evaluation_at=? WHERE dynamic_enabled=1",now())
    if(data.hideLoopbackEvents!==undefined)run("UPDATE app_settings SET value=? WHERE key='hide_loopback_events'",String(data.hideLoopbackEvents))
    if(data.ignoreLoopbackIngest!==undefined)run("UPDATE app_settings SET value=? WHERE key='ignore_loopback_ingest'",String(data.ignoreLoopbackIngest))
    audit(req.user.id,'observability.settings.update','app-settings','observability',before,data)
  })()
  res.json(observabilitySettings())
})
api.get('/settings/directory',requireRole('admin'),(_req,res)=>res.json(publicDirectory(directorySettings())))
api.patch('/settings/directory',requireRole('admin'),(req,res)=>{
  const data=body(z.object({
    url:z.string().url().refine(value=>{const parsed=new URL(value);return parsed.protocol==='ldaps:'&&!parsed.username&&!parsed.password&&parsed.pathname==='/'&&!parsed.search&&!parsed.hash},{message:'Use an ldaps:// server URL without embedded credentials or query parameters'}),
    baseDn:z.string().min(3).max(512).refine(value=>/(^|,)\s*DC=/i.test(value),{message:'Search base must include a DC component'}),
    bindCredentialId:z.string().min(1),nodeCredentialId:z.string().nullable().optional(),enabled:z.boolean().default(false),syncIntervalMinutes:z.number().int().min(5).max(1440).default(60),allowLdapFallback:z.boolean().optional(),ldapFallbackApproved:z.boolean().optional(),ldapFallbackApproval:z.string().optional()
  }),req)
  for(const credentialId of [data.bindCredentialId,data.nodeCredentialId].filter(Boolean)){
    const credential=one('SELECT * FROM credentials WHERE id=?',credentialId)
    if(!credential||!canUseCredential(req.user,credential))return res.status(400).json({error:'Selected directory credential is unavailable'})
  }
  const prior=directorySettings(),before=publicDirectory(prior)
  const allowLdapFallback=data.allowLdapFallback===undefined?!!prior.allow_ldap_fallback:data.allowLdapFallback
  const scopeChanged=data.url!==prior.url||data.bindCredentialId!==prior.bind_credential_id
  const needsApproval=allowLdapFallback&&(!prior.allow_ldap_fallback||!prior.ldap_fallback_approved_at||scopeChanged)
  if(needsApproval&&!data.ldapFallbackApproved&&data.ldapFallbackApproval!=='ALLOW LDAP 389')return res.status(400).json({error:'Administrator confirmation is required before enabling LDAP 389 fallback'})
  const approvedAt=needsApproval?now():allowLdapFallback?prior.ldap_fallback_approved_at:null
  const approvedBy=needsApproval?req.user.id:allowLdapFallback?prior.ldap_fallback_approved_by:null
  db.transaction(()=>{
    run("UPDATE directory_connections SET url=?,base_dn=?,bind_credential_id=?,node_credential_id=?,enabled=?,sync_interval_minutes=?,allow_ldap_fallback=?,ldap_fallback_approved_by=?,ldap_fallback_approved_at=?,last_transport=CASE WHEN ? THEN NULL ELSE last_transport END,last_sync_status=CASE WHEN ? THEN NULL ELSE last_sync_status END,last_sync_error=CASE WHEN ? THEN NULL ELSE last_sync_error END WHERE id='default'",data.url,data.baseDn,data.bindCredentialId,data.nodeCredentialId||null,Number(data.enabled),data.syncIntervalMinutes,Number(allowLdapFallback),approvedBy,approvedAt,Number(scopeChanged),Number(scopeChanged),Number(scopeChanged))
    if(needsApproval)audit(req.user.id,'directory.ldap_fallback.approve','directory','default',null,{url:data.url,bindCredentialId:data.bindCredentialId,approvedAt})
    if(prior.allow_ldap_fallback&&!allowLdapFallback)audit(req.user.id,'directory.ldap_fallback.revoke','directory','default',null,{url:data.url})
    audit(req.user.id,'directory.settings.update','directory','default',before,{url:data.url,baseDn:data.baseDn,bindCredentialId:data.bindCredentialId,nodeCredentialId:data.nodeCredentialId||null,enabled:data.enabled,syncIntervalMinutes:data.syncIntervalMinutes,allowLdapFallback})
  })()
  res.json(publicDirectory(directorySettings()))
})
api.patch('/settings/directory/action-credential',requireRole('admin'),(req,res)=>{
  const {credentialId}=body(z.object({credentialId:z.string().uuid().nullable()}),req)
  if(credentialId){const credential=one('SELECT * FROM credentials WHERE id=?',credentialId);if(!credential||!canUseCredential(req.user,credential))return res.status(400).json({error:'Selected account-control credential is unavailable'})}
  const prior=directorySettings()
  run("UPDATE directory_connections SET action_credential_id=? WHERE id='default'",credentialId)
  audit(req.user.id,'directory.action-credential.update','directory','default',{credentialId:prior.action_credential_id||null},{credentialId})
  res.json(publicDirectory(directorySettings()))
})
api.post('/directory/test',requireRole('admin'),wrap(async(req,res)=>{
  const settings=directorySettings()
  if(!settings?.url||!settings.base_dn)throw Object.assign(new Error('Configure the directory connection first'),{status:400})
  const result=await testDirectoryConnection(settings,directoryCredential(settings))
  audit(req.user.id,'directory.test','directory','default',null,{connected:result.connected,transport:result.transport,fallbackUsed:result.fallbackUsed})
  res.json(result)
}))
let directorySyncInFlight=false
async function syncDirectoryUserInventory(settings,actorId,clientFactory){
  const {users,transport}=await readDirectoryUsers(settings,directoryCredential(settings),clientFactory)
  const seenAt=now()
  db.transaction(()=>{
    run('UPDATE directory_users SET missing=1')
    for(const user of users)run(`INSERT INTO directory_users(id,sid,dn,sam_account_name,upn,email,display_name,member_of_json,enabled,missing,last_logon_at,changed_at,seen_at)
      VALUES(?,?,?,?,?,?,?,?,?,0,?,?,?) ON CONFLICT(id) DO UPDATE SET sid=excluded.sid,dn=excluded.dn,sam_account_name=excluded.sam_account_name,upn=excluded.upn,email=excluded.email,display_name=excluded.display_name,member_of_json=excluded.member_of_json,enabled=excluded.enabled,missing=0,last_logon_at=excluded.last_logon_at,changed_at=excluded.changed_at,seen_at=excluded.seen_at`,user.guid,user.sid,user.dn,user.samAccountName,user.upn,user.email,user.displayName,json(user.memberOf),Number(user.enabled),user.lastLogonAt,user.changedAt,seenAt)
    audit(actorId,'directory.users.sync','directory','default',null,{count:users.length,transport})
  })()
  return {count:users.length,transport}
}
export async function syncDirectory(actorId=null,clientFactory=undefined) {
  if(directorySyncInFlight)throw Object.assign(new Error('Directory sync is already running'),{status:409})
  directorySyncInFlight=true
  try {
  const settings=directorySettings()
  if(!settings?.enabled)throw Object.assign(new Error('Directory sync is disabled'),{status:409})
  if(!settings.url||!settings.base_dn)throw Object.assign(new Error('Directory connection is incomplete'),{status:400})
  run("UPDATE directory_connections SET last_sync_attempt_at=?,last_sync_status='running',last_sync_error=NULL WHERE id='default'",now())
  try {
    const {computers,transport}=await readDirectoryComputers(settings,directoryCredential(settings),clientFactory)
    const seenAt=now(),stats={found:computers.length,created:0,updated:0,missing:0,transport,fallbackUsed:transport==='ldap'},unresolved=[]
    db.transaction(()=>{
      run('UPDATE nodes SET ad_missing=1 WHERE ad_guid IS NOT NULL')
      for(const computer of computers){
        let node=one('SELECT * FROM nodes WHERE ad_guid=?',computer.guid)
        if(!node)node=one('SELECT * FROM nodes WHERE fqdn=? COLLATE NOCASE AND ad_guid IS NULL',computer.fqdn)
        if(!node){const matches=all('SELECT * FROM nodes WHERE hostname=? COLLATE NOCASE AND ad_guid IS NULL',computer.name);if(matches.length===1)node=matches[0]}
        if(node){
          const hasFacts=!!one('SELECT 1 FROM node_facts WHERE node_id=?',node.id)
          run('UPDATE nodes SET hostname=?,fqdn=?,ad_guid=?,ad_sid=?,ad_dn=?,ad_snapshot_json=?,ad_last_seen_at=?,ad_enabled=?,ad_missing=0,inventory_source=?,os_version=?,os_build=? WHERE id=?',computer.name,computer.fqdn,computer.guid,computer.sid,computer.dn,json(computer),seenAt,Number(computer.enabled),node.inventory_source.startsWith('manual')?'manual+ad':'ad',hasFacts?node.os_version:computer.operatingSystem||node.os_version,hasFacts?node.os_build:computer.operatingSystemVersion||node.os_build,node.id)
          if(computer.enabled&&node.firewall_state==='unmanaged'&&!one('SELECT 1 FROM learning_sessions WHERE node_id=?',node.id))startTraining(node,trainingDays(),'auto',actorId)
          stats.updated++
        } else {
          const nodeId=id()
          run("INSERT INTO nodes(id,hostname,fqdn,os_version,os_build,inventory_source,ad_guid,ad_sid,ad_dn,ad_snapshot_json,ad_last_seen_at,ad_enabled,ad_missing,firewall_state) VALUES(?,?,?,?,?,'ad',?,?,?,?,?,?,0,?)",nodeId,computer.name,computer.fqdn,computer.operatingSystem||null,computer.operatingSystemVersion||null,computer.guid,computer.sid,computer.dn,json(computer),seenAt,Number(computer.enabled),computer.enabled?'enforcing':'unmanaged')
          node=getNode(nodeId)
          if(computer.enabled)startTraining(node,trainingDays(),'auto',actorId)
          audit(actorId,'directory.node.import','node',nodeId,null,{guid:computer.guid,fqdn:computer.fqdn})
          stats.created++
        }
        if(settings.node_credential_id&&!one('SELECT 1 FROM credential_assignments WHERE credential_id=? AND node_id=?',settings.node_credential_id,node.id))run('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)',settings.node_credential_id,node.id)
        if(computer.enabled&&!node.ip)unresolved.push(node.id)
      }
      stats.missing=one('SELECT COUNT(*) n FROM nodes WHERE ad_guid IS NOT NULL AND ad_missing=1')?.n||0
      run("UPDATE directory_connections SET last_synced_at=?,last_sync_status='success',last_sync_error=NULL,last_sync_count=?,last_transport=? WHERE id='default'",seenAt,stats.found,transport)
      audit(actorId,'directory.sync','directory','default',null,stats)
    })()
    try{stats.users=await syncDirectoryUserInventory(settings,actorId,clientFactory)}
    catch(error){stats.userSyncError=error.message;run("UPDATE directory_connections SET last_sync_error=? WHERE id='default'",`User inventory: ${error.message}`.slice(0,2000));audit(actorId,'directory.users.sync.failed','directory','default',null,{error:error.message})}
    // Keep directory sync bounded for large domains. The DNS sweep finishes
    // remaining records; these first lookups make freshly imported nodes usable.
    await Promise.allSettled(unresolved.slice(0,25).map(nodeId=>lookupDns(getNode(nodeId))))
    return stats
  } catch(error) {
    run("UPDATE directory_connections SET last_sync_status='failed',last_sync_error=? WHERE id='default'",error.message.slice(0,2000))
    audit(actorId,'directory.sync.failed','directory','default',null,{error:error.message})
    throw error
  }
  } finally {directorySyncInFlight=false}
}
api.post('/directory/sync',requireRole('admin'),wrap(async(req,res)=>res.json(await syncDirectory(req.user.id))))
api.get('/directory/accounts',requireRole('auditor'),(req,res)=>{
  const query=z.object({q:z.string().max(200).default(''),source:z.enum(['all','ad','local']).default('all'),enabled:z.enum(['all','true','false']).default('all'),mfa:z.enum(['all','enrolled','missing']).default('all'),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(10).max(250).default(50),sortBy:z.enum(['name','username','email','lastLogon','status','source','node']).default('name'),sortDir:z.enum(['asc','desc']).default('asc')}).parse(req.query)
  const union=`SELECT d.id,d.sid,'ad' source,d.display_name,d.sam_account_name,d.upn,d.email,d.enabled,d.missing,d.last_logon_at,NULL node_id,NULL hostname,d.seen_at,
    EXISTS(SELECT 1 FROM users u WHERE u.ad_guid=d.id AND u.totp_secret IS NOT NULL) mfa_enrolled,
    EXISTS(SELECT 1 FROM users u WHERE u.ad_guid=d.id AND u.auth_source='ad') operator_imported
    FROM directory_users d UNION ALL
    SELECT l.id,l.sid,'local' source,COALESCE(NULLIF(l.full_name,''),l.username) display_name,l.qualified_name sam_account_name,NULL upn,NULL email,l.enabled,l.missing,NULL last_logon_at,l.node_id,n.hostname,l.seen_at,0 mfa_enrolled,0 operator_imported
    FROM local_accounts l JOIN nodes n ON n.id=l.node_id`
  const clauses=[],args=[]
  if(query.source!=='all'){clauses.push('source=?');args.push(query.source)}
  if(query.enabled!=='all'){clauses.push('enabled=?');args.push(query.enabled==='true'?1:0)}
  if(query.mfa!=='all')clauses.push(query.mfa==='enrolled'?'mfa_enrolled=1':'mfa_enrolled=0')
  if(query.q.trim()){const term=`%${query.q.trim().replace(/[\\%_]/g,'\\$&')}%`;clauses.push("(display_name LIKE ? ESCAPE '\\' OR sam_account_name LIKE ? ESCAPE '\\' OR COALESCE(upn,'') LIKE ? ESCAPE '\\' OR COALESCE(email,'') LIKE ? ESCAPE '\\' OR sid LIKE ? ESCAPE '\\' OR COALESCE(hostname,'') LIKE ? ESCAPE '\\')");args.push(term,term,term,term,term,term)}
  const where=clauses.length?`WHERE ${clauses.join(' AND ')}`:''
  const order={name:'display_name',username:'sam_account_name',email:'email',lastLogon:'last_logon_at',status:'enabled',source:'source',node:'hostname'}[query.sortBy]
  const total=one(`SELECT COUNT(*) count FROM (${union}) ${where}`,...args).count
  const items=all(`SELECT * FROM (${union}) ${where} ORDER BY ${order} ${query.sortDir.toUpperCase()},id LIMIT ? OFFSET ?`,...args,query.pageSize,(query.page-1)*query.pageSize)
  res.json({items,total,page:query.page,pageSize:query.pageSize,totalPages:Math.max(1,Math.ceil(total/query.pageSize))})
})
api.get('/directory/local-accounts/:id',requireRole('auditor'),(req,res)=>{
  const account=one('SELECT l.*,n.hostname FROM local_accounts l JOIN nodes n ON n.id=l.node_id WHERE l.id=?',reqId(req));if(!account)return notFound(res,'Local account')
  const logonEvents=all('SELECT e.id,e.node_id,n.hostname,e.event_id,e.action,e.src_ip,e.event_time,e.logon_type FROM log_events e LEFT JOIN nodes n ON n.id=e.node_id WHERE e.account_sid=? AND e.node_id=? AND e.event_id IN (4624,4625,4634,4647,528,540,529,530,531,532,533,534,535,536,537,539,538,551) ORDER BY e.event_time DESC,e.record_id DESC LIMIT 100',account.sid,account.node_id)
  res.json({...account,source:'local',sam_account_name:account.qualified_name,display_name:account.full_name||account.username,logonEvents,mfaEvents:[]})
})
api.post('/nodes/:id/local-accounts/refresh',requireRole('admin'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  if(!['winrm','winrms'].includes(node.transport)||node.connection_mode!=='agentless')return res.status(409).json({error:'Local account inventory requires an agentless WinRM node'})
  const result=await collectAccountInventory(node)
  audit(req.user.id,'local-accounts.refresh','node',node.id,null,result)
  res.json(result)
}))
api.post('/directory/local-accounts/:id/network-rule',requireRole('admin'),(req,res)=>{
  const data=body(z.object({destinationType:z.enum(['address','node','group']).default('address'),destinationId:z.string().trim().optional(),remoteAddress:z.string().trim().max(500).default(''),remotePort:z.string().trim().min(1).max(100),protocol:z.enum(['TCP','UDP']),reason:z.string().trim().min(10).max(500)}),req)
  let remoteAddress=data.remoteAddress
  if(data.destinationType==='node'){
    const destination=getNode(data.destinationId)
    if(!destination)return notFound(res,'Destination node')
    remoteAddress=destination.ip||''
  }else if(data.destinationType==='group'){
    const group=one('SELECT id FROM node_groups WHERE id=?',data.destinationId)
    if(!group)return notFound(res,'Destination node group')
    remoteAddress=all('SELECT DISTINCT n.ip FROM nodes n JOIN node_group_members m ON m.node_id=n.id WHERE m.group_id=? AND n.ip IS NOT NULL AND n.ip<>\'\'',group.id).map(row=>row.ip).join(',')
  }
  if(!remoteAddress||!validateAddressExpression(remoteAddress)||!validatePortExpression(data.remotePort)||data.remotePort==='Any')return res.status(400).json({error:'Choose a destination with a current IP address, or enter a valid destination address and port'})
  const account=one('SELECT * FROM local_accounts WHERE id=? AND missing=0',reqId(req));if(!account)return notFound(res,'Local account')
  const node=getNode(account.node_id);if(!node)return notFound(res,'Node')
  if(node.connection_mode!=='agentless'||!['winrm','winrms'].includes(node.transport)||/^(?:5\.[12]\.|windows (?:xp|server 2003))/i.test(node.os_version||''))return res.status(409).json({error:'Account-scoped firewall rules require Windows with NetSecurity and an agentless WinRM source node'})
  const policy=ensurePersonalPolicy(node,req.user.id)
  const previous=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
  const graph=parse(previous.graph_json)||{nodes:[],edges:[]}
  const matched=graph.nodes.find(item=>item.type==='deny'&&item.data?.localUserSid===account.sid&&item.data?.direction==='out'&&item.data?.remoteAddress===remoteAddress&&item.data?.remotePort===data.remotePort&&item.data?.protocol===data.protocol)
  if(matched)return res.json({policyId:policy.id,versionId:previous.id,versionNo:previous.version_no,duplicate:true,pendingSync:true})
  const ruleNode={id:id(),type:'deny',data:{name:`Block ${account.qualified_name} to ${data.destinationType==='address'?remoteAddress:data.destinationType==='node'?'node':'node group'}:${data.remotePort}`,direction:'out',protocol:data.protocol,localPort:'Any',remotePort:data.remotePort,remoteAddress,program:'Any',profile:'Any',localUserSid:account.sid}}
  const next={nodes:[...graph.nodes,ruleNode],edges:graph.edges||[]},rules=compilePolicy(next,policy.id)
  assertManagementAccess(rules)
  const conflicts=assignmentConflicts(policy.id,rules,[node]);if(conflicts.length)return rejectConflicts(res,conflicts)
  const versionId=id(),versionNo=Number(previous.version_no)+1
  db.transaction(()=>{
    if(!one('SELECT id FROM policy_assignments WHERE policy_id=? AND node_id=?',policy.id,node.id))run('INSERT INTO policy_assignments(id,policy_id,node_id,assigned_by) VALUES(?,?,?,?)',id(),policy.id,node.id,req.user.id)
    run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,policy.id,versionNo,json(next),json(rules),req.user.id,data.reason)
    run('UPDATE policies SET current_version_id=? WHERE id=?',versionId,policy.id)
      audit(req.user.id,'local-account.network-rule.stage','policy',policy.id,null,{nodeId:node.id,accountSid:account.sid,destinationType:data.destinationType,destinationId:data.destinationId||null,remoteAddress,remotePort:data.remotePort,protocol:data.protocol,versionId,reason:data.reason})
  })()
  res.status(201).json({policyId:policy.id,versionId,versionNo,pendingSync:true})
})
api.get('/directory/users',requireRole('auditor'),(req,res)=>{
  const query=z.object({q:z.string().max(200).default(''),enabled:z.enum(['all','true','false']).default('all'),mfa:z.enum(['all','enrolled','missing']).default('all'),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(10).max(250).default(50),sortBy:z.enum(['name','username','email','lastLogon','status']).default('name'),sortDir:z.enum(['asc','desc']).default('asc')}).parse(req.query)
  const clauses=[],args=[]
  if(query.q.trim()){const term=`%${query.q.trim().replace(/[\\%_]/g,'\\$&')}%`;clauses.push("(d.display_name LIKE ? ESCAPE '\\' OR d.sam_account_name LIKE ? ESCAPE '\\' OR d.upn LIKE ? ESCAPE '\\' OR d.email LIKE ? ESCAPE '\\')");args.push(term,term,term,term)}
  if(query.enabled!=='all'){clauses.push('d.enabled=?');args.push(query.enabled==='true'?1:0)}
  if(query.mfa!=='all')clauses.push(query.mfa==='enrolled'?"EXISTS(SELECT 1 FROM users u WHERE u.ad_guid=d.id AND u.totp_secret IS NOT NULL)":"NOT EXISTS(SELECT 1 FROM users u WHERE u.ad_guid=d.id AND u.totp_secret IS NOT NULL)")
  const where=clauses.length?`WHERE ${clauses.join(' AND ')}`:''
  const order={name:'d.display_name',username:'d.sam_account_name',email:'d.email',lastLogon:'d.last_logon_at',status:'d.enabled'}[query.sortBy]
  const total=one(`SELECT COUNT(*) count FROM directory_users d ${where}`,...args).count
  const items=all(`SELECT d.*,EXISTS(SELECT 1 FROM users u WHERE u.ad_guid=d.id AND u.totp_secret IS NOT NULL) mfa_enrolled,EXISTS(SELECT 1 FROM users u WHERE u.ad_guid=d.id AND u.auth_source='ad') operator_imported FROM directory_users d ${where} ORDER BY ${order} ${query.sortDir.toUpperCase()},d.id LIMIT ? OFFSET ?`,...args,query.pageSize,(query.page-1)*query.pageSize).map(({member_of_json,...row})=>({...row,memberOf:parse(member_of_json)||[]}))
  res.json({items,total,page:query.page,pageSize:query.pageSize,totalPages:Math.max(1,Math.ceil(total/query.pageSize))})
})
api.get('/directory/users/:id',requireRole('auditor'),(req,res)=>{
  const user=one('SELECT * FROM directory_users WHERE id=?',reqId(req));if(!user)return notFound(res,'Directory user')
  const mfa=all('SELECT id,segment_id,node_id,status,challenged_at,resolved_at FROM mfa_challenges WHERE lower(user_upn) IN (?,?) ORDER BY challenged_at DESC LIMIT 100',String(user.upn||'').toLowerCase(),String(user.email||'').toLowerCase())
  const logons=all('SELECT e.id,e.node_id,n.hostname,e.event_id,e.action,e.src_ip,e.event_time,e.logon_type FROM log_events e LEFT JOIN nodes n ON n.id=e.node_id WHERE e.account_sid=? AND e.event_id IN (4624,4625,4634,4647,528,540,529,530,531,532,533,534,535,536,537,539,538,551) ORDER BY e.event_time DESC,e.record_id DESC LIMIT 100',user.sid)
  const associatedNodes=all('SELECT n.id,n.hostname,n.fqdn,n.ip,n.status,MAX(e.event_time) last_event_at FROM log_events e JOIN nodes n ON n.id=e.node_id WHERE e.account_sid=? GROUP BY n.id ORDER BY last_event_at DESC',user.sid)
  const {member_of_json,...publicUser}=user
  res.json({...publicUser,memberOf:parse(member_of_json)||[],mfaEnrolled:!!one('SELECT 1 FROM users WHERE ad_guid=? AND totp_secret IS NOT NULL',user.id),operatorImported:!!one("SELECT 1 FROM users WHERE ad_guid=? AND auth_source='ad'",user.id),mfaEvents:mfa,logonEvents:logons,associatedNodes})
})
api.post('/directory/users/:id/status',requireRole('admin'),wrap(async(req,res)=>{
  const data=body(z.object({enabled:z.boolean(),reason:z.string().trim().min(10).max(500),confirmed:z.boolean().optional(),confirmation:z.string().optional(),durationMinutes:z.number().int().min(5).max(10080).optional()}),req)
  if(!data.confirmed&&data.confirmation!==(data.enabled?'ENABLE AD USER':'DISABLE AD USER'))return res.status(400).json({error:'Confirmation is required'})
  if(data.enabled&&data.durationMinutes)return res.status(400).json({error:'A duration applies only when disabling an account'})
  const user=one('SELECT * FROM directory_users WHERE id=?',reqId(req));if(!user)return notFound(res,'Directory user')
  if(user.missing)return res.status(409).json({error:'Sync the directory before changing a missing AD user'})
  if(!data.enabled&&one("SELECT id FROM ad_account_holds WHERE user_guid=? AND status='active'",user.id))return res.status(409).json({error:'A temporary account hold is already active'})
  audit(req.user.id,'directory.user.status.attempt','directory_user',user.id,null,{enabled:data.enabled,reason:data.reason,durationMinutes:data.durationMinutes||null})
  const settings=directorySettings(),actionCredential=directoryActionCredential(settings)
  let result
  try{result=await writeDirectoryUserStatus(settings,actionCredential,user,data.enabled)}
  catch(error){audit(req.user.id,'directory.user.status.failed','directory_user',user.id,null,{enabled:data.enabled,reason:data.reason,error:error.message});throw error}
  if(data.durationMinutes&&!result.changed)return res.status(409).json({error:'The account was already disabled; WinFire did not schedule an automatic re-enable'})
  const expiresAt=data.durationMinutes?new Date(Date.now()+data.durationMinutes*60_000).toISOString():null
  try{db.transaction(()=>{
    run('UPDATE directory_users SET enabled=?,seen_at=? WHERE id=?',Number(data.enabled),now(),user.id)
    if(data.enabled)run("UPDATE ad_account_holds SET status='resolved-manually',resolved_at=? WHERE user_guid=? AND status='active'",now(),user.id)
    if(expiresAt)run('INSERT INTO ad_account_holds(id,user_guid,expected_uac,expires_at,status,created_by,created_at) VALUES(?,?,?,?,?,?,?)',id(),user.id,result.afterUac,expiresAt,'active',req.user.id,now())
    audit(req.user.id,'directory.user.status.changed','directory_user',user.id,{enabled:!!user.enabled,uac:result.beforeUac},{enabled:data.enabled,uac:result.afterUac,reason:data.reason,expiresAt})
  })()}catch(error){
    if(result.changed){
      try{await writeDirectoryUserStatus(settings,actionCredential,user,!data.enabled,{expectedUac:result.afterUac})}
      catch(rollbackError){throw new Error(`AD was changed but its local record could not be stored (${error.message}); automatic rollback failed (${rollbackError.message}). Immediate manual review is required`)}
    }
    throw new Error(`AD change was rolled back because its local record could not be stored: ${error.message}`)
  }
  res.json({enabled:data.enabled,changed:result.changed,expiresAt})
}))
export async function processDueAdAccountHolds(){
  const due=all("SELECT h.*,d.sid,d.dn FROM ad_account_holds h JOIN directory_users d ON d.id=h.user_guid WHERE h.status='active' AND h.expires_at<=? AND (h.last_attempt_at IS NULL OR h.last_attempt_at<=?) ORDER BY h.expires_at LIMIT 20",now(),new Date(Date.now()-5*60_000).toISOString())
  for(const hold of due){
    run('UPDATE ad_account_holds SET last_attempt_at=? WHERE id=?',now(),hold.id)
    try{
      const result=await writeDirectoryUserStatus(directorySettings(),directoryActionCredential(directorySettings()),{id:hold.user_guid,sid:hold.sid,dn:hold.dn},true,{expectedUac:hold.expected_uac})
      db.transaction(()=>{
        run('UPDATE directory_users SET enabled=1,seen_at=? WHERE id=?',now(),hold.user_guid)
        run("UPDATE ad_account_holds SET status='expired',resolved_at=?,error=NULL WHERE id=?",now(),hold.id)
        audit(null,'directory.user.hold.expired','directory_user',hold.user_guid,{enabled:false,uac:result.beforeUac},{enabled:true,uac:result.afterUac})
      })()
    }catch(error){
      const review=error.status===409
      run('UPDATE ad_account_holds SET status=?,error=? WHERE id=?',review?'review':'active',error.message.slice(0,500),hold.id)
      if(review||!hold.error)audit(null,'directory.user.hold.failed','directory_user',hold.user_guid,null,{error:error.message,manualReview:review})
    }
  }
  return due.length
}
api.post('/directory/users/:id/import-operator',requireRole('admin'),wrap(async(req,res)=>{
  const {role}=body(z.object({role:z.enum(['admin','editor','auditor']).default('auditor')}),req)
  const directoryUser=one('SELECT * FROM directory_users WHERE id=?',reqId(req));if(!directoryUser)return notFound(res,'Directory user')
  if(directoryUser.missing||!directoryUser.enabled||!directoryUser.upn||!directoryUser.email||!z.email().safeParse(directoryUser.email).success)return res.status(409).json({error:'Directory user must be present, enabled, and have a valid email and UPN'})
  let user=one('SELECT * FROM users WHERE ad_guid=?',directoryUser.id)
  const byEmail=one('SELECT * FROM users WHERE email=?',directoryUser.email)
  if(byEmail&&byEmail.id!==user?.id&&!byEmail.directory_only)return res.status(409).json({error:'An existing local operator uses this email; resolve that account before importing'})
  if(!user&&byEmail?.directory_only)user=byEmail
  const userId=user?.id||id(),passwordHash=user?.password_hash||await argon2.hash(crypto.randomBytes(48).toString('base64url'))
  db.transaction(()=>{
    if(user)run("UPDATE users SET email=?,role=?,auth_source='ad',ad_guid=?,directory_only=0,email_verified=1,session_version=session_version+1 WHERE id=?",directoryUser.email,role,directoryUser.id,user.id)
    else{run("INSERT INTO users(id,email,password_hash,role,email_verified,auth_source,ad_guid) VALUES(?,?,?,?,1,'ad',?)",userId,directoryUser.email,passwordHash,role,directoryUser.id);run('INSERT INTO user_profiles(user_id) VALUES(?)',userId)}
    run('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=?',now(),userId)
    audit(req.user.id,'directory.operator.import','user',userId,null,{directoryGuid:directoryUser.id,email:directoryUser.email,role})
  })()
  res.status(user?200:201).json(publicUser(one('SELECT * FROM users WHERE id=?',userId)))
}))

const visibleCredentials=user=>(user.role==='owner'||user.role==='admin' ? all('SELECT id,name,type,username,owner_user_id,visibility,team_id,priority,created_at FROM credentials ORDER BY priority,name') : all(`SELECT id,name,type,username,owner_user_id,visibility,team_id,priority,created_at FROM credentials WHERE owner_user_id=? OR (visibility='team' AND team_id=?) OR EXISTS (SELECT 1 FROM resource_grants g WHERE g.resource_type='credential' AND g.resource_id=credentials.id AND g.grantee_user_id=?) ORDER BY priority,name`,user.id,user.team_id,user.id)).map(credential=>({...credential,canWrite:canWriteResource(user,'credential',credential)}))
api.get('/credentials',(req,res)=>res.json(visibleCredentials(req.user)))
const credentialInputSchema=z.object({name:z.string().trim().min(1).max(120),type:z.enum(['local','domain','esxi','snmp-v2c','snmp-v3']),username:z.string().trim().max(255).default(''),password:z.string().max(4096).optional(),community:z.string().max(255).optional(),securityLevel:z.enum(['noAuthNoPriv','authNoPriv','authPriv']).optional(),authProtocol:z.enum(['md5','sha','sha224','sha256','sha384','sha512']).optional(),authKey:z.string().max(4096).optional(),privProtocol:z.enum(['des','aes','aes256b','aes256r']).optional(),privKey:z.string().max(4096).optional(),visibility:z.enum(['private','team']).default('private'),teamId:z.string().optional(),priority:z.number().int().min(-100000).max(100000).default(100)}).superRefine((value,ctx)=>{
  if(['local','domain','esxi'].includes(value.type)&&(!value.username||!value.password))ctx.addIssue({code:'custom',path:['password'],message:'Username and password are required for this credential'})
  if(value.type==='snmp-v2c'&&!value.community&&!value.password)ctx.addIssue({code:'custom',path:['community'],message:'SNMP v2c requires a community string'})
  if(value.type==='snmp-v3')try{normalizeSnmpSecret(value.type,value)}catch(error){ctx.addIssue({code:'custom',path:['username'],message:error.message})}
})
const sealedCredentialSecret=data=>['snmp-v2c','snmp-v3'].includes(data.type)?normalizeSnmpSecret(data.type,data):{password:data.password}
api.post('/credentials',requireRole('editor'),(req,res)=>{
  const data=body(credentialInputSchema,req),credentialId=id(),username=data.type==='snmp-v2c'?(data.username||'community') : data.username
  run('INSERT INTO credentials(id,name,type,username,encrypted_blob,owner_user_id,visibility,team_id,priority) VALUES(?,?,?,?,?,?,?,?,?)',credentialId,data.name,data.type,username,seal(sealedCredentialSecret(data)),req.user.id,data.visibility,data.teamId||req.user.team_id||null,data.priority)
  audit(req.user.id,'credential.create','credential',credentialId,null,{name:data.name,type:data.type});res.status(201).json({id:credentialId,name:data.name,type:data.type,username,visibility:data.visibility})
})
api.patch('/credentials/:id',requireRole('editor'),(req,res)=>{
  const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res)
  if(!canWriteResource(req.user,'credential',credential))return res.status(403).json({error:'Insufficient permission'})
  const data=body(z.object({name:z.string().trim().min(1).max(120).optional(),username:z.string().trim().max(255).optional(),password:z.string().max(4096).optional(),community:z.string().max(255).optional(),securityLevel:z.enum(['noAuthNoPriv','authNoPriv','authPriv']).optional(),authProtocol:z.enum(['md5','sha','sha224','sha256','sha384','sha512']).optional(),authKey:z.string().max(4096).optional(),privProtocol:z.enum(['des','aes','aes256b','aes256r']).optional(),privKey:z.string().max(4096).optional(),priority:z.number().int().min(-100000).max(100000).optional()}),req)
  let encrypted=credential.encrypted_blob
  if(['snmp-v2c','snmp-v3'].includes(credential.type)&&(data.password||data.community||data.securityLevel||data.authProtocol||data.authKey||data.privProtocol||data.privKey||data.username)){
    const current=openSealed(credential.encrypted_blob),next={...current,...data,username:data.username||credential.username}
    encrypted=seal(normalizeSnmpSecret(credential.type,next))
  }else if(data.password)encrypted=seal({password:data.password})
  db.transaction(()=>{
    run('UPDATE credentials SET name=?,username=?,encrypted_blob=?,priority=? WHERE id=?',data.name||credential.name,data.username||credential.username,encrypted,data.priority??credential.priority,credential.id)
    if(data.password||data.username&&data.username!==credential.username){
      const directory=directorySettings()
      if(directory?.bind_credential_id===credential.id&&directory.allow_ldap_fallback&&directory.ldap_fallback_approved_at){
        run("UPDATE directory_connections SET ldap_fallback_approved_by=NULL,ldap_fallback_approved_at=NULL WHERE id='default'")
        audit(req.user.id,'directory.ldap_fallback.revoke','directory','default',null,{reason:'bind_credential_changed',bindCredentialId:credential.id})
      }
    }
    audit(req.user.id,'credential.rotate','credential',credential.id,null,{rotated:!!data.password})
  })()
  res.json({id:credential.id,name:data.name||credential.name})
})
api.delete('/credentials/:id',requireRole('editor'),(req,res)=>{const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res);if(!canWriteResource(req.user,'credential',credential))return res.status(403).json({error:'Insufficient permission'});db.transaction(()=>{run("DELETE FROM resource_grants WHERE resource_type='credential' AND resource_id=?",credential.id);run('DELETE FROM credentials WHERE id=?',credential.id);audit(req.user.id,'credential.delete','credential',credential.id,null,null)})();res.status(204).end()})
api.post('/credentials/:id/assignments',requireRole('editor'),(req,res)=>{
  const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res)
  if(!canUseCredential(req.user,credential))return res.status(403).json({error:'Insufficient permission'})
  const data=body(z.object({nodeId:z.string().optional(),nodeGroupId:z.string().optional()}),req)
  if(Number(!!data.nodeId)+Number(!!data.nodeGroupId)!==1)return res.status(400).json({error:'Specify exactly one nodeId or nodeGroupId'})
  if(data.nodeId&&!getNode(data.nodeId))return notFound(res,'Node')
  const targetGroup=data.nodeGroupId?one('SELECT * FROM node_groups WHERE id=?',data.nodeGroupId):null
  if(data.nodeGroupId&&!targetGroup)return notFound(res,'Node group')
  if(targetGroup&&!canWriteResource(req.user,'node_group',targetGroup))return res.status(403).json({error:'Insufficient permission for node group'})
  if(one('SELECT 1 FROM credential_assignments WHERE credential_id=? AND node_id IS ? AND node_group_id IS ?',credential.id,data.nodeId||null,data.nodeGroupId||null))return res.json({ok:true,alreadyAssigned:true})
  run('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,?)',reqId(req),data.nodeId||null,data.nodeGroupId||null)
  audit(req.user.id,'credential.assign','credential',reqId(req),null,data);res.status(201).json({ok:true})
})
api.post('/credentials/:id/test',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({nodeId:z.string()}),req),node=getNode(data.nodeId)
  if(!node)return notFound(res,'Node')
  const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res,'Credential')
  if(!canUseCredential(req.user,credential))return res.status(403).json({error:'Insufficient permission'})
  const assigned=one('SELECT 1 FROM credential_assignments WHERE credential_id=? AND (node_id=? OR node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?))',credential.id,node.id,node.id)
  if(!assigned)return res.status(400).json({error:'Assign credential to node first'})
  try {res.json(await testNodeCredential(node,credential.id))}catch(error){res.json({success:false,transport:node.transport||'winrm',error:error.message})}
}))
api.post('/credentials/:id/preflight',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({host:z.string().trim().min(1).max(253),expectedName:z.string().trim().max(253).optional()}),req)
  const credential=one('SELECT * FROM credentials WHERE id=?',reqId(req));if(!credential)return notFound(res,'Credential')
  if(!canUseCredential(req.user,credential))return res.status(403).json({error:'Insufficient permission'})
  if(!['local','domain'].includes(credential.type))return res.status(400).json({error:'Only Windows local or domain credentials support WMI/WinRM preflight'})
  let secret
  try{secret=openSealed(credential.encrypted_blob)}catch{return res.status(500).json({error:'Credential secret could not be opened'})}
  try{
    const result=await preflightCredential({host:data.host,expectedName:data.expectedName,credential:{username:credential.username,secret}})
    audit(req.user.id,'credential.preflight.success','credential',credential.id,null,{host:data.host,transport:result.transport})
    res.json(result)
  }catch(error){
    audit(req.user.id,'credential.preflight.failure','credential',credential.id,null,{host:data.host,error:String(error.message||error).slice(0,500)})
    const message=String(error.message||error),redacted=secret?.password?message.replaceAll(secret.password,'[redacted]'):message
    res.json({success:false,error:redacted,ports:error.ports})
  }
}))

const serverNodeManaged=node=>{
  if(!node||node.manageability==='unmanaged')return false
  if(node.transport==='snmp'||node.connection_mode==='snmp'||node.connection_mode==='agent'||node.agent_id)return true
  if(node.probe_status==='winrm-authenticated'||node.probe_status==='winrms-authenticated'||node.probe_status==='wmi-authenticated'||node.probe_status==='netsh-authenticated')return true
  if(node.firewall_state==='enforcing'&&!(node.agent_required&&!node.agent_id))return true
  return false
}
api.get('/nodes',(req,res)=>{
  const rows=all('SELECT n.*,f.snapshot_json FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id').filter(isLocalAssetNode)
  // The unparameterized form remains an array for API compatibility. Inventory
  // uses the parameterized form below so searching, filtering, sorting and
  // pagination happen here rather than in the browser.
  if(!Object.keys(req.query||{}).length)return res.json(rows.sort((a,b)=>String(b.created_at||'').localeCompare(String(a.created_at||''))).map(publicNode))
  const page=Math.max(1,Number.parseInt(req.query.page||'1',10)||1),pageSize=Math.min(500,Math.max(1,Number.parseInt(req.query.pageSize||'25',10)||25)),term=String(req.query.search||'').trim().toLowerCase(),filter=String(req.query.filter||'all'),sort=String(req.query.sort||'priority'),direction=String(req.query.direction||'asc').toLowerCase()==='desc'?-1:1
  let filtered=rows.filter(node=>{
    if(term&&!([node.hostname,node.fqdn,node.ip,node.os_name,node.os_version,node.platform,node.device_type,node.transport,node.hypervisor,node.virtual_machine?'virtual machine':''].map(value=>String(value||'').toLowerCase()).join(' ').includes(term)))return false
    const managed=serverNodeManaged(node)
    if(filter==='managed'&& !managed)return false
    if(filter==='unmanaged'&& managed)return false
    if(filter==='reachable'&&node.status!=='reachable')return false
    if(filter==='unreachable'&&node.status!=='unreachable')return false
    return true
  })
  const value=(node,key)=>key==='priority'?(serverNodeManaged(node)?0:1):key==='hostname'?String(node.hostname||'').toLowerCase():key==='address'?String(node.ip||node.fqdn||'').toLowerCase():key==='status'?String(node.status||'').toLowerCase():key==='mode'?String(node.transport==='snmp'||node.connection_mode==='snmp'?'snmp':node.connection_mode||'').toLowerCase():String(node.created_at||'')
  filtered.sort((a,b)=>{if(sort!=='priority'){const ap=value(a,'priority'),bp=value(b,'priority');if(ap!==bp)return ap<bp?-1:1}const av=value(a,sort),bv=value(b,sort);return av===bv?String(a.hostname||'').localeCompare(String(b.hostname||''))*direction:(av<bv?-1:1)*direction})
  const total=filtered.length,start=(page-1)*pageSize
  res.json({items:filtered.slice(start,start+pageSize).map(publicNode),total,page,pageSize,totalPages:Math.max(1,Math.ceil(total/pageSize)),sort,direction:direction===-1?'desc':'asc'})
})
api.post('/nodes',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({hostname:z.string().min(1),fqdn:z.string().optional(),ip:z.string().optional(),connectionMode:z.enum(['agentless','agent']).default('agentless'),credentialIds:z.array(z.string()).default([])}),req)
  if(data.credentialIds.some(credentialId=>!canUseCredential(req.user,one('SELECT * FROM credentials WHERE id=?',credentialId))))return res.status(403).json({error:'Credential unavailable'})
  const nodeId=id(),days=trainingDays()
  const training=db.transaction(()=>{
    run('INSERT INTO nodes(id,hostname,fqdn,ip,connection_mode) VALUES(?,?,?,?,?)',nodeId,data.hostname,data.fqdn||null,data.ip||null,data.connectionMode)
    for(const credentialId of data.credentialIds)run('INSERT OR IGNORE INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)',credentialId,nodeId)
    audit(req.user.id,'node.create','node',nodeId,null,data)
    return startTraining(getNode(nodeId),days,'auto',req.user.id)
  })()
  const node=getNode(nodeId),dns=await lookupDns(node);res.status(201).json({...node,dns,training})
}))
api.get('/nodes/:id',(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');const factsRow=one('SELECT snapshot_json FROM node_facts WHERE node_id=?',node.id);res.json({...publicNode({...node,snapshot_json:factsRow?.snapshot_json}),dns:one('SELECT * FROM dns_lookups WHERE node_id=?',node.id),credentialIds:all('SELECT credential_id FROM credential_assignments WHERE node_id=?',node.id).map(item=>item.credential_id),groups:all('SELECT g.* FROM node_groups g JOIN node_group_members m ON m.group_id=g.id WHERE m.node_id=? ORDER BY g.name',node.id).filter(group=>canReadResource(req.user,'node_group',group)).map(group=>({id:group.id,name:group.name,canWrite:canWriteResource(req.user,'node_group',group)}))})})
api.post('/nodes/:id/training',requireRole('editor'),(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const {durationDays}=body(z.object({durationDays:z.number().int().min(1).max(365)}),req)
  const session=db.transaction(()=>startTraining(node,durationDays,'auto',req.user.id))()
  res.status(201).json(session)
})
api.patch('/nodes/:id',requireRole('editor'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const data=body(z.object({hostname:z.string().trim().min(1).optional(),fqdn:z.string().trim().nullable().optional(),ip:z.string().refine(value=>isIP(value)!==0,'Invalid IP address').nullable().optional(),connectionMode:z.enum(['agentless','agent','snmp']).optional(),deviceType:z.enum(['auto','switch','firewall','router','printer','hypervisor','esxi','other']).optional(),managementType:z.enum(['auto','snmp','agentless','agent','manual']).optional(),credentialIds:z.array(z.string()).max(20).optional()}),req)
  const hostname=data.hostname??node.hostname,fqdn=data.fqdn===undefined?node.fqdn:data.fqdn,ip=data.ip===undefined?node.ip:data.ip,mode=data.connectionMode||node.connection_mode
  if(node.ad_guid&&(hostname!==node.hostname||fqdn!==node.fqdn))return res.status(409).json({error:'Active Directory manages this computer name and FQDN; edit them in the directory'})
  if(mode==='agent'&&!node.agent_id)return res.status(409).json({error:'Enroll an agent before switching to agent mode'})
  if(mode==='agentless'&&node.agent_id)return res.status(409).json({error:'Revoke the agent before switching to agentless mode'})
  const targetChanged=(fqdn||ip||hostname)!==(node.fqdn||node.ip||node.hostname)
  if(targetChanged&&one('SELECT id FROM policy_assignments WHERE node_id=? OR node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?)',node.id,node.id))return res.status(409).json({error:'Remove assigned policies before changing the management address; existing firewall rules may still be present on the old host'})
  const identityChanged=hostname!==node.hostname||fqdn!==node.fqdn||ip!==node.ip
  const managementType=data.managementType??node.management_type??'auto',requestedDeviceType=data.deviceType??node.device_type??'auto',deviceType=requestedDeviceType==='auto'?(node.device_type||null):requestedDeviceType,isEsxi=deviceType==='esxi'
  const effectiveManagementType=isEsxi?'manual':managementType,nextMode=isEsxi?'agentless':effectiveManagementType==='snmp'?'snmp':mode,nextTransport=isEsxi?(node.transport==='esxi-soap'?node.transport:null):effectiveManagementType==='snmp'?'snmp':targetChanged?null:node.transport,nextStatus=isEsxi&&node.transport==='esxi-soap'&&node.status==='reachable'?'reachable':effectiveManagementType==='snmp'&&node.status==='reachable'?'reachable':targetChanged?'unknown':node.status
  const assignedIds=data.credentialIds===undefined?all('SELECT credential_id FROM credential_assignments WHERE node_id=?',node.id).map(item=>item.credential_id):data.credentialIds
  const assignedCredentials=assignedIds.map(credentialId=>one('SELECT * FROM credentials WHERE id=?',credentialId))
  if(assignedCredentials.some(credential=>!credential||!canUseCredential(req.user,credential)))return res.status(403).json({error:'One or more credentials are unavailable'})
  if(isEsxi&&!assignedCredentials.some(credential=>credential.type==='esxi')&&!assignedNodeCredentials(node.id).some(credential=>credential.type==='esxi'&&canUseCredential(req.user,credential)))return res.status(400).json({error:'VMware ESXi nodes require an ESXi credential from the vault'})
  const nextManageability=isEsxi?'unmanaged':node.manageability,nextSnmpCapable=isEsxi?1:node.snmp_capable,nextFirewallState=isEsxi?'unmanaged':node.firewall_state,nextHypervisor=isEsxi?'VMware ESXi':node.device_type==='esxi'?null:node.hypervisor,nextAgentRequired=isEsxi?0:node.agent_required
  db.transaction(()=>{
    run('UPDATE nodes SET hostname=?,fqdn=?,ip=?,connection_mode=?,transport=?,device_type=?,management_type=?,manageability=?,snmp_capable=?,hypervisor=?,firewall_state=?,agent_required=?,status=?,failures=?,next_retry_at=? WHERE id=?',hostname,fqdn,ip,nextMode,nextTransport,deviceType,effectiveManagementType,nextManageability,nextSnmpCapable,nextHypervisor,nextFirewallState,nextAgentRequired,nextStatus,targetChanged?0:node.failures,targetChanged?null:node.next_retry_at,node.id)
    if(data.credentialIds!==undefined){
      run('DELETE FROM credential_assignments WHERE node_id=?',node.id)
      for(const credentialId of data.credentialIds)run('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)',credentialId,node.id)
    }
    if(targetChanged)run('DELETE FROM node_facts WHERE node_id=?',node.id)
    audit(req.user.id,'node.update','node',node.id,node,{hostname,fqdn,ip,connectionMode:nextMode,deviceType,managementType:effectiveManagementType,credentialIds:data.credentialIds,targetChanged})
  })()
  if(identityChanged)await lookupDns(getNode(node.id))
  res.json(getNode(node.id))
}))
api.put('/nodes/:id/credentials',requireRole('editor'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const data=body(z.object({credentialIds:z.array(z.string()).max(20)}),req)
  const credentials=data.credentialIds.map(credentialId=>one('SELECT * FROM credentials WHERE id=?',credentialId))
  if(credentials.some((credential,index)=>!credential||!canUseCredential(req.user,credential)))return res.status(403).json({error:'One or more credentials are unavailable'})
  const before=all('SELECT credential_id FROM credential_assignments WHERE node_id=?',node.id).map(item=>item.credential_id)
  db.transaction(()=>{
    run('DELETE FROM credential_assignments WHERE node_id=?',node.id)
    for(const credentialId of data.credentialIds)run('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)',credentialId,node.id)
    audit(req.user.id,'node.credentials.replace','node',node.id,{credentialIds:before},{credentialIds:data.credentialIds})
  })()
  let snmpPoll=null
  const snmpCredential=credentials.find(credential=>['snmp-v2c','snmp-v3'].includes(credential.type))
  if(snmpCredential&&node.device_type!=='esxi'){
    try{snmpPoll=await pollSnmpNode(getNode(node.id),{credential:openedCredential(snmpCredential),actorId:req.user.id})}
    catch(error){audit(req.user.id,'snmp-node.poll.failed','node',node.id,null,{error:String(error.message||error).slice(0,500)})}
  }
  res.json({credentialIds:data.credentialIds,snmpPoll})
}))
api.delete('/nodes/:id',requireRole('admin'),(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const data=z.object({confirmed:z.boolean().optional(),confirmation:z.string().optional()}).parse(req.body||{})
  if((data.confirmed!==undefined||data.confirmation!==undefined)&&!data.confirmed&&data.confirmation!==node.hostname)return res.status(400).json({error:'Confirmation is required'})
  if(node.ad_guid)return res.status(409).json({error:'This computer is managed by Active Directory and will be imported again. Remove it from the directory search scope first.'})
  if(one('SELECT id FROM agents WHERE node_id=? AND revoked_at IS NULL',node.id))return res.status(409).json({error:'Revoke the enrolled agent before removing this node'})
  if(one("SELECT id FROM break_glass_sessions WHERE node_id=? AND status IN ('activating','activation-unknown','active','ending')",node.id))return res.status(409).json({error:'End break glass before removing this node'})
  if(one('SELECT id FROM identity_segments WHERE node_id=?',node.id))return res.status(409).json({error:'Remove identity segments for this node before deleting it'})
  if(one('SELECT id FROM policy_assignments WHERE node_id=? OR node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?)',node.id,node.id))return res.status(409).json({error:'Remove policy assignments for this node and its groups before deleting it; managed firewall rules may still be present on the host'})
  db.transaction(()=>{
    run('DELETE FROM credential_assignments WHERE node_id=?',node.id)
    run('DELETE FROM enrollment_tokens WHERE node_id=?',node.id)
    run("DELETE FROM agent_poll_settings WHERE target_type='node' AND target_id=?",node.id)
    run('DELETE FROM node_group_members WHERE node_id=?',node.id)
    run('DELETE FROM learning_sessions WHERE node_id=?',node.id)
    run('DELETE FROM agent_jobs WHERE agent_id IN (SELECT id FROM agents WHERE node_id=?)',node.id)
    run('DELETE FROM agents WHERE node_id=?',node.id)
    run('DELETE FROM nodes WHERE id=?',node.id)
    audit(req.user.id,'node.delete','node',node.id,node,{inventoryRemoved:true,historyRetained:true})
  })()
  res.status(204).end()
})
api.post('/nodes/:id/probe',requireRole('editor'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const snmpCredential=assignedSnmpCredential(node.id,req.user)
  if(snmpCredential&&node.device_type!=='esxi'){
    try{
      const result=await pollSnmpNode(node,{credential:openedCredential(snmpCredential),actorId:req.user.id})
      const refreshed=getNode(node.id)
      // SNMP fingerprints ESXi reliably, but the SOAP inventory still needs
      // the separate ESXi vault credential. Run it after the SNMP facts pass
      // so a hypervisor keeps both its infrastructure identity and VM list.
      if(result.classification?.deviceType==='hypervisor'&&refreshed?.ip){
        const esxiCredentials=accessibleEsxiCredentials(refreshed,req.user).flatMap(credential=>{try{const secret=openSealed(credential.encrypted_blob);return secret?.password?[{username:credential.username,password:secret.password}]:[]}catch{return []}})
        const detected=await identifyHypervisor(refreshed.ip,{credentials:esxiCredentials}).catch(()=>({detected:false}))
        if(detected.detected){persistHypervisor(node.id,detected);return res.json({transport:detected.api==='soap'?'esxi-soap':'hypervisor',status:'reachable',probeStatus:detected.authenticated?'hypervisor-authenticated':'hypervisor-detected',snmp:result,esxi:detected,hypervisor:detected})}
      }
      return res.json({transport:'snmp',status:'reachable',probeStatus:'snmp-authenticated',snmp:result,esxi:{detected:false},hypervisor:refreshed?.hypervisor?{detected:true,hypervisor:refreshed.hypervisor}: {detected:false}})
    }catch(error){
      if(node.transport==='snmp'||node.connection_mode==='snmp')return res.status(502).json({error:`SNMP poll failed: ${String(error.message||error).slice(0,500)}`})
    }
  }
  const credentials=accessibleEsxiCredentials(node,req.user).flatMap(credential=>{try{const secret=openSealed(credential.encrypted_blob);return secret?.password?[{username:credential.username,password:secret.password}]:[]}catch{return []}})
  const detected=node.ip?await identifyHypervisor(node.ip,{credentials}):{detected:false}
  const infrastructure=detected.detected?detected:node.ip?await detectInfrastructureHost(node.ip).catch(()=>null):null
  const hypervisor=detected.detected?detected:infrastructure?.hypervisor?{...infrastructure,detected:true,osName:infrastructure.osName||infrastructure.hypervisorName,hypervisor:infrastructure.hypervisorName||infrastructure.hypervisor,api:'https'}:detected
  if(hypervisor.detected)persistHypervisor(node.id,hypervisor)
  const result=hypervisor.detected?{transport:hypervisor.api==='soap'?'esxi-soap':'hypervisor',status:'reachable',probeStatus:hypervisor.authenticated?'hypervisor-authenticated':'hypervisor-detected'}:await probeNode(getNode(node.id)).catch(error=>({transport:getNode(node.id)?.transport||'unknown',error:error.message}))
  res.json({...result,esxi:hypervisor.api==='soap'?hypervisor:{detected:false},hypervisor})
}))
api.post('/nodes/:id/activate-agentless',requireRole('admin'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  if(!node.ad_guid||node.ad_missing||!node.ad_enabled||node.connection_mode!=='agentless')return res.status(409).json({error:'This action requires an enabled AD-discovered agentless computer'})
  let facts
  try{facts=await enrichNode(node)}catch(error){
    // A failed remote verification is an upstream management failure. Keep the
    // response actionable instead of collapsing it into the generic 500 page;
    // the connector message does not contain credentials and is safe to show
    // to the administrator who initiated the check.
    const detail=String(error?.message||'The remote host did not complete verification').slice(0,500)
    throw Object.assign(new Error(`Agentless verification failed: ${detail}`),{status:502,cause:error})
  }
  audit(req.user.id,'node.agentless.verify','node',node.id,null,{transport:one('SELECT transport FROM nodes WHERE id=?',node.id)?.transport,computerName:facts?.computer?.Name})
  res.json({managed:true,transport:one('SELECT transport FROM nodes WHERE id=?',node.id)?.transport,computerName:facts?.computer?.Name})
}))
api.post('/nodes/:id/wef/configure',requireRole('admin'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  if(!wefEnabled())return res.status(409).json({error:'Enable WEF push in Administration before configuring a source'})
  const secret=wefSecret();if(!secret)return res.status(503).json({error:'Set WEF_SHARED_SECRET on the control plane before configuring WEF push'})
  if(!['winrm','winrms'].includes(node.transport)||node.connection_mode!=='agentless'||node.status!=='reachable')return res.status(409).json({error:'WEF source configuration requires a reachable authenticated WinRM node'})
  const data=body(z.object({refreshSeconds:z.number().int().min(60).max(86400).default(900)}),req)
  const base=effectivePublicBaseUrl(req)
  let subscriptionUrl
  try {
    const parsed=new URL(base)
    if(parsed.protocol!=='https:')throw new Error('WEF push requires an HTTPS PUBLIC_BASE_URL')
    subscriptionUrl=wefSubscriptionUrl(parsed.origin,secret,node.id,wefPath())
  } catch(error) {throw Object.assign(new Error(error.message),{status:503})}
  const applyRunId=id();run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',applyRunId,node.id,'running')
  try {
    const result=await remote(node,'wef_configure',{subscriptionUrl,refreshSeconds:data.refreshSeconds})
    if(result?.configured!==true)throw Object.assign(new Error('WEF source configuration was not confirmed'),{status:502})
    const configured=new URL(subscriptionUrl);configured.searchParams.delete('token')
    const summary={operation:'wef_configure',path:configured.pathname,refreshSeconds:result.refreshSeconds,auditPolicy:result.auditPolicy}
    run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json(summary),now(),applyRunId)
    audit(req.user.id,'wef.source.configure','node',node.id,null,{...summary,runId:applyRunId,transport:node.transport})
    res.json({nodeId:node.id,configured:true,subscriptionManager:configured.toString(),refreshSeconds:result.refreshSeconds,auditPolicy:result.auditPolicy,runId:applyRunId})
  } catch(error) {
    run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?',error.status===502?'unknown':'failed',error.message,now(),applyRunId)
    audit(req.user.id,'wef.source.configure.failed','node',node.id,null,{runId:applyRunId,error:error.message})
    throw Object.assign(new Error(`WEF source configuration failed: ${error.message}`),{status:error.status||502})
  }
}))
api.post('/nodes/:id/deploy-agent',requireRole('admin'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  if(node.connection_mode!=='agentless'||!['winrm','winrms'].includes(node.transport)||node.agent_id||one('SELECT id FROM agents WHERE node_id=?',node.id))return res.status(409).json({error:'Agent deployment requires an unenrolled WinRM agentless node'})
  if(!req.secure||!agentPkiReady())return res.status(503).json({error:'Agent deployment requires HTTPS and configured agent PKI'})
  const base=effectivePublicBaseUrl(req)
  if(!base.startsWith('https://'))return res.status(503).json({error:'Configure an HTTPS public base URL in Server config or PUBLIC_BASE_URL'})
  if(!process.env.AGENT_PACKAGE_PATH)return res.status(503).json({error:'Set AGENT_PACKAGE_PATH to a signed Windows agent executable'})
  let signerThumbprint
  try{signerThumbprint=normalizeSignerThumbprint(process.env.AGENT_SIGNER_THUMBPRINT)}
  catch(error){return res.status(503).json({error:error.message})}
  const packagePath=path.resolve(process.env.AGENT_PACKAGE_PATH)
  if(!fs.existsSync(packagePath)||!fs.statSync(packagePath).isFile())return res.status(503).json({error:'The signed agent executable was not found'})
  const digest=crypto.createHash('sha256')
  for await(const chunk of fs.createReadStream(packagePath))digest.update(chunk)
  const token=crypto.randomBytes(32).toString('base64url'),tokenId=id(),expiresAt=new Date(Date.now()+15*60_000).toISOString()
  run('INSERT INTO enrollment_tokens(id,node_id,token_hash,expires_at) VALUES(?,?,?,?)',tokenId,node.id,hashToken(token),expiresAt)
  const applyRunId=id(),packageSha256=digest.copy().digest('hex')
  run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',applyRunId,node.id,'running')
  audit(req.user.id,'agent.remote-deploy.start','node',node.id,null,{runId:applyRunId,packageSha256,expiresAt})
  try{
    const result=await remote(node,'agent_deploy',{serverUrl:base.replace(/\/$/,''),packageUrl:new URL('/api/v1/agent-package/WinFire.Agent.exe',base).toString(),sha256:digest.digest('hex'),signerThumbprint,token})
    const agent=one('SELECT id FROM agents WHERE node_id=?',node.id)
    if(!result?.installed||!agent||String(result.status).toLowerCase()!=='running'||String(result.sha256).toLowerCase()!==packageSha256)throw new Error('The agent service, package hash, or certificate enrollment was not confirmed')
    db.transaction(()=>{
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json({operation:'agent_deploy',agentId:agent.id,serviceStatus:result.status,packageSha256}),now(),applyRunId)
      audit(req.user.id,'agent.remote-deploy.success','node',node.id,null,{runId:applyRunId,agentId:agent.id,serviceStatus:result.status})
    })()
    res.json({installed:true,serviceStatus:result.status,agentId:agent.id,runId:applyRunId})
  }catch(error){
    run('DELETE FROM enrollment_tokens WHERE id=? AND used_at IS NULL',tokenId)
    const agentEnrolled=!!one('SELECT id FROM agents WHERE node_id=?',node.id)
    const status=agentEnrolled||/timed?\s*out|timeout|connection|unreachable|ECONNRESET/i.test(error.message)?'unknown':'failed'
    db.transaction(()=>{
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?',status,error.message,now(),applyRunId)
      audit(req.user.id,'agent.remote-deploy.failed','node',node.id,null,{runId:applyRunId,status,error:error.message,agentEnrolled})
    })()
    throw Object.assign(new Error(error.message),{status:502})
  }
}))
function queueBreakGlassJob(node,type,payload){
  const agent=one('SELECT id,last_checkin_at FROM agents WHERE id=? AND revoked_at IS NULL',node.agent_id)
  if(!agent)throw Object.assign(new Error('No active agent is enrolled on this node'),{status:409})
  if(!agent.last_checkin_at||Date.parse(agent.last_checkin_at)<Date.now()-5*60_000)throw Object.assign(new Error('Agent is offline; break glass requires an online agent'),{status:409})
  const jobId=id()
  run('INSERT INTO agent_jobs(id,agent_id,type,payload_json) VALUES(?,?,?,?)',jobId,agent.id,type,json(payload))
  return jobId
}
async function endBreakGlass(session,actorId=null,finalStatus='ended'){
  const node=getNode(session.node_id)
  if(!node)throw Object.assign(new Error('Node is missing'),{status:404})
  if(node.connection_mode==='agent'&&session.status==='ending')return {queued:true,session:publicBreakGlass(session)}
  const applyRunId=id()
  run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',applyRunId,node.id,'running')
  audit(actorId,'break-glass.end.start','node',node.id,null,{sessionId:session.id,runId:applyRunId,finalStatus})
  if(node.connection_mode==='agent'){
    try{
      const jobId=queueBreakGlassJob(node,'breakglass.end',{action:'end',breakGlassSessionId:session.id,sessionId:session.id,profiles:parse(session.profile_snapshot_json)||[],finalStatus,applyRunId})
      run("UPDATE break_glass_sessions SET status='ending',agent_job_id=?,last_error=NULL WHERE id=?",jobId,session.id)
      audit(actorId,'break-glass.end.queued','node',node.id,null,{sessionId:session.id,jobId,runId:applyRunId,finalStatus})
      return {queued:true,runId:applyRunId,session:publicBreakGlass(one('SELECT * FROM break_glass_sessions WHERE id=?',session.id))}
    }catch(error){
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',error.message,now(),applyRunId)
      audit(actorId,'break-glass.end.failed','node',node.id,null,{sessionId:session.id,runId:applyRunId,error:error.message})
      throw error
    }
  }
  try{
    const result=await remote(node,'breakglass_end',{sessionId:session.id,profiles:parse(session.profile_snapshot_json)||[]})
    if(result?.restored!==true)throw new Error('Firewall profile restore was not confirmed')
    db.transaction(()=>{
      run('UPDATE break_glass_sessions SET status=?,ended_at=?,last_error=NULL WHERE id=?',finalStatus,now(),session.id)
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json({operation:'breakglass_end',sessionId:session.id,profiles:result.profiles}),now(),applyRunId)
      audit(actorId,finalStatus==='expired'?'break-glass.expired':'break-glass.end','node',node.id,null,{sessionId:session.id,runId:applyRunId,profiles:result.profiles})
    })()
    return {queued:false,runId:applyRunId,session:publicBreakGlass(one('SELECT * FROM break_glass_sessions WHERE id=?',session.id))}
  }catch(error){
    db.transaction(()=>{
      run('UPDATE break_glass_sessions SET last_error=? WHERE id=?',error.message,session.id)
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','unknown',error.message,now(),applyRunId)
      audit(actorId,'break-glass.end.failed','node',node.id,null,{sessionId:session.id,runId:applyRunId,error:error.message})
    })()
    throw Object.assign(new Error(`Firewall restoration was not confirmed: ${error.message}`),{status:502})
  }
}
api.get('/nodes/:id/break-glass',requireRole('admin'),(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const sessions=all('SELECT * FROM break_glass_sessions WHERE node_id=? ORDER BY started_at DESC LIMIT 10',node.id).map(publicBreakGlass)
  res.json({active:sessions.find(session=>['activating','activation-unknown','active','ending'].includes(session.status))||null,history:sessions})
})
api.post('/nodes/:id/break-glass',requireRole('admin'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const data=body(z.object({durationMinutes:z.number().int().min(5).max(240),reason:z.string().trim().min(10).max(500),confirmed:z.boolean().optional(),confirmation:z.string().optional()}),req)
  if((data.confirmed!==undefined||data.confirmation!==undefined)&&!data.confirmed&&data.confirmation!=='OPEN FIREWALL')return res.status(400).json({error:'Confirmation is required'})
  if(node.connection_mode!=='agent'&&!['winrm','winrms'].includes(node.transport))return res.status(409).json({error:'Break glass requires WinRM or an enrolled agent'})
  if(one("SELECT id FROM break_glass_sessions WHERE node_id=? AND status IN ('activating','activation-unknown','active','ending')",node.id))return res.status(409).json({error:'Break glass is already active or pending for this node'})
  const sessionId=id(),startedAt=now(),expiresAt=new Date(Date.now()+data.durationMinutes*60_000).toISOString()
  run("INSERT INTO break_glass_sessions(id,node_id,actor_user_id,reason,started_at,expires_at,status) VALUES(?,?,?,?,?,?,'activating')",sessionId,node.id,req.user.id,data.reason,startedAt,expiresAt)
  const applyRunId=id()
  run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',applyRunId,node.id,'running')
  audit(req.user.id,'break-glass.request','node',node.id,null,{sessionId,runId:applyRunId,reason:data.reason,durationMinutes:data.durationMinutes,expiresAt})
  try{
    if(node.connection_mode==='agent'){
      const jobId=queueBreakGlassJob(node,'breakglass.start',{action:'start',breakGlassSessionId:sessionId,sessionId,expiresAt,applyRunId})
      run('UPDATE break_glass_sessions SET agent_job_id=? WHERE id=?',jobId,sessionId)
      return res.status(202).json({queued:true,runId:applyRunId,session:publicBreakGlass(one('SELECT * FROM break_glass_sessions WHERE id=?',sessionId))})
    }
    const result=await remote(node,'breakglass_start',{sessionId,expiresAt})
    const profiles=normalizeProfileSnapshot(result?.profiles)
    if(result?.active!==true||!profiles)throw new Error('Firewall disable readback or profile snapshot was invalid')
    db.transaction(()=>{
      run("UPDATE break_glass_sessions SET status='active',profile_snapshot_json=? WHERE id=?",json(profiles),sessionId)
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json({operation:'breakglass_start',sessionId,expiresAt,profiles}),now(),applyRunId)
      audit(req.user.id,'break-glass.active','node',node.id,null,{sessionId,runId:applyRunId,expiresAt,profiles})
    })()
    res.status(201).json({queued:false,runId:applyRunId,session:publicBreakGlass(one('SELECT * FROM break_glass_sessions WHERE id=?',sessionId))})
  }catch(error){
    run('UPDATE break_glass_sessions SET status=?,last_error=? WHERE id=?',node.connection_mode==='agent'?'failed':'activation-unknown',error.message,sessionId)
    run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?',node.connection_mode==='agent'?'failed':'unknown',error.message,now(),applyRunId)
    audit(req.user.id,'break-glass.start.failed','node',node.id,null,{sessionId,runId:applyRunId,error:error.message})
    res.status(error.status||502).json({error:error.message})
  }
}))
api.post('/nodes/:id/break-glass/end',requireRole('admin'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  const {sessionId}=body(z.object({sessionId:z.string().uuid()}),req)
  const session=one('SELECT * FROM break_glass_sessions WHERE id=? AND node_id=?',sessionId,node.id)
  if(!session)return notFound(res,'Break-glass session')
  if(!['activating','activation-unknown','active','ending'].includes(session.status))return res.status(409).json({error:'Break glass is not active'})
  if(session.status==='activating'&&node.connection_mode==='agent'){
    const job=one('SELECT status FROM agent_jobs WHERE id=?',session.agent_job_id)
    if(job?.status==='queued'){
      run("UPDATE agent_jobs SET status='failed',error='Cancelled before activation',finished_at=? WHERE id=?",now(),session.agent_job_id)
      const applyRunId=parse(one('SELECT payload_json FROM agent_jobs WHERE id=?',session.agent_job_id)?.payload_json)?.applyRunId
      if(applyRunId)run("UPDATE policy_apply_runs SET status='failed',error='Cancelled before activation',finished_at=? WHERE id=?",now(),applyRunId)
      run("UPDATE break_glass_sessions SET status='ended',ended_at=? WHERE id=?",now(),session.id)
      audit(req.user.id,'break-glass.cancel','node',node.id,null,{sessionId:session.id})
      return res.json({queued:false,session:publicBreakGlass(one('SELECT * FROM break_glass_sessions WHERE id=?',session.id))})
    }
    return res.status(409).json({error:'Wait for the agent to finish activating break glass before ending it'})
  }
  const result=await endBreakGlass(session,req.user.id)
  res.status(result.queued?202:200).json(result)
}))
api.get('/nodes/:id/facts',(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json(parse(one('SELECT snapshot_json FROM node_facts WHERE node_id=?',node.id)?.snapshot_json)||{})})
api.get('/nodes/:id/audit-policy',wrap(async(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');if(node.connection_mode==='agent')return res.status(409).json({error:'Audit policy inspection requires a WinRM node'});res.json(await remote(node,'audit_policy'))}))
api.post('/nodes/:id/audit-policy/enable',requireRole('admin'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  if(node.connection_mode==='agent')return res.status(409).json({error:'Audit policy changes require a WinRM node'})
  const data=body(z.object({confirmed:z.boolean().optional(),confirmation:z.string().optional()}),req)
  if(!data.confirmed&&data.confirmation!=='ENABLE WFP AUDITING')return res.status(400).json({error:'Confirmation is required'})
  const runId=id()
  run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',runId,node.id,'running')
  let before=null,attempted=false
  try {
    before=await remote(node,'audit_policy')
    attempted=true
    const after=await remote(node,'audit_policy_enable')
    if(after?.successEnabled!==true||after?.failureEnabled!==true)throw Object.assign(new Error('Audit policy readback did not confirm success and failure auditing'),{status:502})
    db.transaction(()=>{
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json({operation:'audit_policy_enable',before,after}),now(),runId)
      audit(req.user.id,'node.audit-policy.enable','node',node.id,before,{...after,runId})
    })()
    res.json(after)
  } catch(error){
    db.transaction(()=>{
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?',attempted?'unknown':'failed',error.message,now(),runId)
      audit(req.user.id,'node.audit-policy.enable.failed','node',node.id,before,{runId,error:error.message})
    })()
    throw error
  }
}))
api.post('/nodes/:id/facts/refresh',requireRole('editor'),wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  if(node.device_type==='esxi'){
    const credentials=accessibleEsxiCredentials(node,req.user).flatMap(credential=>{try{const secret=openSealed(credential.encrypted_blob);return secret?.password?[{username:credential.username,password:secret.password}]:[]}catch{return []}})
    const hypervisor=await identifyHypervisor(node.ip||node.fqdn||node.hostname,{credentials})
    if(!hypervisor.detected)return res.status(502).json({error:'VMware ESXi API did not respond or the assigned credential was rejected'})
    persistHypervisor(node.id,hypervisor)
    return res.json({source:'esxi',...hypervisor})
  }
  const snmpCredential=assignedSnmpCredential(node.id,req.user)
  if(snmpCredential){
    const result=await pollSnmpNode(node,{credential:openedCredential(snmpCredential),actorId:req.user.id})
    return res.json({...result,source:'snmp'})
  }
  const facts=await collectFacts(node);audit(req.user.id,'node.facts.refresh','node',node.id,null,facts);res.json(facts)
}))
api.get('/nodes/:id/firewall-rules',wrap(async(req,res)=>{
  const node=getNode(reqId(req));if(!node)return notFound(res,'Node')
  if(node.connection_mode==='agent')return res.status(409).json({error:'Live rule inventory requires a WinRM node'})
  const {offset,limit}=z.object({offset:z.coerce.number().int().min(0).default(0),limit:z.coerce.number().int().min(1).max(200).default(100)}).parse(req.query)
  const result=await remote(node,'all_rules',{offset,limit})
  res.json({total:Number(result?.total||0),offset,rules:Array.isArray(result?.rules)?result.rules:result?.rules?[result.rules]:[]})
}))
api.get('/nodes/:id/dns',(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json(one('SELECT * FROM dns_lookups WHERE node_id=?',node.id)||{})})
api.post('/nodes/:id/dns/refresh',requireRole('editor'),wrap(async(req,res)=>{const node=getNode(reqId(req));if(!node)return notFound(res,'Node');res.json(await lookupDns(node))}))
api.get('/node-groups',(req,res)=>res.json(all('SELECT * FROM node_groups ORDER BY name').filter(group=>canReadResource(req.user,'node_group',group)).map(group=>({...group,...publicDynamicGroup(group),count:Number(one('SELECT COUNT(*) count FROM node_group_members WHERE group_id=?',group.id)?.count||0),policy_count:Number(one('SELECT COUNT(*) count FROM policy_assignments WHERE node_group_id=?',group.id)?.count||0),canWrite:canWriteResource(req.user,'node_group',group)}))))
api.get('/node-groups/:id',(req,res)=>{
  const group=one('SELECT * FROM node_groups WHERE id=?',reqId(req));if(!group)return notFound(res,'Node group')
  if(!canReadResource(req.user,'node_group',group))return res.status(403).json({error:'Insufficient permission for node group'})
  const members=all('SELECT n.id,n.hostname,n.fqdn,n.ip,n.status,n.firewall_state FROM nodes n JOIN node_group_members m ON m.node_id=n.id WHERE m.group_id=? ORDER BY n.hostname',group.id)
  res.json({...group,...publicDynamicGroup(group),count:members.length,members,canWrite:canWriteResource(req.user,'node_group',group)})
})
api.post('/node-groups',requireRole('editor'),(req,res)=>{
  const data=body(z.object({name:z.string().trim().min(1).max(120),dynamic:z.object({enabled:z.boolean().optional(),match:z.enum(['all','any']).optional(),rules:z.array(z.object({field:z.enum(['name','hostname','fqdn','ip']),operator:z.enum(['contains','equals','cidr']),value:z.string().trim().min(1).max(255)})).max(25).optional()}).optional()}),req)
  let dynamic
  try{dynamic=normalizeDynamicRules(data.dynamic||{})}catch(error){return res.status(400).json({error:error.message})}
  const groupId=id(),next=dynamic.enabled?new Date(Date.now()+dynamicNodeGroupSettings().intervalMinutes*60_000).toISOString():null
  run('INSERT INTO node_groups(id,name,owner_user_id,dynamic_enabled,dynamic_match,dynamic_rules_json,dynamic_next_evaluation_at) VALUES(?,?,?,?,?,?,?)',groupId,data.name,req.user.id,Number(dynamic.enabled),dynamic.match,json(dynamic.rules),next)
  audit(req.user.id,'node-group.create','node-group',groupId,null,{name:data.name,dynamic})
  let group=one('SELECT * FROM node_groups WHERE id=?',groupId)
  if(dynamic.enabled){refreshDynamicGroups({groupId,force:true});group=one('SELECT * FROM node_groups WHERE id=?',groupId)}
  res.status(201).json({...group,...publicDynamicGroup(group),count:Number(one('SELECT COUNT(*) count FROM node_group_members WHERE group_id=?',groupId)?.count||0),owner_user_id:req.user.id})
})
api.patch('/node-groups/:id',requireRole('editor'),(req,res)=>{
  const group=one('SELECT * FROM node_groups WHERE id=?',reqId(req));if(!group)return notFound(res,'Node group')
  if(!canWriteResource(req.user,'node_group',group))return res.status(403).json({error:'Insufficient permission for node group'})
  const data=body(z.object({name:z.string().trim().min(1).max(120).optional(),dynamic:z.object({enabled:z.boolean().optional(),match:z.enum(['all','any']).optional(),rules:z.array(z.object({field:z.enum(['name','hostname','fqdn','ip']),operator:z.enum(['contains','equals','cidr']),value:z.string().trim().min(1).max(255)})).max(25).optional()}).optional()}),req)
  if(data.name!==undefined)run('UPDATE node_groups SET name=? WHERE id=?',data.name,group.id)
  if(data.dynamic!==undefined){let dynamicGroup;try{dynamicGroup=updateDynamicGroup(group.id,data.dynamic,req.user.id)}catch(error){return res.status(error.status||400).json({error:error.message})};if(dynamicGroup?.dynamic_enabled)refreshDynamicGroups({groupId:group.id,force:true})}
  const updated=one('SELECT * FROM node_groups WHERE id=?',group.id)
  res.json({...updated,...publicDynamicGroup(updated),count:Number(one('SELECT COUNT(*) count FROM node_group_members WHERE group_id=?',group.id)?.count||0),canWrite:canWriteResource(req.user,'node_group',updated)})
})
api.post('/node-groups/:id/refresh',requireRole('editor'),(req,res)=>{
  const group=one('SELECT * FROM node_groups WHERE id=?',reqId(req));if(!group)return notFound(res,'Node group')
  if(!group.dynamic_enabled)return res.status(409).json({error:'This node group does not use dynamic membership'})
  if(!canWriteResource(req.user,'node_group',group))return res.status(403).json({error:'Insufficient permission for node group'})
  res.json({results:refreshDynamicGroups({groupId:group.id,force:true})})
})
api.post('/node-groups/:id/members',requireRole('editor'),(req,res)=>{
  const {nodeId}=body(z.object({nodeId:z.string()}),req),node=getNode(nodeId),group=one('SELECT * FROM node_groups WHERE id=?',reqId(req))
  if(!node)return notFound(res,'Node')
  if(!group)return notFound(res,'Node group')
  if(group.dynamic_enabled)return res.status(409).json({error:'Dynamic node group membership is managed by its rules'})
  if(!canWriteResource(req.user,'node_group',group))return res.status(403).json({error:'Insufficient permission for node group'})
  const assigned=all(`SELECT DISTINCT p.id,p.name,v.rules_compiled_json FROM policies p JOIN policy_assignments a ON a.policy_id=p.id JOIN policy_versions v ON v.id=p.current_version_id WHERE a.node_group_id=?`,group.id)
  if(assigned.some(policy=>one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id)))return res.status(409).json({error:'Wait for pending agent firewall cleanup before changing this group'})
  const conflicts=[]
  for(const policy of assigned)conflicts.push(...assignmentConflicts(policy.id,parse(policy.rules_compiled_json)||[],[node]))
  for(let i=0;i<assigned.length;i++)for(let j=i+1;j<assigned.length;j++)for(const match of findRuleConflicts(parse(assigned[i].rules_compiled_json)||[],parse(assigned[j].rules_compiled_json)||[]))conflicts.push({nodeId:node.id,hostname:node.hostname,otherPolicyId:assigned[j].id,otherPolicy:assigned[j].name,...match})
  if(conflicts.length)return rejectConflicts(res,conflicts)
  run('INSERT OR IGNORE INTO node_group_members(group_id,node_id) VALUES(?,?)',group.id,nodeId)
  audit(req.user.id,'node-group.member','node-group',group.id,null,{nodeId});res.json({ok:true})
})
api.delete('/node-groups/:id/members/:nodeId',requireRole('editor'),wrap(async(req,res)=>{
  const group=one('SELECT * FROM node_groups WHERE id=?',reqId(req)),node=getNode(req.params.nodeId)
  if(!group)return notFound(res,'Node group')
  if(!node)return notFound(res,'Node')
  if(group.id==='winfire-global-all-nodes')return res.status(409).json({error:'Every node belongs to the global policy scope'})
  if(group.dynamic_enabled)return res.status(409).json({error:'Dynamic node group membership is managed by its rules'})
  if(!canWriteResource(req.user,'node_group',group))return res.status(403).json({error:'Insufficient permission for node group'})
  if(!one('SELECT 1 FROM node_group_members WHERE group_id=? AND node_id=?',group.id,node.id))return notFound(res,'Group membership')
  const policies=all('SELECT DISTINCT p.* FROM policies p JOIN policy_assignments a ON a.policy_id=p.id WHERE a.node_group_id=?',group.id)
  if(policies.some(policy=>!canWriteResource(req.user,'policy',policy)))return res.status(403).json({error:'Write access to each assigned policy is required to remove this member'})
  if(policies.some(policy=>one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id)))return res.status(409).json({error:'Wait for pending agent firewall cleanup before changing this group'})
  const cleanup=policies.filter(policy=>!one(`SELECT a.id FROM policy_assignments a WHERE a.policy_id=? AND (a.node_id=? OR a.node_group_id IN (SELECT m.group_id FROM node_group_members m WHERE m.node_id=? AND m.group_id<>?))`,policy.id,node.id,node.id,group.id))
  if(cleanup.length&&firewallConnectorFor(node).queuedReadback)return res.status(409).json({error:'Removing an agent node from a policy group needs coordinated agent cleanup and is not available yet'})
  const snapshots=[]
  try {
    for(const policy of cleanup){
      const rules=await firewallConnectorFor(node).readRules(`WinFireSecure:${policy.id}`)
      snapshots.push({policy,rules})
    }
  } catch(error){return res.status(502).json({error:`Could not read managed rules before membership removal: ${error.message}`})}
  const completed=[]
  for(const snapshot of snapshots){
    const runId=id()
    run('INSERT INTO policy_apply_runs(id,policy_id,version_id,node_id,status) VALUES(?,?,?,?,?)',runId,snapshot.policy.id,snapshot.policy.current_version_id,node.id,'running')
    try {completed.push({...snapshot,runId,diff:await applyManagedRules(node,snapshot.policy.id,[])})}
    catch(error){
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',error.message,now(),runId)
      const rollbackErrors=[]
      for(const prior of completed.reverse()){
        try {await applyManagedRules(node,prior.policy.id,prior.rules)}
        catch(rollbackError){rollbackErrors.push({policyId:prior.policy.id,error:rollbackError.message})}
        run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',rollbackErrors.find(item=>item.policyId===prior.policy.id)?.error||'Membership removal aborted; original rules restored',now(),prior.runId)
      }
      audit(req.user.id,'node-group.member.remove.failed','node-group',group.id,null,{nodeId:node.id,policyId:snapshot.policy.id,error:error.message,rollbackErrors})
      return res.status(502).json({error:'Firewall cleanup failed; group membership retained',policyId:snapshot.policy.id,detail:error.message,rollbackErrors})
    }
  }
  db.transaction(()=>{
    run('DELETE FROM node_group_members WHERE group_id=? AND node_id=?',group.id,node.id)
    for(const item of completed)run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json(item.diff),now(),item.runId)
    audit(req.user.id,'node-group.member.remove','node-group',group.id,{nodeId:node.id},{cleanedPolicies:completed.map(item=>item.policy.id),retainedByOtherAssignment:policies.length-completed.length})
  })()
  res.json({removed:true,cleanedPolicies:completed.map(item=>item.policy.id),retainedByOtherAssignment:policies.length-completed.length})
}))

api.get('/policies',(req,res)=>res.json(all('SELECT p.*,v.version_no FROM policies p LEFT JOIN policy_versions v ON v.id=p.current_version_id ORDER BY p.created_at DESC').filter(policy=>canReadResource(req.user,'policy',policy)).map(policy=>({...policy,scopes:all('SELECT node_id,node_group_id FROM policy_assignments WHERE policy_id=?',policy.id),verificationStatus:policyVerification(policy.id),learning:policy.origin==='learned'?one('SELECT id,status,ends_at,progressive_enabled,next_progressive_at,last_progressive_at FROM learning_sessions WHERE generated_policy_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1',policy.id):null}))))
api.get('/policies/sync',requireRole('admin'),(_req,res)=>res.json({pending:pendingPolicySync(),schedules:all("SELECT id,execute_at,status,created_at,finished_at,result_json FROM policy_sync_schedules WHERE status IN ('scheduled','running') ORDER BY execute_at") }))
api.post('/policies/sync',requireRole('admin'),wrap(async(req,res)=>{
  const data=body(z.object({executeAt:z.iso.datetime({offset:true}).optional()}),req)
  if(data.executeAt&&Date.parse(data.executeAt)>Date.now()+10_000){
    const scheduleId=id()
    run('INSERT INTO policy_sync_schedules(id,requested_by,execute_at,status) VALUES(?,?,?,?)',scheduleId,req.user.id,data.executeAt,'scheduled')
    audit(req.user.id,'policy.sync.schedule','policy',null,null,{scheduleId,executeAt:data.executeAt})
    return res.status(201).json({id:scheduleId,status:'scheduled',executeAt:data.executeAt})
  }
  const results=await performPolicySync(req.user.id)
  res.json({results,pending:pendingPolicySync().length})
}))
api.delete('/policies/sync/:scheduleId',requireRole('admin'),(req,res)=>{
  const schedule=one("SELECT * FROM policy_sync_schedules WHERE id=? AND status='scheduled'",req.params.scheduleId)
  if(!schedule)return notFound(res,'Scheduled sync')
  run("UPDATE policy_sync_schedules SET status='cancelled',finished_at=? WHERE id=?",now(),schedule.id)
  audit(req.user.id,'policy.sync.cancel','policy',null,schedule,null)
  res.status(204).end()
})
api.post('/policies',requireRole('editor'),(req,res)=>{const data=body(z.object({name:z.string().min(1),description:z.string().default('')}),req),policyId=id();run('INSERT INTO policies(id,name,description,owner_user_id) VALUES(?,?,?,?)',policyId,data.name,data.description,req.user.id);audit(req.user.id,'policy.create','policy',policyId,null,data);res.status(201).json(getPolicy(policyId))})
api.get('/policies/:id',(req,res)=>{const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy');if(!canReadResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'});res.json({...policy,versions:all('SELECT id,version_no,created_at,comment FROM policy_versions WHERE policy_id=? ORDER BY version_no DESC',policy.id),assignments:all('SELECT * FROM policy_assignments WHERE policy_id=?',policy.id)})})
api.get('/policies/:id/versions',(req,res)=>{const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy');if(!canReadResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'});res.json(all('SELECT * FROM policy_versions WHERE policy_id=? ORDER BY version_no DESC',policy.id).map(v=>{const graph=parse(v.graph_json)||{nodes:[],edges:[]};return {...v,graph,rules:parse(v.rules_compiled_json),mfaGates:extractMfaGates(graph)}}))})
api.get('/policies/:id/learning-preview',(req,res)=>{
  const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy')
  if(!canReadResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'})
  const session=one("SELECT * FROM learning_sessions WHERE generated_policy_id=? AND status='active' ORDER BY started_at DESC,rowid DESC LIMIT 1",policy.id)
  if(!session)return res.status(409).json({error:'This policy has no active learning session'})
  res.json(learningPreview(session))
})
api.post('/policies/:id/versions',requireRole('editor'),(req,res)=>{
  const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy')
  if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'})
  if(hasActiveLearning(policy.id))return res.status(409).json({error:'Automatic learning owns this policy until training ends'})
  if(one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id))return res.status(409).json({error:'Wait for pending agent firewall cleanup before changing this policy'})
  const data=body(z.object({graph:graphSchema,comment:z.string().default('')}),req),rules=compilePolicy(data.graph,policy.id),versionId=id()
  assertManagementAccess(rules)
  const conflicts=assignmentConflicts(policy.id,rules,assignedNodes(policy.id))
  if(conflicts.length)return rejectConflicts(res,conflicts)
  const last=one('SELECT MAX(version_no) as n FROM policy_versions WHERE policy_id=?',policy.id)?.n||0
  db.transaction(()=>{run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,policy.id,last+1,json(data.graph),json(rules),req.user.id,data.comment);run('UPDATE policies SET current_version_id=? WHERE id=?',versionId,policy.id);audit(req.user.id,'policy.version.create','policy',policy.id,null,{versionId,versionNo:last+1,rules})})()
  res.status(201).json({id:versionId,versionNo:last+1,rules,mfaGates:extractMfaGates(data.graph)})
})
api.post('/policies/:id/versions/:versionId/recall',requireRole('editor'),(req,res)=>{const policy=getPolicy(reqId(req)),version=one('SELECT * FROM policy_versions WHERE id=? AND policy_id=?',req.params.versionId,reqId(req));if(!policy||!version)return notFound(res,'Version');if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'});if(hasActiveLearning(policy.id))return res.status(409).json({error:'Automatic learning owns this policy until training ends'});if(one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id))return res.status(409).json({error:'Wait for pending agent firewall cleanup before changing this policy'});const conflicts=assignmentConflicts(policy.id,parse(version.rules_compiled_json)||[],assignedNodes(policy.id));if(conflicts.length)return rejectConflicts(res,conflicts);run('UPDATE policies SET current_version_id=? WHERE id=?',version.id,policy.id);audit(req.user.id,'policy.recall','policy',policy.id,{versionId:policy.current_version_id},{versionId:version.id});res.json({versionId:version.id,pendingSync:true})})
api.post('/policies/:id/assignments',requireRole('editor'),(req,res)=>{const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy');if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'});if(hasActiveLearning(policy.id))return res.status(409).json({error:'Automatic learning owns this policy until training ends'});if(one('SELECT id FROM policy_assignments WHERE policy_id=? AND removal_job_id IS NOT NULL',policy.id))return res.status(409).json({error:'Wait for pending agent firewall cleanup before assigning this policy'});if(one("SELECT id FROM learning_sessions WHERE generated_policy_id=? AND status IN ('review','apply-failed')",policy.id))return res.status(409).json({error:'Approve the learning proposal before assigning it'});const data=body(z.object({nodeId:z.string().optional(),nodeGroupId:z.string().optional()}),req);if(Number(!!data.nodeId)+Number(!!data.nodeGroupId)!==1)return res.status(400).json({error:'Specify exactly one nodeId or nodeGroupId'});const targets=data.nodeId?[getNode(data.nodeId)].filter(Boolean):all('SELECT n.* FROM nodes n JOIN node_group_members m ON m.node_id=n.id WHERE m.group_id=?',data.nodeGroupId);if(data.nodeId&&!targets.length)return notFound(res,'Node');const targetGroup=data.nodeGroupId?one('SELECT * FROM node_groups WHERE id=?',data.nodeGroupId):null;if(data.nodeGroupId&&!targetGroup)return notFound(res,'Node group');if(targetGroup&&!canWriteResource(req.user,'node_group',targetGroup))return res.status(403).json({error:'Insufficient permission for node group'});const rules=parse(one('SELECT rules_compiled_json FROM policy_versions WHERE id=?',policy.current_version_id)?.rules_compiled_json)||[];const conflicts=assignmentConflicts(policy.id,rules,targets);if(conflicts.length)return rejectConflicts(res,conflicts);const assignmentId=id();run('INSERT INTO policy_assignments(id,policy_id,node_id,node_group_id,assigned_by) VALUES(?,?,?,?,?)',assignmentId,policy.id,data.nodeId||null,data.nodeGroupId||null,req.user.id);audit(req.user.id,'policy.assign','policy',policy.id,null,data);res.status(201).json({id:assignmentId,...data})})
api.delete('/policies/:id/assignments/:assignmentId',requireRole('editor'),wrap(async(req,res)=>{
  const policy=getPolicy(reqId(req))
  if(!policy)return notFound(res,'Policy')
  if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'})
  if(hasActiveLearning(policy.id))return res.status(409).json({error:'Automatic learning owns this policy until training ends'})
  const assignment=one('SELECT * FROM policy_assignments WHERE id=? AND policy_id=?',req.params.assignmentId,policy.id)
  if(!assignment)return notFound(res,'Assignment')
  const group=assignment.node_group_id?one('SELECT * FROM node_groups WHERE id=?',assignment.node_group_id):null
  if(group&&!canWriteResource(req.user,'node_group',group))return res.status(403).json({error:'Insufficient permission for node group'})
  if(assignment.removal_job_id)return res.status(202).json({queued:true,jobId:assignment.removal_job_id})
  const targets=assignment.node_id?[getNode(assignment.node_id)].filter(Boolean):all('SELECT n.* FROM nodes n JOIN node_group_members m ON m.node_id=n.id WHERE m.group_id=?',assignment.node_group_id)
  const cleanup=targets.filter(node=>!one(`SELECT id FROM policy_assignments WHERE policy_id=? AND id<>? AND (node_id=? OR node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?))`,policy.id,assignment.id,node.id,node.id))
  if(cleanup.some(node=>firewallConnectorFor(node).queuedReadback)){
    if(!assignment.node_id||cleanup.length!==1)return res.status(409).json({error:'Group removal with agent nodes needs coordinated cleanup and is not available yet'})
    const queued=firewallConnectorFor(cleanup[0]).queuePolicyRemoval({policy,assignment,actorId:req.user.id})
    return res.status(202).json({queued:true,...queued})
  }
  const snapshots=[]
  try {
    for(const node of cleanup){
      const rules=await firewallConnectorFor(node).readRules(`WinFireSecure:${policy.id}`)
      snapshots.push({node,rules})
    }
  } catch(error){return res.status(502).json({error:`Could not read managed rules before removal: ${error.message}`})}
  const completed=[]
  for(const snapshot of snapshots){
    const runId=id()
    run('INSERT INTO policy_apply_runs(id,policy_id,version_id,node_id,status) VALUES(?,?,?,?,?)',runId,policy.id,policy.current_version_id,snapshot.node.id,'running')
    try {
      const diff=await applyManagedRules(snapshot.node,policy.id,[])
      completed.push({...snapshot,runId,diff})
    } catch(error){
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',error.message,now(),runId)
      const rollbackErrors=[]
      for(const prior of completed.reverse()){
        try {await applyManagedRules(prior.node,policy.id,prior.rules)}
        catch(rollbackError){rollbackErrors.push({nodeId:prior.node.id,error:rollbackError.message})}
        run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',rollbackErrors.find(item=>item.nodeId===prior.node.id)?.error||'Removal aborted; original rules restored',now(),prior.runId)
      }
      audit(req.user.id,'policy.unassign.failed','policy',policy.id,null,{assignmentId:assignment.id,nodeId:snapshot.node.id,error:error.message,rollbackErrors})
      return res.status(502).json({error:'Firewall cleanup failed; assignment retained',nodeId:snapshot.node.id,detail:error.message,rollbackErrors})
    }
  }
  db.transaction(()=>{
    run('DELETE FROM policy_assignments WHERE id=?',assignment.id)
    for(const item of completed)run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json(item.diff),now(),item.runId)
    audit(req.user.id,'policy.unassign','policy',policy.id,assignment,{assignmentId:assignment.id,cleanedNodes:completed.map(item=>item.node.id),retainedByOtherAssignment:targets.length-completed.length})
  })()
  res.json({removed:true,cleanedNodes:completed.map(item=>item.node.id),retainedByOtherAssignment:targets.length-completed.length})
}))
api.post('/policies/:id/apply',requireRole('admin'),wrap(async(req,res)=>{const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy');if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'});if(hasActiveLearning(policy.id))return res.status(409).json({error:'Automatic learning owns this policy until training ends'});if(one("SELECT id FROM learning_sessions WHERE generated_policy_id=? AND status IN ('review','apply-failed')",policy.id))return res.status(409).json({error:'Approve the learning proposal before applying it'});res.json({results:await applyPolicy(policy,req.user.id)})}))
api.get('/policies/:id/diff',(req,res)=>{
  const policy=getPolicy(reqId(req));if(!policy)return notFound(res,'Policy')
  if(!canReadResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'})
  const a=one('SELECT * FROM policy_versions WHERE id=? AND policy_id=?',req.query.from,reqId(req)),b=one('SELECT * FROM policy_versions WHERE id=? AND policy_id=?',req.query.to,reqId(req))
  if(!a||!b)return notFound(res,'Version')
  const left=parse(a.rules_compiled_json)||[],right=parse(b.rules_compiled_json)||[]
  const before=parse(a.graph_json)||{nodes:[],edges:[]},after=parse(b.graph_json)||{nodes:[],edges:[]}
  const oldNodes=new Map(before.nodes.map(node=>[node.id,node])),newNodes=new Map(after.nodes.map(node=>[node.id,node]))
  const edgeKey=edge=>`${edge.source}\u0000${edge.target}`
  const oldEdges=new Set(before.edges.map(edgeKey)),newEdges=new Set(after.edges.map(edgeKey))
  res.json({
    from:{id:a.id,versionNo:a.version_no},to:{id:b.id,versionNo:b.version_no},
    added:right.filter(rule=>!left.some(previous=>JSON.stringify(previous)===JSON.stringify(rule))),
    removed:left.filter(rule=>!right.some(next=>JSON.stringify(next)===JSON.stringify(rule))),
    graph:{
      addedNodes:after.nodes.filter(node=>!oldNodes.has(node.id)),
      removedNodes:before.nodes.filter(node=>!newNodes.has(node.id)),
      changedNodes:after.nodes.filter(node=>oldNodes.has(node.id)&&JSON.stringify(oldNodes.get(node.id))!==JSON.stringify(node)).map(node=>({before:oldNodes.get(node.id),after:node})),
      addedEdges:after.edges.filter(edge=>!oldEdges.has(edgeKey(edge))),
      removedEdges:before.edges.filter(edge=>!newEdges.has(edgeKey(edge)))
    }
  })
})

export async function runDriftCheck(data={},actorId=null,canCheckPolicy=()=>true) {
  if(data.policyId&&!getPolicy(data.policyId))throw Object.assign(new Error('Policy not found'),{status:404})
  if(data.nodeId&&!getNode(data.nodeId))throw Object.assign(new Error('Node not found'),{status:404})
  const policies=(data.policyId?[getPolicy(data.policyId)]:all('SELECT * FROM policies WHERE current_version_id IS NOT NULL')).filter(canCheckPolicy)
  const checks=[]
  for(const policy of policies){
    const version=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
    if(!version)continue
    const desired=activePolicyRules(parse(version.rules_compiled_json)||[])
    for(const node of assignedNodes(policy.id).filter(item=>!data.nodeId||item.id===data.nodeId)){
      const connector=firewallConnectorFor(node)
      if(connector.queuedReadback){
        const pending=one(`SELECT d.* FROM policy_drift_checks d JOIN agent_jobs j ON json_extract(j.payload_json,'$.driftCheckId')=d.id WHERE d.node_id=? AND d.policy_id=? AND d.version_id=? AND d.status='pending' AND j.status IN ('queued','leased') ORDER BY datetime(d.checked_at) DESC LIMIT 1`,node.id,policy.id,version.id)
        if(pending){checks.push({id:pending.id,policyId:policy.id,versionId:version.id,nodeId:node.id,status:'pending',diff:null,error:null,checkedAt:pending.checked_at,reused:true});continue}
      }
      let status='unknown',diff=null,error=null
      try {
        const observed=await connector.readRules(`WinFireSecure:${policy.id}`)
        if(connector.queuedReadback)status='pending'
        else{
          diff=diffRules(desired,observed)
          status=diff.add.length||diff.remove.length?'drift':'in-sync'
        }
      } catch(cause){error=cause.message}
      const check={id:id(),policyId:policy.id,versionId:version.id,nodeId:node.id,status,diff,error,checkedAt:now()}
      const previous=one('SELECT status FROM policy_drift_checks WHERE policy_id=? AND node_id=? AND version_id=? ORDER BY checked_at DESC,rowid DESC LIMIT 1',policy.id,node.id,version.id)?.status
      db.transaction(()=>{
        run('INSERT INTO policy_drift_checks(id,policy_id,version_id,node_id,status,diff_json,error,checked_at) VALUES(?,?,?,?,?,?,?,?)',check.id,check.policyId,check.versionId,check.nodeId,check.status,json(check.diff),check.error,check.checkedAt)
        if(status==='pending')connector.queueReadback({driftCheckId:check.id,policyId:policy.id,versionId:version.id})
      })()
      if(status==='drift'&&previous!=='drift')emitNotification({eventKey:`drift:${check.id}`,category:'policy_drift',title:'Policy drift detected',body:`${policy.name} differs from the firewall rules on ${node.hostname}.`,entityType:'node',entityId:node.id})
      checks.push(check)
    }
  }
  audit(actorId,'policy.drift.check','policy',data.policyId||null,null,{nodeId:data.nodeId||null,checks:checks.length,drift:checks.filter(check=>check.status==='drift').length,unknown:checks.filter(check=>check.status==='unknown').length})
  return {checks}
}
api.post('/drift/checks',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({nodeId:z.string().optional(),policyId:z.string().optional()}),req)
  if(data.policyId&&!canWriteResource(req.user,'policy',getPolicy(data.policyId)))return res.status(403).json({error:'Insufficient permission for policy'})
  res.status(201).json(await runDriftCheck(data,req.user.id,policy=>canWriteResource(req.user,'policy',policy)))
}))
api.get('/drift/checks',(req,res)=>{
  const filters=[],args=[]
  if(req.query.nodeId){filters.push('node_id=?');args.push(String(req.query.nodeId))}
  if(req.query.policyId){filters.push('policy_id=?');args.push(String(req.query.policyId))}
  const visible=readablePolicyIds(req.user)
  res.json(all(`SELECT * FROM policy_drift_checks ${filters.length?'WHERE '+filters.join(' AND '):''} ORDER BY datetime(checked_at) DESC LIMIT 500`,...args).filter(row=>visible.has(row.policy_id)).map(row=>({...row,diff:parse(row.diff_json)})))
})

async function verifyOne(node,policy,rule,runId,actualRules,targetConnector,vantageNode=null,vantageConnector=null) {
  const singleTcpPort=rule.direction==='in' && rule.protocol==='TCP' && /^\d{1,5}$/.test(String(rule.localPort))
  const port=singleTcpPort?Number(rule.localPort):null
  const supported=port!==null && port>=1 && port<=65535
  const started=Date.now()
  let baselineRecordId=null,eventError=null
  if(rule.action==='block'&&supported&&targetConnector.readsSecurityEvents){
    try{
      baselineRecordId=Number(await targetConnector.eventCursor())
      if(!Number.isSafeInteger(baselineRecordId)||baselineRecordId<0)throw new Error('Invalid Security log cursor')
    }catch(error){baselineRecordId=null;eventError=`Security log cursor unavailable: ${error.message}`}
  }
  const probeStartedAt=now()
  let probe=null,probeError=null
  if(supported){
    if(vantageNode?.id===node.id)probeError='The verifier peer is the target node; choose another peer for a network-path check'
    else if(vantageNode){
      try{
        probe=await vantageConnector.probeTcp({host:node.ip||node.fqdn||node.hostname,port,timeoutMs:1500})
        if(!['open','refused','timeout','unreachable'].includes(probe?.status))throw new Error('Verifier peer returned invalid probe evidence')
      }catch(error){probe=null;probeError=`Verifier peer unavailable: ${error.message}`}
    }else probe=await tcpProbe(node.ip||node.fqdn||node.hostname,port,1500)
  }
  const probeFinishedAt=now()
  const managedRulePresent=actualRules===null?null:hasManagedRule(rule,actualRules)
  let firewallEvent=null
  if(rule.action==='block'&&supported&&['refused','timeout'].includes(probe?.status)&&probe?.sourceIp&&probe?.sourcePort){
    if(targetConnector.readsSecurityEvents&&baselineRecordId!==null){
      try{
        const collected=await targetConnector.probeEvents()
        insertCollectedEvents(node.id,Array.isArray(collected)?collected:collected?[collected]:[],false)
      }catch(error){eventError=error.message}
    }
    if(!targetConnector.readsSecurityEvents||baselineRecordId!==null){
      const candidates=all(`SELECT e.record_id,e.event_id,e.event_time,e.action,e.filter_origin,e.filter_runtime_id,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.direction,p.direction) direction,COALESCE(e.src_ip,p.src_ip) src_ip,e.src_port,COALESCE(e.dst_port,p.dst_port) dst_port
        FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE ${visibleFirewallEventSql()} AND e.node_id=? AND e.event_id=5157 AND e.src_port=? AND COALESCE(e.dst_port,p.dst_port)=? AND (? IS NULL OR e.record_id>?) AND (? IS NOT NULL OR datetime(e.event_time)>=datetime(?)) ORDER BY e.record_id DESC LIMIT 100`,node.id,probe.sourcePort,port,baselineRecordId,baselineRecordId,baselineRecordId,new Date(Date.parse(probeStartedAt)-2000).toISOString())
      firewallEvent=findMatchingDenyEvent(candidates,probe,port,probeStartedAt,probeFinishedAt,baselineRecordId)
    }
  }
  const managedRuleName=managedRulePresent?actualRules.find(item=>item.name===rule.name)?.internalName:null
  const evidence=probeError?{status:'inconclusive',reason:probeError}:supported?classifyVerification(rule,probe.status,managedRulePresent,firewallEvent,managedRuleName):{status:'inconclusive',reason:'Only single-port inbound TCP rules have a network probe'}
  if(eventError&&evidence.status==='inconclusive'&&rule.action==='block')evidence.reason+=`; event collection failed: ${eventError}`
  const expected=rule.action==='allow'?'open':'closed',actual=probe?.status==='open'?'open':probe?.status||'not-probed'
  const result={id:id(),runId,nodeId:node.id,policyId:policy.id,vantageNodeId:vantageNode?.id||null,port,proto:rule.protocol,expected,actual,probeStatus:probe?.status||null,probeSourceIp:probe?.sourceIp||null,probeSourcePort:probe?.sourcePort||null,firewallEventRecordId:firewallEvent?.record_id||null,firewallEventTime:firewallEvent?.event_time||null,firewallEventFilterOrigin:firewallEvent?.filter_origin||null,managedRulePresent,latencyMs:Date.now()-started,...evidence,passed:evidence.status==='inconclusive'?null:evidence.status==='pass'}
  const previous=one('SELECT status FROM verifier_results WHERE node_id=? AND policy_id=? AND port IS ? AND proto=? AND expected=? ORDER BY run_at DESC,rowid DESC LIMIT 1',node.id,policy.id,port,rule.protocol,expected)?.status
  run('INSERT INTO verifier_results(id,run_id,node_id,policy_id,vantage_node_id,port,proto,expected,actual,latency_ms,passed,status,reason,probe_status,managed_rule_present,probe_source_ip,probe_source_port,firewall_event_record_id,firewall_event_time,firewall_event_filter_origin) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',result.id,runId,node.id,policy.id,result.vantageNodeId,port,rule.protocol,expected,actual,result.latencyMs,result.passed===null?null:Number(result.passed),result.status,result.reason,result.probeStatus,result.managedRulePresent===null?null:Number(result.managedRulePresent),result.probeSourceIp,result.probeSourcePort,result.firewallEventRecordId,result.firewallEventTime,result.firewallEventFilterOrigin)
  if(result.status==='fail'&&previous!=='fail')emitNotification({eventKey:`verifier:${result.id}`,category:'verifier_failure',title:'Firewall verification failed',body:`${policy.name} on ${node.hostname}: ${rule.protocol} ${port||'rule'} — ${result.reason}.`,entityType:'node',entityId:node.id})
  return result
}
export async function runVerification(data={},actorId=null,canCheckPolicy=()=>true) {
  const vantageNode=data.vantageNodeId?getNode(data.vantageNodeId):null
  const vantageConnector=vantageNode?firewallConnectorFor(vantageNode):null
  if(data.vantageNodeId&&!vantageNode)throw Object.assign(new Error('Verifier peer not found'),{status:404})
  if(vantageConnector&&!vantageConnector.supportsTcpProbe)throw Object.assign(new Error('Verifier peer requires a working WinRM connection'),{status:409})
  const runId=id()
  run('INSERT INTO verifier_runs(id,status,requested_by) VALUES(?,?,?)',runId,'running',actorId)
  const policies=(data.policyId?[getPolicy(data.policyId)].filter(Boolean):all('SELECT * FROM policies WHERE current_version_id IS NOT NULL')).filter(canCheckPolicy)
  const results=[]
  for(const policy of policies){
    const version=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
    const rules=parse(version.rules_compiled_json)||[]
    for(const node of assignedNodes(policy.id).filter(n=>!data.nodeId||n.id===data.nodeId)){
      const targetConnector=firewallConnectorFor(node)
      let actualRules=null
      if(rules.some(rule=>rule.action==='block')) {
        try {actualRules=await targetConnector.readRules(`WinFireSecure:${policy.id}`)}
        catch {actualRules=null}
      }
      for(const rule of rules){const result=await verifyOne(node,policy,rule,runId,actualRules,targetConnector,vantageNode,vantageConnector);if(result)results.push(result)}
    }
  }
  run('UPDATE verifier_runs SET status=?,finished_at=? WHERE id=?','complete',now(),runId)
  audit(actorId,'verifier.run','verifier',runId,null,{results:results.length,vantageNodeId:vantageNode?.id||null})
  return {id:runId,status:'complete',results}
}
api.post('/verifier/runs',requireRole('editor'),wrap(async(req,res)=>{
  const data=body(z.object({nodeId:z.string().optional(),policyId:z.string().optional(),vantageNodeId:z.string().optional()}),req)
  if(data.policyId&&!canWriteResource(req.user,'policy',getPolicy(data.policyId)))return res.status(403).json({error:'Insufficient permission for policy'})
  res.status(201).json(await runVerification(data,req.user.id,policy=>canWriteResource(req.user,'policy',policy)))
}))
api.get('/verifier/runs/:id',(req,res)=>{const result=one('SELECT * FROM verifier_runs WHERE id=?',reqId(req));if(!result)return notFound(res,'Verifier run');const visible=readablePolicyIds(req.user),results=all('SELECT * FROM verifier_results WHERE run_id=?',result.id).filter(row=>visible.has(row.policy_id));if(!results.length&&result.requested_by!==req.user.id&&!['owner','admin'].includes(req.user.role))return notFound(res,'Verifier run');res.json({...result,results})})
api.get('/verifier/results',(req,res)=>{const visible=readablePolicyIds(req.user);res.json(all('SELECT * FROM verifier_results ORDER BY run_at DESC LIMIT 500').filter(row=>visible.has(row.policy_id)))})

function driftSummaryByNode() {
  const assignments=all(`SELECT DISTINCT a.policy_id,COALESCE(a.node_id,m.node_id) node_id FROM policy_assignments a LEFT JOIN node_group_members m ON m.group_id=a.node_group_id WHERE COALESCE(a.node_id,m.node_id) IS NOT NULL`)
  const latest=all(`SELECT d.node_id,d.policy_id,d.status FROM policy_drift_checks d JOIN policies p ON p.id=d.policy_id AND p.current_version_id=d.version_id WHERE d.rowid=(SELECT d2.rowid FROM policy_drift_checks d2 WHERE d2.node_id=d.node_id AND d2.policy_id=d.policy_id AND d2.version_id=d.version_id ORDER BY datetime(d2.checked_at) DESC,d2.rowid DESC LIMIT 1)`)
  const byPair=new Map(latest.map(row=>[`${row.node_id}:${row.policy_id}`,row.status]))
  const byNode=new Map()
  for(const assignment of assignments){
    const statuses=byNode.get(assignment.node_id)||[]
    statuses.push(byPair.get(`${assignment.node_id}:${assignment.policy_id}`)||'unchecked')
    byNode.set(assignment.node_id,statuses)
  }
  return new Map([...byNode].map(([nodeId,statuses])=>[nodeId,statuses.includes('drift')?'drift':statuses.includes('unknown')?'unknown':statuses.includes('pending')?'pending':statuses.includes('unchecked')?'unchecked':'in-sync']))
}
function report(name,user=null) {
  if(name==='inventory')return all(`SELECT n.id,n.hostname,n.fqdn,n.ip,n.os_name,n.os_version,n.os_build,n.status,n.last_seen_at,n.connection_mode,n.inventory_source,n.ad_enabled,n.ad_missing,n.firewall_state,f.snapshot_json,f.collected_at,(SELECT status FROM policy_apply_runs WHERE node_id=n.id AND policy_id IS NOT NULL ORDER BY started_at DESC,rowid DESC LIMIT 1) last_apply_status,(SELECT finished_at FROM policy_apply_runs WHERE node_id=n.id AND policy_id IS NOT NULL ORDER BY started_at DESC,rowid DESC LIMIT 1) last_apply_at,(SELECT status FROM verifier_results WHERE node_id=n.id ORDER BY run_at DESC,rowid DESC LIMIT 1) last_verify_status FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id ORDER BY n.hostname`).filter(isLocalAssetNode).map(({snapshot_json,...row})=>{
    const facts=parse(snapshot_json)||{}
    const profiles=Array.isArray(facts.firewall)?facts.firewall:facts.firewall?[facts.firewall]:[]
    return {...row,...normalizedNodeOs(row),model:facts.computer?.Model||null,manufacturer:facts.computer?.Manufacturer||null,bios_serial:facts.bios?.SerialNumber||null,firewall_service:facts.service?.Status||null,firewall_profiles:profiles.map(profile=>`${profile.Name}: ${profile.Enabled?'on':'off'}`).join(', ')||null}
  })
  if(name==='dns')return all(`SELECT n.id,n.hostname,n.fqdn,n.ip,d.forward_result,d.reverse_result,d.mismatch,d.checked_at FROM nodes n LEFT JOIN dns_lookups d ON d.node_id=n.id ORDER BY n.hostname`).map(row=>{
    const forward=parse(row.forward_result)||[],reverse=parse(row.reverse_result)||[]
    const expected=String(row.fqdn||row.hostname).toLowerCase().replace(/\.$/,'')
    const ptrMissing=!!(row.ip&&!reverse.length)
    const ptrMismatch=!!(reverse.length&&!reverse.some(name=>String(name).toLowerCase().replace(/\.$/,'')===expected))
    const forwardMismatch=!!(row.ip&&forward.length&&!forward.some(address=>address.address===row.ip))
    return {id:row.id,hostname:row.hostname,fqdn:row.fqdn,ip:row.ip,forward_addresses:forward.map(address=>address.address).join(', '),reverse_names:reverse.join(', '),ptr_missing:ptrMissing,ptr_mismatch:ptrMismatch,forward_mismatch:forwardMismatch,mismatch:ptrMissing||ptrMismatch||forwardMismatch,checked_at:row.checked_at}
  })
  if(name==='coverage'){
    const drift=driftSummaryByNode()
    return all(`SELECT n.id,n.hostname,n.ip,n.status,COUNT(DISTINCT a.policy_id) AS policy_count,(SELECT status FROM policy_apply_runs WHERE node_id=n.id AND policy_id IS NOT NULL ORDER BY started_at DESC LIMIT 1) AS last_apply_status,(SELECT passed FROM verifier_results WHERE node_id=n.id ORDER BY run_at DESC LIMIT 1) AS last_verify_passed FROM nodes n LEFT JOIN policy_assignments a ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id) GROUP BY n.id ORDER BY n.hostname`).filter(isLocalAssetNode).map(row=>({...row,drift_status:drift.get(row.id)||null}))
  }
  if(name==='verification'){
    const visible=user?readablePolicyIds(user):null
    return all(`SELECT n.hostname,p.id AS policy_id,p.name AS policy,COALESCE(v.hostname,'Control plane') AS vantage,r.port,r.proto,r.expected,r.actual,r.status,r.reason,r.managed_rule_present,r.probe_source_ip,r.probe_source_port,r.firewall_event_record_id,r.firewall_event_time,r.firewall_event_filter_origin,r.run_at FROM verifier_results r LEFT JOIN nodes n ON n.id=r.node_id LEFT JOIN nodes v ON v.id=r.vantage_node_id LEFT JOIN policies p ON p.id=r.policy_id ORDER BY r.run_at DESC LIMIT 1000`).filter(row=>!visible||visible.has(row.policy_id)).map(({policy_id,...row})=>row)
  }
  const drift=driftSummaryByNode()
  return all(`SELECT n.id,n.hostname,n.status,COUNT(DISTINCT a.policy_id) AS policies,COALESCE((SELECT SUM(passed) FROM verifier_results WHERE node_id=n.id),0) AS checks_passed,COALESCE((SELECT COUNT(passed) FROM verifier_results WHERE node_id=n.id),0) AS checks_decisive,COALESCE((SELECT COUNT(*) FROM verifier_results WHERE node_id=n.id AND passed IS NULL),0) AS checks_inconclusive FROM nodes n LEFT JOIN policy_assignments a ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id) GROUP BY n.id ORDER BY n.hostname`).map(row=>({...row,drift_status:drift.get(row.id)||null}))
}
function exportReport(req,res,name,data) {
  if(req.query.export==='csv'){
    const columns=Object.keys(data[0]||{hostname:''})
    const cell=value=>'"'+String(value??'').replaceAll('"','""')+'"'
    res.type('text/csv').attachment(`${name}.csv`).send([columns.map(cell).join(','),...data.map(row=>columns.map(key=>cell(row[key])).join(','))].join('\n'));return
  }
  if(req.query.export==='pdf'){
    res.type('application/pdf').attachment(`${name}.pdf`)
    const pdf=new PDFDocument({margin:40});pdf.pipe(res);pdf.fontSize(18).text(`WinFire ${name} report`);pdf.fontSize(9).text(`Generated ${now()}`);pdf.moveDown()
    for(const row of data){pdf.fontSize(10).text(Object.entries(row).map(([k,v])=>`${k}: ${typeof v==='string'?v.slice(0,100):v}`).join(' | '),{width:510});pdf.moveDown(.4)}pdf.end();return
  }
  res.json(data)
}
for(const name of ['inventory','dns','coverage','compliance','verification'])api.get(`/reports/${name}`,(req,res)=>exportReport(req,res,name,report(name,req.user)))
api.get('/reports/dashboard',(_req,res)=>{
  const localNodes=all('SELECT id,ip,status FROM nodes').filter(isLocalAssetNode),localIds=new Set(localNodes.map(node=>node.id)),total=localNodes.length,reachable=localNodes.filter(node=>node.status==='reachable').length
  const policies=one('SELECT COUNT(*) n FROM policies').n, failed=one("SELECT COUNT(*) n FROM policy_apply_runs WHERE status='failed' AND policy_id IS NOT NULL").n
  const checks=one('SELECT COUNT(passed) n,COALESCE(SUM(passed),0) passed,COUNT(*)-COUNT(passed) inconclusive FROM verifier_results')
  const agentCutoff=new Date(Date.now()-120_000).toISOString()
  const agents=localIds.size?one('SELECT COUNT(*) total,COALESCE(SUM(CASE WHEN a.revoked_at IS NULL AND a.last_checkin_at>=? THEN 1 ELSE 0 END),0) online FROM agents a JOIN nodes n ON n.id=a.node_id WHERE n.id IN ('+Array.from(localIds).map(()=>'?').join(',')+')',agentCutoff,...Array.from(localIds)):{total:0,online:0}
  const denied=all(`SELECT COALESCE(e.dst_port,p.dst_port) dst_port,COUNT(*) count FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE e.action='block' AND ${visibleFirewallEventSql()} GROUP BY COALESCE(e.dst_port,p.dst_port) ORDER BY count DESC LIMIT 6`)
  const verifierTrend=all("SELECT date(run_at) day,COUNT(passed) decisive,SUM(CASE WHEN passed=1 THEN 1 ELSE 0 END) passed FROM verifier_results WHERE datetime(run_at)>=datetime('now','-14 days') GROUP BY date(run_at) ORDER BY day").map(row=>({day:row.day,decisive:row.decisive,passRate:row.decisive?Math.round(row.passed/row.decisive*100):null}))
  const mfaTrend=all("SELECT date(resolved_at) day,SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) approved,SUM(CASE WHEN status='denied' THEN 1 ELSE 0 END) denied FROM mfa_challenges WHERE datetime(resolved_at)>=datetime('now','-14 days') GROUP BY date(resolved_at) ORDER BY day")
  const coverage=report('coverage').filter(row=>localIds.has(row.id))
  const compliant=coverage.filter(row=>row.policy_count>0&&row.drift_status==='in-sync'&&row.last_apply_status==='success'&&row.last_verify_passed===1).length
  res.json({totalNodes:total,reachableNodes:reachable,agentsOnline:agents.online,agentsOffline:agents.total-agents.online,policies,failedApplies:failed,verifierPassRate:checks.n?Math.round(checks.passed/checks.n*100):null,verifierInconclusive:checks.inconclusive,deniedPorts:denied,compliantNodes:compliant,fleetCompliancePct:total?Math.round(compliant/total*100):null,verifierTrend,mfaTrend})
})

api.get('/identity/learning-preview',(req,res)=>{
  const query=z.object({nodeId:z.uuid().optional(),days:z.coerce.number().int().min(1).max(90).default(30)}).parse(req.query)
  if(query.nodeId&&!getNode(query.nodeId))return notFound(res,'Node')
  const since=new Date(Date.now()-query.days*864e5).toISOString()
  const observations=all(`SELECT e.node_id,n.hostname,e.account_sid,COALESCE(e.logon_type,'') logon_type,
      COALESCE(e.src_ip,p.src_ip,'') source_ip,
      SUM(CASE WHEN e.event_id IN (4624,528,540) THEN 1 ELSE 0 END) successes,
      SUM(CASE WHEN e.event_id IN (4625,529,530,531,532,533,534,535,536,537,539) THEN 1 ELSE 0 END) failures,
      MAX(COALESCE(e.event_time,e.received_at)) last_seen_at
    FROM log_events e JOIN nodes n ON n.id=e.node_id LEFT JOIN event_patterns p ON p.id=e.pattern_id
    WHERE e.event_id IN (4624,4625,528,540,529,530,531,532,533,534,535,536,537,539) AND e.account_sid IS NOT NULL
      AND datetime(COALESCE(e.event_time,e.received_at))>=datetime(?)
      AND (? IS NULL OR e.node_id=?)
    GROUP BY e.node_id,e.account_sid,COALESCE(e.logon_type,''),COALESCE(e.src_ip,p.src_ip,'')
    ORDER BY last_seen_at DESC LIMIT 501`,since,query.nodeId||null,query.nodeId||null)
  const items=observations.slice(0,500).map(row=>({
    ...row,...accountName(row.node_id,row.account_sid),
    classification:['4','5'].includes(row.logon_type)?'service':['2','7','10','11'].includes(row.logon_type)?'interactive':row.logon_type==='3'?'network':'review'
  }))
  const baseline=all('SELECT node_id,account_sid,logon_type,right_assignment FROM logon_rights WHERE baseline=1')
  const assignments=new Set(baseline.map(right=>`${right.node_id}:${right.account_sid}:${right.right_assignment==='deny'?'SeDeny':'Se'}${right.logon_type}LogonRight`))
  const nodesWithBaseline=new Set(baseline.map(right=>right.node_id))
  const grouped=new Map()
  for(const item of items){
    const suggestedRight=suggestedRightForLogonType(item.logon_type)
    if(!suggestedRight||!Number(item.successes)||!/^S-1-5-21-(?:\d+-){3}\d+$/.test(item.account_sid))continue
    const key=`${item.node_id}:${item.account_sid}:${suggestedRight}`
    const proposal=grouped.get(key)||{nodeId:item.node_id,hostname:item.hostname,accountSid:item.account_sid,accountName:item.accountName,accountSource:item.accountSource,classification:item.classification,suggestedRight,successes:0,failures:0,lastSeenAt:item.last_seen_at,sourceIps:[]}
    proposal.successes+=Number(item.successes)
    proposal.failures+=Number(item.failures)
    if(item.last_seen_at>proposal.lastSeenAt)proposal.lastSeenAt=item.last_seen_at
    if(item.source_ip&&!proposal.sourceIps.includes(item.source_ip)&&proposal.sourceIps.length<5)proposal.sourceIps.push(item.source_ip)
    grouped.set(key,proposal)
  }
  const proposals=[...grouped.values()].map(proposal=>{
    const directAllow=assignments.has(`${proposal.nodeId}:${proposal.accountSid}:${proposal.suggestedRight}`)
    const directDeny=assignments.has(`${proposal.nodeId}:${proposal.accountSid}:${denyRightForAllow(proposal.suggestedRight)}`)
    return {...proposal,directAllow,directDeny,baselineCollected:nodesWithBaseline.has(proposal.nodeId),status:directDeny?'explicit-deny':directAllow?'already-direct':nodesWithBaseline.has(proposal.nodeId)?'review':'collect-baseline'}
  }).sort((a,b)=>b.lastSeenAt.localeCompare(a.lastSeenAt))
  res.json({items,proposals,days:query.days,truncated:observations.length>500})
})

const segmentBaselines=segmentId=>all('SELECT segment_id,node_id,account_sid,allow_right,deny_right,enforced_at,enforced_by FROM segment_lsa_baselines WHERE segment_id=? ORDER BY node_id',segmentId)
function segmentNodes(segment,nodeId=null){
  const nodes=segment.node_id?[getNode(segment.node_id)]:all('SELECT n.* FROM nodes n JOIN node_group_members m ON m.node_id=n.id WHERE m.group_id=? ORDER BY n.hostname',segment.node_group_id)
  const filtered=nodes.filter(Boolean).filter(node=>!nodeId||node.id===nodeId)
  if(nodeId&&!filtered.length)throw Object.assign(new Error('The selected node is not covered by this segment'),{status:400})
  if(!filtered.length)throw Object.assign(new Error('The segment has no target nodes'),{status:409})
  return filtered
}
function assertLsaSegment(segment){
  if(!segment.account_sid)throw Object.assign(new Error('Configure an account SID before enforcing an LSA baseline'),{status:409})
  const rights=segmentRightsForPort(segment.port)
  if(!rights)throw Object.assign(new Error('LSA gating is supported for RDP TCP 3389 and SSH TCP 22'),{status:409})
  const critical=new Set(['S-1-1-0','S-1-5-9','S-1-5-11','S-1-5-18','S-1-5-19','S-1-5-20','S-1-5-32-544','S-1-5-32-548','S-1-5-32-580'])
  if(critical.has(segment.account_sid)||/-(?:500|512|518|519)$/.test(segment.account_sid))throw Object.assign(new Error('This account is protected from LSA gate enforcement'),{status:409})
  return rights
}
function managementCredentialSids(nodeId){
  const names=all(`SELECT DISTINCT lower(c.username) username FROM credentials c JOIN credential_assignments a ON a.credential_id=c.id
    WHERE a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?)`,nodeId,nodeId).map(row=>row.username)
  const sids=[]
  for(const raw of names){
    const short=raw.includes('\\')?raw.split('\\').pop():raw.split('@')[0]
    const ad=one('SELECT sid FROM directory_users WHERE missing=0 AND (lower(upn)=? OR lower(sam_account_name)=?)',raw,short)
    const local=one('SELECT sid FROM local_accounts WHERE node_id=? AND missing=0 AND (lower(qualified_name)=? OR lower(username)=?)',nodeId,raw,short)
    if(ad?.sid)sids.push(ad.sid)
    if(local?.sid)sids.push(local.sid)
  }
  return [...new Set(sids)]
}
function validateLsaNode(node,segment,rights){
  if(node.connection_mode!=='agentless'||!['winrm','winrms'].includes(node.transport))throw Object.assign(new Error(`${node.hostname} requires working agentless WinRM for LSA enforcement`),{status:409})
  if(rights.logonType==='Network'&&!managementCredentialSids(node.id).some(sid=>sid.toLowerCase()!==segment.account_sid.toLowerCase()))throw Object.assign(new Error(`${node.hostname} needs a resolved WinRM credential with a different SID before SSH network-logon gating can be enforced`),{status:409})
}
async function changeLsaRight(node,accountSid,right,present){
  const result=await remote(node,'rights_change',{accountSid,right,present})
  if(result?.accountSid!==accountSid||result?.right!==right||result?.present!==present)throw Object.assign(new Error(`LSA readback did not confirm ${right}`),{status:502})
  return result
}
api.get('/segments',(_req,res)=>res.json(all('SELECT * FROM identity_segments ORDER BY created_at DESC').map(segment=>({...segment,lsaBaselines:segmentBaselines(segment.id)}))))
api.post('/segments',requireRole('admin'),(req,res)=>{
  const data=body(z.object({name:z.string().min(1),nodeId:z.string().optional(),nodeGroupId:z.string().optional(),policyId:z.string().nullable().optional(),port:z.number().int().min(1).max(65535),accountSid:z.string().max(184).optional(),sourceIp:z.string().max(255).optional(),extraPorts:z.array(z.number().int().min(1).max(65535)).max(100).default([]),sourceProcess:z.string().max(1024).optional(),fallbackToLoggedOnUser:z.boolean().default(false),failOpen:z.boolean().default(false),ttlMinutes:z.number().int().min(2).max(10080).default(240),mode:z.enum(['agentless','agent']).default('agentless'),mfaProvider:z.enum(['totp','entra']).default('totp'),allowedUpns:z.array(z.email()).max(100).default([]),entraGroupId:z.string().trim().max(256).optional().default(''),portalEnabled:z.boolean().default(true),autoPromptEnabled:z.boolean().default(false)}),req)
  if(Number(!!data.nodeId)+Number(!!data.nodeGroupId)!==1)return res.status(400).json({error:'Choose one node or node group'})
  if(data.nodeId&&!getNode(data.nodeId))return notFound(res,'Node')
  if(data.nodeGroupId&&!one('SELECT id FROM node_groups WHERE id=?',data.nodeGroupId))return notFound(res,'Node group')
  if(data.policyId&&!getPolicy(data.policyId))return notFound(res,'Policy')
  if(data.accountSid&&!/^S-1-\d+-\d+(?:-\d+)+$/.test(data.accountSid))return res.status(400).json({error:'A valid account SID is required'})
  data.extraPorts=[...new Set(data.extraPorts)].filter(port=>port!==data.port)
  const segmentId=id();run('INSERT INTO identity_segments(id,name,node_id,node_group_id,policy_id,port,account_sid,source_ip,extra_ports,source_process,fallback_to_logged_on_user,fail_open,ttl_minutes,mode,mfa_provider,allowed_upns,entra_group_id,portal_enabled,auto_prompt_enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',segmentId,data.name,data.nodeId||null,data.nodeGroupId||null,data.policyId||null,data.port,data.accountSid||null,data.sourceIp||null,json(data.extraPorts),data.sourceProcess||null,Number(data.fallbackToLoggedOnUser),Number(data.failOpen),data.ttlMinutes,data.mode,data.mfaProvider,json(data.allowedUpns.map(value=>value.toLowerCase())),data.entraGroupId||null,Number(data.portalEnabled),Number(data.autoPromptEnabled))
  audit(req.user.id,'segment.create','segment',segmentId,null,data);res.status(201).json(one('SELECT * FROM identity_segments WHERE id=?',segmentId))
})
api.patch('/segments/:id',requireRole('admin'),(req,res)=>{
  const before=one('SELECT * FROM identity_segments WHERE id=?',reqId(req))
  if(!before)return notFound(res,'Segment')
  const data=body(z.object({allowedUpns:z.array(z.email()).max(100).optional(),entraGroupId:z.string().trim().max(256).optional().nullable(),mfaProvider:z.enum(['totp','entra']).optional(),portalEnabled:z.boolean().optional(),autoPromptEnabled:z.boolean().optional(),ttlMinutes:z.number().int().min(2).max(10080).optional(),sourceIp:z.string().max(255).optional(),policyId:z.string().nullable().optional(),accountSid:z.string().max(184).optional(),extraPorts:z.array(z.number().int().min(1).max(65535)).max(100).optional(),sourceProcess:z.string().max(1024).optional(),fallbackToLoggedOnUser:z.boolean().optional(),failOpen:z.boolean().optional()}),req)
  if(data.policyId&&!getPolicy(data.policyId))return notFound(res,'Policy')
  const next={allowedUpns:data.allowedUpns?data.allowedUpns.map(value=>value.toLowerCase()):parse(before.allowed_upns)||[],entraGroupId:data.entraGroupId===undefined?before.entra_group_id:data.entraGroupId||null,mfaProvider:data.mfaProvider||before.mfa_provider,portalEnabled:data.portalEnabled===undefined?!!before.portal_enabled:data.portalEnabled,autoPromptEnabled:data.autoPromptEnabled===undefined?!!before.auto_prompt_enabled:data.autoPromptEnabled,ttlMinutes:data.ttlMinutes||before.ttl_minutes,sourceIp:data.sourceIp===undefined?before.source_ip:data.sourceIp||null,policyId:data.policyId===undefined?before.policy_id:data.policyId,accountSid:data.accountSid===undefined?before.account_sid:data.accountSid||null,extraPorts:data.extraPorts===undefined?parse(before.extra_ports)||[]:[...new Set(data.extraPorts)].filter(port=>port!==before.port),sourceProcess:data.sourceProcess===undefined?before.source_process:data.sourceProcess||null,fallbackToLoggedOnUser:data.fallbackToLoggedOnUser===undefined?!!before.fallback_to_logged_on_user:data.fallbackToLoggedOnUser,failOpen:data.failOpen===undefined?!!before.fail_open:data.failOpen}
  if(next.accountSid&&!/^S-1-\d+-\d+(?:-\d+)+$/.test(next.accountSid))return res.status(400).json({error:'A valid account SID is required'})
  if(next.accountSid!==before.account_sid&&one('SELECT 1 FROM segment_lsa_baselines WHERE segment_id=?',before.id))return res.status(409).json({error:'Restore this segment’s LSA baselines before changing its account SID'})
  run('UPDATE identity_segments SET allowed_upns=?,entra_group_id=?,mfa_provider=?,portal_enabled=?,auto_prompt_enabled=?,ttl_minutes=?,source_ip=?,policy_id=?,account_sid=?,extra_ports=?,source_process=?,fallback_to_logged_on_user=?,fail_open=? WHERE id=?',json(next.allowedUpns),next.entraGroupId,next.mfaProvider,Number(next.portalEnabled),Number(next.autoPromptEnabled),next.ttlMinutes,next.sourceIp,next.policyId,next.accountSid,json(next.extraPorts),next.sourceProcess,Number(next.fallbackToLoggedOnUser),Number(next.failOpen),before.id)
  audit(req.user.id,'segment.update','segment',before.id,{allowedUpns:parse(before.allowed_upns),entraGroupId:before.entra_group_id||null,mfaProvider:before.mfa_provider,portalEnabled:!!before.portal_enabled,autoPromptEnabled:!!before.auto_prompt_enabled,ttlMinutes:before.ttl_minutes,sourceIp:before.source_ip,policyId:before.policy_id,accountSid:before.account_sid,extraPorts:parse(before.extra_ports)||[],sourceProcess:before.source_process,fallbackToLoggedOnUser:!!before.fallback_to_logged_on_user,failOpen:!!before.fail_open},next)
  res.json(one('SELECT * FROM identity_segments WHERE id=?',before.id))
})
api.post('/segments/:id/entra-group/sync',requireRole('admin'),wrap(async(req,res)=>{
  const segment=one('SELECT * FROM identity_segments WHERE id=?',reqId(req))
  if(!segment)return notFound(res,'Segment')
  if(!segment.entra_group_id)return res.status(400).json({error:'This segment has no Entra group configured'})
  try{
    const result=await syncEntraGroup(segment.entra_group_id,{force:true})
    audit(req.user.id,'entra.group.sync','segment',segment.id,null,result)
    res.json(result)
  }catch(error){
    audit(req.user.id,'entra.group.sync.failed','segment',segment.id,null,{error:String(error.message).slice(0,500)})
    throw error
  }
}))
api.get('/segments/:id/entra-group/members',requireRole('admin'),(req,res)=>{
  const segment=one('SELECT * FROM identity_segments WHERE id=?',reqId(req))
  if(!segment)return notFound(res,'Segment')
  if(!segment.entra_group_id)return res.status(400).json({error:'This segment has no Entra group configured'})
  const group=String(segment.entra_group_id).trim().toLowerCase()
  res.json({groupId:group,members:cachedEntraGroupMembers(group)})
})
api.get('/segments/:id/lsa-baselines',requireRole('admin'),(req,res)=>{
  const segment=one('SELECT * FROM identity_segments WHERE id=?',reqId(req));if(!segment)return notFound(res,'Segment')
  res.json(segmentBaselines(segment.id))
})
api.post('/segments/:id/lsa-baselines',requireRole('admin'),wrap(async(req,res)=>{
  const segment=one('SELECT * FROM identity_segments WHERE id=?',reqId(req));if(!segment)return notFound(res,'Segment')
  const data=body(z.object({enabled:z.boolean(),nodeId:z.string().uuid().optional(),reason:z.string().trim().min(10).max(500),confirmed:z.boolean().optional(),confirmation:z.string().optional()}),req)
  if(!data.confirmed&&data.confirmation!=='ENFORCE LSA GATE')return res.status(400).json({error:'Confirmation is required'})
  const rights=assertLsaSegment(segment),targets=segmentNodes(segment,data.nodeId)
  const results=[]
  for(const node of targets){
    validateLsaNode(node,segment,rights)
    const existing=one('SELECT * FROM segment_lsa_baselines WHERE segment_id=? AND node_id=?',segment.id,node.id)
    if(data.enabled&&existing){results.push({...existing,unchanged:true});continue}
    if(!data.enabled&&!existing){results.push({nodeId:node.id,enabled:false,unchanged:true});continue}
    if(one("SELECT 1 FROM jit_grants WHERE segment_id=? AND node_id=? AND revoked_at IS NULL AND expires_at>?",segment.id,node.id,now()))throw Object.assign(new Error(`Close active MFA grants on ${node.hostname} before changing its LSA baseline`),{status:409})
    const applyRunId=id();run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',applyRunId,node.id,'running')
    try{
      if(data.enabled){
        const raw=await remote(node,'rights'),lines=Array.isArray(raw)?raw:[raw].filter(Boolean)
        const allowWasPresent=hasDirectRight(lines,segment.account_sid,rights.allowRight),denyWasPresent=hasDirectRight(lines,segment.account_sid,rights.denyRight)
        let denyChanged=false
        try{
          await changeLsaRight(node,segment.account_sid,rights.denyRight,true);denyChanged=!denyWasPresent
          await changeLsaRight(node,segment.account_sid,rights.allowRight,false)
        }catch(error){
          if(denyChanged)await changeLsaRight(node,segment.account_sid,rights.denyRight,denyWasPresent).catch(()=>{})
          await changeLsaRight(node,segment.account_sid,rights.allowRight,allowWasPresent).catch(()=>{})
          throw error
        }
        run('INSERT INTO segment_lsa_baselines(segment_id,node_id,account_sid,allow_right,deny_right,allow_was_present,deny_was_present,enforced_at,enforced_by) VALUES(?,?,?,?,?,?,?,?,?)',segment.id,node.id,segment.account_sid,rights.allowRight,rights.denyRight,Number(allowWasPresent),Number(denyWasPresent),now(),req.user.id)
        results.push({nodeId:node.id,enabled:true,allowRight:rights.allowRight,denyRight:rights.denyRight})
      }else{
        await changeLsaRight(node,existing.account_sid,existing.allow_right,!!existing.allow_was_present)
        await changeLsaRight(node,existing.account_sid,existing.deny_right,!!existing.deny_was_present)
        run('DELETE FROM segment_lsa_baselines WHERE segment_id=? AND node_id=?',segment.id,node.id)
        results.push({nodeId:node.id,enabled:false})
      }
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json({operation:data.enabled?'lsa_baseline_enforce':'lsa_baseline_restore',segmentId:segment.id,accountSid:segment.account_sid,...rights}),now(),applyRunId)
      audit(req.user.id,data.enabled?'segment.lsa.enforce':'segment.lsa.restore','segment',segment.id,null,{nodeId:node.id,accountSid:segment.account_sid,...rights,reason:data.reason,runId:applyRunId})
    }catch(error){
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','failed',error.message,now(),applyRunId)
      audit(req.user.id,'segment.lsa.failed','segment',segment.id,null,{nodeId:node.id,enabled:data.enabled,error:error.message,reason:data.reason,runId:applyRunId})
      throw error
    }
  }
  res.status(201).json({results,baselines:segmentBaselines(segment.id)})
}))
const portalAccessLimit=rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:'draft-8',legacyHeaders:false})
function portalTarget(req,segment,requestedNodeId){
  if(!segment)throw Object.assign(new Error('Segment not found'),{status:404})
  if(!segment.portal_enabled||segment.mode!=='agentless')throw Object.assign(new Error('The access portal is disabled for this segment'),{status:409})
  if(!(parse(segment.allowed_upns)||[]).includes(req.user.email.toLowerCase()))throw Object.assign(new Error('Your account is not assigned to this segment'),{status:403})
  if(segment.fail_open)throw Object.assign(new Error('Portal access requires a fail-closed segment'),{status:409})
  if(segment.source_process)throw Object.assign(new Error('Agentless portal access cannot enforce a source process'),{status:409})
  const nodeId=segment.node_id||requestedNodeId
  if(!nodeId||segment.node_id&&requestedNodeId&&requestedNodeId!==segment.node_id||segment.node_group_id&&!one('SELECT 1 FROM node_group_members WHERE group_id=? AND node_id=?',segment.node_group_id,nodeId))throw Object.assign(new Error('Choose a node covered by this segment'),{status:400})
  const node=getNode(nodeId)
  if(!node)throw Object.assign(new Error('Node not found'),{status:404})
  if(node.connection_mode!=='agentless'||!['winrm','winrms'].includes(node.transport))throw Object.assign(new Error('Agentless portal access requires a working WinRM node'),{status:409})
  if(node.firewall_state==='learning')throw Object.assign(new Error('The target is still learning; enforce its firewall policy before enabling portal access'),{status:409})
  if(segment.account_sid&&!one('SELECT 1 FROM segment_lsa_baselines WHERE segment_id=? AND node_id=? AND account_sid=?',segment.id,node.id,segment.account_sid))throw Object.assign(new Error('Enforce the segment LSA deny baseline on this node before granting access'),{status:409})
  if(segment.policy_id){
    const policy=getPolicy(segment.policy_id)
    if(!policy||!assignedNodes(policy.id).some(target=>target.id===node.id))throw Object.assign(new Error('The linked MFA policy is not assigned to this node'),{status:409})
    const applied=one('SELECT version_id,status FROM policy_apply_runs WHERE policy_id=? AND node_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1',policy.id,node.id)
    if(!applied||applied.version_id!==policy.current_version_id||applied.status!=='success')throw Object.assign(new Error('Sync the linked MFA policy to this node before granting access'),{status:409})
  }
  if(segment.ttl_minutes<2)throw Object.assign(new Error('Portal access TTL must be at least two minutes'),{status:409})
  const sourceIp=normalizeSourceIp(req.ip)
  if(!sourceMatches(sourceIp,segment.source_ip))throw Object.assign(new Error('Your source IP is outside this segment'),{status:403})
  return {node,sourceIp}
}
function portalPrompt(req,segment,node,sourceIp,promptId){
  if(!promptId)return null
  const prompt=one('SELECT * FROM mfa_prompt_events WHERE id=?',promptId)
  if(!prompt||prompt.segment_id!==segment.id||prompt.target_node_id!==node.id||prompt.source_ip!==sourceIp||prompt.status!=='opened'||prompt.expires_at<=now())throw Object.assign(new Error('MFA browser prompt is invalid or expired'),{status:409})
  return prompt
}
export function matchesJitRule(rule,sourceIp,ports){
  if(!rule||String(rule.action).toLowerCase()!=='allow'||rule.direction!=='in'||!['TCP','6'].includes(String(rule.protocol).toUpperCase()))return false
  if(String(rule.remoteAddress)!==sourceIp)return false
  const actual=String(rule.localPort||'').split(',').map(value=>value.trim()).filter(Boolean)
  return actual.length===ports.length&&new Set(actual).size===ports.length&&ports.every(port=>actual.includes(String(port)))
}
async function grantPortalAccess(req,segment,node,sourceIp,provider,promptId=null,existingChallengeId=null){
  const challengeId=existingChallengeId||createMfaChallenge({nodeId:node.id,userUpn:req.user.email,segmentId:segment.id,connection:{srcIp:sourceIp,dstPort:segment.port,protocol:'TCP'},provider,promptId,actorId:req.user.id})
  const grantId=id(),expiresAt=new Date(Date.now()+segment.ttl_minutes*60_000).toISOString()
  let ruleStarted=false,grantRecorded=false,applyRunId=null
  try{
    portalPrompt(req,segment,node,sourceIp,promptId)
    if(promptId){
      const reserved=run("UPDATE mfa_prompt_events SET status='consuming' WHERE id=? AND status='opened' AND expires_at>?",promptId,now())
      if(reserved.changes!==1)throw Object.assign(new Error('MFA browser prompt was already used'),{status:409})
    }
    const ports=[segment.port,...(parse(segment.extra_ports)||[])]
    const baseline=segment.account_sid?one('SELECT * FROM segment_lsa_baselines WHERE segment_id=? AND node_id=?',segment.id,node.id):null
    const lsaScope=baseline?{accountSid:baseline.account_sid,allowRight:baseline.allow_right,denyRight:baseline.deny_right}:{}
    const preflight=await remote(node,'jit_preflight',{port:segment.port,ports,...lsaScope})
    if(!preflight?.safe){
      const names=[...(preflight?.conflictingAllows||[]),...(preflight?.conflictingBlocks||[])].map(item=>item.name).slice(0,3).join(', ')
      const lsa=preflight?.lsaReady===false?' and restore its enforced LSA deny baseline':''
      throw Object.assign(new Error(`Firewall gate is not ready for TCP ${segment.port}; check inbound profile defaults${names?` and overlapping rules: ${names}`:' and overlapping rules'}${lsa}`),{status:409})
    }
    const args={grantId,sourceIp,port:segment.port,ports,expiresAt,...lsaScope}
    applyRunId=id()
    run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',applyRunId,node.id,'running')
    try{const started=await remote(node,'jit_start',args);if(started?.active!==true)throw new Error('The node did not confirm the temporary firewall rule');ruleStarted=true}
    catch(error){
      const current=await remote(node,'rules',{group:`WinFireSecure:JIT:${grantId}`}).catch(()=>null)
      const rules=Array.isArray(current)?current:current?[current]:[]
      if(rules.length)ruleStarted=true
      if(rules.length!==1||!matchesJitRule(rules[0],sourceIp,ports)||!/timed? out|timeout|connection|unreachable/i.test(error.message))throw error
    }
    db.transaction(()=>{
      run('INSERT INTO jit_grants(id,segment_id,node_id,account_sid,src_ip,dst_port,ports_json,rule_path,grant_type,ttl_seconds,granted_at,expires_at,mfa_challenge_id,prompt_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',grantId,segment.id,node.id,segment.account_sid||null,sourceIp,segment.port,json(ports),`WinFireSecure:JIT:${grantId}`,'portal_firewall',segment.ttl_minutes*60,now(),expiresAt,challengeId,promptId)
      if(promptId)run("UPDATE mfa_prompt_events SET status='consumed',consumed_at=? WHERE id=?",now(),promptId)
      if(!resolveMfaChallenge(challengeId,'approved',{actorId:req.user.id}))throw Object.assign(new Error('MFA challenge expired before access could open'),{status:409})
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json({operation:'mfa_jit_start',grantId,sourceIp,ports,expiresAt,lsaTemporary:!!baseline}),now(),applyRunId)
      audit(req.user.id,'mfa.portal.granted','jit-grant',grantId,null,{segmentId:segment.id,nodeId:node.id,sourceIp,ports,expiresAt,provider,promptId})
    })()
    grantRecorded=true
    return {grantId,nodeId:node.id,sourceIp,port:segment.port,ports,expiresAt,applyRunId}
  }catch(error){
    let cleanupFailed=false
    if(ruleStarted){
      try{
        await remote(node,'jit_end',{grantId,...lsaScope})
        if(grantRecorded)run('UPDATE jit_grants SET revoked_at=? WHERE id=?',now(),grantId)
      }catch(cleanupError){
        cleanupFailed=true
        audit(req.user.id,'mfa.portal.cleanup.failed','jit-grant',grantId,null,{nodeId:node.id,error:cleanupError.message})
      }
    }
    if(applyRunId)run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?',cleanupFailed||/timed? out|timeout|connection|unreachable/i.test(error.message)?'unknown':'failed',error.message,now(),applyRunId)
    const challenge=one('SELECT expires_at FROM mfa_challenges WHERE id=?',challengeId)
    resolveMfaChallenge(challengeId,challenge?.expires_at&&challenge.expires_at<=now()?'expired':'denied',{actorId:req.user.id,reason:error.message})
    if(promptId)run("UPDATE mfa_prompt_events SET status='failed',consumed_at=NULL,error=? WHERE id=? AND status IN ('consuming','consumed')",error.message,promptId)
    audit(req.user.id,'mfa.portal.failed','challenge',challengeId,null,{segmentId:segment.id,nodeId:node.id,sourceIp,error:error.message,provider})
    throw error
  }
}
api.get('/segments/access',wrap(async(req,res)=>{
  const segments=[]
  for(const segment of all("SELECT * FROM identity_segments WHERE portal_enabled=1 AND mode='agentless' ORDER BY name")){
    if(!await segmentAllowsOperatorAsync(segment,req.user.email))continue
    segments.push({id:segment.id,name:segment.name,nodeId:segment.node_id,nodeGroupId:segment.node_group_id,port:segment.port,ttlMinutes:segment.ttl_minutes,mfaProvider:segment.mfa_provider,nodes:segment.node_group_id?all('SELECT n.id,n.hostname FROM nodes n JOIN node_group_members m ON m.node_id=n.id WHERE m.group_id=? ORDER BY n.hostname',segment.node_group_id):[{id:segment.node_id,hostname:getNode(segment.node_id)?.hostname||segment.node_id}]})
  }
  res.json(segments)
}))
api.get('/segments/access/grants',(req,res)=>{
  const admin=['owner','admin'].includes(req.user.role)
  const grants=all(`SELECT g.id,g.node_id,g.src_ip,g.dst_port,g.ports_json,g.granted_at,g.expires_at,g.segment_id,g.fallback_reason,c.user_upn,n.hostname FROM jit_grants g LEFT JOIN mfa_challenges c ON c.id=g.mfa_challenge_id LEFT JOIN nodes n ON n.id=g.node_id WHERE g.grant_type='portal_firewall' AND g.revoked_at IS NULL AND g.expires_at>? AND (?=1 OR c.user_upn=?) ORDER BY g.expires_at`,now(),Number(admin),req.user.email)
  res.json(grants.map(({ports_json,...grant})=>({...grant,ports:parse(ports_json)||[grant.dst_port]})))
})
api.get('/segments/access/prompts/:promptId',wrap(async(req,res)=>{
  const prompt=one('SELECT * FROM mfa_prompt_events WHERE id=?',req.params.promptId)
  if(!prompt||prompt.status!=='opened'||prompt.expires_at<=now()||prompt.source_ip!==normalizeSourceIp(req.ip))return notFound(res,'MFA prompt')
  const segment=one('SELECT * FROM identity_segments WHERE id=?',prompt.segment_id)
  if(!segment?.portal_enabled||!await segmentAllowsOperatorAsync(segment,req.user.email))return notFound(res,'MFA prompt')
  res.json({id:prompt.id,segmentId:prompt.segment_id,nodeId:prompt.target_node_id,sourceIp:prompt.source_ip,sourceNode:one('SELECT hostname FROM nodes WHERE id=?',prompt.source_node_id)?.hostname||null,sessionUser:prompt.opened_user,sessionId:prompt.opened_session_id,processId:prompt.opened_process_id,port:segment.port,expiresAt:prompt.expires_at})
}))
api.post('/segments/access/grants/:grantId/revoke',wrap(async(req,res)=>{
  const grant=one(`SELECT g.*,c.user_upn FROM jit_grants g LEFT JOIN mfa_challenges c ON c.id=g.mfa_challenge_id WHERE g.id=? AND g.grant_type='portal_firewall'`,req.params.grantId)
  if(!grant)return notFound(res,'Access grant')
  if(!['owner','admin'].includes(req.user.role)&&grant.user_upn!==req.user.email)return res.status(403).json({error:'This grant belongs to another user'})
  if(grant.revoked_at)return res.json({revoked:true})
  res.json(await revokePortalGrant(grant,req.user.id))
}))
api.post('/segments/:id/access',portalAccessLimit,wrap(async(req,res)=>{
  const segment=one('SELECT * FROM identity_segments WHERE id=?',reqId(req))
  const data=body(z.object({nodeId:z.string().optional(),promptId:z.uuid().optional(),code:z.string().regex(/^\d{6}$/)}),req)
  const {node,sourceIp}=portalTarget(req,segment,data.nodeId)
  portalPrompt(req,segment,node,sourceIp,data.promptId)
  if(segment.mfa_provider!=='totp')return res.status(409).json({error:'Use the Entra sign-in action for this segment'})
  if(!req.user.totp_secret)return res.status(409).json({error:'Set up Google Authenticator or another TOTP app in Administration → Security first'})
  const challengeId=createMfaChallenge({nodeId:node.id,userUpn:req.user.email,segmentId:segment.id,connection:{srcIp:sourceIp,dstPort:segment.port,protocol:'TCP'},provider:'totp',promptId:data.promptId||null,actorId:req.user.id})
  markVerifiedAdChallenge(challengeId,req.user,req.user.email,'ad-session')
  const counter=matchingTotpCounter(openSealed(req.user.totp_secret).secret,data.code)
  if(counter===null){resolveMfaChallenge(challengeId,'denied',{actorId:req.user.id,reason:'Invalid authenticator code',failureKind:'totp'});return res.status(401).json({error:'Invalid authenticator code'})}
  const consumed=run('INSERT INTO mfa_totp_replay(user_id,last_counter) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET last_counter=excluded.last_counter WHERE excluded.last_counter>mfa_totp_replay.last_counter',req.user.id,counter)
  if(consumed.changes!==1){resolveMfaChallenge(challengeId,'denied',{actorId:req.user.id,reason:'Authenticator code replayed',failureKind:'totp'});return res.status(401).json({error:'Authenticator code was already used; wait for a new code'})}
  res.status(201).json(await grantPortalAccess(req,segment,node,sourceIp,'totp',data.promptId,challengeId))
}))
api.post('/segments/:id/entra/start',portalAccessLimit,wrap(async(req,res)=>{
  const segment=one('SELECT * FROM identity_segments WHERE id=?',reqId(req))
  const data=body(z.object({nodeId:z.string().optional(),promptId:z.uuid().optional()}),req)
  const {node,sourceIp}=portalTarget(req,segment,data.nodeId)
  portalPrompt(req,segment,node,sourceIp,data.promptId)
  if(segment.mfa_provider!=='entra')return res.status(409).json({error:'This segment uses an authenticator code'})
  if(!entraConfigured())return res.status(503).json({error:'Entra tenant, app, secret, and public URL are not configured'})
  const flow=await startEntraAuthentication(),flowExpiresAt=new Date(Date.now()+5*60_000).toISOString()
  db.transaction(()=>{
    const challengeId=createMfaChallenge({nodeId:node.id,userUpn:req.user.email,segmentId:segment.id,connection:{srcIp:sourceIp,dstPort:segment.port,protocol:'TCP'},provider:'entra',promptId:data.promptId||null,actorId:req.user.id,expiresAt:flowExpiresAt})
    run('INSERT INTO mfa_entra_flows(state_hash,user_id,segment_id,node_id,source_ip,sealed_checks,expires_at,prompt_id,challenge_id) VALUES(?,?,?,?,?,?,?,?,?)',hashToken(flow.state),req.user.id,segment.id,node.id,sourceIp,seal({verifier:flow.verifier,nonce:flow.nonce}),flowExpiresAt,data.promptId||null,challengeId)
  })()
  audit(req.user.id,'mfa.entra.start','segment',segment.id,null,{nodeId:node.id,sourceIp})
  res.json({authorizationUrl:flow.url})
}))
api.post('/segments/entra/complete',portalAccessLimit,wrap(async(req,res)=>{
  const data=body(z.object({code:z.string().min(8).max(4096),state:z.string().min(16).max(512)}),req)
  const flow=one('SELECT * FROM mfa_entra_flows WHERE state_hash=?',hashToken(data.state))
  if(!flow||flow.used_at||flow.expires_at<=now()||flow.user_id!==req.user.id)return res.status(401).json({error:'Entra sign-in has expired or was already used'})
  if(normalizeSourceIp(req.ip)!==flow.source_ip)return res.status(403).json({error:'Entra sign-in source IP changed'})
  const segment=one('SELECT * FROM identity_segments WHERE id=?',flow.segment_id)
  const {node,sourceIp}=portalTarget(req,segment,flow.node_id)
  portalPrompt(req,segment,node,sourceIp,flow.prompt_id)
  if(segment.mfa_provider!=='entra')return res.status(409).json({error:'This segment no longer uses Entra'})
  const reserved=run('UPDATE mfa_entra_flows SET used_at=? WHERE state_hash=? AND used_at IS NULL',now(),flow.state_hash)
  if(reserved.changes!==1)return res.status(401).json({error:'Entra sign-in was already used'})
  try{
    const checks=openSealed(flow.sealed_checks)
    const identity=await completeEntraAuthentication({code:data.code,state:data.state,...checks})
    if(identity.email!==req.user.email.toLowerCase())throw Object.assign(new Error('Entra identity does not match your WinFire account'),{status:403})
    res.status(201).json(await grantPortalAccess(req,segment,node,sourceIp,'entra',flow.prompt_id,flow.challenge_id))
  }catch(error){
    if(flow.challenge_id)resolveMfaChallenge(flow.challenge_id,'denied',{actorId:req.user.id,reason:'Entra sign-in failed'})
    audit(req.user.id,'mfa.entra.failed','segment',segment.id,null,{nodeId:node.id,sourceIp,error:error.message});throw error
  }
}))
api.post('/segments/entra/cancel',portalAccessLimit,(req,res)=>{
  const data=body(z.object({state:z.string().min(16).max(512),error:z.string().regex(/^[A-Za-z0-9_]{1,64}$/)}),req)
  const flow=one('SELECT * FROM mfa_entra_flows WHERE state_hash=?',hashToken(data.state))
  if(!flow||flow.used_at||flow.expires_at<=now()||flow.user_id!==req.user.id)return res.status(401).json({error:'Entra sign-in has expired or was already used'})
  if(normalizeSourceIp(req.ip)!==flow.source_ip)return res.status(403).json({error:'Entra sign-in source IP changed'})
  const reserved=run('UPDATE mfa_entra_flows SET used_at=? WHERE state_hash=? AND used_at IS NULL',now(),flow.state_hash)
  if(reserved.changes!==1)return res.status(401).json({error:'Entra sign-in was already used'})
  if(flow.challenge_id)resolveMfaChallenge(flow.challenge_id,'denied',{actorId:req.user.id,reason:`Entra sign-in returned ${data.error}`})
  audit(req.user.id,'mfa.entra.cancel','segment',flow.segment_id,null,{nodeId:flow.node_id,sourceIp:flow.source_ip,error:data.error})
  res.json({ok:true})
})
api.get('/segments/:id/challenges',(req,res)=>res.json(all('SELECT * FROM mfa_challenges WHERE segment_id=? ORDER BY challenged_at DESC LIMIT 200',reqId(req))))
api.get('/mfa/challenges/search',requireRole('auditor'),(req,res)=>{
  const query=z.object({segmentId:z.string().optional(),nodeId:z.string().optional(),status:z.enum(['pending','approved','denied','expired']).optional(),provider:z.enum(['totp','entra','manual']).optional(),userUpn:z.string().max(255).optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(200).default(10)}).parse(req.query)
  const filters=[],args=[]
  for(const [key,column] of [['segmentId','c.segment_id'],['nodeId','c.node_id'],['status','c.status'],['provider','c.provider']])if(query[key]){filters.push(`${column}=?`);args.push(query[key])}
  if(query.userUpn){filters.push("c.user_upn LIKE ? ESCAPE '\\'");args.push(`%${query.userUpn.replace(/[\\%_]/g,'\\$&')}%`)}
  const from=`FROM mfa_challenges c LEFT JOIN identity_segments s ON s.id=c.segment_id LEFT JOIN nodes n ON n.id=c.node_id ${filters.length?'WHERE '+filters.join(' AND '):''}`
  const total=one(`SELECT COUNT(*) count ${from}`,...args).count
  const items=all(`SELECT c.*,s.name segment_name,n.hostname node_name ${from} ORDER BY datetime(c.challenged_at) DESC,c.rowid DESC LIMIT ? OFFSET ?`,...args,query.pageSize,(query.page-1)*query.pageSize)
  res.json({items,total,page:query.page,pageSize:query.pageSize,totalPages:Math.ceil(total/query.pageSize)})
})
api.post('/segments/:id/challenges',requireRole('editor'),(req,res)=>{
  const segment=one('SELECT * FROM identity_segments WHERE id=?',reqId(req));if(!segment)return notFound(res,'Segment')
  const data=body(z.object({userUpn:z.email(),nodeId:z.string().optional(),connection:z.record(z.string(),z.any()).optional()}),req),expires=new Date(Date.now()+5*60*1000).toISOString()
  const nodeId=segment.node_id||data.nodeId
  if(!nodeId||segment.node_group_id&&!one('SELECT 1 FROM node_group_members WHERE group_id=? AND node_id=?',segment.node_group_id,nodeId))return res.status(400).json({error:'Choose a node in this segment group'})
  const challengeId=createMfaChallenge({nodeId,userUpn:data.userUpn,segmentId:segment.id,connection:data.connection,provider:'manual',actorId:req.user.id,expiresAt:expires})
  res.status(201).json({id:challengeId,status:'pending',expiresAt:expires})
})
api.post('/segments/:id/challenges/:challengeId/resolve',requireRole('admin'),(req,res)=>{
  const challenge=one('SELECT * FROM mfa_challenges WHERE id=? AND segment_id=?',req.params.challengeId,reqId(req));if(!challenge)return notFound(res,'Challenge')
  if(challenge.status!=='pending'||challenge.expires_at<now())return res.status(409).json({error:'Challenge expired or already resolved'})
  const data=body(z.object({approved:z.boolean()}),req)
  resolveMfaChallenge(challenge.id,data.approved?'approved':'denied',{actorId:req.user.id,reason:data.approved?null:'Denied by administrator'})
  res.json({ok:true})
})

api.get('/logon-rights',(req,res)=>res.json(all('SELECT r.* FROM logon_rights r WHERE (? IS NULL OR r.node_id=?) ORDER BY r.at DESC LIMIT 500',req.query.nodeId||null,req.query.nodeId||null).map(right=>({...right,...accountName(right.node_id,right.account_sid)}))))
// LSA changes use the authenticated WinRM connector and require readback.
api.post('/logon-rights/baseline',requireRole('admin'),wrap(async(req,res)=>{
  const {nodeId}=body(z.object({nodeId:z.string()}),req),node=getNode(nodeId);if(!node)return notFound(res,'Node')
  const raw=await remote(node,'rights'),lines=Array.isArray(raw)?raw:[raw].filter(Boolean)
  let parsed
  try{parsed=parseSeceditRights(lines)}catch(error){throw Object.assign(error,{status:502})}
  try{await collectAccountInventory(node,parsed.map(right=>right.accountSid))}
  catch(error){audit(req.user.id,'local-accounts.baseline.failed','node',node.id,null,{error:error.message})}
  const rights=db.transaction(()=>{
    run('DELETE FROM logon_rights WHERE node_id=? AND baseline=1',node.id)
    const collected=parsed.map(right=>{const rightId=id();run('INSERT INTO logon_rights(id,node_id,account_sid,logon_type,right_assignment,source,baseline,created_by) VALUES(?,?,?,?,?,?,1,?)',rightId,node.id,right.accountSid,right.logonType,right.assignment,'secedit',req.user.id);return {id:rightId,...right}})
    audit(req.user.id,'logon-rights.baseline','node',node.id,null,{count:collected.length,allow:collected.filter(right=>right.assignment==='allow').length,deny:collected.filter(right=>right.assignment==='deny').length})
    return collected
  })()
  res.status(201).json(rights)
}))

api.post('/logon-rights/change',requireRole('admin'),wrap(async(req,res)=>{
  const data=body(z.object({nodeId:z.string().uuid(),accountSid:z.string().regex(/^S-1-\d+-\d+(?:-\d+)+$/),right:z.enum(['SeNetworkLogonRight','SeDenyNetworkLogonRight','SeRemoteInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight','SeInteractiveLogonRight','SeDenyInteractiveLogonRight','SeBatchLogonRight','SeDenyBatchLogonRight','SeServiceLogonRight','SeDenyServiceLogonRight']),present:z.boolean(),reason:z.string().trim().min(10).max(500),confirmed:z.boolean().optional(),confirmation:z.string().optional()}),req)
  if(!data.confirmed&&data.confirmation!=='CHANGE LOGON RIGHT')return res.status(400).json({error:'Confirmation is required'})
  const node=getNode(data.nodeId);if(!node)return notFound(res,'Node')
  if(!['winrm','winrms'].includes(node.transport)||node.connection_mode!=='agentless')return res.status(409).json({error:'Logon rights changes require an agentless WinRM node'})
  if(data.right==='SeNetworkLogonRight'&&!data.present||data.right==='SeDenyNetworkLogonRight'&&data.present)return res.status(409).json({error:'This network logon change could block WinRM administration; use a separately validated enforcement workflow'})
  const critical=new Set(['S-1-1-0','S-1-5-9','S-1-5-11','S-1-5-18','S-1-5-19','S-1-5-20','S-1-5-32-544','S-1-5-32-548','S-1-5-32-580'])
  if(critical.has(data.accountSid)||/-(?:500|512|518|519)$/.test(data.accountSid))return res.status(409).json({error:'This account is protected from direct logon-right changes'})
  const runId=id()
  run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',runId,node.id,'running')
  try{
    const result=await remote(node,'rights_change',{accountSid:data.accountSid,right:data.right,present:data.present})
    if(result?.accountSid!==data.accountSid||result?.right!==data.right||result?.present!==data.present)throw Object.assign(new Error('LSA readback did not confirm the requested right'),{status:502})
    db.transaction(()=>{
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json({operation:'rights_change',accountSid:data.accountSid,right:data.right,before:result.before,present:result.present,changed:result.changed}),now(),runId)
      audit(req.user.id,'logon-rights.change','node',node.id,{accountSid:data.accountSid,right:data.right,present:result.before},{accountSid:data.accountSid,right:data.right,present:result.present,changed:result.changed,reason:data.reason,runId})
    })()
    res.json({...result,runId})
  }catch(error){
    db.transaction(()=>{
      run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?',/timed? out|timeout|connection|unreachable/i.test(error.message)?'unknown':'failed',error.message,now(),runId)
      audit(req.user.id,'logon-rights.change.failed','node',node.id,null,{accountSid:data.accountSid,right:data.right,present:data.present,reason:data.reason,runId,error:error.message})
    })()
    throw error
  }
}))

api.get('/logs/search',(req,res)=>{
  const query=z.object({
    nodeId:z.string().optional(),action:z.enum(['allow','block','success','failure','logon','logoff']).optional(),direction:z.enum(['in','out']).optional(),
    program:z.string().max(1024).optional(),challengeId:z.string().max(128).optional(),
    eventId:z.coerce.number().int().min(0).optional(),protocol:z.string().max(32).optional(),srcIp:z.string().max(128).optional(),dstIp:z.string().max(128).optional(),
    port:z.coerce.number().int().min(1).max(65535).optional(),from:z.iso.datetime({local:true,offset:true}).optional(),to:z.iso.datetime({local:true,offset:true}).optional(),
    eventType:z.enum(['firewall','logon','all']).default('all'),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(500).default(100),
    sortBy:z.enum(['time','node','eventId','action','direction','srcIp','dstIp','port','program','account']).default('time'),sortDir:z.enum(['asc','desc']).default('desc'),hideLoopback:z.enum(['true','false']).optional(),account:z.string().max(200).default('')
  }).parse(req.query)
  if(query.from&&query.to&&new Date(query.from)>new Date(query.to))return res.status(400).json({error:'From must be earlier than To'})
  const filters=[visibleFirewallEventSql()],args=[]
  if(query.eventType==='logon')filters.push("(COALESCE(e.event_type,p.event_type)='logon' OR e.event_id IN (4624,4634))")
  if(query.eventType==='firewall')filters.push("COALESCE(e.event_type,p.event_type,'firewall')<>'logon' AND e.event_id NOT IN (4624,4634)")
  for(const [key,column] of [['nodeId','e.node_id'],['direction','COALESCE(e.direction,p.direction)'],['challengeId','e.challenge_id'],['eventId','e.event_id'],['port','COALESCE(e.dst_port,p.dst_port)']])if(query[key]!==undefined){filters.push(`${column}=?`);args.push(query[key])}
  if(query.action){if(query.action==='logon')filters.push('e.event_id=4624');else if(query.action==='logoff')filters.push('e.event_id=4634');else{filters.push('e.action=?');args.push(query.action)}}
  for(const [key,column] of [['program','COALESCE(e.program,p.program)'],['protocol','COALESCE(e.protocol,p.protocol)'],['srcIp','COALESCE(e.src_ip,p.src_ip)'],['dstIp','COALESCE(e.dst_ip,p.dst_ip)']])if(query[key]){filters.push(`${column} LIKE ? ESCAPE '\\'`);args.push(`%${query[key].replace(/[\\%_]/g,'\\$&')}%`)}
  if(query.account.trim()){const term=`%${query.account.trim().replace(/[\\%_]/g,'\\$&')}%`;filters.push("(e.account_sid LIKE ? ESCAPE '\\' OR COALESCE(ad.sam_account_name,ad.upn,'') LIKE ? ESCAPE '\\' OR COALESCE(la.qualified_name,'') LIKE ? ESCAPE '\\' OR COALESCE(sr.qualified_name,'') LIKE ? ESCAPE '\\')");args.push(term,term,term,term)}
  if(query.from){filters.push('datetime(COALESCE(e.event_time,e.received_at))>=datetime(?)');args.push(query.from)}
  if(query.to){filters.push('datetime(COALESCE(e.event_time,e.received_at))<=datetime(?)');args.push(query.to)}
  if((query.hideLoopback===undefined?observabilitySettings().hideLoopbackEvents:query.hideLoopback==='true'))filters.push("NOT ((COALESCE(e.src_ip,p.src_ip,'') LIKE '127.%' OR COALESCE(e.src_ip,p.src_ip,'') IN ('::1','0:0:0:0:0:0:0:1')) AND (COALESCE(e.dst_ip,p.dst_ip,'') LIKE '127.%' OR COALESCE(e.dst_ip,p.dst_ip,'') IN ('::1','0:0:0:0:0:0:0:1')))")
  const where=filters.length?'WHERE '+filters.join(' AND '):''
  const sortColumns={time:'julianday(COALESCE(e.event_time,e.received_at))',node:'n.hostname COLLATE NOCASE',eventId:'e.event_id',action:'e.action COLLATE NOCASE',direction:'COALESCE(e.direction,p.direction) COLLATE NOCASE',srcIp:'COALESCE(e.src_ip,p.src_ip) COLLATE NOCASE',dstIp:'COALESCE(e.dst_ip,p.dst_ip) COLLATE NOCASE',port:'COALESCE(e.dst_port,p.dst_port)',program:'COALESCE(e.program,p.program) COLLATE NOCASE',account:'COALESCE(ad.sam_account_name,ad.upn,la.qualified_name,sr.qualified_name,e.account_sid) COLLATE NOCASE'}
  const fromSql=`FROM log_events e LEFT JOIN nodes n ON n.id=e.node_id LEFT JOIN node_facts f ON f.node_id=e.node_id LEFT JOIN event_patterns p ON p.id=e.pattern_id LEFT JOIN directory_users ad ON ad.sid=e.account_sid LEFT JOIN local_accounts la ON la.node_id=e.node_id AND la.sid=e.account_sid AND la.missing=0 LEFT JOIN sid_resolutions sr ON sr.node_id=e.node_id AND sr.sid=e.account_sid ${where}`
  const total=one(`SELECT COUNT(*) AS count ${fromSql}`,...args).count
  const items=all(`SELECT e.*,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,e.src_port,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,COALESCE(e.program,p.program) program,COALESCE(e.event_type,p.event_type) event_type,n.ip node_ip,f.snapshot_json node_snapshot_json,COALESCE(ad.sam_account_name,ad.upn,la.qualified_name,sr.qualified_name) account_name ${fromSql} ORDER BY ${sortColumns[query.sortBy]} ${query.sortDir.toUpperCase()}, e.id DESC LIMIT ? OFFSET ?`,...args,query.pageSize,(query.page-1)*query.pageSize).map(event=>{
    const sourceIp=event.src_ip||(event.direction==='out'?event.node_ip:null),destinationIp=event.dst_ip||(event.direction==='in'?event.node_ip:null)
    const classification=classifyNetworkFlow({node:{ip:event.node_ip,snapshot_json:event.node_snapshot_json},sourceIp,destinationIp,protocol:event.protocol,sourcePort:event.src_port,destinationPort:event.dst_port,program:event.program})
    const account=event.account_name?event.account_name:event.account_sid?accountName(event.node_id,event.account_sid).accountName:null
    const {node_ip:_nodeIp,node_snapshot_json:_snapshot,...publicEvent}=event
    const action=Number(publicEvent.event_id)===4624?'logon':Number(publicEvent.event_id)===4634?'logoff':publicEvent.action
    return {...publicEvent,action,protocol:normalizeNetworkProtocol(publicEvent.protocol),account_name:account,traffic_service:classification.service,traffic_class:classification.trafficClass,traffic_scope:classification.scope,traffic_reason:classification.reason}
  })
  res.json({items,total,page:query.page,pageSize:query.pageSize,totalPages:Math.ceil(total/query.pageSize)})
})
const publicEventExport=destination=>({id:destination.id,name:destination.name,kind:destination.kind,endpoint:destination.endpoint,hasToken:!!destination.token_blob,createdAt:destination.created_at,updatedAt:destination.updated_at})
api.get('/event-export/destinations',requireRole('admin'),(_req,res)=>res.json(all('SELECT * FROM event_export_destinations ORDER BY name').map(publicEventExport)))
api.post('/event-export/destinations',requireRole('admin'),(req,res)=>{
  const data=body(z.object({name:z.string().trim().min(1).max(100),kind:z.enum(['syslog_tls','splunk_hec']),endpoint:z.string().trim().min(1).max(2048),token:z.string().min(16).max(512).optional()}),req)
  const endpoint=validateExportDestination(data.kind,data.endpoint)
  if(data.kind==='splunk_hec'&&!data.token)return res.status(400).json({error:'A Splunk HEC token is required'})
  const destinationId=id(),timestamp=now()
  run('INSERT INTO event_export_destinations(id,name,kind,endpoint,token_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',destinationId,data.name,data.kind,endpoint,data.token?seal({token:data.token}):null,timestamp,timestamp)
  audit(req.user.id,'event-export.destination.create','event-export',destinationId,null,{name:data.name,kind:data.kind,endpoint})
  res.status(201).json(publicEventExport(one('SELECT * FROM event_export_destinations WHERE id=?',destinationId)))
})
api.patch('/event-export/destinations/:id',requireRole('admin'),(req,res)=>{
  const before=one('SELECT * FROM event_export_destinations WHERE id=?',reqId(req));if(!before)return notFound(res,'Export destination')
  const data=body(z.object({name:z.string().trim().min(1).max(100),kind:z.enum(['syslog_tls','splunk_hec']),endpoint:z.string().trim().min(1).max(2048),token:z.string().min(16).max(512).optional()}),req)
  const endpoint=validateExportDestination(data.kind,data.endpoint),tokenBlob=data.token?seal({token:data.token}):data.kind===before.kind?before.token_blob:null
  if(data.kind==='splunk_hec'&&!tokenBlob)return res.status(400).json({error:'A Splunk HEC token is required'})
  run('UPDATE event_export_destinations SET name=?,kind=?,endpoint=?,token_blob=?,updated_at=? WHERE id=?',data.name,data.kind,endpoint,tokenBlob,now(),before.id)
  audit(req.user.id,'event-export.destination.update','event-export',before.id,publicEventExport(before),{name:data.name,kind:data.kind,endpoint,tokenChanged:!!data.token})
  res.json(publicEventExport(one('SELECT * FROM event_export_destinations WHERE id=?',before.id)))
})
api.delete('/event-export/destinations/:id',requireRole('admin'),(req,res)=>{
  const destination=one('SELECT * FROM event_export_destinations WHERE id=?',reqId(req));if(!destination)return notFound(res,'Export destination')
  run('DELETE FROM event_export_destinations WHERE id=?',destination.id)
  audit(req.user.id,'event-export.destination.delete','event-export',destination.id,publicEventExport(destination),null)
  res.json({ok:true})
})
api.post('/event-export/send',requireRole('admin'),wrap(async(req,res)=>{
  const data=body(z.object({destinationId:z.string().uuid(),eventIds:z.array(z.string().uuid()).min(1).max(500)}),req)
  const eventIds=[...new Set(data.eventIds)],destination=one('SELECT * FROM event_export_destinations WHERE id=?',data.destinationId)
  if(!destination)return notFound(res,'Export destination')
  const events=all(`SELECT e.*,n.hostname,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,COALESCE(e.program,p.program) program FROM log_events e LEFT JOIN nodes n ON n.id=e.node_id LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE ${visibleFirewallEventSql()} AND e.id IN (${eventIds.map(()=>'?').join(',')})`,...eventIds)
  if(events.length!==eventIds.length)return res.status(404).json({error:'One or more selected events no longer exist'})
  audit(req.user.id,'event-export.send.attempt','event-export',destination.id,null,{eventIds,count:events.length})
  try{
    const result=await exportSelectedEvents(destination,events,destination.token_blob?openSealed(destination.token_blob).token:null)
    audit(req.user.id,'event-export.send.success','event-export',destination.id,null,{eventIds,count:result.sent,kind:result.kind})
    res.json(result)
  }catch(error){
    audit(req.user.id,'event-export.send.failed','event-export',destination.id,null,{eventIds,count:events.length,error:error.message})
    throw Object.assign(new Error(error.message),{status:502})
  }
}))
api.post('/logs/:id/ignore-traffic',requireRole('admin'),(req,res)=>{
  const event=one(`SELECT e.id,e.event_id,e.account_sid,COALESCE(e.action,p.action) action,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,COALESCE(e.program,p.program) program FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE ${visibleFirewallEventSql()} AND e.id=?`,reqId(req))
  if(!event)return notFound(res,'Event')
  let pattern
  try{pattern=trafficIgnoreFromEvent(event)}catch(error){return res.status(400).json({error:error.message})}
  const fingerprint=trafficIgnoreFingerprint(pattern),existing=one('SELECT * FROM traffic_ignore_rules WHERE fingerprint=?',fingerprint)
  if(existing)return res.json({...publicTrafficIgnore(existing),existing:true})
  const ruleId=id(),label=`${event.action||'traffic'} ${event.protocol||'network'} ${event.direction||'flow'}${event.dst_port?` ${event.dst_port}`:''}`
  run('INSERT INTO traffic_ignore_rules(id,label,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,program,account_sid,fingerprint,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',ruleId,label,pattern.eventId,pattern.action,pattern.protocol,pattern.srcIp,pattern.dstIp,pattern.dstPort,pattern.direction,pattern.program,pattern.accountSid,fingerprint,req.user.id,now())
  refreshTrafficIgnores(db)
  const created=one('SELECT * FROM traffic_ignore_rules WHERE id=?',ruleId)
  audit(req.user.id,'traffic-ignore.create-from-event','settings',ruleId,null,{...publicTrafficIgnore(created),eventId:event.id})
  res.status(201).json(publicTrafficIgnore(created))
})
api.post('/logs/:id/rule',requireRole('admin'),(req,res)=>{
  const event=one(`SELECT e.*,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,COALESCE(e.program,p.program) program FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE ${visibleFirewallEventSql()} AND e.id=?`,reqId(req));if(!event)return notFound(res,'Event')
  const node=getNode(event.node_id);if(!node)return notFound(res,'Node')
  const data=body(z.object({action:z.enum(['allow','block']),policyId:z.string().optional()}),req)
  if(!['in','out'].includes(event.direction)||!['TCP','UDP'].includes(event.protocol)||!Number.isInteger(event.dst_port)||event.dst_port<1||event.dst_port>65535)return res.status(400).json({error:'This event lacks a direction, TCP/UDP protocol, or valid destination port'})
  const remoteAddress=event.direction==='in'?event.src_ip:event.dst_ip
  if(!validateAddressExpression(remoteAddress))return res.status(400).json({error:'This event has no valid remote address for a scoped rule'})
  const policy=data.policyId?getPolicy(data.policyId):ensurePersonalPolicy(node,req.user.id)
  if(!policy)return notFound(res,'Policy')
  if(data.policyId&&policy.origin==='learned'&&policy.source_node_id!==node.id)return res.status(400).json({error:'A personal policy belongs to a different node'})
  if(data.policyId&&policy.origin!=='learned'&&!one('SELECT id FROM policy_assignments WHERE policy_id=? AND node_group_id IS NOT NULL',policy.id))return res.status(400).json({error:'Choose a group or global policy'})
  if(!canWriteResource(req.user,'policy',policy))return res.status(403).json({error:'Insufficient permission for policy'})
  if(hasActiveLearning(policy.id))return res.status(409).json({error:'This personal policy is still owned by host training. Finish training before adding a manual rule.'})
  const previous=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
  const graph=parse(previous?.graph_json)||{nodes:[],edges:[]}
  const ruleId=id(),port=String(event.dst_port)
  graph.nodes.push({id:ruleId,type:data.action==='block'?'deny':'allow',position:{x:80+(graph.nodes.length%3)*230,y:80+Math.floor(graph.nodes.length/3)*140},data:{name:`${data.action==='block'?'Reject':'Allow'} ${event.protocol} ${port} from event ${event.event_id}`,direction:event.direction,protocol:event.protocol,localPort:event.direction==='in'?port:'Any',remotePort:event.direction==='out'?port:'Any',remoteAddress,profile:'Any',program:validateProgramPath(event.program)?event.program:'Any'}})
  const rules=compilePolicy(graph,policy.id),conflicts=assignmentConflicts(policy.id,rules,assignedNodes(policy.id))
  assertManagementAccess(rules)
  if(conflicts.length)return rejectConflicts(res,conflicts)
  const versionId=id(),versionNo=(one('SELECT MAX(version_no) n FROM policy_versions WHERE policy_id=?',policy.id)?.n||0)+1
  db.transaction(()=>{
    run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,policy.id,versionNo,json(graph),json(rules),req.user.id,`Rule from firewall event ${event.id}`)
    run('UPDATE policies SET current_version_id=? WHERE id=?',versionId,policy.id)
    if(!data.policyId&&!one('SELECT id FROM policy_assignments WHERE policy_id=? AND node_id=?',policy.id,node.id))run('INSERT INTO policy_assignments(id,policy_id,node_id,assigned_by) VALUES(?,?,?,?)',id(),policy.id,node.id,req.user.id)
    audit(req.user.id,'policy.rule.from-event','policy',policy.id,null,{eventId:event.id,nodeId:node.id,action:data.action,versionId,versionNo})
  })()
  res.status(201).json({policyId:policy.id,versionId,versionNo,ruleCount:rules.length,pendingSync:true})
})
api.post('/logs/ingest',requireRole('editor'),(req,res)=>{
  const data=body(z.object({nodeId:z.string(),events:z.array(z.object({recordId:z.number().optional(),eventId:z.number().int(),action:z.string().optional(),protocol:z.string().optional(),srcIp:z.string().optional(),dstIp:z.string().optional(),dstPort:z.number().optional(),direction:z.string().optional(),program:z.string().optional(),accountSid:z.string().optional(),challengeId:z.string().optional(),logonType:z.string().optional(),logonStatus:z.string().optional(),logonSubStatus:z.string().optional()})).max(1000)}),req)
  const ignoreLoopback=observabilitySettings().ignoreLoopbackIngest
  let inserted=0;db.transaction(()=>{for(const event of data.events){if(ignoreLoopback&&isLoopbackEvent(event)||isExcludedFirewallEvent(event)||isIgnoredFirewallEvent(event))continue;const action=normalizeLogAction(event.eventId,event.action),result=run('INSERT OR IGNORE INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,program,account_sid,challenge_id,logon_type,logon_status,logon_sub_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',id(),data.nodeId,event.recordId??null,event.eventId,action,event.protocol||null,event.srcIp||null,event.dstIp||null,event.dstPort||null,event.direction||null,event.program||null,event.accountSid||null,event.challengeId||null,event.logonType||null,event.logonStatus||null,event.logonSubStatus||null);inserted+=result.changes;if(result.changes&&event.eventId>=5156)recordNetworkFlow(data.nodeId,{...event,eventType:'firewall',action})}})()
  res.status(201).json({inserted})
})

function insertCollectedEvents(nodeId,events,ignoreLoopback){
  let inserted=0
  db.transaction(()=>{for(const event of events){
    const item=normalizeWindowsEvent(event)
    if(ignoreLoopback&&isLoopbackEvent(item))continue
    if(isExcludedFirewallEvent(item)||isIgnoredFirewallEvent(item))continue
    const result=run('INSERT OR IGNORE INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,src_port,dst_ip,dst_port,direction,program,process_id,account_sid,event_time,event_type,logon_type,filter_origin,filter_runtime_id,logon_status,logon_sub_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',id(),nodeId,item.recordId,item.eventId,normalizeLogAction(item.eventId,item.action),item.protocol,item.srcIp,item.srcPort,item.dstIp,item.dstPort,item.direction,item.program,item.processId,item.accountSid,item.eventTime,item.eventType,item.logonType,item.filterOrigin,item.filterRuntimeId,item.logonStatus,item.logonSubStatus)
    inserted+=result.changes
    if(result.changes&&item.eventType==='firewall')recordNetworkFlow(nodeId,item)
    if(!result.changes&&item.filterOrigin)run('UPDATE log_events SET filter_origin=COALESCE(filter_origin,?),filter_runtime_id=COALESCE(filter_runtime_id,?) WHERE node_id=? AND record_id=? AND filter_origin IS NULL',item.filterOrigin,item.filterRuntimeId,nodeId,item.recordId)
    if(!result.changes&&item.eventType==='firewall'&&item.direction==='in')run('UPDATE log_events SET src_ip=?,src_port=?,dst_ip=?,dst_port=? WHERE node_id=? AND record_id=? AND pattern_id IS NULL AND (src_ip IS NOT ? OR src_port IS NOT ? OR dst_ip IS NOT ? OR dst_port IS NOT ?)',item.srcIp,item.srcPort,item.dstIp,item.dstPort,nodeId,item.recordId,item.srcIp,item.srcPort,item.dstIp,item.dstPort)
  }})()
  return inserted
}
function wefNodeForRequest(req) {
  const hint=String(req.query.node||req.get('x-winfire-node')||'').trim()
  if(hint){
    const exact=one('SELECT * FROM nodes WHERE id=? OR hostname=? OR fqdn=? OR ip=?',hint,hint,hint,hint)
    if(exact)return exact
    throw Object.assign(new Error('WEF source node was not found'),{status:404})
  }
  const address=String(req.socket.remoteAddress||req.ip||'').replace(/^::ffff:/,'')
  const matches=all('SELECT * FROM nodes WHERE ip=? OR fqdn=?',address,address)
  if(matches.length===1)return matches[0]
  if(matches.length>1)throw Object.assign(new Error('WEF source address matches more than one node'),{status:409})
  throw Object.assign(new Error('WEF source node identity is required'),{status:401})
}
async function refreshUnknownEventAccounts(node){
  if(node.connection_mode!=='agentless'||!['winrm','winrms'].includes(node.transport))return
  const last=one('SELECT collected_at FROM account_inventory_state WHERE node_id=?',node.id)?.collected_at
  if(last&&Date.now()-Date.parse(last)<60*60*1000)return
  const recent=all("SELECT DISTINCT account_sid FROM log_events WHERE node_id=? AND account_sid IS NOT NULL AND datetime(COALESCE(event_time,received_at))>=datetime('now','-1 hour') LIMIT 500",node.id)
  const unknown=recent.map(item=>item.account_sid).filter(sid=>/^S-1-\d+-\d+(?:-\d+)+$/i.test(sid)&&!accountName(node.id,sid).accountName)
  if(!unknown.length)return
  try{await collectAccountInventory(node,unknown)}catch(error){audit(null,'local-accounts.event-lookup.failed','node',node.id,null,{error:error.message,count:unknown.length})}
}
export async function pullRecentLogs(nodeId,actorId=null,quiet=false){
  const node=getNode(nodeId);if(!node)throw Object.assign(new Error('Node not found'),{status:404})
  const raw=await remote(node,'events_recent'),events=Array.isArray(raw)?raw:[raw].filter(Boolean)
  const inserted=insertCollectedEvents(nodeId,events,observabilitySettings().ignoreLoopbackIngest)
  if(inserted)await refreshUnknownEventAccounts(node)
  if(!quiet)audit(actorId,'logs.pull.recent','node',nodeId,null,{inserted,sampled:events.length,latestRecordId:events.at(-1)?.RecordId??null})
  return {inserted,sampled:events.length,latestRecordId:events.at(-1)?.RecordId??null}
}
export async function pullLogs(nodeId,actorId=null,maxPages=5,quiet=false) {
  const node=getNode(nodeId);if(!node)throw Object.assign(new Error('Node not found'),{status:404})
  const ignoreLoopback=observabilitySettings().ignoreLoopbackIngest
  // The recent tail is stored in log_events too. Never use MAX(record_id) to
  // initialize the historical cursor, or one fresh sample skips the backlog.
  const auditedCursor=one("SELECT json_extract(after_json,'$.lastRecordId') value FROM audit_log WHERE action='logs.pull' AND entity_id=? ORDER BY at DESC,rowid DESC LIMIT 1",nodeId)?.value
  let cursor=one('SELECT last_record_id FROM node_log_cursors WHERE node_id=?',nodeId)?.last_record_id??auditedCursor??0
  let inserted=0,pages=0,caughtUp=false
  for(;pages<maxPages;pages++){
    const raw=await remote(node,'events',{after:cursor}),events=Array.isArray(raw)?raw:[raw].filter(Boolean)
    if(!events.length){caughtUp=true;break}
    inserted+=insertCollectedEvents(nodeId,events,ignoreLoopback)
    const next=Number(events.at(-1).RecordId)
    if(next<=cursor)break
    cursor=next
    run('INSERT INTO node_log_cursors(node_id,last_record_id,updated_at) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET last_record_id=MAX(node_log_cursors.last_record_id,excluded.last_record_id),updated_at=excluded.updated_at',nodeId,cursor,now())
    if(events.length<500){caughtUp=true;pages++;break}
  }
  if(inserted)await refreshUnknownEventAccounts(node)
  if(!quiet)audit(actorId,'logs.pull','node',nodeId,null,{inserted,pages,lastRecordId:cursor,caughtUp})
  return {inserted,pages,lastRecordId:cursor,caughtUp}
}
export async function onboardPendingNodes(limit=5,{resolveDns=lookupDns,enrich=enrichNode,invoke=remote,pullRecent=pullRecentLogs,pullHistory=pullLogs}={}){
  const pending=all(`SELECT n.id FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id
    WHERE n.connection_mode='agentless' AND COALESCE(n.ad_enabled,1)=1
      AND (n.next_retry_at IS NULL OR n.next_retry_at<=?)
      AND EXISTS (SELECT 1 FROM credential_assignments a WHERE a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id))
      AND (f.node_id IS NULL OR NOT EXISTS
        (SELECT 1 FROM audit_log a WHERE a.entity_id=n.id AND a.action='node.onboarding.complete'))
    ORDER BY CASE WHEN f.node_id IS NULL THEN 0 ELSE 1 END,n.created_at LIMIT ?`,now(),limit)
  const results=[]
  for(const item of pending){
    const node=getNode(item.id)
    try{
      if(!node.ip)await resolveDns(node)
      if(!one('SELECT 1 FROM node_facts WHERE node_id=?',node.id)||!['winrm','winrms','wmi','netsh'].includes(node.transport)||node.status!=='reachable')await enrich(getNode(node.id))
      const managed=getNode(node.id)
      const logonOnly=/^(?:5\.[12]\.|windows (?:xp|server 2003))/i.test(String(managed.os_version||''))
      let policy=logonOnly?{supported:false,reason:'WFP 515x audit events are unavailable on XP/Server 2003'}:await invoke(managed,'audit_policy')
      if(!logonOnly&&(!policy?.successEnabled||!policy?.failureEnabled)){
        const before=policy,applyRunId=id()
        run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',applyRunId,node.id,'running')
        try{
          policy=await invoke(managed,'audit_policy_enable')
          if(!policy?.successEnabled||!policy?.failureEnabled)throw new Error('Filtering Platform Connection audit policy could not be confirmed')
          run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',json({operation:'audit_policy_auto_enable',before,after:policy}),now(),applyRunId)
          audit(null,'node.audit-policy.auto-enable','node',node.id,before,{...policy,runId:applyRunId})
        }catch(error){
          run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','unknown',error.message,now(),applyRunId)
          audit(null,'node.audit-policy.auto-enable.failed','node',node.id,before,{runId:applyRunId,error:error.message})
          throw error
        }
      }
      const recent=await pullRecent(node.id,null,true)
      const history=await pullHistory(node.id,null,2,true)
      if(logonOnly)db.transaction(()=>{
        run("UPDATE learning_sessions SET status='unsupported',last_error='XP/Server 2003 firewall enforcement is unavailable' WHERE node_id=? AND mode='auto' AND status='active'",node.id)
        run("UPDATE nodes SET firewall_state='unmanaged' WHERE id=?",node.id)
        audit(null,'node.onboarding.logon-only','node',node.id,null,{transport:managed.transport,osVersion:managed.os_version})
      })()
      audit(null,'node.onboarding.complete','node',node.id,null,{transport:managed.transport,auditPolicy:policy,eventsInserted:recent.inserted+history.inserted,historyCaughtUp:history.caughtUp,logonOnly})
      results.push({nodeId:node.id,status:'complete'})
    }catch(error){
      run('UPDATE nodes SET next_retry_at=? WHERE id=?',new Date(Date.now()+15*60_000).toISOString(),node.id)
      audit(null,'node.onboarding.failed','node',node.id,null,{error:error.message})
      results.push({nodeId:node.id,status:'failed',error:error.message})
    }
  }
  return results
}
api.post('/logs/pull',requireRole('editor'),wrap(async(req,res)=>{
  const {nodeId}=body(z.object({nodeId:z.string()}),req)
  const recent=await pullRecentLogs(nodeId,req.user.id)
  const history=await pullLogs(nodeId,req.user.id)
  res.json({...history,inserted:history.inserted+recent.inserted,recent})
}))
api.get('/learning-sessions',(req,res)=>res.json(all('SELECT * FROM learning_sessions WHERE (? IS NULL OR node_id=?) ORDER BY started_at DESC,rowid DESC LIMIT 500',req.query.nodeId||null,req.query.nodeId||null)))
api.post('/learning-sessions',requireRole('editor'),(req,res)=>{
  const {nodeId,durationHours}=body(z.object({nodeId:z.string(),durationHours:z.number().min(1).max(720).default(24)}),req),node=getNode(nodeId)
  if(!node)return notFound(res,'Node')
  if(/^(?:5\.[12]\.|windows (?:xp|server 2003))/i.test(String(node.os_version||'')))return res.status(409).json({error:'XP/Server 2003 can collect legacy logons but cannot train or enforce modern firewall policies'})
  const active=one("SELECT * FROM learning_sessions WHERE node_id=? AND status='active'",nodeId)
  if(active?.mode==='manual')return res.status(409).json({error:'Node already learning'})
  if(!active&&one("SELECT id FROM learning_sessions WHERE node_id=? AND status IN ('review','applying','apply-failed')",nodeId))return res.status(409).json({error:'Finish the current learning session before starting another'})
  const endsAt=new Date(Date.now()+durationHours*360e4).toISOString()
  const sessionId=active?.id||id()
  db.transaction(()=>{
    const policy=ensurePersonalPolicy(node,req.user.id)
    if(active)run("UPDATE learning_sessions SET mode='manual',ends_at=?,last_error=NULL,progressive_enabled=0,next_progressive_at=NULL,generated_policy_id=? WHERE id=?",endsAt,policy.id,sessionId)
    else run("INSERT INTO learning_sessions(id,node_id,ends_at,status,mode,generated_policy_id) VALUES(?,?,?,'active','manual',?)",sessionId,nodeId,endsAt,policy.id)
    run("UPDATE nodes SET firewall_state='learning' WHERE id=?",nodeId)
    audit(req.user.id,active?'learning.switch-to-manual':'learning.start','node',nodeId,null,{sessionId,endsAt,durationHours,mode:'manual'})
  })()
  res.status(201).json({id:sessionId,nodeId,endsAt,mode:'manual',status:'active'})
})
function learningRuleKey(direction,protocol,port,address,program='Any'){return [direction,String(protocol).toUpperCase(),String(port),String(address).toLowerCase(),String(program).toLowerCase()].join('|')}
function ruleLearningKey(rule){return learningRuleKey(rule.direction,rule.protocol,rule.direction==='in'?rule.localPort:rule.remotePort,rule.remoteAddress,rule.program||'Any')}
function learningPreview(session) {
  const policy=getPolicy(session.generated_policy_id)
  if(!policy)throw Object.assign(new Error('Personal learning policy is missing'),{status:409})
  const processAware=getNode(session.node_id)?.connection_mode==='agent'
  const current=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
  const base=parse(current?.graph_json)||{nodes:[],edges:[]}
  const known=new Set((parse(current?.rules_compiled_json)||[]).filter(rule=>rule.action==='allow').map(ruleLearningKey))
  const assigned=all(`SELECT DISTINCT v.rules_compiled_json FROM policy_versions v JOIN policies p ON p.current_version_id=v.id JOIN policy_assignments a ON a.policy_id=p.id WHERE p.id<>? AND (a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?))`,policy.id,session.node_id,session.node_id)
  for(const row of assigned)for(const rule of parse(row.rules_compiled_json)||[])if(rule.action==='allow')known.add(ruleLearningKey(rule))
  const endAt=new Date(Math.min(Date.now(),Date.parse(session.ends_at))).toISOString()
  const observations=all(`SELECT COALESCE(e.direction,p.direction) direction,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,${processAware?'COALESCE(e.program,p.program)':'NULL'} program,e.src_port src_port,COUNT(*) event_count,MIN(COALESCE(e.event_time,e.received_at)) first_seen_at,MAX(COALESCE(e.event_time,e.received_at)) last_seen_at FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE ${visibleFirewallEventSql()} AND e.node_id=? AND e.action='allow' AND datetime(COALESCE(e.event_time,e.received_at)) BETWEEN datetime(?) AND datetime(?) AND COALESCE(e.dst_port,p.dst_port) BETWEEN 1 AND 65535 AND COALESCE(e.protocol,p.protocol) IN ('TCP','UDP') AND COALESCE(e.direction,p.direction) IN ('in','out') GROUP BY 1,3,2,4,5,6,7 ORDER BY 1,3,2,4,5,7 LIMIT 10001`,session.node_id,session.started_at,endAt)
  if(observations.length>10000)throw Object.assign(new Error('Learning preview exceeds 10,000 observed 5-tuples; narrow the session'),{status:409})
  const existingLearned=new Map((base.nodes||[]).filter(node=>node.id?.startsWith('learned-')&&node.type==='allow').map(node=>[learningRuleKey(node.data.direction,node.data.protocol,node.data.direction==='in'?node.data.localPort:node.data.remotePort,node.data.remoteAddress,node.data.program||'Any'),node.id]))
  const existingKeyByNode=new Map([...existingLearned].map(([key,nodeId])=>[nodeId,key]))
  const broadKeys=new Set([...existingLearned.keys()].filter(key=>key.endsWith('|any')))
  for(const event of observations){
    const remoteAddress=event.direction==='in'?event.src_ip:event.dst_ip
    if(isIP(remoteAddress||'')&&(!processAware||!validateProgramPath(event.program)))broadKeys.add(learningRuleKey(event.direction,event.protocol,event.dst_port,remoteAddress))
  }
  const retainedBaseNodes=(base.nodes||[]).filter(node=>{
    const key=existingKeyByNode.get(node.id)
    return !key||key.endsWith('|any')||!broadKeys.has(key.slice(0,key.lastIndexOf('|'))+'|any')
  })
  const additions=[],seen=new Set(),evidenceByKey=new Map()
  for(const event of observations){
    const remoteAddress=event.direction==='in'?event.src_ip:event.dst_ip
    if(!isIP(remoteAddress||''))continue
    const broadKey=learningRuleKey(event.direction,event.protocol,event.dst_port,remoteAddress)
    const program=processAware&&validateProgramPath(event.program)&&!broadKeys.has(broadKey)?event.program:'Any'
    const key=learningRuleKey(event.direction,event.protocol,event.dst_port,remoteAddress,program)
    if(!existingLearned.has(key)&&(known.has(key)||known.has(broadKey)))continue
    let evidence=evidenceByKey.get(key)
    if(!evidence){
      if(!existingLearned.has(key)&&!seen.has(key)){
        seen.add(key);additions.push({...event,remoteAddress,program,key})
        if(additions.length>500)throw Object.assign(new Error('Learning preview exceeds 500 distinct new flows; narrow the session'),{status:409})
      }
      evidence={eventCount:0,sourcePortCount:0,firstSeenAt:event.first_seen_at,lastSeenAt:event.last_seen_at,sample:null,samples:[],sourcePorts:new Set(),unresolvedProgram:false}
      evidenceByKey.set(key,evidence)
    }
    const sample={sourceIp:event.src_ip,sourcePort:event.src_port,destinationIp:event.dst_ip,destinationPort:event.dst_port,protocol:event.protocol,program:event.program||null,eventCount:event.event_count}
    evidence.eventCount+=event.event_count
    if(processAware&&event.program&&!validateProgramPath(event.program))evidence.unresolvedProgram=true
    if(event.src_port!==null)evidence.sourcePorts.add(event.src_port)
    if(!evidence.sample){const {eventCount,...flow}=sample;evidence.sample=flow}
    if(evidence.samples.length<5)evidence.samples.push(sample)
    if(event.first_seen_at<evidence.firstSeenAt)evidence.firstSeenAt=event.first_seen_at
    if(event.last_seen_at>evidence.lastSeenAt)evidence.lastSeenAt=event.last_seen_at
  }
  const ruleEvidence=key=>{const {sourcePorts,...evidence}=evidenceByKey.get(key);return {...evidence,sourcePortCount:sourcePorts.size}}
  const nodes=[...retainedBaseNodes.map(node=>{const key=existingKeyByNode.get(node.id);return key&&evidenceByKey.has(key)?{...node,data:{...node.data,evidence:ruleEvidence(key)}}:node}),...additions.map((event,index)=>({id:`learned-${crypto.createHash('sha256').update(event.key).digest('hex').slice(0,16)}`,type:'allow',position:{x:80+((retainedBaseNodes.length+index)%4)*180,y:80+Math.floor((retainedBaseNodes.length+index)/4)*100},data:{name:`Learned ${event.protocol} ${event.dst_port} ${event.direction}`,localPort:event.direction==='in'?String(event.dst_port):'Any',remotePort:event.direction==='out'?String(event.dst_port):'Any',protocol:event.protocol,remoteAddress:event.remoteAddress,direction:event.direction,program:event.program,evidence:ruleEvidence(event.key)}}))]
  const graph={nodes,edges:base.edges||[]},rules=compilePolicy(graph,policy.id)
  assertManagementAccess(rules)
  return {policyId:policy.id,nodeId:session.node_id,sessionId:session.id,status:session.status,graph,rules,newFlowCount:additions.length,observedFlowCount:observations.length,asOf:now(),endsAt:session.ends_at,progressiveEnabled:!!session.progressive_enabled,nextProgressiveAt:session.next_progressive_at,lastProgressiveAt:session.last_progressive_at}
}
function saveLearningVersion(session,preview,actorId,comment){
  const policy=getPolicy(session.generated_policy_id),current=one('SELECT * FROM policy_versions WHERE id=?',policy.current_version_id)
  if(current?.graph_json===json(preview.graph))return current
  const versionId=id(),versionNo=(one('SELECT MAX(version_no) n FROM policy_versions WHERE policy_id=?',policy.id)?.n||0)+1
  db.transaction(()=>{
    run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json,created_by,comment) VALUES(?,?,?,?,?,?,?)',versionId,policy.id,versionNo,json(preview.graph),json(preview.rules),actorId,comment)
    run('UPDATE policies SET current_version_id=? WHERE id=?',versionId,policy.id)
    audit(actorId,'learning.version','policy',policy.id,null,{sessionId:session.id,versionId,versionNo,ruleCount:preview.rules.length})
  })()
  return one('SELECT * FROM policy_versions WHERE id=?',versionId)
}
export function finalizeLearning(sessionId,actorId=null) {
  const session=one('SELECT * FROM learning_sessions WHERE id=?',sessionId)
  if(!session)throw Object.assign(new Error('Learning session not found'),{status:404})
  if(!['active','expired'].includes(session.status))throw Object.assign(new Error('Session already finalized'),{status:409})
  if(!session.generated_policy_id){const policy=ensurePersonalPolicy(getNode(session.node_id),actorId);run('UPDATE learning_sessions SET generated_policy_id=? WHERE id=?',policy.id,session.id);session.generated_policy_id=policy.id}
  const preview=learningPreview(session)
  const version=saveLearningVersion(session,preview,actorId,'Final learning snapshot')
  db.transaction(()=>{
    run("UPDATE learning_sessions SET status='review',last_error=NULL WHERE id=?",session.id)
    run("UPDATE nodes SET firewall_state='review' WHERE id=?",session.node_id)
    audit(actorId,'learning.finalize','node',session.node_id,null,{policyId:preview.policyId,observations:preview.newFlowCount,mode:session.mode})
  })()
  return {policyId:preview.policyId,versionId:version.id,ruleCount:preview.rules.length,status:'review'}
}
api.post('/learning-sessions/:id/finalize',requireRole('editor'),(req,res)=>{
  const session=one('SELECT * FROM learning_sessions WHERE id=?',reqId(req))
  if(!session)return notFound(res,'Learning session')
  if(session.mode==='auto')return res.status(409).json({error:'Automatic training finalizes at its scheduled end'})
  res.json(finalizeLearning(session.id,req.user.id))
})
function assignedPoliciesForNode(nodeId){return all(`SELECT DISTINCT p.* FROM policies p JOIN policy_assignments a ON a.policy_id=p.id WHERE a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?) ORDER BY CASE WHEN p.origin='learned' THEN 0 ELSE 1 END,p.name`,nodeId,nodeId)}
export async function approveLearning(sessionId,actorId=null) {
  const session=one('SELECT * FROM learning_sessions WHERE id=?',sessionId)
  if(!session)throw Object.assign(new Error('Learning session not found'),{status:404})
  if(!['review','apply-failed'].includes(session.status))throw Object.assign(new Error('Session is not awaiting approval'),{status:409})
  const policy=getPolicy(session.generated_policy_id),node=getNode(session.node_id)
  if(!policy||!node)throw Object.assign(new Error('Learning proposal or node is missing'),{status:409})
  const rules=parse(one('SELECT rules_compiled_json FROM policy_versions WHERE id=?',policy.current_version_id)?.rules_compiled_json)||[]
  const conflicts=assignmentConflicts(policy.id,rules,[node])
  if(conflicts.length)throw Object.assign(new Error('Conflicting firewall rules on assigned nodes'),{status:409,conflicts})
  const attemptId=id()
  db.transaction(()=>{
    if(!one('SELECT id FROM policy_assignments WHERE policy_id=? AND node_id=?',policy.id,node.id))run('INSERT INTO policy_assignments(id,policy_id,node_id,assigned_by) VALUES(?,?,?,?)',id(),policy.id,node.id,actorId)
    run("UPDATE learning_sessions SET status='applying',last_attempt_at=?,last_error=NULL,current_apply_attempt_id=? WHERE id=?",now(),attemptId,session.id)
    audit(actorId,session.mode==='auto'?'learning.auto-apply':'learning.approve','node',node.id,null,{sessionId:session.id,policyId:policy.id})
  })()
  const results=[],assignedPolicies=assignedPoliciesForNode(node.id)
  try{for(const assigned of assignedPolicies)results.push(...await applyPolicy(assigned,actorId,[node],{learningSessionId:session.id,learningAttemptId:attemptId,learningExpectedJobs:assignedPolicies.length}))}
  catch(error){run("UPDATE learning_sessions SET status='apply-failed',last_error=? WHERE id=?",error.message,session.id);run("UPDATE nodes SET firewall_state='review' WHERE id=?",node.id);throw error}
  const status=results.every(result=>result.status==='success')?'enforced':results.some(result=>result.status==='failed')?'apply-failed':'applying'
  run('UPDATE learning_sessions SET status=?,last_error=? WHERE id=?',status,results.find(result=>result.status==='failed')?.error||null,session.id)
  run('UPDATE nodes SET firewall_state=? WHERE id=?',status==='enforced'?'enforcing':status==='applying'?'applying':'review',node.id)
  return {status,results}
}
api.post('/learning-sessions/:id/approve',requireRole('editor'),wrap(async(req,res)=>res.json(await approveLearning(reqId(req),req.user.id))))

async function collectTrainingTelemetry(node){
  if(node.connection_mode==='agent'){
    const agent=one('SELECT last_checkin_at FROM agents WHERE id=? AND revoked_at IS NULL',node.agent_id)
    if(!agent?.last_checkin_at||Date.parse(agent.last_checkin_at)<Date.now()-5*60_000)throw new Error('Agent is not online to confirm training telemetry')
  }else{
    if(!['winrm','winrms','wmi','netsh'].includes(node.transport))throw new Error('No working event collection transport; probe the node before training can finish')
    const auditPolicy=await remote(node,'audit_policy')
    if(auditPolicy?.successEnabled!==true)throw new Error('Filtering Platform Connection success auditing is disabled; enable it before automatic training can finish')
    const collection=await pullLogs(node.id)
    if(!collection.caughtUp)throw new Error('Security event backlog remains; training will finish after collection catches up')
  }
}
async function applyProgressiveLearning(session,node){
  const pending=one("SELECT id FROM agent_jobs WHERE agent_id=? AND type='policy.apply' AND status IN ('queued','leased') AND json_extract(payload_json,'$.policyId')=?",node.agent_id,session.generated_policy_id)
  if(pending)throw new Error('Previous agent learning apply is still pending')
  const preview=learningPreview(session),policy=getPolicy(session.generated_policy_id)
  const conflicts=assignmentConflicts(policy.id,preview.rules,[node])
  if(conflicts.length)throw Object.assign(new Error('Learned rules conflict with another assigned policy'),{status:409,conflicts})
  const current=one('SELECT graph_json,rules_compiled_json FROM policy_versions WHERE id=?',policy.current_version_id)
  const changed=current?.graph_json!==json(preview.graph)
  const rulesChanged=current?.rules_compiled_json!==json(preview.rules)
  if(changed)saveLearningVersion(session,preview,null,'Progressive learning snapshot')
  if(preview.rules.length&&!one('SELECT id FROM policy_assignments WHERE policy_id=? AND node_id=?',policy.id,node.id))run('INSERT INTO policy_assignments(id,policy_id,node_id) VALUES(?,?,?)',id(),policy.id,node.id)
  let result={status:'unchanged'}
  if(preview.rules.length&&(rulesChanged||session.last_error)){
    result=(await applyPolicy(getPolicy(policy.id),null,[node],{progressiveSessionId:session.id}))[0]
    if(result.status==='failed')throw new Error(result.error)
  }
  const at=now(),next=new Date(Math.min(Date.parse(session.ends_at),Date.now()+session.progressive_interval_hours*36e5)).toISOString()
  run('UPDATE learning_sessions SET last_progressive_at=?,next_progressive_at=?,last_attempt_at=?,last_error=NULL WHERE id=?',at,next,at,session.id)
  audit(null,'learning.progressive','node',node.id,null,{sessionId:session.id,policyId:policy.id,newFlows:preview.newFlowCount,ruleCount:preview.rules.length,status:result.status,next})
  return {sessionId:session.id,status:result.status==='queued'?'queued':changed?'updated':'unchanged',ruleCount:preview.rules.length,nextProgressiveAt:next}
}
export async function processDueTraining(limit=25) {
  const cutoff=now(),retryBefore=new Date(Date.now()-60*60*1000).toISOString()
  const due=all("SELECT * FROM learning_sessions WHERE mode='auto' AND (((status='active' AND (ends_at<=? OR (progressive_enabled=1 AND next_progressive_at<=?))) OR status IN ('review','apply-failed')) AND (last_attempt_at IS NULL OR last_attempt_at<=?)) ORDER BY ends_at LIMIT ?",cutoff,cutoff,retryBefore,limit)
  const results=[]
  for(const session of due){
    try{
      if(session.status==='active'){
        const node=getNode(session.node_id)
        if(!node)throw new Error('Node is missing')
        await collectTrainingTelemetry(node)
        if(session.ends_at>cutoff){results.push(await applyProgressiveLearning(session,node));continue}
        if(node.connection_mode==='agent'&&one("SELECT id FROM agent_jobs WHERE agent_id=? AND type='policy.apply' AND status IN ('queued','leased') AND json_extract(payload_json,'$.progressiveSessionId')=?",node.agent_id,session.id))throw new Error('Wait for the previous progressive apply before finalizing learning')
        finalizeLearning(session.id)
      }
      const applied=await approveLearning(session.id)
      results.push({sessionId:session.id,status:applied.status})
    }catch(error){
      run('UPDATE learning_sessions SET last_error=?,last_attempt_at=? WHERE id=?',error.message,now(),session.id)
      audit(null,'learning.auto-failed','node',session.node_id,null,{sessionId:session.id,error:error.message})
      results.push({sessionId:session.id,status:'failed',error:error.message})
    }
  }
  return results
}

export async function processDueBreakGlass(limit=25){
  const due=all("SELECT * FROM break_glass_sessions WHERE status IN ('activating','activation-unknown','active','ending') AND expires_at<=? ORDER BY expires_at LIMIT ?",now(),limit)
  const results=[]
  for(const session of due){
    try{
      if(session.status==='ending'){results.push({sessionId:session.id,status:'ending'});continue}
      if(session.status==='activating'&&getNode(session.node_id)?.connection_mode==='agent'){
        const job=one('SELECT status FROM agent_jobs WHERE id=?',session.agent_job_id)
        if(job?.status==='queued'){
          run("UPDATE agent_jobs SET status='failed',error='Break-glass window expired before activation',finished_at=? WHERE id=?",now(),session.agent_job_id)
          run("UPDATE break_glass_sessions SET status='failed',last_error='Expired before agent activation' WHERE id=?",session.id)
          results.push({sessionId:session.id,status:'failed'})
        }else results.push({sessionId:session.id,status:'activation-pending'})
        continue
      }
      const result=await endBreakGlass(session,null,'expired')
      results.push({sessionId:session.id,status:result.queued?'ending':'expired'})
    }catch(error){results.push({sessionId:session.id,status:'failed',error:error.message})}
  }
  return results
}

api.get('/rpc-filters',requireRole('auditor'),(req,res)=>{
  const nodeId=String(req.query.nodeId||'').trim()
  const rows=all(`SELECT r.*,n.hostname node_hostname,n.transport node_transport,n.status node_status FROM rpc_filter_rules r LEFT JOIN nodes n ON n.id=r.node_id ${nodeId?'WHERE r.node_id=?':''} ORDER BY COALESCE(n.hostname,''),r.label,r.id`,...(nodeId?[nodeId]:[]))
  res.json(rows.map(row=>({...publicRpcFilter(row),nodeHostname:row.node_hostname||null,nodeTransport:row.node_transport||null,nodeStatus:row.node_status||null})))
})
api.post('/rpc-filters',requireRole('admin'),(req,res)=>{
  const data=body(z.object({nodeId:z.string(),interfaceUuid:z.string(),opnum:z.number().int().min(0).max(65535).nullable().optional(),source:z.string().trim().max(255).default('Any'),action:z.enum(['allow','block','continue']),audit:z.boolean().default(true),label:z.string().trim().max(160).default('')}),req)
  const node=getNode(data.nodeId);if(!node)return notFound(res,'Node')
  const normalized=normalizeRpcFilter(data,{idValue:id()})
  const duplicate=one('SELECT id FROM rpc_filter_rules WHERE node_id=? AND interface_uuid=? AND opnum IS ? AND COALESCE(source,\'Any\')=? AND action=?',data.nodeId,normalized.interfaceUuid,normalized.opnum,normalized.source||'Any',normalized.action)
  if(duplicate)return res.status(409).json({error:'An equivalent RPC filter already exists'})
  run('INSERT INTO rpc_filter_rules(id,node_id,interface_uuid,opnum,source,action,audit,label) VALUES(?,?,?,?,?,?,?,?)',normalized.id,data.nodeId,normalized.interfaceUuid,normalized.opnum,normalized.source,normalized.action,Number(normalized.audit),normalized.label)
  audit(req.user.id,'rpc-filter.create','rpc-filter',normalized.id,null,{...normalized,nodeId:data.nodeId})
  res.status(201).json(publicRpcFilter(one('SELECT * FROM rpc_filter_rules WHERE id=?',normalized.id)))
})
api.post('/rpc-filters/:id/apply-inventory',requireRole('admin'),wrap(async(req,res)=>{
  const filter=one('SELECT * FROM rpc_filter_rules WHERE id=?',reqId(req));if(!filter)return notFound(res,'RPC filter')
  const node=getNode(filter.node_id);if(!node)return notFound(res,'Node')
  if(!['winrm','winrms','netsh'].includes(node.transport)||node.status!=='reachable')return res.status(409).json({error:'RPC filter deployment requires a reachable authenticated WinRM or SMB/netsh node'})
  const rows=all('SELECT * FROM rpc_filter_rules WHERE node_id=? ORDER BY rowid,id',node.id)
  const rules=rows.map(row=>normalizeRpcFilter({id:row.id,interfaceUuid:row.interface_uuid,opnum:row.opnum,source:row.source,action:row.action,audit:!!row.audit,label:row.label},{idValue:row.id}))
  const result=await remote(node,'rpc_filter_apply',{rules})
  const applied=new Set(result?.applied||[])
  if(applied.size!==rules.length)throw Object.assign(new Error('RPC filter deployment did not confirm every filter key'),{status:502})
  run(`UPDATE rpc_filter_rules SET applied_at=? WHERE node_id=? AND id IN (${rows.map(()=>'?').join(',')})`,now(),node.id,...rows.map(row=>row.id))
  audit(req.user.id,'rpc-filter.apply','node',node.id,null,{filterIds:rows.map(row=>row.id),count:rows.length,transport:node.transport})
  res.json({nodeId:node.id,applied:rows.map(row=>row.id),transport:node.transport,inventory:result?.output||null})
}))
api.get('/rpc-filters/:id/inventory',requireRole('auditor'),wrap(async(req,res)=>{
  const filter=one('SELECT * FROM rpc_filter_rules WHERE id=?',reqId(req));if(!filter)return notFound(res,'RPC filter')
  const node=getNode(filter.node_id);if(!node)return notFound(res,'Node')
  if(!['winrm','winrms','netsh'].includes(node.transport)||node.status!=='reachable')return res.status(409).json({error:'Native RPC filter inventory requires a reachable authenticated WinRM or SMB/netsh node'})
  const result=await remote(node,'rpc_filters',{})
  res.json({nodeId:node.id,transport:node.transport,raw:result?.raw||''})
}))
api.delete('/rpc-filters/:id',requireRole('admin'),wrap(async(req,res)=>{
  const filter=one('SELECT * FROM rpc_filter_rules WHERE id=?',reqId(req));if(!filter)return notFound(res,'RPC filter')
  const node=getNode(filter.node_id)
  if(filter.applied_at){
    if(!node||!['winrm','winrms','netsh'].includes(node.transport)||node.status!=='reachable')return res.status(409).json({error:'Reconnect the authenticated node before removing its applied RPC filter'})
    const result=await remote(node,'rpc_filter_remove',{filterKeys:[filter.id]})
    if(!result?.removed?.includes(filter.id))throw Object.assign(new Error('RPC filter removal was not confirmed'),{status:502})
  }
  run('DELETE FROM rpc_filter_rules WHERE id=?',filter.id)
  audit(req.user.id,'rpc-filter.delete','rpc-filter',filter.id,publicRpcFilter(filter),null)
  res.status(204).end()
}))
api.post('/logon-rights/revoke',requireRole('admin'),(req,res)=>res.status(501).json({error:'LSA rights mutation requires a validated Windows test target and is not enabled by this build'}))
api.post('/logon-rights/jit-grant',requireRole('admin'),(req,res)=>res.status(501).json({error:'JIT logon-rights mutation requires a validated Windows test target and is not enabled by this build'}))

api.get('/agents',(_req,res)=>res.json(all('SELECT * FROM agents ORDER BY last_checkin_at DESC')))
api.post('/agents/:id/revoke',requireRole('admin'),(req,res)=>{
  const agent=one('SELECT * FROM agents WHERE id=?',reqId(req));if(!agent)return notFound(res,'Agent')
  db.transaction(()=>{
    for(const assignment of all(`SELECT a.* FROM policy_assignments a JOIN agent_jobs j ON j.id=a.removal_job_id WHERE j.agent_id=?`,agent.id)){
      run("UPDATE agent_jobs SET status='failed',error='Agent revoked before firewall cleanup',finished_at=? WHERE id=?",now(),assignment.removal_job_id)
      const applyRunId=parse(one('SELECT payload_json FROM agent_jobs WHERE id=?',assignment.removal_job_id)?.payload_json)?.applyRunId
      if(applyRunId)run("UPDATE policy_apply_runs SET status='failed',error='Agent revoked before firewall cleanup',finished_at=? WHERE id=?",now(),applyRunId)
      run('UPDATE policy_assignments SET removal_job_id=NULL WHERE id=?',assignment.id)
      audit(req.user.id,'policy.unassign.failed','policy',assignment.policy_id,assignment,{reason:'agent_revoked',nodeId:agent.node_id})
    }
    run('UPDATE agents SET revoked_at=? WHERE id=?',now(),agent.id)
    run("UPDATE nodes SET status='unreachable' WHERE id=?",agent.node_id)
    audit(req.user.id,'agent.revoke','agent',agent.id,null,{nodeId:agent.node_id})
  })()
  res.json({revoked:true})
})
function issueAgentEnrollmentToken(nodeId,actorId,expiresAt){
  const token=crypto.randomBytes(32).toString('base64url')
  run('INSERT INTO enrollment_tokens(id,node_id,token_hash,expires_at) VALUES(?,?,?,?)',id(),nodeId,hashToken(token),expiresAt)
  audit(actorId,'agent.token.create','node',nodeId,null,{expires:expiresAt})
  return {nodeId,token,expiresAt}
}
api.post('/agents/enrollment-tokens/bulk',requireRole('admin'),(req,res)=>{
  if(!req.secure)return res.status(426).json({error:'Agent enrollment tokens require HTTPS'})
  if(!agentPkiReady())return res.status(503).json({error:'Configure HTTPS and agent PKI before generating enrollment tokens'})
  const {nodeIds}=body(z.object({nodeIds:z.array(z.string()).min(1).max(50).refine(ids=>new Set(ids).size===ids.length,'Choose each node only once')}),req)
  const nodes=all(`SELECT id,hostname FROM nodes WHERE id IN (${nodeIds.map(()=>'?').join(',')})`,...nodeIds)
  if(nodes.length!==nodeIds.length)return res.status(404).json({error:'One or more nodes were not found'})
  const enrolled=all(`SELECT node_id FROM agents WHERE node_id IN (${nodeIds.map(()=>'?').join(',')})`,...nodeIds)
  if(enrolled.length)return res.status(409).json({error:'One or more nodes already have an agent; use certificate renewal'})
  const byId=new Map(nodes.map(node=>[node.id,node]))
  const expiresAt=new Date(Date.now()+15*60*1000).toISOString()
  const tokens=db.transaction(()=>nodeIds.map(nodeId=>({hostname:byId.get(nodeId).hostname,...issueAgentEnrollmentToken(nodeId,req.user.id,expiresAt)})))()
  res.status(201).json({tokens,expiresAt})
})
api.post('/agents/enrollment-tokens',requireRole('admin'),(req,res)=>{
  if(!req.secure)return res.status(426).json({error:'Agent enrollment tokens require HTTPS'})
  if(!agentPkiReady())return res.status(503).json({error:'Configure HTTPS and agent PKI before generating enrollment tokens'})
  const {nodeId}=body(z.object({nodeId:z.string()}),req);if(!getNode(nodeId))return notFound(res,'Node')
  if(one('SELECT id FROM agents WHERE node_id=?',nodeId))return res.status(409).json({error:'This node already has an agent; use certificate renewal'})
  const issued=issueAgentEnrollmentToken(nodeId,req.user.id,new Date(Date.now()+15*60*1000).toISOString())
  res.status(201).json({token:issued.token,expiresAt:issued.expiresAt})
})
api.get('/agents/:id',(req,res)=>{const agent=one('SELECT * FROM agents WHERE id=?',reqId(req));return agent?res.json(agent):notFound(res,'Agent')})

app.use((error,req,res,_next)=>{
  if(error instanceof z.ZodError)return res.status(400).json({error:'Validation failed',issues:error.issues})
  if(error?.code==='SQLITE_CONSTRAINT_UNIQUE'||error?.code==='SQLITE_CONSTRAINT_PRIMARYKEY')return res.status(409).json({error:'Record already exists'})
  if([400,401,403,404,409,413,429,502,503].includes(error.status))return res.status(error.status).json({error:error.message,...(error.conflicts?{conflicts:error.conflicts}:{})})
  console.error(error)
  res.status(500).json({error:'Internal server error'})
})
