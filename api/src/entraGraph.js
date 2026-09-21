import crypto from 'node:crypto'
import {effectiveEntraSettings} from './entraSettings.js'
import {clientCredentialsForm} from './entraClientAuth.js'
import {db,all,one,run,now} from './db.js'

const guid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const tokenCache=new Map()
const groupCacheTtlMs=5*60*1000

function normalizedGroupId(value){
  const group=String(value||'').trim().toLowerCase()
  return guid.test(group)?group:null
}
function graphError(response,body){
  const error=new Error(`Microsoft Graph request failed (${response.status})`)
  error.status=502
  error.graphStatus=response.status
  error.code=body?.error?.code||null
  return error
}
function graphSettings(){
  const settings=effectiveEntraSettings()
  const credential=settings.clientAuthMethod==='certificate'?settings.clientCertificate&&settings.clientPrivateKey:settings.clientSecret
  if(!settings.enabled||!guid.test(String(settings.tenantId||''))||!guid.test(String(settings.clientId||''))||!credential){
    throw Object.assign(new Error('Configure and enable Microsoft Graph application credentials before syncing an Entra group'),{status:409})
  }
  return settings
}
function settingsKey(settings){
  return crypto.createHash('sha256').update(`${settings.tenantId}:${settings.clientId}:${settings.clientAuthMethod}:${settings.clientSecret||''}:${settings.clientCertificate||''}`).digest('hex')
}
async function graphToken(settings,fetchImpl){
  const key=settingsKey(settings)
  const cached=tokenCache.get(key)
  if(cached&&cached.expiresAt>Date.now()+60_000)return cached.value
  const endpoint=`https://login.microsoftonline.com/${encodeURIComponent(settings.tenantId)}/oauth2/v2.0/token`
  const response=await fetchImpl(endpoint,{
    method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams(clientCredentialsForm(settings))
  })
  const body=await response.json().catch(()=>null)
  if(!response.ok||!body?.access_token)throw graphError(response,body)
  const value=body.access_token
  tokenCache.set(key,{value,expiresAt:Date.now()+Math.max(60,Number(body.expires_in)||3600)*1000})
  return value
}

export async function fetchEntraGroupMembers(groupId,{fetchImpl=globalThis.fetch,force=false,settingsOverride=null}={}){
  const normalized=normalizedGroupId(groupId)
  if(!normalized)throw Object.assign(new Error('Entra group targeting requires a group object ID (GUID)'),{status:400})
  if(typeof fetchImpl!=='function')throw Object.assign(new Error('Fetch is unavailable for Microsoft Graph'),{status:503})
  const settings=settingsOverride||graphSettings()
  const token=await graphToken(settings,fetchImpl)
  const members=[]
  let url=`https://graph.microsoft.com/v1.0/groups/${encodeURIComponent(normalized)}/members/microsoft.graph.user?$select=id,userPrincipalName,mail,accountEnabled&$top=999`
  for(let page=0;url&&page<20;page++){
    const response=await fetchImpl(url,{headers:{authorization:`Bearer ${token}`,accept:'application/json'}})
    const body=await response.json().catch(()=>null)
    if(!response.ok)throw graphError(response,body)
    for(const member of Array.isArray(body?.value)?body.value:[]){
      const objectId=String(member.id||'').trim().toLowerCase()
      const upn=String(member.userPrincipalName||'').trim().toLowerCase()
      const email=String(member.mail||'').trim().toLowerCase()
      if(objectId&&(upn||email))members.push({objectId,upn:upn||null,email:email||null,enabled:member.accountEnabled!==false})
    }
    url=typeof body?.['@odata.nextLink']==='string'&&body['@odata.nextLink'].startsWith('https://graph.microsoft.com/')?body['@odata.nextLink']:null
  }
  if(url)throw Object.assign(new Error('Microsoft Graph returned too many group member pages'),{status:502})
  const unique=new Map()
  for(const member of members)unique.set(member.objectId,member)
  return [...unique.values()]
}

export async function syncEntraGroup(groupId,{fetchImpl=globalThis.fetch,force=false,ttlMs=groupCacheTtlMs}={}){
  const normalized=normalizedGroupId(groupId)
  if(!normalized)throw Object.assign(new Error('Entra group targeting requires a group object ID (GUID)'),{status:400})
  const settings=graphSettings(),key=settingsKey(settings)
  const cached=one('SELECT * FROM entra_group_sync WHERE group_id=?',normalized)
  if(!force&&cached?.settings_key===key&&cached?.expires_at>now())return {groupId:normalized,count:all('SELECT object_id FROM entra_group_members WHERE group_id=? AND settings_key=?',normalized,key).length,cached:true,syncedAt:cached.synced_at}
  try{
    const members=await fetchEntraGroupMembers(normalized,{fetchImpl,force,settingsOverride:settings})
    const seen=now(),expiresAt=new Date(Date.now()+ttlMs).toISOString()
    db.transaction(()=>{
      run('DELETE FROM entra_group_members WHERE group_id=?',normalized)
      for(const member of members)run('INSERT INTO entra_group_members(group_id,object_id,upn,email,enabled,seen_at,expires_at,settings_key) VALUES(?,?,?,?,?,?,?,?)',normalized,member.objectId,member.upn,member.email,Number(member.enabled),seen,expiresAt,key)
      run('INSERT INTO entra_group_sync(group_id,synced_at,expires_at,last_error,settings_key) VALUES(?,?,?,NULL,?) ON CONFLICT(group_id) DO UPDATE SET synced_at=excluded.synced_at,expires_at=excluded.expires_at,last_error=NULL,settings_key=excluded.settings_key',normalized,seen,expiresAt,key)
    })()
    return {groupId:normalized,count:members.length,cached:false,syncedAt:seen}
  }catch(error){
    run('INSERT INTO entra_group_sync(group_id,synced_at,expires_at,last_error,settings_key) VALUES(?,?,?,?,?) ON CONFLICT(group_id) DO UPDATE SET synced_at=excluded.synced_at,expires_at=excluded.expires_at,last_error=excluded.last_error,settings_key=excluded.settings_key',normalized,now(),new Date(Date.now()+60_000).toISOString(),String(error.message).slice(0,500),key)
    throw error
  }
}

export async function entraGroupAllowsOperator(groupId,email,options={}){
  const normalizedEmail=String(email||'').trim().toLowerCase()
  const normalizedGroup=normalizedGroupId(groupId)
  if(!normalizedEmail||!normalizedGroup)return false
  try{await syncEntraGroup(normalizedGroup,options)}catch{return false}
  let key
  try{key=settingsKey(graphSettings())}catch{return false}
  return !!one('SELECT 1 FROM entra_group_members WHERE group_id=? AND settings_key=? AND enabled=1 AND expires_at>? AND (lower(upn)=? OR lower(email)=?) LIMIT 1',normalizedGroup,key,now(),normalizedEmail,normalizedEmail)
}

export function cachedEntraGroupMembers(groupId){
  const normalized=normalizedGroupId(groupId)
  if(!normalized)return []
  let key
  try{key=settingsKey(graphSettings())}catch{return []}
  return all('SELECT object_id objectId,upn,email,enabled,seen_at seenAt,expires_at expiresAt FROM entra_group_members WHERE group_id=? AND settings_key=? AND expires_at>? ORDER BY lower(coalesce(upn,email))',normalized,key,now())
}

export function clearEntraGraphTokenCache(){tokenCache.clear()}
