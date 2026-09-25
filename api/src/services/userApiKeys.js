import crypto from 'node:crypto'
import {z} from 'zod'
import {db,all,one,run,id,now,audit} from '../db.js'
import {hashToken} from '../security.js'
import {enrollReporter,bindings} from '../ai/reporters.js'
const fail=(status,message)=>{throw Object.assign(new Error(message),{status})}
const name=z.string().trim().min(1).max(100)
const expiry=z.iso.datetime().refine(v=>Date.parse(v)>Date.now()&&Date.parse(v)<=Date.now()+365*86400000,'Expiry must be in the future and within one year')
export const keyCreateSchema=z.strictObject({name,userId:z.string().min(1).optional(),purpose:z.enum(['api','mcp']),access:z.enum(['read','write']).default('read'),expiresAt:expiry,nodeIds:z.array(z.string().min(1)).max(100).default([])})
export const keyEditSchema=z.strictObject({name:name.optional(),expiresAt:expiry.optional()})
const admin=user=>['admin','owner'].includes(user.role)
function ownerFor(actor,userId=actor.id){
  const owner=one('SELECT * FROM users WHERE id=?',userId)
  if(!owner)fail(404,'User not found')
  if(owner.id!==actor.id){
    if(!admin(actor))fail(403,'You can manage only your own API keys')
    if(all('SELECT permission_id FROM role_permissions WHERE role_id=?',owner.role).some(p=>!one('SELECT 1 FROM role_permissions WHERE role_id=? AND permission_id=?',actor.role,p.permission_id)))fail(403,'Cannot administer keys for a user with higher permissions')
  }
  return owner
}
const publicKey=r=>({id:r.id,userId:r.user_id,ownerEmail:r.email,name:r.name,prefix:r.prefix,scopes:JSON.parse(r.scopes_json),purpose:JSON.parse(r.scopes_json).includes('mcp:report')?'mcp':'api',reporterId:r.reporter_id,nodeIds:r.reporter_id?bindings(r.reporter_id):[],createdAt:r.created_at,updatedAt:r.updated_at,expiresAt:r.expires_at,lastUsedAt:r.last_used_at,revokedAt:r.revoked_at,status:r.revoked_at?'revoked':r.expires_at<=now()?'expired':'active'})
function ownedKey(actor,keyId){const row=one('SELECT k.*,u.email FROM user_api_keys k JOIN users u ON u.id=k.user_id WHERE k.id=?',keyId);if(!row)fail(404,'API key not found');ownerFor(actor,row.user_id);return row}
const newSecret=()=>`wfuk_${crypto.randomBytes(32).toString('base64url')}`
export function keyOptions(actor){return {canAdminister:admin(actor),users:(admin(actor)?all('SELECT id,email,role,suspended,directory_only FROM users ORDER BY email'):[actor]).filter(u=>{try{ownerFor(actor,u.id);return !u.suspended&&!u.directory_only}catch{return false}}).map(u=>({id:u.id,email:u.email})),scopes:['api:read','api:write','mcp:report']}}
export function listKeys(actor,input){
  const q=z.object({q:z.string().trim().max(200).default(''),owner:z.string().default('self'),status:z.enum(['all','active','expired','revoked']).default('all'),purpose:z.enum(['all','api','mcp']).default('all'),sort:z.enum(['name','created','expires','used']).default('created'),direction:z.enum(['asc','desc']).default('desc'),page:z.coerce.number().int().min(1).max(1000000).default(1),pageSize:z.coerce.number().int().min(1).max(100).default(25)}).parse(input)
  const where=[],args=[]
  if(q.owner==='all'){if(!admin(actor))fail(403,'Administrator access required');const owners=all('SELECT id FROM users').filter(u=>{try{ownerFor(actor,u.id);return true}catch{return false}});where.push('k.user_id IN ('+owners.map(()=>'?').join(',')+')');args.push(...owners.map(u=>u.id))}
  else{const owner=ownerFor(actor,q.owner==='self'?actor.id:q.owner);where.push('k.user_id=?');args.push(owner.id)}
  if(q.q){where.push("(k.name LIKE ? ESCAPE '\\' OR u.email LIKE ? ESCAPE '\\' OR k.prefix LIKE ? ESCAPE '\\')");const term='%'+q.q.replace(/[\\%_]/g,'\\$&')+'%';args.push(term,term,term)}
  if(q.purpose!=='all')where.push(`json_extract(k.scopes_json,'$[0]') ${q.purpose==='api'?'<>':'='} 'mcp:report'`)
  if(q.status==='revoked')where.push('k.revoked_at IS NOT NULL')
  if(['active','expired'].includes(q.status)){where.push(`k.revoked_at IS NULL AND k.expires_at${q.status==='active'?'>':'<='}?`);args.push(now())}
  const clause=where.join(' AND '),sort={name:'k.name',created:'k.created_at',expires:'k.expires_at',used:'k.last_used_at'}[q.sort]
  return {items:all(`SELECT k.*,u.email FROM user_api_keys k JOIN users u ON u.id=k.user_id WHERE ${clause} ORDER BY ${sort} ${q.direction},k.id LIMIT ? OFFSET ?`,...args,q.pageSize,(q.page-1)*q.pageSize).map(publicKey),total:one(`SELECT COUNT(*) n FROM user_api_keys k JOIN users u ON u.id=k.user_id WHERE ${clause}`,...args).n,page:q.page,pageSize:q.pageSize}
}
export function createKey(actor,input){
  const v=keyCreateSchema.parse(input),owner=ownerFor(actor,v.userId),keyId=id(),secret=newSecret(),stamp=now()
  if(owner.suspended||owner.directory_only)fail(409,'Choose an active API user')
  if(v.nodeIds.length&&(!admin(actor)||v.purpose!=='mcp'))fail(403,'Only administrators can bind MCP keys to reporting nodes')
  if(v.purpose==='mcp'&&v.access==='write')fail(400,'MCP keys permit reporting only')
  const scopes=v.purpose==='mcp'?['mcp:report']:v.access==='write'?['api:read','api:write']:['api:read']
  db.transaction(()=>{
    let reporterId=null
    if(v.purpose==='mcp'){
      const result=enrollReporter({name:v.name,nodeIds:v.nodeIds,coverage:v.nodeIds.length>1?'collector':'self-reported',actorId:owner.id},actor.id)
      reporterId=result.reporter.id
      // The key is the sole credential for this reporter; do not leave a second enrollment secret active.
      run('UPDATE ai_reporters SET credential_hash=NULL WHERE id=?',reporterId)
    }
    run('INSERT INTO user_api_keys(id,user_id,name,token_hash,prefix,scopes_json,reporter_id,created_at,updated_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)',keyId,owner.id,v.name,hashToken(secret),secret.slice(0,13),JSON.stringify(scopes),reporterId,stamp,stamp,new Date(v.expiresAt).toISOString())
    audit(actor.id,'api-key.create','api-key',keyId,null,{userId:owner.id,name:v.name,scopes,expiresAt:v.expiresAt})
  })()
  return {key:publicKey(ownedKey(actor,keyId)),secret}
}
export function editKey(actor,keyId,input){const before=ownedKey(actor,keyId),v=keyEditSchema.parse(input);run('UPDATE user_api_keys SET name=?,expires_at=?,updated_at=? WHERE id=?',v.name??before.name,v.expiresAt?new Date(v.expiresAt).toISOString():before.expires_at,now(),keyId);audit(actor.id,'api-key.update','api-key',keyId,{name:before.name,expiresAt:before.expires_at},v);return publicKey(ownedKey(actor,keyId))}
export function rotateKey(actor,keyId){const before=ownedKey(actor,keyId);if(before.revoked_at||before.expires_at<=now())fail(409,'Create a new key to replace an expired or revoked key');const secret=newSecret();run('UPDATE user_api_keys SET token_hash=?,prefix=?,updated_at=?,last_used_at=NULL WHERE id=?',hashToken(secret),secret.slice(0,13),now(),keyId);audit(actor.id,'api-key.rotate','api-key',keyId,null,{rotated:true});return {key:publicKey(ownedKey(actor,keyId)),secret}}
export function removeKey(actor,keyId,{revoke=false}={}){const before=ownedKey(actor,keyId);db.transaction(()=>{if(revoke)run('UPDATE user_api_keys SET revoked_at=COALESCE(revoked_at,?),updated_at=? WHERE id=?',now(),now(),keyId);else run('DELETE FROM user_api_keys WHERE id=?',keyId);if(before.reporter_id)run("UPDATE ai_reporters SET status='revoked',credential_hash=NULL,updated_at=? WHERE id=?",now(),before.reporter_id);audit(actor.id,revoke?'api-key.revoke':'api-key.delete','api-key',keyId,{userId:before.user_id,name:before.name,prefix:before.prefix},null)})();return {revoked:true}}
