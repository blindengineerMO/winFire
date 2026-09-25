import crypto from 'node:crypto'
import {one,run,now} from './db.js'
export const isUserApiKey=token=>typeof token==='string'&&token.startsWith('wfuk_')
export function authenticateApiKey(token,scope){
  const reject=(status,message)=>{throw Object.assign(new Error(message),{status})}
  if(!/^wfuk_[A-Za-z0-9_-]{43}$/.test(token||''))reject(401,'Invalid API key')
  const key=one('SELECT * FROM user_api_keys WHERE token_hash=?',crypto.createHash('sha256').update(token).digest('hex'))
  if(!key||key.revoked_at||key.expires_at<=now())reject(401,'Invalid, expired or revoked API key')
  const user=one('SELECT * FROM users WHERE id=? AND suspended=0',key.user_id)
  if(!user||user.directory_only||user.auth_source==='ad'&&!one('SELECT 1 FROM directory_users WHERE id=? AND enabled=1 AND missing=0',user.ad_guid))reject(401,'API key owner is inactive')
  const scopes=JSON.parse(key.scopes_json)
  if(!scopes.includes(scope))reject(403,'API key does not permit this operation')
  if(scope==='mcp:report'&&(!key.reporter_id||!one("SELECT id FROM ai_reporters WHERE id=? AND status='active'",key.reporter_id)))reject(401,'MCP reporting identity is revoked')
  if(!key.last_used_at||Date.now()-Date.parse(key.last_used_at)>60000)run('UPDATE user_api_keys SET last_used_at=? WHERE id=?',now(),key.id)
  return {key,user,scopes}
}
