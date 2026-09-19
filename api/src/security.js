import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import argon2 from 'argon2'
import jwt from 'jsonwebtoken'
import {db, one, run, id, now, audit} from './db.js'

const dataDir = path.resolve(process.env.DATA_DIR || 'data')
const secretsPath = path.join(dataDir, 'secrets.json')
let stored = {}
if (fs.existsSync(secretsPath)) stored = JSON.parse(fs.readFileSync(secretsPath, 'utf8'))
else {
  stored = {jwt:crypto.randomBytes(32).toString('base64url'), vault:crypto.randomBytes(32).toString('base64')}
  fs.writeFileSync(secretsPath, JSON.stringify(stored), {mode:0o600})
}
const jwtSecret = process.env.JWT_SECRET || stored.jwt
const masterKey = Buffer.from(process.env.VAULT_MASTER_KEY || stored.vault, 'base64')
if (masterKey.length !== 32) throw new Error('VAULT_MASTER_KEY must decode to 32 bytes')

export function seal(value) {
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()])
  const wrapIv = crypto.randomBytes(12), wrap = crypto.createCipheriv('aes-256-gcm', masterKey, wrapIv)
  const wrapped = Buffer.concat([wrap.update(key), wrap.final()])
  return JSON.stringify({v:1, iv:iv.toString('base64'), tag:cipher.getAuthTag().toString('base64'), data:ciphertext.toString('base64'), wrapIv:wrapIv.toString('base64'), wrapTag:wrap.getAuthTag().toString('base64'), key:wrapped.toString('base64')})
}
export function openSealed(value) {
  const blob = JSON.parse(value), unwrap = crypto.createDecipheriv('aes-256-gcm', masterKey, Buffer.from(blob.wrapIv,'base64'))
  unwrap.setAuthTag(Buffer.from(blob.wrapTag,'base64'))
  const key = Buffer.concat([unwrap.update(Buffer.from(blob.key,'base64')),unwrap.final()])
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(blob.iv,'base64'))
  decipher.setAuthTag(Buffer.from(blob.tag,'base64'))
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(blob.data,'base64')),decipher.final()]).toString())
}
export const hashToken = token => crypto.createHash('sha256').update(token).digest('hex')
export async function bootstrap() {
  if (one('SELECT id FROM users LIMIT 1')) return
  const email = process.env.BOOTSTRAP_EMAIL || 'owner@winfire.local'
  const password = process.env.BOOTSTRAP_PASSWORD || crypto.randomBytes(18).toString('base64url')
  const uid = id()
  run('INSERT INTO users(id,email,password_hash,role,email_verified) VALUES(?,?,?,?,1)', uid,email.toLowerCase(),await argon2.hash(password),'owner')
  run('INSERT INTO user_profiles(user_id) VALUES(?)',uid)
  console.log(`WinFire first login: ${email} / ${password}`)
  console.log('Set BOOTSTRAP_EMAIL and BOOTSTRAP_PASSWORD before first start to choose your own credentials.')
}
export async function ensureBootstrapAdmin() {
  const marker=one("SELECT user_id FROM bootstrap_accounts WHERE kind='demo-admin'")
  const enabled=!['0','false','no'].includes(String(process.env.BOOTSTRAP_ADMIN_ENABLED??(process.env.NODE_ENV==='production'?'false':'true')).toLowerCase())
  if(!enabled){
    if(marker){
      const user=one('SELECT id,suspended FROM users WHERE id=?',marker.user_id)
      if(user&&!user.suspended)db.transaction(()=>{
        run('UPDATE users SET suspended=1,session_version=session_version+1 WHERE id=?',user.id)
        run('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL',now(),user.id)
        audit(null,'bootstrap.admin.disabled','user',user.id,null,null)
      })()
    }
    return
  }
  const email=String(process.env.BOOTSTRAP_ADMIN_EMAIL||'admin@winfire.local').trim().toLowerCase()
  const password=process.env.BOOTSTRAP_ADMIN_PASSWORD||'WinFireDemo!2026'
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))throw new Error('BOOTSTRAP_ADMIN_EMAIL must be a valid email address')
  if(password.length<12)throw new Error('BOOTSTRAP_ADMIN_PASSWORD must contain at least 12 characters')
  const user=marker?one('SELECT * FROM users WHERE id=?',marker.user_id):null
  if(!user){
    if(one('SELECT id FROM users WHERE email=?',email))throw new Error('BOOTSTRAP_ADMIN_EMAIL is already used by another account')
    const userId=id(),passwordHash=await argon2.hash(password)
    db.transaction(()=>{
      run('INSERT INTO users(id,email,password_hash,role,email_verified) VALUES(?,?,?,?,1)',userId,email,passwordHash,'admin')
      run("INSERT INTO user_profiles(user_id,theme) VALUES(?,'enterprise')",userId)
      run('INSERT INTO bootstrap_accounts(kind,user_id) VALUES(?,?)','demo-admin',userId)
      audit(null,'bootstrap.admin.created','user',userId,null,{email,role:'admin'})
    })()
  }else{
    const conflict=one('SELECT id FROM users WHERE email=? AND id<>?',email,user.id)
    if(conflict)throw new Error('BOOTSTRAP_ADMIN_EMAIL is already used by another account')
    const passwordMatches=await argon2.verify(user.password_hash,password)
    const changed=!passwordMatches||user.email!==email||user.role!=='admin'||!!user.suspended||!!user.totp_secret||!user.email_verified
    if(changed){
      const passwordHash=passwordMatches?user.password_hash:await argon2.hash(password)
      db.transaction(()=>{
        run('UPDATE users SET email=?,password_hash=?,role=?,suspended=0,totp_secret=NULL,email_verified=1,failed_attempts=0,locked_until=NULL,session_version=session_version+1 WHERE id=?',email,passwordHash,'admin',user.id)
        run('UPDATE refresh_tokens SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL',now(),user.id)
        audit(null,'bootstrap.admin.reconciled','user',user.id,{email:user.email,role:user.role},{email,role:'admin',passwordChanged:!passwordMatches})
      })()
    }
  }
  console.log(`Demo admin ready: ${email}. Set BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_PASSWORD, or BOOTSTRAP_ADMIN_ENABLED to change it.`)
}
export function issueAccess(user) { return jwt.sign({sub:user.id,role:user.role,sv:user.session_version},jwtSecret,{expiresIn:'15m',issuer:'winfire'}) }
export function verifyAccess(token) { return jwt.verify(token,jwtSecret,{issuer:'winfire'}) }
export function issueRefresh(userId) {
  const token = crypto.randomBytes(48).toString('base64url'), tokenId = id()
  run('INSERT INTO refresh_tokens(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)',tokenId,userId,hashToken(token),new Date(Date.now()+30*864e5).toISOString())
  return token
}
export function rotateRefresh(token) {
  return db.transaction(() => {
    const row = one('SELECT * FROM refresh_tokens WHERE token_hash=?',hashToken(token || ''))
    if (!row || row.revoked_at || row.expires_at <= now()) return null
    const user = one('SELECT * FROM users WHERE id=? AND suspended=0',row.user_id)
    if (!user) return null
    const consumed=run('UPDATE refresh_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL',now(),row.id)
    if(consumed.changes!==1)return null
    audit(user.id,'auth.refresh','user',user.id,null,null)
    return {accessToken:issueAccess(user),refreshToken:issueRefresh(user.id),user:publicUser(user)}
  })()
}
export const publicUser = user => ({id:user.id,email:user.email,role:user.role,teamId:user.team_id,suspended:!!user.suspended})
export function auth(req,res,next) {
  const token = req.headers.authorization?.replace(/^Bearer /i,'')
  if (!token) return res.status(401).json({error:'Authentication required'})
  try {
    const payload = verifyAccess(token)
    const user = one('SELECT * FROM users WHERE id=? AND suspended=0',payload.sub)
    if (!user || user.session_version!==payload.sv) return res.status(401).json({error:'Session revoked'})
    req.user = user; next()
  } catch { res.status(401).json({error:'Invalid or expired token'}) }
}
const rolePermission={auditor:'portal.read',editor:'portal.edit',admin:'portal.admin',owner:'portal.owner'}
export const requireRole = role => (req,res,next) => one('SELECT 1 FROM role_permissions WHERE role_id=? AND permission_id=?',req.user?.role||'',rolePermission[role]||'') ? next() : res.status(403).json({error:'Insufficient permission'})
