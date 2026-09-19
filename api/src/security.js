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
const rank = {auditor:0,editor:1,admin:2,owner:3}
export const requireRole = role => (req,res,next) => rank[req.user?.role] >= rank[role] ? next() : res.status(403).json({error:'Insufficient permission'})
