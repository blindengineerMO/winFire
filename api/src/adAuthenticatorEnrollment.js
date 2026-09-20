import crypto from 'node:crypto'
import argon2 from 'argon2'
import {db,one,run,id,now,audit} from './db.js'
import {seal,openSealed,hashToken} from './security.js'
import {makeTotpSecret,matchingTotpCounter} from './totp.js'
import {authenticateDirectoryUser} from './directory.js'

const fail=(message,status)=>Object.assign(new Error(message),{status})
const enrollmentError=()=>fail('Enrollment is invalid or expired; start again',401)

export async function beginAdAuthenticatorEnrollment({settings,email,password,sourceIp,authenticate=authenticateDirectoryUser}){
  const upn=email.trim().toLowerCase()
  await authenticate(settings,upn,password)
  const existing=one('SELECT id,directory_only,totp_secret,suspended FROM users WHERE email=?',upn)
  if(existing?.totp_secret)throw fail('An authenticator is already enrolled for this account; contact an administrator for recovery',409)
  if(existing&&!existing.directory_only)throw fail('This account already has a WinFire profile. Enroll from Administration → Security after signing in',409)
  if(existing?.suspended)throw fail('This account cannot enroll an authenticator',403)
  const secret=makeTotpSecret(),token=crypto.randomBytes(32).toString('base64url')
  const expiresAt=new Date(Date.now()+10*60_000).toISOString()
  db.transaction(()=>{
    run('DELETE FROM ad_authenticator_enrollments WHERE email=? OR expires_at<=?',upn,now())
    run('INSERT INTO ad_authenticator_enrollments(token_hash,email,sealed_secret,source_ip,expires_at) VALUES(?,?,?,?,?)',hashToken(token),upn,seal({secret}),sourceIp,expiresAt)
  })()
  return {token,secret,uri:`otpauth://totp/WinFire:${encodeURIComponent(upn)}?secret=${secret}&issuer=WinFire&algorithm=SHA1&digits=6&period=30`,expiresAt}
}

export async function confirmAdAuthenticatorEnrollment({token,code,sourceIp}){
  const tokenHash=hashToken(token)
  const pending=one('SELECT * FROM ad_authenticator_enrollments WHERE token_hash=?',tokenHash)
  if(!pending||pending.expires_at<=now()||pending.source_ip!==sourceIp||pending.attempts>=5)throw enrollmentError()
  const secret=openSealed(pending.sealed_secret).secret
  const counter=matchingTotpCounter(secret,code)
  if(counter===null){
    run('UPDATE ad_authenticator_enrollments SET attempts=attempts+1 WHERE token_hash=?',tokenHash)
    throw fail('Authenticator code is invalid; use the current six-digit code',401)
  }
  const passwordHash=await argon2.hash(crypto.randomBytes(48).toString('base64url'))
  return db.transaction(()=>{
    if(run('DELETE FROM ad_authenticator_enrollments WHERE token_hash=? AND expires_at>? AND attempts<5',tokenHash,now()).changes!==1)throw enrollmentError()
    let user=one('SELECT * FROM users WHERE email=?',pending.email)
    if(user&&(user.totp_secret||!user.directory_only||user.suspended))throw fail('This account cannot enroll an authenticator',409)
    if(!user){
      const userId=id()
      run('INSERT INTO users(id,email,password_hash,role,email_verified,directory_only,totp_secret) VALUES(?,?,?,\'auditor\',1,1,?)',userId,pending.email,passwordHash,seal({secret}))
      run('INSERT INTO user_profiles(user_id) VALUES(?)',userId)
      user=one('SELECT * FROM users WHERE id=?',userId)
    }else run('UPDATE users SET totp_secret=? WHERE id=?',seal({secret}),user.id)
    run('INSERT INTO mfa_totp_replay(user_id,last_counter) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET last_counter=excluded.last_counter WHERE excluded.last_counter>mfa_totp_replay.last_counter',user.id,counter)
    audit(user.id,'auth.ad_totp.enrolled','user',user.id,null,{email:pending.email})
    return {enrolled:true,email:pending.email}
  })()
}
