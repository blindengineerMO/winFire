import {all,one,run,id,now,json,audit} from './db.js'
import {emitNotification} from './notifications.js'

export function createMfaChallenge({nodeId,userUpn,segmentId,connection=null,provider=null,promptId=null,actorId=null,expiresAt=new Date(Date.now()+5*60_000).toISOString()}){
  const challengeId=id()
  run('INSERT INTO mfa_challenges(id,node_id,user_upn,segment_id,connection_5tuple,status,expires_at,provider,prompt_id) VALUES(?,?,?,?,?,?,?,?,?)',challengeId,nodeId,userUpn,segmentId,json(connection),'pending',expiresAt,provider,promptId)
  audit(actorId,'mfa.challenge.create','challenge',challengeId,null,{nodeId,userUpn,segmentId,provider,promptId,expiresAt})
  return challengeId
}

export function markVerifiedAdChallenge(challengeId,user,email,method){
  if(!['ad-session','ldaps-bind'].includes(method)||user?.auth_source!=='ad'||!user.ad_guid)return false
  const challenge=one("SELECT user_upn,status,provider FROM mfa_challenges WHERE id=?",challengeId)
  if(challenge?.status!=='pending'||challenge.provider!=='totp'||challenge.user_upn?.toLowerCase()!==String(email||'').toLowerCase()||user.email?.toLowerCase()!==String(email||'').toLowerCase())return false
  const directoryUser=one('SELECT sid,upn FROM directory_users WHERE id=? AND enabled=1 AND missing=0',user.ad_guid)
  if(!directoryUser||directoryUser.upn?.toLowerCase()!==String(email||'').toLowerCase()||!/^S-1-\d+(?:-\d+)+$/.test(directoryUser.sid||''))return false
  const stamp=now()
  const changed=run("UPDATE mfa_challenges SET verified_account_sid=?,verified_at=?,verified_method=? WHERE id=? AND status='pending' AND verified_account_sid IS NULL",directoryUser.sid,stamp,method,challengeId)
  if(changed.changes!==1)return false
  audit(user.id,'mfa.challenge.ad-identity-verified','challenge',challengeId,null,{accountSid:directoryUser.sid,method})
  return true
}

export function resolveMfaChallenge(challengeId,status,{actorId=null,reason=null,failureKind=null}={}){
  if(!['approved','denied','expired'].includes(status))throw new Error('Invalid MFA challenge result')
  if(failureKind!==null&&!(status==='denied'&&failureKind==='totp'))throw new Error('Invalid MFA challenge failure kind')
  const challenge=one('SELECT * FROM mfa_challenges WHERE id=?',challengeId)
  if(!challenge||challenge.status!=='pending')return false
  if(status==='approved'&&challenge.expires_at&&challenge.expires_at<=now()){
    resolveMfaChallenge(challengeId,'expired',{actorId,reason:'Challenge expired before approval'})
    return false
  }
  const safeReason=reason?String(reason).slice(0,300):null
  const changed=run("UPDATE mfa_challenges SET status=?,resolved_at=?,failure_reason=?,failure_kind=? WHERE id=? AND status='pending'",status,now(),safeReason,failureKind,challengeId)
  if(changed.changes!==1)return false
  audit(actorId,'mfa.challenge.resolve','challenge',challengeId,{status:'pending'},{status,reason:safeReason,failureKind,provider:challenge.provider,nodeId:challenge.node_id,segmentId:challenge.segment_id})
  if(status==='denied'){
    const segmentName=one('SELECT name FROM identity_segments WHERE id=?',challenge.segment_id)?.name||challenge.segment_id
    emitNotification({eventKey:`mfa:${challengeId}`,category:'mfa_challenge_failure',title:'MFA challenge denied',body:`The challenge for ${challenge.user_upn} on segment ${segmentName} was denied.`,entityType:'challenge',entityId:challengeId})
  }
  return true
}

export function expireMfaChallenges(limit=100){
  const due=all("SELECT id FROM mfa_challenges WHERE status='pending' AND expires_at IS NOT NULL AND expires_at<=? ORDER BY expires_at LIMIT ?",now(),limit)
  for(const row of due)resolveMfaChallenge(row.id,'expired',{reason:'Challenge expired before approval'})
  return due.length
}
