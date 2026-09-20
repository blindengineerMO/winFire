import {all,one,run,id,now,json,audit} from './db.js'
import {emitNotification} from './notifications.js'

export function createMfaChallenge({nodeId,userUpn,segmentId,connection=null,provider=null,promptId=null,actorId=null,expiresAt=new Date(Date.now()+5*60_000).toISOString()}){
  const challengeId=id()
  run('INSERT INTO mfa_challenges(id,node_id,user_upn,segment_id,connection_5tuple,status,expires_at,provider,prompt_id) VALUES(?,?,?,?,?,?,?,?,?)',challengeId,nodeId,userUpn,segmentId,json(connection),'pending',expiresAt,provider,promptId)
  audit(actorId,'mfa.challenge.create','challenge',challengeId,null,{nodeId,userUpn,segmentId,provider,promptId,expiresAt})
  return challengeId
}

export function resolveMfaChallenge(challengeId,status,{actorId=null,reason=null}={}){
  if(!['approved','denied','expired'].includes(status))throw new Error('Invalid MFA challenge result')
  const challenge=one('SELECT * FROM mfa_challenges WHERE id=?',challengeId)
  if(!challenge||challenge.status!=='pending')return false
  if(status==='approved'&&challenge.expires_at&&challenge.expires_at<=now()){
    resolveMfaChallenge(challengeId,'expired',{actorId,reason:'Challenge expired before approval'})
    return false
  }
  const safeReason=reason?String(reason).slice(0,300):null
  const changed=run("UPDATE mfa_challenges SET status=?,resolved_at=?,failure_reason=? WHERE id=? AND status='pending'",status,now(),safeReason,challengeId)
  if(changed.changes!==1)return false
  audit(actorId,'mfa.challenge.resolve','challenge',challengeId,{status:'pending'},{status,reason:safeReason,provider:challenge.provider,nodeId:challenge.node_id,segmentId:challenge.segment_id})
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
