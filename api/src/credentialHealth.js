import {all,one,run,now,audit} from './db.js'
import {classifyOnboardingError} from './onboardingErrors.js'

const windowMinutes=()=>Math.max(5,Number(process.env.CREDENTIAL_ROTATION_FAILURE_WINDOW_MINUTES||30))
const threshold=()=>Math.max(2,Number(process.env.CREDENTIAL_ROTATION_FAILURE_THRESHOLD||3))
const cutoff=()=>new Date(Date.now()-windowMinutes()*60_000).toISOString()

const credentialName=credentialId=>one('SELECT name FROM credentials WHERE id=?',credentialId)?.name||'credential'
const noticeFor=(credentialId,rows=all(`SELECT h.*,n.hostname,n.ip,n.fqdn FROM credential_auth_health h JOIN nodes n ON n.id=h.node_id WHERE h.credential_id=? AND h.failure_code='auth_rejected' AND h.last_auth_failure_at>=? AND h.last_success_at IS NOT NULL ORDER BY h.last_auth_failure_at`,credentialId,cutoff()))=>{
  const affected=rows.filter(row=>row.last_auth_failure_at).map(row=>({id:row.node_id,hostname:row.hostname,address:row.ip||row.fqdn||null,lastFailureAt:row.last_auth_failure_at}))
  if(affected.length<threshold())return null
  return {code:'credential_may_be_stale',title:'Credential may be stale',credentialId,credentialName:credentialName(credentialId),affectedNodeCount:affected.length,affectedNodes:affected,windowMinutes:windowMinutes(),firstFailureAt:affected[0].lastFailureAt,lastFailureAt:affected.at(-1).lastFailureAt,summary:`${credentialName(credentialId)} failed authentication on ${affected.length} previously authenticated nodes within ${windowMinutes()} minutes.`,remediation:'Verify or rotate this vault credential, then retry the affected nodes.'}
}

export function recordCredentialAuthSuccess({credentialId,nodeId,transport}={}) {
  if(!credentialId||!nodeId)return
  const timestamp=now()
  run(`INSERT INTO credential_auth_health(credential_id,node_id,last_success_at,last_success_transport,last_auth_failure_at,failure_code,failure_count)
    VALUES(?,?,?, ?,NULL,NULL,0)
    ON CONFLICT(credential_id,node_id) DO UPDATE SET last_success_at=excluded.last_success_at,last_success_transport=excluded.last_success_transport,last_auth_failure_at=NULL,failure_code=NULL,failure_count=0`,credentialId,nodeId,timestamp,transport||null)
}

export function recordCredentialAuthFailure({credentialId,nodeId,error,transport,operation}={}) {
  if(!credentialId||!nodeId)return null
  const classified=error?.onboardingError||classifyOnboardingError(error,{operation,transport})
  const message=String(error?.message||error||'')
  const snmpAuthFailure=transport==='snmp'&&/authorizationerror|authentication(?: failure|failed)|unknown user|wrong digest|bad community|usm.*(?:auth|priv)/i.test(message)
  if(classified.code!=='auth_rejected'&&!snmpAuthFailure)return null
  const prior=one('SELECT * FROM credential_auth_health WHERE credential_id=? AND node_id=?',credentialId,nodeId)
  if(!prior?.last_success_at)return null
  const before=all(`SELECT node_id FROM credential_auth_health WHERE credential_id=? AND failure_code='auth_rejected' AND last_auth_failure_at>=? AND last_success_at IS NOT NULL`,credentialId,cutoff()).length
  const timestamp=now()
  run(`UPDATE credential_auth_health SET last_auth_failure_at=?,failure_code='auth_rejected',failure_count=failure_count+1,last_success_transport=COALESCE(last_success_transport,?) WHERE credential_id=? AND node_id=?`,timestamp,transport||null,credentialId,nodeId)
  const notice=noticeFor(credentialId)
  if(notice&&before<threshold())audit(null,'credential.stale.detected','credential',credentialId,{affectedNodeCount:before},{affectedNodeCount:notice.affectedNodeCount,windowMinutes:notice.windowMinutes,code:notice.code})
  return notice
}

export function activeCredentialStaleNotices() {
  const ids=all(`SELECT DISTINCT credential_id FROM credential_auth_health WHERE failure_code='auth_rejected' AND last_auth_failure_at>=? AND last_success_at IS NOT NULL`,cutoff()).map(row=>row.credential_id)
  return ids.map(credentialId=>noticeFor(credentialId)).filter(Boolean)
}

export const credentialHealthConfig=()=>({windowMinutes:windowMinutes(),threshold:threshold()})
