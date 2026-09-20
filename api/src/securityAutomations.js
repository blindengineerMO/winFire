import {db,all,one,run,id,now,audit,json} from './db.js'
import {emitNotification} from './notifications.js'
import {writeDirectoryUserStatus} from './directory.js'
import {openSealed} from './security.js'
import {remote} from './connector.js'

const cutoff=minutes=>new Date(Date.now()-minutes*60_000).toISOString()
const safeDestination=value=>String(value||'').trim().toLowerCase()
export function previewSecurityAutomation(policy,{limit=100,offset=0,upperBound=now(),ascending=false}={}){
  const destination=safeDestination(policy.destination)
  if(policy.trigger_type==='destination'){
    if(!destination)return {count:0,items:[]}
    const items=all(`SELECT e.id,e.node_id,e.event_id,e.direction,e.process_id,e.account_sid,e.dst_ip,e.event_time,e.received_at,n.hostname,n.transport
      FROM log_events e JOIN nodes n ON n.id=e.node_id
      WHERE e.received_at>=? AND e.received_at>=? AND e.received_at<=? AND
      (lower(COALESCE(e.dst_ip,''))=? OR EXISTS(SELECT 1 FROM nodes target
        WHERE (lower(target.hostname)=? OR lower(target.fqdn)=?) AND
        lower(COALESCE(e.dst_ip,'')) IN (lower(COALESCE(target.ip,'')),lower(COALESCE(target.fqdn,'')))))
      ORDER BY e.rowid ${ascending?'ASC':'DESC'} LIMIT ? OFFSET ?`,cutoff(policy.window_minutes),policy.created_at||'1970-01-01',upperBound,destination,destination,destination,limit,offset)
    return {count:items.length,items}
  }
  const items=all(`SELECT lower(user_upn) user_upn,COUNT(*) failures,MAX(resolved_at) latest
    FROM mfa_challenges WHERE status='denied' AND resolved_at>=? AND resolved_at>=? AND resolved_at<=?
    AND user_upn IS NOT NULL GROUP BY lower(user_upn) HAVING COUNT(*)>=?
    ORDER BY user_upn ${ascending?'ASC':'DESC'} LIMIT ? OFFSET ?`,cutoff(policy.window_minutes),policy.created_at||'1970-01-01',upperBound,policy.failure_count,limit,offset)
  return {count:items.length,items}
}

function emitIncident(policy,subject,eventRef,detail,status){
  const recent=one('SELECT 1 FROM security_automation_incidents WHERE policy_id=? AND subject_key=? AND created_at>=? LIMIT 1',policy.id,subject,cutoff(policy.cooldown_minutes))
  if(recent)return false
  const incidentId=id()
  run('INSERT OR IGNORE INTO security_automation_incidents(id,policy_id,subject_key,event_ref,status,detail_json,created_at) VALUES(?,?,?,?,?,?,?)',incidentId,policy.id,subject,eventRef,status,json(detail),now())
  if(!one('SELECT 1 FROM security_automation_incidents WHERE id=?',incidentId))return false
  audit(null,'security.automation.triggered','security_automation',policy.id,null,{incidentId,subject,eventRef,status,...detail})
  emitNotification({eventKey:`security-automation:${incidentId}`,category:'security_policy',title:`Security policy: ${policy.name}`,body:`${status}: ${detail.summary}`,entityType:'security_automation',entityId:policy.id})
  return true
}
const coolingDown=(policy,subject)=>!!one('SELECT 1 FROM security_automation_incidents WHERE policy_id=? AND subject_key=? AND created_at>=? LIMIT 1',policy.id,subject,cutoff(policy.cooldown_minutes))

async function disableVerifiedAccount(policy,subject,eventRef,detail,node,event,{logoff=async(target,args)=>remote(target,'security_session_logoff',args)}={}){
  const user=one('SELECT * FROM directory_users WHERE sid=? AND enabled=1 AND missing=0',detail.accountSid)
  if(!user)return emitIncident(policy,subject,eventRef,{...detail,summary:`${detail.summary}. AD action skipped: no enabled directory user matched the Windows SID`},'review')
  if(one("SELECT 1 FROM ad_account_holds WHERE user_guid=? AND status='active'",user.id))return false
  const settings=one("SELECT * FROM directory_connections WHERE id='default'")
  const credential=settings?.action_credential_id?one('SELECT * FROM credentials WHERE id=?',settings.action_credential_id):null
  if(!settings?.enabled||!credential)return emitIncident(policy,subject,eventRef,{...detail,summary:`${detail.summary}. AD action skipped: separate account-control credential is unavailable`},'review')
  audit(null,'security.automation.ad-disable.attempt','directory_user',user.id,null,{policyId:policy.id,eventRef})
  const actionCredential={username:credential.username,password:openSealed(credential.encrypted_blob).password}
  try{
    const result=await writeDirectoryUserStatus(settings,actionCredential,user,false)
    if(!result.changed)throw new Error('AD account state changed before policy action')
    const expiresAt=new Date(Date.now()+policy.disable_minutes*60_000).toISOString()
    try{
      db.transaction(()=>{
        run('UPDATE directory_users SET enabled=0,seen_at=? WHERE id=?',now(),user.id)
        run('INSERT INTO ad_account_holds(id,user_guid,expected_uac,expires_at,status,created_by,created_at) VALUES(?,?,?,?,?,?,?)',id(),user.id,result.afterUac,expiresAt,'active',null,now())
        audit(null,'security.automation.ad-disable.success','directory_user',user.id,{enabled:true,uac:result.beforeUac},{enabled:false,uac:result.afterUac,expiresAt,policyId:policy.id})
      })()
    }catch(error){
      try{await writeDirectoryUserStatus(settings,actionCredential,user,true,{expectedUac:result.afterUac})}
      catch(rollbackError){throw new Error(`AD was disabled but the account hold could not be stored (${error.message}); automatic AD rollback failed (${rollbackError.message}). Immediate manual review is required`)}
      throw new Error(`The account hold could not be stored (${error.message}); AD disable was rolled back`)
    }
    let status='disabled',summary=`${detail.summary}. ${user.sam_account_name} disabled until ${expiresAt}`
    if(policy.action_type==='disable_ad_logoff'){
      try{
        const result=await logoff(node,{processId:event.process_id,eventTime:event.event_time,accountSid:detail.accountSid,sessionId:detail.sessionId})
        if(!result?.loggedOff||result.sessionId!==detail.sessionId)throw new Error('Client did not confirm session logoff')
        status='disabled_and_logged_off';summary+=`; active client session ${detail.sessionId} logged off`
        audit(null,'security.automation.client-logoff.success','node',node.id,null,{policyId:policy.id,sessionId:detail.sessionId,accountSid:detail.accountSid})
      }catch(error){
        status='partial';summary+=`; client logoff failed: ${error.message}`
        audit(null,'security.automation.client-logoff.failed','node',node.id,null,{policyId:policy.id,sessionId:detail.sessionId,error:error.message})
      }
    }
    return emitIncident(policy,subject,eventRef,{...detail,summary},status)
  }catch(error){
    audit(null,'security.automation.ad-disable.failed','directory_user',user.id,null,{policyId:policy.id,eventRef,error:error.message})
    return emitIncident(policy,subject,eventRef,{...detail,summary:`${detail.summary}. AD action failed: ${error.message}`},'failed')
  }
}

export async function processSecurityAutomations({verifyOwner=async(node,event)=>remote(node,'security_process_owner',{processId:event.process_id,eventTime:event.event_time})}={}){
  let triggered=0
  const upperBound=now()
  const verifiedProcesses=new Map()
  for(const policy of all('SELECT * FROM security_automations WHERE enabled=1 ORDER BY created_at')){
    if(policy.trigger_type==='mfa_failures'){
      for(let offset=0;;offset+=500){
      const rows=previewSecurityAutomation(policy,{limit:500,offset,upperBound,ascending:true}).items
      for(const row of rows){
        const latest=one("SELECT id FROM mfa_challenges WHERE status='denied' AND lower(user_upn)=? AND resolved_at=? ORDER BY rowid DESC LIMIT 1",row.user_upn,row.latest)
        if(!latest)continue
        // A challenge's submitted UPN is not proof of identity. Never disable AD from this trigger.
        if(emitIncident(policy,row.user_upn,latest.id,{summary:`${row.failures} failed MFA challenges for ${row.user_upn} in ${policy.window_minutes} minutes`,failures:row.failures},'alert'))triggered++
      }
      if(rows.length<500)break
      }
      continue
    }
    for(let offset=0;;offset+=500){
    const events=previewSecurityAutomation(policy,{limit:500,offset,upperBound,ascending:true}).items
    for(const event of events){
      if(one('SELECT 1 FROM security_automation_incidents WHERE policy_id=? AND event_ref=?',policy.id,event.id))continue
      let owner=null,reviewReason=null
      if(policy.action_type==='disable_ad'){
        if(event.direction!=='out'||![5156,5157,5150,5151].includes(event.event_id))reviewReason='Only a source host outbound WFP event can identify the client user'
        else if(!event.process_id||!event.event_time||!['winrm','winrms'].includes(event.transport))reviewReason='No recent WinRM process evidence is available on the source host'
        else{
          const key=`${event.node_id}:${event.process_id}`
          try{
            if(!verifiedProcesses.has(key))verifiedProcesses.set(key,await verifyOwner(one('SELECT * FROM nodes WHERE id=?',event.node_id),event))
            owner=verifiedProcesses.get(key)
            if(!/^S-1-\d+(?:-\d+)+$/.test(String(owner?.sid||'')))throw new Error('Process owner SID is invalid')
            if(!owner.createdAt||Date.parse(owner.createdAt)>Date.parse(event.event_time)+1000)throw new Error('The process ID was reused after this event')
          }catch(error){reviewReason=`Process owner could not be verified: ${error.message.slice(0,160)}`}
        }
      }
      const subject=policy.action_type==='alert'?(event.account_sid||event.node_id):(owner?.sid||event.node_id)
      if(coolingDown(policy,subject))continue
      const detail={summary:`Destination ${policy.destination} matched traffic on ${event.hostname}`,accountSid:owner?.sid||null,sessionId:owner?.sessionId||null,nodeId:event.node_id,eventId:event.id}
      const fired=policy.action_type!=='alert'&&owner?.sid
        ?await disableVerifiedAccount(policy,subject,event.id,detail,one('SELECT * FROM nodes WHERE id=?',event.node_id),event)
        :emitIncident(policy,subject,event.id,{...detail,summary:policy.action_type!=='alert'?`${detail.summary}. AD action skipped: ${reviewReason||'No verified process owner SID'}`:detail.summary},policy.action_type!=='alert'?'review':'alert')
      if(fired)triggered++
    }
    if(events.length<500)break
    }
  }
  return triggered
}
