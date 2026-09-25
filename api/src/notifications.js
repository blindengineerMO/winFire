import {deliverServiceNow} from './services/servicenow.js'
import {db,all,one,run,id,now,parse,json} from './db.js'
import {deliverAlert} from './mailer.js'

export const categories=['policy_drift','verifier_failure','mfa_access_request','mfa_challenge_failure','agent_offline','node_unreachable','security_policy','ddos_attack']
export const channels=['in_app','email','webhook','servicenow']
export const preferenceKeys=categories.flatMap(category=>channels.map(channel=>`${category}.${channel}`))

function enabled(preferences,category,channel){
  const value=preferences?.[`${category}.${channel}`]
  return value===undefined?channel==='in_app':value===true
}

export function emitNotification({eventKey,category,title,body,entityType=null,entityId=null,recipientEmails=null}){
  if(!categories.includes(category))throw new Error('Unknown notification category')
  if(!eventKey||!title||!body)throw new Error('Notification event key, title and body are required')
  const allowed=recipientEmails?new Set(recipientEmails.map(value=>String(value).toLowerCase())):null
  const recipients=all('SELECT u.id,u.email,u.email_verified,p.notification_prefs FROM users u LEFT JOIN user_profiles p ON p.user_id=u.id WHERE u.suspended=0').filter(user=>!allowed||allowed.has(user.email.toLowerCase()))
  db.transaction(()=>{
    for(const user of recipients){
      const preferences=parse(user.notification_prefs)||{}
      if(enabled(preferences,category,'in_app'))run('INSERT OR IGNORE INTO notifications(id,user_id,event_key,category,title,body,entity_type,entity_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)',id(),user.id,eventKey,category,title,body,entityType,entityId,now())
      for(const channel of ['email','webhook','servicenow']){
        if(!enabled(preferences,category,channel))continue
        if(channel==='email'&&!user.email_verified)continue
        run('INSERT OR IGNORE INTO notification_deliveries(id,user_id,event_key,category,channel,recipient_email,title,body,status,next_attempt_at) VALUES(?,?,?,?,?,?,?,?,?,?)',id(),user.id,eventKey,category,channel,channel==='email'?user.email:null,title,body,'pending',now())
      }
    }
  })()
  return recipients.length
}

function webhookUrl(){
  if(!process.env.NOTIFICATION_WEBHOOK_URL)return null
  const target=new URL(process.env.NOTIFICATION_WEBHOOK_URL)
  if(target.protocol!=='https:')throw new Error('NOTIFICATION_WEBHOOK_URL must use HTTPS')
  return target
}

export async function deliverPendingNotifications(limit=25){
  const due=all("SELECT d.*,u.email,u.email_verified,u.suspended FROM notification_deliveries d JOIN users u ON u.id=d.user_id WHERE d.status='pending' AND d.next_attempt_at<=? ORDER BY d.next_attempt_at LIMIT ?",now(),limit)
  for(const item of due){
    if(item.suspended){run("UPDATE notification_deliveries SET status='cancelled' WHERE id=?",item.id);continue}
    if(item.channel==='email'&&(!item.email_verified||item.recipient_email!==item.email)){run("UPDATE notification_deliveries SET status='cancelled' WHERE id=?",item.id);continue}
    try{
      if(item.channel==='email'){
        if(!process.env.SMTP_HOST)continue
        await deliverAlert(item.recipient_email,item.title,item.body)
      }else if(item.channel==='servicenow'){
        if(!await deliverServiceNow(item))continue
      }else{
        const target=webhookUrl()
        if(!target)continue
        const response=await fetch(target,{method:'POST',headers:{'content-type':'application/json'},body:json({id:item.id,eventKey:item.event_key,category:item.category,userId:item.user_id,title:item.title,body:item.body}),redirect:'error',signal:AbortSignal.timeout(10_000)})
        if(!response.ok)throw new Error(`Webhook returned HTTP ${response.status}`)
      }
      run("UPDATE notification_deliveries SET status='sent',sent_at=?,last_error=NULL WHERE id=?",now(),item.id)
    }catch(error){
      const attempts=item.attempts+1
      run('UPDATE notification_deliveries SET status=?,attempts=?,next_attempt_at=?,last_error=? WHERE id=?',attempts>=5?'failed':'pending',attempts,new Date(Date.now()+Math.min(60,2**attempts)*60_000).toISOString(),(item.channel==='servicenow'&&!String(error.message).startsWith('ServiceNow')?'ServiceNow connection failed; check DNS, TLS and connectivity':String(error.message).slice(0,500)),item.id)
    }
  }
  return due.length
}

export function notificationSummary(userId){
  return {unread:one('SELECT COUNT(*) AS count FROM notifications WHERE user_id=? AND read_at IS NULL',userId).count,items:all('SELECT id,event_key,category,title,body,entity_type,entity_id,created_at,read_at FROM notifications WHERE user_id=? ORDER BY created_at DESC,rowid DESC LIMIT 50',userId)}
}
