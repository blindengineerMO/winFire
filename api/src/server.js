import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import express from 'express'
import https from 'node:https'
import {app,runVerification,runDriftCheck,pullLogs,pullRecentLogs,processDueTraining,processDueBreakGlass,processDuePolicySync,processDueAdAccountHolds,syncDirectory} from './app.js'
import {bootstrap,ensureBootstrapAdmin} from './security.js'
import {all,one,run,now,audit} from './db.js'
import {agentTlsOptions} from './agentPki.js'
import {sweepAgentHealth} from './agentHealth.js'
import {collectFacts,enrichNode} from './connector.js'
import {pruneOldEvents,refreshDueDns,runCompactionIfDue} from './maintenance.js'
import {deliverPendingNotifications} from './notifications.js'
import {sweepLoopbackBaseline} from './loopbackBaseline.js'
import {revokeExpiredGrants} from './mfaPortal.js'
import {sweepMfaPrompts} from './mfaPrompt.js'
import {expireMfaChallenges} from './mfaChallenges.js'

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..')
const dist=path.join(root,'web/dist')
await bootstrap()
await ensureBootstrapAdmin()
if(fs.existsSync(dist)){
  app.use(express.static(dist))
  app.get(/^(?!\/api\/).*/,(_req,res)=>res.sendFile(path.join(dist,'index.html')))
}
const tlsSettings=['TLS_CERT','TLS_KEY','AGENT_CA_CERT','AGENT_CA_KEY'].map(name=>process.env[name])
if(tlsSettings.some(Boolean)&&!tlsSettings.every(Boolean))throw new Error('TLS_CERT, TLS_KEY, AGENT_CA_CERT and AGENT_CA_KEY must be configured together')
const tls=agentTlsOptions()
const server=tls?https.createServer(tls,app):app
server.listen(Number(process.env.PORT||3000),process.env.HOST||'0.0.0.0',()=>console.log(`WinFire ready on ${tls?'https':'http'}://localhost:${process.env.PORT||3000}`))
let trainingRunning=false
async function sweepTraining(){
  if(trainingRunning)return
  trainingRunning=true
  try{await processDueTraining()}
  catch(error){console.error('Training sweep failed:',error)}
  finally{trainingRunning=false}
}
setTimeout(sweepTraining,1000).unref()
const trainingTimer=setInterval(sweepTraining,Math.max(1,Number(process.env.TRAINING_SWEEP_INTERVAL_MINUTES||5))*60*1000)
trainingTimer.unref()
let breakGlassRunning=false
async function sweepBreakGlass(){
  if(breakGlassRunning)return
  breakGlassRunning=true
  try{await processDueBreakGlass()}
  catch(error){console.error('Break-glass sweep failed:',error)}
  finally{breakGlassRunning=false}
}
setTimeout(sweepBreakGlass,1000).unref()
const breakGlassTimer=setInterval(sweepBreakGlass,60_000)
breakGlassTimer.unref()
setTimeout(()=>processDuePolicySync().catch(error=>console.error('Policy sync sweep failed:',error)),1500).unref()
const policySyncTimer=setInterval(()=>processDuePolicySync().catch(error=>console.error('Policy sync sweep failed:',error)),60_000)
policySyncTimer.unref()
setTimeout(()=>sweepLoopbackBaseline().catch(error=>console.error('Loopback baseline sweep failed:',error)),3000).unref()
const loopbackTimer=setInterval(()=>sweepLoopbackBaseline().catch(error=>console.error('Loopback baseline sweep failed:',error)),60_000)
loopbackTimer.unref()
setTimeout(()=>revokeExpiredGrants().catch(error=>console.error('MFA grant expiry sweep failed:',error)),4000).unref()
const grantTimer=setInterval(()=>revokeExpiredGrants().catch(error=>console.error('MFA grant expiry sweep failed:',error)),60_000)
grantTimer.unref()
let mfaPollRunning=false,mfaPollCursor=0
async function pollMfaEvents(){
  if(mfaPollRunning)return
  mfaPollRunning=true
  try{
    const targets=all(`SELECT DISTINCT n.id FROM nodes n JOIN identity_segments s ON (s.node_id=n.id OR s.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id))
      WHERE s.portal_enabled=1 AND s.auto_prompt_enabled=1 AND s.mode='agentless' AND n.connection_mode='agentless' AND n.transport IN ('winrm','winrms') AND n.firewall_state<>'learning'
        AND (n.next_retry_at IS NULL OR n.next_retry_at<=?) ORDER BY n.id`,now())
    const batch=targets.length?Array.from({length:Math.min(targets.length,5)},(_,index)=>targets[(mfaPollCursor+index)%targets.length]):[]
    mfaPollCursor=targets.length?(mfaPollCursor+batch.length)%targets.length:0
    await Promise.all(batch.map(async target=>{try{await pullRecentLogs(target.id,null,true)}catch(error){console.error(`MFA event poll failed for ${target.id}:`,error.message)}}))
    await sweepMfaPrompts()
  }catch(error){console.error('MFA prompt sweep failed:',error)}
  finally{mfaPollRunning=false}
}
setTimeout(pollMfaEvents,15_000).unref()
const mfaPollTimer=setInterval(pollMfaEvents,Math.max(15,Number(process.env.MFA_EVENT_POLL_SECONDS||30))*1000)
mfaPollTimer.unref()
let inventoryRunning=false
async function sweepNewNodes(){
  if(inventoryRunning)return
  inventoryRunning=true
  try{
    const pending=all(`SELECT n.* FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id WHERE f.node_id IS NULL AND n.connection_mode='agentless' AND COALESCE(n.ad_enabled,1)=1 AND (n.next_retry_at IS NULL OR n.next_retry_at<=?) AND EXISTS (SELECT 1 FROM credential_assignments a WHERE a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id)) ORDER BY n.created_at LIMIT 5`,now())
    for(const node of pending){
      try{await enrichNode(node);audit(null,'node.inventory.collected','node',node.id,null,{transport:one('SELECT transport FROM nodes WHERE id=?',node.id)?.transport||null})}
      catch(error){run('UPDATE nodes SET next_retry_at=? WHERE id=?',new Date(Date.now()+15*60*1000).toISOString(),node.id);audit(null,'node.inventory.failed','node',node.id,null,{error:error.message})}
    }
  }catch(error){console.error('Node inventory sweep failed:',error)}
  finally{inventoryRunning=false}
}
setTimeout(sweepNewNodes,1000).unref()
const inventoryTimer=setInterval(sweepNewNodes,60_000)
inventoryTimer.unref()
let directoryRunning=false
async function sweepDirectory(){
  if(directoryRunning)return
  const settings=one("SELECT enabled,sync_interval_minutes,last_sync_attempt_at FROM directory_connections WHERE id='default'")
  if(!settings?.enabled||settings.last_sync_attempt_at&&Date.parse(settings.last_sync_attempt_at)>Date.now()-settings.sync_interval_minutes*60_000)return
  directoryRunning=true
  try{await syncDirectory()}
  catch(error){console.error('Directory sync failed:',error.message)}
  finally{directoryRunning=false}
}
setTimeout(sweepDirectory,2000).unref()
const directoryTimer=setInterval(sweepDirectory,5*60_000)
directoryTimer.unref()
setTimeout(()=>processDueAdAccountHolds().catch(error=>console.error('AD account hold sweep failed:',error)),10_000).unref()
const adHoldTimer=setInterval(()=>processDueAdAccountHolds().catch(error=>console.error('AD account hold sweep failed:',error)),60_000)
adHoldTimer.unref()
let dnsRunning=false
async function sweepDns(){
  if(dnsRunning)return
  dnsRunning=true
  try{await refreshDueDns()}
  catch(error){console.error('DNS refresh sweep failed:',error)}
  finally{dnsRunning=false}
}
setTimeout(sweepDns,5000).unref()
const dnsTimer=setInterval(sweepDns,15*60_000)
dnsTimer.unref()
const compactionTimer=setInterval(()=>runCompactionIfDue(),5*60*1000)
compactionTimer.unref()
setTimeout(()=>runCompactionIfDue(),10_000).unref()
const timer=setInterval(()=>{pruneOldEvents();run('DELETE FROM mfa_entra_flows WHERE expires_at<?',now());run("DELETE FROM mfa_prompt_events WHERE datetime(created_at)<datetime('now','-7 days')")},60*60*1000)
timer.unref()
setTimeout(()=>expireMfaChallenges(),10_000).unref()
const challengeTimer=setInterval(()=>expireMfaChallenges(),60_000)
challengeTimer.unref()
const agentHealth=setInterval(()=>sweepAgentHealth(),60_000)
agentHealth.unref()
let notificationsRunning=false
const notificationTimer=setInterval(async()=>{
  if(notificationsRunning)return
  notificationsRunning=true
  try{await deliverPendingNotifications()}
  catch(error){console.error('Notification delivery failed:',error)}
  finally{notificationsRunning=false}
},30_000)
notificationTimer.unref()
let jobsRunning=false
let logPollRunning=false
async function pollNodeLogs(){
  if(logPollRunning)return
  logPollRunning=true
  try{
    for(const node of all("SELECT id,hostname FROM nodes WHERE transport IN ('winrm','winrms') AND (next_retry_at IS NULL OR next_retry_at<=?) ORDER BY hostname",now())){
      try{
        await pullRecentLogs(node.id,null,true)
        await pullLogs(node.id,null,5,true)
      }catch(error){
        audit(null,'logs.pull.failed','node',node.id,null,{error:error.message})
        console.error(`Event collection failed for ${node.hostname}:`,error.message)
      }
    }
  }finally{logPollRunning=false}
}
setTimeout(()=>pollNodeLogs().catch(error=>console.error('Event collection failed:',error)),5000).unref()
const logPollTimer=setInterval(()=>pollNodeLogs().catch(error=>console.error('Event collection failed:',error)),Math.max(30,Number(process.env.LOG_POLL_INTERVAL_SECONDS||120))*1000)
logPollTimer.unref()
const jobs=setInterval(async()=>{
  if(jobsRunning)return
  jobsRunning=true
  try {
    for(const node of all("SELECT * FROM nodes WHERE transport IN ('winrm','winrms') AND (next_retry_at IS NULL OR next_retry_at<=?)",now())) {
      try{
        if(node.status==='unreachable')await collectFacts(node)
      }catch(error){audit(null,'logs.pull.failed','node',node.id,null,{error:error.message})}
    }
    await runVerification()
    await runDriftCheck()
  } catch(error) {console.error('Scheduled checks failed:',error)}
  finally {jobsRunning=false}
},Number(process.env.SWEEP_INTERVAL_MINUTES||60)*60*1000)
jobs.unref()
process.on('SIGTERM',()=>server.close())
