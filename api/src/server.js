import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import express from 'express'
import https from 'node:https'
import {app,runVerification,runDriftCheck,pullLogs,finalizeLearning,processDueTraining,syncDirectory} from './app.js'
import {bootstrap} from './security.js'
import {all,one,run,now,audit} from './db.js'
import {agentTlsOptions} from './agentPki.js'
import {sweepAgentHealth} from './agentHealth.js'
import {collectFacts,enrichNode} from './connector.js'

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..')
const dist=path.join(root,'web/dist')
await bootstrap()
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
const timer=setInterval(()=>{
  const retention=Math.max(1,Number(process.env.LOG_RETENTION_DAYS||90))
  run('DELETE FROM log_events WHERE datetime(received_at)<datetime(?)',new Date(Date.now()-retention*864e5).toISOString())
  for(const session of all("SELECT id FROM learning_sessions WHERE status='active' AND ends_at<?",now())){
    try {finalizeLearning(session.id)}
    catch(error){audit(null,'learning.finalize.failed','learning-session',session.id,null,{error:error.message})}
  }
},60*60*1000)
timer.unref()
const agentHealth=setInterval(()=>sweepAgentHealth(),60_000)
agentHealth.unref()
let jobsRunning=false
const jobs=setInterval(async()=>{
  if(jobsRunning)return
  jobsRunning=true
  try {
    for(const node of all("SELECT * FROM nodes WHERE transport IN ('winrm','winrms') AND (next_retry_at IS NULL OR next_retry_at<=?)",now())) {
      try{
        if(node.status==='unreachable')await collectFacts(node)
        await pullLogs(node.id)
      }catch(error){audit(null,'logs.pull.failed','node',node.id,null,{error:error.message})}
    }
    await runVerification()
    await runDriftCheck()
  } catch(error) {console.error('Scheduled checks failed:',error)}
  finally {jobsRunning=false}
},Number(process.env.SWEEP_INTERVAL_MINUTES||60)*60*1000)
jobs.unref()
process.on('SIGTERM',()=>server.close())
