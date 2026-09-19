import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import express from 'express'
import https from 'node:https'
import {app,runVerification,runDriftCheck,pullLogs,finalizeLearning} from './app.js'
import {bootstrap} from './security.js'
import {all,run,now,audit} from './db.js'
import {agentTlsOptions} from './agentPki.js'
import {sweepAgentHealth} from './agentHealth.js'
import {collectFacts} from './connector.js'

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
