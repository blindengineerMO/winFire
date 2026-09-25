import fs from 'node:fs'
import os from 'node:os'
import express from 'express'
import {fileURLToPath} from 'node:url'
const root=fileURLToPath(new URL('..',import.meta.url))
process.chdir(root)
process.env.DATA_DIR=fs.mkdtempSync(os.tmpdir()+'/winfire-ai-ui-');process.env.NODE_ENV='test';process.env.BOOTSTRAP_EMAIL='ai-ui@example.test';process.env.BOOTSTRAP_PASSWORD='Ui-test-only-123'
const {app}=await import('../api/src/app.js'),{bootstrap}=await import('../api/src/security.js'),{db,run,one}=await import('../api/src/db.js'),{enrollReporter}=await import('../api/src/ai/reporters.js'),{ingestBatch}=await import('../api/src/ai/ingestion.js'),{seedCatalog,matchService}=await import('../api/src/ai/catalog.js'),{retainObservation}=await import('../api/src/ai/observations.js')
await bootstrap();run("INSERT INTO nodes(id,hostname,ip) VALUES('ui-ai-node','AI workstation','192.168.88.22')")
const reporter=enrollReporter({name:'Instrumented research worker',nodeIds:['ui-ai-node'],coverage:'instrumented'},null)
const events=Array.from({length:30},(_,i)=>({schemaVersion:1,eventId:'ui-event-'+i,operation:i%2?'search':'model_request',provider:'anthropic',model:'fixture-model',hostname:'api.anthropic.com',observedAt:new Date(Date.now()-i*1000).toISOString(),inputTokens:100,outputTokens:50,traceId:'ui-trace-'+i,outcome:i===1?'failure':'success'}));ingestBatch(reporter.reporter.id,{events});seedCatalog()
retainObservation({source:'fixture',source_id:'ui-source',node_id:'ui-ai-node',observed_at:new Date().toISOString(),hostname:'api.anthropic.com',trace_id:'ui-trace-0',rule:matchService('api.anthropic.com'),category:'observed',confidence:'high',action:'allow',evidence:{reason:'Controlled fixture: explicit requested host'}})
app.use(express.static(root+'/web/dist'));app.get('/{*path}',(_req,res)=>res.sendFile(root+'/web/dist/index.html'))
const server=app.listen(Number(process.env.AI_UI_PORT||3318),'127.0.0.1',()=>console.log('AI isolated UI fixture ready'))
process.on('SIGTERM',()=>server.close(()=>{db.close();fs.rmSync(process.env.DATA_DIR,{recursive:true,force:true});process.exit(0)}))
