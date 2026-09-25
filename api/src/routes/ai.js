import express from 'express'
import {z} from 'zod'
import {auth,requireRole} from '../security.js'
import {one,all,run,audit} from '../db.js'
import {reporterAuth,enrollReporter,editReporter,rotateReporter,revokeReporter,listReporters,settings,saveSettings,heartbeat} from '../ai/reporters.js'
import {ingestBatch,ingestDns} from '../ai/ingestion.js'
import {listRules,saveRule,seedCatalog} from '../ai/catalog.js'
import {listAi,summarizeAi,aiDetails,health,attributionSuggestions,listAiConfiguration} from '../ai/queries.js'
import {resetAiBackfill,pruneAi} from '../ai/observations.js'
import {aiRateLimit,oauthConfig} from '../ai/mcp.js'
export const aiRoutes=express.Router()
const wrap=fn=>(req,res,next)=>Promise.resolve().then(()=>fn(req,res)).catch(next)
const bounded=(req,res,next)=>{if(Buffer.byteLength(JSON.stringify(req.body||{}))>262144)return res.status(413).json({error:'AI payload exceeds 256 KiB',code:'payload_too_large'});next()}
aiRoutes.use(bounded)
const intakeLimit=aiRateLimit({limit:600})
aiRoutes.post('/usage\\:batch',intakeLimit,reporterAuth,aiRateLimit(),(req,res)=>res.json(ingestBatch(req.aiReporter.id,req.body)))
aiRoutes.post('/dns',intakeLimit,reporterAuth,aiRateLimit(),(req,res)=>res.status(201).json(ingestDns(req.aiReporter.id,req.body)))
aiRoutes.post('/heartbeat',intakeLimit,reporterAuth,aiRateLimit(),(req,res)=>res.json(heartbeat(req.aiReporter.id,req.body||{})))
aiRoutes.use(auth,requireRole('auditor'))
for(const [path,kind] of [['usage','usage'],['observations','observations']]){
 aiRoutes.get(`/${path}`,wrap((req,res)=>res.json(listAi(req.query,kind,req.user))))
 aiRoutes.get(`/${path}/summary`,wrap((req,res)=>res.json(summarizeAi(req.query,kind,req.user))))
 aiRoutes.get(`/${path}/export`,wrap((req,res)=>{const result=listAi(req.query,kind,req.user,{exportAll:true});audit(req.user.id,'ai.export','ai-usage',null,null,{kind,count:result.total});res.set('Content-Disposition',`attachment; filename="ai-${path}.json"`).json(result)}))
 aiRoutes.get(`/${path}/:id`,wrap((req,res)=>res.json(aiDetails(req.params.id,kind))))
}
aiRoutes.get('/actors',(_req,res)=>res.json({items:all('SELECT u.id,u.email FROM users u WHERE EXISTS(SELECT 1 FROM ai_reporters r WHERE r.actor_id=u.id) OR EXISTS(SELECT 1 FROM ai_usage_events a WHERE a.actor_id=u.id) ORDER BY u.email LIMIT 1000')}))
aiRoutes.get('/reporters',(req,res)=>res.json(listAiConfiguration(req.query,'reporters')))
aiRoutes.get('/health',(_req,res)=>res.json({...health(),oauth:oauthConfig()}))
aiRoutes.get('/service-rules',(req,res)=>{seedCatalog();res.json(listAiConfiguration(req.query,'rules'))})
aiRoutes.get('/settings',(_req,res)=>res.json(settings()))
aiRoutes.post('/reporters',requireRole('admin'),(req,res)=>res.status(201).json(enrollReporter(req.body,req.user.id)))
aiRoutes.patch('/reporters/:id',requireRole('admin'),(req,res)=>res.json(editReporter(req.params.id,req.body,req.user.id)))
aiRoutes.post('/reporters/:id/rotate',requireRole('admin'),(req,res)=>res.json(rotateReporter(req.params.id,req.user.id)))
aiRoutes.post('/reporters/:id/revoke',requireRole('admin'),(req,res)=>res.json(revokeReporter(req.params.id,req.user.id)))
aiRoutes.get('/reporters/:id/suggestions',requireRole('admin'),(req,res)=>res.json(attributionSuggestions(req.params.id,req.query)))
aiRoutes.post('/service-rules',requireRole('admin'),(req,res)=>res.status(201).json(saveRule(null,req.body,req.user.id)))
aiRoutes.patch('/service-rules/:id',requireRole('admin'),(req,res)=>res.json(saveRule(req.params.id,req.body,req.user.id)))
aiRoutes.patch('/settings',requireRole('admin'),(req,res)=>res.json(saveSettings(req.body,req.user.id)))
aiRoutes.post('/backfill',requireRole('admin'),(req,res)=>{audit(req.user.id,'ai.backfill','ai-usage',null,null,{requested:true});res.status(202).json(resetAiBackfill())})
aiRoutes.post('/purge',requireRole('admin'),(req,res)=>{const result=pruneAi();audit(req.user.id,'ai.retention.purge','ai-usage',null,null,result);res.json(result)})
aiRoutes.use((error,req,res,_next)=>{const schema=error instanceof z.ZodError;const code=schema?'invalid_request_schema':error.code?.startsWith('SQLITE_CONSTRAINT')?'conflicting_record':error.code||'ai_request_failed';const status=schema?400:code==='conflicting_record'?409:error.status||500;if(status===500)run('UPDATE ai_worker_state SET last_error=? WHERE id=1','request_failed');res.status(status).json({error:code.replaceAll('_',' '),code})})
export const nodeAiUsage=(req,res,next)=>{try{if(!one('SELECT id FROM nodes WHERE id=?',req.params.id))return res.status(404).json({error:'Node not found'});const input={...req.query,nodeId:req.params.id};res.json({reported:listAi(input,'usage',req.user),observations:listAi(input,'observations',req.user)})}catch(e){next(e)}}
