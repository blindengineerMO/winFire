import {Router} from 'express'
import {requireRole} from '../security.js'
import {all,run,one,audit,now} from '../db.js'
import {serviceNowSettings,saveServiceNow,testServiceNow,serviceNowDeliveries} from '../services/servicenow.js'
import {ddosPolicies,saveDdosPolicy,deleteDdosPolicy,ddosIncidents,ddosIncident,releaseDdosIncident,ddosEvidence} from '../services/ddos.js'
export const protectionRoutes=Router()
const r=protectionRoutes;r.use(['/notifications/servicenow','/protection/ddos'],requireRole('admin'))
r.get('/notifications/servicenow',(req,res)=>res.json({settings:serviceNowSettings(),credentials:all("SELECT id,name,username FROM credentials WHERE type='servicenow' ORDER BY name")}))
r.put('/notifications/servicenow',(req,res)=>res.json(saveServiceNow(req.body,req.user.id)))
r.post('/notifications/servicenow/test',async(req,res)=>{const result=await testServiceNow();audit(req.user.id,'servicenow.test','integration','servicenow',null,{ok:result.ok});res.json(result)})
r.get('/notifications/servicenow/deliveries',(req,res)=>res.json(serviceNowDeliveries(req.query)))
r.post('/notifications/servicenow/deliveries/:id/retry',(req,res)=>{const d=one("SELECT id FROM notification_deliveries WHERE id=? AND channel='servicenow' AND status='failed'",req.params.id);if(!d)return res.status(409).json({error:'Only failed ServiceNow deliveries can be retried'});run("UPDATE notification_deliveries SET status='pending',attempts=0,next_attempt_at=?,last_error=NULL WHERE id=?",now(),d.id);audit(req.user.id,'servicenow.retry','notification_delivery',d.id,null,null);res.json({ok:true})})
r.get('/protection/ddos/policies',(_req,res)=>res.json(ddosPolicies().filter(p=>!p.archived)))
r.post('/protection/ddos/policies',(req,res)=>res.status(201).json(saveDdosPolicy(req.body,req.user.id)))
r.put('/protection/ddos/policies/:id',(req,res)=>res.json(saveDdosPolicy(req.body,req.user.id,req.params.id)))
r.delete('/protection/ddos/policies/:id',(req,res)=>{deleteDdosPolicy(req.params.id,req.user.id);res.status(204).end()})
r.get('/protection/ddos/policies/:id/preview',(req,res)=>{const p=ddosPolicies().find(p=>p.id===req.params.id&&!p.archived);if(!p)return res.status(404).json({error:'DDoS policy not found'});res.json(p.nodeIds.map(nodeId=>{const n=one('SELECT * FROM nodes WHERE id=?',nodeId);return {nodeId,hostname:n?.hostname,evidence:n?ddosEvidence(p,n):null}}))})
r.get('/protection/ddos/incidents',(req,res)=>res.json(ddosIncidents(req.query)))
r.get('/protection/ddos/incidents/:id',(req,res)=>res.json(ddosIncident(req.params.id)))
r.post('/protection/ddos/incidents/:id/release',async(req,res)=>res.json(await releaseDdosIncident(req.params.id,req.user.id)))
