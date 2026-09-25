import {Router} from 'express'
import {z} from 'zod'
import {all,one} from '../db.js'
import {requireRole} from '../security.js'
import {connections,saveConnection,deleteConnection,enqueueRun,getRun,listRuns,cancelRun} from './service.js'
import {scopes,saveScope,listSources,nodeSources,resolveConflict,sourceHistory,resolveSource} from './inventory.js'
import {pageSchema} from './schemas.js'
import {coverageSettings,saveCoverageSettings,fleetCoverage,nodeCoverage} from '../services/capabilities.js'
export const cloudRoutes=Router()
const r=cloudRoutes,admin=requireRole('admin')
r.get('/settings/coverage',admin,(_req,res)=>res.json(coverageSettings()))
r.put('/settings/coverage',admin,(req,res)=>res.json(saveCoverageSettings(z.record(z.string(),z.number()).parse(req.body),req.user.id)))
r.get('/reports/capabilities',(req,res)=>res.json(fleetCoverage(z.object({q:z.string().max(200).default(''),scopeId:z.string().optional(),transport:z.string().optional(),source:z.string().optional(),gap:z.string().optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(250).default(25)}).parse(req.query))))
r.get('/nodes/:id/capabilities',(req,res)=>{const node=one('SELECT * FROM nodes WHERE id=?',req.params.id);if(!node)return res.status(404).json({error:'Node not found'});res.json(nodeCoverage(node))})
r.get('/inventory/scopes',(req,res)=>res.json(scopes()))
r.post('/inventory/scopes',admin,(req,res)=>res.status(201).json(saveScope(req.body,req.user.id)))
r.put('/inventory/scopes/:id',admin,(req,res)=>res.json(saveScope(req.body,req.user.id,req.params.id)))
r.get('/discovery/azure/connections',(req,res)=>res.json(connections()))
r.post('/discovery/azure/connections',admin,(req,res)=>res.status(201).json(saveConnection(req.body,req.user.id)))
r.put('/discovery/azure/connections/:id',admin,(req,res)=>res.json(saveConnection(req.body,req.user.id,req.params.id)))
r.delete('/discovery/azure/connections/:id',admin,(req,res)=>{deleteConnection(req.params.id,req.user.id);res.status(204).end()})
for(const action of ['test','preview','sync'])r.post(`/discovery/azure/connections/:id/${action}`,admin,(req,res)=>res.status(202).json(enqueueRun(req.params.id,action,req.user.id)))
r.get('/discovery/azure/runs',(req,res)=>res.json(listRuns(req.query)))
r.get('/discovery/azure/runs/:id',(req,res)=>res.json(getRun(req.params.id)))
r.post('/discovery/azure/runs/:id/cancel',admin,(req,res)=>res.json(cancelRun(req.params.id,req.user.id)))
r.get('/discovery/azure/resources',(req,res)=>res.json(listSources(req.query)))
r.get('/discovery/azure/resources/:id/history',(req,res)=>res.json(sourceHistory(req.params.id,req.query)))
r.post('/discovery/azure/resources/:id/resolve',admin,(req,res)=>res.json(resolveSource(req.params.id,req.body,req.user.id)))
r.get('/discovery/azure/resources/export',(req,res)=>{
  const query=pageSchema.parse(req.query),items=[]
  for(let page=1;;page++){const result=listSources({...query,page,pageSize:250});items.push(...result.items);if(items.length>=result.total)break;if(items.length>=100000)return res.status(413).json({error:'Narrow the export to at most 100,000 resources'})}
  res.attachment('azure-resources.json').json({total:items.length,items})
})
r.get('/nodes/:id/sources',(req,res)=>{if(!one('SELECT id FROM nodes WHERE id=?',req.params.id))return res.status(404).json({error:'Node not found'});res.json(nodeSources(req.params.id))})
r.get('/inventory/conflicts',(req,res)=>{
  const q=pageSchema.parse(req.query),state=z.enum(['open','resolved','all']).default('open').parse(req.query.conflictState),where=state==='all'?'':'WHERE c.state=?',args=state==='all'?[]:[state]
  res.json({items:all(`SELECT c.*,s.resource_id,s.scope_id FROM asset_identity_conflicts c JOIN asset_sources s ON s.id=c.source_id ${where} ORDER BY c.created_at DESC,c.id LIMIT ? OFFSET ?`,...args,q.pageSize,(q.page-1)*q.pageSize).map(c=>({...c,candidates:JSON.parse(c.candidates_json),decision:JSON.parse(c.decision_json||'null'),candidates_json:undefined,decision_json:undefined})),total:one(`SELECT COUNT(*) n FROM asset_identity_conflicts c ${where}`,...args).n,page:q.page,pageSize:q.pageSize})
})
r.post('/inventory/conflicts/:id/resolve',admin,(req,res)=>res.json(resolveConflict(req.params.id,req.body,req.user.id)))
