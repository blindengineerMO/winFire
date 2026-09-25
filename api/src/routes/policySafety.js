import {containmentPreview,queueContainment,containments,containment,restoreContainment} from '../services/containment.js'
import {deploymentPreview,queueDeployment,deployment,listDeployments,deploymentAction} from '../services/stagedDeployment.js'
import {one} from '../db.js'
import {createException,exceptions,reviewException,retirementPreview,ruleHygiene} from '../services/ruleLifecycle.js'
import {metadataSources,saveMetadataSources,refreshMetadataSources,proposeMetadata,reviewMetadata,metadataPreview,nodeApplication,applicationDependencies,serviceTemplates,templateGraph} from '../services/applicationContext.js'
import {Router} from 'express'
import {requireRole} from '../security.js'
import {capturePolicyContext,queueSimulation,listSimulations,simulation,simulationResults,cancelSimulation,approveSimulation} from '../services/policySimulation.js'
export const policySafetyRoutes=Router()
const r=policySafetyRoutes
r.get('/policies/:id/simulations',(req,res)=>res.json(listSimulations(req.params.id,req.user)))
r.post('/policies/:id/simulations',requireRole('editor'),(req,res)=>res.status(202).json(queueSimulation(req.params.id,req.body,req.user)))
r.get('/policy-simulations/:id',(req,res)=>res.json(simulation(req.params.id,req.user)))
r.get('/policy-simulations/:id/results',(req,res)=>res.json(simulationResults(req.params.id,req.user,req.query)))
r.post('/policy-simulations/:id/cancel',requireRole('editor'),(req,res)=>res.json(cancelSimulation(req.params.id,req.user)))
r.post('/policy-simulations/:id/approve',requireRole('admin'),(req,res)=>res.json(approveSimulation(req.params.id,req.body.reason,req.user)))

r.get('/nodes/:id/application',(req,res)=>{const result=nodeApplication(req.params.id);if(!['owner','admin'].includes(req.user.role))result.proposals=[];res.json(result)})
r.post('/nodes/:id/application/proposals',requireRole('admin'),(req,res)=>res.status(201).json(proposeMetadata(req.params.id,req.body,req.user.id)))
r.get('/application-proposals/:id',requireRole('admin'),(req,res)=>res.json(metadataPreview(req.params.id)))
r.post('/application-proposals/:id/review',requireRole('admin'),(req,res)=>res.json(reviewMetadata(req.params.id,req.body,req.user.id)))
r.get('/mapping/applications',(req,res)=>res.json(applicationDependencies(req.query)))
r.get('/policy-templates',(_req,res)=>res.json(serviceTemplates))
r.post('/policy-templates/preview',requireRole('editor'),(req,res)=>res.json(templateGraph(req.body)))

r.get('/rule-exceptions',(req,res)=>res.json(exceptions(req.user,req.query)))
r.post('/policies/:id/exceptions',requireRole('editor'),(req,res)=>res.status(201).json(createException(req.params.id,req.body,req.user)))
r.post('/rule-exceptions/:id/review',requireRole('editor'),(req,res)=>res.json(reviewException(req.params.id,req.body,req.user)))
r.get('/rule-exceptions/:id/retirement-preview',(req,res)=>res.json(retirementPreview(req.params.id,req.user)))
r.get('/policies/:id/hygiene',(req,res)=>res.json(ruleHygiene(req.params.id,req.user)))

r.post('/policy-deployments/preview',requireRole('admin'),(req,res)=>res.json(deploymentPreview(req.body,req.user)))
r.post('/policy-deployments',requireRole('admin'),(req,res)=>res.status(202).json(queueDeployment(req.body,req.user)))
r.get('/policy-deployments/:id',(req,res)=>res.json(deployment(req.params.id,req.user)))
r.get('/policies/:id/deployments',(req,res)=>res.json(listDeployments(req.params.id,req.user)))
for(const action of ['cancel','resume','restore'])r.post(`/policy-deployments/:id/${action}`,requireRole('admin'),(req,res)=>res.json(deploymentAction(req.params.id,action,req.body.reason,req.user)))
r.use('/policies/:id/versions',(req,res,next)=>{if(req.method==='POST'&&one("SELECT id FROM policy_deployment_jobs WHERE policy_id=? AND status IN ('queued','running','paused','partial','cancelling','restoring')",req.params.id))return res.status(409).json({error:'Finish or restore the staged deployment before publishing another policy version'});next()})

r.get('/settings/application-metadata',requireRole('admin'),(_req,res)=>res.json(metadataSources()))
r.put('/settings/application-metadata',requireRole('admin'),(req,res)=>res.json(saveMetadataSources(req.body,req.user.id)))
r.post('/application-proposals/refresh',requireRole('admin'),(_req,res)=>res.json(refreshMetadataSources()))

r.post('/containments/preview',requireRole('admin'),(req,res)=>res.json(containmentPreview(req.body,req.user)))
r.post('/containments',requireRole('admin'),(req,res)=>res.status(202).json(queueContainment(req.body,req.user)))
r.get('/containments',requireRole('admin'),(req,res)=>res.json(containments(req.query)))
r.get('/containments/:id',requireRole('admin'),(req,res)=>res.json(containment(req.params.id)))
r.post('/containments/:id/restore',requireRole('admin'),(req,res)=>res.json(restoreContainment(req.params.id,req.body.reason,req.user)))

r.post('/nodes/:id/policy-context',requireRole('admin'),async(req,res)=>res.json(await capturePolicyContext(req.params.id,req.user)))
