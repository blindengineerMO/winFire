import {Router} from 'express'
import {z} from 'zod'
import {requireRole} from '../security.js'
import {evidenceDestinations,saveEvidenceDestination,evidenceSnapshot,evidenceDeliveries,queueEvidenceSnapshot,retryEvidence} from '../services/evidenceExports.js'
export const evidenceRoutes=Router()
const admin=requireRole('admin')
evidenceRoutes.get('/reports/evidence',admin,(req,res)=>{const {scopeId}=z.object({scopeId:z.string().min(1).max(200).default('default')}).strict().parse(req.query);res.json(evidenceSnapshot(scopeId))})
evidenceRoutes.get('/evidence-destinations',admin,(_req,res)=>res.json(evidenceDestinations()))
evidenceRoutes.post('/evidence-destinations',admin,(req,res)=>res.status(201).json(saveEvidenceDestination(req.body,req.user.id)))
evidenceRoutes.put('/evidence-destinations/:id',admin,(req,res)=>res.json(saveEvidenceDestination(req.body,req.user.id,req.params.id)))
evidenceRoutes.post('/evidence-destinations/:id/snapshot',admin,(req,res)=>res.status(202).json(queueEvidenceSnapshot(req.params.id,req.user.id)))
evidenceRoutes.get('/evidence-deliveries',admin,(req,res)=>res.json(evidenceDeliveries(req.query)))
evidenceRoutes.post('/evidence-deliveries/:id/retry',admin,(req,res)=>res.json(retryEvidence(req.params.id,req.user.id)))
