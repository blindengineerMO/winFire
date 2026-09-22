import express from 'express'
import {requireRole} from '../security.js'
import {listMapping, listArp, rebuildMapping} from '../controllers/mappingController.js'

export const mappingRoutes = express.Router()
mappingRoutes.get('/', listMapping)
mappingRoutes.get('/arp', listArp)
mappingRoutes.post('/rebuild', requireRole('admin'), rebuildMapping)
