import express from 'express'
import {requireRole} from '../security.js'
import {listFilterOptions, listMapping, listArp, listTopology, rebuildMapping} from '../controllers/mappingController.js'

export const mappingRoutes = express.Router()
mappingRoutes.get('/', listMapping)
mappingRoutes.get('/filter-options', listFilterOptions)
mappingRoutes.get('/topology', listTopology)
mappingRoutes.get('/arp', listArp)
mappingRoutes.post('/rebuild', requireRole('admin'), rebuildMapping)
