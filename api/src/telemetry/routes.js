import {receiverStatus} from './receiver.js'
import {importVnetBlob,refreshCloudNetwork,cloudNetworkContext} from './vnet.js'
import {Router} from 'express'
import {z} from 'zod'
import {requireRole} from '../security.js'
import {exporters,saveExporter,observationRows,importSyslog,ingestDatagram} from './service.js'
export const telemetryRoutes=Router(),r=telemetryRoutes,admin=requireRole('admin')
r.get('/telemetry/exporters',admin,(_req,res)=>res.json(exporters()))
r.post('/telemetry/exporters',admin,(req,res)=>res.status(201).json(saveExporter(req.body,req.user.id)))
r.put('/telemetry/exporters/:id',admin,(req,res)=>res.json(saveExporter(req.body,req.user.id,req.params.id)))
r.post('/telemetry/exporters/:id/syslog',admin,(req,res)=>res.json(importSyslog(req.params.id,req.body,req.user.id)))
r.post('/telemetry/exporters/:id/datagram',admin,(req,res)=>{const q=z.object({base64:z.string().min(4).max(87384).regex(/^[A-Za-z0-9+/]+={0,2}$/)}).strict().parse(req.body);res.json(ingestDatagram(req.params.id,Buffer.from(q.base64,'base64')))})
r.get('/telemetry/observations',(req,res)=>res.json(observationRows(req.query)))
r.get('/telemetry/observations/export',(req,res)=>{const items=[];for(let page=1;page<=400;page++){const result=observationRows({...req.query,page,pageSize:250});if(result.total>100000)return res.status(413).json({error:'Narrow the export to at most 100,000 observations'});items.push(...result.items);if(items.length>=result.total)break}res.attachment('traffic-observations.json').json({total:items.length,items})})

r.post('/telemetry/exporters/:id/vnet-blob',admin,async(req,res)=>res.json(await importVnetBlob(req.params.id,req.body,req.user.id)))
r.post('/discovery/azure/connections/:id/network-context',admin,async(req,res)=>res.json(await refreshCloudNetwork(req.params.id,req.user.id)))
r.get('/mapping/cloud-context',(req,res)=>res.json(cloudNetworkContext(req.query)))

r.get('/telemetry/receiver-status',admin,(_req,res)=>res.json(receiverStatus))
