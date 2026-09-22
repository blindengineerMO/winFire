import {z} from 'zod'
import {db, all, one, run, audit} from '../db.js'
import {mappingRows, arpRows, recordNetworkFlow} from '../services/networkMapping.js'

const querySchema = z.object({
  nodeId: z.string().optional(),
  external: z.enum(['0', '1']).optional(),
  trafficClass: z.string().regex(/^[a-z-]+$/).optional(),
  from: z.string().optional(),
  to: z.string().optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(10).max(500).default(100)
})

export function listMapping(req, res) {
  res.json(mappingRows(querySchema.parse(req.query)))
}

export function listArp(req, res) {
  res.json({items: arpRows(req.query.nodeId || null, Number(req.query.limit) || 500)})
}

export function rebuildMapping(req, res) {
  const events = all("SELECT node_id,event_id,action,protocol,src_ip srcIp,src_port srcPort,dst_ip dstIp,dst_port dstPort,direction,program,event_type eventType,event_time eventTime FROM log_events WHERE (event_type='firewall' OR event_id IN (5150,5151,5156,5157)) ORDER BY rowid")
  db.transaction(() => {
    run('DELETE FROM network_map_pairs')
    for (const event of events) recordNetworkFlow(event.node_id, event, event.eventTime)
  })()
  audit(req.user.id, 'network-mapping.rebuild', 'network-map', 'global', null, {events: events.length})
  res.json({ok: true, events: events.length, rows: one('SELECT COUNT(*) count FROM network_map_pairs').count})
}
