import {z} from 'zod'
import {db, all, one, run, audit} from '../db.js'
import {mappingRows, arpRows, topologyGraph, recordNetworkFlow} from '../services/networkMapping.js'

import {mappingFilterOptions, subnetMatcher} from '../services/mappingScope.js'

const scopeSchema = z.object({
  subnet: z.string().trim().max(64).refine(value => {try {subnetMatcher(value); return true} catch {return false}}, 'Enter a valid IPv4 or IPv6 CIDR').optional(),
  switchId: z.string().min(1).max(200).optional(),
  nodeId: z.string().optional(),
  external: z.enum(['0', '1']).optional(),
  trafficClass: z.string().regex(/^[a-z-]+$/).optional(),
  from: z.string().max(40).refine(value => Number.isFinite(Date.parse(value)), 'Invalid start date').optional(),
  to: z.string().max(40).refine(value => Number.isFinite(Date.parse(value)), 'Invalid end date').optional()
})
const orderedDates = value => !value.from || !value.to || Date.parse(value.from)<=Date.parse(value.to)
const dateOrderError = {message:'From must be before To',path:['to']}
const querySchema = scopeSchema.extend({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(10).max(500).default(100)
}).refine(orderedDates,dateOrderError)

function parseQuery(schema, query) {
  const result=schema.safeParse(query)
  if(!result.success)throw Object.assign(new Error(result.error.issues.map(issue=>issue.message).join('; ')),{status:400})
  return result.data
}

export function listMapping(req, res) {
  res.json(mappingRows(parseQuery(querySchema,req.query)))
}

export function listArp(req, res) {
  const query = parseQuery(scopeSchema.extend({limit:z.coerce.number().int().min(1).max(2000).default(500)}).refine(orderedDates,dateOrderError),req.query)
  res.json({items: arpRows(query.nodeId || null, query.limit, query)})
}

export function listTopology(req, res) {
  const query = parseQuery(scopeSchema.extend({maxNodes:z.coerce.number().int().min(20).max(500).default(300),maxEdges:z.coerce.number().int().min(20).max(1000).default(700)}).refine(orderedDates,dateOrderError),req.query)
  res.json(topologyGraph(query))
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

export function listFilterOptions(req, res) { res.json(mappingFilterOptions()) }
