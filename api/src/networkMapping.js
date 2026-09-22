import {isIP} from 'node:net'
import {all, one, run, id, now} from './db.js'

const ipv4 = value => String(value || '').trim().split('/')[0]
const privateV4 = value => {
  const ip = ipv4(value)
  if (isIP(ip) !== 4) return false
  const [a,b] = ip.split('.').map(Number)
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127 || (a === 169 && b === 254)
}
const privateV6 = value => /^::1$|^fe80:/i.test(ipv4(value)) || /^fd|^fc/i.test(ipv4(value))
export const isInternalAddress = value => privateV4(value) || privateV6(value)
const clean = value => value === undefined || value === null || value === '' ? null : String(value)
const port = value => Number.isInteger(Number(value)) && Number(value) > 0 && Number(value) <= 65535 ? Number(value) : null
const localNode = nodeId => one('SELECT id,ip,hostname FROM nodes WHERE id=?', nodeId)
const nodeForIp = address => address ? one('SELECT id,hostname FROM nodes WHERE lower(ip)=lower(?) LIMIT 1', address) : null

export function recordNetworkFlow(nodeId, event, observedAt = null) {
  if (!event || event.eventType && event.eventType !== 'firewall' || !event.srcIp && !event.dstIp) return false
  const node = localNode(nodeId)
  if (!node) return false
  const direction = String(event.direction || 'unknown').toLowerCase()
  const sourceIp = clean(event.srcIp || (direction === 'out' ? node.ip : null))
  const destinationIp = clean(event.dstIp || (direction === 'in' ? node.ip : null))
  if (!sourceIp || !destinationIp || isIP(ipv4(sourceIp)) === 0 || isIP(ipv4(destinationIp)) === 0) return false
  const sourceNode = direction === 'out' ? node : nodeForIp(sourceIp)
  const destinationNode = direction === 'in' ? node : nodeForIp(destinationIp)
  const protocol = String(event.protocol || 'UNKNOWN').toUpperCase()
  const sourcePort = port(event.srcPort)
  const destinationPort = port(event.dstPort)
  const external = !(sourceNode && destinationNode) && (!isInternalAddress(sourceIp) || !isInternalAddress(destinationIp))
  const key = [sourceNode?.id || '', destinationNode?.id || '', sourceIp, destinationIp, protocol, sourcePort || '', destinationPort || ''].join('|')
  const at = observedAt || event.eventTime || now()
  const existing = one('SELECT map_key FROM network_map_pairs WHERE map_key=?', key)
  if (existing) {
    run('UPDATE network_map_pairs SET connection_count=connection_count+1,last_seen_at=?,updated_at=?,sample_program=COALESCE(sample_program,?) WHERE map_key=?', at, now(), clean(event.program), key)
  } else {
    run('INSERT INTO network_map_pairs(map_key,source_node_id,destination_node_id,source_ip,destination_ip,protocol,source_port,destination_port,direction,external,connection_count,sample_program,first_seen_at,last_seen_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', key, sourceNode?.id || null, destinationNode?.id || null, sourceIp, destinationIp, protocol, sourcePort, destinationPort, direction, Number(external), 1, clean(event.program), at, at, now())
  }
  return true
}

export function recordArpEntries(nodeId, entries, source = 'agent') {
  const items = Array.isArray(entries) ? entries.slice(0, 5000) : []
  let saved = 0
  for (const item of items) {
    const ip = clean(item.ip)
    if (!ip || isIP(ipv4(ip)) === 0) continue
    const existing = one('SELECT id FROM arp_entries WHERE node_id=? AND ip=? AND mac IS ?', nodeId, ip, clean(item.mac))
    const at = clean(item.observedAt) || now()
    if (existing) run('UPDATE arp_entries SET hostname=?,interface=?,state=?,source=?,observed_at=? WHERE id=?', clean(item.hostname), clean(item.interface), clean(item.state), source, at, existing.id)
    else run('INSERT INTO arp_entries(id,node_id,ip,mac,hostname,interface,state,source,observed_at) VALUES(?,?,?,?,?,?,?,?,?)', id(), nodeId, ip, clean(item.mac), clean(item.hostname), clean(item.interface), clean(item.state), source, at)
    saved++
  }
  return saved
}

export function mappingRows({nodeId = null, external = null, from = null, to = null, page = 1, pageSize = 100} = {}) {
  const filters = [], args = []
  if (nodeId) { filters.push('(m.source_node_id=? OR m.destination_node_id=?)'); args.push(nodeId, nodeId) }
  if (external !== null && external !== undefined && external !== '') { filters.push('m.external=?'); args.push(Number(external) ? 1 : 0) }
  if (from) { filters.push('datetime(m.last_seen_at)>=datetime(?)'); args.push(from) }
  if (to) { filters.push('datetime(m.first_seen_at)<=datetime(?)'); args.push(to) }
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : ''
  const total = one(`SELECT COUNT(*) count FROM network_map_pairs m ${where}`, ...args)?.count || 0
  const safePage = Math.max(1, Number(page) || 1), safeSize = Math.min(500, Math.max(10, Number(pageSize) || 100))
  const rows = all(`SELECT m.*,sn.hostname source_hostname,dn.hostname destination_hostname FROM network_map_pairs m LEFT JOIN nodes sn ON sn.id=m.source_node_id LEFT JOIN nodes dn ON dn.id=m.destination_node_id ${where} ORDER BY m.connection_count DESC,m.last_seen_at DESC LIMIT ? OFFSET ?`, ...args, safeSize, (safePage - 1) * safeSize)
  const topTalkers = all(`SELECT node_id,hostname,SUM(connections) connections FROM (SELECT source_node_id node_id,COALESCE(sn.hostname,source_ip) hostname,connection_count connections FROM network_map_pairs m LEFT JOIN nodes sn ON sn.id=m.source_node_id ${where} UNION ALL SELECT destination_node_id,COALESCE(dn.hostname,destination_ip),connection_count FROM network_map_pairs m LEFT JOIN nodes dn ON dn.id=m.destination_node_id ${where}) GROUP BY node_id,hostname ORDER BY connections DESC LIMIT 20`, ...args, ...args)
  return {rows, topTalkers, total: Number(total), page: safePage, pageSize: safeSize, pages: Math.ceil(Number(total) / safeSize)}
}

export function arpRows(nodeId = null, limit = 500) {
  const rows = nodeId ? all('SELECT a.*,n.hostname FROM arp_entries a JOIN nodes n ON n.id=a.node_id WHERE a.node_id=? ORDER BY a.observed_at DESC LIMIT ?', nodeId, Math.min(2000, limit)) : all('SELECT a.*,n.hostname FROM arp_entries a JOIN nodes n ON n.id=a.node_id ORDER BY a.observed_at DESC LIMIT ?', Math.min(2000, limit))
  return rows
}
