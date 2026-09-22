import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import {all, one, run, id, now} from '../db.js'

const moduleDir = path.dirname(fileURLToPath(import.meta.url))
const catalog = JSON.parse(fs.readFileSync(path.join(moduleDir, '../classifierCatalog.json'), 'utf8'))
const protocolRules = [
  {id: 'builtin-icmp', catalogId: 'builtin-icmp', protocol: 'ICMP', portStart: null, portEnd: null, service: 'ICMP (Internet Control Message Protocol)', description: 'Internet control and diagnostic messages', source: 'built-in', priority: 20, enabled: true},
  {id: 'builtin-igmp', catalogId: 'builtin-igmp', protocol: 'IGMP', portStart: null, portEnd: null, service: 'Internet Group Management Protocol (IGMP)', description: 'Multicast group membership messages', source: 'built-in', priority: 20, enabled: true},
]

let cached = null
const normalizeProtocol = value => {
  const raw = String(value || '').trim().toUpperCase()
  const mapped = ({'1': 'ICMP', '2': 'IGMP', '6': 'TCP', '17': 'UDP', '41': 'IPv6-in-IPv4', '47': 'GRE', '50': 'ESP', '51': 'AH', '58': 'ICMPv6', '89': 'OSPF', '132': 'SCTP', ICMPV6: 'ICMPv6', TCPV4: 'TCP', TCPV6: 'TCP', UDPV4: 'UDP', UDPV6: 'UDP'})[raw]
  if (mapped) return mapped
  if (/\bTCP\b/.test(raw)) return 'TCP'
  if (/\bUDP\b/.test(raw)) return 'UDP'
  return raw || 'ANY'
}
const normalizePort = value => {
  if (value === null || value === undefined || value === '') return null
  const number = typeof value === 'number' ? value : Number(String(value).trim())
  return Number.isInteger(number) && number > 0 && number <= 65535 ? number : null
}
const publicRule = rule => ({
  id: rule.id,
  catalogId: rule.catalog_id ?? rule.catalogId ?? null,
  protocol: rule.protocol,
  portStart: rule.port_start ?? rule.portStart ?? null,
  portEnd: rule.port_end ?? rule.portEnd ?? null,
  service: rule.service,
  description: rule.description || '',
  source: rule.source || 'custom',
  priority: Number(rule.priority ?? 10),
  enabled: Boolean(rule.enabled ?? 1),
  createdAt: rule.created_at ?? rule.createdAt ?? null,
  updatedAt: rule.updated_at ?? rule.updatedAt ?? null,
})
const catalogRows = () => [...protocolRules, ...catalog.rules]

function effectiveRules() {
  if (cached) return cached
  const overrides = all('SELECT * FROM classifier_rules ORDER BY priority ASC,updated_at DESC,id').map(publicRule)
  const byCatalog = new Map(overrides.filter(rule => rule.catalogId).map(rule => [rule.catalogId, rule]))
  const rows = catalogRows().map(rule => {
    const override = byCatalog.get(rule.id)
    return override ? {...rule, ...override, id: override.id, catalogId: rule.id} : {...rule, catalogId: rule.id}
  })
  rows.push(...overrides.filter(rule => !rule.catalogId))
  cached = rows
  return cached
}

export function invalidateClassifierRules() { cached = null }
export function classifierCatalogMetadata() {
  return {source: catalog.source, sourceUrl: catalog.sourceUrl, retrieved: catalog.retrieved, catalogCount: catalogRows().length}
}
export function findClassifierCatalogRule(ruleId) {
  return catalogRows().find(rule => rule.id === ruleId) || null
}
export function findClassifierOverride(ruleId) {
  const row = one('SELECT * FROM classifier_rules WHERE id=?', ruleId)
  return row ? publicRule(row) : null
}

// Return the currently effective representation for audit snapshots and
// callers that need to address either a catalog rule or a custom override.
// Catalog rows are static, while overrides are persisted with a generated id;
// effectiveRules() already applies the override to the catalog entry.
export function classifierRuleById(ruleId) {
  return effectiveRules().find(rule => rule.id === ruleId || rule.catalogId === ruleId) || null
}

export function classifierRuleRows({search = '', protocol = '', source = '', enabled = '', page = 1, pageSize = 100, sortBy = 'port', sortDir = 'asc'} = {}) {
  let rows = effectiveRules()
  const term = String(search || '').trim().toLowerCase()
  if (term) rows = rows.filter(rule => `${rule.service} ${rule.description} ${rule.protocol} ${rule.portStart ?? ''}`.toLowerCase().includes(term))
  if (protocol) rows = rows.filter(rule => rule.protocol === normalizeProtocol(protocol))
  if (source) rows = rows.filter(rule => rule.source === source)
  if (enabled === true || enabled === false || enabled === 'true' || enabled === 'false') rows = rows.filter(rule => rule.enabled === (enabled === true || enabled === 'true'))
  const sorters = {
    port: rule => rule.portStart ?? -1,
    protocol: rule => rule.protocol,
    service: rule => rule.service.toLowerCase(),
    source: rule => rule.source,
    priority: rule => rule.priority,
    enabled: rule => Number(rule.enabled),
  }
  const sorter = sorters[sortBy] || sorters.port
  const direction = sortDir === 'desc' ? -1 : 1
  rows = [...rows].sort((left, right) => {
    const a = sorter(left), b = sorter(right)
    return (a < b ? -1 : a > b ? 1 : left.id.localeCompare(right.id)) * direction
  })
  const safePage = Math.max(1, Number(page) || 1)
  const safePageSize = Math.min(500, Math.max(10, Number(pageSize) || 100))
  return {items: rows.slice((safePage - 1) * safePageSize, safePage * safePageSize), total: rows.length, page: safePage, pageSize: safePageSize, totalPages: Math.max(1, Math.ceil(rows.length / safePageSize)), ...classifierCatalogMetadata()}
}

export function resolveClassifierService(protocol, sourcePort = null, destinationPort = null, {maxPriority = Number.MAX_SAFE_INTEGER, sources = null} = {}) {
  const proto = normalizeProtocol(protocol)
  const ports = [normalizePort(destinationPort), normalizePort(sourcePort)].filter(port => port !== null)
  const rows = effectiveRules().filter(rule => rule.priority <= maxPriority && (!sources || sources.includes(rule.source)) && (rule.protocol === proto || rule.protocol === 'ANY'))
  const compare = (left, right) => {
    const priority = left.priority - right.priority
    if (priority) return priority
    const protocolSpecificity = Number(right.protocol === proto) - Number(left.protocol === proto)
    if (protocolSpecificity) return protocolSpecificity
    const leftWidth = left.portStart === null ? Number.MAX_SAFE_INTEGER : left.portEnd - left.portStart
    const rightWidth = right.portStart === null ? Number.MAX_SAFE_INTEGER : right.portEnd - right.portStart
    return leftWidth - rightWidth
  }
  for (const port of ports) {
    const match = rows.filter(rule => rule.portStart !== null && port >= rule.portStart && port <= rule.portEnd).sort(compare)[0]
    if (match) return match.enabled ? match.service : null
  }
  const protocolRule = rows.filter(rule => rule.portStart === null).sort(compare)[0]
  return protocolRule?.enabled ? protocolRule.service : null
}

export function classifierRuleSuppresses(protocol, sourcePort = null, destinationPort = null, options = {}) {
  const proto = normalizeProtocol(protocol)
  const ports = [normalizePort(destinationPort), normalizePort(sourcePort)].filter(port => port !== null)
  const rows = effectiveRules().filter(rule => rule.priority <= (options.maxPriority ?? Number.MAX_SAFE_INTEGER) && (!options.sources || options.sources.includes(rule.source)) && (rule.protocol === proto || rule.protocol === 'ANY'))
  const compare = (left, right) => {
    const priority = left.priority - right.priority
    if (priority) return priority
    const protocolSpecificity = Number(right.protocol === proto) - Number(left.protocol === proto)
    if (protocolSpecificity) return protocolSpecificity
    const leftWidth = left.portStart === null ? Number.MAX_SAFE_INTEGER : left.portEnd - left.portStart
    const rightWidth = right.portStart === null ? Number.MAX_SAFE_INTEGER : right.portEnd - right.portStart
    return leftWidth - rightWidth
  }
  for (const port of ports) {
    const match = rows.filter(rule => rule.portStart !== null && port >= rule.portStart && port <= rule.portEnd).sort(compare)[0]
    if (match) return !match.enabled
  }
  const protocolRule = rows.filter(rule => rule.portStart === null).sort(compare)[0]
  return Boolean(protocolRule && !protocolRule.enabled)
}

export function createClassifierRule(data, actorId) {
  const timestamp = now(), ruleId = id()
  run('INSERT INTO classifier_rules(id,catalog_id,protocol,port_start,port_end,service,description,source,priority,enabled,created_by,updated_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', ruleId, null, data.protocol, data.portStart, data.portEnd, data.service, data.description || null, 'custom', data.priority, Number(data.enabled), actorId, actorId, timestamp, timestamp)
  invalidateClassifierRules()
  return publicRule(one('SELECT * FROM classifier_rules WHERE id=?', ruleId))
}

export function updateClassifierRule(ruleId, data, actorId) {
  const existing = findClassifierOverride(ruleId)
  const catalogRule = findClassifierCatalogRule(ruleId)
  const timestamp = now()
  if (existing) {
    run('UPDATE classifier_rules SET protocol=?,port_start=?,port_end=?,service=?,description=?,priority=?,enabled=?,updated_by=?,updated_at=? WHERE id=?', data.protocol, data.portStart, data.portEnd, data.service, data.description || null, data.priority, Number(data.enabled), actorId, timestamp, ruleId)
    invalidateClassifierRules()
    return publicRule(one('SELECT * FROM classifier_rules WHERE id=?', ruleId))
  }
  if (!catalogRule) return null
  const overrideId = id()
  run('INSERT INTO classifier_rules(id,catalog_id,protocol,port_start,port_end,service,description,source,priority,enabled,created_by,updated_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', overrideId, catalogRule.id, data.protocol, data.portStart, data.portEnd, data.service, data.description || null, 'custom', data.priority, Number(data.enabled), actorId, actorId, timestamp, timestamp)
  invalidateClassifierRules()
  return publicRule(one('SELECT * FROM classifier_rules WHERE id=?', overrideId))
}

export function deleteClassifierRule(ruleId, actorId) {
  const existing = findClassifierOverride(ruleId)
  if (existing) {
    if (existing.catalogId) run('DELETE FROM classifier_rules WHERE id=?', ruleId)
    else run('DELETE FROM classifier_rules WHERE id=?', ruleId)
    invalidateClassifierRules()
    return true
  }
  const catalogRule = findClassifierCatalogRule(ruleId)
  if (!catalogRule) return false
  const timestamp = now(), overrideId = id()
  run('INSERT INTO classifier_rules(id,catalog_id,protocol,port_start,port_end,service,description,source,priority,enabled,created_by,updated_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', overrideId, catalogRule.id, catalogRule.protocol, catalogRule.portStart, catalogRule.portEnd, catalogRule.service, catalogRule.description || null, 'custom', catalogRule.priority, 0, actorId, actorId, timestamp, timestamp)
  invalidateClassifierRules()
  return true
}
