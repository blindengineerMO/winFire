import {subnetMatcher,configuredCidrs,effectiveCidrs} from './networkBoundary.js'
export {subnetMatcher} from './networkBoundary.js'
import {db, all, one} from '../db.js'

const address = value => String(value || '').trim().split('%')[0].toLowerCase()
const mac = value => String(value || '').replace(/[^a-f0-9]/gi, '').toLowerCase()
db.function('winfire_mapping_subnet', {deterministic: true}, (ip, cidr) => Number(subnetMatcher(cidr)(ip)))
db.function('winfire_mapping_mac', {deterministic: true}, mac)

export function mappingFilterOptions() {
  const cidrs=configuredCidrs()
  return {
    subnets: [...new Set(cidrs.map(value => String(value).trim()).filter(value => { try { subnetMatcher(value); return true } catch { return false } }))],
    switches: all("SELECT id,hostname,ip FROM nodes WHERE device_type='switch' ORDER BY hostname,id")
  }
}

// Use the selected switch's ARP observations and its current forwarding
// snapshot. Resolve learned MACs using ARP from any collector or inventory;
// never traverse traffic links, which would pull in unrelated networks.
export function mappingScope({subnet = null, switchId = null} = {}) {
  const inSubnet = subnet ? subnetMatcher(subnet) : () => true
  let switchNode = null, addresses = null
  if (switchId) {
    switchNode = one("SELECT id,hostname,ip FROM nodes WHERE id=? AND device_type='switch'", switchId)
    if (!switchNode) throw Object.assign(new Error('Selected switch was not found'), {status: 400})
    const rows = all(`WITH learned AS (
      SELECT winfire_mapping_mac(json_extract(j.value,'$.mac')) mac
      FROM network_table_snapshots s, json_each(CASE WHEN json_valid(s.state_json) THEN s.state_json ELSE '{}' END,'$.macPorts') j
      WHERE s.node_id=? AND json_type(j.value,'$.mac')='text'
    )
    SELECT ip FROM arp_entries WHERE node_id=?
    UNION SELECT a.ip FROM arp_entries a JOIN learned l ON l.mac=winfire_mapping_mac(a.mac) AND length(l.mac)=12
    UNION SELECT n.ip FROM nodes n JOIN learned l ON l.mac=winfire_mapping_mac(n.mac_address) AND length(l.mac)=12`, switchId, switchId)
    addresses = new Set([switchNode.ip, ...rows.map(row => row.ip)].filter(Boolean).map(address))
  }
  const selectedAddresses = addresses ? [...addresses].filter(inSubnet) : null
  const endpointSql = (ip, nodeId) => {
    const conditions = [], args = []
    if (subnet) { conditions.push(`winfire_mapping_subnet(${ip},?)=1`); args.push(subnet) }
    if (switchId) {
      conditions.push(`(${nodeId}=? OR lower(${ip}) IN (SELECT value FROM json_each(?)))`)
      args.push(switchId, JSON.stringify([...addresses]))
    }
    return {sql: conditions.length ? `(${conditions.join(' AND ')})` : '1', args}
  }
  const pairSql = (sourceIp, sourceId, destinationIp, destinationId) => {
    const left = endpointSql(sourceIp, sourceId), right = endpointSql(destinationIp, destinationId)
    return {sql: `(${left.sql} OR ${right.sql})`, args: [...left.args, ...right.args]}
  }
  return {
    active: Boolean(subnet || switchId),
    matches: (ip, nodeId) => inSubnet(ip) && (!addresses || addresses.has(address(ip)) || nodeId === switchId),
    pairSql,
    summary: {subnet, switchId, switchName: switchNode?.hostname || null, observedAddresses: selectedAddresses?.length ?? null}
  }
}

export function mappingFlowWhere({nodeId = null, external = null, trafficClass = null, from = null, to = null, ...scopeOptions} = {}, scope = mappingScope(scopeOptions)) {
  const filters = [], args = []
  if (nodeId) { filters.push('(m.source_node_id=? OR m.destination_node_id=?)'); args.push(nodeId, nodeId) }
  if (external !== null && external !== undefined && external !== '') { filters.push('(winfire_outside(m.source_ip,?) OR winfire_outside(m.destination_ip,?))=?'); const cidrs=JSON.stringify(effectiveCidrs());args.push(cidrs,cidrs,Number(external)?1:0) }
  if (trafficClass) { filters.push('m.traffic_class=?'); args.push(trafficClass) }
  if (from) { filters.push('datetime(m.last_seen_at)>=datetime(?)'); args.push(from) }
  if (to) { filters.push('datetime(m.first_seen_at)<=datetime(?)'); args.push(to) }
  if (scope.active) { const match = scope.pairSql('m.source_ip', 'm.source_node_id', 'm.destination_ip', 'm.destination_node_id'); filters.push(match.sql); args.push(...match.args) }
  return {where: filters.length ? `WHERE ${filters.join(' AND ')}` : '', args}
}
