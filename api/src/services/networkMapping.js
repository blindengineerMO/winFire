import {isIP} from 'node:net'
import {all, one, run, id, now} from '../db.js'

const ipv4 = value => String(value || '').trim().split('/')[0]
  .split('%')[0].toLowerCase()
const ipv4Int = value => {
  const ip = ipv4(value)
  if (isIP(ip) !== 4) return null
  const octets = ip.split('.').map(Number)
  return octets.reduce((result, octet) => (result * 256) + octet, 0) >>> 0
}
const inV4 = (value, start, end) => {
  const number = ipv4Int(value)
  if (number === null) return false
  return number >= start && number <= end
}
const V4 = {
  private10: [0x0a000000, 0x0affffff],
  private172: [0xac100000, 0xac1fffff],
  private192: [0xc0a80000, 0xc0a8ffff],
  loopback: [0x7f000000, 0x7fffffff],
  linkLocal: [0xa9fe0000, 0xa9feffff],
  shared: [0x64400000, 0x647fffff],
  documentation192: [0xc0000200, 0xc00002ff],
  documentation198: [0xc6336400, 0xc63364ff],
  documentation203: [0xcb007100, 0xcb0071ff],
  benchmark: [0xc6120000, 0xc612ffff],
  multicast: [0xe0000000, 0xefffffff],
  reserved: [0xf0000000, 0xffffffff],
}
const privateV4 = value => inV4(value, ...V4.private10) || inV4(value, ...V4.private172) || inV4(value, ...V4.private192)
const privateV6 = value => /^fc|^fd/i.test(ipv4(value))
const normalizedIp = value => ipv4(value)
const isLoopback = value => inV4(value, ...V4.loopback) || normalizedIp(value) === '::1'
const isLinkLocal = value => inV4(value, ...V4.linkLocal) || /^fe[89ab][0-9a-f]:/i.test(normalizedIp(value))
const isMulticast = value => inV4(value, ...V4.multicast) || /^ff[0-9a-f]{2}:/i.test(normalizedIp(value))
const isBroadcast = value => normalizedIp(value) === '255.255.255.255'
const isUnspecified = value => normalizedIp(value) === '0.0.0.0' || normalizedIp(value) === '::'
const isDocumentation = value => inV4(value, ...V4.documentation192) || inV4(value, ...V4.documentation198) || inV4(value, ...V4.documentation203) || /^2001:db8:/i.test(normalizedIp(value))
const isReserved = value => inV4(value, ...V4.reserved) || inV4(value, ...V4.benchmark)
export const isInternalAddress = value => privateV4(value) || privateV6(value) || isLoopback(value) || isLinkLocal(value) || isMulticast(value) || isBroadcast(value)

const addressCategory = value => {
  const address = normalizedIp(value)
  if (!address || isIP(address) === 0) return 'unknown'
  if (isBroadcast(address)) return 'broadcast'
  if (isMulticast(address)) return 'multicast'
  if (isLoopback(address)) return 'loopback'
  if (isUnspecified(address)) return 'unspecified'
  if (isLinkLocal(address)) return 'link-local'
  if (privateV4(address) || privateV6(address)) return 'private'
  if (inV4(address, ...V4.shared)) return 'shared'
  if (isDocumentation(address)) return 'documentation'
  if (isReserved(address)) return 'reserved'
  return 'public'
}

export const normalizeNetworkProtocol = value => {
  const raw = String(value || '').trim().toUpperCase()
  return ({'6': 'TCP', '17': 'UDP', '1': 'ICMP', '58': 'ICMPV6', TCPV4: 'TCP', TCPV6: 'TCP', UDPV4: 'UDP', UDPV6: 'UDP'})[raw] || raw
}

// Well-known services are intentionally kept in the classifier instead of in
// the UI so agents, Mapping, Firewall Events, and future exports agree on the
// same interpretation. A service is selected from the destination port first
// and the source port second, which covers both request and response flows.
const servicePorts = {
  20: {TCP: 'FTP data transfer'},
  21: {TCP: 'FTP control'},
  22: {TCP: 'SSH/SFTP remote access'},
  23: {TCP: 'Telnet remote terminal'},
  25: {TCP: 'SMTP mail transfer'},
  53: {TCP: 'DNS name resolution', UDP: 'DNS name resolution'},
  67: {UDP: 'DHCP server'},
  68: {UDP: 'DHCP client'},
  69: {UDP: 'TFTP file transfer'},
  546: {UDP: 'DHCPv6 client'},
  547: {UDP: 'DHCPv6 server'},
  80: {TCP: 'HTTP web traffic'},
  88: {TCP: 'Kerberos authentication', UDP: 'Kerberos authentication'},
  110: {TCP: 'POP3 mail retrieval'},
  119: {TCP: 'NNTP news transfer'},
  123: {UDP: 'NTP time synchronization'},
  135: {TCP: 'MS RPC endpoint mapper', UDP: 'MS RPC endpoint mapper'},
  137: {UDP: 'NetBIOS name service'},
  138: {UDP: 'NetBIOS datagram service'},
  139: {TCP: 'NetBIOS session service'},
  143: {TCP: 'IMAP mail retrieval'},
  161: {UDP: 'SNMP monitoring'},
  162: {UDP: 'SNMP traps'},
  389: {TCP: 'LDAP directory access', UDP: 'LDAP directory access'},
  443: {TCP: 'HTTPS web traffic', UDP: 'HTTP/3 (QUIC) web traffic'},
  445: {TCP: 'SMB file or management traffic'},
  465: {TCP: 'SMTPS mail transfer'},
  500: {UDP: 'IKE/IPsec negotiation'},
  514: {TCP: 'Syslog', UDP: 'Syslog'},
  587: {TCP: 'SMTP submission'},
  636: {TCP: 'LDAPS secure directory access'},
  993: {TCP: 'IMAPS secure mail retrieval'},
  995: {TCP: 'POP3S secure mail retrieval'},
  1433: {TCP: 'Microsoft SQL Server'},
  1521: {TCP: 'Oracle database'},
  1701: {UDP: 'L2TP VPN'},
  1723: {TCP: 'PPTP VPN'},
  1812: {UDP: 'RADIUS authentication'},
  1813: {UDP: 'RADIUS accounting'},
  1883: {TCP: 'MQTT messaging'},
  2049: {TCP: 'NFS file sharing', UDP: 'NFS file sharing'},
  2375: {TCP: 'Docker API (unencrypted)'},
  2376: {TCP: 'Docker API TLS'},
  3268: {TCP: 'Active Directory Global Catalog'},
  3269: {TCP: 'Active Directory Global Catalog over LDAPS'},
  3306: {TCP: 'MySQL database'},
  3389: {TCP: 'RDP remote desktop'},
  3478: {TCP: 'STUN/TURN traversal', UDP: 'STUN/TURN traversal'},
  4500: {UDP: 'IPsec NAT traversal'},
  5060: {TCP: 'SIP signaling', UDP: 'SIP signaling'},
  5061: {TCP: 'SIP over TLS', UDP: 'SIP over TLS'},
  5353: {UDP: 'mDNS service discovery'},
  5355: {UDP: 'LLMNR name resolution'},
  5432: {TCP: 'PostgreSQL database'},
  5671: {TCP: 'AMQPS messaging'},
  5672: {TCP: 'AMQP messaging'},
  5985: {TCP: 'WinRM management over HTTP'},
  5986: {TCP: 'WinRM management over HTTPS'},
  6379: {TCP: 'Redis database'},
  6443: {TCP: 'Kubernetes API'},
  8080: {TCP: 'HTTP alternate web traffic'},
  8443: {TCP: 'HTTPS alternate web traffic'},
  9100: {TCP: 'JetDirect printing'},
  27017: {TCP: 'MongoDB database'},
}

const serviceFor = ({source, destination, protocol, sourcePort, destinationPort}) => {
  const proto = normalizeNetworkProtocol(protocol)
  const ports = new Set([sourcePort, destinationPort].filter(Number.isInteger))
  const addresses = new Set([normalizedIp(source), normalizedIp(destination)])
  const has = port => ports.has(port)
  if ((addresses.has('224.0.0.251') || addresses.has('ff02::fb')) && has(5353)) return 'mDNS service discovery'
  if ((addresses.has('224.0.0.252') || addresses.has('ff02::1:3')) && has(5355)) return 'LLMNR name resolution'
  if ((addresses.has('239.255.255.250') || addresses.has('ff02::c')) && has(1900)) return 'SSDP/UPnP discovery'
  if (has(3702) && (addresses.has('239.255.255.250') || addresses.has('ff02::c'))) return 'WS-Discovery'
  if (proto === 'UDP' && (has(67) || has(68)) && (addresses.has('0.0.0.0') || addresses.has('255.255.255.255') || addresses.has('::'))) return 'DHCPv4 address assignment'
  if (proto === 'UDP' && (has(546) || has(547)) && (addresses.has('ff02::1:2') || addresses.has('::'))) return 'DHCPv6 address assignment'
  // Prefer the destination port, then use the source port for response flows.
  for (const candidate of [destinationPort, sourcePort]) {
    if (!Number.isInteger(candidate)) continue
    const service = servicePorts[candidate]?.[proto]
    if (service) return service
  }
  return null
}

const directedBroadcastFor = (address, node) => {
  const number = ipv4Int(address)
  if (number === null || number === 0xffffffff || (number & 0xff) !== 0xff) return false
  let facts
  try { facts = node?.snapshot_json ? JSON.parse(node.snapshot_json) : null } catch { facts = null }
  for (const adapter of facts?.network || []) {
    const ips = Array.isArray(adapter.ipAddresses) ? adapter.ipAddresses : []
    const masks = Array.isArray(adapter.subnets) ? adapter.subnets : []
    for (let index = 0; index < ips.length; index++) {
      const host = ipv4Int(ips[index]), maskValue = ipv4Int(masks[index])
      if (host === null || maskValue === null || isIP(ipv4(ips[index])) !== 4) continue
      const broadcast = ((host & maskValue) | (~maskValue >>> 0)) >>> 0
      if (broadcast === number) return true
    }
  }
  return false
}

export function classifyNetworkFlow({node, sourceIp, destinationIp, sourceNode, destinationNode, protocol, sourcePort, destinationPort}) {
  const source = normalizedIp(sourceIp), destination = normalizedIp(destinationIp)
  const sourceCategory = addressCategory(source), destinationCategory = addressCategory(destination)
  const broadcast = sourceCategory === 'broadcast' || destinationCategory === 'broadcast' || directedBroadcastFor(source, node) || directedBroadcastFor(destination, node)
  const multicast = sourceCategory === 'multicast' || destinationCategory === 'multicast'
  const service = serviceFor({source, destination, protocol, sourcePort, destinationPort})
  let trafficClass = 'unicast'
  if (broadcast) trafficClass = 'broadcast'
  else if (multicast) trafficClass = 'multicast'
  else if (sourceCategory === 'loopback' || destinationCategory === 'loopback') trafficClass = 'loopback'
  else if (sourceCategory === 'link-local' || destinationCategory === 'link-local') trafficClass = 'link-local'
  else if (sourceCategory === 'unspecified' || destinationCategory === 'unspecified') trafficClass = 'unspecified'
  else if (sourceNode && destinationNode) trafficClass = 'node-to-node'
  else if (sourceCategory === 'private' && destinationCategory === 'private') trafficClass = 'private'
  else if (sourceCategory === 'documentation' || destinationCategory === 'documentation' || sourceCategory === 'reserved' || destinationCategory === 'reserved') trafficClass = 'special-purpose'
  else if (sourceCategory === 'shared' || destinationCategory === 'shared') trafficClass = 'shared-address'
  else if (sourceCategory === 'public' || destinationCategory === 'public') trafficClass = 'public-unicast'

  const localCategories = new Set(['broadcast', 'multicast', 'loopback', 'link-local', 'private', 'unspecified'])
  const hasPublic = sourceCategory === 'public' || destinationCategory === 'public'
  const scope = trafficClass === 'loopback' ? 'host-local' : (localCategories.has(sourceCategory) && localCategories.has(destinationCategory) && !hasPublic) || sourceNode && destinationNode ? 'internal' : hasPublic ? 'external' : 'unknown'
  let reason
  if (trafficClass === 'multicast') reason = `${destination || source} is a multicast group; multicast is link or site scoped and is treated as internal traffic`
  else if (trafficClass === 'broadcast') reason = `${destination || source} is an IPv4 broadcast address; broadcast is local to the attached network`
  else if (trafficClass === 'node-to-node') reason = 'Both endpoints resolve to managed nodes in the inventory'
  else if (trafficClass === 'link-local') reason = 'A link-local address is valid only on the local network segment'
  else if (trafficClass === 'loopback') reason = 'Loopback traffic terminates on the originating host'
  else if (trafficClass === 'private') reason = 'Both endpoints use private address space'
  else if (trafficClass === 'special-purpose') reason = 'At least one endpoint is a documentation or reserved address and should not be treated as Internet traffic'
  else if (trafficClass === 'shared-address') reason = '100.64.0.0/10 is shared carrier-grade NAT space, not a public Internet destination'
  else if (trafficClass === 'public-unicast') reason = 'At least one endpoint is globally routable and no local-scope exception matched'
  else reason = 'Address scope could not be determined from the observed tuple'
  if (service) reason += `; identified as ${service}`
  return {trafficClass, scope, service, reason, sourceCategory, destinationCategory, external: scope === 'external' ? 1 : 0}
}
const clean = value => value === undefined || value === null || value === '' ? null : String(value)
const port = value => Number.isInteger(Number(value)) && Number(value) > 0 && Number(value) <= 65535 ? Number(value) : null
const localNode = nodeId => one('SELECT n.id,n.ip,n.hostname,f.snapshot_json FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id WHERE n.id=?', nodeId)
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
  const protocol = normalizeNetworkProtocol(event.protocol || 'UNKNOWN')
  const sourcePort = port(event.srcPort)
  const destinationPort = port(event.dstPort)
  const classification = classifyNetworkFlow({node, sourceIp, destinationIp, sourceNode, destinationNode, protocol, sourcePort, destinationPort})
  const key = [sourceNode?.id || '', destinationNode?.id || '', sourceIp, destinationIp, protocol, sourcePort || '', destinationPort || ''].join('|')
  const at = observedAt || event.eventTime || now()
  const existing = one('SELECT map_key FROM network_map_pairs WHERE map_key=?', key)
  if (existing) {
    run('UPDATE network_map_pairs SET connection_count=connection_count+1,last_seen_at=?,updated_at=?,sample_program=COALESCE(sample_program,?),traffic_class=?,traffic_scope=?,traffic_service=?,classification_reason=?,classification_json=?,external=? WHERE map_key=?', at, now(), clean(event.program), classification.trafficClass, classification.scope, classification.service, classification.reason, JSON.stringify(classification), classification.external, key)
  } else {
    run('INSERT INTO network_map_pairs(map_key,source_node_id,destination_node_id,source_ip,destination_ip,protocol,source_port,destination_port,direction,external,traffic_class,traffic_scope,traffic_service,classification_reason,classification_json,connection_count,sample_program,first_seen_at,last_seen_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', key, sourceNode?.id || null, destinationNode?.id || null, sourceIp, destinationIp, protocol, sourcePort, destinationPort, direction, classification.external, classification.trafficClass, classification.scope, classification.service, classification.reason, JSON.stringify(classification), 1, clean(event.program), at, at, now())
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

export function mappingRows({nodeId = null, external = null, trafficClass = null, from = null, to = null, page = 1, pageSize = 100} = {}) {
  const filters = [], args = []
  if (nodeId) { filters.push('(m.source_node_id=? OR m.destination_node_id=?)'); args.push(nodeId, nodeId) }
  if (external !== null && external !== undefined && external !== '') { filters.push('m.external=?'); args.push(Number(external) ? 1 : 0) }
  if (trafficClass) { filters.push('m.traffic_class=?'); args.push(trafficClass) }
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
