import {effectiveCidrs,outsideLocal,inLocalCidrs,inventoryEligibleIp,boundaryState} from './networkBoundary.js'
import {isIP} from 'node:net'
import {mappingScope, mappingFlowWhere} from './mappingScope.js'
import {all, one, run, id, now} from '../db.js'
import {resolveClassifierService,resolveProcessService,classifierRuleSuppresses} from './classifierRules.js'

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
  const known = ({'1': 'ICMP', '2': 'IGMP', '6': 'TCP', '17': 'UDP', '41': 'IPv6-in-IPv4', '47': 'GRE', '50': 'ESP', '51': 'AH', '58': 'ICMPv6', '89': 'OSPF', '132': 'SCTP', ICMPV6: 'ICMPv6', TCPV4: 'TCP', TCPV6: 'TCP', UDPV4: 'UDP', UDPV6: 'UDP'})[raw]
  if (known) return known
  // Some Windows providers label the address family as “TCP/IPv4” or
  // “UDP (IPv6)”. Keep those records on the same service catalog path.
  if (/\bTCP\b/.test(raw)) return 'TCP'
  if (/\bUDP\b/.test(raw)) return 'UDP'
  return raw
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
  1900: {UDP: 'SSDP/UPnP device discovery'},
  3702: {UDP: 'WS-Discovery'},
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
  515: {TCP: 'LPD printer service'},
  631: {TCP: 'IPP printer service'},
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

// Firewall connectors and SQLite can return ports as numbers, numeric strings,
// or empty values depending on the source (WFP, WinRM, an agent, or a compacted
// event pattern). Normalize at the classifier boundary so every caller gets
// the same service result.
const normalizePort = value => {
  if (value === null || value === undefined || value === '') return null
  const number = typeof value === 'number' ? value : Number(String(value).trim())
  return Number.isInteger(number) && number > 0 && number <= 65535 ? number : null
}

const serviceFor = ({source, destination, protocol, sourcePort, destinationPort, program}) => {
  const proto = normalizeNetworkProtocol(protocol)
  const normalizedSourcePort = normalizePort(sourcePort)
  const normalizedDestinationPort = normalizePort(destinationPort)
  const ports = new Set([normalizedSourcePort, normalizedDestinationPort].filter(Number.isInteger))
  const addresses = new Set([normalizedIp(source), normalizedIp(destination)])
  const has = port => ports.has(port)
  // Process rules identify services that use dynamic or ambiguous ports. The
  // administrator can add, edit, disable, or restore these patterns in the
  // Classifier administration view.
  const processService = resolveProcessService(program)
  if (processService) return processService
  // Customer rules have precedence over the built-in and IANA catalog,
  // regardless of the customer-selected priority value.
  if (classifierRuleSuppresses(proto, normalizedSourcePort, normalizedDestinationPort, {sources: ['custom']})) return null
  const customService = resolveClassifierService(proto, normalizedSourcePort, normalizedDestinationPort, {sources: ['custom']})
  if (customService) return customService
  // ICMP and IGMP do not use TCP/UDP ports. Identify them directly from the
  // protocol number/name so control and multicast membership traffic are never
  // shown as unidentified services.
  if (proto === 'ICMP') return 'ICMP (Internet Control Message Protocol)'
  if (proto === 'IGMP') return 'Internet Group Management Protocol (IGMP)'
  if ((addresses.has('224.0.0.251') || addresses.has('ff02::fb')) && has(5353)) return 'mDNS service discovery'
  if ((addresses.has('224.0.0.252') || addresses.has('ff02::1:3')) && has(5355)) return 'LLMNR name resolution'
  if ((addresses.has('239.255.255.250') || addresses.has('ff02::c')) && has(1900)) return 'SSDP/UPnP discovery'
  if (has(3702) && (addresses.has('239.255.255.250') || addresses.has('ff02::c'))) return 'WS-Discovery'
  if (proto === 'UDP' && (has(67) || has(68)) && (addresses.has('0.0.0.0') || addresses.has('255.255.255.255') || addresses.has('::'))) return 'DHCPv4 address assignment'
  if (proto === 'UDP' && (has(546) || has(547)) && (addresses.has('ff02::1:2') || addresses.has('::'))) return 'DHCPv6 address assignment'
  const catalogService = resolveClassifierService(proto, normalizedSourcePort, normalizedDestinationPort)
  if (catalogService) return catalogService
  // Prefer the destination port, then use the source port for response flows.
  for (const candidate of [normalizedDestinationPort, normalizedSourcePort]) {
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

export function classifyNetworkFlow({node, sourceIp, destinationIp, sourceNode, destinationNode, protocol, sourcePort, destinationPort, program}) {
  const source = normalizedIp(sourceIp), destination = normalizedIp(destinationIp)
  const sourceCategory = addressCategory(source), destinationCategory = addressCategory(destination)
  const broadcast = sourceCategory === 'broadcast' || destinationCategory === 'broadcast' || directedBroadcastFor(source, node) || directedBroadcastFor(destination, node)
  const multicast = sourceCategory === 'multicast' || destinationCategory === 'multicast'
  const service = serviceFor({source, destination, protocol, sourcePort, destinationPort, program})
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
  let scope = trafficClass === 'loopback' ? 'host-local' : (localCategories.has(sourceCategory) && localCategories.has(destinationCategory) && !hasPublic) || sourceNode && destinationNode ? 'internal' : hasPublic ? 'external' : 'unknown'
  const boundary=effectiveCidrs()
  if(!['loopback','broadcast','multicast','link-local','unspecified'].includes(trafficClass))scope=boundary.length?(outsideLocal(source,boundary)||outsideLocal(destination,boundary)?'external':inLocalCidrs(source,boundary)&&inLocalCidrs(destination,boundary)?'internal':'unknown'):'unknown'
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
  if(boundary.length&&scope==='external')reason='A unicast endpoint is outside configured local CIDRs; its address category does not imply public routability'
  if (service) reason += `; identified as ${service}`
  return {trafficClass, scope, service, reason, sourceCategory, destinationCategory, external: scope === 'external' ? 1 : 0}
}
const clean = value => value === undefined || value === null || value === '' ? null : String(value)
const port = normalizePort
const hasIdentifiedService = value => {
  const service = String(value || '').trim()
  return Boolean(service) && !/^(?:unknown|unidentified|unclassified)(?:\s+service)?$|^n\/a$|^-$/.test(service.toLowerCase())
}
const localNode = nodeId => one('SELECT n.id,n.ip,n.hostname,f.snapshot_json FROM nodes n LEFT JOIN node_facts f ON f.node_id=n.id WHERE n.id=?', nodeId)
const nodeForIp = address => address ? one('SELECT id,hostname FROM nodes WHERE lower(ip)=lower(?) LIMIT 1', address) : null

const PASSIVE_MANAGEMENT_PORTS = new Set([22, 80, 443, 445, 3389, 5985, 5986, 8006, 902])
const PASSIVE_PRINTER_PORTS = new Set([515, 631, 9100])
const PASSIVE_SERVICE_GROUPS = {
  mdns: /m(?:-?dns|dns).*service|service discovery/i,
  ssdp: /ssdp|upnp/i,
  wsDiscovery: /ws-?discovery/i,
  netbios: /netbios/i,
  printer: /printer|printing|ipp|jetdirect|lpd|airprint/i,
  snmp: /snmp/i
}
const boundedText = value => String(value || '').trim().slice(0, 160)

/**
 * Infer a conservative device-type hint from traffic that was already
 * persisted by the mapping classifier. This is deliberately advisory: it
 * never claims an authenticated OS or management protocol and returns null
 * when the observed signals are too weak.
 */
export function inferPassiveDeviceType({ip, rows = [], observedAt = now()} = {}) {
  const address = normalizedIp(ip)
  if (!address) return null
  const services = new Set(), ports = new Set(), evidence = [], managementPorts = new Set()
  const addEvidence = value => { const text = boundedText(value); if (text && !evidence.includes(text) && evidence.length < 12) evidence.push(text) }
  for (const row of Array.isArray(rows) ? rows.slice(0, 2000) : []) {
    const source = normalizedIp(row.source_ip || row.sourceIp), destination = normalizedIp(row.destination_ip || row.destinationIp)
    if (source !== address && destination !== address) continue
    const protocol = normalizeNetworkProtocol(row.protocol)
    const sourcePort = normalizePort(row.source_port ?? row.sourcePort), destinationPort = normalizePort(row.destination_port ?? row.destinationPort)
    const service = boundedText(row.traffic_service || row.trafficService) || serviceFor({source, destination, protocol, sourcePort, destinationPort, program: row.sample_program || row.program})
    if (service) {
      services.add(service)
      addEvidence(`${protocol || 'traffic'} ${sourcePort || '—'}→${destinationPort || '—'} · ${service}`)
    }
    for (const portValue of [sourcePort, destinationPort]) {
      if (!portValue) continue
      ports.add(portValue)
      if (PASSIVE_MANAGEMENT_PORTS.has(portValue)) managementPorts.add(portValue)
    }
  }
  const serviceList = [...services].slice(0, 8)
  const has = group => serviceList.some(service => PASSIVE_SERVICE_GROUPS[group].test(service))
  const printerPort = [...ports].some(portValue => PASSIVE_PRINTER_PORTS.has(portValue))
  const printerSignal = has('printer') || printerPort
  const passiveDiscoverySignal = has('mdns') || has('ssdp') || has('wsDiscovery') || has('netbios')
  if (!passiveDiscoverySignal && !printerSignal && !has('snmp')) return null

  let type = null, label = null, confidence = 'low'
  if (printerSignal && managementPorts.size === 0) {
    type = 'printer'; label = 'Printer'; confidence = 'high'
  } else if (has('snmp') && managementPorts.size === 0) {
    type = 'network-device'; label = 'Network device'; confidence = 'medium'
  } else if ((has('ssdp') || has('wsDiscovery') || has('mdns')) && managementPorts.size === 0) {
    type = 'iot'; label = 'IoT device'; confidence = has('ssdp') || has('wsDiscovery') ? 'medium' : 'low'
  } else if (has('netbios') && managementPorts.size === 0) {
    type = 'other'; label = 'Network endpoint'; confidence = 'low'
  }
  if (!type) return null
  return {
    type,
    label,
    confidence,
    source: 'passive-traffic',
    method: 'network-map-classifier',
    observedServices: serviceList,
    observedPorts: [...ports].sort((a, b) => a - b).slice(0, 24),
    managementPorts: [...managementPorts].sort((a, b) => a - b),
    evidence,
    observedAt
  }
}

export function passiveDeviceHintForIp(ip, {maxRows = 500, windowDays = 7} = {}) {
  const address = normalizedIp(ip)
  if (!address) return null
  const rows = all(`SELECT source_ip,destination_ip,protocol,source_port,destination_port,traffic_service,sample_program,last_seen_at
    FROM network_map_pairs
    WHERE external=0 AND (lower(source_ip)=lower(?) OR lower(destination_ip)=lower(?))
      AND (last_seen_at IS NULL OR datetime(last_seen_at)>=datetime('now',?))
    ORDER BY last_seen_at DESC LIMIT ?`, address, address, `-${Math.min(30, Math.max(1, Number(windowDays) || 7))} days`, Math.min(2000, Math.max(1, Number(maxRows) || 500)))
  return inferPassiveDeviceType({ip: address, rows})
}

export function recordNetworkFlow(nodeId, event, observedAt = null) {
  if (!event || event.eventType && event.eventType !== 'firewall' || !event.srcIp && !event.dstIp) return false
  const node = localNode(nodeId)
  if (!node) return false
  const direction = String(event.direction || 'unknown').toLowerCase()
  const sourceIp = clean(event.srcIp || (direction === 'out' ? node.ip : null))
  const destinationIp = clean(event.dstIp || (direction === 'in' ? node.ip : null))
  if (!sourceIp || !destinationIp || isIP(ipv4(sourceIp)) === 0 || isIP(ipv4(destinationIp)) === 0) return false
  const sourceNode = sourceIp === node.ip ? node : nodeForIp(sourceIp)
  const destinationNode = destinationIp === node.ip ? node : nodeForIp(destinationIp)
  const protocol = normalizeNetworkProtocol(event.protocol || 'UNKNOWN')
  const sourcePort = port(event.srcPort)
  const destinationPort = port(event.dstPort)
  const classification = classifyNetworkFlow({node, sourceIp, destinationIp, sourceNode, destinationNode, protocol, sourcePort, destinationPort, program:event.program})
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
  const sourceNode = one('SELECT id,ip FROM nodes WHERE id=?', nodeId)
  for (const item of items) {
    const ip = clean(item.ip)
    if (!ip || isIP(ipv4(ip)) === 0) continue
    const mac = clean(item.mac) || null
    const existing = one('SELECT id FROM arp_entries WHERE node_id=? AND ip=? AND mac IS ?', nodeId, ip, mac)
    const at = clean(item.observedAt) || now()
    if (existing) run('UPDATE arp_entries SET hostname=?,interface=?,state=?,source=?,observed_at=? WHERE id=?', clean(item.hostname), clean(item.interface), clean(item.state), source, at, existing.id)
    else run('INSERT INTO arp_entries(id,node_id,ip,mac,hostname,interface,state,source,observed_at) VALUES(?,?,?,?,?,?,?,?,?)', id(), nodeId, ip, mac, clean(item.hostname), clean(item.interface), clean(item.state), source, at)
    // A managed node's ARP cache is a passive discovery source. Queue only
    // addresses that are not already inventory records and never queue the
    // reporting node's own address. The queue keeps ingestion synchronous and
    // lets the normal DNS/WinRM onboarding worker handle network operations.
    const inventoryNode = one('SELECT id FROM nodes WHERE lower(ip)=lower(?) LIMIT 1', ip)
    if (sourceNode && ip !== sourceNode.ip && !inventoryNode && inventoryEligibleIp(ip)) run(`INSERT INTO passive_discovery_candidates(id,ip,mac,source_node_id,hostname,first_seen_at,last_seen_at,status,attempts,next_attempt_at,node_id,last_error,updated_at)
      VALUES(?,?,?,?,?,?,?,'queued',0,NULL,NULL,NULL,?)
      ON CONFLICT(ip) DO UPDATE SET mac=COALESCE(excluded.mac,passive_discovery_candidates.mac),source_node_id=excluded.source_node_id,hostname=COALESCE(excluded.hostname,passive_discovery_candidates.hostname),last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at,
        status=CASE WHEN passive_discovery_candidates.status='registered' THEN passive_discovery_candidates.status ELSE 'queued' END,
        next_attempt_at=CASE WHEN passive_discovery_candidates.status='registered' THEN passive_discovery_candidates.next_attempt_at ELSE NULL END`, id(), ip, mac, nodeId, clean(item.hostname) || null, at, at, at)
    saved++
  }
  return saved
}

export function mappingRows({page = 1, pageSize = 100, ...options} = {}) {
  const {where, args} = mappingFlowWhere(options)
  const total = one(`SELECT COUNT(*) count FROM network_map_pairs m ${where}`, ...args)?.count || 0
  const safePage = Math.max(1, Number(page) || 1), safeSize = Math.min(500, Math.max(10, Number(pageSize) || 100))
  const rows = all(`SELECT m.*,sn.hostname source_hostname,dn.hostname destination_hostname FROM network_map_pairs m LEFT JOIN nodes sn ON sn.id=m.source_node_id LEFT JOIN nodes dn ON dn.id=m.destination_node_id ${where} ORDER BY m.connection_count DESC,m.last_seen_at DESC,m.map_key LIMIT ? OFFSET ?`, ...args, safeSize, (safePage - 1) * safeSize).map(row => {
    // Older map rows predate the classification columns. Enrich those rows at
    // read time so the table remains useful before an administrator rebuilds
    // the map, while preserving the stored values for current rows.
    const classification = classifyNetworkFlow({
      sourceIp: row.source_ip,
      destinationIp: row.destination_ip,
      protocol: row.protocol,
      sourcePort: row.source_port,
      destinationPort: row.destination_port,
      program: row.sample_program,
      sourceNode: row.source_node_id ? {id: row.source_node_id} : null,
      destinationNode: row.destination_node_id ? {id: row.destination_node_id} : null,
    })
    return {
      ...row,
      protocol: normalizeNetworkProtocol(row.protocol),
      traffic_class: row.traffic_class || classification.trafficClass,
      traffic_scope: classification.scope,
      external:classification.external,
      // Reclassify legacy rows whose old analyzer stored a placeholder. This
      // makes existing mappings immediately show a known service after the
      // catalog or port normalization is updated.
      traffic_service: hasIdentifiedService(row.traffic_service) ? row.traffic_service : classification.service,
      classification_reason: classification.reason,
    }
  })
  const topTalkers = all(`SELECT node_id,hostname,SUM(connections) connections FROM (SELECT source_node_id node_id,COALESCE(sn.hostname,source_ip) hostname,connection_count connections FROM network_map_pairs m LEFT JOIN nodes sn ON sn.id=m.source_node_id ${where} UNION ALL SELECT destination_node_id,COALESCE(dn.hostname,destination_ip),connection_count FROM network_map_pairs m LEFT JOIN nodes dn ON dn.id=m.destination_node_id ${where}) GROUP BY node_id,hostname ORDER BY connections DESC LIMIT 20`, ...args, ...args)
  return {scopeBoundary:boundaryState(),rows, topTalkers, total: Number(total), page: safePage, pageSize: safeSize, pages: Math.ceil(Number(total) / safeSize)}
}

/**
 * Build a bounded topology projection from persisted flow, ARP, and SNMP
 * observations. The graph intentionally contains no live collection logic;
 * discovery and agents remain the producers while this endpoint only shapes
 * data for the Mapping view.
 */
export function topologyGraph({nodeId = null, maxNodes = 300, maxEdges = 700, ...options} = {}) {
  const scope = mappingScope(options)
  const {where, args} = mappingFlowWhere({nodeId, ...options}, scope)
  const inventory = all(`SELECT id,hostname,fqdn,ip,mac_address,device_type,transport,connection_mode,status,manageability,hypervisor
    FROM nodes ORDER BY hostname`)
  const byId = new Map(inventory.map(node => [node.id, node]))
  const byIp = new Map(inventory.filter(node => node.ip).map(node => [normalizedIp(node.ip), node]))
  const graphNodes = new Map()
  const graphEdges = new Map()
  const sourceCounts = {flows: 0, arp: 0, forwarding: 0}
  const roleFor = node => {
    const type = String(node?.device_type || '').toLowerCase()
    if (type === 'switch') return 'switch'
    if (type === 'router') return 'router'
    if (type === 'firewall') return 'firewall'
    if (type === 'esxi' || type === 'hypervisor' || /hypervisor/i.test(String(node?.hypervisor || ''))) return 'hypervisor'
    return 'host'
  }
  const addAsset = node => {
    if (!node) return null
    const id = `asset:${node.id}`
    if (!graphNodes.has(id)) graphNodes.set(id, {id,kind:'asset',role:roleFor(node),label:node.hostname || node.ip || node.id,address:node.ip || node.fqdn || null,hostname:node.hostname || null,deviceType:node.device_type || null,transport:node.transport || null,status:node.status || null,manageability:node.manageability || null,hypervisor:node.hypervisor || null})
    return id
  }
  const addPeer = ip => {
    const address = normalizedIp(ip)
    if (!address || !isIP(address)) return null
    const id = `peer:${address}`
    if (!graphNodes.has(id)) graphNodes.set(id, {id,kind:'peer',role:'host',label:address,address,hostname:null,deviceType:'peer',transport:null,status:'observed',manageability:'unmanaged',hypervisor:null})
    return id
  }
  const addEdge = (left, right, kind, metadata = {}) => {
    if (!left || !right || left === right) return
    const [source, target] = [left, right].sort()
    const key = `${source}|${target}|${kind}`
    const existing = graphEdges.get(key)
    if (existing) {
      existing.observations += Number(metadata.observations || 1)
      existing.weight += Number(metadata.weight || 1)
      if (!existing.port && metadata.port) existing.port = metadata.port
      if (!existing.label && metadata.label) existing.label = metadata.label
      return
    }
    graphEdges.set(key, {id:`edge:${graphEdges.size + 1}`,source,target,kind,observations:Number(metadata.observations || 1),weight:Number(metadata.weight || 1),port:metadata.port || null,label:metadata.label || null})
  }

  inventory.forEach(addAsset)
  const flowRows = all(`SELECT m.* FROM network_map_pairs m ${where}
    ORDER BY m.connection_count DESC,m.map_key LIMIT 3001`, ...args)
  for (const row of flowRows.slice(0,3000)) {
    const source = addAsset(byId.get(row.source_node_id) || byIp.get(normalizedIp(row.source_ip))) || addPeer(row.source_ip)
    const target = addAsset(byId.get(row.destination_node_id) || byIp.get(normalizedIp(row.destination_ip))) || addPeer(row.destination_ip)
    if (source && target) { addEdge(source,target,'traffic',{weight:Number(row.connection_count)||1,observations:Number(row.connection_count)||1,label:`${Number(row.connection_count)||1} flows`}); sourceCounts.flows++ }
  }

  // When the operator focuses a host, include the switch/router ARP rows that
  // point at that host as well as rows reported by the focused infrastructure
  // node. This keeps the focused graph useful in both directions without
  // moving relationship filtering into the browser.
  const arpRowsForGraph = arpRows(nodeId, 5001, {...options, graph: true})
  const arpByMac = new Map()
  for (const row of arpRowsForGraph.slice(0,5000)) {
    const source = addAsset(byId.get(row.node_id)); if (!source) continue
    const targetNode = byIp.get(normalizedIp(row.ip)), target = targetNode ? addAsset(targetNode) : addPeer(row.ip)
    if (!target) continue
    addEdge(source,target,'link',{observations:1,label:'ARP'}); sourceCounts.arp++
    const mac = String(row.mac || '').replace(/[^0-9a-f]/gi,'').toLowerCase()
    if (mac) { if (!arpByMac.has(mac)) arpByMac.set(mac, []); arpByMac.get(mac).push({nodeId:row.node_id,target}) }
  }

  // Forwarding tables belong to the reporting switch. Once ARP has narrowed
  // the target set above, reading the bounded recent snapshot window lets a
  // focused host still resolve the switch port that learned its MAC.
  for (const node of inventory) {
    const mac = String(node.mac_address || '').replace(/[^0-9a-f]/gi,'').toLowerCase()
    if (mac && (!nodeId || node.id === nodeId) && (!scope.active || scope.matches(node.ip,node.id))) {
      if (!arpByMac.has(mac)) arpByMac.set(mac, [])
      if (!arpByMac.get(mac).some(item => item.target === `asset:${node.id}`)) arpByMac.get(mac).push({target: addAsset(node)})
    }
  }
  const snapshotFilters = [], snapshotArgs = []
  if (options.from) { snapshotFilters.push('datetime(collected_at)>=datetime(?)'); snapshotArgs.push(options.from) }
  if (options.to) { snapshotFilters.push('datetime(collected_at)<=datetime(?)'); snapshotArgs.push(options.to) }
  const snapshots = all(`SELECT node_id,state_json FROM network_table_snapshots ${snapshotFilters.length ? `WHERE ${snapshotFilters.join(' AND ')}` : ''} ORDER BY collected_at DESC`, ...snapshotArgs)
  for (const snapshot of snapshots) {
    const source = addAsset(byId.get(snapshot.node_id)); if (!source) continue
    let state = {}; try { state = JSON.parse(snapshot.state_json || '{}') || {} } catch {}
    for (const entry of Array.isArray(state.macPorts) ? state.macPorts : []) {
      const mac = String(entry.mac || '').replace(/[^0-9a-f]/gi,'').toLowerCase()
      for (const match of arpByMac.get(mac) || []) {
        const targetNode = graphNodes.get(match.target)
        if (scope.active && !scope.matches(byId.get(snapshot.node_id)?.ip, snapshot.node_id) && !scope.matches(targetNode?.address, targetNode?.id?.slice(6))) continue
        const port = entry.port == null ? null : String(entry.port)
        addEdge(source,match.target,'link',{observations:1,port,label:port ? `port ${port}` : 'SNMP forwarding'}); sourceCounts.forwarding++
      }
    }
  }

  const edges = [...graphEdges.values()].sort((a,b) => b.weight - a.weight || a.id.localeCompare(b.id)).slice(0,maxEdges)
  const connected = new Set(edges.flatMap(edge => [edge.source,edge.target]))
  const candidateNodes = [...graphNodes.values()].filter(node => connected.has(node.id) || nodeId && node.id === `asset:${nodeId}` && (!scope.active || scope.matches(node.address,nodeId))).map(node => ({...node, scopeMatch: scope.active && scope.matches(node.address, node.kind === 'asset' ? node.id.slice(6) : null)})).sort((a,b) => Number(b.scopeMatch)-Number(a.scopeMatch) || `${a.role}:${a.label}`.localeCompare(`${b.role}:${b.label}`))
  const nodes = candidateNodes.slice(0,maxNodes)
  const allowed = new Set(nodes.map(node => node.id))
  const boundedEdges = edges.filter(edge => allowed.has(edge.source) && allowed.has(edge.target))
  return {nodes,edges:boundedEdges,scope:scope.summary,generatedAt:now(),truncated:flowRows.length>3000||arpRowsForGraph.length>5000||candidateNodes.length>nodes.length||graphEdges.size>edges.length,sources:sourceCounts,nodeCount:nodes.length,edgeCount:boundedEdges.length}
}

export function arpRows(nodeId = null, limit = 500, options = {}) {
  const scope = mappingScope(options), filters = [], args = []
  if (nodeId) {
    if (options.graph) { filters.push('(a.node_id=? OR a.ip=(SELECT ip FROM nodes WHERE id=?))'); args.push(nodeId,nodeId) }
    else { filters.push('a.node_id=?'); args.push(nodeId) }
  }
  if (scope.active) { const match=scope.pairSql('n.ip','a.node_id','a.ip','NULL'); filters.push(match.sql); args.push(...match.args) }
  if (options.from) { filters.push('datetime(a.observed_at)>=datetime(?)'); args.push(options.from) }
  if (options.to) { filters.push('datetime(a.observed_at)<=datetime(?)'); args.push(options.to) }
  return all(`SELECT a.*,n.hostname FROM arp_entries a JOIN nodes n ON n.id=a.node_id
    ${filters.length ? `WHERE ${filters.join(' AND ')}` : ''} ORDER BY a.observed_at DESC,a.id LIMIT ?`,
    ...args, Math.min(options.graph ? 5001 : 2000, Math.max(1, Number(limit)||500)))
}
