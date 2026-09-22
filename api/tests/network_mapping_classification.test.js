import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'winfire-mapping-'))
process.env.DATA_DIR = dir
const {classifyNetworkFlow} = await import('../src/services/networkMapping.js')

test.after(() => fs.rmSync(dir, {recursive: true, force: true}))

test('mDNS multicast is internal and explains why it is not Internet traffic', () => {
  const result = classifyNetworkFlow({
    sourceIp: '192.168.88.10', destinationIp: '224.0.0.251', protocol: 'UDP',
    sourcePort: 5353, destinationPort: 5353,
    sourceNode: {id: 'springfield'}, destinationNode: null,
  })
  assert.equal(result.trafficClass, 'multicast')
  assert.equal(result.scope, 'internal')
  assert.equal(result.external, 0)
  assert.equal(result.service, 'mDNS service discovery')
  assert.match(result.reason, /multicast group/)
})

test('broadcast, link-local, loopback and IPv6 multicast have local scope', () => {
  assert.equal(classifyNetworkFlow({sourceIp: '192.168.88.10', destinationIp: '255.255.255.255', protocol: 'UDP', destinationPort: 137}).trafficClass, 'broadcast')
  assert.equal(classifyNetworkFlow({sourceIp: '169.254.10.2', destinationIp: '169.254.255.255', protocol: 'UDP'}).scope, 'internal')
  assert.equal(classifyNetworkFlow({sourceIp: '127.0.0.1', destinationIp: '127.0.0.1', protocol: 'TCP', destinationPort: 3000}).scope, 'host-local')
  const ipv6 = classifyNetworkFlow({sourceIp: 'fe80::1', destinationIp: 'ff02::fb', protocol: 'UDP', destinationPort: 5353})
  assert.equal(ipv6.trafficClass, 'multicast')
  assert.equal(ipv6.scope, 'internal')
})

test('private node pairs and public peers are separated by scope', () => {
  const internal = classifyNetworkFlow({sourceIp: '10.0.0.4', destinationIp: '192.168.88.10', protocol: 'TCP', destinationPort: 445, sourceNode: {id: 'a'}, destinationNode: {id: 'b'}})
  assert.equal(internal.trafficClass, 'node-to-node')
  assert.equal(internal.scope, 'internal')
  assert.equal(internal.service, 'SMB file or management traffic')
  const external = classifyNetworkFlow({sourceIp: '192.168.88.10', destinationIp: '203.0.113.5', protocol: 'TCP', destinationPort: 443})
  assert.equal(external.scope, 'unknown')
  assert.equal(external.trafficClass, 'special-purpose')
  const publicInternet = classifyNetworkFlow({sourceIp: '192.168.88.10', destinationIp: '8.8.8.8', protocol: 'UDP', destinationPort: 53})
  assert.equal(publicInternet.scope, 'external')
  assert.equal(publicInternet.service, 'DNS name resolution')
})

test('well-known ports identify common services for mapping and event analysis', () => {
  const cases = [
    ['TCP', 443, 'HTTPS web traffic'],
    ['TCP', 80, 'HTTP web traffic'],
    ['UDP', 53, 'DNS name resolution'],
    ['TCP', 53, 'DNS name resolution'],
    ['TCP', 389, 'LDAP directory access'],
    ['TCP', 636, 'LDAPS secure directory access'],
    ['TCP', 445, 'SMB file or management traffic'],
    ['TCP', 3389, 'RDP remote desktop'],
    ['TCP', 5985, 'WinRM management over HTTP'],
    ['TCP', 5986, 'WinRM management over HTTPS'],
    ['TCP', 3268, 'Active Directory Global Catalog'],
    ['TCP', 5432, 'PostgreSQL database'],
    ['TCP', 3306, 'MySQL database'],
  ]
  for (const [protocol, port, service] of cases) {
    const result = classifyNetworkFlow({sourceIp: '192.168.88.10', destinationIp: '10.0.0.20', protocol, destinationPort: port})
    assert.equal(result.service, service, `${protocol}/${port}`)
  }
  assert.equal(classifyNetworkFlow({sourceIp: '8.8.8.8', destinationIp: '192.168.88.10', protocol: '6', destinationPort: 443}).service, 'HTTPS web traffic')
  assert.equal(classifyNetworkFlow({sourceIp: '10.0.0.20', destinationIp: '192.168.88.10', protocol: 'UDP', sourcePort: 443}).service, 'HTTP/3 (QUIC) web traffic')
  assert.equal(classifyNetworkFlow({sourceIp: '192.168.88.10', destinationIp: '224.0.0.1', protocol: '2'}).trafficClass, 'multicast')
})
