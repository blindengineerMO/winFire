import test from 'node:test'
import assert from 'node:assert/strict'
import {EventEmitter} from 'node:events'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-discovery-'))
process.env.DATA_DIR=dir
const {parseNeighborTable,parsePingTtl,classifyTtl,probeHostLiveness,tcpProbe,DISCOVERY_TCP_PORTS,persistHypervisor}=await import('../src/networkDiscovery.js')
const {ensureSnmpNode}=await import('../src/snmpDiscoveryService.js')
const {topologyGraph}=await import('../src/services/networkMapping.js')
const {run,one,id,now}=await import('../src/db.js')
const {classifyInfrastructureResponse,classifyOperatingSystem}=await import('../src/infrastructureDiscovery.js')

test.after(()=>fs.rmSync(dir,{recursive:true,force:true}))

test('parses Linux, macOS and Windows ARP output only when the target has a MAC',()=>{
  assert.equal(parseNeighborTable('192.168.88.201 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE','192.168.88.201'),true)
  assert.equal(parseNeighborTable('? (192.168.88.202) at aa-bb-cc-dd-ee-ff on en0 ifscope [ethernet]','192.168.88.202'),true)
  assert.equal(parseNeighborTable('Interface: 192.168.88.1 ---\n  192.168.88.203    00-11-22-33-44-55     dynamic','192.168.88.203'),true)
  assert.equal(parseNeighborTable('192.168.88.204 dev eth0 INCOMPLETE','192.168.88.204'),false)
  assert.equal(parseNeighborTable('192.168.88.205 dev eth0 lladdr 00:00:00:00:00:00 FAILED','192.168.88.205'),false)
})

test('liveness falls back from ICMP to ARP and then bounded management ports',async()=>{
  const arp=await probeHostLiveness('192.168.88.201',{icmpProbe:async()=>false,arpLivenessProbe:async()=>true,tcpLivenessProbe:async()=>false})
  assert.deepEqual(arp,{alive:true,method:'arp'})
  const tcp=await probeHostLiveness('10.20.0.7',{icmpProbe:async()=>false,arpLivenessProbe:async()=>false,tcpLivenessProbe:async(_host,port)=>port===5985})
  assert.deepEqual(tcp,{alive:true,method:'tcp:5985'})
  const dead=await probeHostLiveness('10.20.0.8',{icmpProbe:async()=>false,arpLivenessProbe:async()=>false,tcpLivenessProbe:async()=>false})
  assert.deepEqual(dead,{alive:false,method:null})
  assert.deepEqual(DISCOVERY_TCP_PORTS,[445,3389,5985,5986])
})

test('ICMP TTL fingerprints common operating system families',async()=>{
  assert.equal(parsePingTtl('64 bytes from 10.0.0.4: icmp_seq=1 ttl=64 time=1.2 ms'),64)
  assert.deepEqual(classifyTtl(63),{family:'linux-unix',osName:'Linux / Unix',initialTtl:64})
  assert.deepEqual(classifyTtl(127),{family:'windows',osName:'Windows',initialTtl:128})
  assert.deepEqual(classifyTtl(254),{family:'network-device',osName:'Network device',initialTtl:255})
  const result=await probeHostLiveness('10.0.0.5',{icmpProbe:async()=>({alive:true,ttl:127,osHint:'Windows',ttlFingerprint:classifyTtl(127)})})
  assert.deepEqual(result,{alive:true,method:'icmp',ttl:127,osHint:'Windows',ttlFingerprint:{family:'windows',osName:'Windows',initialTtl:128}})
})

test('bounded infrastructure fingerprints and Windows release labels are conservative',()=>{
  const esxi=classifyInfrastructureResponse({port:443,body:'VMware ESXi Host Client'})
  assert.equal(esxi.hypervisorName,'VMware ESXi')
  assert.deepEqual(esxi.classificationEvidence,{source:'infrastructure-discovery',method:'https-fingerprint',matched:'VMware ESXi',signal:'https/443',confidence:'high'})
  assert.equal(classifyInfrastructureResponse({port:8006,body:'pve-manager Proxmox Virtual Environment'}).hypervisorName,'Proxmox VE')
  assert.equal(classifyInfrastructureResponse({port:443,body:'Citrix Hypervisor XenServer'}).hypervisorName,'Citrix Hypervisor / XenServer')
  assert.equal(classifyInfrastructureResponse({port:443,body:'ordinary web server'}),null)
  assert.equal(classifyOperatingSystem({caption:'Windows 11 IoT Enterprise',version:'10.0.26100',build:'26100'}),'Windows 11 IoT Enterprise · 24H2')
})

test('TCP liveness treats an established connection and an explicit reset as alive',async()=>{
  const connected=await tcpProbe('127.0.0.1',443,100,()=>{
    const socket=new EventEmitter();socket.destroy=()=>{};queueMicrotask(()=>socket.emit('connect'));return socket
  })
  assert.equal(connected,true)
  const refused=await tcpProbe('127.0.0.1',443,100,()=>{
    const socket=new EventEmitter();socket.destroy=()=>{};queueMicrotask(()=>socket.emit('error',{code:'ECONNREFUSED'}));return socket
  })
  assert.equal(refused,true)
  const timeout=await tcpProbe('127.0.0.1',443,5,()=>{const socket=new EventEmitter();socket.destroy=()=>{};return socket})
  assert.equal(timeout,false)
})

test('authenticated ESXi guest inventory marks matching assets as virtual machines',()=>{
  const hypervisorId=id(),guestId=id()
  run('INSERT INTO nodes(id,hostname,ip,connection_mode,status) VALUES(?,?,?,?,?)',hypervisorId,'esxi-01','192.168.88.3','agentless','reachable')
  run('INSERT INTO nodes(id,hostname,fqdn,ip,connection_mode,status) VALUES(?,?,?,?,?,?)',guestId,'web-01','web-01.example.test','192.168.88.42','agentless','reachable')
  persistHypervisor(hypervisorId,{detected:true,authenticated:true,api:'soap',osName:'VMware ESXi',hypervisor:'VMware ESXi',virtualMachines:[{name:'web-01',uuid:'uuid-42',ip:'192.168.88.42',hostname:'web-01.example.test',guestOs:'Ubuntu Linux (64-bit)',powerState:'poweredOn',cpuCount:4,memoryMb:8192}]})
  const guest=one('SELECT virtual_machine,virtual_machine_host_id,virtual_machine_details_json FROM nodes WHERE id=?',guestId)
  assert.equal(guest.virtual_machine,1)
  assert.equal(guest.virtual_machine_host_id,hypervisorId)
  assert.equal(JSON.parse(guest.virtual_machine_details_json).hypervisorHost,'esxi-01')
  const facts=JSON.parse(one('SELECT snapshot_json FROM node_facts WHERE node_id=?',hypervisorId).snapshot_json)
  const persisted=one('SELECT vendor,classification_evidence_json FROM nodes WHERE id=?',hypervisorId)
  assert.equal(persisted.vendor,'VMware ESXi')
  assert.equal(JSON.parse(persisted.classification_evidence_json).matched,'VMware ESXi')
  const hypervisor=one('SELECT device_type,management_type,transport,manageability,snmp_capable FROM nodes WHERE id=?',hypervisorId)
  assert.equal(hypervisor.device_type,'esxi')
  assert.equal(hypervisor.management_type,'api')
  assert.equal(facts.virtualMachines[0].guestOs,'Ubuntu Linux (64-bit)')
})

test('SNMP enrichment preserves an authenticated ESXi SOAP/API transport and VM facts',()=>{
  const hostId=id()
  run("INSERT INTO nodes(id,hostname,ip,connection_mode,status,device_type,transport,management_type,probe_status,os_name,os_version) VALUES(?,?,?,?,?,?,?,?,?,?,?)",hostId,'esxi-02','192.168.88.4','agentless','reachable','esxi','esxi-soap','api','hypervisor-authenticated','VMware ESXi','VMware ESXi 8.0.3 build-24677879')
  run("INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?)",hostId,JSON.stringify({source:'esxi-soap',virtualMachines:[{name:'guest-01'}]}),now())
  ensureSnmpNode({host:'192.168.88.4',source:'snmp:test'},{identity:{sysName:'esxi-02',sysDescr:'VMware ESXi 8.0.3'},classification:{vendor:'VMware ESXi',hypervisor:'VMware ESXi',deviceType:'hypervisor',manageability:'unmanaged'},arp:[{ip:'192.168.88.42'}],macPorts:[],routes:{},tcpStates:{}},now())
  const node=one('SELECT connection_mode,transport,management_type,probe_status,os_name,os_version FROM nodes WHERE id=?',hostId)
  assert.deepEqual(node,{connection_mode:'agentless',transport:'esxi-soap',management_type:'api',probe_status:'hypervisor-authenticated',os_name:'VMware ESXi',os_version:'VMware ESXi 8.0.3 build-24677879'})
  const facts=JSON.parse(one('SELECT snapshot_json FROM node_facts WHERE node_id=?',hostId).snapshot_json)
  assert.equal(facts.virtualMachines[0].name,'guest-01')
  assert.equal(facts.arp[0].ip,'192.168.88.42')
})

test('topology graph correlates flow, ARP, and SNMP forwarding observations',()=>{
  const switchId=id(),hostId=id()
  run("INSERT INTO nodes(id,hostname,ip,connection_mode,status,device_type,transport) VALUES(?,?,?,?,?,?,?)",switchId,'core-switch','192.168.88.1','snmp','reachable','switch','snmp')
  run("INSERT INTO nodes(id,hostname,ip,connection_mode,status,device_type,transport) VALUES(?,?,?,?,?,?,?)",hostId,'workstation-01','192.168.88.20','agentless','reachable','other','ssh')
  run("INSERT INTO arp_entries(id,node_id,ip,mac,interface,state,source,observed_at) VALUES(?,?,?,?,?,?,?,?)",id(),switchId,'192.168.88.20','00:11:22:33:44:55','12','reachable','snmp',now())
  run("INSERT INTO network_table_snapshots(node_id,arp_json,state_json,source,collected_at) VALUES(?,?,?,?,?)",switchId,'[]',JSON.stringify({macPorts:[{mac:'00:11:22:33:44:55',port:12}]}),'snmp',now())
  run("INSERT INTO network_map_pairs(map_key,source_node_id,destination_node_id,source_ip,destination_ip,protocol,direction,external,connection_count,first_seen_at,last_seen_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",`topology-${switchId}`,switchId,hostId,'192.168.88.1','192.168.88.20','TCP','out',0,8,now(),now(),now())
  const graph=topologyGraph({maxNodes:50,maxEdges:50})
  assert.equal(graph.nodes.find(node=>node.id===`asset:${switchId}`).role,'switch')
  assert.equal(graph.nodes.find(node=>node.id===`asset:${hostId}`).label,'workstation-01')
  assert.ok(graph.edges.some(edge=>edge.kind==='traffic'&&edge.weight===8))
  assert.ok(graph.edges.some(edge=>edge.kind==='link'&&edge.port==='12'))
  assert.equal(typeof graph.truncated,'boolean')
  const focused=topologyGraph({nodeId:hostId,maxNodes:50,maxEdges:50})
  assert.ok(focused.nodes.some(node=>node.id===`asset:${switchId}`),'focused host graph keeps its reporting switch')
  assert.ok(focused.edges.some(edge=>edge.kind==='link'&&edge.port==='12'),'focused host graph keeps the learned switch port')
})
