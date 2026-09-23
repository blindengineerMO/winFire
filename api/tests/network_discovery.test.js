import test from 'node:test'
import assert from 'node:assert/strict'
import {EventEmitter} from 'node:events'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-discovery-'))
process.env.DATA_DIR=dir
const {parseNeighborTable,parsePingTtl,classifyTtl,probeHostLiveness,tcpProbe,DISCOVERY_TCP_PORTS}=await import('../src/networkDiscovery.js')
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
  assert.equal(classifyInfrastructureResponse({port:443,body:'VMware ESXi Host Client'}).hypervisorName,'VMware ESXi')
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
