import test from 'node:test'
import assert from 'node:assert/strict'
import {EventEmitter} from 'node:events'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-discovery-'))
process.env.DATA_DIR=dir
const {parseNeighborTable,probeHostLiveness,tcpProbe,DISCOVERY_TCP_PORTS}=await import('../src/networkDiscovery.js')

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
