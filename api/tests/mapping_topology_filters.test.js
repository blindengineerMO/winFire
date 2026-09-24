import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-topology-filters-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@mapping.test'
process.env.BOOTSTRAP_PASSWORD='mapping-test-password'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db,run,now}=await import('../src/db.js')
const {mappingRows,topologyGraph,arpRows}=await import('../src/services/networkMapping.js')
const {subnetMatcher}=await import('../src/services/mappingScope.js')
await bootstrap()
run("INSERT OR REPLACE INTO app_settings(key,value) VALUES('local_asset_cidrs',?)",JSON.stringify(['10.0.0.0/8','fc00::/7']))
const request=supertest(app)
const login=await request.post('/api/v1/auth/login').send({email:process.env.BOOTSTRAP_EMAIL,password:process.env.BOOTSTRAP_PASSWORD})
const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})
for(const [id,ip,type,mac] of [
  ['switch-a','10.0.0.1','switch',null],['switch-b','10.0.1.1','switch',null],
  ['a','10.10.0.20','auto',null],['b','10.20.0.20','auto',null],
  ['inventory-only','10.10.0.21','auto','AA-BB-CC-DD-EE-21'],
  ['peer','10.30.0.20','auto',null],['v6','fd00:abcd::5','auto',null]
])run('INSERT INTO nodes(id,hostname,ip,device_type,mac_address) VALUES(?,?,?,?,?)',id,id,ip,type,mac)
function arp(id,collector,ip,mac){run('INSERT INTO arp_entries(id,node_id,ip,mac,source,observed_at) VALUES(?,?,?,?,?,?)',id,collector,ip,mac,'snmp',now())}
arp('a-arp','switch-b','10.10.0.20','aa:bb:cc:dd:ee:20')
arp('a-peer','switch-a','10.20.0.20','aa:bb:cc:dd:ee:30')
arp('unrelated','switch-b','10.30.0.20','aa:bb:cc:dd:ee:40')
run('INSERT INTO network_table_snapshots(node_id,state_json,collected_at) VALUES(?,?,?)','switch-a',JSON.stringify({macPorts:[{mac:'AA-BB-CC-DD-EE-20',port:4},{mac:'aa:bb:cc:dd:ee:21',port:5}]}),now())
function flow(key,src,dst,count=1,external=0,at=now()){
  const source=db.prepare('SELECT ip FROM nodes WHERE id=?').get(src)?.ip||src,destination=db.prepare('SELECT ip FROM nodes WHERE id=?').get(dst)?.ip||dst
  run('INSERT INTO network_map_pairs(map_key,source_node_id,destination_node_id,source_ip,destination_ip,protocol,external,traffic_class,connection_count,first_seen_at,last_seen_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',key,isNode(src)?src:null,isNode(dst)?dst:null,source,destination,'TCP',external,external?'public-unicast':'node-to-node',count,at,at,at)
}
function isNode(id){return !!db.prepare('SELECT id FROM nodes WHERE id=?').get(id)}
flow('a-peer','a','peer',3)
flow('b-peer','b','peer',5)
flow('inventory-peer','inventory-only','peer',7)
flow('unrelated','peer','switch-b',500)
flow('a-internet','a','8.8.8.8',11,1)
flow('ipv6','v6','peer',13)

test('CIDRs support IPv4, IPv6 and exact boundaries, and reject invalid prefixes',()=>{
  assert.equal(subnetMatcher('10.10.0.99/24')('10.10.0.255'),true)
  assert.equal(subnetMatcher('10.10.0.0/24')('10.10.1.0'),false)
  assert.equal(subnetMatcher('fd00:abcd::/64')('fd00:abcd::5'),true)
  assert.equal(subnetMatcher('fd00:abcd::/128')('fd00:abcd::5'),false)
  for(const cidr of ['garbage','10.1.0.0/-1','10.1.0.0/33','fd00::/129','10.1.0.0/','10.1.0.0/24/1'])assert.throws(()=>subnetMatcher(cidr))
})

test('switch filters correlate remote ARP and inventory MACs without following traffic peers',()=>{
  const result=mappingRows({switchId:'switch-a'})
  assert.deepEqual(result.rows.map(row=>row.map_key).sort(),['a-internet','a-peer','b-peer','inventory-peer'])
  assert.equal(result.total,4)
  assert.equal(result.topTalkers.find(item=>item.node_id==='peer').connections,15)
  assert.equal(result.topTalkers.some(item=>item.node_id==='switch-b'),false)
  const combined=mappingRows({switchId:'switch-a',subnet:'10.10.0.0/24',external:'0'})
  assert.deepEqual(combined.rows.map(row=>row.map_key).sort(),['a-peer','inventory-peer'])
  // Different endpoints satisfying different filters must not count as a match.
  assert.equal(mappingRows({switchId:'switch-a',subnet:'10.30.0.0/24'}).total,0)
  assert.deepEqual(arpRows(null,500,{switchId:'switch-a',subnet:'10.10.0.0/24'}).map(row=>row.id),['a-arp'])
})

test('topology highlights matches and keeps boundary peers and learned switch ports',()=>{
  const graph=topologyGraph({switchId:'switch-a',subnet:'10.10.0.0/24'})
  assert.equal(graph.nodes.find(node=>node.id==='asset:a').scopeMatch,true)
  assert.equal(graph.nodes.find(node=>node.id==='asset:peer').scopeMatch,false)
  assert.equal(graph.nodes.find(node=>node.id==='peer:8.8.8.8').scopeMatch,false)
  assert.equal(graph.nodes.some(node=>node.id==='asset:b'),false)
  assert.ok(graph.edges.some(edge=>edge.port==='4'))
  assert.ok(graph.edges.some(edge=>edge.port==='5'))
  assert.equal(graph.edges.some(edge=>edge.weight===500),false)
  assert.equal(graph.scope.switchName,'switch-a')
  const empty=topologyGraph({subnet:'172.16.1.0/24'})
  assert.deepEqual(empty.nodes,[])
  assert.deepEqual(empty.edges,[])
  assert.equal(mappingRows({subnet:'fd00:abcd::/64'}).total,1)
})

test('API filters intersect before pagination and totals and enforce validation',async()=>{
  for(let i=0;i<12;i++)flow(`page-${i}`,'a','peer',20+i)
  const query={switchId:'switch-a',subnet:'10.10.0.0/24',external:'0',pageSize:10}
  const first=await auth(request.get('/api/v1/mapping').query({...query,page:1})).expect(200)
  const second=await auth(request.get('/api/v1/mapping').query({...query,page:2})).expect(200)
  assert.equal(first.body.total,14)
  assert.equal(first.body.rows.length,10)
  assert.equal(second.body.rows.length,4)
  assert.equal(new Set([...first.body.rows,...second.body.rows].map(row=>row.map_key)).size,14)
  for(const endpoint of ['/mapping','/mapping/topology','/mapping/arp']){
    await auth(request.get(`/api/v1${endpoint}`).query({subnet:'10.0.0.0/45'})).expect(400)
    await auth(request.get(`/api/v1${endpoint}`).query({switchId:'missing'})).expect(400)
    await auth(request.get(`/api/v1${endpoint}`).query({switchId:'a'})).expect(400)
    await auth(request.get(`/api/v1${endpoint}`).query({from:'garbage'})).expect(400)
    await auth(request.get(`/api/v1${endpoint}`).query({from:'2026-01-02',to:'2026-01-01'})).expect(400)
  }
  const graph=await auth(request.get('/api/v1/mapping/topology').query({subnet:'10.10.0.0/24',external:'1'})).expect(200)
  assert.equal(graph.body.edges.filter(edge=>edge.kind==='traffic').length,1)
  const dated=await auth(request.get('/api/v1/mapping').query({from:'2000-01-01',to:'2001-01-01',subnet:'10.10.0.0/24'})).expect(200)
  assert.equal(dated.body.total,0)
  await request.get('/api/v1/mapping/filter-options').expect(401)
  const options=await auth(request.get('/api/v1/mapping/filter-options')).expect(200)
  assert.deepEqual(options.body.switches.map(item=>item.id),['switch-a','switch-b'])
})
