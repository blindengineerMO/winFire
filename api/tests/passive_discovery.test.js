import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-passive-discovery-'))
process.env.DATA_DIR=dir
const {db}=await import('../src/db.js')
const {recordArpEntries}=await import('../src/services/networkMapping.js')
const {passiveDiscoverySummary,processPassiveDiscovery}=await import('../src/passiveDiscovery.js')
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('passive candidates are processed through normal registration and become idempotent',async()=>{
  db.prepare("INSERT INTO nodes(id,hostname,ip,status) VALUES(?,?,?,?)").run('managed-source','MANAGED-SOURCE','192.0.2.10','reachable')
  recordArpEntries('managed-source',[{ip:'192.0.2.20',mac:'00:11:22:33:44:55'}])
  db.prepare("INSERT INTO nodes(id,hostname,ip,status) VALUES(?,?,?,?)").run('new-node','NEW-NODE','192.0.2.20','reachable')
  assert.deepEqual(passiveDiscoverySummary(),{queued:1,processing:0,registered:0,failed:0,total:1})
  const result=await processPassiveDiscovery({register:async(ip,scanId,method)=>({ip,nodeId:'new-node',scanId,method})})
  assert.equal(result.processed,1)
  assert.deepEqual(passiveDiscoverySummary(),{queued:0,processing:0,registered:1,failed:0,total:1})
  const row=db.prepare('SELECT status,node_id,last_error FROM passive_discovery_candidates WHERE ip=?').get('192.0.2.20')
  assert.deepEqual(row,{status:'registered',node_id:'new-node',last_error:null})
  const second=await processPassiveDiscovery({register:async()=>{throw new Error('should not run')}})
  assert.equal(second.processed,0)
})

test('failed passive registration is retried with a bounded schedule',async()=>{
  recordArpEntries('managed-source',[{ip:'192.0.2.21',mac:'00:11:22:33:44:66'}])
  const result=await processPassiveDiscovery({register:async()=>{throw new Error('temporary DNS failure')}})
  assert.equal(result.processed,1)
  const row=db.prepare('SELECT status,attempts,next_attempt_at,last_error FROM passive_discovery_candidates WHERE ip=?').get('192.0.2.21')
  assert.equal(row.status,'queued')
  assert.equal(row.attempts,1)
  assert.match(row.next_attempt_at,/T/)
  assert.equal(row.last_error,'temporary DNS failure')
})
