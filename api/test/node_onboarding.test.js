import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-onboarding-test-'))
process.env.DATA_DIR=dataDir
const {onboardPendingNodes}=await import('../src/app.js')
const {db}=await import('../src/db.js')
test.after(()=>{db.close();fs.rmSync(dataDir,{recursive:true,force:true})})

test('AD node onboarding collects facts, enables auditing, and starts event collection once',async()=>{
  db.prepare("INSERT INTO nodes(id,hostname,fqdn,inventory_source,ad_guid,ad_enabled,ad_missing) VALUES(?,?,?,?,?,1,0)").run('new-ad-node','AD-NODE','ad-node.example.test','ad','ad-guid')
  db.prepare("INSERT INTO credentials(id,name,type,username,encrypted_blob) VALUES(?,?,?,?,?)").run('cred','Domain account','domain','EXAMPLE\\user','unused-by-mock')
  db.prepare('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)').run('cred','new-ad-node')
  const calls=[]
  const handlers={
    resolveDns:async node=>{calls.push('dns');db.prepare('UPDATE nodes SET ip=? WHERE id=?').run('192.0.2.10',node.id)},
    enrich:async node=>{calls.push('facts');db.prepare("UPDATE nodes SET transport='winrm',status='reachable' WHERE id=?").run(node.id);db.prepare('INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?)').run(node.id,'{}',new Date().toISOString())},
    invoke:async(_node,operation)=>{calls.push(operation);return operation==='audit_policy'?{successEnabled:false,failureEnabled:false}:{successEnabled:true,failureEnabled:true}},
    pullRecent:async()=>{calls.push('recent');return {inserted:2}},
    pullHistory:async()=>{calls.push('history');return {inserted:3,caughtUp:false}}
  }
  assert.deepEqual(await onboardPendingNodes(5,handlers),[{nodeId:'new-ad-node',status:'complete'}])
  assert.equal(db.prepare("SELECT status FROM policy_apply_runs WHERE node_id='new-ad-node' ORDER BY rowid DESC LIMIT 1").get().status,'success')
  assert.deepEqual(calls,['dns','facts','audit_policy','audit_policy_enable','recent','history'])
  assert.equal(db.prepare('SELECT ip FROM nodes WHERE id=?').get('new-ad-node').ip,'192.0.2.10')
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE entity_id=? AND action='node.onboarding.complete'").get('new-ad-node').n,1)
  assert.deepEqual(await onboardPendingNodes(5,handlers),[])
})
