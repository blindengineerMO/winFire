import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-log-catchup-'))
process.env.DATA_DIR=dataDir
const stub=path.join(dataDir,'collector-stub')
fs.writeFileSync(stub,`#!/usr/bin/env node
let body='';process.stdin.on('data',part=>body+=part);process.stdin.on('end',()=>{
  const input=JSON.parse(body)
  const event=recordId=>({RecordId:recordId,Id:5156,TimeCreated:new Date(Date.now()-(1000-recordId)*1000).toISOString(),Fields:{Protocol:'6',Direction:'%%14593',SourceAddress:'192.0.2.10',SourcePort:'49152',DestAddress:'198.51.100.20',DestPort:'443',Application:'test.exe'}})
  const result=input.operation==='events_recent'?[event(1000)]:input.operation==='events'&&input.args.after===0?[event(1),event(2)]:[]
  process.stdout.write(JSON.stringify(result))
})
`,{mode:0o700})
process.env.WINRM_PYTHON=stub
const {db,one,run}=await import('../src/db.js')
const {seal}=await import('../src/security.js')
const {pullRecentLogs,pullLogs}=await import('../src/app.js')
test.after(()=>{db.close();fs.rmSync(dataDir,{recursive:true,force:true})})

test('recent firewall events appear immediately while the history cursor retains its backlog',async()=>{
  run("INSERT INTO nodes(id,hostname,ip,transport) VALUES('node-1','TEST','192.0.2.10','winrm')")
  run("INSERT INTO credentials(id,name,type,username,encrypted_blob) VALUES('cred-1','test','domain','user',?)",seal({password:'secret'}))
  run("INSERT INTO credential_assignments(credential_id,node_id) VALUES('cred-1','node-1')")
  const recent=await pullRecentLogs('node-1',null,true)
  assert.equal(recent.inserted,1)
  assert.equal(one('SELECT MAX(record_id) value FROM log_events').value,1000)
  const history=await pullLogs('node-1',null,1,true)
  assert.equal(history.inserted,2)
  assert.equal(history.lastRecordId,2)
  assert.deepEqual(db.prepare('SELECT record_id FROM log_events ORDER BY record_id').all().map(row=>row.record_id),[1,2,1000])
  assert.equal((await pullRecentLogs('node-1',null,true)).inserted,0)
})
