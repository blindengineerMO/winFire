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
  const modern={RecordId:1001,Id:5157,TimeCreated:new Date().toISOString(),Fields:{Protocol:'6',Direction:'%%14592',InterfaceIndex:'1',SourceAddress:'198.51.100.20',SourcePort:'49200',DestAddress:'192.0.2.10',DestPort:'3389',FilterOrigin:'{TEST-RULE}',FilterRTID:'123'}}
  if(process.env.WINFIRE_TEST_ADVANCE_CURSOR&&input.operation==='events'&&input.args.after===0){const Database=require(require.resolve('better-sqlite3',{paths:[process.cwd()]}));const db=new Database(require('path').join(process.env.DATA_DIR,'winfire.db'));db.prepare("INSERT INTO node_log_cursors(node_id,last_record_id,updated_at) VALUES('node-1',2000,CURRENT_TIMESTAMP) ON CONFLICT(node_id) DO UPDATE SET last_record_id=2000").run();db.close()}
  const result=input.operation==='events_recent'?[process.env.WINFIRE_TEST_MODERN?modern:event(1000)]:input.operation==='events'&&input.args.after===0?[event(1),event(2)]:[]
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

test('recollection repairs an older reversed inbound tuple and fills its rule origin',async()=>{
  run("INSERT INTO log_events(id,node_id,record_id,event_id,action,protocol,src_ip,src_port,dst_ip,dst_port,direction,event_type,event_time) VALUES('old-modern','node-1',1001,5157,'block','TCP','192.0.2.10',3389,'198.51.100.20',49200,'in','firewall',?)",new Date().toISOString())
  process.env.WINFIRE_TEST_MODERN='1'
  try{
    assert.equal((await pullRecentLogs('node-1',null,true)).inserted,0)
    assert.deepEqual(one('SELECT src_ip,src_port,dst_ip,dst_port,filter_origin,filter_runtime_id FROM log_events WHERE id=?','old-modern'),{src_ip:'198.51.100.20',src_port:49200,dst_ip:'192.0.2.10',dst_port:3389,filter_origin:'{TEST-RULE}',filter_runtime_id:'123'})
  }finally{delete process.env.WINFIRE_TEST_MODERN}
})

test('a concurrent collector cannot move the history cursor backward',async()=>{
  run("DELETE FROM node_log_cursors WHERE node_id='node-1'")
  process.env.WINFIRE_TEST_ADVANCE_CURSOR='1'
  try{
    await pullLogs('node-1',null,1,true)
    assert.equal(one("SELECT last_record_id FROM node_log_cursors WHERE node_id='node-1'").last_record_id,2000)
  }finally{delete process.env.WINFIRE_TEST_ADVANCE_CURSOR}
})
