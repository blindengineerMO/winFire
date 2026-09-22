import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'
import {randomUUID} from 'node:crypto'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-wef-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@wef.test'
process.env.BOOTSTRAP_PASSWORD='wef-owner-password-123'
process.env.WEF_SHARED_SECRET='wef-test-secret'
process.env.PUBLIC_BASE_URL='https://control.test'
process.env.AUTH_RATE_LIMIT='100'
const {app}=await import('../src/app.js')
const {db}=await import('../src/db.js')
const {bootstrap}=await import('../src/security.js')
const {parseWefEvents,wefNodeToken,wefSubscriptionUrl}=await import('../src/wefReceiver.js')
const request=supertest(app)
await bootstrap()
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

const eventXml=(recordId=44)=>`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>5157</EventID><TimeCreated SystemTime="2026-09-21T12:00:00.000Z"/><EventRecordID>${recordId}</EventRecordID></System><EventData><Data Name="Protocol">6</Data><Data Name="Direction">%%14592</Data><Data Name="InterfaceIndex">12</Data><Data Name="SourceAddress">192.0.2.4</Data><Data Name="SourcePort">51111</Data><Data Name="DestAddress">192.0.2.50</Data><Data Name="DestPort">3389</Data><Data Name="Application">C:\\Windows\\System32\\svchost.exe</Data></EventData></Event>`

test('WEF parser normalizes namespaced events and rejects unsafe XML',()=>{
  const parsed=parseWefEvents(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>${eventXml(77)}</s:Body></s:Envelope>`)
  assert.equal(parsed[0].RecordId,77)
  assert.equal(parsed[0].Id,5157)
  assert.equal(parsed[0].TimeCreated,'2026-09-21T12:00:00.000Z')
  assert.equal(parsed[0].Fields.DestPort,'3389')
  assert.throws(()=>parseWefEvents('<!DOCTYPE foo [<!ENTITY x "y">]>'+eventXml()),/DOCTYPE/)
  assert.equal(wefNodeToken('secret','node').length>20,true)
  assert.match(wefSubscriptionUrl('https://control.test','secret','node'),/token=/)
})

test('authenticated WEF push inserts events and returns a SOAP acknowledgement',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@wef.test',password:'wef-owner-password-123'}).expect(200)
  const authorization=`Bearer ${login.body.accessToken}`
  await request.patch('/api/v1/settings/wef').set('Authorization',authorization).send({enabled:true}).expect(200)
  const nodeId=randomUUID()
  db.prepare("INSERT INTO nodes(id,hostname,ip,transport,status,connection_mode) VALUES(?,?,?,?,?,'agentless')").run(nodeId,'WEF-SOURCE','192.0.2.50','winrm','reachable')
  const token=wefNodeToken(process.env.WEF_SHARED_SECRET,nodeId)
  const response=await request.post(`/api/v1/wef/wsman?node=${nodeId}&token=${encodeURIComponent(token)}`).set('content-type','application/soap+xml').send(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>${eventXml()}</s:Body></s:Envelope>`).expect(200)
  assert.match(response.text,/EventsResponse/)
  assert.deepEqual(db.prepare('SELECT event_id,src_ip,dst_port FROM log_events WHERE node_id=?').get(nodeId),{event_id:5157,src_ip:'192.0.2.4',dst_port:3389})
  await request.post(`/api/v1/wef/wsman?node=${nodeId}&token=wrong`).set('content-type','application/soap+xml').send(eventXml(45)).expect(401)
  await request.post(`/api/v1/wef/wsman?node=${nodeId}&token=${encodeURIComponent(token)}`).set('content-type','application/soap+xml').send('<Envelope/>').expect(400)
})

test('administrator can store an encrypted WEF secret when environment configuration is absent',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@wef.test',password:'wef-owner-password-123'}).expect(200)
  const authorization=`Bearer ${login.body.accessToken}`
  const previous=process.env.WEF_SHARED_SECRET
  const previousPublic=process.env.PUBLIC_BASE_URL
  delete process.env.WEF_SHARED_SECRET
  delete process.env.PUBLIC_BASE_URL
  try{
    const saved=await request.patch('/api/v1/settings/wef').set('Authorization',authorization).send({enabled:false,sharedSecret:'administration-secret'}).expect(200)
    assert.equal(saved.body.secretConfigured,true)
    assert.equal(saved.body.secretSource,'administration')
    const server=await request.patch('/api/v1/settings/server').set('Authorization',authorization).send({fqdn:'control.example.test',publicBaseUrl:'https://control.example.test'}).expect(200)
    assert.equal(server.body.fqdn,'control.example.test')
    assert.equal(server.body.publicBaseUrl,'https://control.example.test')
  }finally{process.env.WEF_SHARED_SECRET=previous;process.env.PUBLIC_BASE_URL=previousPublic}
})
