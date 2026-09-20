import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'
import {validateExportDestination,syslogFrame,exportSelectedEvents} from '../src/eventExport.js'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-export-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@event-export.test'
process.env.BOOTSTRAP_PASSWORD='event-export-test-password'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('event destination validation and syslog TLS framing',()=>{
  assert.equal(validateExportDestination('syslog_tls','logs.example.test:6514'),'logs.example.test:6514')
  assert.throws(()=>validateExportDestination('syslog_tls','logs.example.test:0'),/hostname and port/)
  assert.throws(()=>validateExportDestination('splunk_hec','http://splunk.example.test/services/collector/event'),/HTTPS/)
  assert.throws(()=>validateExportDestination('splunk_hec','https://splunk.example.test/other'),/collector\/event/)
  const frame=syslogFrame({id:'event-1',event_time:'2026-09-20T00:00:00.000Z',event_id:5157})
  const [length,message]=frame.match(/^(\d+) (.*)$/s).slice(1)
  assert.equal(Buffer.byteLength(message),Number(length))
  assert.match(message,/WinFire.*5157/)
})

test('Splunk HEC export sends only chosen events with token in header',async()=>{
  const event={id:'chosen',hostname:'srv01',event_time:'2026-09-20T00:00:00.000Z',event_id:5157}
  let captured
  const result=await exportSelectedEvents({kind:'splunk_hec',endpoint:'https://splunk.example.test/services/collector/event'},[event],'test-token',{fetchImpl:async(url,options)=>{captured={url,options};return {ok:true,status:200,json:async()=>({code:0})}}})
  assert.deepEqual(result,{sent:1,kind:'splunk_hec'})
  assert.equal(captured.options.headers.Authorization,'Splunk test-token')
  assert.equal(JSON.parse(captured.options.body).event.id,'chosen')
  await assert.rejects(exportSelectedEvents({kind:'splunk_hec',endpoint:'https://splunk.example.test/services/collector/event'},[event],'test-token',{fetchImpl:async()=>({ok:true,status:200,json:async()=>({code:4})})}),/rejected/)
})

test('administrators can configure encrypted destinations and selection is validated',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@event-export.test',password:'event-export-test-password'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  await auth(request.post('/api/v1/event-export/destinations')).send({name:'Insecure',kind:'splunk_hec',endpoint:'http://splunk.example.test/services/collector/event',token:'secret-token-123456'}).expect(400)
  const created=await auth(request.post('/api/v1/event-export/destinations')).send({name:'Splunk',kind:'splunk_hec',endpoint:'https://splunk.example.test:8088/services/collector/event',token:'secret-token-123456'}).expect(201)
  assert.equal(created.body.hasToken,true)
  assert.equal(JSON.stringify(created.body).includes('secret-token'),false)
  const row=db.prepare('SELECT token_blob FROM event_export_destinations WHERE id=?').get(created.body.id)
  assert.equal(row.token_blob.includes('secret-token'),false)
  await auth(request.post('/api/v1/event-export/send')).send({destinationId:created.body.id,eventIds:['11111111-1111-4111-8111-111111111111']}).expect(404)
  await auth(request.delete(`/api/v1/event-export/destinations/${created.body.id}`)).expect(200)
})
