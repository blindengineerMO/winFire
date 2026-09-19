import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const host=process.env.WINFIRE_TEST_HOST
const username=process.env.WINFIRE_TEST_USER
const password=process.env.WINFIRE_TEST_PASSWORD
if(!host||!username||!password)throw new Error('Set WINFIRE_TEST_HOST, WINFIRE_TEST_USER and WINFIRE_TEST_PASSWORD')

const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-rights-read-'))
process.env.DATA_DIR=temporary
process.env.BOOTSTRAP_EMAIL='rights-read@example.test'
process.env.BOOTSTRAP_PASSWORD='temporary-rights-read-12345'
let database
try {
  const dbModule=await import('../src/db.js')
  database=dbModule.db
  const {bootstrap}=await import('../src/security.js')
  const {app}=await import('../src/app.js')
  const {remote}=await import('../src/connector.js')
  await bootstrap()
  const request=supertest(app)
  const login=await request.post('/api/v1/auth/login').send({email:process.env.BOOTSTRAP_EMAIL,password:process.env.BOOTSTRAP_PASSWORD}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Temporary rights read',type:'domain',username,password}).expect(201)
  const node=await auth(request.post('/api/v1/nodes')).send({hostname:host,ip:host,credentialIds:[credential.body.id]}).expect(201)
  const probe=await auth(request.post(`/api/v1/nodes/${node.body.id}/probe`)).send({}).expect(200)
  if(!['winrm','winrms'].includes(probe.body.transport))throw new Error(`WinRM was not detected: ${probe.body.transport}`)
  const raw=await remote(dbModule.one('SELECT * FROM nodes WHERE id=?',node.body.id),'rights')
  const lines=Array.isArray(raw)?raw:[raw].filter(Boolean)
  console.log(JSON.stringify({transport:probe.body.transport,rightTypes:lines.length,names:lines.map(line=>String(line).split('=')[0].trim())}))
} finally {
  database?.close()
  fs.rmSync(temporary,{recursive:true,force:true})
}
