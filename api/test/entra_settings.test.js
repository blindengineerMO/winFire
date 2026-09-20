import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-entra-settings-'))
process.env.DATA_DIR=dataDir
process.env.BOOTSTRAP_EMAIL='owner@entra-settings.test'
process.env.BOOTSTRAP_PASSWORD='entra-settings-password-123'
process.env.PUBLIC_BASE_URL='https://access.example.test'
process.env.ENTRA_TENANT_ID='11111111-1111-4111-8111-111111111111'
process.env.ENTRA_CLIENT_ID='22222222-2222-4222-8222-222222222222'
process.env.ENTRA_CLIENT_SECRET='environment-secret-value'
const {app}=await import('../src/app.js')
const {bootstrap,openSealed}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {effectiveEntraSettings}=await import('../src/entraSettings.js')
const {entraConfigured,entraRedirectUri}=await import('../src/entraPortal.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dataDir,{recursive:true,force:true})})

test('admin can replace environment Entra config with encrypted write-only settings and disable it',async()=>{
  const initial=await request.get('/api/v1/settings/entra').expect(401)
  assert.equal(initial.body.error!==undefined,true)
  const login=await request.post('/api/v1/auth/login').send({email:'owner@entra-settings.test',password:'entra-settings-password-123'}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const environment=await auth(request.get('/api/v1/settings/entra')).expect(200)
  assert.equal(environment.body.source,'environment')
  assert.equal(environment.body.ready,true)
  assert.equal(environment.body.clientSecretConfigured,true)
  assert.equal(JSON.stringify(environment.body).includes('environment-secret-value'),false)

  const tenantId='33333333-3333-4333-8333-333333333333',clientId='44444444-4444-4444-8444-444444444444'
  await auth(request.patch('/api/v1/settings/entra')).send({tenantId,clientId,enabled:true}).expect(400)
  const saved=await auth(request.patch('/api/v1/settings/entra')).send({tenantId,clientId,clientSecret:'first-secret-value',enabled:true}).expect(200)
  assert.equal(saved.body.source,'settings')
  assert.equal(saved.body.ready,true)
  assert.deepEqual(saved.body.redirectUris,['https://access.example.test/identity','https://access.example.test/mfa/callback'])
  assert.equal(JSON.stringify(saved.body).includes('first-secret-value'),false)
  assert.equal(entraConfigured(),true)
  assert.equal(entraRedirectUri('/mfa/callback'),'https://access.example.test/mfa/callback')
  const stored=db.prepare("SELECT * FROM entra_integrations WHERE id='default'").get()
  assert.equal(openSealed(stored.client_secret_sealed).secret,'first-secret-value')
  assert.equal(JSON.stringify(stored).includes('first-secret-value'),false)
  assert.equal(effectiveEntraSettings().tenantId,tenantId)

  await auth(request.patch('/api/v1/settings/entra')).send({tenantId,clientId,enabled:true}).expect(200)
  assert.equal(openSealed(db.prepare("SELECT client_secret_sealed FROM entra_integrations WHERE id='default'").get().client_secret_sealed).secret,'first-secret-value')
  await auth(request.patch('/api/v1/settings/entra')).send({tenantId,clientId,clientSecret:'rotated-secret-value',enabled:false}).expect(200)
  assert.equal(entraConfigured(),false)
  assert.equal(openSealed(db.prepare("SELECT client_secret_sealed FROM entra_integrations WHERE id='default'").get().client_secret_sealed).secret,'rotated-secret-value')
  await assert.rejects(Promise.resolve().then(()=>entraRedirectUri()),error=>error.status===503)
  const audit=db.prepare("SELECT before_json,after_json FROM audit_log WHERE action='entra.settings.update'").all()
  assert.equal(JSON.stringify(audit).includes('secret-value'),false)
})
