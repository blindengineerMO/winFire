import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const directory=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-bootstrap-defaults-'))
process.env.DATA_DIR=directory
delete process.env.BOOTSTRAP_ADMIN_ENABLED
delete process.env.BOOTSTRAP_ADMIN_EMAIL
delete process.env.BOOTSTRAP_ADMIN_PASSWORD
process.env.BOOTSTRAP_EMAIL='owner@bootstrap-defaults.test'
process.env.BOOTSTRAP_PASSWORD='owner-bootstrap-defaults-password'
const {app}=await import('../src/app.js')
const {bootstrap,ensureBootstrapAdmin}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(directory,{recursive:true,force:true})})

test('a fresh local database creates the documented default demo admin',async()=>{
  await bootstrap()
  await ensureBootstrapAdmin()
  const response=await request.post('/api/v1/auth/login').send({email:'admin@winfire.local',password:'WinFireDemo!2026'}).expect(200)
  assert.equal(response.body.user.email,'admin@winfire.local')
  assert.equal(response.body.user.role,'admin')
})
