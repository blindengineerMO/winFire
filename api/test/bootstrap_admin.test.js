import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const directory=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-bootstrap-admin-'))
process.env.DATA_DIR=directory
process.env.BOOTSTRAP_EMAIL='owner@bootstrap.test'
process.env.BOOTSTRAP_PASSWORD='owner-bootstrap-password'
process.env.BOOTSTRAP_ADMIN_ENABLED='true'
process.env.BOOTSTRAP_ADMIN_EMAIL='demo@bootstrap.test'
process.env.BOOTSTRAP_ADMIN_PASSWORD='demo-bootstrap-password'
const {app}=await import('../src/app.js')
const {bootstrap,ensureBootstrapAdmin}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(directory,{recursive:true,force:true})})

test('demo admin survives restart and follows environment credentials',async()=>{
  await bootstrap()
  await ensureBootstrapAdmin()
  const first=await request.post('/api/v1/auth/login').send({email:'demo@bootstrap.test',password:'demo-bootstrap-password'}).expect(200)
  assert.equal(first.body.user.role,'admin')
  assert.equal(db.prepare('SELECT theme FROM user_profiles WHERE user_id=?').get(first.body.user.id).theme,'enterprise')
  const original=db.prepare("SELECT u.id,u.password_hash FROM users u JOIN bootstrap_accounts b ON b.user_id=u.id WHERE b.kind='demo-admin'").get()
  await ensureBootstrapAdmin()
  const repeated=db.prepare('SELECT password_hash FROM users WHERE id=?').get(original.id)
  assert.equal(repeated.password_hash,original.password_hash)
  process.env.BOOTSTRAP_ADMIN_EMAIL='changed@bootstrap.test'
  process.env.BOOTSTRAP_ADMIN_PASSWORD='changed-bootstrap-password'
  await ensureBootstrapAdmin()
  const changed=db.prepare('SELECT id,email FROM users WHERE id=?').get(original.id)
  assert.equal(changed.email,'changed@bootstrap.test')
  await request.post('/api/v1/auth/login').send({email:'demo@bootstrap.test',password:'demo-bootstrap-password'}).expect(401)
  await request.post('/api/v1/auth/login').send({email:'changed@bootstrap.test',password:'demo-bootstrap-password'}).expect(401)
  await request.post('/api/v1/auth/login').send({email:'changed@bootstrap.test',password:'changed-bootstrap-password'}).expect(200)
  await request.get('/api/v1/auth/me').set('Authorization',`Bearer ${first.body.accessToken}`).expect(401)
  process.env.BOOTSTRAP_ADMIN_ENABLED='false'
  await ensureBootstrapAdmin()
  await request.post('/api/v1/auth/login').send({email:'changed@bootstrap.test',password:'changed-bootstrap-password'}).expect(401)
})
