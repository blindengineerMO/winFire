import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-ad-enroll-'))
process.env.DATA_DIR=dataDir
process.env.BOOTSTRAP_EMAIL='owner@enroll.test'
process.env.BOOTSTRAP_PASSWORD='owner-password-123456'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
const {beginAdAuthenticatorEnrollment,confirmAdAuthenticatorEnrollment}=await import('../src/adAuthenticatorEnrollment.js')
const {totpCode}=await import('../src/totp.js')
await bootstrap()
const request=supertest(app)
test.after(()=>{db.close();fs.rmSync(dataDir,{recursive:true,force:true})})
const settings={enabled:1,url:'ldaps://dc.enroll.test:636/'}
const authenticated=async(_settings,email,password)=>{
  assert.equal(email,'person@enroll.test')
  if(password!=='correct-ad-password')throw Object.assign(new Error('Invalid directory credentials'),{status:401})
}

test('AD self-enrollment requires a valid directory bind, a current code, and single use',async()=>{
  await assert.rejects(beginAdAuthenticatorEnrollment({settings,email:'person@enroll.test',password:'wrong',sourceIp:'192.0.2.4',authenticate:authenticated}),error=>error.status===401)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM ad_authenticator_enrollments').get().n,0)
  const started=await beginAdAuthenticatorEnrollment({settings,email:'PERSON@enroll.test',password:'correct-ad-password',sourceIp:'192.0.2.4',authenticate:authenticated})
  assert.match(started.uri,/otpauth:\/\/totp\/WinFire:/)
  const pending=db.prepare('SELECT * FROM ad_authenticator_enrollments').get()
  assert.equal(JSON.stringify(pending).includes(started.secret),false)
  assert.equal(JSON.stringify(pending).includes(started.token),false)
  await assert.rejects(confirmAdAuthenticatorEnrollment({token:started.token,code:totpCode(started.secret),sourceIp:'192.0.2.5'}),error=>error.status===401)
  await assert.rejects(confirmAdAuthenticatorEnrollment({token:started.token,code:'000000',sourceIp:'192.0.2.4'}),error=>error.status===401)
  assert.equal(db.prepare('SELECT id FROM users WHERE email=?').get('person@enroll.test'),undefined)
  assert.deepEqual(await confirmAdAuthenticatorEnrollment({token:started.token,code:totpCode(started.secret),sourceIp:'192.0.2.4'}),{enrolled:true,email:'person@enroll.test'})
  const user=db.prepare('SELECT * FROM users WHERE email=?').get('person@enroll.test')
  assert.equal(user.directory_only,1)
  assert.equal(user.email_verified,1)
  assert.equal(JSON.stringify(user).includes(started.secret),false)
  assert.equal(db.prepare('SELECT last_counter FROM mfa_totp_replay WHERE user_id=?').get(user.id).last_counter,Math.floor(Date.now()/30000))
  await assert.rejects(confirmAdAuthenticatorEnrollment({token:started.token,code:totpCode(started.secret),sourceIp:'192.0.2.4'}),error=>error.status===401)
  await request.post('/api/v1/auth/login').send({email:'person@enroll.test',password:'correct-ad-password'}).expect(401)
  await assert.rejects(beginAdAuthenticatorEnrollment({settings,email:'person@enroll.test',password:'correct-ad-password',sourceIp:'192.0.2.4',authenticate:authenticated}),error=>error.status===409)
})

test('public routes validate enrollment input before directory access',async()=>{
  await request.post('/api/v1/auth/ad-totp/enroll').send({email:'bad',password:'test'}).expect(400)
  await request.post('/api/v1/auth/ad-totp/confirm').send({token:'x'.repeat(40),code:'123456'}).expect(401)
})
