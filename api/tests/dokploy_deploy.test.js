import test from 'node:test'
import assert from 'node:assert/strict'
import {normalizeDokployUrl, validateBaseDomain, randomSubdomain, parseRepository, buildEnvironment} from '../../scripts/deploy-dokploy.mjs'

test('Dokploy input helpers normalize URLs and validate DNS names', () => {
  assert.equal(normalizeDokployUrl('192.168.88.9:3000'), 'http://192.168.88.9:3000/api')
  assert.equal(normalizeDokployUrl('https://dokploy.example/api/'), 'https://dokploy.example/api')
  assert.equal(validateBaseDomain('Example.COM'), 'example.com')
  assert.throws(() => validateBaseDomain('bad domain.example'))
  assert.throws(() => normalizeDokployUrl('ftp://dokploy.example'))
})

test('generated hostname and GitHub repository are safe for Dokploy', () => {
  const hostname = randomSubdomain('example.com', 'jfeiur83r3')
  assert.equal(hostname, 'jfeiur83r3.example.com')
  assert.deepEqual(parseRepository('https://github.com/blindengineerMO/winFire.git'), {owner: 'blindengineerMO', repository: 'winFire'})
  assert.throws(() => parseRepository('https://gitlab.com/acme/app'))
})

test('deployment environment includes durable secrets and generated origin', () => {
  const env = buildEnvironment({hostname: 'random.example.com', postgresPassword: 'db', jwtSecret: 'jwt', vaultMasterKey: 'vault', bootstrapEmail: 'admin@example.com', bootstrapPassword: 'long-password'})
  assert.match(env, /PUBLIC_BASE_URL="http:\/\/random\.example\.com"/)
  assert.match(env, /POSTGRES_URL="postgresql:\/\/winfire:db@postgres:5432\/winfire"/)
  assert.match(env, /BOOTSTRAP_ADMIN_PASSWORD="long-password"/)
  assert.match(env, /DATABASE_DRIVER="sqlite"/)
})
