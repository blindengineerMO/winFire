import test from 'node:test'
import assert from 'node:assert/strict'
import {normalizeDokployUrl, validateBaseDomain, randomSubdomain, parseRepository, buildEnvironment, buildDomainPayloads, buildDomainUrls} from '../../scripts/deploy-dokploy.mjs'

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
  const env = buildEnvironment({hostname: 'random.example.com', postgresPassword: 'db', jwtSecret: 'jwt', vaultMasterKey: 'vault', bootstrapEmail: 'admin@example.com', bootstrapPassword: 'long-password', httpsEnabled: false})
  assert.match(env, /PUBLIC_BASE_URL="http:\/\/random\.example\.com"/)
  assert.match(env, /POSTGRES_URL="postgresql:\/\/winfire:db@postgres:5432\/winfire"/)
  assert.match(env, /BOOTSTRAP_ADMIN_PASSWORD="long-password"/)
  assert.match(env, /DATABASE_DRIVER="sqlite"/)
  const secureEnv = buildEnvironment({hostname: 'random.example.com', postgresPassword: 'db', jwtSecret: 'jwt', vaultMasterKey: 'vault', bootstrapEmail: 'admin@example.com', bootstrapPassword: 'long-password'})
  assert.match(secureEnv, /PUBLIC_BASE_URL="https:\/\/random\.example\.com"/)
})

test('Dokploy receives HTTP and HTTPS domains for the same host', () => {
  const domains = buildDomainPayloads({hostname: 'random.example.com', composeId: 'compose-1'})
  assert.equal(domains.length, 2)
  assert.deepEqual(domains.map(domain => ({host: domain.host, port: domain.port, https: domain.https, certificateType: domain.certificateType})), [
    {host: 'random.example.com', port: 80, https: false, certificateType: 'none'},
    {host: 'random.example.com', port: 80, https: true, certificateType: 'letsencrypt'},
  ])
  assert.deepEqual(buildDomainUrls('random.example.com'), {http: 'http://random.example.com', https: 'https://random.example.com'})
  assert.deepEqual(buildDomainPayloads({hostname: 'private.internal', composeId: 'compose-2', httpsEnabled: false}).map(domain => domain.https), [false])
})
