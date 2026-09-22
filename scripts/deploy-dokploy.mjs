#!/usr/bin/env node
/*
 * Interactive Dokploy deployment helper.
 *
 * The helper deliberately keeps the Dokploy API key in memory only.  It creates
 * the compose application first, then adds a Dokploy domain (Dokploy requires a
 * compose service before a domain can be attached), and finally deploys it.
 */
import crypto from 'node:crypto'
import http from 'node:http'
import https from 'node:https'
import path from 'node:path'
import process from 'node:process'
import readline from 'node:readline'
import {pathToFileURL} from 'node:url'

const DEFAULT_DOKPLOY = process.env.DOKPLOY_URL || 'http://localhost:3000'
const DEFAULT_REPOSITORY = 'https://github.com/blindengineerMO/winFire.git'
const COMPOSE_PATH = 'deploy/dokploy/docker-compose.yml'

export function normalizeDokployUrl(value) {
  const raw = String(value || '').trim().replace(/\/+$/, '')
  if (!raw) throw new Error('Dokploy URL is required')
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) && !/^https?:\/\//i.test(raw)) throw new Error('Dokploy URL must use http or https')
  const url = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`
  const parsed = new URL(url)
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Dokploy URL must use http or https')
  return `${parsed.origin}/api`
}

export function validateBaseDomain(value) {
  const domain = String(value || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '')
  if (!domain || domain.length > 253 || domain.includes('/') || domain.includes(':')) throw new Error('Enter a DNS base domain such as example.com')
  if (!domain.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error('Base domain contains an invalid DNS label')
  return domain
}

export function randomSubdomain(baseDomain, random = crypto.randomBytes(7).toString('base64url').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10)) {
  const domain = validateBaseDomain(baseDomain)
  const label = String(random).toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 32)
  if (label.length < 6) throw new Error('Generated DNS label is too short')
  return `${label}.${domain}`
}

export function parseRepository(repository = DEFAULT_REPOSITORY) {
  const value = String(repository).trim().replace(/\.git$/, '')
  const parsed = new URL(value)
  if (parsed.hostname !== 'github.com') throw new Error('The Dokploy source repository must be a GitHub HTTPS URL')
  const parts = parsed.pathname.split('/').filter(Boolean)
  if (parts.length !== 2) throw new Error('GitHub repository must look like https://github.com/owner/repository')
  return {owner: parts[0], repository: parts[1]}
}

export function randomSecret(bytes = 32) { return crypto.randomBytes(bytes).toString('base64url') }

const envLine = (name, value) => `${name}=${JSON.stringify(String(value))}`

export function buildEnvironment({hostname, postgresPassword, jwtSecret, vaultMasterKey, bootstrapEmail, bootstrapPassword, httpsEnabled = false}) {
  const origin = `${httpsEnabled ? 'https' : 'http'}://${hostname}`
  return [
    envLine('NODE_ENV', 'production'),
    envLine('PORT', 3000),
    envLine('HOST', '0.0.0.0'),
    envLine('DATA_DIR', '/data'),
    // The API currently uses its SQLite migration engine.  Keep it durable while
    // the PostgreSQL service is available for the planned database adapter.
    envLine('DATABASE_DRIVER', 'sqlite'),
    envLine('POSTGRES_DB', 'winfire'),
    envLine('POSTGRES_USER', 'winfire'),
    envLine('POSTGRES_PASSWORD', postgresPassword),
    envLine('POSTGRES_URL', `postgresql://winfire:${postgresPassword}@postgres:5432/winfire`),
    envLine('PUBLIC_BASE_URL', origin),
    envLine('CORS_ORIGIN', origin),
    envLine('JWT_SECRET', jwtSecret),
    envLine('VAULT_MASTER_KEY', vaultMasterKey),
    envLine('BOOTSTRAP_ADMIN_ENABLED', 'true'),
    envLine('BOOTSTRAP_ADMIN_EMAIL', bootstrapEmail),
    envLine('BOOTSTRAP_ADMIN_PASSWORD', bootstrapPassword),
    envLine('WINRM_INSECURE_HTTP', 'false'),
    envLine('LOG_RETENTION_DAYS', 90),
    envLine('SWEEP_INTERVAL_MINUTES', 60),
    envLine('LOG_POLL_INTERVAL_SECONDS', 120),
  ].join('\n') + '\n'
}

async function request(base, key, endpoint, options = {}) {
  const response = await fetch(`${base}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`, {
    ...options,
    headers: {'content-type': 'application/json', 'x-api-key': key, ...(options.headers || {})},
  })
  const text = await response.text()
  let body
  try { body = text ? JSON.parse(text) : null } catch { body = text }
  if (!response.ok) {
    const detail = typeof body === 'string' ? body : JSON.stringify(body)
    throw new Error(`Dokploy ${response.status} ${endpoint}: ${detail}`)
  }
  return body
}

function question(rl, label, fallback = '') {
  return new Promise(resolve => rl.question(`${label}${fallback ? ` [${fallback}]` : ''}: `, answer => resolve(answer.trim() || fallback)))
}

async function configuredOrQuestion(rl, name, label, fallback = '') {
  return Object.prototype.hasOwnProperty.call(process.env, name) ? process.env[name] : question(rl, label, fallback)
}

function secretQuestion(rl, label) {
  if (!process.stdin.isTTY) return question(rl, label)
  return new Promise(resolve => {
    const wasRaw = process.stdin.isRaw
    process.stdin.setRawMode(true)
    process.stdin.resume()
    let value = ''
    process.stdout.write(`${label}: `)
    const onData = chunk => {
      const key = chunk.toString()
      if (key === '\u0003') { process.stdin.setRawMode(wasRaw); process.exit(130) }
      if (key === '\r' || key === '\n') {
        process.stdin.setRawMode(wasRaw)
        process.stdin.removeListener('data', onData)
        process.stdout.write('\n')
        resolve(value)
      } else if (key === '\u007f') value = value.slice(0, -1)
      else value += key
    }
    process.stdin.on('data', onData)
  })
}

async function choose(rl, items, label, name = item => item.name || item.projectId || item.environmentId) {
  if (items.length === 1) return items[0]
  items.forEach((item, index) => console.log(`  ${index + 1}. ${name(item)}`))
  const answer = await question(rl, `Select ${label}`, '1')
  const index = Number(answer) - 1
  if (!Number.isInteger(index) || !items[index]) throw new Error(`Select a number between 1 and ${items.length}`)
  return items[index]
}

function jsonBody(body) { return JSON.stringify(body) }

async function waitForDeployment(base, key, composeId, timeoutMs) {
  const end = Date.now() + timeoutMs
  let latest = null
  while (Date.now() < end) {
    try {
      const deployments = await request(base, key, `/deployment.allByCompose?composeId=${encodeURIComponent(composeId)}`)
      const list = Array.isArray(deployments) ? deployments : deployments?.deployments || []
      latest = list[0] || latest
      const status = String(latest?.status || latest?.state || '').toLowerCase()
      if (['done', 'success', 'succeeded', 'running'].includes(status)) return latest
      if (['error', 'failed', 'failure', 'cancelled'].includes(status)) throw new Error(`Deployment failed (${status})`)
    } catch (error) {
      if (error.message.startsWith('Deployment failed')) throw error
    }
    await new Promise(resolve => setTimeout(resolve, 5000))
  }
  return latest
}

async function reachability(url, timeoutMs = 15_000, resolveIp = '') {
  const target = new URL(url)
  if (resolveIp) {
    const transport = target.protocol === 'https:' ? https : http
    return await new Promise(resolve => {
      const req = transport.request({hostname: resolveIp, port: target.port || (target.protocol === 'https:' ? 443 : 80), path: `${target.pathname}${target.search}`, servername: target.hostname, rejectUnauthorized: false, timeout: timeoutMs, headers: {host: target.host}}, response => {response.resume(); resolve({ok: response.statusCode < 500, status: response.statusCode, resolvedTo: resolveIp})})
      req.on('timeout', () => {req.destroy(); resolve({ok: false, error: 'timeout', resolvedTo: resolveIp})})
      req.on('error', error => resolve({ok: false, error: error.message, resolvedTo: resolveIp}))
      req.end()
    })
  }
  if (target.protocol === 'http:') {
    try { const response = await fetch(target, {signal: AbortSignal.timeout(timeoutMs), redirect: 'manual'}); return {ok: response.status < 500, status: response.status} } catch (error) { return {ok: false, error: error.message} }
  }
  return await new Promise(resolve => {
    const req = https.request(target, {rejectUnauthorized: false, timeout: timeoutMs}, response => {response.resume(); resolve({ok: response.statusCode < 500, status: response.statusCode})})
    req.on('timeout', () => {req.destroy(); resolve({ok: false, error: 'timeout'})})
    req.on('error', error => resolve({ok: false, error: error.message}))
    req.end()
  })
}

export async function deploy({dokployUrl, apiKey, project, environment, serviceName, baseDomain, repository = DEFAULT_REPOSITORY, branch = 'main', bootstrapEmail = 'admin@winfire.local', bootstrapPassword = randomSecret(18), httpsEnabled = false, timeoutMs = 20 * 60_000, reachabilityIp = process.env.DOKPLOY_REACHABILITY_IP || ''}) {
  const base = normalizeDokployUrl(dokployUrl)
  if (!apiKey) throw new Error('Dokploy API key is required')
  const hostname = randomSubdomain(baseDomain)
  parseRepository(repository)
  // Use Dokploy's generic Git source for public GitHub repositories. This
  // clones the repository directly and does not require a GitHub OAuth provider
  // to be configured on the Dokploy instance.
  const compose = await request(base, apiKey, '/compose.create', {method: 'POST', body: jsonBody({name: serviceName, environmentId: environment.environmentId, composeType: 'docker-compose', sourceType: 'git', appName: serviceName})})
  const composeId = compose?.composeId || compose?.id
  if (!composeId) throw new Error('Dokploy did not return a compose id')
  const postgresPassword = randomSecret(24)
  const env = buildEnvironment({hostname, postgresPassword, jwtSecret: randomSecret(), vaultMasterKey: randomSecret(), bootstrapEmail, bootstrapPassword, httpsEnabled})
  await request(base, apiKey, '/compose.update', {method: 'POST', body: jsonBody({composeId, sourceType: 'git', customGitUrl: repository, customGitBranch: branch, composePath: COMPOSE_PATH, composeType: 'docker-compose'})})
  await request(base, apiKey, '/compose.saveEnvironment', {method: 'POST', body: jsonBody({composeId, env})})
  const domain = await request(base, apiKey, '/domain.create', {method: 'POST', body: jsonBody({host: hostname, https: httpsEnabled, certificateType: httpsEnabled ? 'letsencrypt' : 'none', composeId, serviceName: 'ui', domainType: 'compose', port: 80})})
  const deployment = await request(base, apiKey, '/compose.deploy', {method: 'POST', body: jsonBody({composeId, title: `Deploy ${serviceName}`})})
  const finished = await waitForDeployment(base, apiKey, composeId, timeoutMs)
  const url = `${httpsEnabled ? 'https' : 'http'}://${hostname}`
  const check = await reachability(url, 15_000, reachabilityIp)
  return {composeId, hostname, url, domain, deployment, finished, reachability: check, projectId: project.projectId, environmentId: environment.environmentId}
}

async function main() {
  const rl = readline.createInterface({input: process.stdin, output: process.stdout})
  try {
    console.log('\nWinFire Dokploy deployment\n')
    const dokployUrl = await configuredOrQuestion(rl, 'DOKPLOY_URL', 'Dokploy URL or IP', DEFAULT_DOKPLOY)
    const apiKey = process.env.DOKPLOY_API_KEY || await secretQuestion(rl, 'Dokploy API key')
    if (process.env.DOKPLOY_API_KEY) console.log('Using DOKPLOY_API_KEY from the environment (it will not be saved).')
    const base = normalizeDokployUrl(dokployUrl)
    const projectsBody = await request(base, apiKey, '/project.all')
    const projects = Array.isArray(projectsBody) ? projectsBody : projectsBody?.projects || []
    const project = process.env.DOKPLOY_PROJECT_ID
      ? projects.find(item => item.projectId === process.env.DOKPLOY_PROJECT_ID) || (() => { throw new Error('DOKPLOY_PROJECT_ID was not returned by Dokploy') })()
      : await choose(rl, projects, 'project', item => `${item.name || item.projectId} (${item.projectId})`)
    const environments = project.environments || []
    const environment = process.env.DOKPLOY_ENVIRONMENT_ID
      ? environments.find(item => item.environmentId === process.env.DOKPLOY_ENVIRONMENT_ID) || (() => { throw new Error('DOKPLOY_ENVIRONMENT_ID was not returned by Dokploy') })()
      : await choose(rl, environments, 'environment', item => `${item.name || item.environmentId} (${item.environmentId})`)
    const serviceName = await configuredOrQuestion(rl, 'WINFIRE_SERVICE_NAME', 'Service name', 'winfire')
    if (!/^[a-z0-9][a-z0-9-]{1,62}$/i.test(serviceName)) throw new Error('Service name must be 2-63 letters, numbers, or hyphens')
    const baseDomain = validateBaseDomain(await configuredOrQuestion(rl, 'WINFIRE_BASE_DOMAIN', 'Base domain for the generated hostname', 'example.com'))
    const repository = await configuredOrQuestion(rl, 'WINFIRE_GITHUB_REPOSITORY', 'GitHub repository', DEFAULT_REPOSITORY)
    const branch = await configuredOrQuestion(rl, 'WINFIRE_GITHUB_BRANCH', 'Git branch', 'main')
    const bootstrapEmail = await configuredOrQuestion(rl, 'WINFIRE_BOOTSTRAP_EMAIL', 'Bootstrap admin email', 'admin@winfire.local')
    const bootstrapPassword = process.env.WINFIRE_BOOTSTRAP_PASSWORD || await secretQuestion(rl, 'Bootstrap admin password (12+ characters)')
    if (bootstrapPassword.length < 12) throw new Error('Bootstrap admin password must contain at least 12 characters')
    const httpsEnabled = process.env.WINFIRE_HTTPS !== undefined
      ? process.env.WINFIRE_HTTPS === 'true'
      : /^y(es)?$/i.test(await question(rl, 'Request a Let\'s Encrypt certificate? (y/N)', 'N'))
    console.log('\nCreating the compose service and generated domain...')
    const result = await deploy({dokployUrl, apiKey, project, environment, serviceName, baseDomain, repository, branch, bootstrapEmail, bootstrapPassword, httpsEnabled})
    console.log(JSON.stringify({status: result.finished?.status || result.deployment?.status || 'submitted', service: serviceName, url: result.url, hostname: result.hostname, composeId: result.composeId, reachability: result.reachability}, null, 2))
  } catch (error) {
    console.error(`Deployment failed: ${error.message}`)
    process.exitCode = 1
  } finally { rl.close() }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) await main()
