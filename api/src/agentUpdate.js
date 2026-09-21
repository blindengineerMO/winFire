import fs from 'node:fs'
import crypto from 'node:crypto'
import {normalizeSignerThumbprint} from './agentBootstrap.js'

let cached = null

function packagePath() {
  return process.env.AGENT_UPDATE_PACKAGE_PATH || process.env.AGENT_PACKAGE_PATH || ''
}

function packageVersion() {
  return String(process.env.AGENT_UPDATE_VERSION || process.env.AGENT_PACKAGE_VERSION || '0.1.0').trim()
}

function packageMetadata() {
  const file = packagePath()
  if (!file) return null
  const absolute = fs.realpathSync(file)
  const stat = fs.statSync(absolute)
  const signer = normalizeSignerThumbprint(process.env.AGENT_SIGNER_THUMBPRINT || '')
  if (!signer) throw new Error('AGENT_SIGNER_THUMBPRINT is required for agent self-update')
  const cacheKey = `${absolute}:${stat.size}:${stat.mtimeMs}:${packageVersion()}:${signer}`
  if (cached?.key === cacheKey) return cached.value
  const digest = crypto.createHash('sha256')
  const data = fs.readFileSync(absolute)
  digest.update(data)
  const value = {
    version: packageVersion(),
    sha256: digest.digest('hex'),
    size: stat.size,
    signerThumbprint: signer,
    path: absolute
  }
  cached = {key: cacheKey, value}
  return value
}

export function getAgentUpdateManifest(currentVersion, packageUrl) {
  const metadata = packageMetadata()
  if (!metadata) return {available: false}
  return {
    available: metadata.version !== String(currentVersion || '').trim(),
    version: metadata.version,
    sha256: metadata.sha256,
    size: metadata.size,
    signerThumbprint: metadata.signerThumbprint,
    packageUrl
  }
}

export function getAgentUpdatePackagePath() {
  const metadata = packageMetadata()
  return metadata?.path || null
}
