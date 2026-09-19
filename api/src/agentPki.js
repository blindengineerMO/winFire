import crypto, {X509Certificate} from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {spawn} from 'node:child_process'

export function agentPkiReady() {
  return !!(process.env.TLS_CERT && process.env.TLS_KEY && process.env.AGENT_CA_CERT && process.env.AGENT_CA_KEY)
}

export function agentTlsOptions() {
  if(!agentPkiReady())return null
  if(process.env.NODE_ENV==='production') {
    const key=fs.readFileSync(process.env.AGENT_CA_KEY,'utf8')
    if(!process.env.AGENT_CA_PASSPHRASE||!key.includes('BEGIN ENCRYPTED PRIVATE KEY'))throw new Error('Production agent CA key must be encrypted and AGENT_CA_PASSPHRASE must be set')
  }
  return {
    cert:fs.readFileSync(process.env.TLS_CERT),
    key:fs.readFileSync(process.env.TLS_KEY),
    ca:[fs.readFileSync(process.env.AGENT_CA_CERT)],
    requestCert:true,
    rejectUnauthorized:false,
    minVersion:'TLSv1.2'
  }
}

function openssl(args) {
  return new Promise((resolve,reject)=>{
    const child=spawn('openssl',args,{env:{...process.env,WINFIRE_CA_PASS:process.env.AGENT_CA_PASSPHRASE||''},stdio:['ignore','pipe','pipe']})
    let output='',error=''
    child.stdout.on('data',chunk=>output+=chunk)
    child.stderr.on('data',chunk=>error+=chunk)
    child.once('error',reject)
    child.once('close',code=>code?reject(new Error(error.trim()||`OpenSSL exited ${code}`)):resolve(output))
  })
}

export function certificateFingerprint(certPem) {
  return new X509Certificate(certPem).fingerprint256.replaceAll(':','').toUpperCase()
}

export async function signAgentCsr(csrPem,nodeId) {
  if(!agentPkiReady())throw Object.assign(new Error('Agent PKI is not configured'),{status:503})
  if(process.env.NODE_ENV==='production'&&!process.env.AGENT_CA_PASSPHRASE)throw Object.assign(new Error('Encrypted agent CA key passphrase is required'),{status:503})
  if(typeof csrPem!=='string'||csrPem.length>12000||!/^-----BEGIN CERTIFICATE REQUEST-----[\s\S]+-----END CERTIFICATE REQUEST-----\s*$/.test(csrPem))throw Object.assign(new Error('Invalid certificate signing request'),{status:400})
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-csr-'))
  try {
    const csr=path.join(dir,'agent.csr'),cert=path.join(dir,'agent.crt'),ext=path.join(dir,'extensions.cnf')
    fs.writeFileSync(csr,csrPem,{mode:0o600})
    fs.writeFileSync(ext,`basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,clientAuth\nsubjectAltName=URI:urn:winfire:agent:${nodeId}\n`,{mode:0o600})
    await openssl(['req','-in',csr,'-verify','-noout'])
    await openssl(['x509','-req','-in',csr,'-CA',process.env.AGENT_CA_CERT,'-CAkey',process.env.AGENT_CA_KEY,'-passin','env:WINFIRE_CA_PASS','-set_serial',`0x${crypto.randomBytes(16).toString('hex')}`,'-days','7','-sha256','-subj',`/CN=WinFire-agent-${nodeId}`,'-extfile',ext,'-out',cert])
    const certificate=fs.readFileSync(cert,'utf8'),parsed=new X509Certificate(certificate)
    return {certificate,caCertificate:fs.readFileSync(process.env.AGENT_CA_CERT,'utf8'),fingerprint:certificateFingerprint(certificate),expiresAt:new Date(parsed.validTo).toISOString()}
  } finally {fs.rmSync(dir,{recursive:true,force:true})}
}
