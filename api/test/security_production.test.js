import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import {spawnSync} from 'node:child_process'

const root=path.resolve(import.meta.dirname,'../..')

test('production requires externally supplied keys and never creates a local master-key file',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-production-keys-'))
  try{
    const run=(extra={})=>spawnSync(process.execPath,['--input-type=module','-e','await import("./api/src/security.js"); console.log("ready")'],{cwd:root,env:{...process.env,DATA_DIR:dir,NODE_ENV:'production',JWT_SECRET:'',VAULT_MASTER_KEY:'',...extra},encoding:'utf8'})
    const missing=run()
    assert.notEqual(missing.status,0)
    assert.match(missing.stderr,/Production requires JWT_SECRET and VAULT_MASTER_KEY/)
    assert.equal(fs.existsSync(path.join(dir,'secrets.json')),false)
    const configured=run({JWT_SECRET:'J'.repeat(40),VAULT_MASTER_KEY:crypto.randomBytes(32).toString('base64')})
    assert.equal(configured.status,0,configured.stderr)
    assert.match(configured.stdout,/ready/)
    assert.equal(fs.existsSync(path.join(dir,'secrets.json')),false)
  }finally{fs.rmSync(dir,{recursive:true,force:true})}
})

test('production agent HTTPS refuses unencrypted server and CA keys',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-production-tls-'))
  try{
    const files={TLS_CERT:'server.crt',TLS_KEY:'server.key',AGENT_CA_CERT:'ca.crt',AGENT_CA_KEY:'ca.key'}
    for(const [name,file] of Object.entries(files))fs.writeFileSync(path.join(dir,file),name.endsWith('KEY')?'-----BEGIN PRIVATE KEY-----\nunsafe\n-----END PRIVATE KEY-----':'certificate')
    const run=(extra={})=>spawnSync(process.execPath,['--input-type=module','-e','import {agentTlsOptions} from "./api/src/agentPki.js"; console.log(Boolean(agentTlsOptions()))'],{cwd:root,env:{...process.env,NODE_ENV:'production',...Object.fromEntries(Object.entries(files).map(([name,file])=>[name,path.join(dir,file)])),AGENT_CA_PASSPHRASE:'ca-passphrase',TLS_KEY_PASSPHRASE:'tls-passphrase',...extra},encoding:'utf8'})
    const unsafeCa=run()
    assert.notEqual(unsafeCa.status,0)
    assert.match(unsafeCa.stderr,/Production agent CA key must be encrypted/)
    fs.writeFileSync(path.join(dir,'ca.key'),'-----BEGIN ENCRYPTED PRIVATE KEY-----\nprotected\n-----END ENCRYPTED PRIVATE KEY-----')
    const unsafeServer=run()
    assert.notEqual(unsafeServer.status,0)
    assert.match(unsafeServer.stderr,/Production TLS key must be encrypted/)
    fs.writeFileSync(path.join(dir,'server.key'),'-----BEGIN ENCRYPTED PRIVATE KEY-----\nprotected\n-----END ENCRYPTED PRIVATE KEY-----')
    const missingPassphrase=run({TLS_KEY_PASSPHRASE:''})
    assert.notEqual(missingPassphrase.status,0)
    assert.match(missingPassphrase.stderr,/TLS_KEY_PASSPHRASE/)
    const configured=run()
    assert.equal(configured.status,0,configured.stderr)
    assert.match(configured.stdout,/true/)
  }finally{fs.rmSync(dir,{recursive:true,force:true})}
})
