import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-credential-preflight-'))
process.env.DATA_DIR=dataDir
const {preflightCredential}=await import('../src/connector.js')

test.after(()=>fs.rmSync(dataDir,{recursive:true,force:true}))

const credential={username:'CONTOSO\\operator',secret:{password:'test-password'}}
const openPorts=async()=>({status:'open',latencyMs:1})

test('preflight accepts a WMI identity without creating a node',async()=>{
  const result=await preflightCredential({host:'10.0.0.10',expectedName:'SERVER-10',credential,probePort:openPorts,wmi:async input=>({success:true,transport:'wmi',computerName:'SERVER-10'}),winrm:async()=>{throw new Error('WinRM should not be needed')}})
  assert.equal(result.success,true)
  assert.equal(result.transport,'wmi')
  assert.equal(result.computerName,'SERVER-10')
})

test('preflight falls back to an open WinRM endpoint when WMI is unavailable',async()=>{
  const transports=[]
  const result=await preflightCredential({host:'server.example.test',credential,probePort:async(_host,port)=>({status:port===5985?'open':'refused'}),wmi:async()=>{throw new Error('RPC unavailable')},winrm:async input=>{transports.push(input.transport);return {authenticated:true}}})
  assert.equal(result.success,true)
  assert.equal(result.transport,'winrm')
  assert.deepEqual(transports,['winrm'])
})

test('preflight returns a redacted failure when neither management path works',async()=>{
  await assert.rejects(()=>preflightCredential({host:'10.0.0.12',credential,probePort:async()=>({status:'timeout'}),wmi:async()=>{throw new Error('bad test-password')},winrm:async()=>{throw new Error('bad test-password')}}),error=>{
    assert.match(error.message,/Credential preflight failed/)
    assert.doesNotMatch(error.message,/test-password/)
    assert.match(error.message,/rpc timeout/)
    return true
  })
})
