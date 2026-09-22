import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import {spawnSync} from 'node:child_process'
import supertest from 'supertest'

const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-rights-change-'))
process.env.DATA_DIR=dataDir
process.env.BOOTSTRAP_EMAIL='owner@rights-change.test'
process.env.BOOTSTRAP_PASSWORD='rights-change-password-123'
const stub=path.join(dataDir,'rights-stub')
fs.writeFileSync(stub,`#!/usr/bin/env node
let body='';process.stdin.on('data',part=>body+=part);process.stdin.on('end',()=>{
 const input=JSON.parse(body)
 if(input.operation!=='rights_change')throw Error('Unexpected operation')
 process.stdout.write(JSON.stringify({accountSid:input.args.accountSid,right:input.args.right,before:!input.args.present,present:process.env.WINFIRE_TEST_RIGHTS_WRONG==='1'?!input.args.present:input.args.present,changed:true}))
})
`,{mode:0o700})
process.env.WINRM_PYTHON=stub
const {app}=await import('../src/app.js')
const {db,run,one}=await import('../src/db.js')
const {bootstrap,seal}=await import('../src/security.js')
await bootstrap()
const request=supertest(app),nodeId=crypto.randomUUID()
run('INSERT INTO nodes(id,hostname,ip,connection_mode,transport) VALUES(?,?,?,?,?)',nodeId,'LAB','192.0.2.90','agentless','winrm')
run("INSERT INTO credentials(id,name,type,username,encrypted_blob) VALUES('cred-rights','rights','domain','user',?)",seal({password:'secret'}))
run('INSERT INTO credential_assignments(credential_id,node_id) VALUES(?,?)','cred-rights',nodeId)
test.after(()=>{db.close();fs.rmSync(dataDir,{recursive:true,force:true})})

test('LSA change script confirms add, no-op, and remove against readback',()=>{
  if(!spawnSync('pwsh',['-Version'],{encoding:'utf8'}).stdout) return
  const file=path.resolve('api/sidecar/lsa_rights.ps1').replaceAll("'","''")
  const script=`$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
public static class WinFireLsaRights {
  private static readonly HashSet<string> Rights = new HashSet<string>();
  public static string[] Read() { var rows=new List<string>(); foreach(var right in new[]{"SeBatchLogonRight","SeInteractiveLogonRight"}) if(Rights.Contains("S-1-5-21-1-2-3-999:"+right)) rows.Add(right+" = *S-1-5-21-1-2-3-999"); return rows.ToArray(); }
  public static void Change(string sid,string right,bool present) { if(present) Rights.Add(sid+":"+right); else Rights.Remove(sid+":"+right); }
}
'@
. '${file}'
$add=Set-WinFireLogonRight @{accountSid='S-1-5-21-1-2-3-999';right='SeBatchLogonRight';present=$true}
$same=Set-WinFireLogonRight @{accountSid='S-1-5-21-1-2-3-999';right='SeBatchLogonRight';present=$true}
$remove=Set-WinFireLogonRight @{accountSid='S-1-5-21-1-2-3-999';right='SeBatchLogonRight';present=$false}
$interactive=Set-WinFireLogonRight @{accountSid='S-1-5-21-1-2-3-999';right='SeInteractiveLogonRight';present=$true}
@($add,$same,$remove,$interactive) | ConvertTo-Json -Compress
`
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  const [add,same,remove,interactive]=JSON.parse(result.stdout.trim())
  assert.deepEqual([add.changed,add.present,same.changed,same.present,remove.changed,remove.present],[true,true,false,true,true,false])
  assert.equal(interactive.present,true)
})

test('administrator LSA change is confirmed and recorded as an apply run',async()=>{
  const login=await request.post('/api/v1/auth/login').send({email:'owner@rights-change.test',password:'rights-change-password-123'}).expect(200)
  const post=payload=>request.post('/api/v1/logon-rights/change').set('Authorization',`Bearer ${login.body.accessToken}`).send(payload)
  const valid={nodeId,accountSid:'S-1-5-21-1-2-3-999',right:'SeBatchLogonRight',present:true,reason:'Temporary lab account validation',confirmation:'CHANGE LOGON RIGHT'}
  await post({...valid,confirmation:'yes'}).expect(400)
  await post({...valid,accountSid:'S-1-5-32-544'}).expect(409)
  await post({...valid,right:'SeNetworkLogonRight',present:false}).expect(409)
  await post({...valid,right:'SeDenyNetworkLogonRight',present:true}).expect(409)
  const changed=await post(valid).expect(200)
  assert.equal(changed.body.present,true)
  const interactive=await post({...valid,right:'SeInteractiveLogonRight'}).expect(200)
  assert.equal(interactive.body.right,'SeInteractiveLogonRight')
  assert.equal(one('SELECT status FROM policy_apply_runs WHERE id=?',changed.body.runId).status,'success')
  assert.equal(one('SELECT action FROM audit_log WHERE action=? AND entity_id=?','logon-rights.change',nodeId).action,'logon-rights.change')
  process.env.WINFIRE_TEST_RIGHTS_WRONG='1'
  try{await post({...valid,present:false}).expect(502)}finally{delete process.env.WINFIRE_TEST_RIGHTS_WRONG}
  assert.equal(one("SELECT status FROM policy_apply_runs WHERE node_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1",nodeId).status,'failed')
})
