import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'

const host=process.env.WINFIRE_TEST_HOST
const username=process.env.WINFIRE_TEST_USER
const password=process.env.WINFIRE_TEST_PASSWORD
if(!host||!username||!password)throw new Error('Set WINFIRE_TEST_HOST, WINFIRE_TEST_USER and WINFIRE_TEST_PASSWORD for a disposable Windows test host')

const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-rights-write-'))
process.env.DATA_DIR=temporary
process.env.BOOTSTRAP_EMAIL='rights-write@example.test'
process.env.BOOTSTRAP_PASSWORD='temporary-rights-write-12345'
let database,node,remote,one,accountSid,mutationAttempted=false,cleaned=false
const right='SeBatchLogonRight'
function assigned(lines){
  return (Array.isArray(lines)?lines:[lines]).some(line=>String(line).startsWith(`${right} = `)&&String(line).split(' = ')[1].split(',').some(item=>item.replace(/^\*/,'')===accountSid))
}
try{
  const dbModule=await import('../src/db.js')
  database=dbModule.db;one=dbModule.one
  const {bootstrap}=await import('../src/security.js')
  const {app}=await import('../src/app.js')
  ;({remote}=await import('../src/connector.js'))
  await bootstrap()
  const request=supertest(app)
  const login=await request.post('/api/v1/auth/login').send({email:process.env.BOOTSTRAP_EMAIL,password:process.env.BOOTSTRAP_PASSWORD}).expect(200)
  const auth=req=>req.set('Authorization',`Bearer ${login.body.accessToken}`)
  const credential=await auth(request.post('/api/v1/credentials')).send({name:'Temporary LSA write test',type:'domain',username,password}).expect(201)
  const created=await auth(request.post('/api/v1/nodes')).send({hostname:host,ip:host,credentialIds:[credential.body.id]}).expect(201)
  const probe=await auth(request.post(`/api/v1/nodes/${created.body.id}/probe`)).send({}).expect(200)
  if(!['winrm','winrms'].includes(probe.body.transport))throw new Error(`WinRM was not detected: ${probe.body.transport}`)
  node=one('SELECT * FROM nodes WHERE id=?',created.body.id)
  accountSid=`S-1-5-21-${Array.from({length:4},()=>crypto.randomInt(100000,2000000000)).join('-')}`
  if(assigned(await remote(node,'rights')))throw new Error('Synthetic test SID unexpectedly has a batch logon right')
  const body={nodeId:node.id,accountSid,right,present:true,reason:'Reversible synthetic SID connector test',confirmation:'CHANGE LOGON RIGHT'}
  mutationAttempted=true
  const applied=await auth(request.post('/api/v1/logon-rights/change')).send(body).expect(200)
  if(!applied.body.changed||!assigned(await remote(node,'rights')))throw new Error('Live LSA addition did not persist')
  const removed=await auth(request.post('/api/v1/logon-rights/change')).send({...body,present:false}).expect(200)
  if(!removed.body.changed||assigned(await remote(node,'rights')))throw new Error('Live LSA removal did not persist')
  cleaned=true
  console.log(JSON.stringify({host,transport:probe.body.transport,right,added:true,removed:true,remaining:false,applyRuns:one('SELECT COUNT(*) count FROM policy_apply_runs WHERE node_id=?',node.id).count}))
} finally {
  if(node&&remote&&accountSid&&mutationAttempted&&!cleaned){
    try {
      if(assigned(await remote(node,'rights'))){
        await remote(node,'rights_change',{accountSid,right,present:false})
        if(assigned(await remote(node,'rights')))throw new Error('Synthetic SID still has the right after cleanup')
        console.error('Fallback cleanup removed the synthetic right')
      }
    }catch(error){console.error(`CHECK TEST HOST ${host}: synthetic SID ${accountSid}: ${error.message}`);process.exitCode=1}
  }
  database?.close()
  fs.rmSync(temporary,{recursive:true,force:true})
}
