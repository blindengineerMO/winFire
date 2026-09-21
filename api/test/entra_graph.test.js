import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {execFileSync} from 'node:child_process'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-entra-graph-test-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@entra-graph.test'
process.env.BOOTSTRAP_PASSWORD='entra-graph-test-password-123'
const {db}=await import('../src/db.js')
const {saveEntraSettings}=await import('../src/entraSettings.js')
const {fetchEntraGroupMembers,syncEntraGroup,entraGroupAllowsOperator,cachedEntraGroupMembers,clearEntraGraphTokenCache}=await import('../src/entraGraph.js')
const {segmentAllowsOperatorAsync}=await import('../src/segmentAccess.js')
const {clientCredentialsForm}=await import('../src/entraClientAuth.js')

const tenant='11111111-1111-1111-1111-111111111111'
const client='22222222-2222-2222-2222-222222222222'
const group='33333333-3333-3333-3333-333333333333'
saveEntraSettings({tenantId:tenant,clientId:client,clientSecret:'test-client-secret',enabled:true},null)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

function response(body,status=200){return {ok:status>=200&&status<300,status,json:async()=>body}}

test('Graph group resolver requests client credentials and follows bounded pagination',async()=>{
  clearEntraGraphTokenCache()
  const calls=[]
  const fetchImpl=async(url,options={})=>{
    calls.push({url,options})
    if(url.includes('/oauth2/'))return response({access_token:'graph-token',expires_in:3600})
    if(url.includes('$skiptoken=next'))return response({value:[{id:'USER-2',mail:'two@example.test',accountEnabled:false}]})
    return response({value:[{id:'USER-1',userPrincipalName:'One@Example.test',mail:null,accountEnabled:true}], '@odata.nextLink':'https://graph.microsoft.com/v1.0/groups/x/members/microsoft.graph.user?$skiptoken=next'})
  }
  const members=await fetchEntraGroupMembers(group,{fetchImpl})
  assert.deepEqual(members,[
    {objectId:'user-1',upn:'one@example.test',email:null,enabled:true},
    {objectId:'user-2',upn:null,email:'two@example.test',enabled:false}
  ])
  assert.equal(calls.length,3)
  assert.match(String(calls[0].options.body),/grant_type=client_credentials/)
  assert.equal(calls[1].options.headers.authorization,'Bearer graph-token')
})

test('group membership is persisted, cached, and used by async segment access',async()=>{
  clearEntraGraphTokenCache()
  let graphCalls=0
  const fetchImpl=async(url)=>{
    graphCalls++
    if(url.includes('/oauth2/'))return response({access_token:'graph-token-2',expires_in:3600})
    return response({value:[{id:'USER-3',userPrincipalName:'casey@example.test',mail:'casey@example.test',accountEnabled:true}]})
  }
  const segment={allowed_upns:'[]',entra_group_id:group}
  assert.equal(await segmentAllowsOperatorAsync(segment,'casey@example.test',{fetchImpl}),true)
  assert.equal(await segmentAllowsOperatorAsync(segment,'other@example.test',{fetchImpl}),false)
  assert.equal(graphCalls,2)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM entra_group_members WHERE group_id=?').get(group).n,1)
  assert.equal(cachedEntraGroupMembers(group).length,1)
  const cached=await syncEntraGroup(group,{fetchImpl})
  assert.equal(cached.cached,true)
  assert.equal('settingsKey' in cached,false)
  assert.equal(await entraGroupAllowsOperator(group,'casey@example.test',{fetchImpl}),true)
})

test('Graph group IDs are validated before any network request',async()=>{
  let called=false
  await assert.rejects(()=>fetchEntraGroupMembers('CN=Operators,DC=example,DC=com',{fetchImpl:async()=>{called=true}}),/object ID \(GUID\)/)
  assert.equal(called,false)
})

test('expired Graph membership fails closed when refresh is unavailable',async()=>{
  const expiringGroup='44444444-4444-4444-4444-444444444444'
  const okFetch=async(url)=>url.includes('/oauth2/')?response({access_token:'graph-token-3',expires_in:3600}):response({value:[{id:'USER-4',userPrincipalName:'stale@example.test',accountEnabled:true}]})
  await syncEntraGroup(expiringGroup,{fetchImpl:okFetch,force:true,ttlMs:1})
  await new Promise(resolve=>setTimeout(resolve,10))
  const failing=async()=>{throw new Error('Graph unavailable')}
  assert.equal(await entraGroupAllowsOperator(expiringGroup,'stale@example.test',{fetchImpl:failing}),false)
})

test('rotating the Entra application secret invalidates the membership cache',async()=>{
  const rotatingGroup='55555555-5555-5555-5555-555555555555'
  const okFetch=async(url)=>url.includes('/oauth2/')?response({access_token:'graph-token-4',expires_in:3600}):response({value:[{id:'USER-5',userPrincipalName:'rotate@example.test',accountEnabled:true}]})
  await syncEntraGroup(rotatingGroup,{fetchImpl:okFetch,force:true})
  saveEntraSettings({tenantId:tenant,clientId:client,clientSecret:'rotated-client-secret',enabled:true},null)
  const failing=async()=>{throw new Error('Graph unavailable')}
  assert.equal(await entraGroupAllowsOperator(rotatingGroup,'rotate@example.test',{fetchImpl:failing}),false)
})

test('certificate Graph credentials emit a PS256 private key assertion',()=>{
  const certificateDir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-entra-graph-cert-'))
  try{
    execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=WinFire graph test','-days','3650','-keyout',path.join(certificateDir,'client.key'),'-out',path.join(certificateDir,'client.crt')],{stdio:'ignore'})
    const settings={tenantId:tenant,clientId:client,clientAuthMethod:'certificate',clientCertificate:fs.readFileSync(path.join(certificateDir,'client.crt'),'utf8'),clientPrivateKey:fs.readFileSync(path.join(certificateDir,'client.key'),'utf8')}
    const form=clientCredentialsForm(settings),parts=form.client_assertion.split('.'),header=JSON.parse(Buffer.from(parts[0],'base64url').toString()),claims=JSON.parse(Buffer.from(parts[1],'base64url').toString())
    assert.equal(header.alg,'PS256')
    assert.ok(header['x5t#S256'])
    assert.equal(claims.iss,client)
    assert.equal(form.client_assertion_type,'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
    assert.equal(form.client_secret,undefined)
  }finally{fs.rmSync(certificateDir,{recursive:true,force:true})}
})
