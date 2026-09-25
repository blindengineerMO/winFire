import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'
import {execFileSync} from 'node:child_process'
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-cloud-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='cloud@example.test'
process.env.BOOTSTRAP_PASSWORD='cloud-test-only-password'
const {app}=await import('../src/app.js')
const {bootstrap,issueAccess}=await import('../src/security.js')
const {db,one,run,id}=await import('../src/db.js')
const {azureClient}=await import('../src/cloud/client.js')
const {discoverAzure,normalizeAzure}=await import('../src/cloud/azureAdapter.js')
const {processAzureWork,enqueueRun,getRun}=await import('../src/cloud/service.js')
const {reconcileRecord,resolveConflict}=await import('../src/cloud/inventory.js')
const {assertDirectManagement,isLocalAssetNode}=await import('../src/services/networkBoundary.js')
await bootstrap()
const request=supertest(app),owner=one("SELECT * FROM users WHERE email='cloud@example.test'"),token=issueAccess(owner),auth=req=>req.set('Authorization',`Bearer ${token}`)
const tenant=id(),subscription=id(),uuid=id(),base=`/subscriptions/${subscription}/resourceGroups/fixture`,credentialSecret='cloud-secret-do-not-leak'
const settings={name:'Azure test',tenantId:tenant,clientId:id(),authMethod:'secret',clientSecret:credentialSecret}
let scopeA,scopeB,connection
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})
test('Azure credentials and scoped configuration validate and never disclose secret material',async()=>{
  scopeA=(await auth(request.post('/api/v1/inventory/scopes')).send({name:'VNet A',kind:'azure-vnet',cidrs:['10.0.0.0/24']}).expect(201)).body.id
  scopeB=(await auth(request.post('/api/v1/inventory/scopes')).send({name:'VNet B',kind:'azure-vnet',cidrs:['10.0.0.0/24']}).expect(201)).body.id
  const credential=(await auth(request.post('/api/v1/credentials')).send({type:'azure',...settings}).expect(201)).body
  assert.ok(!JSON.stringify(credential).includes(credentialSecret))
  const {openSealed}=await import('../src/security.js')
  const stored=one('SELECT * FROM credentials WHERE id=?',credential.id)
  assert.equal(stored.type,'azure')
  assert.equal(openSealed(stored.encrypted_blob).clientSecret,credentialSecret)
  assert.ok(!stored.encrypted_blob.includes(credentialSecret))
  const listed=(await auth(request.get('/api/v1/credentials')).expect(200)).body
  const vaultEntry=listed.find(c=>c.id===credential.id)
  assert.equal(vaultEntry.tenantId,settings.tenantId)
  assert.equal(vaultEntry.authMethod,'secret')
  assert.equal(vaultEntry.encrypted_blob,undefined)
  assert.ok(!JSON.stringify(listed).includes(credentialSecret))
  await auth(request.patch('/api/v1/credentials/'+credential.id)).send({password:'incorrect-shape'}).expect(400)
  connection=(await auth(request.post('/api/v1/discovery/azure/connections')).send({name:'Azure fixture',credentialId:credential.id,subscriptions:[subscription],scopeId:scopeA}).expect(201)).body
  const audit=one("SELECT after_json FROM audit_log WHERE entity_id=? ORDER BY at DESC LIMIT 1",credential.id)
  assert.ok(!JSON.stringify(audit).includes(credentialSecret))
  await request.get('/api/v1/discovery/azure/connections').expect(401)
})
test('Azure vault authentication changes discard obsolete secrets and retain the credential identity',async()=>{
  const credential=(await auth(request.post('/api/v1/credentials')).send({type:'azure',...settings,name:'Rotating identity'}).expect(201)).body
  const rotated=(await auth(request.patch('/api/v1/credentials/'+credential.id)).send({authMethod:'managed-identity'}).expect(200)).body
  assert.equal(rotated.id,credential.id)
  const {openSealed}=await import('../src/security.js')
  const saved=openSealed(one('SELECT encrypted_blob FROM credentials WHERE id=?',credential.id).encrypted_blob)
  assert.equal(saved.authMethod,'managed-identity')
  assert.equal(saved.clientSecret,undefined)
  await auth(request.patch('/api/v1/credentials/'+credential.id)).send({authMethod:'secret'}).expect(400)
})
const record=(name,scopeIp='10.0.0.5')=>({provider:'azure',tenantId:tenant,resourceId:base+'/providers/Microsoft.Compute/virtualMachines/'+name,subscriptionId:subscription,resourceGroup:'fixture',name,hostname:name,kind:'vm',uuid:id(),addresses:[scopeIp],osName:'Linux',networkIds:[]})
test('overlapping private addresses remain separate, strong Arc/VM identities correlate, weak identities require review',()=>{
  const a=record('a'),first=reconcileRecord(a,connection,'first',owner.id)
  const b=record('b'),second=reconcileRecord(b,{...connection,scopeId:scopeB},'second',owner.id)
  assert.notEqual(first.nodeId,second.nodeId)
  const node=one('SELECT * FROM nodes WHERE id=?',first.nodeId)
  assert.equal(node.firewall_state,'unmanaged');assert.equal(node.status,'unknown');assert.equal(isLocalAssetNode(node),true)
  assert.throws(()=>assertDirectManagement(node),/inventory-only/)
  const arc=reconcileRecord({...a,provider:'azure-arc',resourceId:base+'/providers/Microsoft.HybridCompute/machines/a'},connection,'arc',owner.id)
  assert.equal(arc.nodeId,first.nodeId)
  const weak=reconcileRecord(record('weak'),connection,'weak',owner.id)
  assert.equal(weak.state,'conflict');assert.equal(weak.nodeId,null)
  const conflict=one('SELECT id FROM asset_identity_conflicts WHERE source_id=?',weak.sourceId)
  resolveConflict(conflict.id,{action:'link',nodeId:first.nodeId,reason:'Operator verified asset serial'},owner.id)
  resolveConflict(conflict.id,{action:'unlink',reason:'Review reversal'},owner.id)
  assert.equal(reconcileRecord(record('weak'),connection,'again',owner.id).nodeId,null)
  const external=reconcileRecord(record('external','8.8.8.8'),connection,'external',owner.id)
  assert.equal(external.state,'out-of-scope');assert.equal(external.nodeId,null)
  assert.equal(one('SELECT COUNT(*) n FROM nodes').n,2)
})
test('Azure client bounds retries, refreshes tokens, rejects redirects/endpoints and never leaks Azure error bodies',async()=>{
  let authCount=0,reads=0;const sleeps=[]
  const client=azureClient(settings,{sleep:async n=>sleeps.push(n),fetchImpl:async(url,options)=>{
    if(String(url).includes('login.microsoftonline.com')){authCount++;return Response.json({access_token:'opaque-test-token',expires_in:3600})}
    assert.equal(options.method,'GET');reads++
    if(reads===1)return new Response('',{status:401})
    if(reads===2)return new Response('',{status:429,headers:{'retry-after':'999'}})
    if(reads===3)return new Response('',{status:503})
    return Response.json({value:[]})
  }})
  assert.deepEqual(await client.request('/subscriptions/test'),{value:[]});assert.equal(authCount,2);assert.equal(reads,4);assert.equal(sleeps[0],30000)
  await assert.rejects(client.request('https://untrusted.example/test'),/unsupported endpoint/)
  await assert.rejects(client.request('/subscriptions/test',{method:'DELETE'}),/read operations only/)
  const bad=azureClient(settings,{fetchImpl:async()=>Response.json({error_description:credentialSecret},{status:401})})
  await assert.rejects(bad.accessToken(),e=>!e.message.includes(credentialSecret)&&e.code==='authentication_failed')
})
test('adapter paginates over 1000 resources, collects all valid NICs, preserves unknown versions and partial scopes',async()=>{
  const vm=i=>({id:base+'/providers/Microsoft.Compute/virtualMachines/vm'+i,name:'vm'+i,type:'Microsoft.Compute/virtualMachines',properties:{vmId:id(),storageProfile:{osDisk:{osType:'Linux'},imageReference:{offer:'Not an OS version'}},networkProfile:{networkInterfaces:[{id:base+'/providers/Microsoft.Network/networkInterfaces/nic'}]}}})
  const nic={id:base+'/providers/Microsoft.Network/networkInterfaces/nic',properties:{macAddress:'00-11-22-33-44-55',ipConfigurations:[{properties:{privateIPAddress:'10.0.0.8',subnet:{id:base+'/providers/Microsoft.Network/virtualNetworks/a/subnets/one'}}},{properties:{privateIPAddress:'2001:db8::8'}},{properties:{privateIPAddress:'bad'}}]}}
  const client={requests:0,request:async url=>{client.requests++;const u=new URL(url,'https://management.azure.com')
    if(u.pathname.endsWith('/permissions'))return {value:[{actions:['*/read'],notActions:[]}]}
    if(u.pathname.endsWith('virtualMachines'))return u.searchParams.has('page')?{value:[vm(1000)]}:{value:Array.from({length:1000},(_,i)=>vm(i)),nextLink:u.href+'&page=2'}
    if(u.pathname.endsWith('networkInterfaces'))return {value:[nic]}
    return {value:[]}
  }}
  const result=await discoverAzure({...connection,resourceGroups:[],tags:{}},settings,client)
  assert.equal(result.records.length,1001);assert.equal(result.complete,true);assert.equal(result.records[0].osVersion,null);assert.deepEqual(result.records[0].addresses,['10.0.0.8','2001:db8::8'])
  const arc=normalizeAzure({id:base+'/providers/Microsoft.HybridCompute/machines/empty',type:'Microsoft.HybridCompute/machines',properties:{status:'Connected'}},{tenantId:tenant})
  assert.equal(arc.osVersion,null);assert.deepEqual(arc.addresses,[])
  const partial=await discoverAzure({...connection,resourceGroups:[],tags:{}},settings,{request:async()=>{throw Object.assign(new Error('private response'),{code:'permission_denied'})}})
  assert.equal(partial.complete,false);assert.equal(partial.scopes[0].errors.length,4);assert.ok(!JSON.stringify(partial).includes('private response'))
})
test('durable preview has no inventory writes; sync keeps management state, excludes public peers and cancellation is durable',async()=>{
  const before=one('SELECT COUNT(*) n FROM nodes').n
  const observations=[record('fresh','10.0.0.50'),record('outside','8.8.4.4')]
  const adapter=async()=>({records:observations,scopes:[{subscriptionId:subscription,complete:true}],complete:true,requests:1})
  const preview=enqueueRun(connection.id,'preview',owner.id)
  await processAzureWork({adapter,clientFactory:()=>({}),schedule:false})
  assert.equal(getRun(preview.id).status,'completed');assert.equal(one('SELECT COUNT(*) n FROM nodes').n,before)
  const sync=enqueueRun(connection.id,'sync',owner.id)
  await processAzureWork({adapter,clientFactory:()=>({}),schedule:false})
  assert.equal(getRun(sync.id).status,'completed');assert.equal(one('SELECT COUNT(*) n FROM nodes').n,before+1)
  const queued=enqueueRun(connection.id,'sync',owner.id)
  await auth(request.post(`/api/v1/discovery/azure/runs/${queued.id}/cancel`)).expect(200)
  assert.equal(getRun(queued.id).status,'cancelled')
  const resources=(await auth(request.get('/api/v1/discovery/azure/resources')).expect(200)).body
  assert.equal(resources.pageSize,25)
})
test('coverage separates Arc observations, SNMP visibility, stale collection and failed operations',async()=>{
  const {capabilityEvidence,nodeCoverage}=await import('../src/services/capabilities.js')
  const nodeId=id();run("INSERT INTO nodes(id,hostname,ip,scope_id,transport,connection_mode,inventory_source,status) VALUES(?,?,'10.0.0.60',?,'snmp','snmp','discovery','reachable')",nodeId,'SNMP coverage fixture',scopeA)
  capabilityEvidence(nodeId,'authentication','snmp');capabilityEvidence(nodeId,'facts','snmp')
  let coverage=nodeCoverage(one('SELECT * FROM nodes WHERE id=?',nodeId))
  assert.equal(coverage.capabilities.authentication.state,'fresh');assert.equal(coverage.capabilities.firewallWrite.state,'unsupported');assert.equal(coverage.learningReady,false)
  run("UPDATE nodes SET transport='winrm',connection_mode='agentless' WHERE id=?",nodeId)
  capabilityEvidence(nodeId,'events','winrm');run("UPDATE node_capability_evidence SET last_success_at='2020-01-01T00:00:00.000Z' WHERE node_id=? AND capability='events'",nodeId)
  coverage=nodeCoverage(one('SELECT * FROM nodes WHERE id=?',nodeId));assert.equal(coverage.capabilities.events.state,'stale');assert.equal(coverage.learningReady,false)
  capabilityEvidence(nodeId,'firewallRead','winrm',{success:false})
  assert.equal(nodeCoverage(one('SELECT * FROM nodes WHERE id=?',nodeId)).capabilities.firewallRead.state,'failed')
  const arc=one("SELECT * FROM nodes WHERE inventory_source='azure' LIMIT 1")
  const cloud=nodeCoverage(arc);assert.equal(cloud.cloudObservationOnly,true);assert.equal(cloud.capabilities.authentication.state,'unsupported')
  const inventory=(await auth(request.get('/api/v1/nodes?page=1&pageSize=250')).expect(200)).body
  const report=(await auth(request.get('/api/v1/reports/capabilities')).expect(200)).body
  assert.equal(inventory.total,report.eligibleDenominator)
  const exported=(await auth(request.get('/api/v1/discovery/azure/resources/export?scopeId='+scopeA)).expect(200)).body
  const filtered=(await auth(request.get('/api/v1/discovery/azure/resources?scopeId='+scopeA)).expect(200)).body
  assert.equal(exported.total,filtered.total)
})
test('authenticated AD/ESXi UUID evidence preserves node references and provider refresh cannot overwrite host facts',()=>{
  const hardware=id(),nodeId=id(),group='winfire-global-all-nodes'
  run("INSERT INTO nodes(id,hostname,ip,scope_id,inventory_source,ad_guid,os_name,os_version,firewall_state,virtual_machine_details_json) VALUES(?,'AD guest','10.0.0.71',?,'ad',?,'Authenticated OS','6.1','learning',?)",nodeId,scopeA,id(),JSON.stringify({uuid:hardware}))
  run('INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?)',nodeId,JSON.stringify({identity:{biosUuid:hardware}}),new Date().toISOString())
  const incoming={...record('arc-ad','10.0.0.71'),uuid:hardware,provider:'azure-arc',osName:'Weak OS',osVersion:'wrong'}
  const linked=reconcileRecord(incoming,connection,'ad-arc',owner.id)
  assert.equal(linked.nodeId,nodeId);assert.equal(linked.reason,'Hardware/VM UUID')
  assert.ok(one('SELECT 1 FROM node_group_members WHERE node_id=? AND group_id=?',nodeId,group))
  assert.equal(one('SELECT os_name FROM nodes WHERE id=?',nodeId).os_name,'Authenticated OS')
  reconcileRecord({...incoming,osName:'New provider OS'},connection,'ad-arc-refresh',owner.id)
  assert.equal(one('SELECT firewall_state FROM nodes WHERE id=?',nodeId).firewall_state,'learning')
  assert.equal(one('SELECT os_name FROM nodes WHERE id=?',nodeId).os_name,'Authenticated OS')
})
test('read-only roles cannot mutate cloud discovery and OpenAPI includes dedicated schemas',async()=>{
  const auditor=one("SELECT * FROM users WHERE email='cloud@example.test'")
  run("UPDATE users SET role='auditor' WHERE id=?",auditor.id)
  try{
    await auth(request.get('/api/v1/discovery/azure/resources')).expect(200)
    await auth(request.post(`/api/v1/discovery/azure/connections/${connection.id}/sync`)).expect(403)
    await auth(request.post('/api/v1/credentials')).send({type:'azure',...settings}).expect(403)
  }finally{run("UPDATE users SET role='owner' WHERE id=?",auditor.id)}
  const spec=(await request.get('/api/v1/openapi.json').expect(200)).body
  assert.ok(spec.paths['/discovery/azure/connections/{id}/sync'].post.responses['202'])
  assert.ok(spec.components.schemas.AzureCredentialRequest.properties.clientCertificatePem)
})
test('permission loss cannot mark missing; restart requeues abandoned runs and rotation invalidates pinned runs',async()=>{
  const source=one("SELECT * FROM asset_sources WHERE state='linked' LIMIT 1"),before=source.missing_runs
  const partial=enqueueRun(connection.id,'sync',owner.id)
  await processAzureWork({schedule:false,clientFactory:()=>({}),adapter:async()=>({records:[],scopes:[{subscriptionId:subscription,complete:false}],complete:false,requests:1})})
  assert.equal(getRun(partial.id).status,'partial');assert.equal(one('SELECT missing_runs FROM asset_sources WHERE id=?',source.id).missing_runs,before)
  const recovered=enqueueRun(connection.id,'preview',owner.id)
  run("UPDATE azure_runs SET status='running',lease_until='2020-01-01T00:00:00.000Z' WHERE id=?",recovered.id)
  await processAzureWork({schedule:false,clientFactory:()=>({}),adapter:async()=>({records:[],scopes:[],complete:true,requests:1})})
  assert.equal(getRun(recovered.id).status,'completed')
  const queued=enqueueRun(connection.id,'sync',owner.id)
  await auth(request.patch('/api/v1/credentials/'+connection.credentialId)).send({...settings,clientSecret:'replacement-test-secret'}).expect(200)
  await processAzureWork({schedule:false,clientFactory:()=>{throw new Error('Should not authenticate a superseded run')}})
  assert.equal(getRun(queued.id).status,'failed');assert.match(getRun(queued.id).error,/changed/)
})
test('Azure certificate validation, tenant mismatch and explicit host identity errors are actionable',async()=>{
  const certDir=fs.mkdtempSync(path.join(os.tmpdir(),'cloud-cert-'))
  try{
    execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=Azure fixture','-days','1','-keyout',path.join(certDir,'key.pem'),'-out',path.join(certDir,'cert.pem')],{stdio:'ignore'})
    const cert={...settings,authMethod:'certificate',clientSecret:undefined,clientCertificatePem:fs.readFileSync(path.join(certDir,'cert.pem'),'utf8'),clientPrivateKeyPem:fs.readFileSync(path.join(certDir,'key.pem'),'utf8')}
    const created=await auth(request.post('/api/v1/credentials')).send({type:'azure',...cert}).expect(201)
    assert.ok(!JSON.stringify(created.body).includes('PRIVATE KEY'))
    assert.throws(()=>azureClient({...cert,clientPrivateKeyPem:'invalid'}),/certificate/)
    const actualNow=Date.now;try{Date.now=()=>actualNow()+3*86400000;assert.throws(()=>azureClient(cert),/expired/)}finally{Date.now=actualNow}
    const wrongTenant=azureClient(settings,{fetchImpl:async()=>Response.json({access_token:'header.'+Buffer.from(JSON.stringify({tid:id()})).toString('base64url')+'.signature',expires_in:3600})})
    await assert.rejects(wrongTenant.accessToken(),e=>e.code==='tenant_mismatch')
    const previous=process.env.AZURE_DISCOVERY_MANAGED_IDENTITY;delete process.env.AZURE_DISCOVERY_MANAGED_IDENTITY
    try{await assert.rejects(azureClient({...settings,authMethod:'managed-identity'}).accessToken(),e=>e.code==='identity_unavailable')}finally{if(previous!==undefined)process.env.AZURE_DISCOVERY_MANAGED_IDENTITY=previous}
  }finally{fs.rmSync(certDir,{recursive:true,force:true})}
})

test('recreated resources stay quarantined across scans and automatic links can be reviewed and reversed',async()=>{
  const original=record('recreated','10.0.0.90'),first=reconcileRecord(original,connection,'identity-original',owner.id)
  const replacement={...original,uuid:id(),hostname:'replacement'}
  assert.equal(reconcileRecord(replacement,connection,'identity-replaced',owner.id).state,'conflict')
  assert.equal(reconcileRecord(replacement,connection,'identity-repeat',owner.id).state,'conflict')
  assert.equal(one('SELECT hostname FROM nodes WHERE id=?',first.nodeId).hostname,original.hostname)
  await auth(request.post(`/api/v1/discovery/azure/resources/${first.sourceId}/resolve`)).send({action:'link',nodeId:first.nodeId,reason:'Operator confirmed replacement retains asset ownership'}).expect(200)
  assert.equal(reconcileRecord(replacement,connection,'identity-reviewed',owner.id).state,'linked')
  await auth(request.post(`/api/v1/discovery/azure/resources/${first.sourceId}/resolve`)).send({action:'unlink',reason:'Reversing source association'}).expect(200)
  assert.equal(reconcileRecord(replacement,connection,'identity-unlinked',owner.id).nodeId,null)
  const history=(await auth(request.get(`/api/v1/discovery/azure/resources/${first.sourceId}/history`)).expect(200)).body
  assert.equal(history.pageSize,25)
  assert.ok(history.items.some(h=>h.after.reason==='Resource identity changed or was recreated'))
  assert.ok(history.items.some(h=>h.after.previousNodeId===first.nodeId&&h.after.action==='unlink'))
  assert.ok(one('SELECT id FROM nodes WHERE id=?',first.nodeId))
  run("UPDATE users SET role='auditor' WHERE id=?",owner.id)
  try{
    await auth(request.get(`/api/v1/discovery/azure/resources/${first.sourceId}/history`)).expect(200)
    await auth(request.post(`/api/v1/discovery/azure/resources/${first.sourceId}/resolve`)).send({action:'ignore',reason:'Not permitted'}).expect(403)
  }finally{run("UPDATE users SET role='owner' WHERE id=?",owner.id)}
})

test('clones, resource moves and IP reuse require review while renames preserve manual fields',()=>{
  const original=record('move-original','10.0.0.91'),first=reconcileRecord(original,connection,'move-original',owner.id)
  const clone={...original,resourceId:original.resourceId+'-clone',name:'clone'}
  assert.equal(reconcileRecord(clone,connection,'clone',owner.id).state,'conflict')
  assert.equal(reconcileRecord({...original,resourceId:original.resourceId.replace('/fixture/','/moved-group/')},connection,'moved',owner.id).state,'conflict')
  const reuse={...record('ip-reused','10.0.0.91'),uuid:id()}
  assert.equal(reconcileRecord(reuse,connection,'ip-reused',owner.id).state,'conflict')
  run('UPDATE nodes SET hostname=? WHERE id=?','Operator chosen name',first.nodeId)
  const renamed=reconcileRecord({...original,name:'renamed',hostname:'Provider renamed host'},connection,'rename',owner.id)
  assert.equal(renamed.nodeId,first.nodeId)
  assert.equal(one('SELECT hostname FROM nodes WHERE id=?',first.nodeId).hostname,'Operator chosen name')
})

test('complete misses require grace and provider confirmation; deletion and re-onboarding preserve the node',async()=>{
  const {saveConnection}=await import('../src/cloud/service.js')
  const cfg=saveConnection({name:'Lifecycle fixture',credentialId:connection.credentialId,subscriptions:[subscription],scopeId:scopeA},owner.id)
  const observed=record('lifecycle','10.0.0.92')
  let records=[observed],complete=true,confirmation='exists'
  const adapter=async()=>({records,scopes:[{subscriptionId:subscription,complete}],complete,requests:1})
  const clientFactory=()=>({request:async()=>{if(confirmation==='missing')throw Object.assign(new Error('Deleted'),{code:'resource_unavailable'});if(confirmation==='denied')throw Object.assign(new Error('Denied'),{code:'permission_denied'});return {id:observed.resourceId}}})
  const sync=async()=>{const job=enqueueRun(cfg.id,'sync',owner.id);await processAzureWork({adapter,clientFactory,schedule:false});return getRun(job.id)}
  await sync()
  const source=one('SELECT * FROM asset_sources WHERE resource_id=?',observed.resourceId.toLowerCase())
  run("UPDATE nodes SET firewall_state='learning' WHERE id=?",source.node_id)
  const groupCount=one('SELECT COUNT(*) n FROM node_group_members WHERE node_id=?',source.node_id).n
  records=[];complete=false;await sync()
  assert.equal(one('SELECT missing_runs FROM asset_sources WHERE id=?',source.id).missing_runs,0)
  complete=true;await sync();await sync();await sync()
  assert.equal(one('SELECT state FROM asset_sources WHERE id=?',source.id).state,'missing')
  run("UPDATE asset_sources SET missing_since='2020-01-01T00:00:00Z' WHERE id=?",source.id)
  confirmation='denied';await sync()
  assert.equal(one('SELECT state FROM asset_sources WHERE id=?',source.id).state,'missing')
  confirmation='exists';await sync()
  assert.equal(one('SELECT state FROM asset_sources WHERE id=?',source.id).state,'missing')
  confirmation='missing';await sync()
  assert.equal(one('SELECT state FROM asset_sources WHERE id=?',source.id).state,'retired')
  assert.equal(one('SELECT firewall_state FROM nodes WHERE id=?',source.node_id).firewall_state,'learning')
  assert.equal(one('SELECT COUNT(*) n FROM node_group_members WHERE node_id=?',source.node_id).n,groupCount)
  records=[observed];await sync()
  const returned=one('SELECT * FROM asset_sources WHERE id=?',source.id)
  assert.equal(returned.node_id,source.node_id);assert.equal(returned.state,'linked');assert.equal(returned.missing_runs,0)
})

test('resource search, sort, pagination and export share the filtered population',async()=>{
  for(let i=0;i<32;i++)reconcileRecord(record('page-'+String(i).padStart(2,'0'),'10.0.0.'+(120+i)),connection,'pagination',owner.id)
  const query='q=page-&scopeId='+scopeA+'&sort=name&direction=asc'
  const page1=(await auth(request.get('/api/v1/discovery/azure/resources?'+query)).expect(200)).body
  const page2=(await auth(request.get('/api/v1/discovery/azure/resources?'+query+'&page=2')).expect(200)).body
  const exported=(await auth(request.get('/api/v1/discovery/azure/resources/export?'+query)).expect(200)).body
  assert.equal(page1.total,32);assert.equal(page1.items.length,25);assert.equal(page2.items.length,7)
  assert.deepEqual(exported.items.map(r=>r.id),[...page1.items,...page2.items].map(r=>r.id))
  assert.equal(new Set(exported.items.map(r=>r.id)).size,32)
})

test('recurring sync recovers an abandoned lease without duplicates and running cancellation writes no assets',async()=>{
  const {saveConnection,cancelRun}=await import('../src/cloud/service.js')
  const cfg=saveConnection({name:'Scheduled fixture',credentialId:connection.credentialId,subscriptions:[subscription],scopeId:scopeA,enabled:true,intervalMinutes:5},owner.id)
  const observation=record('scheduled','10.0.0.190')
  const adapter=async()=>({records:[observation],scopes:[{subscriptionId:subscription,complete:true}],complete:true,requests:1})
  await processAzureWork({adapter,clientFactory:()=>({})})
  assert.equal(one('SELECT status FROM azure_runs WHERE connection_id=?',cfg.id).status,'completed')
  assert.ok(Date.parse(one('SELECT next_run_at FROM azure_connections WHERE id=?',cfg.id).next_run_at)>Date.now())
  const source=one('SELECT node_id FROM asset_sources WHERE resource_id=?',observation.resourceId.toLowerCase())
  const abandoned=enqueueRun(cfg.id,'sync',owner.id)
  run("UPDATE azure_runs SET status='running',lease_until='2020-01-01T00:00:00Z' WHERE id=?",abandoned.id)
  await processAzureWork({adapter,clientFactory:()=>({})})
  assert.equal(getRun(abandoned.id).status,'completed')
  assert.equal(one('SELECT COUNT(*) n FROM azure_runs WHERE connection_id=?',cfg.id).n,2)
  assert.equal(one('SELECT node_id FROM asset_sources WHERE resource_id=?',observation.resourceId.toLowerCase()).node_id,source.node_id)
  const cancelled=enqueueRun(cfg.id,'sync',owner.id),before=one('SELECT COUNT(*) n FROM nodes').n
  await processAzureWork({schedule:false,clientFactory:()=>({}),adapter:async()=>{cancelRun(cancelled.id,owner.id);return {records:[record('cancelled','10.0.0.191')],scopes:[],complete:true,requests:1}}})
  assert.equal(getRun(cancelled.id).status,'cancelled')
  assert.equal(one('SELECT COUNT(*) n FROM nodes').n,before)
})
