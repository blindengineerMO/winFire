import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import supertest from 'supertest'
const dir=fs.mkdtempSync(os.tmpdir()+'/winfire-traffic-evidence-')
process.env.DATA_DIR=dir;process.env.NODE_ENV='test'
const {app}=await import('../src/app.js'),{db,run,one,id,now,json}=await import('../src/db.js')
const {issueAccess}=await import('../src/security.js')
const {saveExporter,saveObservations,observationRows}=await import('../src/telemetry/service.js')
const {correlateObservation,processTrafficCorrelations}=await import('../src/telemetry/correlation.js')
const {cloudPath,evaluateNsg}=await import('../src/telemetry/cloudPath.js')
const owner={id:id(),email:'evidence@example.test',role:'owner'}
run('INSERT INTO users(id,email,password_hash,role) VALUES(?,?,?,?)',owner.id,owner.email,'fixture',owner.role)
const auth=r=>r.set('Authorization','Bearer '+issueAccess(one('SELECT * FROM users WHERE id=?',owner.id)))
run("INSERT INTO app_settings(key,value) VALUES('local_asset_cidrs','[\"10.42.0.0/24\"]') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
run("INSERT INTO nodes(id,hostname,ip,transport) VALUES('router','Router','10.42.0.1','snmp'),('endpoint','Endpoint','10.42.0.2','winrm')")
const exporter=saveExporter({name:'Cloud sensor',nodeId:'router',format:'azure-vnet',enabled:true},owner.id)
const tuple={srcIp:'10.42.0.2',dstIp:'8.8.8.8',srcPort:50000,dstPort:443,protocol:'TCP',eventTime:now(),action:null,metadata:{nat:{sourceIp:null,destinationIp:null}}}
function observation(overrides={}){saveObservations(exporter,[{...tuple,...overrides}],id());return one('SELECT id FROM traffic_observations ORDER BY rowid DESC LIMIT 1').id}
function endpoint(overrides={}){const e={id:id(),node:'endpoint',...tuple,action:'allow',...overrides};run("INSERT INTO log_events(id,node_id,event_id,action,event_type,src_ip,dst_ip,src_port,dst_port,protocol,event_time) VALUES(?,?,5156,?,'firewall',?,?,?,?,?,?)",e.id,e.node,e.action,e.srcIp,e.dstIp,e.srcPort,e.dstPort,e.protocol,e.eventTime);return e.id}
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})
test('same scoped five-tuple associates without merging or multiplying observations',async()=>{
 const key=observation(),match=endpoint();assert.equal(correlateObservation(key).endpointEventId,match)
 assert.equal(processTrafficCorrelations().processed,1)
 const list=observationRows({correlation:'associated'});assert.equal(list.total,1);assert.equal(list.items[0].endpoint_event_id,match)
 const result=await auth(supertest(app).get('/api/v1/telemetry/observations/export?correlation=associated')).expect(200)
 assert.equal(result.body.total,list.total);assert.equal(result.body.items[0].correlation_status,'associated')
 run('DELETE FROM log_events WHERE id=?',match);assert.equal(observationRows({correlation:'associated'}).items[0].endpoint_reference,match)
 assert.equal(observationRows({correlation:'associated'}).items[0].endpoint_event_id,null)
})
test('ambiguous, conflicting, expired, translated, sampled and incomplete evidence stays separate',()=>{
 const key=observation({srcPort:50001});endpoint({srcPort:50001});endpoint({srcPort:50001});assert.equal(correlateObservation(key).status,'ambiguous')
 const conflict=observation({srcPort:50002,action:'block'});endpoint({srcPort:50002});assert.equal(correlateObservation(conflict).status,'conflicting')
 assert.equal(correlateObservation(observation({srcPort:null})).status,'insufficient')
 assert.equal(correlateObservation(observation({metadata:{samplingInterval:10}})).status,'insufficient')
 assert.equal(correlateObservation(observation({metadata:{nat:{sourceIp:'192.0.2.10'}}})).status,'insufficient')
 assert.equal(correlateObservation(observation({eventTime:'2000-01-01T00:00:00Z'})).status,'unmatched')
})
test('overlapping site addresses cannot associate across scopes; late endpoints are retried',()=>{
 run("INSERT INTO inventory_scopes(id,name,cidrs_json,kind,created_at) VALUES('other','Other','[\"10.42.0.0/24\"]','site',?)",now())
 run("INSERT INTO nodes(id,hostname,ip,scope_id) VALUES('other-endpoint','Other endpoint','10.42.0.2','other')")
 const key=observation({srcPort:50003});endpoint({srcPort:50003,node:'other-endpoint'});assert.equal(correlateObservation(key).status,'unmatched')
 processTrafficCorrelations({limit:100});endpoint({srcPort:50003});processTrafficCorrelations({limit:100,at:new Date(Date.now()+120000)})
 assert.equal(one('SELECT status FROM traffic_correlations WHERE observation_id=?',key).status,'associated')
})
const flow={sourceIp:'10.42.0.2',destinationIp:'10.42.0.3',sourcePort:50000,destinationPort:443,protocol:'TCP'}
const rule=(name,priority,access='Allow',extra={})=>({name,properties:{priority,access,direction:'Outbound',protocol:'Tcp',sourceAddressPrefix:'*',destinationAddressPrefix:'10.42.0.0/24',sourcePortRange:'*',destinationPortRange:'443',...extra}})
test('NSG rules use Azure first-match priority, not Windows block precedence',()=>{
 const nsg={properties:{securityRules:[rule('lower-block',200,'Deny'),rule('first-allow',100)],defaultSecurityRules:[]}}
 assert.equal(evaluateNsg(nsg,flow,'Outbound').decision,'allow')
 nsg.properties.securityRules.push(rule('unknown-service-tag',50,'Deny',{sourceAddressPrefix:'AzureCloud'}))
 assert.equal(evaluateNsg(nsg,flow,'Outbound').decision,'indeterminate')
 assert.equal(evaluateNsg({properties:{securityRules:[]}},flow,'Outbound').decision,'indeterminate')
 nsg.properties.securityRules.push(rule('duplicate-priority',100));assert.equal(evaluateNsg(nsg,flow,'Outbound').decision,'indeterminate')
})
test('cloud path uses scoped, current snapshots and distinguishes configuration from reachability',async()=>{
 const connection=id(),vnet='/subscriptions/sub/resourcegroups/rg/providers/microsoft.network/virtualnetworks/net',nsg='/nsg/web'
 run('INSERT INTO azure_connections(id,name,config_json,created_at) VALUES(?,?,?,?)',connection,'Network','{}',now())
 const put=(key,kind,snapshot,at=now())=>run('INSERT INTO cloud_network_context(connection_id,resource_id,kind,snapshot_json,observed_at) VALUES(?,?,?,?,?)',connection,key,kind,json(snapshot),at)
 put(vnet,'virtualNetworks',{properties:{subnets:[{id:vnet+'/subnets/one',properties:{}}]}})
 for(const [key,ip] of [['source',flow.sourceIp],['destination',flow.destinationIp]])put('/nic/'+key,'networkInterfaces',{properties:{networkSecurityGroup:{id:nsg},ipConfigurations:[{properties:{privateIPAddress:ip,subnet:{id:vnet+'/subnets/one'}}}]}})
 put(nsg,'networkSecurityGroups',{properties:{securityRules:[rule('out',100),rule('in',100,'Allow',{direction:'Inbound'})],defaultSecurityRules:[]}})
 let result=cloudPath({connectionId:connection,...flow});assert.equal(result.configurationDecision,'allow');assert.equal(result.reachability,'indeterminate');assert.equal(result.activelyVerified,false)
 const api=await auth(supertest(app).get('/api/v1/mapping/cloud-path').query({connectionId:connection,...flow})).expect(200);assert.deepEqual(api.body.steps,result.steps)
 run('UPDATE cloud_network_context SET observed_at=? WHERE resource_id=?','2000-01-01T00:00:00Z',nsg)
 assert.equal(cloudPath({connectionId:connection,...flow}).configurationDecision,'indeterminate')
 await auth(supertest(app).get('/api/v1/mapping/cloud-path').query({connectionId:connection,...flow,destinationIp:'invalid'})).expect(400)
})
test('complete cloud refresh removes disappeared resources while partial reads preserve prior context',async()=>{
 const {refreshCloudNetwork}=await import('../src/telemetry/vnet.js'),{seal}=await import('../src/security.js')
 const credential=id(),connection=id(),subscription='33333333-3333-4333-8333-333333333333',base=`/subscriptions/${subscription}`,resourceId=base+'/resourceGroups/test/providers/Microsoft.Network/networkInterfaces/new'
 run('INSERT INTO credentials(id,name,type,username,encrypted_blob) VALUES(?,?,?,?,?)',credential,'Cloud fixture','azure','fixture',seal({tenantId:subscription,clientId:subscription,authMethod:'secret',clientSecret:'fixture-secret'}))
 run('INSERT INTO azure_connections(id,name,credential_id,config_json,created_at) VALUES(?,?,?,?,?)',connection,'Cloud refresh',credential,json({subscriptions:[subscription],resourceGroups:[]}),now())
 run('INSERT INTO cloud_network_context(connection_id,resource_id,kind,snapshot_json,observed_at) VALUES(?,?,?,?,?)',connection,'/obsolete','networkInterfaces','{}',now())
 const clientFactory=()=>({async request(url){return {value:url.includes('/networkInterfaces?')?[{id:resourceId,properties:{}}]:[]}}})
 await refreshCloudNetwork(connection,owner.id,{clientFactory})
 assert.equal(one('SELECT count(*) n FROM cloud_network_context WHERE connection_id=?',connection).n,1)
 assert.equal(one('SELECT resource_id FROM cloud_network_context WHERE connection_id=?',connection).resource_id,resourceId.toLowerCase())
 await assert.rejects(()=>refreshCloudNetwork(connection,owner.id,{clientFactory:()=>({async request(){throw Error('Permission denied')}})}),/Permission denied/)
 assert.equal(one('SELECT count(*) n FROM cloud_network_context WHERE connection_id=?',connection).n,1)
})
