import fs from 'node:fs'
import os from 'node:os'
import assert from 'node:assert/strict'
const dir=fs.mkdtempSync(os.tmpdir()+'/winfire-operational-load-')
process.env.DATA_DIR=dir;process.env.NODE_ENV='test'
const {db,run,one,id,now,json}=await import('../api/src/db.js')
const {discoverAzure}=await import('../api/src/cloud/azureAdapter.js')
const {saveExporter,saveObservations}=await import('../api/src/telemetry/service.js')
const {processTrafficCorrelations}=await import('../api/src/telemetry/correlation.js')
const {enrollReporter}=await import('../api/src/ai/reporters.js'),{ingestBatch}=await import('../api/src/ai/ingestion.js'),{processAiWork}=await import('../api/src/ai/observations.js')
const {queueSimulation,processSimulations,simulation}=await import('../api/src/services/policySimulation.js')
const {evidenceSnapshot,saveEvidenceDestination,queueEvidenceSnapshot,deliverEvidence}=await import('../api/src/services/evidenceExports.js')
const {searchLogEvents}=await import('../api/src/logSearch.js')
const {compilePolicy}=await import('../packages/shared/index.js')
const timings={},measure=(name,fn)=>{const start=performance.now(),result=fn();timings[name]=Number((performance.now()-start).toFixed(2));return result},asyncMeasure=async(name,fn)=>{const start=performance.now(),result=await fn();timings[name]=Number((performance.now()-start).toFixed(2));return result}
try{
  const owner={id:id(),email:'benchmark@example.test',role:'owner'}
  run('INSERT INTO users(id,email,password_hash,role) VALUES(?,?,?,?)',owner.id,owner.email,'fixture',owner.role)
  run("INSERT INTO app_settings(key,value) VALUES('local_asset_cidrs','[\"10.42.0.0/24\"]') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
  run("INSERT INTO nodes(id,hostname,ip,transport) VALUES('host','Host','10.42.0.2','winrm'),('sensor','Sensor','10.42.0.1','snmp')")
  const subscription='11111111-1111-4111-8111-111111111111',base=`/subscriptions/${subscription}`,vms=Array.from({length:1500},(_,i)=>({id:`${base}/resourceGroups/test/providers/Microsoft.Compute/virtualMachines/vm-${i}`,name:'VM '+i,type:'Microsoft.Compute/virtualMachines',properties:{}}))
  const client={requests:0,async request(url){this.requests++;return url.includes('Authorization/permissions')?{value:[{actions:['*'],notActions:[]}]}:{value:url.includes('Compute/virtualMachines')?vms:[]}}}
  const discovered=await asyncMeasure('readOnlyDiscoveryMs',()=>discoverAzure({subscriptions:[subscription],resourceGroups:[],tags:{}},{tenantId:subscription},client));assert.equal(discovered.records.length,1500)
  const at=now(),put=db.prepare("INSERT INTO log_events(id,node_id,record_id,event_id,event_type,action,protocol,src_ip,dst_ip,src_port,dst_port,direction,event_time) VALUES(?,'host',?,5156,'firewall','allow','TCP','10.42.0.2','8.8.8.8',50000,443,'out',?)")
  measure('endpointIngest2000Ms',()=>db.transaction(()=>{for(let i=0;i<2000;i++)put.run('load-'+i,i+1,at)})())
  const exporter=saveExporter({name:'Fixture sensor',nodeId:'sensor',format:'ipfix-v10',enabled:true},owner.id)
  const records=Array.from({length:500},(_,i)=>({srcIp:'10.42.0.2',dstIp:'8.8.8.8',srcPort:51000+i,dstPort:443,protocol:'TCP',eventTime:at,metadata:{samplingInterval:1}}))
  assert.equal(measure('flowIngest500Ms',()=>saveObservations(exporter,records,'fixture')).accepted,500)
  const reporter=enrollReporter({name:'Benchmark reporter',nodeIds:['host'],coverage:'instrumented'},owner.id)
  const reports=Array.from({length:100},(_,i)=>({schemaVersion:1,eventId:'load-ai-'+i,nodeId:'host',operation:'model_request',provider:'local',observedAt:at,outcome:'success'}))
  assert.equal(measure('aiIngest100Ms',()=>ingestBatch(reporter.reporter.id,{events:reports})).counts.accepted,100)
  measure('boundedAiWorkerMs',()=>processAiWork({limit:50}))
  const policy=id(),version=id(),graph={nodes:[{id:'web',type:'allow',data:{name:'Web',protocol:'TCP',direction:'out',remotePort:'443'}}],edges:[]}
  run('INSERT INTO policies(id,name,owner_user_id) VALUES(?,?,?)',policy,'Benchmark policy',owner.id)
  run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json) VALUES(?,?,1,?,?)',version,policy,json(graph),json(compilePolicy(graph,policy)))
  run('UPDATE policies SET current_version_id=? WHERE id=?',version,policy);run("INSERT INTO policy_assignments(id,policy_id,node_id) VALUES(?,?,'host')",id(),policy)
  const job=measure('simulationQueueMs',()=>queueSimulation(policy,{baseVersionId:version,nodeIds:['host'],from:new Date(Date.now()-3600000).toISOString(),to:new Date(Date.now()+1000).toISOString()},owner))
  measure('boundedSimulationWorkerMs',()=>processSimulations({limit:250}))
  const correlations=measure('boundedCorrelationWorkerMs',()=>processTrafficCorrelations({limit:25}));assert.equal(correlations.processed,25)
  const result=measure('eventChunkMs',()=>searchLogEvents(db,{pagination:'cursor',includeTotal:'false'}));assert.equal(result.items.length,100)
  const snapshot=measure('scopeSnapshotMs',()=>evidenceSnapshot());assert.equal(snapshot.total,2)
  const destination=saveEvidenceDestination({name:'Fixture receiver',endpoint:'https://fixture.invalid/receiver',enabled:true},owner.id)
  queueEvidenceSnapshot(destination.id,owner.id)
  await asyncMeasure('mockSignedDeliveryMs',()=>deliverEvidence({fetchImpl:async()=>new Response(null,{status:204})}))
  assert.equal(one('SELECT count(*) n FROM policy_apply_runs').n,0)
  assert.equal(simulation(job.id,owner).processed,250)
  console.log(JSON.stringify({fixture:{discoveredResources:1500,endpointEvents:2000,flowObservations:500,aiReports:100,assets:2},timingsMs:timings,bounds:{aiWorker:50,simulationWorker:250,correlationWorker:25,eventChunk:100},externalNetworkRequests:0,endpointWrites:0,queueDepths:{ai:one('SELECT count(*) n FROM ai_work_queue').n,correlation:one("SELECT count(*) n FROM traffic_correlations WHERE status='pending'").n},note:'Local single-process functional load rehearsal; not a sustained throughput or retention capacity claim'},null,2))
}finally{db.close();fs.rmSync(dir,{recursive:true,force:true})}
