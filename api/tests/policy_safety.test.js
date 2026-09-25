import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import supertest from 'supertest'
const dir=fs.mkdtempSync(os.tmpdir()+'/winfire-safety-');process.env.DATA_DIR=dir;process.env.NODE_ENV='test'
const {app}=await import('../src/app.js'),{db,run,one,all,id,now,json}=await import('../src/db.js'),{issueAccess}=await import('../src/security.js')
const {nodeCoverage,capabilityEvidence,fleetCoverage}=await import('../src/services/capabilities.js')
const {queueSimulation,processSimulations,simulation,simulationResults,approveSimulation,evaluatePolicyImpact,ruleMatch}=await import('../src/services/policySimulation.js')
const owner={id:id(),email:'safety@example.test',role:'owner'}
run('INSERT INTO users(id,email,password_hash,role,email_verified) VALUES(?,?,?,?,1)',owner.id,owner.email,'fixture',owner.role)
const request=supertest(app),as=r=>r.set('Authorization','Bearer '+issueAccess(one('SELECT * FROM users WHERE id=?',owner.id)))
run("INSERT INTO app_settings(key,value) VALUES('local_asset_cidrs','[\"10.42.0.0/24\"]') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
for(const [key,transport,source] of [['windows','winrm','manual'],['snmp','snmp','snmp'],['arc',null,'azure-arc'],['linux','ssh','manual']])run('INSERT INTO nodes(id,hostname,ip,transport,inventory_source) VALUES(?,?,?,?,?)',key,key,'10.42.0.'+({windows:1,snmp:2,arc:3,linux:4}[key]),transport,source)
const node=key=>one('SELECT * FROM nodes WHERE id=?',key)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})
test('coverage distinguishes visibility, cloud heartbeat, stale events and flow evidence',()=>{
 for(const c of ['authentication','facts','verification'])capabilityEvidence('snmp',c,'snmp')
 let coverage=nodeCoverage(node('snmp'));assert.equal(coverage.capabilities.verification.state,'fresh');assert.equal(coverage.capabilities.firewallWrite.state,'unsupported');assert.equal(coverage.capabilities.events.state,'unsupported');assert.equal(coverage.learningReady,false)
 coverage=nodeCoverage(node('arc'));assert.equal(coverage.cloudObservationOnly,true);assert.equal(coverage.capabilities.authentication.state,'unsupported')
 capabilityEvidence('windows','authentication','winrm');capabilityEvidence('windows','events','winrm');assert.equal(nodeCoverage(node('windows')).learningReady,true)
 run("UPDATE node_capability_evidence SET last_success_at='2000-01-01T00:00:00.000Z' WHERE node_id='windows' AND capability='events'");assert.equal(nodeCoverage(node('windows')).learningReady,false)
 capabilityEvidence('snmp','flows','ipfix');assert.equal(nodeCoverage(node('snmp')).capabilities.flows.state,'fresh')
 const report=fleetCoverage();assert.equal(report.eligibleDenominator,4);assert.equal(report.breakdown.transport.snmp.eligible,1)
})
const policyId=id(),versionId=id(),graph={nodes:[{id:'rule-one',type:'allow',position:{x:0,y:0},data:{name:'Web',protocol:'TCP',direction:'out',remotePort:'443',remoteAddress:'Any'}}],edges:[]}
run('INSERT INTO policies(id,name,owner_user_id) VALUES(?,?,?)',policyId,'Safety fixture',owner.id)
const {compilePolicy}=await import('../../packages/shared/index.js')
run('INSERT INTO policy_versions(id,policy_id,version_no,graph_json,rules_compiled_json) VALUES(?,?,?,?,?)',versionId,policyId,1,json(graph),json(compilePolicy(graph,policyId)))
run('UPDATE policies SET current_version_id=? WHERE id=?',versionId,policyId)
function event(){const key=id();run('INSERT INTO log_events(id,node_id,event_id,action,protocol,src_ip,dst_ip,dst_port,direction,event_type,event_time) VALUES(?,?,?,?,?,?,?,?,?,?,?)',key,'windows',5156,'allow','TCP','10.42.0.1','203.0.113.1',443,'out','firewall',now());return key}
const query=()=>({baseVersionId:versionId,nodeIds:['windows'],from:new Date(Date.now()-3600000).toISOString(),to:new Date(Date.now()+1000).toISOString()})
test('historical replay pins evidence, survives log removal, summaries match, approvals invalidate',()=>{
 capabilityEvidence('windows','events','winrm');const key=event(),job=queueSimulation(policyId,query(),owner);assert.ok(job.evidence_hash)
 run('DELETE FROM log_events WHERE id=?',key);processSimulations();const done=simulation(job.id,owner);assert.equal(done.status,'completed');assert.equal(done.processed,1);const results=simulationResults(job.id,owner);assert.equal(results.total,1);assert.equal(results.items[0].flow.destinationIp,'203.0.113.1');assert.equal(Object.values(done.summary).reduce((a,b)=>a+b,0),results.total)
 assert.equal(approveSimulation(job.id,'Reviewed matching traffic',owner).approvalValid,true)
 run("UPDATE nodes SET transport='wmi' WHERE id='windows'");assert.equal(simulation(job.id,owner).approvalValid,false);run("UPDATE nodes SET transport='winrm' WHERE id='windows'")
 assert.equal(one('SELECT COUNT(*) n FROM policy_apply_runs').n,0)
 assert.throws(()=>simulationResults(job.id,owner,{pageSize:-1}))
})
test('unsupported platform, missing profile, missing coverage stay indeterminate',()=>{
 const r=compilePolicy(graph,policyId)[0],e={id:'x',node_id:'n',action:'allow',direction:'out',protocol:'TCP',src_ip:'10.42.0.1',dst_ip:'203.0.113.1',dst_port:443}
 assert.equal(ruleMatch({...r,profile:'Domain'},e).match,null)
 assert.equal(ruleMatch({...r,profile:'Domain'},{...e,profile:'Private'}).match,false)
 assert.equal(evaluatePolicyImpact({nodes:[{id:'n',transport:'ssh'}],rules:[r],baselineRules:[r]},e).outcome,'indeterminate')
 assert.equal(evaluatePolicyImpact({nodes:[{id:'n',transport:'winrm',coverage:{learningReady:false}}],rules:[r],baselineRules:[r]},e).outcome,'indeterminate')
})
test('observe runs do not starve historical work; API validates and exposes results',async()=>{
 const stamp=Date.now();const observe=queueSimulation(policyId,{...query(),kind:'observe',from:new Date(stamp).toISOString(),to:new Date(stamp+3600000).toISOString()},owner)
 const historical=queueSimulation(policyId,query(),owner);for(let i=0;i<4;i++)processSimulations()
 assert.equal(simulation(historical.id,owner).status,'completed');assert.equal(simulation(observe.id,owner).status,'observing')
 await as(request.get('/api/v1/policies/'+policyId+'/simulations')).expect(200)
 await as(request.get('/api/v1/policy-simulations/'+historical.id+'/results?pageSize=-1')).expect(400)
 await as(request.post('/api/v1/policy-simulations/'+observe.id+'/cancel')).send({}).expect(200)
 assert.equal(simulation(observe.id,owner).status,'cancelled')
})
const {proposeMetadata,reviewMetadata,templateGraph}=await import('../src/services/applicationContext.js')
const {createException,reviewException,retirementPreview,ruleHygiene}=await import('../src/services/ruleLifecycle.js')
test('metadata review shows group impact and stale proposals fail closed; scoped service templates compile',()=>{
 const group=id();run('INSERT INTO node_groups(id,name,dynamic_enabled,dynamic_rules_json,dynamic_match) VALUES(?,?,1,?,?)',group,'Application servers',json([{field:'application',operator:'equals',value:'billing'}]),'all')
 const proposal=proposeMetadata('windows',{source:'manual',sourceRef:'test',values:{application:'billing',workload_role:'dns-server'}},owner.id);assert.equal(proposal.groupChanges[0].action,'add')
 const stale=proposeMetadata('windows',{source:'manual',sourceRef:'test',values:{application:'other'}},owner.id)
 reviewMetadata(proposal.id,{approve:true,reason:'Reviewed application membership'},owner.id);assert.equal(node('windows').application,'billing')
 assert.throws(()=>reviewMetadata(stale.id,{approve:true,reason:'Try stale target'},owner.id),/changed|reviewed/)
 const preview=templateGraph({templateId:'dns',endpointNodeIds:['windows']});assert.ok(compilePolicy(preview.graph,policyId).length);assert.ok(!JSON.stringify(preview.graph).includes('0.0.0.0/0'))
 assert.throws(()=>templateGraph({templateId:'files',endpointNodeIds:['windows']}),/file-server/)
})
test('exception ownership and recertification are audited; retirement produces a draft without enforcement',()=>{
 const future=new Date(Date.now()+86400000).toISOString(),e=createException(policyId,{versionId,ruleId:'rule-one',owner:'Network team',justification:'Scoped service access',reviewAt:future},owner)
 assert.throws(()=>createException(policyId,{versionId,ruleId:'foreign-rule',owner:'Network team',justification:'No',reviewAt:future},owner),/owned by/)
 reviewException(e.id,{action:'retire',reason:'Service decommissioned'},owner);const preview=retirementPreview(e.id,owner);assert.equal(preview.graph.nodes.length,0);assert.equal(one('SELECT current_version_id FROM policies WHERE id=?',policyId).current_version_id,versionId);assert.equal(one('SELECT count(*) n FROM policy_apply_runs').n,0);assert.equal(ruleHygiene(policyId,owner).unusedConclusion,'not-established')
 assert.ok(one("SELECT id FROM audit_log WHERE action='rule.exception.retire' AND entity_id=?",e.id))
})
test('offline agent heartbeat cannot be masked by older authenticated transport evidence',()=>{
 const agentId=id();run("INSERT INTO agents(id,node_id,last_checkin_at) VALUES(?,?,'2000-01-01T00:00:00Z')",agentId,'windows');run("UPDATE nodes SET connection_mode='agent',agent_id=? WHERE id='windows'",agentId)
 const coverage=nodeCoverage(node('windows'));assert.equal(coverage.agentOnline,false);assert.equal(coverage.capabilities.authentication.state,'stale');assert.equal(coverage.learningReady,false);assert.equal(coverage.transport,'agent')
})
test('configured OU source changes produce reviewed proposals; manual metadata keeps precedence',async()=>{
 const {saveMetadataSources,refreshMetadataSources,reviewMetadata,proposeMetadata}=await import('../src/services/applicationContext.js');run("INSERT INTO nodes(id,hostname,ip) VALUES('metadata-node','metadata-node','10.42.0.50')");run("UPDATE nodes SET ad_dn='CN=metadata-node,OU=Servers,DC=example,DC=com' WHERE id='metadata-node'");saveMetadataSources({enabled:true,dependencyAlerts:false,rules:[{id:'servers',source:'ad-ou',dn:'OU=Servers,DC=example,DC=com',values:{application:'Directory'}}]},owner.id);assert.ok(refreshMetadataSources().created>=1);const first=one("SELECT id FROM application_metadata_proposals WHERE node_id='metadata-node' AND source='ad-ou' ORDER BY rowid DESC");reviewMetadata(first.id,{approve:true,reason:'Reviewed OU membership targets'},owner.id);assert.equal(node('metadata-node').application,'Directory');const manual=proposeMetadata('metadata-node',{source:'manual',sourceRef:'owner',values:{application:'Identity'}},owner.id);reviewMetadata(manual.id,{approve:true,reason:'Explicit owner attribution'},owner.id);saveMetadataSources({enabled:true,dependencyAlerts:false,rules:[{id:'servers',source:'ad-ou',dn:'OU=Servers,DC=example,DC=com',values:{application:'Changed directory'}}]},owner.id);refreshMetadataSources();const next=one("SELECT id FROM application_metadata_proposals WHERE node_id='metadata-node' AND source='ad-ou' ORDER BY rowid DESC");assert.notEqual(next.id,first.id);reviewMetadata(next.id,{approve:true,reason:'Reviewed changed source'},owner.id);assert.equal(node('metadata-node').application,'Identity');assert.equal(refreshMetadataSources().created,0)
})
test('pinned effective Windows defaults and foreign blocks yield newly allowed/blocked or indeterminate outcomes',()=>{
 const rule={name:'HTTPS',sourceNodeId:'https',action:'allow',direction:'out',protocol:'TCP',localPort:'Any',remotePort:'443',remoteAddress:'8.8.8.8',program:'Any',profile:'Any'},event={id:'flow',node_id:'context-test',direction:'out',protocol:'TCP',dst_ip:'8.8.8.8',src_ip:'10.42.0.50',dst_port:443,src_port:50000,action:'block'},context={complete:true,serviceRunning:true,authenticatedBypassExcluded:true,profiles:['Domain','Private','Public'].map(name=>({name,enabled:true,localRules:true,inboundRules:true,inbound:'block',outbound:'block'})),rules:[]},snapshot={policyId:'test',baselineRules:[],rules:[rule],nodes:[{id:'context-test',transport:'winrm',firewallContext:context}]};assert.equal(evaluatePolicyImpact(snapshot,event).outcome,'newly-allowed');assert.equal(evaluatePolicyImpact({...snapshot,baselineRules:[rule],rules:[]},event).outcome,'newly-blocked');context.rules=[{...rule,name:'Foreign block',group:'Other',action:'block'}];assert.equal(evaluatePolicyImpact(snapshot,event).outcome,'unchanged');context.rules=[{...context.rules[0],unsupportedQualifiers:true}];assert.equal(evaluatePolicyImpact(snapshot,event).outcome,'indeterminate');context.rules=[];context.authenticatedBypassExcluded=false;assert.equal(evaluatePolicyImpact(snapshot,event).outcome,'indeterminate')
})
test('Azure tag changes and removals generate reviewed membership diffs and preserve source fallback',async()=>{
 const {saveMetadataSources,refreshMetadataSources,reviewMetadata,metadataPreview}=await import('../src/services/applicationContext.js');const source=id();run("INSERT INTO nodes(id,hostname,ip,ad_dn) VALUES('tag-node','tag-node','10.42.0.51','CN=tag-node,OU=Servers,DC=example,DC=com')");run("INSERT INTO asset_sources(id,provider,tenant_id,resource_id,node_id,state,evidence_json,fetched_at,first_seen_at) VALUES(?,?,?,?,?,'linked',?,?,?)",source,'azure-vm','fixture-tenant','/fixture/vm','tag-node',json({tags:{application:'billing'}}),now(),now());saveMetadataSources({enabled:true,dependencyAlerts:false,rules:[{id:'azure-app',source:'azure-tag',tag:'application',field:'application'},{id:'ou-app',source:'ad-ou',dn:'OU=Servers,DC=example,DC=com',values:{application:'directory'}}]},owner.id)
 refreshMetadataSources();let p=one("SELECT id FROM application_metadata_proposals WHERE node_id='tag-node' AND source='ad-ou' ORDER BY rowid DESC");reviewMetadata(p.id,{approve:true,reason:'Fallback ownership'},owner.id);refreshMetadataSources();p=one("SELECT id FROM application_metadata_proposals WHERE node_id='tag-node' AND source='azure-tag' ORDER BY rowid DESC");reviewMetadata(p.id,{approve:true,reason:'Reviewed Azure application'},owner.id);assert.equal(node('tag-node').application,'billing')
 run('UPDATE asset_sources SET evidence_json=? WHERE id=?',json({tags:{application:'payments'}}),source);refreshMetadataSources();p=one("SELECT id FROM application_metadata_proposals WHERE node_id='tag-node' AND source='azure-tag' ORDER BY rowid DESC");assert.equal(metadataPreview(p.id).effective.application,'payments');assert.equal(node('tag-node').application,'billing');reviewMetadata(p.id,{approve:true,reason:'Changed tag reviewed'},owner.id);assert.equal(node('tag-node').application,'payments')
 run('UPDATE asset_sources SET evidence_json=? WHERE id=?',json({tags:{}}),source);refreshMetadataSources();p=one("SELECT id FROM application_metadata_proposals WHERE node_id='tag-node' AND source='azure-tag' ORDER BY rowid DESC");assert.equal(metadataPreview(p.id).effective.application,'directory');reviewMetadata(p.id,{approve:true,reason:'Tag removed, retain reviewed OU fallback'},owner.id);assert.equal(node('tag-node').application,'directory')
})
test('Windows dynamic port keywords remain indeterminate rather than ignoring a possible foreign block',()=>{const m=ruleMatch({direction:'in',protocol:'TCP',localPort:'RPC',remotePort:'Any',remoteAddress:'Any',profile:'Any'}, {direction:'in',protocol:'TCP',dst_port:50000,src_port:40000,src_ip:'10.42.0.2',dst_ip:'10.42.0.1'});assert.equal(m.match,null);assert.equal(ruleMatch({direction:'in',protocol:'ICMPv4',localPort:'Any',remotePort:'Any',remoteAddress:'Any',profile:'Any'},{direction:'in',protocol:1,src_ip:'10.42.0.2',dst_ip:'10.42.0.1'}).match,true)})
