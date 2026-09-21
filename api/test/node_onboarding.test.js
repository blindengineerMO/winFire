import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-onboarding-test-'))
process.env.DATA_DIR=dataDir
const {onboardPendingNodes}=await import('../src/app.js')
const {db}=await import('../src/db.js')
const {seal}=await import('../src/security.js')
const {activateWinrmViaWmi,probeNode,remote,enrichNode}=await import('../src/connector.js')
test.after(()=>{db.close();fs.rmSync(dataDir,{recursive:true,force:true})})

test('AD node onboarding collects facts, enables auditing, and starts event collection once',async()=>{
  db.prepare("INSERT INTO nodes(id,hostname,fqdn,inventory_source,ad_guid,ad_enabled,ad_missing) VALUES(?,?,?,?,?,1,0)").run('new-ad-node','AD-NODE','ad-node.example.test','ad','ad-guid')
  db.prepare("INSERT INTO credentials(id,name,type,username,encrypted_blob) VALUES(?,?,?,?,?)").run('cred','Domain account','domain','EXAMPLE\\user','unused-by-mock')
  db.prepare('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)').run('cred','new-ad-node')
  const calls=[]
  const handlers={
    resolveDns:async node=>{calls.push('dns');db.prepare('UPDATE nodes SET ip=? WHERE id=?').run('192.0.2.10',node.id)},
    enrich:async node=>{calls.push('facts');db.prepare("UPDATE nodes SET transport='winrm',status='reachable' WHERE id=?").run(node.id);db.prepare('INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?)').run(node.id,'{}',new Date().toISOString())},
    invoke:async(_node,operation)=>{calls.push(operation);return operation==='audit_policy'?{successEnabled:false,failureEnabled:false}:{successEnabled:true,failureEnabled:true}},
    pullRecent:async()=>{calls.push('recent');return {inserted:2}},
    pullHistory:async()=>{calls.push('history');return {inserted:3,caughtUp:false}}
  }
  assert.deepEqual(await onboardPendingNodes(5,handlers),[{nodeId:'new-ad-node',status:'complete'}])
  assert.equal(db.prepare("SELECT status FROM policy_apply_runs WHERE node_id='new-ad-node' ORDER BY rowid DESC LIMIT 1").get().status,'success')
  assert.deepEqual(calls,['dns','facts','audit_policy','audit_policy_enable','recent','history'])
  assert.equal(db.prepare('SELECT ip FROM nodes WHERE id=?').get('new-ad-node').ip,'192.0.2.10')
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE entity_id=? AND action='node.onboarding.complete'").get('new-ad-node').n,1)
  assert.deepEqual(await onboardPendingNodes(5,handlers),[])
})

test('manual agentless onboarding retries a partial event collection and completes the same audit pipeline',async()=>{
  db.prepare("INSERT INTO nodes(id,hostname,ip,connection_mode,inventory_source) VALUES(?,?,?,'agentless','manual')").run('manual-node','MANUAL-NODE','192.0.2.11')
  db.prepare('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)').run('cred','manual-node')
  const calls=[]
  let recentAttempts=0
  const handlers={
    enrich:async node=>{calls.push('facts');db.prepare("UPDATE nodes SET transport='winrm',status='reachable' WHERE id=?").run(node.id);db.prepare('INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?)').run(node.id,'{}',new Date().toISOString())},
    invoke:async(_node,operation)=>{calls.push(operation);return {successEnabled:true,failureEnabled:true}},
    pullRecent:async()=>{calls.push('recent');recentAttempts++;if(recentAttempts===1)throw new Error('Temporary event collection failure');return {inserted:4}},
    pullHistory:async()=>{calls.push('history');return {inserted:6,caughtUp:true}}
  }
  const first=await onboardPendingNodes(5,handlers)
  assert.equal(first[0].nodeId,'manual-node')
  assert.equal(first[0].status,'failed')
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE entity_id='manual-node' AND action='node.onboarding.complete'").get().n,0)
  db.prepare('UPDATE nodes SET next_retry_at=NULL WHERE id=?').run('manual-node')
  assert.deepEqual(await onboardPendingNodes(5,handlers),[{nodeId:'manual-node',status:'complete'}])
  assert.deepEqual(calls,['facts','audit_policy','recent','audit_policy','recent','history'])
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE entity_id='manual-node' AND action='node.onboarding.complete'").get().n,1)
  assert.deepEqual(await onboardPendingNodes(5,handlers),[])
})

test('WMI host completes onboarding with host facts, audit readback, and event pulls',async()=>{
  db.prepare("INSERT INTO nodes(id,hostname,ip,connection_mode,inventory_source,transport) VALUES(?,?,?,'agentless','manual','wmi')").run('wmi-onboard','WMI-ONBOARD','192.0.2.19')
  db.prepare('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)').run('cred','wmi-onboard')
  const calls=[]
  const handlers={
    enrich:async node=>{calls.push('facts');db.prepare("UPDATE nodes SET status='reachable' WHERE id=?").run(node.id);db.prepare('INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?)').run(node.id,'{}',new Date().toISOString())},
    invoke:async(_node,operation)=>{calls.push(operation);return {successEnabled:true,failureEnabled:true}},
    pullRecent:async()=>{calls.push('recent');return {inserted:1}},
    pullHistory:async()=>{calls.push('history');return {inserted:2,caughtUp:true}}
  }
  assert.deepEqual(await onboardPendingNodes(5,handlers),[{nodeId:'wmi-onboard',status:'complete'}])
  assert.deepEqual(calls,['facts','audit_policy','recent','history'])
  assert.deepEqual(await onboardPendingNodes(5,handlers),[])
})

test('XP onboarding collects legacy logons without attempting WFP auditing or firewall training',async()=>{
  db.prepare("INSERT INTO nodes(id,hostname,ip,connection_mode,inventory_source,transport,os_version,firewall_state) VALUES(?,?,?,'agentless','manual','winrm',?,'learning')").run('xp-onboard','XP-ONBOARD','192.0.2.21','5.1.2600')
  db.prepare('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)').run('cred','xp-onboard')
  db.prepare('INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?)').run('xp-onboard','{}',new Date().toISOString())
  db.prepare("UPDATE nodes SET status='reachable' WHERE id='xp-onboard'").run()
  const calls=[]
  const handlers={
    invoke:async()=>{throw new Error('XP must not receive WFP audit commands')},
    pullRecent:async()=>{calls.push('recent');return {inserted:1}},
    pullHistory:async()=>{calls.push('history');return {inserted:2,caughtUp:true}}
  }
  assert.deepEqual(await onboardPendingNodes(5,handlers),[{nodeId:'xp-onboard',status:'complete'}])
  assert.deepEqual(calls,['recent','history'])
  assert.equal(db.prepare("SELECT firewall_state FROM nodes WHERE id='xp-onboard'").get().firewall_state,'unmanaged')
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE entity_id='xp-onboard' AND action='node.onboarding.logon-only'").get().n,1)
  assert.deepEqual(await onboardPendingNodes(5,handlers),[])
})

test('manual WMI host authenticates and checks identity before audited WinRM activation',async()=>{
  db.prepare("INSERT INTO nodes(id,hostname,ip,connection_mode,inventory_source,transport) VALUES(?,?,?,'agentless','manual','wmi')").run('manual-wmi','MANUAL-WMI','192.0.2.12')
  db.prepare("INSERT INTO credentials(id,name,type,username,encrypted_blob,priority) VALUES(?,?,'domain',?,?,?)").run('wmi-bad','Wrong WMI credential','EXAMPLE\\bad',seal({password:'wrong-secret'}),10)
  db.prepare("INSERT INTO credentials(id,name,type,username,encrypted_blob,priority) VALUES(?,?,'domain',?,?,?)").run('wmi-good','Working WMI credential','EXAMPLE\\good',seal({password:'right-secret'}),20)
  for(const credentialId of ['wmi-bad','wmi-good'])db.prepare('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)').run(credentialId,'manual-wmi')
  const node=db.prepare('SELECT * FROM nodes WHERE id=?').get('manual-wmi'),calls=[]
  const result=await activateWinrmViaWmi(node,{
    wmi:async input=>{calls.push(`${input.mode}:${input.username}`);assert.equal(input.expectedName,'MANUAL-WMI');if(input.username.endsWith('bad'))throw new Error('WMI access denied');return input.mode==='probe'?{success:true,transport:'wmi',computerName:'MANUAL-WMI'}:{success:true,transport:'wmi',computerName:'MANUAL-WMI',activationStarted:true,activationSucceeded:true}},
    probePort:async()=>({status:'open'}),wait:async()=>{},
    invoke:async(_node,operation,_args,options)=>{calls.push(operation);assert.equal(options.credentialId,'wmi-good');return operation==='facts'?{computer:{Name:'MANUAL-WMI'},os:{Version:'10.0.20348'}}:'EXAMPLE\\good'},
    collect:async(_node,{suppliedFacts})=>{calls.push('facts-collected');assert.equal(suppliedFacts.computer.Name,'MANUAL-WMI')}
  })
  assert.equal(result.transport,'winrm')
  assert.deepEqual(calls,['probe:EXAMPLE\\bad','probe:EXAMPLE\\good','enable_winrm:EXAMPLE\\good','auth','facts','facts-collected'])
  assert.equal(db.prepare('SELECT transport FROM nodes WHERE id=?').get(node.id).transport,'winrm')
  assert.equal(db.prepare('SELECT status FROM policy_apply_runs WHERE node_id=? ORDER BY rowid DESC LIMIT 1').get(node.id).status,'success')
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE entity_id=? AND action='node.agentless.activate'").get(node.id).n,1)
  let activationCalls=0
  await assert.rejects(activateWinrmViaWmi(node,{wmi:async input=>{if(input.mode==='enable_winrm')activationCalls++;return {success:true,transport:'wmi',computerName:'WRONG-HOST'}}}),/does not match the inventory record/)
  assert.equal(activationCalls,0)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM policy_apply_runs WHERE node_id=?').get(node.id).n,1)
})

test('node probing tries WMI after open WinRM ports fail authentication',async()=>{
  db.prepare('INSERT INTO nodes(id,hostname,ip) VALUES(?,?,?)').run('probe-fallback','PROBE-FALLBACK','192.0.2.13')
  const node=db.prepare('SELECT * FROM nodes WHERE id=?').get('probe-fallback'),calls=[]
  const ports=async(_host,port)=>({status:[5985,5986,135].includes(port)?'open':'refused'})
  const fallback=await probeNode(node,{
    probePort:ports,
    authenticate:async(target)=>{calls.push(target.transport);throw new Error(`${target.transport} denied access`)},
    authenticateRpc:async()=>{calls.push('rpc');return 'srvinfo success'}
  })
  assert.deepEqual(calls,['winrms','winrm','rpc'])
  assert.equal(fallback.transport,'wmi')
  assert.equal(fallback.status,'reachable')
  assert.equal(fallback.probeStatus,'rpc-authenticated')
  assert.match(fallback.winrmError,/winrms denied access; winrm denied access/)
  calls.length=0
  const secure=await probeNode(node,{
    probePort:ports,
    authenticate:async target=>{calls.push(target.transport);return 'EXAMPLE\\operator'},
    authenticateRpc:async()=>{throw new Error('RPC should not run after WinRM succeeds')}
  })
  assert.deepEqual(calls,['winrms'])
  assert.equal(secure.transport,'winrms')
  assert.equal(secure.probeStatus,'winrms-authenticated')
})

test('node probing falls back to credentialed SMB netsh when WinRM and WMI are unavailable',async()=>{
  db.prepare('INSERT INTO nodes(id,hostname,ip) VALUES(?,?,?)').run('probe-netsh','PROBE-NETSH','192.0.2.23')
  db.prepare('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)').run('cred','probe-netsh')
  const node=db.prepare('SELECT * FROM nodes WHERE id=?').get('probe-netsh')
  const result=await probeNode(node,{
    probePort:async(_host,port)=>({status:port===445?'open':'refused'}),
    authenticate:async()=>{throw new Error('WinRM denied access')},
    authenticateRpc:async()=>{throw new Error('RPC unavailable')},
    authenticateNetsh:async()=>({success:true,transport:'netsh',computerName:'PROBE-NETSH'})
  })
  assert.equal(result.transport,'netsh')
  assert.equal(result.status,'reachable')
  assert.equal(result.probeStatus,'netsh-authenticated')
  assert.equal(result.ports.smb.status,'open')
  assert.equal(db.prepare('SELECT transport,probe_status,status FROM nodes WHERE id=?').get(node.id).transport,'netsh')
})

test('agentless verification uses credentialed WMI when the RPC probe is inconclusive',async()=>{
  db.prepare("INSERT INTO nodes(id,hostname,ip,connection_mode,inventory_source,transport) VALUES(?,?,?,'agentless','ad','wmi')").run('wmi-unverified','WMI-UNVERIFIED','192.0.2.22')
  const node=db.prepare('SELECT * FROM nodes WHERE id=?').get('wmi-unverified')
  const calls=[]
  const facts={computer:{Name:'WMI-UNVERIFIED'},os:{Version:'10.0.26100',BuildNumber:'26100'}}
  const result=await enrichNode(node,{
    probeNodeFn:async()=>({transport:'wmi',probeStatus:'rpc-unverified'}),
    activate:async()=>{calls.push('activate');throw new Error('Should not activate WinRM before credentialed WMI verification')},
    collect:async managed=>{calls.push(managed.transport);return facts}
  })
  assert.deepEqual(calls,['wmi'])
  assert.deepEqual(result,facts)
  assert.deepEqual(db.prepare('SELECT transport,status,probe_status FROM nodes WHERE id=?').get(node.id),{transport:'wmi',status:'reachable',probe_status:'wmi-authenticated'})
})

test('authenticated WMI reads firewall inventory and events and confirms one policy write attempt',async()=>{
  db.prepare("INSERT INTO nodes(id,hostname,ip,connection_mode,inventory_source,transport) VALUES(?,?,?,'agentless','manual','wmi')").run('wmi-inventory','WMI-INVENTORY','192.0.2.14')
  db.prepare("INSERT INTO credentials(id,name,type,username,encrypted_blob) VALUES(?,?,'domain',?,?)").run('wmi-inventory-cred','WMI inventory credential','EXAMPLE\\reader',seal({password:'wmi-read-secret'}))
  db.prepare('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)').run('wmi-inventory-cred','wmi-inventory')
  const stub=path.join(dataDir,'wmi-inventory-stub.cjs')
  fs.writeFileSync(stub,`#!/usr/bin/env node\nlet data='';process.stdin.on('data',part=>data+=part);process.stdin.on('end',()=>{const p=JSON.parse(data);if(p.expectedName!=='WMI-INVENTORY'||p.password!=='wmi-read-secret')process.exit(2);const rule={name:'Test',group:'WinFireSecure:test',action:'allow',direction:'in',protocol:'TCP',localPort:'3389',remotePort:'Any',remoteAddress:'Any',program:'Any',profile:'Domain'};const result={success:true,transport:'wmi',computerName:'WMI-INVENTORY'};if(p.mode==='apply')result.applyResult={applied:true};else if(p.mode==='rules')result.ruleResult=[rule];else if(p.mode==='all_rules')result.ruleResult={total:1,offset:p.args.offset,rules:[rule]};else if(p.mode==='facts')result.factsResult={computer:{Name:'WMI-INVENTORY'},os:{Version:'10.0.20348'}};else if(p.mode==='audit_policy'||p.mode==='audit_policy_enable')result.auditResult={settingValue:3,successEnabled:true,failureEnabled:true};else if(p.mode==='event_cursor')result.eventResult=42;else if(p.mode==='events')result.eventResult=[{RecordId:43,Id:5157,Fields:{DestPort:'3389'}}];else if(p.mode==='events_recent'||p.mode==='events_probe')result.eventResult=[];process.stdout.write(JSON.stringify(result))})\n`,{mode:0o700})
  const previous=process.env.WMI_PROBE_PYTHON
  process.env.WMI_PROBE_PYTHON=stub
  try{
    const node=db.prepare('SELECT * FROM nodes WHERE id=?').get('wmi-inventory')
    const page=await remote(node,'all_rules',{offset:0,limit:100})
    assert.equal(page.total,1)
    assert.equal(page.rules[0].localPort,'3389')
    assert.equal((await remote(node,'facts')).os.Version,'10.0.20348')
    assert.equal((await remote(node,'audit_policy')).successEnabled,true)
    assert.equal((await remote(node,'audit_policy_enable')).failureEnabled,true)
    assert.equal((await remote(node,'rules',{group:'WinFireSecure:test'}))[0].name,'Test')
    assert.equal(db.prepare('SELECT probe_status FROM nodes WHERE id=?').get(node.id).probe_status,'wmi-authenticated')
    assert.deepEqual(await remote(node,'apply',{group:'WinFireSecure:test',add:[],remove:[]}),{applied:true})
    assert.equal(await remote(node,'event_cursor'),42)
    assert.equal((await remote(node,'events',{after:42}))[0].Fields.DestPort,'3389')
    assert.deepEqual(await remote(node,'events_recent'),[])
    await assert.rejects(remote(node,'rights',{}),/other operations require WinRM or an agent/)
  }finally{
    if(previous===undefined)delete process.env.WMI_PROBE_PYTHON
    else process.env.WMI_PROBE_PYTHON=previous
  }
})

test('authenticated SMB netsh fallback reads facts, rules, audit state, and Security events',async()=>{
  db.prepare("INSERT INTO nodes(id,hostname,ip,connection_mode,inventory_source,transport) VALUES(?,?,?,'agentless','manual','netsh')").run('netsh-inventory','NETSH-INVENTORY','192.0.2.24')
  db.prepare("INSERT INTO credentials(id,name,type,username,encrypted_blob) VALUES(?,?,'domain',?,?)").run('netsh-inventory-cred','Netsh inventory credential','EXAMPLE\\reader',seal({password:'netsh-read-secret'}))
  db.prepare('INSERT INTO credential_assignments(credential_id,node_id,node_group_id) VALUES(?,?,NULL)').run('netsh-inventory-cred','netsh-inventory')
  const stub=path.join(dataDir,'netsh-inventory-stub.cjs')
  fs.writeFileSync(stub,`#!/usr/bin/env node
let data='';process.stdin.on('data',part=>data+=part);process.stdin.on('end',()=>{const p=JSON.parse(data);if(p.username!=='EXAMPLE\\\\reader'||p.password!=='netsh-read-secret')process.exit(2);const rule={name:'Test',group:'WinFireSecure:test',action:'allow',direction:'in',protocol:'TCP',localPort:'3389',remotePort:'Any',remoteAddress:'Any',program:'Any',profile:'Domain'};const base={success:true,transport:'netsh',computerName:'NETSH-INVENTORY'};if(p.mode==='event_cursor')process.stdout.write('42');else {if(p.mode==='facts')base.factsResult={computer:{Name:'NETSH-INVENTORY'},os:{Version:'10.0.26100',BuildNumber:'26100'},firewall:{profiles:[]},network:[]};else if(p.mode==='all_rules')base.ruleResult={total:1,offset:p.args.offset||0,rules:[rule]};else if(p.mode==='rules')base.ruleResult=[rule];else if(p.mode==='audit_policy'||p.mode==='audit_policy_enable')base.auditResult={settingValue:3,successEnabled:true,failureEnabled:true};else if(p.mode==='events')base.eventResult=[{RecordId:43,Id:5157,Fields:{DestPort:'3389'}}];else if(p.mode==='events_recent'||p.mode==='events_probe')base.eventResult=[];else if(p.mode==='apply')base.applyResult={applied:true};process.stdout.write(JSON.stringify(base))}})
`,{mode:0o700})
  const previous=process.env.NETSH_PYTHON
  process.env.NETSH_PYTHON=stub
  try{
    const node=db.prepare('SELECT * FROM nodes WHERE id=?').get('netsh-inventory')
    assert.equal((await remote(node,'auth')).account,'EXAMPLE\\reader')
    assert.equal((await remote(node,'facts')).os.Version,'10.0.26100')
    assert.equal((await remote(node,'audit_policy')).successEnabled,true)
    assert.equal((await remote(node,'audit_policy_enable')).failureEnabled,true)
    assert.equal((await remote(node,'all_rules',{offset:0,limit:100})).rules[0].localPort,'3389')
    assert.equal((await remote(node,'rules',{group:'WinFireSecure:test'}))[0].name,'Test')
    assert.deepEqual(await remote(node,'apply',{group:'WinFireSecure:test',add:[],remove:[]}),{applied:true})
    assert.equal(await remote(node,'event_cursor'),42)
    assert.equal((await remote(node,'events',{after:42}))[0].Fields.DestPort,'3389')
    assert.deepEqual(await remote(node,'events_recent'),[])
    assert.equal(db.prepare('SELECT probe_status FROM nodes WHERE id=?').get(node.id).probe_status,'netsh-authenticated')
    await assert.rejects(remote(node,'rights',{}),/Netsh fallback supports/)
  }finally{
    if(previous===undefined)delete process.env.NETSH_PYTHON
    else process.env.NETSH_PYTHON=previous
  }
})
