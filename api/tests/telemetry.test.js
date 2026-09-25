import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import supertest from 'supertest'
const dir=fs.mkdtempSync(os.tmpdir()+'/winfire-telemetry-');process.env.DATA_DIR=dir;process.env.NODE_ENV='test'
const {app}=await import('../src/app.js'),{db,run,one,id,now}=await import('../src/db.js'),{issueAccess}=await import('../src/security.js')
const {FlowDecoder,decodeSyslog}=await import('../src/telemetry/decoders.js'),{saveExporter,importSyslog,saveObservations,observationRows}=await import('../src/telemetry/service.js'),{decodeVnet}=await import('../src/telemetry/vnet.js')
const owner={id:id(),email:'telemetry@example.test',role:'owner'};run('INSERT INTO users(id,email,password_hash,role,email_verified) VALUES(?,?,?,?,1)',owner.id,owner.email,'fixture',owner.role)
run("INSERT INTO app_settings(key,value) VALUES('local_asset_cidrs','[\"10.42.0.0/24\"]') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
run("INSERT INTO nodes(id,hostname,ip,transport,device_type) VALUES('collector','firewall','10.42.0.1','snmp','firewall')")
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})
function packet({version=10,template=true,sequence=1,domain=1,uptime=5000}={}){
 const fields=[[8,4],[12,4],[7,2],[11,2],[4,1],[34,4],[225,4]],data=Buffer.from([10,42,0,2,8,8,8,8,0xc0,0x01,0,53,17,0,0,0,100,203,0,113,1]),sets=[]
 if(template){const t=Buffer.alloc(8+fields.length*4);t.writeUInt16BE(version===9?0:2);t.writeUInt16BE(t.length,2);t.writeUInt16BE(256,4);t.writeUInt16BE(fields.length,6);fields.forEach(([type,size],i)=>{t.writeUInt16BE(type,8+i*4);t.writeUInt16BE(size,10+i*4)});sets.push(t)}
 const d=Buffer.alloc(4+data.length);d.writeUInt16BE(256);d.writeUInt16BE(d.length,2);data.copy(d,4);sets.push(d)
 const h=Buffer.alloc(version===9?20:16);h.writeUInt16BE(version);if(version===10){h.writeUInt16BE(h.length+sets.reduce((n,b)=>n+b.length,0),2);h.writeUInt32BE(1700000000,4);h.writeUInt32BE(sequence,8);h.writeUInt32BE(domain,12)}else{h.writeUInt32BE(uptime,4);h.writeUInt32BE(1700000000,8);h.writeUInt32BE(sequence,12);h.writeUInt32BE(domain,16)}return Buffer.concat([h,...sets])
}
test('NetFlow/IPFIX enrollment boundaries, templates, retransmit, reboot, NAT, sampling and malformed frames',()=>{
 for(const version of [9,10]){const decoder=new FlowDecoder(),first=decoder.decode(packet({version}),'cisco');assert.equal(first.records[0].dstIp,'8.8.8.8');assert.equal(first.records[0].action,null);assert.equal(first.records[0].metadata.samplingInterval,100);assert.equal(first.records[0].metadata.nat.sourceIp,'203.0.113.1');assert.equal(decoder.decode(packet({version}),'cisco').duplicate,true);assert.equal(decoder.decode(packet({version,template:false,sequence:2}),'mikrotik').missingTemplates,1);assert.equal(decoder.decode(packet({version,template:false,sequence:2}),'cisco').records.length,1);const reset=decoder.decode(packet({version,template:false,sequence:0,uptime:1}),'cisco');assert.equal(reset.reboot,true);assert.equal(reset.missingTemplates,1);assert.throws(()=>decoder.decode(packet({version}).subarray(0,25),'bad'),/Truncated|length/)}
})
const pf='2026-09-25T12:00:00Z firewall filterlog: 5,,,123,igb0,match,block,in,4,0x0,,64,12,0,none,17,udp,60,10.42.0.2,8.8.8.8,45000,53,40'
test('vendor syslog preserves evidence and does not guess missing verdicts',()=>{
 assert.equal(decodeSyslog(pf,'pf-filterlog').action,'block')
 const m=decodeSyslog('firewall,info forward: in:bridge out:ether1, proto TCP (SYN), 10.42.0.2:50000->8.8.8.8:443, len 52','mikrotik-firewall');assert.equal(m.srcIp,'10.42.0.2');assert.equal(m.dstPort,443);assert.equal(m.action,null)
 const s=decodeSyslog('id=firewall m=123 src=10.42.0.2:50000:X0 dst=8.8.8.8:443:X1 proto=tcp fw_action=drop msg="Packet dropped"','sonicwall-kv');assert.equal(s.action,'block');assert.equal(s.dstPort,443)
 assert.throws(()=>decodeSyslog('bad','pf-filterlog'))
})
test('ingestion is idempotent, public peers stay outside inventory and Activities includes external telemetry',async()=>{
 const e=saveExporter({name:'Firewall',nodeId:'collector',format:'pf-filterlog',enabled:true},owner.id),q={captureKey:'fixture:one',lines:[pf]};assert.equal(importSyslog(e.id,q,owner.id).accepted,1);assert.equal(importSyslog(e.id,q,owner.id).duplicates,1);assert.throws(()=>importSyslog(e.id,{...q,lines:[pf+' changed']},owner.id),/different content/)
 assert.equal(one('SELECT count(*) n FROM nodes').n,1);assert.equal(observationRows({exporterId:e.id}).total,1)
 const request=supertest(app),token=issueAccess(one('SELECT * FROM users WHERE id=?',owner.id));const result=await request.get('/api/v1/logs/search?eventType=firewall&hideLoopback=false').set('Authorization','Bearer '+token).expect(200);assert.equal(result.body.total,1)
})
test('VNet v4 retains state/capture identity, both epoch formats and replays without duplication',()=>{
 const record={flowLogVersion:4,flowLogGUID:'flow-guid',targetResourceID:'/subscriptions/test/virtualNetworks/test',category:'FlowLogFlowEvent',macAddress:'112233445566',flowRecords:{flows:[{aclID:'acl',flowGroups:[{rule:'rule',flowTuples:['1700000000,10.42.0.2,8.8.8.8,50000,443,6,O,B,NX,0,0,0,0','1700000000000,10.42.0.2,8.8.8.8,50000,443,6,O,D,NX,0,0,0,0']}]}]}}
 const rows=decodeVnet({records:[record]});assert.equal(rows[0].eventTime,rows[1].eventTime);assert.equal(rows[0].action,null);assert.equal(rows[1].action,'block');const e=saveExporter({name:'Cloud',nodeId:'collector',format:'azure-vnet',enabled:true},owner.id);assert.equal(saveObservations(e,rows,'blob1').accepted,2);assert.equal(saveObservations(e,rows,'blob2').duplicates,2);assert.throws(()=>decodeVnet({records:[{...record,flowLogVersion:2}]}),/version 4/)
})
function optionsPacket(version,sequence=1){
 const fields=[[version===9?1:149,4],[34,4],[35,1]],t=Buffer.alloc(10+fields.length*4);t.writeUInt16BE(version===9?1:3);t.writeUInt16BE(t.length,2);t.writeUInt16BE(300,4);t.writeUInt16BE(version===9?4:3,6);t.writeUInt16BE(version===9?8:1,8);fields.forEach(([type,len],i)=>{t.writeUInt16BE(type,10+i*4);t.writeUInt16BE(len,12+i*4)})
 const d=Buffer.alloc(13);d.writeUInt16BE(300);d.writeUInt16BE(13,2);d.writeUInt32BE(1,4);d.writeUInt32BE(250,8);d[12]=1;const h=packet({version,sequence}).subarray(0,version===9?20:16);if(version===10)h.writeUInt16BE(h.length+t.length+d.length,2);return Buffer.concat([h,t,d])
}
test('options sampling respects exporter/domain scopes and cache rollback',()=>{
 for(const version of [9,10]){const decoder=new FlowDecoder();assert.equal(decoder.decode(optionsPacket(version),'router').optionsRecords,1);const flow=packet({version,sequence:2});const templateOffset=version===9?20:16;flow.writeUInt16BE(99,templateOffset+8+5*4);const row=decoder.decode(flow,'router').records[0];assert.equal(row.metadata.samplingInterval,250);assert.equal(row.metadata.samplingSource,'options');assert.equal(decoder.decode(flow,'other').records[0].metadata.samplingKnown,false);const bad=optionsPacket(version,3).subarray(0,-1);assert.throws(()=>decoder.decode(bad,'router'));assert.equal(decoder.sampling.size,1)}
})
test('IPv6 endpoint fields are decoded, expired templates are excluded and reordered exports do not replace templates',()=>{
 const decoder=new FlowDecoder({ttlMs:100}),fields=[[27,16],[28,16],[4,1]],t=Buffer.alloc(8+fields.length*4);t.writeUInt16BE(2);t.writeUInt16BE(t.length,2);t.writeUInt16BE(256,4);t.writeUInt16BE(fields.length,6);fields.forEach(([type,size],i)=>{t.writeUInt16BE(type,8+i*4);t.writeUInt16BE(size,10+i*4)});const d=Buffer.alloc(37);d.writeUInt16BE(256);d.writeUInt16BE(37,2);d.writeUInt16BE(0x2001,4);d.writeUInt16BE(0xdb8,6);d[19]=1;d.writeUInt16BE(0x2001,20);d.writeUInt16BE(0xdb8,22);d[35]=2;d[36]=6;const h=packet().subarray(0,16);h.writeUInt16BE(16+t.length+d.length,2);const p=Buffer.concat([h,t,d]),r=decoder.decode(p,'router',{at:1000});assert.equal(r.records[0].srcIp,'2001:db8:0:0:0:0:0:1');const later=packet({template:false,sequence:2});assert.equal(decoder.decode(later,'router',{at:1200}).missingTemplates,1);const old=packet({sequence:3});old.writeUInt32BE(1600000000,4);assert.equal(decoder.decode(old,'router',{at:1300}).late,true)
})
test('failed persistence does not consume a datagram or its template state',()=>{const d=new FlowDecoder(),p=packet();assert.throws(()=>d.decode(p,'router',{accept(){throw Error('Database unavailable')}}),/Database unavailable/);assert.equal(d.templates.size,0);assert.equal(d.seen.size,0);assert.equal(d.decode(p,'router').records.length,1)})
