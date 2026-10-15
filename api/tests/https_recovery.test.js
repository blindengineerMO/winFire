import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import https from 'node:https'
import {spawnSync} from 'node:child_process'
import supertest from 'supertest'
const root=fs.mkdtempSync(os.tmpdir()+'/winfire-https-recovery-'),dir=path.join(root,'data')
process.env.DATA_DIR=dir;process.env.NODE_ENV='test'
for(const name of ['TLS_CERT','TLS_KEY','AGENT_CA_CERT','AGENT_CA_KEY'])delete process.env[name]
const {app}=await import('../src/app.js'),{db,run,one,id}=await import('../src/db.js'),{issueAccess}=await import('../src/security.js'),{agentTlsOptions,tlsMaterialPaths}=await import('../src/agentPki.js')
const user={id:id(),email:'https@example.test',role:'owner'};run('INSERT INTO users(id,email,password_hash,role) VALUES(?,?,?,?)',user.id,user.email,'fixture',user.role)
const token=issueAccess(one('SELECT * FROM users WHERE id=?',user.id)),request=supertest(app)
const openssl=args=>{const p=spawnSync('openssl',args,{cwd:root,encoding:'utf8'});assert.equal(p.status,0,p.stderr)}
openssl(['req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.crt','-days','1','-subj','/CN=WinFire-disposable-CA','-addext','basicConstraints=critical,CA:TRUE'])
openssl(['req','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=localhost'])
fs.writeFileSync(path.join(root,'server.ext'),'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n')
openssl(['x509','-req','-in','server.csr','-CA','ca.crt','-CAkey','ca.key','-set_serial','1','-days','1','-extfile','server.ext','-out','server.crt'])
test.after(()=>{db.close();fs.rmSync(root,{recursive:true,force:true})})
test('uploaded TLS material survives a real HTTPS listener restart and never bypasses certificate validation',async()=>{
 for(const [kind,file] of [['serverCert','server.crt'],['serverKey','server.key'],['agentCaCert','ca.crt'],['agentCaKey','ca.key']])await request.put('/api/v1/settings/tls/'+kind).set('Authorization','Bearer '+token).send({base64:fs.readFileSync(path.join(root,file)).toString('base64')}).expect(200)
 const paths=tlsMaterialPaths(),read=async()=>{
   const server=https.createServer(agentTlsOptions(),app)
   await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
   try{
     const data=await new Promise((resolve,reject)=>{https.get({hostname:'127.0.0.1',port:server.address().port,path:'/api/v1/settings/tls',headers:{Authorization:'Bearer '+token},ca:fs.readFileSync(path.join(root,'ca.crt'))},res=>{let body='';res.on('data',c=>body+=c);res.on('end',()=>resolve({status:res.statusCode,body:JSON.parse(body)}))}).once('error',reject)})
     assert.equal(data.status,200);assert.equal(data.body.httpsEnabled,true)
   }finally{await new Promise(resolve=>server.close(resolve))}
 }
 await read();await read()
 for(const file of Object.values(paths))assert.equal(fs.statSync(file).mode&0o777,0o600)
 const before=fs.readFileSync(paths.TLS_KEY,'utf8')
 await request.put('/api/v1/settings/tls/serverKey').set('Authorization','Bearer '+token).send({base64:Buffer.from('-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----').toString('base64')}).expect(400)
 assert.equal(fs.readFileSync(paths.TLS_KEY,'utf8'),before)
 // Replacing a previously permissive file restores private permissions atomically.
 fs.chmodSync(paths.TLS_KEY,0o644)
 await request.put('/api/v1/settings/tls/serverKey').set('Authorization','Bearer '+token).send({base64:Buffer.from(before).toString('base64')}).expect(200)
 assert.equal(fs.statSync(paths.TLS_KEY).mode&0o777,0o600)
})
test('node/group destination targeting resolves current inventory through the HTTPS API without enforcement',async()=>{
 run("INSERT INTO nodes(id,hostname,ip,transport,os_version) VALUES('source','Source','10.42.0.1','winrm','10.0.20348'),('dest-one','One','10.42.0.10',NULL,NULL),('dest-two','Two','10.42.0.11',NULL,NULL)")
 const account=id(),group=id()
 run("INSERT INTO local_accounts(id,node_id,sid,username,qualified_name,seen_at) VALUES(?,'source','S-1-5-21-1-2-3-1001','fixture','Source\\fixture',datetime('now'))",account)
 run('INSERT INTO node_groups(id,name) VALUES(?,?)',group,'HTTPS destination group')
 for(const node of ['dest-one','dest-two'])run('INSERT INTO node_group_members(group_id,node_id) VALUES(?,?)',group,node)
 const server=https.createServer(agentTlsOptions(),app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
 try{
   for(const [destinationType,destinationId,expected] of [['node','dest-one',['10.42.0.10']],['group',group,['10.42.0.10','10.42.0.11']]]){
     const body=JSON.stringify({destinationType,destinationId,protocol:'TCP',remotePort:'443',reason:'Controlled HTTPS inventory resolution test'})
     const response=await new Promise((resolve,reject)=>{const req=https.request({hostname:'127.0.0.1',port:server.address().port,path:`/api/v1/directory/local-accounts/${account}/network-rule`,method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)},ca:fs.readFileSync(path.join(root,'ca.crt'))},res=>{let output='';res.on('data',c=>output+=c);res.on('end',()=>resolve({status:res.statusCode,body:JSON.parse(output)}))});req.once('error',reject);req.end(body)})
     assert.equal(response.status,201,JSON.stringify(response.body));const rules=JSON.parse(one('SELECT rules_compiled_json FROM policy_versions WHERE id=?',response.body.versionId).rules_compiled_json)
     assert.deepEqual(rules.at(-1).remoteAddress.split(',').sort(),expected)
   }
   assert.equal(one('SELECT count(*) n FROM policy_apply_runs').n,0)
 }finally{await new Promise(resolve=>server.close(resolve))}
})
