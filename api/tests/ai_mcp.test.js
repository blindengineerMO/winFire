import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import express from 'express'
import {generateKeyPair,exportJWK,SignJWT} from 'jose'
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio'
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client'
const dir=fs.mkdtempSync(os.tmpdir()+'/winfire-ai-mcp-');process.env.DATA_DIR=dir;process.env.NODE_ENV='test';process.env.MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL='true'
const {privateKey,publicKey}=await generateKeyPair('RS256'),jwk=await exportJWK(publicKey);jwk.kid='test-key';jwk.alg='RS256'
const issuerApp=express(),issuerServer=issuerApp.listen(0,'127.0.0.1');await new Promise(resolve=>issuerServer.once('listening',resolve));const issuer=`http://127.0.0.1:${issuerServer.address().port}`
issuerApp.get('/.well-known/openid-configuration',(_req,res)=>res.json({issuer,jwks_uri:issuer+'/jwks',authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',response_types_supported:['code'],grant_types_supported:['authorization_code','client_credentials'],code_challenge_methods_supported:['S256']}));issuerApp.get('/jwks',(_req,res)=>res.json({keys:[jwk]}))
process.env.AI_OAUTH_ISSUER=issuer
const {app}=await import('../src/app.js'),{db,run,one}=await import('../src/db.js'),{enrollReporter,revokeReporter}=await import('../src/ai/reporters.js')
const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base=`http://127.0.0.1:${server.address().port}`,resource=base+'/mcp/ai-usage';process.env.AI_MCP_RESOURCE_URL=resource
run("INSERT INTO nodes(id,hostname) VALUES('mcp-node','MCP fixture')")
const reporter=enrollReporter({name:'OAuth integration',nodeIds:['mcp-node'],coverage:'instrumented',issuer,subject:'service-ai',clientId:'ai-client'},null)
const sign=(extra={})=>new SignJWT({scope:'ai:report',client_id:'ai-client',...extra}).setProtectedHeader({alg:'RS256',kid:'test-key'}).setSubject('service-ai').setIssuer(issuer).setAudience(resource).setIssuedAt().setExpirationTime('5m').sign(privateKey)
const clients=[]
test.after(async()=>{for(const c of clients)await c.close();await new Promise(r=>server.close(r));await new Promise(r=>issuerServer.close(r));db.close();fs.rmSync(dir,{recursive:true,force:true})})
test('OAuth protected-resource discovery and independent SDK tool calls with durable retries',async()=>{
 const metadata=await fetch(base+'/.well-known/oauth-protected-resource/mcp/ai-usage');assert.equal(metadata.status,200);const md=await metadata.json();assert.equal(md.resource,resource);assert.deepEqual(md.authorization_servers,[issuer])
 const token=await sign(),client=new Client({name:'winfire-independent-test',version:'1.0.0'});clients.push(client)
 await client.connect(new StreamableHTTPClientTransport(new URL(resource),{authProvider:{token:async()=>token}}))
 const list=await client.listTools();assert.deepEqual(list.tools.map(t=>t.name).sort(),['report_ai_usage','report_ai_usage_batch'])
 const e={schemaVersion:1,eventId:'sdk-operation',operation:'research',observedAt:new Date().toISOString(),provider:'local'}
 const first=await client.callTool({name:'report_ai_usage',arguments:e});assert.equal(first.isError,false);assert.equal(first.structuredContent.results[0].status,'accepted')
 const again=await client.callTool({name:'report_ai_usage',arguments:e});assert.equal(again.structuredContent.results[0].status,'duplicate');assert.equal(again.structuredContent.results[0].receiptId,first.structuredContent.results[0].receiptId)
 const denied=await client.callTool({name:'report_ai_usage',arguments:{...e,eventId:'cross-node',nodeId:'not-authorized'}});assert.equal(denied.isError,true);assert.equal(denied.structuredContent.results[0].code,'node_not_authorized')
})
test('current protocol 2026-07-28 uses independent SDK negotiation and output schemas',async()=>{
 const client=new Client({name:'current-protocol-fixture',version:'1'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});clients.push(client)
 const token=await sign();await client.connect(new StreamableHTTPClientTransport(new URL(resource),{authProvider:{token:async()=>token}}))
 const tools=await client.listTools();assert.ok(tools.tools.every(t=>t.outputSchema&&t.annotations.idempotentHint))
 const result=await client.callTool({name:'report_ai_usage_batch',arguments:{events:[{schemaVersion:1,eventId:'modern-sdk',operation:'search',observedAt:new Date().toISOString()}]}})
 assert.equal(result.structuredContent.results[0].status,'accepted')
 const missing=await fetch(resource,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});assert.equal(missing.status,401);assert.match(missing.headers.get('www-authenticate'),/resource_metadata/)
})
test('local stdio adapter returns the requested durable receipts through a real SDK client',async()=>{
 const client=new Client({name:'stdio-fixture',version:'1'});clients.push(client)
 await client.connect(new StdioClientTransport({command:process.execPath,args:['integrations/ai/stdio.mjs'],env:{...process.env,WINFIRE_AI_URL:base,WINFIRE_AI_CREDENTIAL:reporter.credential,WINFIRE_AI_SPOOL:dir+'/stdio'},stderr:'pipe'}))
 const event={schemaVersion:1,eventId:'stdio-event',operation:'tool_call',observedAt:new Date().toISOString()}
 const accepted=await client.callTool({name:'report_ai_usage',arguments:event});assert.equal(accepted.structuredContent.results[0].eventId,event.eventId);assert.equal(accepted.structuredContent.results[0].status,'accepted')
 const retry=await client.callTool({name:'report_ai_usage',arguments:event});assert.equal(retry.structuredContent.results[0].receiptId,accepted.structuredContent.results[0].receiptId);assert.equal(retry.structuredContent.results[0].status,'duplicate')
})
test('invalid origin, wrong audience, absent scope, unsupported protocol and reporter revocation fail',async()=>{
 const headers={Authorization:'Bearer '+await sign(),'Content-Type':'application/json',Accept:'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28','Mcp-Method':'tools/list'}
 const body=JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list',params:{_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientInfo':{name:'probe',version:'1'},'io.modelcontextprotocol/clientCapabilities':{}}}})
 assert.equal((await fetch(resource,{method:'POST',headers:{...headers,Origin:'https://evil.example'},body})).status,403)
 const wrong=await new SignJWT({scope:'ai:report',client_id:'ai-client'}).setProtectedHeader({alg:'RS256',kid:'test-key'}).setSubject('service-ai').setIssuer(issuer).setAudience('https://wrong.example').setIssuedAt().setExpirationTime('5m').sign(privateKey)
 assert.equal((await fetch(resource,{method:'POST',headers:{...headers,Authorization:'Bearer '+wrong},body})).status,401)
 assert.equal((await fetch(resource,{method:'POST',headers:{...headers,Authorization:'Bearer '+await sign({scope:'other'})},body})).status,403)
 assert.equal((await fetch(resource,{method:'POST',headers:{...headers,'MCP-Protocol-Version':'1900-01-01'},body})).status,400)
 revokeReporter(reporter.reporter.id,null)
 assert.equal((await fetch(resource,{method:'POST',headers,body})).status,401)
})
