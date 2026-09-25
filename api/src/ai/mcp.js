import {McpServer,createMcpHandler,OAuthError,OAuthErrorCode} from '@modelcontextprotocol/server'
import {toNodeHandler} from '@modelcontextprotocol/node'
import {requireBearerAuth,getOAuthProtectedResourceMetadataUrl,mcpAuthMetadataRouter} from '@modelcontextprotocol/express'
import {createRemoteJWKSet,jwtVerify} from 'jose'
import {rateLimit,ipKeyGenerator} from 'express-rate-limit'
import {one} from '../db.js'
import {eventSchema,batchSchema,receiptSchema,failure} from './schemas.js'
import {ingestBatch} from './ingestion.js'
import {activeReporter} from './reporters.js'
import {isUserApiKey,authenticateApiKey} from '../apiKeyAuth.js'
export function buildAiMcpServer(report){
 const server=new McpServer({name:'winfire-ai-usage',version:'1.0.0'})
 const invoke=async(input,ctx)=>{try{const result=await report(input,ctx);return {content:[{type:'text',text:JSON.stringify(result)}],structuredContent:result,isError:result.results?.some(r=>r.status==='rejected')||false}}catch(e){return {isError:true,content:[{type:'text',text:e.code||'report_failed'}]}}}
 server.registerTool('report_ai_usage',{description:'Write one metadata-only AI operation report. Uses stable reporter/event identity for durable idempotent receipts. Does not execute the operation.',inputSchema:eventSchema,outputSchema:receiptSchema,annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},(e,ctx)=>invoke({events:[e]},ctx))
 server.registerTool('report_ai_usage_batch',{description:'Write up to 100 metadata-only AI operation reports. Returns accepted, duplicate or rejected receipts for each event. Does not read inventory or execute tools.',inputSchema:batchSchema,outputSchema:receiptSchema,annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},invoke)
 return server
}
export function oauthConfig(){const issuer=process.env.AI_OAUTH_ISSUER,audience=process.env.AI_MCP_RESOURCE_URL;return {issuer,audience,configured:!!issuer&&!!audience}}
export function mcpResourceUrl(){
 const base=process.env.PUBLIC_BASE_URL||one("SELECT value FROM app_settings WHERE key='server_public_base_url'")?.value
 const address=process.env.AI_MCP_RESOURCE_URL||(base?base.replace(/\/$/,'')+'/mcp/ai-usage':process.env.NODE_ENV!=='production'?`http://localhost:${process.env.PORT||3000}/mcp/ai-usage`:null)
 try{const url=new URL(address);if(!['https:','http:'].includes(url.protocol)||url.username||url.password||url.search||url.hash||url.pathname!=='/mcp/ai-usage')return null;return url.href}catch{return null}
}
const safeUrl=value=>{const u=new URL(value);if(u.protocol!=='https:'&&process.env.NODE_ENV!=='test')throw failure(503,'oauth_requires_https');if(u.username||u.password||u.search||u.hash)throw failure(503,'invalid_oauth_url');return u}
let cache
async function discovery(){const cfg=oauthConfig();if(!cfg.configured)throw failure(503,'oauth_not_configured');const key=cfg.issuer+'|'+cfg.audience;if(cache?.key===key&&cache.until>Date.now())return cache;const issuer=safeUrl(cfg.issuer),resource=safeUrl(cfg.audience);if(resource.pathname!=='/mcp/ai-usage')throw failure(503,'invalid_mcp_resource_path');const response=await fetch(new URL(issuer.pathname.replace(/\/$/,'')+'/.well-known/openid-configuration',issuer),{signal:AbortSignal.timeout(5000),redirect:'error'});if(!response.ok)throw failure(503,'oauth_discovery_failed');const doc=await response.json();if(doc.issuer!==cfg.issuer)throw failure(503,'oauth_issuer_mismatch');safeUrl(doc.jwks_uri);for(const field of ['authorization_endpoint','token_endpoint'])if(doc[field])safeUrl(doc[field]);cache={key,until:Date.now()+300000,doc,jwks:createRemoteJWKSet(new URL(doc.jwks_uri),{timeoutDuration:5000,cooldownDuration:30000}),resource};return cache}
async function verifyToken(token){const {doc,jwks,resource}=await discovery();const {payload}=await jwtVerify(token,jwks,{issuer:doc.issuer,audience:resource.href,algorithms:['RS256','ES256'],requiredClaims:['exp','sub','iat'],clockTolerance:5});const client=payload.client_id||payload.azp;if(typeof client!=='string')throw failure(401,'oauth_client_identity_missing');const reporter=one("SELECT * FROM ai_reporters WHERE issuer=? AND subject=? AND client_id=? AND status='active'",doc.issuer,payload.sub,client);if(!reporter)throw failure(401,'reporter_not_enrolled');return {token,clientId:client,scopes:typeof payload.scope==='string'?payload.scope.split(' '):[],expiresAt:payload.exp,resource,extra:{reporterId:reporter.id}}}
export async function verifyReporterToken(token){try{
 if(isUserApiKey(token)){const {key}=authenticateApiKey(token,'mcp:report');return {token,clientId:key.id,scopes:['ai:report'],expiresAt:Math.floor(Date.parse(key.expires_at)/1000),resource:new URL(mcpResourceUrl()),extra:{reporterId:key.reporter_id,apiKeyId:key.id}}}
 return await verifyToken(token)
}catch{throw new OAuthError(OAuthErrorCode.InvalidToken,'Invalid AI reporter access token')}}
export const aiRateLimit=({limit=120}={})=>rateLimit({windowMs:60000,limit,standardHeaders:'draft-8',legacyHeaders:false,keyGenerator:req=>req.aiReporter?.id||req.auth?.extra?.reporterId||ipKeyGenerator(req.ip),handler:(_req,res)=>res.status(429).json({error:'AI reporting rate exceeded',code:'rate_limited'})})
export function mountAiMcp(app){
 const configGate=(req,res,next)=>{if(Buffer.byteLength(JSON.stringify(req.body||{}))>262144)return res.status(413).json({error:'AI payload exceeds 256 KiB'});const address=mcpResourceUrl();if(!address)return res.status(503).json({error:'Configure the server public URL or AI_MCP_RESOURCE_URL',code:'mcp_not_configured'});try{const resource=new URL(address),local=process.env.NODE_ENV!=='production'&&['localhost','127.0.0.1','[::1]'].includes(resource.hostname);if(resource.pathname!=='/mcp/ai-usage'||resource.username||resource.password||resource.search||resource.hash||resource.protocol!=='https:'&&!(local&&resource.protocol==='http:')&&process.env.NODE_ENV!=='test')throw new Error('Invalid resource');const origin=req.get('origin'),allowed=[resource.origin,...(process.env.AI_MCP_ALLOWED_ORIGINS||'').split(',').map(v=>v.trim()).filter(Boolean)];if(req.get('host')!==resource.host)return res.status(403).json({error:'Invalid MCP host'});if(origin&&!allowed.includes(origin))return res.status(403).json({error:'Invalid MCP origin'});if(!req.secure&&!local&&process.env.NODE_ENV!=='test')return res.status(400).json({error:'MCP requires HTTPS'});next()}catch{res.status(503).json({error:'Invalid MCP configuration'})}}
 app.use('/.well-known/oauth-protected-resource/mcp/ai-usage',async(req,res,next)=>{try{const {doc,resource}=await discovery();mcpAuthMetadataRouter({oauthMetadata:doc,resourceServerUrl:resource,scopesSupported:['ai:report'],resourceName:'WinFire AI usage'})(Object.assign(req,{url:'/.well-known/oauth-protected-resource/mcp/ai-usage'}),res,next)}catch{res.status(503).json({error:'OAuth discovery unavailable'})}})
 const authGate=(req,res,next)=>requireBearerAuth({verifier:{verifyAccessToken:verifyReporterToken},requiredScopes:['ai:report'],resourceMetadataUrl:getOAuthProtectedResourceMetadataUrl(new URL(mcpResourceUrl()))})(req,res,next)
 const transport=toNodeHandler(createMcpHandler(()=>buildAiMcpServer((input,ctx)=>{const reporterId=ctx.http?.authInfo?.extra?.reporterId;activeReporter(reporterId);return ingestBatch(reporterId,input)}),{legacy:'stateless'}),{maxRequestBodySize:262144})
 app.all('/mcp/ai-usage',configGate,aiRateLimit({limit:600}),authGate,aiRateLimit(),(req,res)=>transport(req,res,req.body))
}
