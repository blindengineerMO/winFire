import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import os from 'node:os'
import {eventSchema} from '../../api/src/ai/schemas.js'
const fields=['schemaVersion','eventId','operationId','nodeId','operation','phase','observedAt','startedAt','endedAt','outcome','errorCode','tool','provider','model','responseModel','hostname','sessionId','traceId','spanId','parentSpanId','requestId','processId','processGuid','processStartedAt','durationMs','inputTokens','outputTokens','cost','adapterVersion']
export function metadataOnly(input){const selected=Object.fromEntries(fields.filter(k=>input[k]!==undefined).map(k=>[k,input[k]]));return eventSchema.parse({schemaVersion:1,eventId:crypto.randomUUID(),observedAt:new Date().toISOString(),operation:'other',...selected})}
export class AiReporter {
 constructor({baseUrl=process.env.WINFIRE_AI_URL,credential=process.env.WINFIRE_AI_CREDENTIAL,spool=process.env.WINFIRE_AI_SPOOL||path.join(os.homedir(),'.winfire','ai-spool'),maxQueued=1000,fetchImpl=fetch}={}){
  const u=new URL(baseUrl);if(u.protocol!=='https:'&&!['localhost','127.0.0.1','[::1]'].includes(u.hostname))throw Error('AI reporting requires HTTPS');if(u.username||u.password||u.search||u.hash)throw Error('Use a clean reporting base URL');this.baseUrl=u.href.replace(/\/$/,'');this.credential=credential;this.spool=spool;this.maxQueued=Math.min(10000,Math.max(1,maxQueued));this.fetch=fetchImpl;this.health={queued:0,dropped:0,schemaErrors:0,adapterVersion:'winfire-js-1'};this.failures=0;this.nextAttempt=0;this.busy=false;fs.mkdirSync(spool,{recursive:true,mode:0o700});fs.chmodSync(spool,0o700)
 }
 record(input){try{return this._record(input)}catch{this.health.dropped++;return null}}
 _record(input){
  if(/report_ai_usage(?:_batch)?$/.test(input.tool||''))return null
  let e;try{e=metadataOnly(input)}catch{this.health.schemaErrors++;return null}
  const files=fs.readdirSync(this.spool).filter(n=>n.endsWith('.json'));if(files.length>=this.maxQueued){this.health.dropped++;return null}
  const name=crypto.createHash('sha256').update(e.eventId).digest('hex')+'.json',target=path.join(this.spool,name);if(fs.existsSync(target))return e.eventId
  const temp=target+'.'+crypto.randomUUID()+'.tmp';fs.writeFileSync(temp,JSON.stringify(e),{mode:0o600});fs.renameSync(temp,target);this.health.queued=files.length+1;return e.eventId
 }
 async track(metadata,work){const startedAt=new Date().toISOString(),operationId=metadata.operationId||crypto.randomUUID();try{const result=await work();this.record({...metadata,operationId,startedAt,endedAt:new Date().toISOString(),outcome:'success'});return result}catch(error){this.record({...metadata,operationId,startedAt,endedAt:new Date().toISOString(),outcome:error?.name==='AbortError'?'cancelled':'failure',errorCode:error?.name==='AbortError'?'cancelled':'operation_failed'});throw error}}
 async flush({force=false}={}){
  if(this.busy||!force&&Date.now()<this.nextAttempt)return {deferred:true,results:[]};this.busy=true
  try{
   const names=fs.readdirSync(this.spool).filter(n=>/^[a-f0-9]{64}\.json$/.test(n)).sort().slice(0,100),events=[],paths=[]
   for(const name of names){const file=path.join(this.spool,name);try{if(fs.lstatSync(file).isSymbolicLink()||fs.statSync(file).size>65536)throw Error();const event=eventSchema.parse(JSON.parse(fs.readFileSync(file,'utf8')));if(Buffer.byteLength(JSON.stringify({events:[...events,event]}))>240*1024)break;events.push(event);paths.push(file)}catch{this.health.schemaErrors++;fs.rmSync(file,{force:true})}}
   if(!events.length)return {results:[]}
   const response=await this.fetch(this.baseUrl+'/api/v1/ai/usage:batch',{method:'POST',headers:{Authorization:'Bearer '+this.credential,'Content-Type':'application/json'},body:JSON.stringify({events}),signal:AbortSignal.timeout(5000),redirect:'error'})
   if(!response.ok)throw Error('report_unavailable')
   const receipt=await response.json();if(!Array.isArray(receipt.results)||receipt.results.length!==events.length)throw Error('invalid_receipt')
   receipt.results.forEach((r,i)=>{if(r.eventId===events[i].eventId&&['accepted','duplicate','rejected'].includes(r.status)&&!r.retryable){fs.rmSync(paths[i],{force:true});if(r.status==='rejected')this.health.schemaErrors++}})
   this.failures=0;this.nextAttempt=0;return receipt
  }catch{this.failures++;this.nextAttempt=Date.now()+Math.min(300000,1000*2**Math.min(this.failures,8));return {offline:true,results:[]}}
  finally{this.busy=false;try{this.health.queued=fs.readdirSync(this.spool).filter(n=>n.endsWith('.json')).length}catch{this.health.dropped++}}
 }
 async heartbeat(){try{await this.fetch(this.baseUrl+'/api/v1/ai/heartbeat',{method:'POST',headers:{Authorization:'Bearer '+this.credential,'Content-Type':'application/json'},body:JSON.stringify(this.health),signal:AbortSignal.timeout(3000),redirect:'error'})}catch{}}
}
