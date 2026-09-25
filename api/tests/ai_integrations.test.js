import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {spawnSync} from 'node:child_process'
import {AiReporter,metadataOnly} from '../../integrations/ai/reporter.mjs'
import {fromClaudeHook} from '../../integrations/ai/claude-hook.mjs'
import {fromOtlp} from '../../integrations/ai/otel.mjs'
const dir=fs.mkdtempSync(os.tmpdir()+'/ai-adapter-');test.after(()=>fs.rmSync(dir,{recursive:true,force:true}))
const metadata={eventId:'offline-operation',operation:'search',observedAt:new Date().toISOString(),provider:'local',prompt:'PROMPT_SECRET',apiKey:'CREDENTIAL_SECRET',hostname:'https://user:URL_SECRET@api.openai.com/search?query=PRIVATE#fragment'}
test('JS offline buffering survives helper restart, retries stable IDs, redacts and caps',async()=>{
 let calls=0,payload
 const fetchImpl=async(_url,options)=>{calls++;payload=JSON.parse(options.body);if(calls===1)throw Error('offline');return {ok:true,json:async()=>({results:payload.events.map(e=>({eventId:e.eventId,status:'accepted',receiptId:'durable'}))})}}
 let reporter=new AiReporter({baseUrl:'http://127.0.0.1:1234',credential:'secret',spool:dir+'/js',fetchImpl,maxQueued:1})
 reporter.record(metadata);assert.equal(reporter.record({operation:'other'}),null);assert.equal(reporter.health.dropped,1)
 assert.equal((await reporter.flush()).offline,true)
 reporter=new AiReporter({baseUrl:'http://127.0.0.1:1234',credential:'secret',spool:dir+'/js',fetchImpl})
 const receipt=await reporter.flush();assert.equal(receipt.results[0].eventId,'offline-operation');assert.equal(payload.events[0].hostname,'api.openai.com');assert.equal(reporter.health.queued,0);assert.ok(!JSON.stringify(payload).includes('SECRET'));assert.ok(!JSON.stringify(payload).includes('PRIVATE'))
 assert.equal(reporter.record({operation:'tool_call',tool:'report_ai_usage'}),null)
 const result=await reporter.track({operation:'model_request'},async()=>42);assert.equal(result,42)
 await assert.rejects(reporter.track({operation:'research'},async()=>{throw new DOMException('DO_NOT_STORE','AbortError')}),{name:'AbortError'})
 const queued=fs.readdirSync(dir+'/js').filter(f=>f.endsWith('.json')).map(f=>JSON.parse(fs.readFileSync(dir+'/js/'+f)));assert.ok(queued.some(e=>e.outcome==='cancelled'));assert.ok(!JSON.stringify(queued).includes('DO_NOT_STORE'))
 fs.rmSync(dir+'/js',{recursive:true});assert.equal(await reporter.track({operation:'other'},async()=>7),7)
})
test('Python helper strips metadata, buffers offline, resumes after restart and records failure',()=>{
 const code=`import sys,json,pathlib\nsys.path.insert(0,'integrations/ai')\nfrom reporter import AiReporter\np=AiReporter(base_url='http://127.0.0.1:1',credential='secret',spool=sys.argv[1])\np.record(json.loads(sys.argv[2]))\nassert p.flush()['offline']\np=AiReporter(base_url='http://127.0.0.1:1',credential='secret',spool=sys.argv[1])\ndef receive(url,data):\n assert 'SECRET' not in json.dumps(data)\n assert data['events'][0]['eventId']=='offline-operation'\n return {'results':[{'eventId':e['eventId'],'status':'duplicate','receiptId':'durable'} for e in data['events']]}\np._post=receive\nassert p.flush()['results'][0]['status']=='duplicate'\ntry:\n with p.track(operation='research'): raise RuntimeError('PRIVATE_ERROR')\nexcept RuntimeError: pass\ndata=[json.loads(f.read_text()) for f in pathlib.Path(sys.argv[1]).glob('*.json')]\nassert data[0]['outcome']=='failure' and 'PRIVATE_ERROR' not in json.dumps(data)\nprint('python adapter passed')`
 const result=spawnSync('python3',['-c',code,dir+'/python',JSON.stringify(metadata)],{encoding:'utf8'});assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/passed/)
})
test('Claude hooks exclude inputs/responses, distinguish interruption and suppress recursion',()=>{
 const source={hook_event_name:'PostToolUse',session_id:'session-1',tool_use_id:'tool-1',tool_name:'WebSearch',tool_input:{query:'PRIVATE'},tool_response:'SECRET'}
 const event=fromClaudeHook(source);assert.equal(event.operation,'search');assert.ok(!JSON.stringify(event).includes('PRIVATE'));assert.equal(fromClaudeHook({...source,tool_name:'mcp__winfire__report_ai_usage'}),null)
 assert.equal(fromClaudeHook({...source,hook_event_name:'PostToolUseFailure',is_interrupt:true}).outcome,'cancelled');assert.equal(event.eventId,fromClaudeHook(source).eventId)
})
test('OTLP JSON maps pinned GenAI metadata, preserves parent IDs and avoids token subset duplication',()=>{
 const span={traceId:'trace1',spanId:'span1',parentSpanId:'parent1',startTimeUnixNano:String(BigInt(Date.now()-100)*1000000n),endTimeUnixNano:String(BigInt(Date.now())*1000000n),status:{code:2},attributes:[{key:'gen_ai.operation.name',value:{stringValue:'chat'}},{key:'gen_ai.request.model',value:{stringValue:'test-model'}},{key:'gen_ai.usage.input_tokens',value:{intValue:'20'}},{key:'gen_ai.usage.cache_read.input_tokens',value:{intValue:'15'}},{key:'gen_ai.input.messages',value:{stringValue:'SECRET_PROMPT'}}]}
 const [event]=fromOtlp({resourceSpans:[{scopeSpans:[{spans:[span]}]}]});assert.equal(event.inputTokens,20);assert.equal(event.operation,'model_request');assert.equal(event.outcome,'failure');assert.equal(event.parentSpanId,'parent1');assert.ok(!JSON.stringify(event).includes('SECRET_PROMPT'));assert.equal(metadataOnly(event).model,'test-model')
 assert.equal(fromOtlp({resourceSpans:[{scopeSpans:[{spans:[{...span,startTimeUnixNano:'bad'}]}]}]}).length,0)
})

test('credential-shaped values are rejected and large valid spool batches respect body limits',async()=>{
 assert.throws(()=>metadataOnly({operation:'model_request',model:'sk-proj-THIS_IS_A_SECRET_FIXTURE_123456'}))
 let payload
 const reporter=new AiReporter({baseUrl:'http://127.0.0.1:1',credential:'secret',spool:dir+'/bytes',fetchImpl:async(_url,options)=>{payload=options.body;return {ok:true,json:async()=>({results:JSON.parse(payload).events.map(e=>({eventId:e.eventId,status:'accepted',receiptId:'test'}))})}}})
 const long='a'.repeat(120),extra=Object.fromEntries(['tool','provider','model','responseModel','sessionId','traceId','spanId','parentSpanId','requestId','processGuid','adapterVersion','errorCode'].map(k=>[k,long]))
 for(let n=0;n<100;n++)reporter.record({...extra,eventId:'large-'+n,operation:'model_request',operationId:'operation-'+long+n,hostname:'https://'+('a'.repeat(60)+'.').repeat(3)+'example.test',cost:{amount:'123456789012.123456789',currency:'USD',source:long}})
 await reporter.flush();assert.ok(Buffer.byteLength(payload)<=240*1024);assert.ok(JSON.parse(payload).events.length>0)
})
