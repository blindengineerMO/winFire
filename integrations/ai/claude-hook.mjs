import fs from 'node:fs'
import crypto from 'node:crypto'
import path from 'node:path'
import {AiReporter} from './reporter.mjs'
export function fromClaudeHook(input,observedAt=new Date().toISOString()){
 if(!['PostToolUse','PostToolUseFailure'].includes(input.hook_event_name)||!input.tool_use_id)return null
 if(/report_ai_usage(?:_batch)?$/.test(input.tool_name||''))return null
 const operationId=crypto.createHash('sha256').update(String(input.session_id||'')+'\0'+String(input.tool_use_id)).digest('hex')
 const outcome=input.hook_event_name==='PostToolUse'?'success':input.is_interrupt?'cancelled':'failure'
 return {schemaVersion:1,eventId:'claude:'+operationId+':end',operationId,operation:['WebSearch'].includes(input.tool_name)?'search':['WebFetch'].includes(input.tool_name)?'browse':'tool_call',tool:input.tool_name,sessionId:input.session_id,observedAt,outcome,durationMs:input.duration_ms,errorCode:outcome==='failure'?'tool_failed':undefined,adapterVersion:'claude-hook-1'}
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
 // Hooks must never print raw input, tool errors or a transcript.
 try{const raw=fs.readFileSync(0,'utf8');if(Buffer.byteLength(raw)<=1048576){const e=fromClaudeHook(JSON.parse(raw));if(e){const reporter=new AiReporter();const clocks=path.join(reporter.spool,'.hook-clocks');fs.mkdirSync(clocks,{recursive:true,mode:0o700});const file=path.join(clocks,e.operationId);try{e.observedAt=fs.readFileSync(file,'utf8')}catch{const names=fs.readdirSync(clocks);if(names.length>=1000){const oldest=names.map(name=>({name,at:fs.statSync(path.join(clocks,name)).mtimeMs})).sort((a,b)=>a.at-b.at)[0];fs.rmSync(path.join(clocks,oldest.name),{force:true})}try{fs.writeFileSync(file,e.observedAt,{mode:0o600,flag:'wx'})}catch{e.observedAt=fs.readFileSync(file,'utf8')}}reporter.record(e)}}}catch{}
}
