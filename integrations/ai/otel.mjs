import crypto from 'node:crypto'
// Metadata allowlist mapped to the GenAI conventions reviewed 2026-09-24.
export const adapterVersion='otel-genai-2026-09-24-v1'
export function fromGenAiSpan(span){
 const a=span.attributes||{},operation=a['gen_ai.operation.name'];if(!operation)return null
 const operations={chat:'model_request',generate_content:'model_request',text_completion:'model_request',embeddings:'embedding',embed:'embedding',execute_tool:'tool_call',invoke_agent:'research',invoke_workflow:'research'}
 const observedAt=new Date(span.endTime||span.startTime).toISOString(),key=crypto.createHash('sha256').update(String(span.traceId)+'\0'+String(span.spanId)).digest('hex')
 return {schemaVersion:1,eventId:'otel:'+key,operationId:key,operation:operations[operation]||'other',observedAt,startedAt:span.startTime?new Date(span.startTime).toISOString():undefined,endedAt:observedAt,traceId:span.traceId,spanId:span.spanId,parentSpanId:span.parentSpanId,tool:a['gen_ai.tool.name'],provider:a['gen_ai.provider.name'],model:a['gen_ai.request.model'],responseModel:a['gen_ai.response.model'],hostname:a['server.address'],inputTokens:a['gen_ai.usage.input_tokens'],outputTokens:a['gen_ai.usage.output_tokens'],outcome:span.status==='ERROR'?'failure':'success',errorCode:span.status==='ERROR'?'span_error':undefined,adapterVersion}
}

// OTLP/JSON export adapter. Only the GenAI metadata allowlist survives conversion.
// Sampled/exported spans are instrumented partial coverage, never a complete fleet count.
export function fromOtlp(payload){
 const events=[]
 for(const resource of payload.resourceSpans||[])for(const scope of resource.scopeSpans||[])for(const span of scope.spans||[]){
  if(events.length>=1000)return events
  try{
   if(!span.traceId||!span.spanId)continue
   const attributes=Object.fromEntries((span.attributes||[]).map(({key,value={}})=>[key,value.stringValue??(value.intValue!==undefined?Number(value.intValue):value.doubleValue??value.boolValue)]))
   const stamp=ns=>new Date(Number(BigInt(ns)/1000000n)).toISOString()
   const event=fromGenAiSpan({...span,attributes,startTime:stamp(span.startTimeUnixNano),endTime:stamp(span.endTimeUnixNano),status:span.status?.code===2?'ERROR':'OK'})
   if(event)events.push(event)
  }catch{} // Malformed/unknown spans never break the collector's work.
 }
 return events
}
