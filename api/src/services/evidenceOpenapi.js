import {z} from 'zod'
import {evidenceDestinationSchema} from './evidenceExports.js'
export const evidenceSchemas={EvidenceDestinationRequest:z.toJSONSchema(evidenceDestinationSchema)}
export function describeEvidenceOperation(operation,method,path){
  if(!path.startsWith('/evidence-')&&path!=='/reports/evidence')return
  operation.tags=['Evidence exports']
  operation.description='Administrator-only scoped retained evidence. HTTPS delivery signs timestamp + dot + delivery UUID + dot + exact UTF-8 body using HMAC-SHA256. Headers: X-WinFire-Timestamp (Unix seconds), X-WinFire-Delivery and Idempotency-Key (stable UUID), X-WinFire-Signature (sha256=hex digest). Validate the signature in constant time, reject stale timestamps and durably deduplicate the delivery UUID. Respond 2xx after durable acceptance; retries are at least once. Destinations default disabled; updates cancel pending deliveries. Raw audit values and arbitrary capability diagnostics are excluded.'
  if(['post','put'].includes(method)&&/^\/evidence-destinations(?:\/\{id\})?$/.test(path))operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/EvidenceDestinationRequest'}}}}
  if(method==='post'&&path==='/evidence-destinations')operation.responses={201:{description:'Destination plus oneTimeSecret; secret is never returned again'},default:operation.responses.default}
  if(method==='post'&&path.endsWith('/snapshot'))operation.responses={202:{description:'Snapshot queued for delivery'},default:operation.responses.default}
  if(method==='get'&&path==='/reports/evidence')operation.parameters.push({name:'scopeId',in:'query',schema:{type:'string',default:'default'}})
  if(method==='get'&&path==='/evidence-deliveries')operation.parameters.push(...Object.entries({destinationId:{type:'string'},status:{enum:['pending','sent','failed','cancelled']},page:{type:'integer',minimum:1,default:1},pageSize:{type:'integer',minimum:1,maximum:100,default:25}}).map(([name,schema])=>({name,in:'query',schema})))
}
