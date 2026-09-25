import {z} from 'zod'
import {domainToASCII} from 'node:url'
import {isIP} from 'node:net'
const secretLike=value=>/^(?:wf(?:uk|ai)_[A-Za-z0-9_-]{20,}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.)/.test(value)
export const identifier=z.string().trim().min(1).max(160).regex(/^[a-zA-Z0-9_.:@/ -]+$/).refine(v=>!secretLike(v),'Credential-like identifier rejected')
export const tag=z.string().trim().min(1).max(128).regex(/^[a-zA-Z0-9_.:/@-]+$/).refine(v=>!secretLike(v),'Credential-like metadata rejected')
export function hostname(raw){
 let text=String(raw||'').trim()
 if(text.includes('://')){try{const u=new URL(text);if(!['http:','https:'].includes(u.protocol))return null;text=u.hostname}catch{return null}}
 const host=domainToASCII(text.toLowerCase().replace(/\.$/,''))
 if(!host||host.length>253||isIP(host)||host.split('.').some(x=>!x||x.length>63||!/^([a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])$/.test(x)))return null
 return host
}
export const hostSchema=z.string().max(2048).transform(hostname).refine(Boolean,'Invalid hostname')
const stamp=z.iso.datetime({offset:true}).transform(v=>new Date(v).toISOString())
const optTag=tag.nullable().optional()
export const eventSchema=z.strictObject({
 schemaVersion:z.literal(1),eventId:identifier,operationId:identifier.optional(),nodeId:identifier.optional(),operation:tag,phase:z.enum(['start','end','complete']).default('complete'),observedAt:stamp,startedAt:stamp.optional(),endedAt:stamp.optional(),outcome:z.enum(['success','failure','cancelled','incomplete']).default('success'),errorCode:optTag,
 tool:optTag,provider:optTag,model:optTag,responseModel:optTag,hostname:hostSchema.optional(),sessionId:optTag,traceId:optTag,spanId:optTag,parentSpanId:optTag,requestId:optTag,processId:z.number().int().min(0).max(2147483647).optional(),processGuid:optTag,processStartedAt:stamp.optional(),durationMs:z.number().min(0).max(31536000000).optional(),
 inputTokens:z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),outputTokens:z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),cost:z.strictObject({amount:z.string().regex(/^\d{1,12}(\.\d{1,9})?$/),currency:z.string().regex(/^[A-Z]{3}$/),source:tag}).optional(),adapterVersion:optTag
}).superRefine((e,c)=>{if(e.startedAt&&e.endedAt&&e.startedAt>e.endedAt)c.addIssue({code:'custom',message:'End precedes start'});if(e.phase==='start'&&(e.cost||e.inputTokens!==undefined||e.outputTokens!==undefined))c.addIssue({code:'custom',message:'Usage metrics require a terminal event'})})
export const batchSchema=z.strictObject({events:z.array(z.unknown()).min(1).max(100)})
export const reporterSchema=z.strictObject({name:z.string().trim().min(1).max(100),nodeIds:z.array(identifier).max(500).default([]),coverage:z.enum(['self-reported','instrumented','collector']).default('self-reported'),actorId:identifier.nullable().optional(),issuer:z.url().refine(v=>{const u=new URL(v);return !u.username&&!u.password&&!u.search&&!u.hash},'Use an issuer URL without credentials, query or fragment').optional(),subject:identifier.optional(),clientId:identifier.optional()}).refine(v=>!v.issuer||v.subject&&v.clientId,'OAuth bindings require issuer, subject and client ID')
export const settingsSchema=z.strictObject({enabled:z.boolean(),retentionDays:z.number().int().min(1).max(3650),correlationWindowSeconds:z.number().int().min(1).max(600),dnsWindowSeconds:z.number().int().min(1).max(600),staleReporterMinutes:z.number().int().min(1).max(1440)})
export const querySchema=z.object({q:z.string().trim().max(200).default(''),nodeId:identifier.optional(),groupId:identifier.optional(),reporterId:identifier.optional(),actorId:identifier.optional(),provider:tag.optional(),model:tag.optional(),operation:tag.optional(),tool:tag.optional(),outcome:z.enum(['success','failure','cancelled','incomplete','allow','block','observed']).optional(),category:z.enum(['reported','observed','suspected','supporting']).optional(),confidence:z.enum(['reported','high','medium','low']).optional(),mapped:z.enum(['all','mapped','unmapped']).default('all'),from:stamp.optional(),to:stamp.optional(),page:z.coerce.number().int().min(1).default(1),limit:z.coerce.number().int().min(1).max(100).default(25),sort:z.enum(['time','node','provider','operation','outcome','model','reporter','hostname']).default('time'),order:z.enum(['asc','desc']).default('desc')}).refine(q=>!q.from||!q.to||q.from<=q.to,'From must precede To')
export const dnsSchema=z.strictObject({schemaVersion:z.literal(1),eventId:identifier,nodeId:identifier.optional(),hostname:hostSchema,answers:z.array(z.string().refine(v=>!!isIP(v),'Invalid IP')).max(32),observedAt:stamp,ttlSeconds:z.number().int().min(0).max(86400).optional(),processId:z.number().int().min(0).optional(),processGuid:optTag,processStartedAt:stamp.optional(),provider:z.literal('Microsoft-Windows-Sysmon'),channel:z.literal('Microsoft-Windows-Sysmon/Operational')})
export const canonical=value=>JSON.stringify(value,(_k,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a.localeCompare(b))):v)
export const failure=(status,code)=>Object.assign(new Error(code.replaceAll('_',' ')),{status,code})

export const receiptSchema=z.object({schemaVersion:z.literal(1),results:z.array(z.object({eventId:z.string().nullable(),status:z.enum(['accepted','duplicate','rejected']),receiptId:z.string().optional(),usageId:z.string().nullable().optional(),mapped:z.boolean().optional(),code:z.string().optional(),retryable:z.boolean().optional()})),counts:z.object({accepted:z.number(),duplicate:z.number(),rejected:z.number()})})
