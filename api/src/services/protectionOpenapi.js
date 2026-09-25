import {z} from 'zod'
import {ddosPolicySchema} from './ddos.js'
import {serviceNowSchema} from './servicenow.js'
export const protectionSchemas={DdosPolicyRequest:z.toJSONSchema(ddosPolicySchema),ServiceNowSettingsRequest:z.toJSONSchema(serviceNowSchema)}
export function describeProtectionOperation(operation,method,path){
 if(!path.startsWith('/protection/ddos')&&!path.startsWith('/notifications/servicenow'))return
 operation.tags=[path.startsWith('/protection/')?'DDoS protection':'ServiceNow']
 operation['x-required-permissions']=['admin']
 operation.description='Administrator/owner only. Changes are audited. ServiceNow credentials stay in the vault. DDoS policies default to disabled detection-only mode; automatic blocking uses expiring host rules, then fresh telemetry to decide whether to repeat.'
 if(method==='put'&&path==='/notifications/servicenow')operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/ServiceNowSettingsRequest'}}}}
 if(['post','put'].includes(method)&&/^\/protection\/ddos\/policies(?:\/\{id\})?$/.test(path)){operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/DdosPolicyRequest'}}}};if(method==='post')operation.responses={201:{description:'Created DDoS policy'},default:operation.responses.default}}
 if(path.endsWith('/deliveries')||path==='/protection/ddos/incidents')operation.parameters.push(...Object.entries({page:{type:'integer',minimum:1,default:1},pageSize:{type:'integer',minimum:1,maximum:100,default:25},...(path.endsWith('/incidents')?{q:{type:'string',maxLength:200},status:{type:'string',enum:['all','active','closed'],default:'all'}}:{})}).map(([name,schema])=>({name,in:'query',schema})))
 if(path.endsWith('/release'))operation.description+=' Disables the incident policy and removes temporary host rules. Returns 409 while evaluation runs; retry later. A failed removal is retained for automatic cleanup retries.'
 if(path.endsWith('/test'))operation.description+=' Tests the saved instance and credentials with a read-only incident-table query. Does not create a test ticket.'
}
