import {createHash} from 'node:crypto'
import {z} from 'zod'
import {all,one,run,now,json,parse,audit} from '../db.js'
import {openSealed} from '../security.js'
const defaults={enabled:false,baseUrl:'',credentialId:'',assignmentGroup:'',impact:2,urgency:2}
export const serviceNowSchema=z.object({enabled:z.boolean(),baseUrl:z.string().trim().max(2048),credentialId:z.string().max(100),assignmentGroup:z.string().regex(/^(?:[a-f0-9]{32})?$/i),impact:z.number().int().min(1).max(3),urgency:z.number().int().min(1).max(3)}).strict()
export const serviceNowSettings=()=>({...defaults,...parse(one('SELECT config_json FROM servicenow_integration WHERE id=1')?.config_json)})
function baseUrl(value){
 let url;try{url=new URL(value)}catch{throw Object.assign(new Error('Enter the HTTPS ServiceNow instance URL'),{status:400})}
 if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||!['','/'].includes(url.pathname))throw Object.assign(new Error('Use an HTTPS instance origin without a path, credentials, query or fragment'),{status:400})
 return url.origin
}
export function saveServiceNow(input,actor){
 const data=serviceNowSchema.parse(input);if(data.baseUrl)data.baseUrl=baseUrl(data.baseUrl)
 if(data.enabled&&(!data.baseUrl||!data.credentialId))throw Object.assign(new Error('Select an instance and ServiceNow vault credential before enabling delivery'),{status:400})
 if(data.credentialId&&!one("SELECT id FROM credentials WHERE id=? AND type='servicenow'",data.credentialId))throw Object.assign(new Error('Select a ServiceNow credential from the vault'),{status:400})
 run('INSERT INTO servicenow_integration(id,config_json,updated_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET config_json=excluded.config_json,updated_at=excluded.updated_at',json(data),now());audit(actor,'servicenow.configure','integration','servicenow',null,data);return data
}
async function request(config,method,query,body,fetcher){
 const credential=one("SELECT * FROM credentials WHERE id=? AND type='servicenow'",config.credentialId)
 if(!credential)throw new Error('ServiceNow vault credential is missing')
 const password=openSealed(credential.encrypted_blob).password
 if(!password||!credential.username)throw new Error('ServiceNow credential needs a username and password')
 const response=await fetcher(baseUrl(config.baseUrl)+'/api/now/v1/table/incident'+(query?'?'+new URLSearchParams(query):''),{method,headers:{Authorization:'Basic '+Buffer.from(credential.username+':'+password).toString('base64'),'Content-Type':'application/json',Accept:'application/json'},...(body?{body:json(body)}:{}),redirect:'error',signal:AbortSignal.timeout(15000)})
 if(!response.ok)throw new Error(`ServiceNow returned HTTP ${response.status}${response.status===401||response.status===403?' (check credentials and incident table ACLs)':''}`)
 // Never include the remote response body or credentials in errors/audit messages.
 let text='',size=0;for await(const chunk of response.body){size+=chunk.byteLength;if(size>1048576)throw new Error('ServiceNow response exceeds 1 MB');text+=Buffer.from(chunk).toString('utf8')}
 let data;try{data=JSON.parse(text)}catch{throw new Error('ServiceNow returned invalid JSON')};return data.result
}
export async function testServiceNow(fetcher=fetch){
 const config=serviceNowSettings();if(!config.baseUrl||!config.credentialId)throw Object.assign(new Error('Save an instance URL and credential first'),{status:400})
 try{const result=await request(config,'GET',{sysparm_limit:1,sysparm_fields:'sys_id,number'},null,fetcher);if(!Array.isArray(result))throw new Error('Unexpected incident table response');return {ok:true,message:'Authentication and incident read access verified. Ticket creation also requires create access to the incident table.'}}catch(e){throw Object.assign(new Error(e.message.startsWith('ServiceNow')?e.message:'ServiceNow connection failed; check DNS, TLS and connectivity'),{status:502})}
}
export async function deliverServiceNow(item,fetcher=fetch){
 const config=serviceNowSettings();if(!config.enabled)return false
 const correlationId='winfire:'+createHash('sha256').update(config.baseUrl+'\0'+item.event_key).digest('hex').slice(0,48)
 if(one('SELECT sys_id FROM servicenow_tickets WHERE correlation_id=?',correlationId)?.sys_id)return true
 run('INSERT OR IGNORE INTO servicenow_tickets(correlation_id,event_key,instance_url,created_at) VALUES(?,?,?,?)',correlationId,item.event_key,config.baseUrl,now())
 // Recover from a successful POST whose response was lost before committing locally.
 const previous=await request(config,'GET',{sysparm_query:'correlation_id='+correlationId,sysparm_fields:'sys_id,number',sysparm_limit:1},null,fetcher)
 if(!Array.isArray(previous))throw new Error('ServiceNow returned an invalid incident search')
 const ticket=previous[0]||await request(config,'POST',null,{short_description:item.title.slice(0,160),description:item.body.slice(0,16000),correlation_id:correlationId,correlation_display:'WinFire '+item.category,impact:String(config.impact),urgency:String(config.urgency),...(config.assignmentGroup?{assignment_group:config.assignmentGroup}:{})},fetcher)
 if(!/^[a-f0-9]{32}$/i.test(ticket?.sys_id||''))throw new Error('ServiceNow did not return a valid incident identifier')
 run('UPDATE servicenow_tickets SET sys_id=?,number=? WHERE correlation_id=?',ticket.sys_id,String(ticket.number||'').slice(0,100),correlationId);return true
}
export function serviceNowDeliveries(query={}){
 const q=z.object({page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(100).default(25)}).parse(query)
 return {...q,total:one("SELECT COUNT(*) n FROM notification_deliveries WHERE channel='servicenow'").n,items:all("SELECT id,event_key,category,title,status,attempts,last_error,sent_at,next_attempt_at FROM notification_deliveries WHERE channel='servicenow' ORDER BY rowid DESC LIMIT ? OFFSET ?",q.pageSize,(q.page-1)*q.pageSize).map(d=>({...d,ticket:one('SELECT number,sys_id,instance_url FROM servicenow_tickets WHERE event_key=? AND sys_id IS NOT NULL ORDER BY created_at DESC LIMIT 1',d.event_key)||null}))}
}
