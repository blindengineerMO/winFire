import {z} from 'zod'
import {keyCreateSchema,keyEditSchema} from './userApiKeys.js'
export const userApiKeySchemas={UserApiKeyCreateRequest:z.toJSONSchema(keyCreateSchema),UserApiKeyEditRequest:z.toJSONSchema(keyEditSchema)}
export function describeUserApiKeyOperation(operation,method,path){
  path=path.replace(/\/$/,'')
  if(!path.startsWith('/api-keys'))return
  operation.tags=['User API keys']
  operation.description='Requires an interactive user-session bearer token. Users manage their own keys; administrators may administer users with equal or lower permissions. API keys cannot call key-management endpoints. Secrets are returned only on create/rotate; all responses are no-store.'
  if(method==='post'&&path==='/api-keys'){
    operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/UserApiKeyCreateRequest'}}}}
    operation.responses={201:{description:'Created: key metadata and one-time secret. Store the secret securely.'},default:operation.responses.default}
  }
  if(method==='patch')operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/UserApiKeyEditRequest'}}}}
  if(method==='delete')operation.responses={204:{description:'Key deleted and reporting identity revoked; audit/usage history retained.'},default:operation.responses.default}
  if(path.endsWith('/rotate'))operation.responses={200:{description:'Replacement one-time secret; the previous secret is invalid immediately.'},default:operation.responses.default}
  if(method==='get'&&path==='/api-keys')operation.parameters.push(...Object.entries({q:{type:'string',maxLength:200},owner:{type:'string',default:'self',description:'self, all (administrators), or a permitted user ID'},status:{type:'string',enum:['all','active','expired','revoked'],default:'all'},purpose:{type:'string',enum:['all','api','mcp'],default:'all'},sort:{type:'string',enum:['name','created','expires','used'],default:'created'},direction:{type:'string',enum:['asc','desc'],default:'desc'},page:{type:'integer',minimum:1,default:1},pageSize:{type:'integer',minimum:1,maximum:100,default:25}}).map(([name,schema])=>({name,in:'query',schema})))
}
