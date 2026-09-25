import {z} from 'zod'
import {azureCredentialSchema,connectionSchema,pageSchema} from './schemas.js'
export const cloudSchemas={
  AzureCredentialRequest:z.toJSONSchema(azureCredentialSchema),AzureConnectionRequest:z.toJSONSchema(connectionSchema),
  InventoryScopeRequest:{type:'object',additionalProperties:false,required:['name','cidrs'],properties:{name:{type:'string',minLength:1,maxLength:180},kind:{type:'string',enum:['site','azure-vnet'],default:'site'},cidrs:{type:'array',maxItems:256,items:{type:'string',maxLength:64}},directManagement:{type:'boolean',default:false}}},
  InventoryResolutionRequest:{type:'object',required:['action','reason'],properties:{action:{type:'string',enum:['link','unlink','ignore','reopen']},nodeId:{type:'string'},reason:{type:'string',minLength:1,maxLength:1000}}}
}
export function describeCloudOperation(operation,method,path){
  if(path==='/credentials'&&method==='post'){
    const azure={...cloudSchemas.AzureCredentialRequest,properties:{...cloudSchemas.AzureCredentialRequest.properties,type:{type:'string',const:'azure'}},required:[...cloudSchemas.AzureCredentialRequest.required,'type']}
    operation.description='Store a credential in the shared encrypted vault. Azure / Arc uses type=azure with tenantId, clientId and explicit authMethod; administrators create cloud credentials. Existing local/domain/SSH/ESXi/SNMP types retain their host credential fields.'
    operation.requestBody={required:true,content:{'application/json':{schema:{oneOf:[azure,{type:'object',required:['name','type'],properties:{name:{type:'string'},type:{type:'string',enum:['local','domain','esxi','ssh','snmp-v2c','snmp-v3']}}}]}}}}
    return
  }
  if(!path.startsWith('/discovery/azure')&&!path.startsWith('/inventory/')&&!/^\/nodes\/\{id\}\/sources$/.test(path))return
  operation.description='Azure/Arc discovery retains provider observations separately from host verification and firewall enforcement. Inventory requires an explicit owned network scope. Mutations require administrator access and are audited.'
  const connection=/^\/discovery\/azure\/connections(?:\/\{id\})?$/.test(path),scope=path.startsWith('/inventory/scopes'),resolution=path.endsWith('/resolve')
  if(['post','put'].includes(method)){
    const schema=connection?'AzureConnectionRequest':scope?'InventoryScopeRequest':resolution?'InventoryResolutionRequest':null
    operation.requestBody={required:!!schema,content:{'application/json':{schema:schema?{$ref:'#/components/schemas/'+schema}:{type:'object',additionalProperties:false}}}}
    if(/\/(test|preview|sync)$/.test(path))operation.responses={202:{description:'Durable run queued; poll /discovery/azure/runs/{id}. Test and preview do not write inventory.'},default:operation.responses.default}
    else if(method==='post'&&!resolution&&!path.endsWith('/cancel'))operation.responses={201:{description:'Created'},default:operation.responses.default}
  }
  if(method==='get'&&['/discovery/azure/resources','/discovery/azure/resources/export','/discovery/azure/runs','/inventory/conflicts'].includes(path)||method==='get'&&path.endsWith('/history')){
    const fields=z.toJSONSchema(pageSchema).properties
    operation.parameters.push(...Object.entries(fields).map(([name,schema])=>({name,in:'query',schema})))
  }
}
