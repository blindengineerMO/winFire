import {containmentSchema} from './containment.js'
import {z} from 'zod'
import {stagedDeploymentSchema} from './stagedDeployment.js'
import {simulationInput} from './policySimulation.js'
import {metadataProposalSchema,metadataSourcesSchema} from './applicationContext.js'
import {exceptionSchema} from './ruleLifecycle.js'
import {exporterSchema} from '../telemetry/service.js'
import {blobSchema} from '../telemetry/vnet.js'
export const policySafetySchemas=Object.fromEntries(Object.entries({ContainmentRequest:containmentSchema,MetadataSourcesRequest:metadataSourcesSchema,StagedDeploymentRequest:stagedDeploymentSchema,PolicySimulationRequest:simulationInput,ApplicationMetadataProposal:metadataProposalSchema,RuleExceptionRequest:exceptionSchema,TelemetryExporterRequest:exporterSchema,VnetBlobRequest:blobSchema}).map(([name,schema])=>[name,z.toJSONSchema(schema)]))
export function describePolicySafetyOperation(operation,method,path){
 if(!/^\/(?:containments|policy-deployments|policy-simulations|policy-templates|rule-exceptions|application-proposals|telemetry)/.test(path)&&!/^\/policies\/\{id\}\/(deployments|simulations|exceptions|hygiene)/.test(path)&&!/^\/nodes\/\{id\}\/(application|policy-context)/.test(path)&&!['/settings/application-metadata','/mapping/cloud-context','/mapping/applications','/discovery/azure/connections/{id}/network-context'].includes(path))return
 operation.tags=[path.startsWith('/telemetry')||path.includes('cloud-context')?'Traffic context':'Policy safety']
 operation.description='Authenticated API. Search, filtering and pagination run on the server. Simulations and proposals never install firewall rules. Traffic records retain observation provenance and do not create inventory assets.'
 const key=method.toUpperCase()+' '+path
 const schemas={'POST /containments/preview':'ContainmentRequest','POST /containments':'ContainmentRequest','PUT /settings/application-metadata':'MetadataSourcesRequest','POST /policy-deployments/preview':'StagedDeploymentRequest','POST /policy-deployments':'StagedDeploymentRequest','POST /policies/{id}/simulations':'PolicySimulationRequest','POST /nodes/{id}/application/proposals':'ApplicationMetadataProposal','POST /policies/{id}/exceptions':'RuleExceptionRequest','POST /telemetry/exporters':'TelemetryExporterRequest','PUT /telemetry/exporters/{id}':'TelemetryExporterRequest','POST /telemetry/exporters/{id}/vnet-blob':'VnetBlobRequest'}
 if(schemas[key])operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/'+schemas[key]}}}}
 const bodies={'POST /containments/{id}/restore':{required:['reason'],properties:{reason:{type:'string',minLength:1,maxLength:2000}}},
  'POST /policy-simulations/{id}/approve':{required:['reason'],properties:{reason:{type:'string',minLength:1,maxLength:1000}}},
  'POST /application-proposals/{id}/review':{required:['approve','reason'],properties:{approve:{type:'boolean'},reason:{type:'string',minLength:1,maxLength:1000}}},
  'POST /telemetry/exporters/{id}/datagram':{required:['base64'],properties:{base64:{type:'string',maxLength:87384,description:'One NetFlow v9 or IPFIX v10 datagram'}}},
  'POST /telemetry/exporters/{id}/syslog':{required:['captureKey','lines'],properties:{captureKey:{type:'string',maxLength:300},lines:{type:'array',minItems:1,maxItems:10000,items:{type:'string',maxLength:16384}}}},
  'POST /policy-templates/preview':{required:['templateId','endpointNodeIds'],properties:{templateId:{type:'string'},endpointNodeIds:{type:'array',minItems:1,maxItems:100,items:{type:'string'}},ports:{type:'array',maxItems:32,items:{type:'integer',minimum:1,maximum:65535}}}},
  'POST /rule-exceptions/{id}/review':{required:['action','reason'],properties:{action:{enum:['recertify','retire']},reason:{type:'string',minLength:1,maxLength:2000},reviewAt:{type:'string',format:'date-time'},expiresAt:{type:['string','null'],format:'date-time'}}}
 }
 for(const action of ['cancel','resume','restore'])bodies['POST /policy-deployments/{id}/'+action]={required:['reason'],properties:{reason:{type:'string',minLength:1,maxLength:2000}}}
 if(bodies[key])operation.requestBody={required:true,content:{'application/json':{schema:{type:'object',additionalProperties:false,...bodies[key]}}}}
 if(method==='post'&&path==='/policies/{id}/simulations')operation.responses={202:{description:'Queued read-only evaluation with immutable historical evidence'},default:operation.responses.default}
 if(method==='post'&&['/telemetry/exporters','/nodes/{id}/application/proposals','/policies/{id}/exceptions'].includes(path))operation.responses={201:{description:'Created record'},default:operation.responses.default}
 if(method==='get'&&['/policy-simulations/{id}/results','/rule-exceptions','/telemetry/observations','/telemetry/observations/export','/mapping/cloud-context','/mapping/applications'].includes(path))operation.parameters.push(...Object.entries({page:{type:'integer',minimum:1,default:1},pageSize:{type:'integer',minimum:1,maximum:250,default:25},...({'/policy-simulations/{id}/results':{outcome:{enum:['unchanged','newly-allowed','newly-blocked','indeterminate']}},'/rule-exceptions':{policyId:{type:'string'},q:{type:'string'},state:{enum:['all','due','expired','retirement-requested']}},'/mapping/applications':{application:{type:'string'}},'/mapping/cloud-context':{connectionId:{type:'string'},kind:{type:'string'}},'/telemetry/observations':{q:{type:'string'},exporterId:{type:'string'}},'/telemetry/observations/export':{q:{type:'string'},exporterId:{type:'string'}}}[path]||{})}).map(([name,schema])=>({name,in:'query',schema})))
}
