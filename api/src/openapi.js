import {protectionSchemas,describeProtectionOperation} from './services/protectionOpenapi.js'
import {cloudSchemas,describeCloudOperation} from './cloud/openapi.js'
import {userApiKeySchemas,describeUserApiKeyOperation} from './services/userApiKeysOpenapi.js'
import {aiSchemas,describeAiOperation} from './ai/openapi.js'
import {internetConnectionSchemas} from './services/internetConnectionSchemas.js'
const publicRoutes=new Set([
  'GET /health','GET /openapi.json','POST /auth/login','POST /auth/refresh',
  'POST /invites/accept','POST /auth/verify-email','POST /auth/ad/login',
  'POST /auth/ad-totp/enroll','POST /auth/ad-totp/confirm','GET /avatars/{id}',
  'GET /portal-branding','GET /portal-branding/image',
  'GET /agent-package/WinFire.Agent.exe','GET /agent-package/WinFire.Agent.msi','GET /agent-package/enroll.ps1',
  'GET /mfa/prompts/{id}','POST /mfa/prompts/{id}/totp','POST /mfa/prompts/{id}/entra/start',
  'POST /mfa/entra/complete','POST /mfa/entra/cancel',
  'POST /agents/enroll'
])
const internetEnrollmentRoutes=new Set(['POST /internet/enroll'])
const internetDeviceRoutes=new Set(['POST /internet/events:batch','GET /internet/config'])
const wefReceiverRoutes=new Set(['POST /wef/wsman'])

const operationId=(method,path)=>method+path.split('/').filter(Boolean).map(part=>part.startsWith('{')?`By${part.slice(1,-1)[0].toUpperCase()}${part.slice(2,-1)}`:part.replace(/(^|-)(\w)/g,(_match,_dash,letter)=>letter.toUpperCase())).join('')
const pathParameters=path=>[...path.matchAll(/\{([^}]+)\}/g)].map(match=>({name:match[1],in:'path',required:true,schema:{type:'string'}}))
const jsonResponse={description:'JSON response',content:{'application/json':{schema:{}}}}
const errorResponse={description:'Error response',content:{'application/json':{schema:{$ref:'#/components/schemas/Error'}}}}

// Keep the public contract useful to operators and generated clients for the
// high impact control and agent operations.  Route discovery still covers the
// complete API, while these explicit schemas prevent management calls from
// being published as unbounded JSON objects.
const requestSchemas={
  'PATCH /settings/directory':'DirectorySettingsRequest',
  'POST /policies/{id}/preview':'PolicyDraftRequest',
  'POST /policies/{id}/versions':'PolicyVersionRequest',
  'POST /internet/peers/{id}/resolve':'EmptyRequest',
  'POST /discovery/snmp-library/preview':'SnmpMibImportRequest',
  'POST /discovery/snmp-library/import':'SnmpMibImportRequest',
  'PATCH /discovery/snmp-library/{id}':'SnmpMibUpdateRequest',
  'POST /discovery/dhcp/preview':'DhcpImportRequest',
  'POST /discovery/dhcp/import':'DhcpImportRequest',
  'POST /auth/logout':'LogoutRequest',
  'POST /auth/ad/login':'AdLoginRequest',
  'POST /auth/ad-totp/enroll':'AdAuthenticatorEnrollRequest',
  'POST /auth/ad-totp/confirm':'AuthenticatorConfirmRequest',
  'POST /invites/accept':'InviteAcceptRequest',
  'POST /auth/verify-email':'VerifyEmailRequest',
  'POST /mfa/prompts/{id}/totp':'MfaPromptTotpRequest',
  'POST /mfa/prompts/{id}/entra/start':'EmptyRequest',
  'POST /mfa/entra/complete':'MfaEntraCompleteRequest',
  'POST /mfa/entra/cancel':'MfaEntraCancelRequest',
  'POST /auth/email-verification/request':'EmptyRequest',
  'POST /auth/totp/confirm':'AuthenticatorCodeRequest',
  'POST /auth/totp/disable':'TotpDisableRequest',
  'POST /auth/totp/setup':'EmptyRequest',
  'POST /internet/enrollment':'InternetEnrollmentRequest',
  'POST /internet/enroll':'InternetDeviceEnrollRequest',
  'POST /internet/events:batch':'InternetEventBatchRequest',
  'POST /internet/policies':'InternetPolicyStageRequest',
  'POST /internet/policies/{id}/publish':'EmptyRequest',
  'POST /internet/policies/{id}/rollback':'EmptyRequest',
  'POST /internet/policies/{id}/emergency-rollback':'EmptyRequest',
  'POST /internet/devices/{id}/revoke':'EmptyRequest',
  'POST /internet/events/cleanup':'InternetCleanupRequest',
  'POST /agents/enroll':'AgentEnrollRequest',
  'POST /agents/{id}/heartbeat':'AgentHeartbeatRequest',
  'POST /agents/{id}/events':'AgentEventBatchRequest',
  'POST /agents/{id}/network':'AgentNetworkRequest',
  'POST /agents/{id}/jobs/{jobId}/result':'AgentJobResultRequest',
  'POST /nodes/{id}/wef/configure':'WefConfigureRequest',
  'PATCH /settings/entra':'EntraSettingsRequest',
  'PATCH /settings/server':'ServerSettingsRequest',
  'PATCH /settings/wef':'WefSettingsRequest',
  'POST /logs/pull':'LogsPullRequest',
  'POST /learning-sessions':'TrainingSessionRequest',
  'POST /segments/{id}/challenges':'MfaChallengeRequest',
  'POST /segments/{id}/challenges/{challengeId}/resolve':'MfaResolveRequest',
  'POST /segments/{id}/lsa-baselines':'LsaBaselineRequest',
  'POST /logon-rights/baseline':'LogsPullRequest',
  'POST /discovery/scans':'DiscoveryScanRequest',
  'POST /nodes/triage/bulk':'TriageBulkRequest',
  'POST /settings/classifier/rules':'ClassifierRuleRequest',
  'PATCH /settings/classifier/rules/{id}':'ClassifierRuleRequest',
  'POST /settings/classifier/process-rules':'ClassifierProcessRuleRequest',
  'PATCH /settings/classifier/process-rules/{id}':'ClassifierProcessRuleRequest'
}

const responseSchemas={
  'POST /policies/{id}/preview':'PolicyDraftPreview',
  'GET /internet/connections':'InternetConnectionPage',
  'GET /internet/connections/summary':'InternetConnectionSummary',
  'GET /internet/connections/export':'InternetConnectionExport',
  'GET /internet/connections/{id}':'InternetConnectionDetails',
  'GET /internet/peers/{id}':'InternetPeer',
  'GET /credentials/health':'CredentialHealthResponse',
  'POST /segments/{id}/entra-group/sync':'EntraGroupSyncResponse',
  'GET /segments/{id}/entra-group/members':'EntraGroupMembersResponse',
  'GET /settings/entra':'EntraSettingsResponse',
  'PATCH /settings/entra':'EntraSettingsResponse'
}

export function buildOpenApi(apiRouter,agentRouter,extraRouters={}){
  const paths={}
  const addRoutes=(router,prefix='')=>{
    for(const layer of router.stack||[]){
      if(!layer.route||typeof layer.route.path!=='string')continue
      // Express also permits a literal colon in a route suffix (the Internet
      // batch endpoint is `/events:batch`). Only convert colon parameters
      // that start a path segment; preserving the suffix keeps OpenAPI aligned
      // with the actual device endpoint.
      const path=(prefix+layer.route.path).replaceAll('\\:',':').replace(/(^|\/)\:([A-Za-z]\w*)(?=\/|$)/g,'$1{$2}')
      const pathItem=paths[path]||={}
      for(const method of Object.keys(layer.route.methods)){
        if(method==='head')continue
        const routeKey=`${method.toUpperCase()} ${path}`
        const operation={
          tags:[path.split('/')[1]||'general'],operationId:operationId(method,path),
          parameters:pathParameters(path),
          responses:method==='delete'&&routeKey==='DELETE /policies/{id}/assignments/{assignmentId}'?{200:jsonResponse,202:{description:'Agent cleanup queued',content:{'application/json':{schema:{type:'object',properties:{queued:{type:'boolean'},jobId:{type:'string'},nodeId:{type:'string'}}}}}},default:errorResponse}:method==='delete'&&['DELETE /teams/{id}','DELETE /node-groups/{id}/members/{nodeId}'].includes(routeKey)?{200:jsonResponse,default:errorResponse}:method==='delete'?{204:{description:'No content'},default:errorResponse}:{200:jsonResponse,default:errorResponse}
        }
        const permissions=layer.route.stack.map(entry=>entry.handle.requiredPermission).filter(Boolean)
        if(permissions.length)operation['x-required-permissions']=[...new Set(permissions)]
        if(path.startsWith('/discovery/snmp-library')||path==='/nodes/{id}/snmp-mibs'){
          operation.description=path.endsWith('/preview')?'Validate one or more ASN.1 MIBs and their dependencies without saving.':path.endsWith('/import')?'Atomically import validated MIBs. Replacement requires replace=true; selected readable objects are collected on matching devices at the next SNMP poll.':path==='/nodes/{id}/snmp-mibs'?'Read the last retained SNMP collection, including library matches, unsupported objects and bounded values. No device polling is triggered.':'Manage built-in collection profiles and imported MIB sources. Administrative library changes are audited.'
          if(routeKey==='POST /discovery/snmp-library/import')operation.responses={201:jsonResponse,default:errorResponse}
          if(method==='get'&&!path.endsWith('/download')){
            const fields={search:{type:'string',maxLength:200},page:{type:'integer',minimum:1,default:1},limit:{type:'integer',minimum:1,maximum:100,default:25}}
            if(path==='/discovery/snmp-library/files')fields.status={type:'string',enum:['all','ready','archived','error','pending','bundled']}
            if(path==='/discovery/snmp-library')Object.assign(fields,{source:{type:'string',enum:['all','builtin','imported'],default:'all'},sort:{type:'string',enum:['name','source','updated'],default:'name'},direction:{type:'string',enum:['asc','desc'],default:'asc'}})
            if(path==='/nodes/{id}/snmp-mibs')fields.moduleId={type:'string'}
            operation.parameters.push(...Object.entries(fields).map(([name,schema])=>({name,in:'query',schema})))
          }
        }
        if(routeKey==='POST /policies/{id}/preview')operation.description='Read-only draft compilation with inherited scopes, assignment conflicts, management-access protection and warnings. Creates no version and changes no host.'
        if(routeKey==='POST /policies/{id}/versions'){operation.description='Save an immutable policy graph version. Supply baseVersionId (null for the initial version) to reject stale drafts with 409. Saving does not deploy.';operation.responses={201:jsonResponse,409:errorResponse,default:errorResponse}}
        if(path.startsWith('/internet/connections')||path.startsWith('/internet/peers/')){
          operation.description=path.startsWith('/internet/connections')?'Retained firewall observations outside the completed local-CIDR boundary revision. PTR is reverse-DNS evidence, not a requested website. Default direction is outbound. Counts and exports use identical filters. Pending reclassification retains the previous complete revision.':'Read reverse-DNS evidence/history or enqueue a coalesced refresh. No inventory asset is created; resolve requires editor permission and is rate limited.'
          if(method==='get'&&['/internet/connections','/internet/connections/summary','/internet/connections/export'].includes(path)){
            const fields={q:{type:'string',maxLength:200},nodeId:{type:'string'},groupId:{type:'string'},ip:{type:'string',description:'Canonical peer IP or IPv4/IPv6 CIDR'},hostname:{type:'string',description:'PTR hostname search'},program:{type:'string'},protocol:{type:'string'},port:{type:'integer',minimum:1,maximum:65535},direction:{type:'string',enum:['out','in','unknown','all'],default:'out'},action:{type:'string',enum:['allow','block']},dnsState:{type:'string',enum:['pending','resolved','not-found','error','stale']},from:{type:'string',format:'date-time'},to:{type:'string',format:'date-time'},page:{type:'integer',minimum:1,default:1},limit:{type:'integer',minimum:1,maximum:100,default:25},sort:{type:'string',enum:['time','node','peer','hostname','program','protocol','port','action','direction'],default:'time'},order:{type:'string',enum:['asc','desc'],default:'desc'}}
            operation.parameters.push(...Object.entries(fields).map(([name,schema])=>({name,in:'query',schema})))
          }
          if(path.endsWith('/resolve'))operation.responses={202:{description:'Refresh queued or coalesced',content:{'application/json':{schema:{$ref:'#/components/schemas/InternetDnsEnqueue'}}}},429:errorResponse,default:errorResponse}
        }
        if(path.startsWith('/discovery/dhcp/')){
          operation.description=path.endsWith('/preview')?'Read-only DHCP enrichment preview; requires configured local CIDRs.':path.endsWith('/import')?'Passively import eligible local leases; preserve verified state and report conflicts. Exact replays return the original report.':'Read retained DHCP import evidence and row outcomes.'
          if(routeKey==='POST /discovery/dhcp/import')operation.responses={201:jsonResponse,default:errorResponse}
          if(path==='/discovery/dhcp/imports')operation.parameters.push(...Object.entries({page:{type:'integer',minimum:1,default:1},pageSize:{type:'integer',minimum:1,maximum:100,default:25}}).map(([name,schema])=>({name,in:'query',schema})))
        }
        if (method==='get' && ['/mapping','/mapping/topology','/mapping/arp'].includes(path)) {
          operation.description='Subnet and switch criteria must match the same endpoint. Connections retain peers outside that scope. Switch membership uses observed ARP and current forwarding MACs, including inventory MAC correlation; it is not proof of direct physical attachment. Neighbor links use node, subnet, switch and date criteria; traffic scope and class apply to flow edges only.'
          const fields={nodeId:{type:'string'},subnet:{type:'string',description:'IPv4 or IPv6 CIDR; host bits are allowed.'},switchId:{type:'string',description:'Inventory ID of a switch.'},from:{type:'string',format:'date-time'},to:{type:'string',format:'date-time'}}
          if(path!=='/mapping/arp')Object.assign(fields,{external:{type:'string',enum:['0','1']},trafficClass:{type:'string'}})
          if(path==='/mapping')Object.assign(fields,{page:{type:'integer',minimum:1,default:1},pageSize:{type:'integer',minimum:10,maximum:500,default:100}})
          if(path==='/mapping/topology')Object.assign(fields,{maxNodes:{type:'integer',minimum:20,maximum:500,default:300},maxEdges:{type:'integer',minimum:20,maximum:1000,default:700}})
          if(path==='/mapping/arp')fields.limit={type:'integer',minimum:1,maximum:2000,default:500}
          operation.parameters.push(...Object.entries(fields).map(([name,schema])=>({name,in:'query',required:false,schema})))
        }
        if(wefReceiverRoutes.has(routeKey))operation.security=[{wefHmac:[]}]
        else if(internetEnrollmentRoutes.has(routeKey))operation.security=[]
        else if(internetDeviceRoutes.has(routeKey))operation.security=[{internetDeviceBearer:[]}]
        else if(!publicRoutes.has(routeKey))operation.security=[{[prefix==='/agents'?'mutualTLS':'bearerAuth']:[]}]
        if(['post','put','patch'].includes(method)){
          const schemaName=requestSchemas[routeKey]
          operation.requestBody={required:!!schemaName&&schemaName!=='EmptyRequest',content:{'application/json':{schema:schemaName?{$ref:`#/components/schemas/${schemaName}`}:{type:'object',additionalProperties:true}}}}
        }
        if(['POST /discovery/snmp-library/preview','POST /discovery/snmp-library/import'].includes(routeKey))operation.requestBody.content['multipart/form-data']={schema:{type:'object',required:['files'],properties:{files:{type:'array',minItems:1,maxItems:20,items:{type:'string',format:'binary'},description:'8 MiB/file, 32 MiB/batch. No aggregate library quota.'},replace:{type:'boolean',default:false}}}}
        if(path.startsWith('/discovery/snmp-library/')&&path.endsWith('/download'))operation.responses={200:{description:'Authenticated original MIB source download',content:{'application/octet-stream':{schema:{type:'string',format:'binary'}}}},default:errorResponse}
        if(routeKey==='POST /auth/login')operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/LoginRequest'}}}}
        if(routeKey==='POST /auth/refresh')operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/RefreshRequest'}}}}
        if(responseSchemas[routeKey])operation.responses[200]={description:'JSON response',content:{'application/json':{schema:{$ref:`#/components/schemas/${responseSchemas[routeKey]}`}}}}
        describeAiOperation(operation,method,path)
        describeCloudOperation(operation,method,path)
        describeUserApiKeyOperation(operation,method,path)
        describeProtectionOperation(operation,method,path)
        pathItem[method]=operation
      }
    }
  }
  addRoutes(apiRouter)
  addRoutes(agentRouter,'/agents')
  for(const [prefix,routers] of Object.entries(extraRouters))for(const router of Array.isArray(routers)?routers:[routers])addRoutes(router,prefix?`/${prefix}`:'')
  return {
    openapi:'3.1.0',info:{title:'WinFire Secure API',version:'0.1.0',description:'Control-plane operations use bearer tokens. Enrolled agent operations use client certificates.'},
    servers:[{url:'/api/v1'}],paths,
    components:{securitySchemes:{aiReporterBearer:{type:'http',scheme:'bearer',bearerFormat:'Reporter enrollment credential',description:'Node-scoped REST/stdio reporting credential. Cannot access operator or fleet routes. Remote MCP accepts OAuth with ai:report or a user-owned MCP reporting key.'},bearerAuth:{type:'http',scheme:'bearer',bearerFormat:'JWT or user API key',description:'User API keys (wfuk_) with api:read/api:write use the owner’s current permissions. Key administration requires a user-session JWT. MCP-only keys cannot authenticate these operator routes.'},internetDeviceBearer:{type:'http',scheme:'bearer',bearerFormat:'Internet device token'},mutualTLS:{type:'mutualTLS'},wefHmac:{type:'apiKey',in:'header',name:'X-WinFire-WEF-Token',description:'Node-scoped HMAC token derived from WEF_SHARED_SECRET. The receiver also accepts the token query parameter for Windows Subscription Manager compatibility.'}},schemas:{
      ...cloudSchemas,
      ...userApiKeySchemas,
      ...protectionSchemas,
      ...internetConnectionSchemas,
      ...aiSchemas,
      PolicyGraph:{type:'object',required:['nodes'],properties:{nodes:{type:'array',items:{type:'object',required:['id','type'],properties:{id:{type:'string'},type:{type:'string',enum:['allow','deny','program','portGroup','addressGroup','profile','schedule','mfaGate']},position:{type:'object',properties:{x:{type:'number'},y:{type:'number'}}},data:{type:'object',additionalProperties:true}}}},edges:{type:'array',items:{type:'object',required:['id','source','target'],properties:{id:{type:'string'},source:{type:'string'},target:{type:'string'}}}}}},
      PolicyDraftRequest:{type:'object',required:['graph'],properties:{graph:{$ref:'#/components/schemas/PolicyGraph'}}},
      PolicyVersionRequest:{type:'object',required:['graph'],properties:{graph:{$ref:'#/components/schemas/PolicyGraph'},comment:{type:'string'},baseVersionId:{type:['string','null'],description:'The saved version on which the draft is based; null for a policy with no saved version.'}}},
      PolicyDraftPreview:{type:'object',required:['rules','mfaGates','warnings','conflicts','managementIssue','canSave'],properties:{rules:{type:'array',items:{type:'object',additionalProperties:true}},mfaGates:{type:'array',items:{type:'object',additionalProperties:true}},warnings:{type:'array',items:{type:'string'}},conflicts:{type:'array',items:{type:'object',additionalProperties:true}},managementIssue:{type:['string','null']},canSave:{type:'boolean'}}},
      OnboardingError:{type:'object',required:['code','title','summary','remediation'],properties:{code:{type:'string',enum:['port_closed','auth_rejected','kerberos_spn_double_hop','winrm_listener_disabled','wmi_dcom_blocked','unknown']},title:{type:'string'},summary:{type:'string'},remediation:{type:'string'},transport:{type:['string','null']},operation:{type:['string','null']},observedOpenPort:{type:'boolean'}}},
      Error:{type:'object',required:['error'],properties:{error:{type:'string'},onboardingError:{$ref:'#/components/schemas/OnboardingError'}}},
      LoginRequest:{type:'object',required:['email','password'],properties:{email:{type:'string',format:'email'},password:{type:'string',format:'password'},totp:{type:'string'}}},
      RefreshRequest:{type:'object',required:['refreshToken'],properties:{refreshToken:{type:'string'}}},
      EmptyRequest:{type:'object',additionalProperties:false},
      LogoutRequest:{type:'object',additionalProperties:false,properties:{refreshToken:{type:'string'}}},
      AdLoginRequest:{type:'object',required:['email','password'],properties:{email:{type:'string',format:'email'},password:{type:'string',format:'password',maxLength:512},totp:{type:'string'}}},
      AdAuthenticatorEnrollRequest:{type:'object',required:['email','password'],properties:{email:{type:'string',format:'email'},password:{type:'string',format:'password',maxLength:512}}},
      AuthenticatorConfirmRequest:{type:'object',required:['token','code'],properties:{token:{type:'string',minLength:32,maxLength:128},code:{type:'string',pattern:'^[0-9]{6}$'}}},
      AuthenticatorCodeRequest:{type:'object',required:['code'],properties:{code:{type:'string',pattern:'^[0-9]{6}$'}}},
      InviteAcceptRequest:{type:'object',required:['token','password'],properties:{token:{type:'string',minLength:32},password:{type:'string',format:'password',minLength:12}}},
      VerifyEmailRequest:{type:'object',required:['token'],properties:{token:{type:'string',minLength:32}}},
      MfaPromptTotpRequest:{type:'object',required:['email','password','code'],properties:{email:{type:'string',format:'email'},password:{type:'string',format:'password',maxLength:512},code:{type:'string',pattern:'^[0-9]{6}$'}}},
      MfaEntraCompleteRequest:{type:'object',required:['code','state'],properties:{code:{type:'string',minLength:8,maxLength:4096},state:{type:'string',minLength:16,maxLength:512}}},
      MfaEntraCancelRequest:{type:'object',required:['state','error'],properties:{state:{type:'string',minLength:16,maxLength:512},error:{type:'string',pattern:'^[A-Za-z0-9_]{1,64}$'}}},
      TotpDisableRequest:{type:'object',required:['password','code'],properties:{password:{type:'string',format:'password'},code:{type:'string',pattern:'^[0-9]{6}$'}}},
      InternetEnrollmentRequest:{type:'object',properties:{nodeId:{type:'string'},nodeGroupId:{type:'string'},userId:{type:'string',format:'uuid'},collectionLevel:{type:'string',enum:['host','path'],default:'host'}},additionalProperties:false,description:'Exactly one of nodeId or nodeGroupId is required.'},
      InternetDeviceEnrollRequest:{type:'object',required:['token','browser','extensionVersion','installId'],properties:{token:{type:'string',minLength:32,maxLength:128},browser:{type:'string',enum:['chrome','edge','firefox']},extensionVersion:{type:'string',minLength:1,maxLength:100},installId:{type:'string',minLength:16,maxLength:200},capabilities:{type:'object',additionalProperties:{type:'boolean'}}}},
      InternetEventBatchRequest:{type:'object',required:['events'],properties:{events:{type:'array',minItems:1,maxItems:500,items:{$ref:'#/components/schemas/InternetEvent'}}}},
      InternetEvent:{type:'object',required:['id','url','observedAt'],properties:{id:{type:'string',format:'uuid'},url:{type:'string',format:'uri',maxLength:4096},observedAt:{type:'string',format:'date-time'},action:{type:'string',enum:['observed','allowed','blocked'],default:'observed'},tabSession:{type:'string',maxLength:200}}},
      InternetPolicyStageRequest:{type:'object',required:['rules'],properties:{rules:{type:'array',maxItems:5000,items:{$ref:'#/components/schemas/InternetRule'}},failMode:{type:'string',enum:['open','closed'],default:'open'},comment:{type:'string',maxLength:500}}},
      InternetRule:{type:'object',required:['pattern','action'],properties:{pattern:{type:'string',minLength:1,maxLength:500},match:{type:'string',enum:['hostname','domain','prefix'],default:'hostname'},action:{type:'string',enum:['allow','block']},nodeIds:{type:'array',maxItems:500,items:{type:'string'}},nodeGroupIds:{type:'array',maxItems:500,items:{type:'string'}},resourceTypes:{type:'array',minItems:1,maxItems:20,items:{type:'string',enum:['main_frame','sub_frame','script','image','stylesheet','font','object','xmlhttprequest','other']}}}},
      InternetCleanupRequest:{type:'object',required:['confirmed'],properties:{confirmed:{const:true},before:{type:'string',format:'date-time'},domain:{type:'string',maxLength:253}}},
      AgentEnrollRequest:{type:'object',required:['token','csr'],properties:{token:{type:'string',minLength:32},csr:{type:'string',minLength:100,maxLength:12000}}},
      AgentHeartbeatRequest:{type:'object',required:['version'],properties:{version:{type:'string',minLength:1,maxLength:100},mode:{type:'string',enum:['pull','push'],default:'pull'},platform:{type:'string',maxLength:80},osVersion:{type:'string',maxLength:200},firewallBackend:{type:'string',maxLength:80},capabilities:{type:'array',maxItems:100,items:{type:'string',maxLength:80}}}},
      AgentEventBatchRequest:{type:'object',required:['events'],properties:{events:{type:'array',minItems:1,maxItems:500,items:{$ref:'#/components/schemas/AgentEvent'}}}},
      AgentEvent:{type:'object',required:['recordId','id','timeCreated'],properties:{recordId:{type:'integer',minimum:1},id:{type:'integer',minimum:1},timeCreated:{type:'string',format:'date-time'},fields:{type:'object',additionalProperties:{type:'string'}}}},
      AgentJobResultRequest:{type:'object',required:['leaseToken','success'],properties:{leaseToken:{type:'string',minLength:20},success:{type:'boolean'},diff:{},result:{},error:{type:'string',maxLength:2000}}},
      AgentNetworkRequest:{type:'object',properties:{flows:{type:'array',maxItems:2000,items:{type:'object'}},arp:{type:'array',maxItems:5000,items:{type:'object'}}}},
      SnmpMibImportRequest:{type:'object',required:['files'],properties:{replace:{type:'boolean',default:false},files:{type:'array',minItems:1,maxItems:20,description:'Plain text ASN.1 MIBs, at most 32 MiB combined (the 2 MiB HTTP JSON-body limit still applies; use multipart for larger batches). Include imported dependencies.',items:{type:'object',required:['filename','content'],properties:{filename:{type:'string',minLength:1,maxLength:200},content:{type:'string',minLength:1,maxLength:8388608}}}}}},
      SnmpMibUpdateRequest:{type:'object',additionalProperties:false,properties:{enabled:{type:'boolean'},match:{type:'object',properties:{sysObjectIdPrefixes:{type:'array',maxItems:32,items:{type:'string',maxLength:512}},sysDescrContains:{type:'array',maxItems:32,items:{type:'string',minLength:2,maxLength:120}}}},selectedObjects:{type:'array',maxItems:64,items:{type:'string',maxLength:128},description:'Readable object names from this module. Empty disables its object collection.'}}},
      DhcpImportRequest:{type:'object',required:['source','observedAt','leases'],additionalProperties:false,properties:{source:{type:'string',minLength:1,maxLength:253},observedAt:{type:'string',format:'date-time'},leases:{type:'array',minItems:1,maxItems:2000,items:{$ref:'#/components/schemas/DhcpLease'}}}},
      DhcpLease:{type:'object',required:['ip','mac','leaseExpiry'],additionalProperties:false,properties:{ip:{type:'string',format:'ipv4'},mac:{type:'string',maxLength:100,description:'Ethernet MAC or Windows Ethernet client ID (optional 01 prefix)'},hostname:{type:'string',maxLength:253,default:''},leaseExpiry:{type:'string',format:'date-time'},state:{type:'string',maxLength:40,default:'Active'}}},
      DiscoveryScanRequest:{type:'object',required:['cidrs'],properties:{cidrs:{type:'array',minItems:1,maxItems:32,items:{type:'string',maxLength:64}}}},
      CredentialHealthResponse:{type:'object',required:['notices','windowMinutes','threshold'],properties:{windowMinutes:{type:'integer',minimum:5},threshold:{type:'integer',minimum:2},notices:{type:'array',items:{type:'object',required:['code','credentialId','credentialName','affectedNodeCount'],properties:{code:{type:'string',enum:['credential_may_be_stale']},title:{type:'string'},credentialId:{type:'string'},credentialName:{type:'string'},affectedNodeCount:{type:'integer',minimum:0},affectedNodes:{type:'array',items:{type:'object'}},windowMinutes:{type:'integer'},firstFailureAt:{type:'string',format:'date-time'},lastFailureAt:{type:'string',format:'date-time'},summary:{type:'string'},remediation:{type:'string'}}}}}},
      TriageBulkRequest:{type:'object',required:['nodeIds','action'],properties:{nodeIds:{type:'array',minItems:1,maxItems:200,items:{type:'string'}},action:{type:'string',enum:['assign_and_retry','flagged','excluded','none']},credentialId:{type:'string'},note:{type:['string','null'],maxLength:500}},additionalProperties:false},
      DirectoryOuCredentialHint:{type:'object',required:['ouDn','credentialId'],properties:{ouDn:{type:'string',minLength:3,maxLength:512,description:'Full OU distinguished name inside baseDn. Closest ancestor wins; escaped separators supported.'},credentialId:{type:'string',format:'uuid',description:'Available local or domain vault credential ID.'}},additionalProperties:false},
      DirectorySettingsRequest:{type:'object',required:['url','baseDn','bindCredentialId'],properties:{url:{type:'string',format:'uri',description:'LDAPS server URL without credentials.'},baseDn:{type:'string',minLength:3,maxLength:512},bindCredentialId:{type:'string'},nodeCredentialId:{type:['string','null']},enabled:{type:'boolean',default:false},syncIntervalMinutes:{type:'integer',minimum:5,maximum:1440,default:60},allowLdapFallback:{type:'boolean'},ldapFallbackApproved:{type:'boolean'},ldapFallbackApproval:{type:'string'},ouCredentialHints:{type:'array',maxItems:200,items:{$ref:'#/components/schemas/DirectoryOuCredentialHint'},description:'Omit to preserve mappings; [] clears them. Applied at next AD sync; explicit node/group bindings take priority.'}},additionalProperties:false},
      ServerSettingsRequest:{type:'object',required:['fqdn','publicBaseUrl'],properties:{fqdn:{type:'string',maxLength:253},publicBaseUrl:{type:'string',maxLength:2048},localCidrs:{type:'array',maxItems:256,items:{type:'string'},default:[]}},additionalProperties:false},
      WefSettingsRequest:{type:'object',required:['enabled'],properties:{enabled:{type:'boolean'},sharedSecret:{type:'string',minLength:8,maxLength:512,format:'password'},clearSecret:{type:'boolean'}},additionalProperties:false},
      ClassifierRuleRequest:{type:'object',required:['protocol','service'],properties:{protocol:{type:'string',enum:['ANY','TCP','UDP','SCTP','DCCP','ICMP','ICMPv6','IGMP','IPv6-in-IPv4','GRE','ESP','AH','OSPF']},portStart:{type:['integer','null'],minimum:1,maximum:65535},portEnd:{type:['integer','null'],minimum:1,maximum:65535},service:{type:'string',minLength:1,maxLength:160},description:{type:'string',maxLength:500},priority:{type:'integer',minimum:1,maximum:10000,default:10},enabled:{type:'boolean',default:true}},additionalProperties:false,description:'Provide both port bounds for a port rule or omit both for a protocol rule. ICMP and IGMP rules do not use ports.'},
      ClassifierProcessRuleRequest:{type:'object',required:['executablePattern','service'],properties:{executablePattern:{type:'string',minLength:1,maxLength:512},service:{type:'string',minLength:1,maxLength:160},description:{type:'string',maxLength:500},priority:{type:'integer',minimum:1,maximum:10000,default:10},enabled:{type:'boolean',default:true}},additionalProperties:false,description:'Matches a case-insensitive executable path substring, such as lsass.exe, to identify traffic from a process.'},
      WefConfigureRequest:{type:'object',properties:{refreshSeconds:{type:'integer',minimum:60,maximum:86400,default:900}}},
      EntraSettingsRequest:{type:'object',required:['tenantId','clientId','enabled'],properties:{tenantId:{type:'string',format:'uuid'},clientId:{type:'string',format:'uuid'},clientAuthMethod:{type:'string',enum:['secret','certificate'],default:'secret'},clientSecret:{type:'string',format:'password',minLength:8,maxLength:4096},clientCertificate:{type:'string',maxLength:30000},clientPrivateKey:{type:'string',format:'password',maxLength:30000},enabled:{type:'boolean'}},additionalProperties:false},
      EntraSettingsResponse:{type:'object',required:['source','enabled','tenantId','clientId','clientAuthMethod','clientSecretConfigured','clientCertificateConfigured','ready'],properties:{source:{type:'string',enum:['environment','settings']},enabled:{type:'boolean'},tenantId:{type:'string'},clientId:{type:'string'},clientAuthMethod:{type:'string',enum:['secret','certificate']},clientSecretConfigured:{type:'boolean'},clientCertificateConfigured:{type:'boolean'},clientCertificateThumbprint:{type:['string','null']},publicBaseUrl:{type:'string'},redirectUris:{type:'array',items:{type:'string',format:'uri'}},ready:{type:'boolean'},updatedAt:{type:['string','null'],format:'date-time'}}},
      LogsPullRequest:{type:'object',required:['nodeId'],properties:{nodeId:{type:'string'}}},
      TrainingSessionRequest:{type:'object',required:['nodeId'],properties:{nodeId:{type:'string'},durationHours:{type:'number',minimum:1,maximum:720,default:24}}},
      MfaChallengeRequest:{type:'object',required:['userUpn'],properties:{userUpn:{type:'string',format:'email'},nodeId:{type:'string'},connection:{type:'object',additionalProperties:true}}},
      MfaResolveRequest:{type:'object',required:['approved'],properties:{approved:{type:'boolean'}}},
      LsaBaselineRequest:{type:'object',required:['enabled','reason'],properties:{enabled:{type:'boolean'},nodeId:{type:'string'},reason:{type:'string',minLength:10,maxLength:500},confirmed:{type:'boolean'},confirmation:{type:'string'}}},
      EntraGroupSyncResponse:{type:'object',required:['groupId','count'],properties:{groupId:{type:'string',format:'uuid'},count:{type:'integer',minimum:0},cached:{type:'boolean'},syncedAt:{type:'string',format:'date-time'}}},
      EntraGroupMembersResponse:{type:'object',required:['groupId','members'],properties:{groupId:{type:'string',format:'uuid'},members:{type:'array',items:{$ref:'#/components/schemas/EntraMember'}}}},
      EntraMember:{type:'object',required:['upn','enabled'],properties:{upn:{type:'string'},displayName:{type:'string'},mail:{type:'string'},enabled:{type:'boolean'}}}
    }}
  }
}
