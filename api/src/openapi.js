const publicRoutes=new Set([
  'GET /health','GET /openapi.json','POST /auth/login','POST /auth/refresh',
  'POST /invites/accept','POST /auth/verify-email','POST /auth/ad/login',
  'POST /auth/ad-totp/enroll','POST /auth/ad-totp/confirm','GET /avatars/{id}',
  'GET /portal-branding','GET /portal-branding/image',
  'GET /settings/training','GET /settings/logs-display',
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
  'POST /agents/{id}/jobs/{jobId}/result':'AgentJobResultRequest',
  'POST /nodes/{id}/wef/configure':'WefConfigureRequest',
  'PATCH /settings/entra':'EntraSettingsRequest',
  'POST /logs/pull':'LogsPullRequest',
  'POST /learning-sessions':'TrainingSessionRequest',
  'POST /segments/{id}/challenges':'MfaChallengeRequest',
  'POST /segments/{id}/challenges/{challengeId}/resolve':'MfaResolveRequest',
  'POST /segments/{id}/lsa-baselines':'LsaBaselineRequest',
  'POST /logon-rights/baseline':'LogsPullRequest'
}

const responseSchemas={
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
      const path=(prefix+layer.route.path).replace(/(^|\/)\:([A-Za-z]\w*)(?=\/|$)/g,'$1{$2}')
      const pathItem=paths[path]||={}
      for(const method of Object.keys(layer.route.methods)){
        if(method==='head')continue
        const routeKey=`${method.toUpperCase()} ${path}`
        const operation={
          tags:[path.split('/')[1]||'general'],operationId:operationId(method,path),
          parameters:pathParameters(path),
          responses:method==='delete'&&routeKey==='DELETE /policies/{id}/assignments/{assignmentId}'?{200:jsonResponse,202:{description:'Agent cleanup queued',content:{'application/json':{schema:{type:'object',properties:{queued:{type:'boolean'},jobId:{type:'string'},nodeId:{type:'string'}}}}}},default:errorResponse}:method==='delete'&&['DELETE /teams/{id}','DELETE /node-groups/{id}/members/{nodeId}'].includes(routeKey)?{200:jsonResponse,default:errorResponse}:method==='delete'?{204:{description:'No content'},default:errorResponse}:{200:jsonResponse,default:errorResponse}
        }
        if(wefReceiverRoutes.has(routeKey))operation.security=[{wefHmac:[]}]
        else if(internetEnrollmentRoutes.has(routeKey))operation.security=[]
        else if(internetDeviceRoutes.has(routeKey))operation.security=[{internetDeviceBearer:[]}]
        else if(!publicRoutes.has(routeKey))operation.security=[{[prefix==='/agents'?'mutualTLS':'bearerAuth']:[]}]
        if(['post','put','patch'].includes(method)){
          const schemaName=requestSchemas[routeKey]
          operation.requestBody={required:!!schemaName&&schemaName!=='EmptyRequest',content:{'application/json':{schema:schemaName?{$ref:`#/components/schemas/${schemaName}`}:{type:'object',additionalProperties:true}}}}
        }
        if(routeKey==='POST /auth/login')operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/LoginRequest'}}}}
        if(routeKey==='POST /auth/refresh')operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/RefreshRequest'}}}}
        if(responseSchemas[routeKey])operation.responses[200]={description:'JSON response',content:{'application/json':{schema:{$ref:`#/components/schemas/${responseSchemas[routeKey]}`}}}}
        pathItem[method]=operation
      }
    }
  }
  addRoutes(apiRouter)
  addRoutes(agentRouter,'/agents')
  for(const [prefix,router] of Object.entries(extraRouters))addRoutes(router,`/${prefix}`)
  return {
    openapi:'3.1.0',info:{title:'WinFire Secure API',version:'0.1.0',description:'Control-plane operations use bearer tokens. Enrolled agent operations use client certificates.'},
    servers:[{url:'/api/v1'}],paths,
    components:{securitySchemes:{bearerAuth:{type:'http',scheme:'bearer',bearerFormat:'JWT'},internetDeviceBearer:{type:'http',scheme:'bearer',bearerFormat:'Internet device token'},mutualTLS:{type:'mutualTLS'},wefHmac:{type:'apiKey',in:'header',name:'X-WinFire-WEF-Token',description:'Node-scoped HMAC token derived from WEF_SHARED_SECRET. The receiver also accepts the token query parameter for Windows Subscription Manager compatibility.'}},schemas:{
      Error:{type:'object',required:['error'],properties:{error:{type:'string'}}},
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
      AgentHeartbeatRequest:{type:'object',required:['version'],properties:{version:{type:'string',minLength:1,maxLength:100},mode:{type:'string',enum:['pull','push'],default:'pull'}}},
      AgentEventBatchRequest:{type:'object',required:['events'],properties:{events:{type:'array',minItems:1,maxItems:500,items:{$ref:'#/components/schemas/AgentEvent'}}}},
      AgentEvent:{type:'object',required:['recordId','id','timeCreated'],properties:{recordId:{type:'integer',minimum:1},id:{type:'integer',minimum:1},timeCreated:{type:'string',format:'date-time'},fields:{type:'object',additionalProperties:{type:'string'}}}},
      AgentJobResultRequest:{type:'object',required:['leaseToken','success'],properties:{leaseToken:{type:'string',minLength:20},success:{type:'boolean'},diff:{},result:{},error:{type:'string',maxLength:2000}}},
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
