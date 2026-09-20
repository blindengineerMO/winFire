const publicRoutes=new Set([
  'GET /health','GET /openapi.json','POST /auth/login','POST /auth/refresh',
  'POST /invites/accept','POST /auth/verify-email','GET /avatars/{id}',
  'POST /agents/enroll'
])

const operationId=(method,path)=>method+path.split('/').filter(Boolean).map(part=>part.startsWith('{')?`By${part.slice(1,-1)[0].toUpperCase()}${part.slice(2,-1)}`:part.replace(/(^|-)(\w)/g,(_match,_dash,letter)=>letter.toUpperCase())).join('')
const pathParameters=path=>[...path.matchAll(/\{([^}]+)\}/g)].map(match=>({name:match[1],in:'path',required:true,schema:{type:'string'}}))
const jsonResponse={description:'JSON response',content:{'application/json':{schema:{}}}}
const errorResponse={description:'Error response',content:{'application/json':{schema:{$ref:'#/components/schemas/Error'}}}}

export function buildOpenApi(apiRouter,agentRouter){
  const paths={}
  const addRoutes=(router,prefix='')=>{
    for(const layer of router.stack||[]){
      if(!layer.route||typeof layer.route.path!=='string')continue
      const path=(prefix+layer.route.path).replace(/:([A-Za-z]\w*)/g,'{$1}')
      const pathItem=paths[path]||={}
      for(const method of Object.keys(layer.route.methods)){
        if(method==='head')continue
        const routeKey=`${method.toUpperCase()} ${path}`
        const operation={
          tags:[path.split('/')[1]||'general'],operationId:operationId(method,path),
          parameters:pathParameters(path),
          responses:method==='delete'&&routeKey==='DELETE /policies/{id}/assignments/{assignmentId}'?{200:jsonResponse,202:{description:'Agent cleanup queued',content:{'application/json':{schema:{type:'object',properties:{queued:{type:'boolean'},jobId:{type:'string'},nodeId:{type:'string'}}}}}},default:errorResponse}:method==='delete'&&['DELETE /teams/{id}','DELETE /node-groups/{id}/members/{nodeId}'].includes(routeKey)?{200:jsonResponse,default:errorResponse}:method==='delete'?{204:{description:'No content'},default:errorResponse}:{200:jsonResponse,default:errorResponse}
        }
        if(!publicRoutes.has(routeKey))operation.security=[{[prefix==='/agents'?'mutualTLS':'bearerAuth']:[]}]
        if(['post','put','patch'].includes(method))operation.requestBody={content:{'application/json':{schema:{type:'object',additionalProperties:true}}}}
        if(routeKey==='POST /auth/login')operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/LoginRequest'}}}}
        if(routeKey==='POST /auth/refresh')operation.requestBody={required:true,content:{'application/json':{schema:{$ref:'#/components/schemas/RefreshRequest'}}}}
        pathItem[method]=operation
      }
    }
  }
  addRoutes(apiRouter)
  addRoutes(agentRouter,'/agents')
  return {
    openapi:'3.1.0',info:{title:'WinFire Secure API',version:'0.1.0',description:'Control-plane operations use bearer tokens. Enrolled agent operations use client certificates.'},
    servers:[{url:'/api/v1'}],paths,
    components:{securitySchemes:{bearerAuth:{type:'http',scheme:'bearer',bearerFormat:'JWT'},mutualTLS:{type:'mutualTLS'}},schemas:{
      Error:{type:'object',required:['error'],properties:{error:{type:'string'}}},
      LoginRequest:{type:'object',required:['email','password'],properties:{email:{type:'string',format:'email'},password:{type:'string',format:'password'},totp:{type:'string'}}},
      RefreshRequest:{type:'object',required:['refreshToken'],properties:{refreshToken:{type:'string'}}}
    }}
  }
}
