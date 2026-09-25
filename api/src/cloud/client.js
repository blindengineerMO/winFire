import {X509Certificate} from 'node:crypto'
import {setTimeout as delay} from 'node:timers/promises'
import {clientAssertion} from '../entraClientAuth.js'

const ARM='https://management.azure.com',audience=ARM+'/.default'
export class AzureError extends Error{
  constructor(code,message,status=502){super(message);this.code=code;this.status=status}
}
export function validateCertificate(settings){
  if(settings.authMethod!=='certificate')return
  try{
    const cert=new X509Certificate(settings.clientCertificatePem),time=Date.now()
    if(time<Date.parse(cert.validFrom)||time>=Date.parse(cert.validTo))throw new Error('expired')
    clientAssertion({clientId:settings.clientId,clientCertificate:settings.clientCertificatePem,clientPrivateKey:settings.clientPrivateKeyPem},'https://login.microsoftonline.com/'+settings.tenantId+'/oauth2/v2.0/token')
  }catch{throw new AzureError('certificate_invalid','The Azure certificate is expired, not yet valid, or does not match its RSA private key',400)}
}
async function boundedJson(response){
  const reader=response.body?.getReader();if(!reader)throw new AzureError('invalid_response','Azure returned an empty response')
  let length=0;const chunks=[]
  try{while(true){const {value,done}=await reader.read();if(done)break;length+=value.length;if(length>16*1024*1024)throw new AzureError('response_limit','Azure response exceeded 16 MiB');chunks.push(Buffer.from(value))}}
  finally{await reader.cancel().catch(()=>{})}
  try{return JSON.parse(Buffer.concat(chunks).toString())}catch{throw new AzureError('invalid_response','Azure returned invalid JSON')}
}
export function azureClient(settings,{fetchImpl=fetch,sleep=delay,signal,budget=5000,onRequest=()=>{},tokenScope=audience}={}){
  if(![audience,'https://storage.azure.com/.default'].includes(tokenScope))throw new AzureError('endpoint_rejected','Unsupported Azure token audience',400)
  validateCertificate(settings)
  let token=null,identity=null,requests=0
  const abort=()=>{if(signal?.aborted)throw new AzureError('cancelled','Discovery cancelled',409)}
  async function accessToken(force=false){
    abort();if(!force&&token?.expires>Date.now()+60000)return token.value
    if(['managed-identity','workload-identity'].includes(settings.authMethod)){
      if(!identity){
        const {ManagedIdentityCredential,WorkloadIdentityCredential}=await import('@azure/identity')
        if(settings.authMethod==='managed-identity'){
          if(process.env.AZURE_DISCOVERY_MANAGED_IDENTITY!=='true')throw new AzureError('identity_unavailable','Enable AZURE_DISCOVERY_MANAGED_IDENTITY on an Azure/Arc host before selecting its identity',409)
          identity=new ManagedIdentityCredential(settings.clientId?{clientId:settings.clientId}:{})
        }else{
          if(!process.env.AZURE_FEDERATED_TOKEN_FILE)throw new AzureError('identity_unavailable','Configure AZURE_FEDERATED_TOKEN_FILE on the API server',409)
          identity=new WorkloadIdentityCredential({tenantId:settings.tenantId,clientId:settings.clientId,tokenFilePath:process.env.AZURE_FEDERATED_TOKEN_FILE,authorityHost:'https://login.microsoftonline.com'})
        }
      }
      try{const value=await identity.getToken(tokenScope,{abortSignal:signal?AbortSignal.any([signal,AbortSignal.timeout(30000)]):AbortSignal.timeout(30000),forceRefresh:force});token={value:value.token,expires:value.expiresOnTimestamp}}
      catch{throw new AzureError('identity_unavailable','The selected Azure identity could not authenticate. Check identity assignment, federation and host configuration',409)}
    }else{
      const endpoint=`https://login.microsoftonline.com/${settings.tenantId}/oauth2/v2.0/token`
      const form={grant_type:'client_credentials',client_id:settings.clientId,scope:tokenScope}
      if(settings.authMethod==='secret')form.client_secret=settings.clientSecret
      else{form.client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer';form.client_assertion=clientAssertion({clientId:settings.clientId,clientCertificate:settings.clientCertificatePem,clientPrivateKey:settings.clientPrivateKeyPem},endpoint)}
      const response=await fetchImpl(endpoint,{method:'POST',redirect:'error',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(form),signal:signal?AbortSignal.any([signal,AbortSignal.timeout(30000)]):AbortSignal.timeout(30000)})
      if(!response.ok){await response.body?.cancel();throw new AzureError('authentication_failed','Azure authentication failed. Check tenant, application ID and credential expiry',409)}
      const value=await boundedJson(response)
      if(typeof value.access_token!=='string')throw new AzureError('authentication_failed','Azure returned no access token',409)
      token={value:value.access_token,expires:Date.now()+Math.min(Number(value.expires_in)||300,86400)*1000}
    }
    // Azure access tokens are issued by the authenticated authority. This check prevents a
    // host-assigned identity from silently selecting another tenant than the configured one.
    try{const claims=JSON.parse(Buffer.from(token.value.split('.')[1],'base64url'));if(claims.tid&&claims.tid.toLowerCase()!==settings.tenantId.toLowerCase()){token=null;throw new AzureError('tenant_mismatch','The selected identity belongs to a different Azure tenant',409)}}catch(error){if(error instanceof AzureError)throw error}
    return token.value
  }
  async function request(path,{body,method=body?'POST':'GET'}={}){
    const url=new URL(path,ARM)
    if(url.origin!==ARM||url.username||url.password||url.hash)throw new AzureError('endpoint_rejected','Azure returned an unsupported endpoint',400)
    // The only allowed POST is Resource Graph's read query. No caller can issue resource mutations.
    if(method!=='GET'&&!(method==='POST'&&url.pathname.toLowerCase()==='/providers/microsoft.resourcegraph/resources'))throw new AzureError('method_rejected','Azure discovery permits read operations only',400)
    let refreshed=false
    for(let attempt=0;attempt<5;attempt++){
      abort();if(++requests>budget)throw new AzureError('request_budget','Azure discovery request budget exhausted')
      onRequest(requests)
      const authorization=await accessToken()
      let response
      try{response=await fetchImpl(url,{method,redirect:'error',headers:{Authorization:`Bearer ${authorization}`,...(body?{'content-type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,signal:signal?AbortSignal.any([signal,AbortSignal.timeout(30000)]):AbortSignal.timeout(30000)})}
      catch{abort();throw new AzureError('network_error','Azure request failed or timed out. Check proxy, TLS trust and outbound connectivity')}
      if(response.status===401&&!refreshed){await response.body?.cancel();refreshed=true;await accessToken(true);continue}
      if([429,503].includes(response.status)&&attempt<4){
        const value=response.headers.get('retry-after'),seconds=Number(value),wait=value?(Number.isFinite(seconds)?seconds*1000:Date.parse(value)-Date.now()):500*2**attempt
        await response.body?.cancel();await sleep(Math.min(30000,Math.max(250,wait||500)),undefined,{signal});continue
      }
      if(!response.ok){await response.body?.cancel();throw new AzureError(response.status===403?'permission_denied':response.status===404?'resource_unavailable':response.status===401?'authentication_failed':'azure_http_'+response.status,response.status===403?'Reader access is missing for this Azure scope':`Azure discovery read failed (HTTP ${response.status})`)}
      return boundedJson(response)
    }
    throw new AzureError('retry_exhausted','Azure retry budget exhausted')
  }
  return {request,accessToken,get requests(){return requests}}
}
