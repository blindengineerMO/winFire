import * as oidc from 'openid-client'

let cached=null,cachedUntil=0
export function entraConfigured(){return !!(process.env.ENTRA_TENANT_ID&&process.env.ENTRA_CLIENT_ID&&process.env.ENTRA_CLIENT_SECRET&&process.env.PUBLIC_BASE_URL)}
export function entraRedirectUri(path='/identity'){
  if(!entraConfigured())throw Object.assign(new Error('Configure ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET, and PUBLIC_BASE_URL'),{status:503})
  if(!['/identity','/mfa/callback'].includes(path))throw new Error('Unsupported Entra redirect path')
  const base=new URL(process.env.PUBLIC_BASE_URL)
  if(base.protocol!=='https:'&&base.hostname!=='localhost')throw Object.assign(new Error('Entra portal requires an HTTPS PUBLIC_BASE_URL'),{status:503})
  return new URL(path,base).href
}
export async function entraConfig(){
  entraRedirectUri()
  if(cached&&Date.now()<cachedUntil)return cached
  const tenant=process.env.ENTRA_TENANT_ID
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenant))throw Object.assign(new Error('ENTRA_TENANT_ID must be a tenant GUID'),{status:503})
  cached=await oidc.discovery(new URL(`https://login.microsoftonline.com/${tenant}/v2.0`),process.env.ENTRA_CLIENT_ID,process.env.ENTRA_CLIENT_SECRET)
  cachedUntil=Date.now()+5*60_000
  return cached
}
export async function startEntraAuthentication({redirectPath='/identity'}={}){
  const config=await entraConfig(),verifier=oidc.randomPKCECodeVerifier(),challenge=await oidc.calculatePKCECodeChallenge(verifier),state=oidc.randomState(),nonce=oidc.randomNonce()
  const url=oidc.buildAuthorizationUrl(config,{redirect_uri:entraRedirectUri(redirectPath),scope:'openid profile email',response_type:'code',code_challenge:challenge,code_challenge_method:'S256',state,nonce,max_age:'0',prompt:'login'})
  return {url:url.href,state,verifier,nonce}
}
export async function completeEntraAuthentication({code,state,verifier,nonce,redirectPath='/identity'}){
  const config=await entraConfig(),callback=new URL(entraRedirectUri(redirectPath))
  callback.searchParams.set('code',code);callback.searchParams.set('state',state)
  const tokens=await oidc.authorizationCodeGrant(config,callback,{pkceCodeVerifier:verifier,expectedState:state,expectedNonce:nonce,maxAge:0,idTokenExpected:true})
  const claims=tokens.claims()
  if(!claims||String(claims.tid).toLowerCase()!==process.env.ENTRA_TENANT_ID.toLowerCase())throw Object.assign(new Error('Entra token tenant did not match the configured tenant'),{status:403})
  if(!Array.isArray(claims.amr)||!claims.amr.includes('mfa'))throw Object.assign(new Error('Entra token did not contain an MFA authentication claim; configure AMR as an optional ID-token claim and require MFA for this app'),{status:403})
  return {email:String(claims.preferred_username||claims.email||claims.upn||'').toLowerCase(),oid:claims.oid||null,tid:claims.tid}
}
