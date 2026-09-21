import * as oidc from 'openid-client'
import {createHash,createPrivateKey,webcrypto} from 'node:crypto'
import {effectiveEntraSettings,entraCertificateDetails} from './entraSettings.js'

let cached=null,cachedUntil=0,cachedKey=null
export function entraConfigured(){
  const settings=effectiveEntraSettings()
  const credential=settings.clientAuthMethod==='certificate'?!!(settings.clientCertificate&&settings.clientPrivateKey):!!settings.clientSecret
  try{const base=new URL(settings.publicBaseUrl);return !!(settings.enabled&&settings.tenantId&&settings.clientId&&credential&&(base.protocol==='https:'||base.hostname==='localhost'))}catch{return false}
}
export function entraRedirectUri(path='/identity'){
  if(!entraConfigured())throw Object.assign(new Error('Configure and enable the Entra integration and PUBLIC_BASE_URL'),{status:503})
  if(!['/identity','/mfa/callback'].includes(path))throw new Error('Unsupported Entra redirect path')
  const base=new URL(effectiveEntraSettings().publicBaseUrl)
  if(base.protocol!=='https:'&&base.hostname!=='localhost')throw Object.assign(new Error('Entra portal requires an HTTPS PUBLIC_BASE_URL'),{status:503})
  return new URL(path,base).href
}
export async function entraConfig(){
  entraRedirectUri()
  const settings=effectiveEntraSettings(),tenant=settings.tenantId
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenant))throw Object.assign(new Error('ENTRA_TENANT_ID must be a tenant GUID'),{status:503})
  const certificate=settings.clientAuthMethod==='certificate'?entraCertificateDetails():null
  if(settings.clientAuthMethod==='certificate'&&!certificate)throw Object.assign(new Error('Configure a valid Entra client certificate and private key'),{status:503})
  const key=createHash('sha256').update(JSON.stringify([tenant,settings.clientId,settings.clientAuthMethod,settings.clientSecret,certificate?.thumbprint])).digest('hex')
  if(cached&&cachedKey===key&&Date.now()<cachedUntil)return cached
  let metadata=settings.clientAuthMethod==='secret'?settings.clientSecret:undefined
  let authentication
  if(certificate){
    const thumbprint=Buffer.from(certificate.thumbprint.replaceAll(':',''),'hex').toString('base64url')
    const keyObject=createPrivateKey(certificate.privateKey)
    const key=await webcrypto.subtle.importKey('pkcs8',keyObject.export({format:'der',type:'pkcs8'}),{name:'RSA-PSS',hash:'SHA-256'},false,['sign'])
    authentication=oidc.PrivateKeyJwt(key,{[oidc.modifyAssertion](header){
      header['x5t#S256']=thumbprint
    }})
  }
  cached=await oidc.discovery(new URL(`https://login.microsoftonline.com/${tenant}/v2.0`),settings.clientId,metadata,authentication)
  cachedKey=key
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
  if(!claims||String(claims.tid).toLowerCase()!==effectiveEntraSettings().tenantId.toLowerCase())throw Object.assign(new Error('Entra token tenant did not match the configured tenant'),{status:403})
  if(!Array.isArray(claims.amr)||!claims.amr.includes('mfa'))throw Object.assign(new Error('Entra token did not contain an MFA authentication claim; configure AMR as an optional ID-token claim and require MFA for this app'),{status:403})
  return {email:String(claims.preferred_username||claims.email||claims.upn||'').toLowerCase(),oid:claims.oid||null,tid:claims.tid}
}
