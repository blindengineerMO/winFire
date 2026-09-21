import fs from 'node:fs'
import crypto from 'node:crypto'
import {one,run,now,audit} from './db.js'
import {seal,openSealed} from './security.js'

const guid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const row=()=>one("SELECT * FROM entra_integrations WHERE id='default'")
const pemCertificate=/^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----\s*$/
const pemPrivateKey=/^-----BEGIN (?:PRIVATE KEY|RSA PRIVATE KEY)-----[\s\S]+-----END (?:PRIVATE KEY|RSA PRIVATE KEY)-----\s*$/
const readEnv=(name,fileName)=>{
  if(process.env[name])return process.env[name]
  if(fileName&&process.env[fileName]){
    try{return fs.readFileSync(process.env[fileName],'utf8')
    }catch(error){throw Object.assign(new Error(`${fileName} could not be read`),{status:503,cause:error})}
  }
  return ''
}
function certificateDetails(certificate,privateKey){
  if(typeof certificate!=='string'||!pemCertificate.test(certificate)||certificate.length>30000)throw Object.assign(new Error('Entra client certificate must be a PEM certificate under 30 KB'),{status:400})
  if(typeof privateKey!=='string'||!pemPrivateKey.test(privateKey)||privateKey.length>30000)throw Object.assign(new Error('Entra client private key must be an unencrypted PEM key under 30 KB'),{status:400})
  let x509,key
  try{
    x509=new crypto.X509Certificate(certificate)
    key=crypto.createPrivateKey(privateKey)
  }catch(error){throw Object.assign(new Error('Entra client certificate or private key is invalid'),{status:400,cause:error})}
  if(key.asymmetricKeyType!=='rsa')throw Object.assign(new Error('Entra client certificates must use an RSA private key'),{status:400})
  if(!x509.checkPrivateKey(key))throw Object.assign(new Error('Entra client certificate does not match its private key'),{status:400})
  const nowMs=Date.now(),notBefore=Date.parse(x509.validFrom),notAfter=Date.parse(x509.validTo)
  if(Number.isFinite(notBefore)&&notBefore>nowMs||Number.isFinite(notAfter)&&notAfter<=nowMs)throw Object.assign(new Error('Entra client certificate is not currently valid'),{status:400})
  const der=x509.raw
  return {certificate,privateKey,thumbprint:x509.fingerprint256||crypto.createHash('sha256').update(der).digest('hex').match(/../g).join(':')}
}
function sealedValue(blob){return blob?openSealed(blob):null}
const redirectUris=()=>{
  try{
    const base=new URL(process.env.PUBLIC_BASE_URL)
    if(base.protocol!=='https:'&&base.hostname!=='localhost')return []
    return ['/identity','/mfa/callback'].map(path=>new URL(path,base).href)
  }catch{return []}
}

export function effectiveEntraSettings(){
  const saved=row()
  if(saved){
    const authMethod=saved.client_auth_method==='certificate'?'certificate':'secret'
    return {source:'settings',enabled:!!saved.enabled,tenantId:saved.tenant_id,clientId:saved.client_id,clientAuthMethod:authMethod,clientSecret:sealedValue(saved.client_secret_sealed)?.secret||null,clientCertificate:sealedValue(saved.client_certificate_sealed)?.value||null,clientPrivateKey:sealedValue(saved.client_private_key_sealed)?.value||null,publicBaseUrl:process.env.PUBLIC_BASE_URL||''}
  }
  const certificate=readEnv('ENTRA_CLIENT_CERTIFICATE','ENTRA_CLIENT_CERTIFICATE_FILE'),privateKey=readEnv('ENTRA_CLIENT_PRIVATE_KEY','ENTRA_CLIENT_PRIVATE_KEY_FILE'),hasCertificate=!!(certificate&&privateKey)
  return {source:'environment',enabled:!!(process.env.ENTRA_TENANT_ID&&process.env.ENTRA_CLIENT_ID&&(process.env.ENTRA_CLIENT_SECRET||hasCertificate)),tenantId:process.env.ENTRA_TENANT_ID||'',clientId:process.env.ENTRA_CLIENT_ID||'',clientAuthMethod:hasCertificate?'certificate':'secret',clientSecret:process.env.ENTRA_CLIENT_SECRET||null,clientCertificate:certificate||null,clientPrivateKey:privateKey||null,publicBaseUrl:process.env.PUBLIC_BASE_URL||''}
}

export function publicEntraSettings(){
  const value=effectiveEntraSettings(),uris=redirectUris()
  let certificateConfigured=!!(value.clientCertificate&&value.clientPrivateKey),thumbprint=null
  if(certificateConfigured){try{thumbprint=certificateDetails(value.clientCertificate,value.clientPrivateKey).thumbprint}catch{certificateConfigured=false}}
  const credentialConfigured=value.clientAuthMethod==='certificate'?certificateConfigured:!!value.clientSecret
  return {source:value.source,enabled:value.enabled,tenantId:value.tenantId,clientId:value.clientId,clientAuthMethod:value.clientAuthMethod,clientSecretConfigured:!!value.clientSecret,clientCertificateConfigured:certificateConfigured,clientCertificateThumbprint:thumbprint,publicBaseUrl:value.publicBaseUrl,redirectUris:uris,ready:!!(value.enabled&&guid.test(value.tenantId)&&guid.test(value.clientId)&&credentialConfigured&&uris.length===2),updatedAt:row()?.updated_at||null}
}

export function saveEntraSettings({tenantId,clientId,clientSecret,clientAuthMethod='secret',clientCertificate,clientPrivateKey,enabled},actorId){
  const before=publicEntraSettings(),prior=row()
  if(!['secret','certificate'].includes(clientAuthMethod))throw Object.assign(new Error('Unsupported Entra client authentication method'),{status:400})
  const secret=clientSecret===undefined?prior?.client_secret_sealed||null:(clientSecret?seal({secret:clientSecret}):null)
  const existingCertificate=prior?.client_certificate_sealed?sealedValue(prior.client_certificate_sealed)?.value:null
  const existingPrivateKey=prior?.client_private_key_sealed?sealedValue(prior.client_private_key_sealed)?.value:null
  let certificate=clientCertificate===undefined?existingCertificate:clientCertificate
  let privateKey=clientPrivateKey===undefined?existingPrivateKey:clientPrivateKey
  if((clientCertificate===undefined)!==(clientPrivateKey===undefined))throw Object.assign(new Error('Provide both the Entra client certificate and private key'),{status:400})
  if(certificate||privateKey){const details=certificateDetails(certificate,privateKey);certificate=details.certificate;privateKey=details.privateKey}
  const certificateSealed=certificate&&privateKey?seal({value:certificate}):null
  const privateKeySealed=certificate&&privateKey?seal({value:privateKey}):null
  const configured=clientAuthMethod==='certificate'?!!(certificateSealed&&privateKeySealed):!!secret
  if(enabled&&!configured)throw Object.assign(new Error(clientAuthMethod==='certificate'?'Enter a matching Entra client certificate and private key before enabling Microsoft sign-in':'Enter a client secret before enabling Microsoft sign-in'),{status:400})
  run("INSERT INTO entra_integrations(id,tenant_id,client_id,client_secret_sealed,client_auth_method,client_certificate_sealed,client_private_key_sealed,enabled,updated_at,updated_by) VALUES('default',?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET tenant_id=excluded.tenant_id,client_id=excluded.client_id,client_secret_sealed=excluded.client_secret_sealed,client_auth_method=excluded.client_auth_method,client_certificate_sealed=excluded.client_certificate_sealed,client_private_key_sealed=excluded.client_private_key_sealed,enabled=excluded.enabled,updated_at=excluded.updated_at,updated_by=excluded.updated_by",tenantId.toLowerCase(),clientId.toLowerCase(),secret,clientAuthMethod,certificateSealed,privateKeySealed,Number(enabled),now(),actorId)
  const after=publicEntraSettings()
  audit(actorId,'entra.settings.update','entra-integration','default',{source:before.source,enabled:before.enabled,tenantId:before.tenantId,clientId:before.clientId,clientAuthMethod:before.clientAuthMethod,clientSecretConfigured:before.clientSecretConfigured,clientCertificateConfigured:before.clientCertificateConfigured},{source:after.source,enabled:after.enabled,tenantId:after.tenantId,clientId:after.clientId,clientAuthMethod:after.clientAuthMethod,clientSecretConfigured:after.clientSecretConfigured,clientCertificateConfigured:after.clientCertificateConfigured,secretRotated:clientSecret!==undefined,certificateRotated:clientCertificate!==undefined})
  return after
}

export function entraCertificateDetails(){
  const settings=effectiveEntraSettings()
  if(settings.clientAuthMethod!=='certificate'||!settings.clientCertificate||!settings.clientPrivateKey)return null
  return certificateDetails(settings.clientCertificate,settings.clientPrivateKey)
}
