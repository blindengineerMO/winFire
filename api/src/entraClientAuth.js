import {createPrivateKey,createSign,X509Certificate,randomUUID,constants} from 'node:crypto'

function base64url(value){return Buffer.from(value).toString('base64url')}

export function clientAssertion({tenantId,clientId,clientCertificate,clientPrivateKey},audience){
  if(!clientCertificate||!clientPrivateKey)throw Object.assign(new Error('Entra client certificate credentials are incomplete'),{status:409})
  let certificate,key
  try{
    certificate=new X509Certificate(clientCertificate)
    key=createPrivateKey(clientPrivateKey)
  }catch(error){throw Object.assign(new Error('Entra client certificate credentials are invalid'),{status:409,cause:error})}
  if(key.asymmetricKeyType!=='rsa'||!certificate.checkPrivateKey(key))throw Object.assign(new Error('Entra client certificate does not match its RSA private key'),{status:409})
  const thumbprint=base64url(Buffer.from(certificate.fingerprint256.replaceAll(':',''),'hex'))
  const header=base64url(JSON.stringify({alg:'PS256',typ:'JWT','x5t#S256':thumbprint}))
  const issued=Math.floor(Date.now()/1000)
  const payload=base64url(JSON.stringify({aud:audience,iss:clientId,sub:clientId,jti:randomUUID(),nbf:issued-30,iat:issued,exp:issued+600}))
  const signingInput=`${header}.${payload}`
  const signature=createSign('sha256').update(signingInput).sign({key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:constants.RSA_PSS_SALTLEN_DIGEST}).toString('base64url')
  return `${signingInput}.${signature}`
}

export function clientCredentialsForm(settings){
  const form={grant_type:'client_credentials',client_id:settings.clientId,scope:'https://graph.microsoft.com/.default'}
  if(settings.clientAuthMethod==='certificate'){
    const endpoint=`https://login.microsoftonline.com/${encodeURIComponent(settings.tenantId)}/oauth2/v2.0/token`
    form.client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    form.client_assertion=clientAssertion(settings,endpoint)
  }else if(settings.clientSecret){
    form.client_secret=settings.clientSecret
  }else throw Object.assign(new Error('Configure an Entra client secret or certificate before syncing an Entra group'),{status:409})
  return form
}
