import {one,run,now,audit} from './db.js'
import {seal,openSealed} from './security.js'

const guid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const row=()=>one("SELECT * FROM entra_integrations WHERE id='default'")
const redirectUris=()=>{
  try{
    const base=new URL(process.env.PUBLIC_BASE_URL)
    if(base.protocol!=='https:'&&base.hostname!=='localhost')return []
    return ['/identity','/mfa/callback'].map(path=>new URL(path,base).href)
  }catch{return []}
}

export function effectiveEntraSettings(){
  const saved=row()
  if(saved)return {source:'settings',enabled:!!saved.enabled,tenantId:saved.tenant_id,clientId:saved.client_id,clientSecret:saved.client_secret_sealed?openSealed(saved.client_secret_sealed).secret:null,publicBaseUrl:process.env.PUBLIC_BASE_URL||''}
  return {source:'environment',enabled:!!(process.env.ENTRA_TENANT_ID&&process.env.ENTRA_CLIENT_ID&&process.env.ENTRA_CLIENT_SECRET),tenantId:process.env.ENTRA_TENANT_ID||'',clientId:process.env.ENTRA_CLIENT_ID||'',clientSecret:process.env.ENTRA_CLIENT_SECRET||null,publicBaseUrl:process.env.PUBLIC_BASE_URL||''}
}

export function publicEntraSettings(){
  const value=effectiveEntraSettings(),uris=redirectUris()
  return {source:value.source,enabled:value.enabled,tenantId:value.tenantId,clientId:value.clientId,clientSecretConfigured:!!value.clientSecret,publicBaseUrl:value.publicBaseUrl,redirectUris:uris,ready:!!(value.enabled&&guid.test(value.tenantId)&&guid.test(value.clientId)&&value.clientSecret&&uris.length===2),updatedAt:row()?.updated_at||null}
}

export function saveEntraSettings({tenantId,clientId,clientSecret,enabled},actorId){
  const before=publicEntraSettings(),prior=row()
  const secret=clientSecret===undefined?prior?.client_secret_sealed||null:seal({secret:clientSecret})
  if(enabled&&!secret)throw Object.assign(new Error('Enter a client secret before enabling Microsoft sign-in'),{status:400})
  run("INSERT INTO entra_integrations(id,tenant_id,client_id,client_secret_sealed,enabled,updated_at,updated_by) VALUES('default',?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET tenant_id=excluded.tenant_id,client_id=excluded.client_id,client_secret_sealed=excluded.client_secret_sealed,enabled=excluded.enabled,updated_at=excluded.updated_at,updated_by=excluded.updated_by",tenantId.toLowerCase(),clientId.toLowerCase(),secret,Number(enabled),now(),actorId)
  const after=publicEntraSettings()
  audit(actorId,'entra.settings.update','entra-integration','default',{source:before.source,enabled:before.enabled,tenantId:before.tenantId,clientId:before.clientId,clientSecretConfigured:before.clientSecretConfigured},{source:after.source,enabled:after.enabled,tenantId:after.tenantId,clientId:after.clientId,clientSecretConfigured:after.clientSecretConfigured,secretRotated:clientSecret!==undefined})
  return after
}
