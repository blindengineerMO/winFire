import {one,parse} from './db.js'
import {entraGroupAllowsOperator} from './entraGraph.js'

// Directory sync stores AD memberOf values as either full DNs or provider
// identifiers. Match case-insensitively and keep the exact value configured by
// an administrator so a future Graph resolver can use the same field.
export function segmentAllowsOperator(segment,email){
  const normalized=String(email||'').trim().toLowerCase()
  if(!normalized)return false
  const allowed=parse(segment?.allowed_upns)||[]
  if(allowed.some(value=>String(value).trim().toLowerCase()===normalized))return true
  const group=String(segment?.entra_group_id||'').trim().toLowerCase()
  if(!group)return false
  const directory=one('SELECT member_of_json FROM directory_users WHERE lower(upn)=? OR lower(email)=? LIMIT 1',normalized,normalized)
  const memberships=parse(directory?.member_of_json)||[]
  return memberships.some(value=>String(value).trim().toLowerCase()===group)
}

export async function segmentAllowsOperatorAsync(segment,email,options={}){
  if(segmentAllowsOperator(segment,email))return true
  const group=String(segment?.entra_group_id||'').trim()
  if(!group)return false
  return entraGroupAllowsOperator(group,email,options)
}
