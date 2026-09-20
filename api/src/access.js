import {one} from './db.js'

export function resourceRecord(type,id) {
  const table={policy:'policies',node_group:'node_groups',credential:'credentials'}[type]
  return table?one(`SELECT * FROM ${table} WHERE id=?`,id):null
}

export function canWriteResource(user,type,record) {
  if(!user||!record)return false
  if(type==='node_group'&&record.id==='winfire-global-all-nodes')return ['owner','admin'].includes(user.role)
  if(['owner','admin'].includes(user.role))return true
  if(user.role!=='editor')return false
  if(record.owner_user_id===user.id)return true
  return !!one("SELECT 1 FROM resource_grants WHERE resource_type=? AND resource_id=? AND grantee_user_id=? AND permission='write'",type,record.id,user.id)
}

export function canReadResource(user,type,record) {
  if(!user||!record)return false
  if(type==='node_group'&&record.id==='winfire-global-all-nodes')return true
  if(type==='policy'&&record.origin==='learned')return true
  if(user.role==='auditor'&&type!=='credential'||canWriteResource(user,type,record))return true
  return !!one('SELECT 1 FROM resource_grants WHERE resource_type=? AND resource_id=? AND grantee_user_id=?',type,record.id,user.id)
}
