import {db,all,one,run,id,now} from './db.js'
import {remote} from './connector.js'

const sidPattern=/^S-1-\d+-\d+(?:-\d+)+$/i
const text=value=>String(value??'').trim()
const wellKnownSidNames={
  'S-1-1-0':'Everyone','S-1-5-2':'NT AUTHORITY\\NETWORK','S-1-5-4':'NT AUTHORITY\\INTERACTIVE',
  'S-1-5-6':'NT AUTHORITY\\SERVICE','S-1-5-7':'NT AUTHORITY\\ANONYMOUS LOGON',
  'S-1-5-9':'Enterprise Domain Controllers','S-1-5-11':'NT AUTHORITY\\Authenticated Users',
  'S-1-5-18':'NT AUTHORITY\\SYSTEM','S-1-5-19':'NT AUTHORITY\\LOCAL SERVICE',
  'S-1-5-20':'NT AUTHORITY\\NETWORK SERVICE'
}

export function storeAccountInventory(node,inventory){
  if(!inventory||!Array.isArray(inventory.accounts)||!Array.isArray(inventory.resolutions))throw new Error('Invalid account inventory response')
  const seen=now(),accounts=inventory.domainController?[]:inventory.accounts
  return db.transaction(()=>{
    run('UPDATE local_accounts SET missing=1 WHERE node_id=?',node.id)
    let count=0
    for(const account of accounts){
      const sid=text(account.sid),username=text(account.username)
      if(!sidPattern.test(sid)||!username||username.length>256)continue
      const qualifiedName=`${text(inventory.computerName)||node.hostname}\\${username}`
      run(`INSERT INTO local_accounts(id,node_id,sid,username,qualified_name,full_name,description,enabled,locked,password_required,missing,seen_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,0,?) ON CONFLICT(node_id,sid) DO UPDATE SET username=excluded.username,qualified_name=excluded.qualified_name,full_name=excluded.full_name,description=excluded.description,enabled=excluded.enabled,locked=excluded.locked,password_required=excluded.password_required,missing=0,seen_at=excluded.seen_at`,
      id(),node.id,sid,username,qualifiedName,text(account.fullName).slice(0,512),text(account.description).slice(0,2048),account.enabled?1:0,account.locked?1:0,account.passwordRequired?1:0,seen)
      count++
    }
    for(const resolution of inventory.resolutions){
      const sid=text(resolution.sid),qualifiedName=text(resolution.qualifiedName)
      if(!sidPattern.test(sid)||!qualifiedName||qualifiedName.length>512)continue
      run('INSERT INTO sid_resolutions(node_id,sid,qualified_name,seen_at) VALUES(?,?,?,?) ON CONFLICT(node_id,sid) DO UPDATE SET qualified_name=excluded.qualified_name,seen_at=excluded.seen_at',node.id,sid,qualifiedName,seen)
    }
    run('INSERT INTO account_inventory_state(node_id,collected_at) VALUES(?,?) ON CONFLICT(node_id) DO UPDATE SET collected_at=excluded.collected_at',node.id,seen)
    return {count,domainController:!!inventory.domainController,collectedAt:seen}
  })()
}

export async function collectAccountInventory(node,sids=[]){
  const valid=[...new Set(sids.filter(sid=>sidPattern.test(String(sid))))].slice(0,500)
  const inventory=await remote(node,'account_inventory',{sids:valid})
  return storeAccountInventory(node,inventory)
}

export function accountName(nodeId,sid){
  const ad=one('SELECT COALESCE(sam_account_name,upn,display_name) account_name FROM directory_users WHERE sid=?',sid)
  if(ad)return {accountName:ad.account_name,accountSource:'ad'}
  const local=one('SELECT qualified_name account_name FROM local_accounts WHERE node_id=? AND sid=? AND missing=0',nodeId,sid)
  if(local)return {accountName:local.account_name,accountSource:'local'}
  const translated=one('SELECT qualified_name account_name FROM sid_resolutions WHERE node_id=? AND sid=?',nodeId,sid)
  if(translated)return {accountName:translated.account_name,accountSource:'windows'}
  return wellKnownSidNames[sid]?{accountName:wellKnownSidNames[sid],accountSource:'windows'}:{accountName:null,accountSource:null}
}
