import fs from 'node:fs'
import path from 'node:path'
import {createHash} from 'node:crypto'
import Database from 'better-sqlite3'

const hash=async file=>{const digest=createHash('sha256');for await(const chunk of fs.createReadStream(file))digest.update(chunk);return digest.digest('hex')}
const nested=(parent,child)=>{const relative=path.relative(parent,child);return !relative||!relative.startsWith('..'+path.sep)&&relative!=='..'&&!path.isAbsolute(relative)}
function safeFile(root,name){if(typeof name!=='string'||!name||path.isAbsolute(name)||name.split(/[\\/]/).some(p=>p==='..'||p==='.'))throw new Error('Unsafe backup path');const file=path.resolve(root,name);if(!nested(root,file))throw new Error('Unsafe backup path');return file}
async function files(root){
  const found=[]
  async function walk(dir){for(const item of fs.readdirSync(dir,{withFileTypes:true})){
    const file=path.join(dir,item.name)
    if(item.isSymbolicLink())throw new Error('Backup and recovery require regular files; symbolic links are not followed')
    if(item.isDirectory())await walk(file)
    else if(item.isFile()){found.push(path.relative(root,file));if(found.length>100000)throw new Error('Backup exceeds 100,000 files')}
  }}
  await walk(root);return found.sort()
}
function exclusiveDirectory(destination){if(fs.existsSync(destination))throw new Error('Destination must be a new, empty directory');fs.mkdirSync(destination,{mode:0o700})}
const destinationPath=value=>path.join(fs.realpathSync(path.dirname(path.resolve(value))),path.basename(path.resolve(value)))
const fingerprint=key=>key?createHash('sha256').update(key).digest('hex'):null
export async function createRecoveryBackup({dataDir,destination}){
  const source=fs.realpathSync(dataDir),target=destinationPath(destination)
  if(nested(source,target)||nested(target,source))throw new Error('Backup destination must be outside the source data directory')
  exclusiveDirectory(target);let connection
  try{
    connection=new Database(path.join(source,'winfire.db'),{readonly:true,fileMustExist:true})
    await connection.backup(path.join(target,'winfire.db'));connection.close();connection=null
    connection=new Database(path.join(target,'winfire.db'));connection.pragma('journal_mode = DELETE');connection.close();connection=null
    const names=await files(source)
    for(const name of names){if(['winfire.db','winfire.db-wal','winfire.db-shm'].includes(name))continue;if(name==='backup-manifest.json')throw new Error('Source data contains a reserved backup manifest');const to=safeFile(target,name);fs.mkdirSync(path.dirname(to),{recursive:true,mode:0o700});fs.copyFileSync(safeFile(source,name),to,fs.constants.COPYFILE_EXCL);fs.chmodSync(to,0o600)}
    const entries=[]
    for(const name of await files(target)){const file=safeFile(target,name);fs.chmodSync(file,0o600);entries.push({name,bytes:fs.statSync(file).size,sha256:await hash(file)})}
    const manifest={version:1,createdAt:new Date().toISOString(),files:entries,vaultKeyFingerprint:fingerprint(process.env.VAULT_MASTER_KEY),externalSecretsRequired:!!process.env.VAULT_MASTER_KEY,externalTlsPaths:Object.entries(process.env).filter(([k])=>['TLS_CERT','TLS_KEY','AGENT_CA_CERT','AGENT_CA_KEY','SNMP_MIB_LIBRARY_DIR'].includes(k)).map(([key])=>key),consistency:'SQLite online snapshot. Stop the service while copying files for a complete file/DB-consistent recovery point.'}
    fs.writeFileSync(path.join(target,'backup-manifest.json'),JSON.stringify(manifest,null,2),{mode:0o600,flag:'wx'})
    return {destination:target,files:entries.length,bytes:entries.reduce((sum,e)=>sum+e.bytes,0),externalSecretsRequired:manifest.externalSecretsRequired,externalPaths:manifest.externalTlsPaths}
  }catch(error){connection?.close();fs.rmSync(target,{recursive:true,force:true});throw error}
}
export async function verifyRecoveryBackup(backup){
  const root=fs.realpathSync(backup),manifestFile=path.join(root,'backup-manifest.json')
  if(fs.lstatSync(manifestFile).isSymbolicLink()||fs.statSync(manifestFile).size>32*1024*1024)throw new Error('Invalid backup manifest')
  const manifest=JSON.parse(fs.readFileSync(manifestFile,'utf8'))
  if(manifest.version!==1||!Array.isArray(manifest.files)||manifest.files.length>100000||!manifest.files.some(e=>e.name==='winfire.db')||new Set(manifest.files.map(e=>e.name)).size!==manifest.files.length)throw new Error('Invalid or incomplete backup manifest')
  const actual=await files(root),listed=new Set(manifest.files.map(e=>e.name))
  if(actual.length!==manifest.files.length+1||actual.some(name=>name!=='backup-manifest.json'&&!listed.has(name)))throw new Error('Backup contains unlisted files')
  for(const entry of manifest.files){const file=safeFile(root,entry.name);if(fs.statSync(file).size!==entry.bytes||await hash(file)!==entry.sha256)throw new Error('Backup integrity mismatch: '+entry.name)}
  const connection=new Database(path.join(root,'winfire.db'),{readonly:true,fileMustExist:true})
  try{if(connection.pragma('integrity_check',{simple:true})!=='ok')throw new Error('SQLite integrity check failed')}finally{connection.close()}
  return manifest
}
export function quarantineRestoredWork(connection){
  const exists=name=>!!connection.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(name)
  const execute=(table,sql)=>{if(exists(table))connection.exec(sql)}
  connection.transaction(()=>{
    execute('users','UPDATE users SET session_version=session_version+1')
    execute('refresh_tokens',"UPDATE refresh_tokens SET revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE revoked_at IS NULL")
    execute('mfa_challenges',"UPDATE mfa_challenges SET status='expired',resolved_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE status='pending'")
    execute('mfa_prompt_events',"UPDATE mfa_prompt_events SET status='expired',expires_at='1970-01-01T00:00:00.000Z' WHERE status IN ('pending','opened','queued')")
    execute('mfa_entra_flows','DELETE FROM mfa_entra_flows')
    execute('identity_segments','UPDATE identity_segments SET portal_enabled=0,fail_open=0')
    execute('jit_grants',"UPDATE jit_grants SET expires_at='1970-01-01T00:00:00.000Z' WHERE revoked_at IS NULL")
    execute('agent_jobs',"UPDATE agent_jobs SET status='cancelled',lease_until=NULL,lease_token=NULL,error='Recovery review: do not replay restored jobs' WHERE status IN ('queued','leased')")
    execute('policy_apply_runs',"UPDATE policy_apply_runs SET status='unknown',error='Recovery review: endpoint state requires readback' WHERE status IN ('queued','running')")
    execute('policy_sync_schedules',"UPDATE policy_sync_schedules SET status='cancelled' WHERE status IN ('scheduled','running')")
    execute('policy_deployment_jobs',"UPDATE policy_deployment_jobs SET status='paused',lease_until=NULL,error='Recovery review: reconcile host transactions before resuming' WHERE status IN ('queued','running','cancelling','restoring','partial')")
    execute('containment_jobs',"UPDATE containment_jobs SET status='recovery-review',lease_until=NULL,error='Recovery review: reconcile owned host changes before restoration' WHERE status<>'restored'")
    execute('learning_sessions',"UPDATE learning_sessions SET status='recovery-review' WHERE status IN ('active','applying','apply-failed')")
    execute('ad_account_holds',"UPDATE ad_account_holds SET status='review',error='Recovery review: do not replay an old account restoration' WHERE status='active'")
    execute('break_glass_sessions',"UPDATE break_glass_sessions SET status='recovery-review',last_error='Recovery review: confirm host-local expiry and current profiles before manual restoration' WHERE status IN ('activating','activation-unknown','active','ending')")
    execute('azure_runs',"UPDATE azure_runs SET status='cancelled',cancel_requested=1,lease_until=NULL WHERE status IN ('queued','running')")
    for(const table of ['azure_connections','discovery_schedules','snmp_discovery_targets','security_automations','ddos_policies','evidence_destinations'])if(exists(table)&&connection.pragma('table_info('+table+')').some(c=>c.name==='enabled'))connection.exec('UPDATE '+table+' SET enabled=0')
    execute('ddos_policies',"UPDATE ddos_policies SET config_json=json_set(config_json,'$.enabled',json('false')) WHERE json_valid(config_json)")
    execute('app_settings',"UPDATE app_settings SET value='closed' WHERE key='mfa_prompt_failure_mode'")
    execute('evidence_deliveries',"UPDATE evidence_deliveries SET status='cancelled',last_error='Recovery review: requeue a fresh snapshot' WHERE status IN ('pending','failed')")
    execute('app_settings',"INSERT INTO app_settings(key,value) VALUES('recovery_review_required','true') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
  })()
}
export async function restoreRecoveryBackup({backup,destination}){
  const root=fs.realpathSync(backup),target=destinationPath(destination),manifest=await verifyRecoveryBackup(root)
  if(nested(root,target)||nested(target,root))throw new Error('Restore destination must be outside the backup')
  if(manifest.vaultKeyFingerprint&&manifest.vaultKeyFingerprint!==fingerprint(process.env.VAULT_MASTER_KEY))throw new Error('Supply the original VAULT_MASTER_KEY from the external secret store')
  exclusiveDirectory(target);let connection
  try{
    for(const entry of manifest.files){const to=safeFile(target,entry.name);fs.mkdirSync(path.dirname(to),{recursive:true,mode:0o700});fs.copyFileSync(safeFile(root,entry.name),to,fs.constants.COPYFILE_EXCL);fs.chmodSync(to,0o600)}
    connection=new Database(path.join(target,'winfire.db'));quarantineRestoredWork(connection);connection.close();connection=null
    return {destination:target,reviewRequired:true,externalPaths:manifest.externalTlsPaths,grants:'Expired for ownership-aware cleanup; host-local expiry remains the independent protection'}
  }catch(error){connection?.close();fs.rmSync(target,{recursive:true,force:true});throw error}
}
export function acknowledgeRecovery(dataDir,confirmation){
  if(confirmation!=='REVIEWED RESTORED HOST STATE')throw new Error('Explicit recovery review acknowledgement is required')
  const connection=new Database(path.join(fs.realpathSync(dataDir),'winfire.db'),{fileMustExist:true})
  try{
    if(connection.prepare("SELECT value FROM app_settings WHERE key='recovery_review_required'").get()?.value!=='true')throw new Error('This data directory has no pending recovery review')
    connection.prepare("UPDATE app_settings SET value='false' WHERE key='recovery_review_required'").run()
  }finally{connection.close()}
  return {reviewRequired:false,schedules:'Remain disabled; enable deliberately after readback and configuration review'}
}
