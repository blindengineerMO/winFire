import {spawn} from 'node:child_process'
import {connect} from 'node:net'
import dns from 'node:dns/promises'
import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import {all, one, run, parse, now, audit} from './db.js'
import {openSealed} from './security.js'

const timeoutMs = 40000
const pause=milliseconds=>new Promise(resolve=>setTimeout(resolve,milliseconds))
const transientError=error=>/timed?\s*out|timeout|ECONNRESET|ECONNREFUSED|Max retries exceeded|unreachable/i.test(error?.message||'')
export function recordNodeSuccess(nodeId) {
  run("UPDATE nodes SET failures=0,status='reachable',next_retry_at=NULL,last_seen_at=? WHERE id=?",now(),nodeId)
}
export function recordNodeTransportFailure(nodeId) {
  const node=one('SELECT failures FROM nodes WHERE id=?',nodeId)
  if(!node)return
  const failures=(node.failures||0)+1
  const delay=Math.min(30*60_000,60_000*2**Math.min(failures-1,10))
  run('UPDATE nodes SET failures=?,status=?,next_retry_at=? WHERE id=?',failures,failures>=3?'unreachable':'degraded',new Date(Date.now()+delay).toISOString(),nodeId)
}
export function tcpProbe(host, port, timeout=2500) {
  return new Promise(resolve => {
    const started=Date.now(), socket=connect({host,port:Number(port)})
    const finish = status => { socket.destroy(); resolve({status,latencyMs:Date.now()-started}) }
    socket.setTimeout(timeout); socket.once('connect',()=>finish('open')); socket.once('timeout',()=>finish('timeout')); socket.once('error',e=>finish(e.code === 'ECONNREFUSED' ? 'refused':'unreachable'))
  })
}
async function rpcProbe(host,nodeId) {
  let lastError
  for(const credential of nodeCredential(nodeId)) {
    try {
      return await new Promise((resolve,reject)=>{
        const child=spawn('rpcclient',['-U',credential.username,'-c','srvinfo',host],{env:{...process.env,PASSWD:credential.secret.password},stdio:['ignore','pipe','pipe']})
        let stdout='',stderr='';const timer=setTimeout(()=>child.kill('SIGKILL'),8000)
        child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk)
        child.once('error',reject);child.once('close',code=>{clearTimeout(timer);code?reject(new Error(stderr.trim()||`rpcclient exited ${code}`)):resolve(stdout.trim())})
      })
    } catch(error) {lastError=error}
  }
  throw lastError||new Error('No credential assigned')
}
async function pwsh(script, input) {
  return new Promise((resolve,reject) => {
    const encoded=Buffer.from(script,'utf16le').toString('base64')
    const child=spawn('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',encoded],{stdio:['pipe','pipe','pipe']})
    let stdout='',stderr=''; const timer=setTimeout(()=>child.kill(),input?.operation==='rights'?120000:timeoutMs)
    child.stdout.on('data',chunk=>stdout+=chunk); child.stderr.on('data',chunk=>stderr+=chunk)
    child.once('error',reject); child.once('close',code=>{clearTimeout(timer); if(code) reject(new Error(stderr.trim() || `PowerShell exited ${code}`)); else {try {resolve(JSON.parse(stdout || 'null'))} catch {reject(new Error(`Invalid PowerShell response: ${stdout.slice(0,300)}`))}}})
    child.stdin.end(JSON.stringify(input))
  })
}
async function pywinrm(input) {
  const sidecar=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../sidecar/wsman_client.py')
  const localPython=path.resolve('.venv/bin/python')
  const python=process.env.WINRM_PYTHON || (fs.existsSync(localPython)?localPython:'python3')
  return new Promise((resolve,reject)=>{
    const child=spawn(python,[sidecar],{stdio:['pipe','pipe','pipe']})
    let stdout='',stderr='';const timer=setTimeout(()=>child.kill('SIGKILL'),input?.operation==='rights'?120000:timeoutMs)
    child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk)
    child.once('error',reject);child.once('close',code=>{clearTimeout(timer);if(code)reject(new Error(stderr.trim()||`WinRM sidecar exited ${code}`));else {try{resolve(JSON.parse(stdout||'null'))}catch{reject(new Error(`Invalid WinRM response: ${stdout.slice(0,300)}`))}}})
    child.stdin.end(JSON.stringify(input))
  })
}
const remoteScript = `
$ErrorActionPreference='Stop'
$payload=[Console]::In.ReadToEnd() | ConvertFrom-Json
$password=ConvertTo-SecureString $payload.password -AsPlainText -Force
$credential=[pscredential]::new($payload.username,$password)
$session=New-PSSession -ComputerName $payload.host -Credential $credential -Authentication Negotiate -UseSSL:($payload.transport -eq 'winrms') -ErrorAction Stop
try {
  $result=Invoke-Command -Session $session -ArgumentList @($payload.operation,$payload.args) -ScriptBlock {
    param($operation,$argsData)
    $ErrorActionPreference='Stop'
    switch($operation) {
      'auth' { [Security.Principal.WindowsIdentity]::GetCurrent().Name }
      'facts' {
        $computer=Get-CimInstance Win32_ComputerSystem; $osInfo=Get-CimInstance Win32_OperatingSystem; $biosInfo=Get-CimInstance Win32_BIOS
        $adapters=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { [pscustomobject]@{description=$_.Description;macAddress=$_.MACAddress;ipAddresses=@($_.IPAddress);subnets=@($_.IPSubnet);gateways=@($_.DefaultIPGateway);dnsServers=@($_.DNSServerSearchOrder);dnsDomain=$_.DNSDomain;dnsSuffixes=@($_.DNSDomainSuffixSearchOrder);dhcpEnabled=$_.DHCPEnabled;dhcpServer=$_.DHCPServer} })
        $lastUser=$null; $machineGuid=$null; $machineSid=$null
        try {$lastUser=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI' -ErrorAction Stop).LastLoggedOnUser} catch {}
        try {$machineGuid=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -ErrorAction Stop).MachineGuid} catch {}
        try {$admin=Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-500'" | Select-Object -First 1; if($admin){$machineSid=$admin.SID -replace '-500$',''}} catch {}
        [pscustomobject]@{computer=$computer | Select-Object Name,Model,Manufacturer,Domain,PartOfDomain,UserName;bios=$biosInfo | Select-Object SerialNumber;os=$osInfo | Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime;identity=[pscustomobject]@{machineGuid=$machineGuid;localMachineSid=$machineSid;domainJoined=[bool]$computer.PartOfDomain;domainName=$computer.Domain;sessionLogonServer=$env:LOGONSERVER;currentInteractiveUser=$computer.UserName;lastLoggedOnUser=$lastUser};network=$adapters;dnsSuffixes=@($adapters | ForEach-Object { @($_.dnsSuffixes)+@($_.dnsDomain) } | Where-Object { $_ } | Select-Object -Unique);firewall=@(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction);service=Get-Service MpsSvc | Select-Object Status}
      }
      'all_rules' {
        $offset=[Math]::Max(0,[int]$argsData.offset); $limit=[Math]::Min(200,[Math]::Max(1,[int]$argsData.limit)); $total=(Get-NetFirewallRule | Measure-Object).Count
        $page=@(Get-NetFirewallRule | Select-Object -Skip $offset -First $limit | ForEach-Object { $r=$_; $p=$r | Get-NetFirewallPortFilter; $a=$r | Get-NetFirewallAddressFilter; $app=$r | Get-NetFirewallApplicationFilter; [pscustomobject]@{name=$r.Name;displayName=$r.DisplayName;group=$r.Group;enabled=[bool]($r.Enabled -eq 'True');action=[string]$r.Action;direction=[string]$r.Direction;profile=[string]$r.Profile;protocol=[string]$p.Protocol;localPort=[string]$p.LocalPort;remotePort=[string]$p.RemotePort;remoteAddress=[string]$a.RemoteAddress;program=[string]$app.Program;source=[string]$r.PolicyStoreSourceType} })
        [pscustomobject]@{total=$total;offset=$offset;rules=$page}
      }
      'rules' { @(Get-NetFirewallRule -Group $argsData.group -ErrorAction SilentlyContinue | ForEach-Object { $r=$_; $p=$r | Get-NetFirewallPortFilter; $a=$r | Get-NetFirewallAddressFilter; $app=$r | Get-NetFirewallApplicationFilter; [pscustomobject]@{name=$r.DisplayName;group=$r.Group;action=([string]$r.Action).ToLower();direction=$(if($r.Direction -eq 'Inbound'){'in'}else{'out'});protocol=[string]$p.Protocol;localPort=[string]$p.LocalPort;remotePort=[string]$p.RemotePort;remoteAddress=[string]$a.RemoteAddress;program=[string]$app.Program;profile=[string]$r.Profile} }) }
  'apply' {
    $old=@(Get-NetFirewallRule -Group $argsData.group -ErrorAction SilentlyContinue | Where-Object { $argsData.remove -contains $_.DisplayName } | ForEach-Object {
      $r=$_; $p=$r | Get-NetFirewallPortFilter; $a=$r | Get-NetFirewallAddressFilter; $app=$r | Get-NetFirewallApplicationFilter
      [pscustomobject]@{internalName=$r.Name;name=$r.DisplayName;action=$r.Action;direction=$r.Direction;protocol=$p.Protocol;localPort=$p.LocalPort;remotePort=$p.RemotePort;remoteAddress=$a.RemoteAddress;program=$app.Program;profile=$r.Profile}
    })
    $created=@()
    try {
      foreach ($r in $argsData.add) {
        $new=New-NetFirewallRule -DisplayName $r.name -Group $r.group -Direction $r.direction -Action $r.action -Protocol $r.protocol -LocalPort $r.localPort -RemotePort $(if($r.remotePort){$r.remotePort}else{'Any'}) -RemoteAddress $r.remoteAddress -Program $r.program -Profile $r.profile -ErrorAction Stop
        $created+=,$new.Name
      }
      foreach($r in $old){Remove-NetFirewallRule -Name $r.internalName -ErrorAction Stop}
    } catch {
      $applyError=$_; $rollbackErrors=@()
      foreach($name in $created){try{if(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue){Remove-NetFirewallRule -Name $name -ErrorAction Stop}}catch{$rollbackErrors+=,"remove new rule $($name): $($_.Exception.Message)"}}
      foreach($r in $old){
        try{if(-not (Get-NetFirewallRule -Name $r.internalName -ErrorAction SilentlyContinue)){New-NetFirewallRule -DisplayName $r.name -Group $argsData.group -Direction $r.direction -Action $r.action -Protocol $r.protocol -LocalPort $r.localPort -RemotePort $r.remotePort -RemoteAddress $r.remoteAddress -Program $r.program -Profile $r.profile -ErrorAction Stop | Out-Null}}
        catch{$rollbackErrors+=,"restore old rule $($r.name): $($_.Exception.Message)"}
      }
      if($rollbackErrors.Count){throw "Firewall apply failed: $($applyError.Exception.Message); rollback incomplete: $($rollbackErrors -join '; ')"}
      throw $applyError
    }
    @{applied = $true}
  }
  'events' { $after=[long]$argsData.after; $xpath="*[System[((EventID=5156 or EventID=5157 or EventID=5150 or EventID=5151 or EventID=4624 or EventID=4625 or EventID=5712) and EventRecordID > $after)]]"; @(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object { $event=$_; $xml=[xml]$event.ToXml(); $fields=@{}; foreach($data in @($xml.Event.EventData.Data)) { if($data.Name) {$fields[$data.Name]=[string]$data.'#text'} }; [pscustomobject]@{RecordId=$event.RecordId;Id=$event.Id;TimeCreated=$event.TimeCreated.ToUniversalTime().ToString('o');Fields=$fields} }) }
      'rights' { $file=Join-Path $env:TEMP ('winfire-'+[guid]::NewGuid().ToString()+'.inf'); try {secedit /export /mergedpolicy /cfg $file /areas USER_RIGHTS | Out-Null; if($LASTEXITCODE -ne 0){throw "secedit export failed with exit code $LASTEXITCODE"}; $content=@(Get-Content $file); $rights=@($content | Where-Object {$_ -match '^\\s*Se\\w*LogonRight\\s*='}); if(!$rights.Count){throw "secedit export contained no logon rights across $($content.Count) lines"}; $rights} finally {Remove-Item $file -Force -ErrorAction SilentlyContinue} }
      default { throw 'Unsupported operation' }
    }
  }
  $result | ConvertTo-Json -Depth 12 -Compress
} finally { Remove-PSSession $session }
`
function nodeCredential(nodeId,credentialId) {
  const rows=all(`SELECT DISTINCT c.* FROM credentials c JOIN credential_assignments a ON a.credential_id=c.id WHERE (a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?)) AND (? IS NULL OR c.id=?) ORDER BY c.priority`,nodeId,nodeId,credentialId||null,credentialId||null)
  if (!rows.length) throw new Error('No credential assigned to node')
  return rows.map(row=>({...row,secret:openSealed(row.encrypted_blob)}))
}
export async function remote(node,operation,args={},options={}) {
  if(node.transport==='wmi')throw new Error('WMI/DCOM transport is detected but authenticated WMI operations are not implemented')
  const host=node.fqdn || node.ip || node.hostname
  let lastError
  for (const credential of nodeCredential(node.id,options.credentialId)) {
    const input={host,transport:node.transport||'winrm',username:credential.username,password:credential.secret.password,operation,args}
    const attempts=operation==='apply'?1:2
    for(let attempt=0;attempt<attempts;attempt++){
      try {
        const result=process.platform==='win32' ? await pwsh(remoteScript,input) : await pywinrm(input)
        recordNodeSuccess(node.id)
        return result
      }
      catch(error) {
        lastError=error
        if(!transientError(error))break
        if(operation==='apply'){
          recordNodeTransportFailure(node.id)
          throw error // Outcome may be ambiguous; re-read state before retrying.
        }
        if(attempt+1<attempts)await pause(300*(attempt+1))
      }
    }
  }
  if(transientError(lastError))recordNodeTransportFailure(node.id)
  throw lastError
}
export async function probeNode(node) {
  const host=node.fqdn || node.ip || node.hostname
  const winrm=await tcpProbe(host,5985)
  const winrms=await tcpProbe(host,5986)
  const wmi=await tcpProbe(host,135)
  const transport=winrms.status==='open'?'winrms':winrm.status==='open'?'winrm':wmi.status==='open'?'wmi':null
  let rpc=null
  if(transport==='wmi')try{rpc=await rpcProbe(host,node.id)}catch(error){rpc={error:error.message}}
  const status=transport==='wmi'?(typeof rpc==='string'?'rpc-authenticated':'unverified'):transport?'port-open':'unreachable'
  run('UPDATE nodes SET transport=?,status=?,last_seen_at=?,failures=?,next_retry_at=NULL WHERE id=?',transport,status,transport?now():node.last_seen_at,transport?0:(node.failures||0)+1,node.id)
  audit(null,'node.probe','node',node.id,null,{transport,status})
  return {transport,status,ports:{winrm,winrms,wmi},rpc,note:transport==='wmi'?'RPC authentication checked; WMI/DCOM operations remain unverified.':transport?'WinRM port is open; authenticate and collect facts to verify access.':'No supported management port responded.'}
}
export async function collectFacts(node) {
  const facts=await remote(node,'facts')
  run('INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET snapshot_json=excluded.snapshot_json,collected_at=excluded.collected_at',node.id,JSON.stringify(facts),now())
  run('UPDATE nodes SET os_version=?,os_build=?,last_seen_at=?,status=? WHERE id=?',facts?.os?.Version||null,facts?.os?.BuildNumber||null,now(),'reachable',node.id)
  return facts
}
export async function enrichNode(node) {
  if(node.connection_mode==='agent')throw new Error('Agent nodes require agent-reported facts')
  const probe=await probeNode(node)
  if(!['winrm','winrms'].includes(probe.transport))throw new Error('No working WinRM transport for inventory collection')
  return collectFacts(one('SELECT * FROM nodes WHERE id=?',node.id))
}
export async function lookupDns(node) {
  let forward=[],reverse=[]
  try {forward=await dns.lookup(node.fqdn || node.hostname,{all:true})} catch {}
  if (node.ip) try {reverse=await dns.reverse(node.ip)} catch {}
  const mismatch=!!(reverse.length && !reverse.some(name=>name.toLowerCase().replace(/\.$/,'') === (node.fqdn || node.hostname).toLowerCase()))
  run('INSERT INTO dns_lookups(node_id,forward_result,reverse_result,mismatch,checked_at) VALUES(?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET forward_result=excluded.forward_result,reverse_result=excluded.reverse_result,mismatch=excluded.mismatch,checked_at=excluded.checked_at',node.id,JSON.stringify(forward),JSON.stringify(reverse),Number(mismatch),now())
  return {forward,reverse,mismatch}
}
export function diffRules(desired,actual) {
  const comparable=r=>JSON.stringify([r.name,r.action,r.direction==='inbound'?'in':r.direction==='outbound'?'out':r.direction,r.protocol,r.localPort,r.remotePort||'Any',r.remoteAddress,r.program,r.profile].map(x=>String(x).toLowerCase()))
  const wanted=new Map(desired.map(r=>[r.name,comparable(r)])), present=new Map((actual||[]).map(r=>[r.name,comparable(r)]))
  return {remove:[...present.keys()].filter(name=>!wanted.has(name)||wanted.get(name)!==present.get(name)),add:desired.filter(r=>!present.has(r.name)||present.get(r.name)!==wanted.get(r.name))}
}
export async function applyRules(node,policyId,rules) {
  const group=`WinFireSecure:${policyId}`
  const asRules=response=>Array.isArray(response)?response:response?[response]:[]
  const previous=asRules(await remote(node,'rules',{group}))
  const diff=diffRules(rules,previous)
  if(diff.add.length||diff.remove.length) {
    let applyError=null
    try {await remote(node,'apply',{group,...diff})}
    catch(error){applyError=error}
    let observed
    try {observed=asRules(await remote(node,'rules',{group}))}
    catch(readError){throw new Error(`Firewall apply outcome is unknown: ${applyError?.message||readError.message}; readback failed: ${readError.message}`)}
    const pending=diffRules(rules,observed)
    if(!pending.add.length&&!pending.remove.length)return diff
    const restore=diffRules(previous,observed)
    if(restore.add.length||restore.remove.length) {
      try {
        await remote(node,'apply',{group,...restore})
        const restored=diffRules(previous,asRules(await remote(node,'rules',{group})))
        if(restored.add.length||restored.remove.length)throw new Error('Readback differs from prior state')
      } catch(rollbackError) {
        throw new Error(`Firewall apply failed: ${applyError?.message||'readback differs from requested policy'}; rollback incomplete: ${rollbackError.message}`)
      }
    }
    throw new Error(`Firewall apply failed: ${applyError?.message||'readback differs from requested policy'}; prior state restored`)
  }
  return diff
}
