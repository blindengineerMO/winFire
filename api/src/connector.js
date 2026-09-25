import {capabilityEvidence} from './services/capabilities.js'
import {assertDirectManagement} from './services/networkBoundary.js'
import {spawn} from 'node:child_process'
import {connect,isIP} from 'node:net'
import dns from 'node:dns/promises'
import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import {all, one, run, parse, now, audit, id} from './db.js'
import {openSealed} from './security.js'
import {breakGlassFunctions} from './breakGlassScript.js'
import {jitAccessFunctions} from './jitAccessScript.js'
import {mfaPromptFunctions} from './mfaPromptScript.js'
import {assertManagementAccess} from './managementGuard.js'
import {emitNotification} from './notifications.js'
import {classifyOperatingSystem,classifyInfrastructureFacts} from './infrastructureDiscovery.js'
import {classifyOnboardingError,attachOnboardingError} from './onboardingErrors.js'
import {recordCredentialAuthSuccess,recordCredentialAuthFailure} from './credentialHealth.js'
import {collectLinuxFacts,collectLinuxRules,applyLinuxFirewall,testSshCredential,launchLinuxPortal} from './sshConnector.js'

const timeoutMs = 40000
const lsaRightsFunctions=fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../sidecar/lsa_rights.ps1'),'utf8')
const firewallUserFunctions=fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../sidecar/firewall_user.ps1'),'utf8')
const accountInventoryFunctions=fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../sidecar/account_inventory.ps1'),'utf8')
const agentDeployFunctions=fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../sidecar/agent_deploy.ps1'),'utf8')
const securityProcessOwnerFunctions=fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../sidecar/security_process_owner.ps1'),'utf8')
const pause=milliseconds=>new Promise(resolve=>setTimeout(resolve,milliseconds))
const transientError=error=>/timed?\s*out|timeout|ECONNRESET|ECONNREFUSED|Max retries exceeded|unreachable/i.test(error?.message||'')
export function recordNodeSuccess(nodeId,probeStatus=null) {
  const managedAt=now()
  if(probeStatus)run("UPDATE nodes SET failures=0,status='reachable',next_retry_at=NULL,last_seen_at=?,last_managed_at=?,probe_status=?,last_probe_at=?,onboarding_error_code=NULL,onboarding_error_updated_at=NULL WHERE id=?",managedAt,managedAt,probeStatus,managedAt,nodeId)
  else run("UPDATE nodes SET failures=0,status='reachable',next_retry_at=NULL,last_seen_at=?,last_managed_at=?,onboarding_error_code=NULL,onboarding_error_updated_at=NULL WHERE id=?",managedAt,managedAt,nodeId)
}
export function recordOnboardingFailure(nodeId,error,context={}) {
  const onboardingError=error?.onboardingError||classifyOnboardingError(error,context)
  if(nodeId)run('UPDATE nodes SET onboarding_error_code=?,onboarding_error_updated_at=? WHERE id=?',onboardingError.code,now(),nodeId)
  if(error&&typeof error==='object')error.onboardingError=onboardingError
  return onboardingError
}
export function recordNodeTransportFailure(nodeId) {
  const node=one('SELECT failures,hostname,status FROM nodes WHERE id=?',nodeId)
  if(!node)return
  const failures=(node.failures||0)+1
  const delay=Math.min(30*60_000,60_000*2**Math.min(failures-1,10))
  run('UPDATE nodes SET failures=?,status=?,next_retry_at=? WHERE id=?',failures,failures>=3?'unreachable':'degraded',new Date(Date.now()+delay).toISOString(),nodeId)
  if(failures>=3&&node.status!=='unreachable'){
    audit(null,'node.unreachable','node',nodeId,{status:node.status,failures:node.failures},{status:'unreachable',failures})
    emitNotification({eventKey:`node-unreachable:${nodeId}:${id()}`,category:'node_unreachable',title:'Node unreachable',body:`${node.hostname||nodeId} failed ${failures} consecutive management connections.`,entityType:'node',entityId:nodeId})
  }
}
export function tcpProbe(host, port, timeout=2500) {
  return new Promise(resolve => {
    const started=Date.now(), socket=connect({host,port:Number(port)})
    const finish = status => { const sourceIp=socket.localAddress||null,sourcePort=socket.localPort||null; socket.destroy(); resolve({status,latencyMs:Date.now()-started,sourceIp,sourcePort}) }
    socket.setTimeout(timeout); socket.once('connect',()=>finish('open')); socket.once('timeout',()=>finish('timeout')); socket.once('error',e=>finish(e.code === 'ECONNREFUSED' ? 'refused':'unreachable'))
  })
}
async function rpcProbe(host,nodeId) {
  let lastError
  for(const credential of nodeCredential(nodeId)) {
    try {
      const result=await new Promise((resolve,reject)=>{
        const child=spawn('rpcclient',['-U',credential.username,'-c','srvinfo',host],{env:{...process.env,PASSWD:credential.secret.password},stdio:['ignore','pipe','pipe']})
        let stdout='',stderr='';const timer=setTimeout(()=>child.kill('SIGKILL'),8000)
        child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk)
        child.once('error',reject);child.once('close',code=>{clearTimeout(timer);code?reject(new Error(stderr.trim()||`rpcclient exited ${code}`)):resolve(stdout.trim())})
      })
      recordCredentialAuthSuccess({credentialId:credential.id,nodeId,transport:'rpc'});return result
    } catch(error) {lastError=error;recordCredentialAuthFailure({credentialId:credential.id,nodeId,error,transport:'rpc',operation:'probe'})}
  }
  throw lastError||new Error('No credential assigned')
}
async function netshProbe(host,nodeId){
  let lastError
  for(const credential of nodeCredential(nodeId)){
    try{const result=await netshExecPython({host,username:credential.username,password:credential.secret.password,mode:'probe'});recordCredentialAuthSuccess({credentialId:credential.id,nodeId,transport:'netsh'});return result}
    catch(error){lastError=error;recordCredentialAuthFailure({credentialId:credential.id,nodeId,error,transport:'netsh',operation:'probe'});error.message=String(error.message).replaceAll(credential.secret.password,'[redacted]')}
  }
  throw lastError||new Error('No credential assigned')
}
async function pwsh(script, input) {
  return new Promise((resolve,reject) => {
    const encoded=Buffer.from(script,'utf16le').toString('base64')
    const child=spawn('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',encoded],{stdio:['pipe','pipe','pipe']})
    let stdout='',stderr=''; const timer=setTimeout(()=>child.kill(),input?.operation?.startsWith('rights')||input?.operation?.startsWith('jit_')||input?.operation==='prompt_browser'||input?.operation==='agent_deploy'||input?.operation==='security_session_logoff'?120000:timeoutMs)
    child.stdout.on('data',chunk=>stdout+=chunk); child.stderr.on('data',chunk=>stderr+=chunk)
    child.once('error',reject); child.once('close',code=>{clearTimeout(timer); if(code) reject(new Error(stderr.trim() || `PowerShell exited ${code}`)); else {try {resolve(JSON.parse(stdout || 'null'))} catch {reject(new Error(`Invalid PowerShell response: ${stdout.slice(0,300)}`))}}})
    child.stdin.end(JSON.stringify(input))
  })
}
async function pywinrm(input) {
  const sidecar=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../sidecar/wsman_client.py')
  const localPython=path.resolve('.venv/bin/python')
  const python=process.env.WINRM_PYTHON || (fs.existsSync(localPython)?localPython:process.platform==='win32'?'python':'python3')
  return new Promise((resolve,reject)=>{
    const child=spawn(python,[sidecar],{stdio:['pipe','pipe','pipe']})
    let stdout='',stderr='';const timer=setTimeout(()=>child.kill('SIGKILL'),input?.operation?.startsWith('rights')||input?.operation?.startsWith('jit_')||input?.operation==='prompt_browser'||input?.operation==='agent_deploy'||input?.operation==='security_session_logoff'?120000:timeoutMs)
    child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk)
    child.once('error',reject);child.once('close',code=>{clearTimeout(timer);if(code)reject(new Error(stderr.trim()||`WinRM sidecar exited ${code}`));else {try{resolve(JSON.parse(stdout||'null'))}catch{reject(new Error(`Invalid WinRM response: ${stdout.slice(0,300)}`))}}})
    child.stdin.end(JSON.stringify(input))
  })
}
async function wmiProbePython(input){
  const sidecar=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../sidecar/wmi_probe.py')
  const localPython=path.resolve('.venv/bin/python')
  const python=process.env.WMI_PROBE_PYTHON||process.env.WINRM_PYTHON||(fs.existsSync(localPython)?localPython:process.platform==='win32'?'python':'python3')
  return new Promise((resolve,reject)=>{
    const child=spawn(python,[sidecar],{stdio:['pipe','pipe','pipe']})
    let stdout='',stderr='',timedOut=false
    const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL')},['facts','audit_policy','audit_policy_enable','all_rules','rules','apply','events','events_recent','events_probe','event_cursor'].includes(input.mode)?45000:12000)
    child.stdout.on('data',chunk=>stdout+=chunk)
    child.stderr.on('data',chunk=>stderr+=chunk)
    child.once('error',error=>{clearTimeout(timer);reject(error)})
    child.once('close',code=>{
      clearTimeout(timer)
      if(timedOut)return reject(new Error('WMI/DCOM probe timed out; check the dynamic RPC port range and firewall'))
      if(code)return reject(new Error(stderr.trim().slice(0,500)||`WMI probe exited ${code}`))
      try{resolve(JSON.parse(stdout))}catch{reject(new Error('Invalid WMI probe response'))}
    })
    child.stdin.end(JSON.stringify(input))
  })
}
async function netshExecPython(input){
  const sidecar=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../sidecar/netsh_exec.py')
  const localPython=path.resolve('.venv/bin/python')
  const python=process.env.NETSH_PYTHON||process.env.WINRM_PYTHON||(fs.existsSync(localPython)?localPython:process.platform==='win32'?'python':'python3')
  return new Promise((resolve,reject)=>{
    const child=spawn(python,[sidecar],{stdio:['pipe','pipe','pipe']})
    let stdout='',stderr='',timedOut=false
    const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL')},Number(input.timeoutSeconds||45)*1000)
    child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk)
    child.once('error',error=>{clearTimeout(timer);reject(error)})
    child.once('close',code=>{
      clearTimeout(timer)
      if(timedOut)return reject(new Error('SMB netsh command timed out; check TCP 445 and service-control permissions'))
      if(code)return reject(new Error(stderr.trim().slice(0,500)||`SMB netsh sidecar exited ${code}`))
      try{resolve(JSON.parse(stdout||'null'))}catch{reject(new Error('Invalid SMB netsh response'))}
    })
    child.stdin.end(JSON.stringify(input))
  })
}
async function wmiProbePowerShell(input){
  const script=`$ErrorActionPreference='Stop';$payload=[Console]::In.ReadToEnd()|ConvertFrom-Json;$secure=ConvertTo-SecureString $payload.password -AsPlainText -Force;$credential=New-Object System.Management.Automation.PSCredential($payload.username,$secure);$computer=Get-WmiObject -Class Win32_ComputerSystem -ComputerName $payload.host -Credential $credential -ErrorAction Stop|Select-Object -First 1 -ExpandProperty Name;if($payload.expectedName -and $computer -ine ($payload.expectedName -split '\\.')[0]){throw 'WMI computer name does not match the directory inventory record'};$result=@{success=$true;transport='wmi';computerName=[string]$computer};if($payload.mode -eq 'enable_winrm'){$command='powershell.exe -NoProfile -NonInteractive -Command "Enable-PSRemoting -Force"';$started=Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $command,$null,$null -ComputerName $payload.host -Credential $credential -ErrorAction Stop;if($started.ReturnValue -ne 0){throw "Win32_Process.Create returned $($started.ReturnValue)"};$result.activationStarted=$true;$result.processId=$started.ProcessId};$result|ConvertTo-Json -Compress`
  const encoded=Buffer.from(script,'utf16le').toString('base64')
  return new Promise((resolve,reject)=>{
    const child=spawn('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',encoded],{stdio:['pipe','pipe','pipe']})
    let stdout='',stderr='',timedOut=false
    const timer=setTimeout(()=>{timedOut=true;child.kill()},12000)
    child.stdout.on('data',chunk=>stdout+=chunk)
    child.stderr.on('data',chunk=>stderr+=chunk)
    child.once('error',error=>{clearTimeout(timer);reject(error)})
    child.once('close',code=>{
      clearTimeout(timer)
      if(timedOut)return reject(new Error('WMI/DCOM probe timed out; check the dynamic RPC port range and firewall'))
      if(code)return reject(new Error(stderr.trim().slice(0,500)||`WMI probe exited ${code}`))
      try{resolve(JSON.parse(stdout))}catch{reject(new Error('Invalid WMI probe response'))}
    })
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
    function Get-WinFireAuditPolicy {
      if(-not ('WinFireAuditPolicyQuery' -as [type])) {
        $source='using System; using System.ComponentModel; using System.Runtime.InteropServices; public static class WinFireAuditPolicyQuery { [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.U1)] private static extern bool AuditQuerySystemPolicy([In] Guid[] ids, uint count, out IntPtr policy); [DllImport("advapi32.dll")] private static extern void AuditFree(IntPtr policy); public static int Read(string text) { Guid id=new Guid(text); IntPtr policy; if(!AuditQuerySystemPolicy(new Guid[]{id},1,out policy)) throw new Win32Exception(Marshal.GetLastWin32Error()); try { if(policy==IntPtr.Zero || Marshal.PtrToStructure<Guid>(policy)!=id) throw new InvalidOperationException("Audit policy query returned an unexpected subcategory"); return Marshal.ReadInt32(policy,16); } finally { if(policy!=IntPtr.Zero) AuditFree(policy); } } }'
        Add-Type -TypeDefinition $source -ErrorAction Stop
      }
      $setting=[WinFireAuditPolicyQuery]::Read('0CCE9226-69AE-11D9-BED3-505054503030')
      [pscustomobject]@{subcategoryGuid='0CCE9226-69AE-11D9-BED3-505054503030';settingValue=$setting;successEnabled=[bool]($setting -band 1);failureEnabled=[bool]($setting -band 2)}
    }
    function Set-WinFireWefSource($argsData) {
      $uri=[uri][string]$argsData.subscriptionUrl
      if($uri.Scheme -ne 'https' -or $uri.UserInfo){throw 'WEF Subscription Manager must be an HTTPS URL without embedded credentials'}
      if($uri.AbsoluteUri.Length -gt 2048){throw 'WEF Subscription Manager URL is too long'}
      $osVersion=[string](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Version
      if($osVersion -match '^(5\\.1|5\\.2)\\.') {throw 'This Windows version does not support the WinFire source-initiated WEF configuration'}
      $refresh=[Math]::Min(86400,[Math]::Max(60,[int]$argsData.refreshSeconds))
      $key='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding'
      New-Item -Path $key -Force | Out-Null
      $before=@((Get-ItemProperty -Path $key -Name SubscriptionManager -ErrorAction SilentlyContinue).SubscriptionManager)
      $value="Server=$($uri.AbsoluteUri),Refresh=$refresh"
      Set-ItemProperty -Path $key -Name SubscriptionManager -PropertyType MultiString -Value @($value) -Force
      auditpol /set '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
      if($LASTEXITCODE -ne 0){throw "Filtering Platform Connection audit policy update failed with exit code $LASTEXITCODE"}
      $readback=@((Get-ItemProperty -Path $key -Name SubscriptionManager -ErrorAction Stop).SubscriptionManager)
      if($readback -notcontains $value){throw 'WEF Subscription Manager registry readback did not confirm the configured URL'}
      $audit=Get-WinFireAuditPolicy
      if(-not ($audit.successEnabled -and $audit.failureEnabled)){throw 'Filtering Platform Connection audit readback did not confirm success and failure auditing'}
      [pscustomobject]@{configured=$true;subscriptionManager=$value;previousSubscriptionManager=$before;refreshSeconds=$refresh;auditPolicy=$audit}
    }
    ${breakGlassFunctions}
    ${jitAccessFunctions}
    __WINFIRE_AGENT_DEPLOY__
    __WINFIRE_PROMPT_FUNCTIONS__
    __WINFIRE_SECURITY_PROCESS_OWNER__
    # __WINFIRE_LSA_RIGHTS__
    # __WINFIRE_ACCOUNT_INVENTORY__
    # __WINFIRE_FIREWALL_USER__
    function Invoke-WinFireRpcNetsh($arguments) {
      $output = & netsh @arguments 2>&1 | Out-String
      if($LASTEXITCODE -ne 0){ throw "netsh RPC command failed with exit code \${LASTEXITCODE}: $output" }
      return $output.Trim()
    }
    function Invoke-WinFireRpcFilter($operation,$argsData) {
      if($operation -eq 'rpc_filters') {
        return [pscustomobject]@{raw=(Invoke-WinFireRpcNetsh @('rpc','filter','show','filter'))}
      }
      if($operation -eq 'rpc_filter_remove') {
        $removed=@()
        foreach($key in @($argsData.filterKeys)) {
          Invoke-WinFireRpcNetsh @('rpc','filter','delete','filter',"filterkey=$key") | Out-Null
          $removed+=,[string]$key
        }
        return [pscustomobject]@{removed=$removed}
      }
      $applied=@()
      foreach($rule in @($argsData.rules)) {
        $action=if([string]$rule.action -eq 'allow'){'permit'}else{[string]$rule.action}
        $ruleArgs=@('rpc','filter','add','rule',"layer=$($rule.layer)","actiontype=$action","filterkey=$($rule.filterKey)",'persistence=yes')
        if([bool]$rule.audit -and $action -eq 'permit' -and [string]$rule.layer -ne 'ep_add'){$ruleArgs+='audit=enable'}
        Invoke-WinFireRpcNetsh $ruleArgs | Out-Null
        foreach($condition in @($rule.conditions)) {
          $conditionArgs=@('rpc','filter','add','condition',"field=$($condition.field)","matchtype=$($condition.matchType)","data=$($condition.data)")
          Invoke-WinFireRpcNetsh $conditionArgs | Out-Null
        }
        Invoke-WinFireRpcNetsh @('rpc','filter','add','filter') | Out-Null
        $applied+=,[string]$rule.filterKey
      }
      return [pscustomobject]@{applied=$applied}
    }
    switch($operation) {
      'account_inventory' { Get-WinFireAccountInventory $argsData }
      'prompt_browser' { Open-WinFireMfaPortal $argsData }
      'prompt_session' { @(Get-WinFireActiveSession) }
      'agent_deploy' { Install-WinFireAgentRemote $argsData }
      'auth' { [Security.Principal.WindowsIdentity]::GetCurrent().Name }
      'security_process_owner' { Get-WinFireProcessOwner $argsData }
      'security_session_logoff' { End-WinFireClientSession $argsData }
      'rpc_filters' { Invoke-WinFireRpcFilter $operation $argsData }
      'rpc_filter_apply' { Invoke-WinFireRpcFilter $operation $argsData }
      'rpc_filter_remove' { Invoke-WinFireRpcFilter $operation $argsData }
      'wef_configure' { Set-WinFireWefSource $argsData }
      'tcp_probe' {
        $addresses=@([System.Net.Dns]::GetHostAddresses([string]$argsData.host));$address=@($addresses | Where-Object AddressFamily -EQ InterNetwork | Select-Object -First 1)[0];if(-not $address){$address=$addresses[0]}
        $route=[System.Net.Sockets.Socket]::new($address.AddressFamily,[System.Net.Sockets.SocketType]::Dgram,[System.Net.Sockets.ProtocolType]::Udp)
        try{$route.Connect($address,[int]$argsData.port);$localAddress=([System.Net.IPEndPoint]$route.LocalEndPoint).Address}finally{$route.Dispose()}
        $client=[System.Net.Sockets.TcpClient]::new($address.AddressFamily);$client.Client.Bind([System.Net.IPEndPoint]::new($localAddress,0));$watch=[Diagnostics.Stopwatch]::StartNew();$status='unreachable'
        try {
          $task=$client.ConnectAsync($address,[int]$argsData.port)
          if($task.Wait([Math]::Min(5000,[Math]::Max(250,[int]$argsData.timeoutMs)))){$status='open'}else{$status='timeout'}
        } catch {
          $cause=$_.Exception;while($cause.InnerException){$cause=$cause.InnerException}
          if($cause -is [System.Net.Sockets.SocketException] -and $cause.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused){$status='refused'}
        } finally {$watch.Stop();$endpoint=$client.Client.LocalEndPoint;$sourceIp=if($endpoint){$endpoint.Address.ToString()}else{$null};$sourcePort=if($endpoint){$endpoint.Port}else{$null};$client.Dispose()}
        [pscustomobject]@{status=$status;latencyMs=$watch.ElapsedMilliseconds;sourceIp=$sourceIp;sourcePort=$sourcePort}
      }
      'facts' {
        $computer=Get-CimInstance Win32_ComputerSystem; $osInfo=Get-CimInstance Win32_OperatingSystem; $biosInfo=Get-CimInstance Win32_BIOS
        $adapters=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { [pscustomobject]@{description=$_.Description;macAddress=$_.MACAddress;ipAddresses=@($_.IPAddress);subnets=@($_.IPSubnet);gateways=@($_.DefaultIPGateway);dnsServers=@($_.DNSServerSearchOrder);dnsDomain=$_.DNSDomain;dnsSuffixes=@($_.DNSDomainSuffixSearchOrder);dhcpEnabled=$_.DHCPEnabled;dhcpServer=$_.DHCPServer} })
        $lastUser=$null; $machineGuid=$null; $machineSid=$null; $biosUuid=$null
        try {$biosUuid=(Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID} catch {}
        try {$lastUser=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI' -ErrorAction Stop).LastLoggedOnUser} catch {}
        try {$machineGuid=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -ErrorAction Stop).MachineGuid} catch {}
        try {$admin=Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-500'" | Select-Object -First 1; if($admin){$machineSid=$admin.SID -replace '-500$',''}} catch {}
        [pscustomobject]@{computer=$computer | Select-Object Name,Model,Manufacturer,Domain,PartOfDomain,UserName;bios=$biosInfo | Select-Object SerialNumber;os=$osInfo | Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime;identity=[pscustomobject]@{machineGuid=$machineGuid;biosUuid=$biosUuid;localMachineSid=$machineSid;domainJoined=[bool]$computer.PartOfDomain;domainName=$computer.Domain;sessionLogonServer=$env:LOGONSERVER;currentInteractiveUser=$computer.UserName;lastLoggedOnUser=$lastUser};network=$adapters;dnsSuffixes=@($adapters | ForEach-Object { @($_.dnsSuffixes)+@($_.dnsDomain) } | Where-Object { $_ } | Select-Object -Unique);firewall=@(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction);service=Get-Service MpsSvc | Select-Object Status}
      }
      'all_rules' {
        $offset=[Math]::Max(0,[int]$argsData.offset); $limit=[Math]::Min(200,[Math]::Max(1,[int]$argsData.limit)); $total=(Get-NetFirewallRule | Measure-Object).Count
        $page=@(Get-NetFirewallRule | Select-Object -Skip $offset -First $limit | ForEach-Object { $r=$_; $p=$r | Get-NetFirewallPortFilter; $a=$r | Get-NetFirewallAddressFilter; $app=$r | Get-NetFirewallApplicationFilter; [pscustomobject]@{name=$r.Name;displayName=$r.DisplayName;group=$r.Group;enabled=[bool]($r.Enabled -eq 'True');action=[string]$r.Action;direction=[string]$r.Direction;profile=[string]$r.Profile;protocol=[string]$p.Protocol;localPort=[string]$p.LocalPort;remotePort=[string]$p.RemotePort;remoteAddress=[string]$a.RemoteAddress;program=[string]$app.Program;source=[string]$r.PolicyStoreSourceType} })
        [pscustomobject]@{total=$total;offset=$offset;rules=$page}
      }
      'rules' { @(Get-NetFirewallRule -Group $argsData.group -ErrorAction SilentlyContinue | ForEach-Object { $r=$_; $p=$r | Get-NetFirewallPortFilter; $a=$r | Get-NetFirewallAddressFilter; $app=$r | Get-NetFirewallApplicationFilter; [pscustomobject]@{internalName=$r.Name;name=$r.DisplayName;group=$r.Group;action=([string]$r.Action).ToLower();direction=$(if($r.Direction -eq 'Inbound'){'in'}else{'out'});protocol=[string]$p.Protocol;localPort=[string]$p.LocalPort;remotePort=[string]$p.RemotePort;remoteAddress=[string]$a.RemoteAddress;program=[string]$app.Program;profile=[string]$r.Profile;localUserSid=Get-WinFireLocalUserSid $r} }) }
  'apply' {
    $old=@(Get-NetFirewallRule -Group $argsData.group -ErrorAction SilentlyContinue | Where-Object { $argsData.remove -contains $_.DisplayName } | ForEach-Object {
      $r=$_; $p=$r | Get-NetFirewallPortFilter; $a=$r | Get-NetFirewallAddressFilter; $app=$r | Get-NetFirewallApplicationFilter
      [pscustomobject]@{internalName=$r.Name;name=$r.DisplayName;action=$r.Action;direction=$r.Direction;protocol=$p.Protocol;localPort=$p.LocalPort;remotePort=$p.RemotePort;remoteAddress=$a.RemoteAddress;program=$app.Program;profile=$r.Profile;localUserSid=Get-WinFireLocalUserSid $r}
    })
    $created=@()
    try {
      foreach ($r in $argsData.add) {
        $new=New-WinFireFirewallRule $r $r.group
        $created+=,$new.Name
      }
      foreach($r in $old){Remove-NetFirewallRule -Name $r.internalName -ErrorAction Stop}
    } catch {
      $applyError=$_; $rollbackErrors=@()
      foreach($name in $created){try{if(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue){Remove-NetFirewallRule -Name $name -ErrorAction Stop}}catch{$rollbackErrors+=,"remove new rule $($name): $($_.Exception.Message)"}}
      foreach($r in $old){
        try{if(-not (Get-NetFirewallRule -Name $r.internalName -ErrorAction SilentlyContinue)){New-WinFireFirewallRule $r $argsData.group | Out-Null}}
        catch{$rollbackErrors+=,"restore old rule $($r.name): $($_.Exception.Message)"}
      }
      if($rollbackErrors.Count){throw "Firewall apply failed: $($applyError.Exception.Message); rollback incomplete: $($rollbackErrors -join '; ')"}
      throw $applyError
    }
    @{applied = $true}
  }
  'events' { $after=[long]$argsData.after; $xpath="*[System[((EventID=5156 or EventID=5157 or EventID=5150 or EventID=5151 or EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=5712) and EventRecordID > $after)]]"; @(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object { $event=$_; $xml=[xml]$event.ToXml(); $fields=@{}; foreach($data in @($xml.Event.EventData.Data)) { if($data.Name) {$fields[$data.Name]=[string]$data.'#text'} }; [pscustomobject]@{RecordId=$event.RecordId;Id=$event.Id;TimeCreated=$event.TimeCreated.ToUniversalTime().ToString('o');Fields=$fields} }) }
  'events_recent' { $firewall=@(Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=5156 or EventID=5157 or EventID=5150 or EventID=5151)]]' -MaxEvents 500 -ErrorAction SilentlyContinue); $other=@(Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=5712)]]' -MaxEvents 100 -ErrorAction SilentlyContinue); @($firewall+$other | Sort-Object RecordId | ForEach-Object { $event=$_; $xml=[xml]$event.ToXml(); $fields=@{}; foreach($data in @($xml.Event.EventData.Data)) { if($data.Name) {$fields[$data.Name]=[string]$data.'#text'} }; [pscustomobject]@{RecordId=$event.RecordId;Id=$event.Id;TimeCreated=$event.TimeCreated.ToUniversalTime().ToString('o');Fields=$fields} }) }
  'events_probe' { @(Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=5157]]' -MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object { $event=$_; $xml=[xml]$event.ToXml(); $fields=@{}; foreach($data in @($xml.Event.EventData.Data)) { if($data.Name) {$fields[$data.Name]=[string]$data.'#text'} }; [pscustomobject]@{RecordId=$event.RecordId;Id=$event.Id;TimeCreated=$event.TimeCreated.ToUniversalTime().ToString('o');Fields=$fields} }) }
  'event_cursor' { [long](Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop).RecordId }
      'audit_policy' { Get-WinFireAuditPolicy }
      'breakglass_start' { Start-WinFireBreakGlass $argsData }
      'breakglass_end' { End-WinFireBreakGlass $argsData }
      'jit_preflight' { Test-WinFireJitGate $argsData }
      'jit_start' { Start-WinFireJitAccess $argsData }
      'jit_end' { End-WinFireJitAccess $argsData }
      'audit_policy_enable' { $before=Get-WinFireAuditPolicy; if($before.successEnabled -and $before.failureEnabled){$before}else{try{auditpol /set '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null; if($LASTEXITCODE -ne 0){throw "auditpol update failed with exit code $LASTEXITCODE"}; $after=Get-WinFireAuditPolicy; if(-not ($after.successEnabled -and $after.failureEnabled)){throw 'Audit policy readback did not confirm success and failure auditing'}; $after}catch{$cause=$_.Exception.Message; $successArg=if($before.successEnabled){'/success:enable'}else{'/success:disable'}; $failureArg=if($before.failureEnabled){'/failure:enable'}else{'/failure:disable'}; auditpol /set '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' $successArg $failureArg | Out-Null; if($LASTEXITCODE -ne 0){throw "Audit policy update failed: $cause; rollback failed with exit code $LASTEXITCODE"}; $restored=Get-WinFireAuditPolicy; if($restored.settingValue -ne $before.settingValue){throw "Audit policy update failed: $cause; rollback readback differs from prior state"}; throw "Audit policy update failed: $cause; prior state restored"}} }
      'rights' { @(Get-WinFireLogonRights) }
      'rights_change' { Set-WinFireLogonRight $argsData }
      default { throw 'Unsupported operation' }
    }
  }
  $result | ConvertTo-Json -Depth 12 -Compress
} finally { Remove-PSSession $session }
`
function nodeCredential(nodeId,credentialId) {
  const rows=all(`SELECT DISTINCT c.* FROM credentials c JOIN credential_assignments a ON a.credential_id=c.id WHERE (a.node_id=? OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=?)) AND (? IS NULL OR c.id=?) ORDER BY CASE WHEN a.source='directory' THEN 1 ELSE 0 END,c.priority`,nodeId,nodeId,credentialId||null,credentialId||null)
  if(!credentialId){
    const directory=one(`SELECT c.* FROM credentials c JOIN directory_connections d ON d.node_credential_id=c.id JOIN nodes n ON n.id=?
      WHERE d.id='default' AND d.enabled=1 AND n.ad_guid IS NOT NULL AND n.ad_enabled=1 AND n.ad_missing=0 AND n.connection_mode='agentless'`,nodeId)
    if(directory&&!rows.some(row=>row.id===directory.id))rows.push(directory)
  }
  if (!rows.length) throw new Error('No credential assigned to node')
  return rows.map(row=>({...row,secret:openSealed(row.encrypted_blob)}))
}
export async function testNodeCredential(node,credentialId){
  if(node.transport==='ssh'){
    const credential=nodeCredential(node.id,credentialId)[0],secret=credential?.secret||{}
    let result
    try{result=await testSshCredential({host:node.fqdn||node.ip||node.hostname,port:secret.port||22,credential:{...credential,secret}})}
    catch(error){recordCredentialAuthFailure({credentialId:credential.id,nodeId:node.id,error,transport:'ssh',operation:'credential_test'});throw error}
    recordCredentialAuthSuccess({credentialId:credential.id,nodeId:node.id,transport:'ssh'});recordNodeSuccess(node.id,'ssh-authenticated')
    return result
  }
  if(node.transport!=='wmi'){
    const account=await remote(node,'auth',{}, {credentialId})
    return {success:true,transport:node.transport||'winrm',account}
  }
  const credential=nodeCredential(node.id,credentialId)[0]
  const input={host:node.fqdn||node.ip||node.hostname,username:credential.username,password:credential.secret.password}
  let result
  try{result=process.platform==='win32'?await wmiProbePowerShell(input):await wmiProbePython(input)}
  catch(error){recordCredentialAuthFailure({credentialId:credential.id,nodeId:node.id,error,transport:'wmi',operation:'credential_test'});error.message=String(error.message).replaceAll(input.password,'[redacted]');throw error}
  if(result?.success!==true||result.transport!=='wmi'||!result.computerName)throw new Error('WMI did not confirm access to Win32_ComputerSystem')
  recordCredentialAuthSuccess({credentialId:credential.id,nodeId:node.id,transport:'wmi'});recordNodeSuccess(node.id,'wmi-authenticated')
  return {success:true,transport:'wmi',account:credential.username,computerName:result.computerName}
}
/**
 * Validate a Windows credential against a host before the host is persisted.
 * This deliberately has no node side effects: callers can use it from add
 * node and discovery forms without creating a triage record on failure.
 */
export async function preflightCredential({host,credential,expectedName=null,wmi=process.platform==='win32'?wmiProbePowerShell:wmiProbePython,winrm=pywinrm,probePort=tcpProbe}={}){
  const target=String(host||'').trim()
  if(!target)throw new Error('A host or IP address is required')
  if(!credential?.username||!credential?.secret?.password)throw new Error('A username and password are required')
  const ports={
    rpc:await probePort(target,135),
    winrm:await probePort(target,5985),
    winrms:await probePort(target,5986)
  }
  const errors=[]
  const password=credential.secret.password
  const expected=expectedName&&String(expectedName).trim()&&!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(String(expectedName).trim())?String(expectedName).trim():null
  try{
    const result=await wmi({host:target,username:credential.username,password,mode:'probe',expectedName:expected})
    if(result?.success!==true||result.transport!=='wmi'||!result.computerName)throw new Error('WMI did not confirm access to Win32_ComputerSystem')
    if(expected&&String(result.computerName).toLowerCase()!==expected.split('.')[0].toLowerCase())throw new Error('WMI computer name does not match the supplied host identity')
    return {success:true,transport:'wmi',account:credential.username,computerName:String(result.computerName),ports}
  }catch(error){
    errors.push(`WMI: ${String(error?.message||error).replaceAll(password,'[redacted]')}`)
  }
  for(const transport of ['winrm','winrms']){
    const port=ports[transport]
    if(port?.status!=='open')continue
    try{
      const result=await winrm({host:target,transport,username:credential.username,password,operation:'auth',args:{}})
      return {success:true,transport,account:credential.username,ports,authentication:typeof result==='string'?undefined:result}
    }catch(error){errors.push(`${transport.toUpperCase()}: ${String(error?.message||error).replaceAll(password,'[redacted]')}`)}
  }
  const portSummary=Object.entries(ports).map(([name,result])=>`${name} ${result?.status||'unknown'}`).join(', ')
  const failure=new Error(`Credential preflight failed for ${target}. ${errors.join('; ')||'No WMI or WinRM endpoint accepted the credential'}. Ports: ${portSummary}`)
  failure.status=502;failure.ports=ports
  attachOnboardingError(failure,{ports,operation:'credential_preflight',message:errors.join('; ')})
  throw failure
}
export async function activateWinrmViaWmi(node,{wmi=process.platform==='win32'?wmiProbePowerShell:wmiProbePython,probePort=tcpProbe,invoke=remote,collect=collectFacts,wait=pause}={}){
  if(node.connection_mode!=='agentless')throw new Error('Only agentless nodes can be activated through WMI')
  const credentials=nodeCredential(node.id)
  if(node.ad_guid){
    const preferred=one("SELECT node_credential_id FROM directory_connections WHERE id='default' AND enabled=1")?.node_credential_id
    if(preferred)credentials.sort((a,b)=>Number(b.id===preferred)-Number(a.id===preferred))
  }
  const host=node.fqdn||node.ip||node.hostname
  const expectedName=isIP(node.hostname)?null:node.hostname
  let selected=null,lastProbeError=null
  for(const credential of credentials){
    const check={host,username:credential.username,password:credential.secret.password,mode:'probe',expectedName}
    try{
      const result=await wmi(check)
      if(result?.success!==true||result.transport!=='wmi'||!result.computerName)throw new Error('WMI did not confirm the computer identity')
      if(expectedName&&String(result.computerName).toLowerCase()!==expectedName.split('.')[0].toLowerCase())throw new Error('WMI computer name does not match the inventory record')
      selected=credential
      break
    }catch(error){lastProbeError=error;error.message=String(error.message).replaceAll(check.password,'[redacted]')}
  }
  if(!selected){
    const failure=attachOnboardingError(lastProbeError||new Error('No assigned credential authenticated over WMI'),{operation:'activate_winrm',transport:'wmi'})
    recordOnboardingFailure(node.id,failure,{operation:'activate_winrm',transport:'wmi'})
    throw failure
  }
  const credentialId=selected.id
  const input={host,username:selected.username,password:selected.secret.password,mode:'enable_winrm',expectedName}
  const applyRunId=id()
  run('INSERT INTO policy_apply_runs(id,node_id,status) VALUES(?,?,?)',applyRunId,node.id,'running')
  audit(null,'node.agentless.activate.start','node',node.id,null,{runId:applyRunId,transport:'wmi'})
  try{
  let activation
  try{activation=await wmi(input)}
  catch(error){error.message=String(error.message).replaceAll(input.password,'[redacted]');throw error}
  if(!activation?.success||!activation.activationStarted)throw new Error('WMI did not confirm the WinRM activation request')
  if(activation.activationSucceeded===false)throw new Error(`WinRM activation command failed on ${node.hostname}: ${String(activation.commandOutput||'no command output').replace(/<Objs[\s\S]*/,'').slice(0,300)}`)
  let lastPort=null
  for(let attempt=0;attempt<12;attempt++){
    await wait(2500)
    const port=await probePort(host,5985,1500)
    lastPort=port
    if(port.status!=='open')continue
    try{
      const managed={...node,transport:'winrm'}
      await invoke(managed,'auth',{}, {credentialId})
      const facts=await invoke(managed,'facts',{}, {credentialId})
      if(String(facts?.computer?.Name||'').toLowerCase()!==String(node.hostname).toLowerCase())throw new Error('WinRM host identity does not match the directory computer')
      run("UPDATE nodes SET transport='winrm',probe_status='winrm-authenticated',status='reachable',last_probe_at=?,last_seen_at=?,next_retry_at=NULL,onboarding_error_code=NULL,onboarding_error_updated_at=NULL WHERE id=?",now(),now(),node.id)
      await collect(managed,{suppliedFacts:facts})
      run('UPDATE policy_apply_runs SET status=?,diff_json=?,finished_at=? WHERE id=?','success',JSON.stringify({operation:'enable_winrm_via_wmi',transport:'winrm',computerName:facts.computer.Name}),now(),applyRunId)
      audit(null,'node.agentless.activate','node',node.id,{transport:node.transport,probeStatus:node.probe_status},{transport:'winrm',credentialId,computerName:facts.computer.Name,runId:applyRunId})
      return {transport:'winrm',status:'reachable',probeStatus:'winrm-authenticated',facts,activation}
    }catch(error){if(attempt===11)throw error}
  }
  let detail=''
  try{
    const diagnostic=process.platform==='win32'?null:await wmi({...input,mode:'diagnose_winrm'})
    if(diagnostic?.winrmService?.State==='Running'&&String(diagnostic.commandOutput||'').includes('ListeningOn ='))detail=' The WinRM service and listener are running; check network ACLs or an effective host firewall block between the control plane and this node.'
  }catch{}
  throw attachOnboardingError(new Error(`WMI started WinRM activation, but TCP 5985 remains ${lastPort?.status||'unreachable'} from the control plane.${detail}`),{operation:'activate_winrm',transport:'winrm',ports:{winrm:lastPort}})
  }catch(error){
    recordOnboardingFailure(node.id,error,{operation:'activate_winrm',transport:'wmi'})
    run('UPDATE policy_apply_runs SET status=?,error=?,finished_at=? WHERE id=?','unknown',error.message,now(),applyRunId)
    audit(null,'node.agentless.activate.failed','node',node.id,null,{runId:applyRunId,error:error.message})
    throw error
  }
}
export async function remote(node,operation,args={},options={}) {
  const capability={auth:'authentication',facts:'facts',rules:'firewallRead',all_rules:'firewallRead',apply:'firewallWrite',events:'events',events_recent:'events',events_probe:'events'}[operation]
  try{
    const result=await remoteOperation(node,operation,args,options)
    if(capability){capabilityEvidence(node.id,capability,node.transport||'unknown');capabilityEvidence(node.id,'authentication',node.transport||'unknown')}
    return result
  }catch(error){if(capability)capabilityEvidence(node.id,capability,node.transport||'unknown',{success:false,code:'operation_failed'});throw error}
}
async function remoteOperation(node,operation,args={},options={}) {
  assertDirectManagement(node)
  if(node.transport==='ssh'){
    if(['jit_preflight','jit_start','jit_end','prompt_session','security_session_logoff','rights','rights_change','wef_configure'].includes(operation))throw new Error('This operation requires an enrolled Windows agent')
    if(!['auth','facts','all_rules','rules','apply','prompt_browser'].includes(operation))throw new Error('SSH transport supports Linux facts, firewall rules, and desktop MFA prompts only')
    if(operation==='apply')assertManagementAccess(args.add||[])
    let lastError
    for(const credential of nodeCredential(node.id,options.credentialId)){
      const secret=credential.secret||{},connection={host:node.fqdn||node.ip||node.hostname,port:secret.port||22,username:credential.username,password:secret.password,privateKey:secret.privateKey,passphrase:secret.passphrase,hostKeyFingerprint:secret.hostKeyFingerprint||secret.hostKey}
      try{
        if(operation==='auth'){const result=await testSshCredential({host:connection.host,port:connection.port,credential:{...credential,secret},probeOnly:true});recordCredentialAuthSuccess({credentialId:credential.id,nodeId:node.id,transport:'ssh'});recordNodeSuccess(node.id,'ssh-authenticated');return result}
        if(operation==='prompt_browser'){
          const result=await launchLinuxPortal(connection,{portalUrl:args.url,preferredUser:args.targetUser||args.username||args.user,browser:args.browser||'xdg-open'})
          run("UPDATE nodes SET connection_mode='agentless',management_type='ssh',transport='ssh',agent_required=0,firewall_state=CASE WHEN firewall_state='enforcing' THEN firewall_state ELSE 'learning' END WHERE id=?",node.id)
          recordCredentialAuthSuccess({credentialId:credential.id,nodeId:node.id,transport:'ssh'});recordNodeSuccess(node.id,'ssh-authenticated');return result
        }
        const result=operation==='facts'?await collectLinuxFacts(connection):operation==='apply'?await applyLinuxFirewall(connection,args):await collectLinuxRules(connection)
        if(operation==='facts'&&!result?.computer?.Name)throw new Error('SSH facts did not return the Linux host identity')
        if(!Array.isArray(result?.rules)&&['rules','all_rules'].includes(operation))throw new Error('SSH firewall inventory returned an invalid result')
        recordCredentialAuthSuccess({credentialId:credential.id,nodeId:node.id,transport:'ssh'});recordNodeSuccess(node.id,'ssh-authenticated');return result
      }catch(error){lastError=error;recordCredentialAuthFailure({credentialId:credential.id,nodeId:node.id,error,transport:'ssh',operation});const secretValues=[secret.password,secret.privateKey,secret.passphrase].filter(Boolean);error.message=secretValues.reduce((text,value)=>text.replaceAll(value,'[redacted]'),String(error.message||error))}
    }
    if(transientError(lastError))recordNodeTransportFailure(node.id)
    throw attachOnboardingError(lastError||new Error('No credential authenticated over SSH'),{operation,transport:'ssh'})
  }
  if(node.transport==='netsh'){
    const eventOperation=['events','events_recent','events_probe','event_cursor'].includes(operation)
    const supported=['auth','facts','audit_policy','audit_policy_enable','all_rules','rules','apply','events','events_recent','events_probe','event_cursor','rpc_filters','rpc_filter_apply','rpc_filter_remove']
    if(!supported.includes(operation))throw new Error('Netsh fallback supports host facts, audit policy, firewall rules and Security events only')
    if(operation==='apply')assertManagementAccess(args.add||[])
    let lastError
    for(const credential of nodeCredential(node.id,options.credentialId)){
      const input={host:node.fqdn||node.ip||node.hostname,username:credential.username,password:credential.secret.password,mode:operation,args,timeoutSeconds:operation==='facts'||eventOperation?60:45}
      try{
        const result=await netshExecPython(input)
        if(operation==='event_cursor'){
          if(!Number.isSafeInteger(result)||result<0)throw new Error('Netsh Security event cursor was invalid')
          recordCredentialAuthSuccess({credentialId:credential.id,nodeId:node.id,transport:'netsh'});recordNodeSuccess(node.id,'netsh-authenticated');return result
        }
        if(result?.success!==true||result.transport!=='netsh'||!result.computerName)throw new Error('Netsh fallback did not confirm the computer identity')
        if(eventOperation&&!Array.isArray(result.eventResult))throw new Error('Netsh Security event query returned an invalid result')
        if(operation==='facts'&&!result.factsResult?.computer?.Name)throw new Error('Netsh facts did not return the computer identity')
        if(['rules','all_rules'].includes(operation)&&!result.ruleResult)throw new Error('Netsh firewall inventory returned an invalid result')
        if(operation==='apply'&&result.applyResult?.applied!==true)throw new Error('Netsh firewall apply was not confirmed')
        if(['rpc_filters','rpc_filter_apply','rpc_filter_remove'].includes(operation)&&!result.rpcFilterResult)throw new Error('Netsh RPC filter operation returned no result')
        recordCredentialAuthSuccess({credentialId:credential.id,nodeId:node.id,transport:'netsh'});recordNodeSuccess(node.id,'netsh-authenticated')
        return operation==='auth'?{success:true,transport:'netsh',account:credential.username,computerName:result.computerName}:operation==='facts'?result.factsResult:operation==='audit_policy'||operation==='audit_policy_enable'?result.auditResult:operation==='apply'?result.applyResult:eventOperation?result.eventResult:['rpc_filters','rpc_filter_apply','rpc_filter_remove'].includes(operation)?result.rpcFilterResult:result.ruleResult
      }catch(error){lastError=error;recordCredentialAuthFailure({credentialId:credential.id,nodeId:node.id,error,transport:'netsh',operation});error.message=String(error.message).replaceAll(credential.secret.password,'[redacted]')}
    }
    if(transientError(lastError))recordNodeTransportFailure(node.id)
    throw attachOnboardingError(lastError||new Error('No credential authenticated over SMB netsh fallback'),{operation,transport:node.transport})
  }
  if(node.transport==='wmi'){
    const eventOperation=['events','events_recent','events_probe','event_cursor'].includes(operation)
    if(['rpc_filters','rpc_filter_apply','rpc_filter_remove'].includes(operation))throw new Error('Native RPC filter management requires WinRM or SMB/netsh; WMI is read-only for this operation')
    if(!['facts','audit_policy','audit_policy_enable','all_rules','rules','apply'].includes(operation)&&!eventOperation)throw new Error('WMI/DCOM supports host facts, audit policy, firewall rules and Security events; other operations require WinRM or an agent')
    if(operation==='apply')assertManagementAccess(args.add||[])
    const host=node.fqdn||node.ip||node.hostname
    const expectedName=isIP(node.hostname)?null:node.hostname
    let lastError
    const credentials=nodeCredential(node.id,options.credentialId)
    if(operation==='apply'||operation==='audit_policy_enable'){
      let selected=null
      for(const credential of credentials){
        const check={host,username:credential.username,password:credential.secret.password,mode:'probe',expectedName}
        try{
          const result=await wmiProbePython(check)
          if(result?.success!==true||result.transport!=='wmi'||!result.computerName||expectedName&&String(result.computerName).toLowerCase()!==expectedName.split('.')[0].toLowerCase())throw new Error('WMI computer identity was not confirmed before policy apply')
          recordCredentialAuthSuccess({credentialId:credential.id,nodeId:node.id,transport:'wmi'});selected=credential
          break
        }catch(error){lastError=error;recordCredentialAuthFailure({credentialId:credential.id,nodeId:node.id,error,transport:'wmi',operation});error.message=String(error.message).replaceAll(check.password,'[redacted]')}
      }
      if(!selected){if(transientError(lastError))recordNodeTransportFailure(node.id);throw attachOnboardingError(lastError||new Error('No credential authenticated over WMI'),{operation,transport:node.transport})}
      const input={host,username:selected.username,password:selected.secret.password,mode:operation,args,expectedName}
      try{
        const result=await wmiProbePython(input)
        if(result?.success!==true||result.transport!=='wmi'||(operation==='apply'?result.applyResult?.applied!==true:result.auditResult?.successEnabled!==true||result.auditResult?.failureEnabled!==true)||expectedName&&String(result.computerName).toLowerCase()!==expectedName.split('.')[0].toLowerCase())throw new Error('WMI write returned no confirmed host readback; inspect host state before retrying')
        recordCredentialAuthSuccess({credentialId:selected.id,nodeId:node.id,transport:'wmi'});recordNodeSuccess(node.id,'wmi-authenticated')
        return operation==='apply'?result.applyResult:result.auditResult
      }catch(error){
        error.message=String(error.message).replaceAll(input.password,'[redacted]')
        if(transientError(error))recordNodeTransportFailure(node.id)
        throw attachOnboardingError(error,{operation,transport:node.transport}) // The host may have applied the change; the caller must read back before retrying.
      }
    }
    for(const credential of credentials){
      const input={host,username:credential.username,password:credential.secret.password,mode:operation,args,expectedName}
      try{
        const result=await wmiProbePython(input)
        if(result?.success!==true||result.transport!=='wmi'||!result.computerName||!(eventOperation?'eventResult' in result:operation==='facts'?'factsResult' in result:operation==='audit_policy'?'auditResult' in result:'ruleResult' in result))throw new Error('WMI query did not return an authenticated result')
        if(expectedName&&String(result.computerName).toLowerCase()!==expectedName.split('.')[0].toLowerCase())throw new Error('WMI computer name does not match the inventory record')
        if(eventOperation){
          if(operation==='event_cursor'?!Number.isSafeInteger(result.eventResult)||result.eventResult<0:!Array.isArray(result.eventResult))throw new Error('WMI Security event query returned an invalid result')
        }else if(operation==='facts'){
          if(!result.factsResult?.computer?.Name||!result.factsResult?.os?.Version||String(result.factsResult.computer.Name).toLowerCase()!==String(result.computerName).toLowerCase())throw new Error('WMI facts did not match the authenticated host')
        }else if(operation==='audit_policy'){
          if(!Number.isInteger(result.auditResult?.settingValue)||typeof result.auditResult?.successEnabled!=='boolean'||typeof result.auditResult?.failureEnabled!=='boolean')throw new Error('WMI audit policy returned an invalid result')
        }else if(operation==='rules'?!Array.isArray(result.ruleResult):!Array.isArray(result.ruleResult?.rules)||!Number.isInteger(result.ruleResult?.total))throw new Error('WMI firewall inventory returned an invalid rule page')
        recordCredentialAuthSuccess({credentialId:credential.id,nodeId:node.id,transport:'wmi'});recordNodeSuccess(node.id,'wmi-authenticated')
        return eventOperation?result.eventResult:operation==='facts'?result.factsResult:operation==='audit_policy'?result.auditResult:result.ruleResult
      }catch(error){lastError=error;recordCredentialAuthFailure({credentialId:credential.id,nodeId:node.id,error,transport:'wmi',operation});error.message=String(error.message).replaceAll(input.password,'[redacted]')}
    }
    if(transientError(lastError))recordNodeTransportFailure(node.id)
    throw attachOnboardingError(lastError||new Error('No credential authenticated over WMI'),{operation,transport:node.transport})
  }
  const host=node.fqdn || node.ip || node.hostname
  let lastError
  for (const credential of nodeCredential(node.id,options.credentialId)) {
    const input={host,transport:node.transport||'winrm',osVersion:node.os_version||null,username:credential.username,password:credential.secret.password,operation,args}
    const mutating=operation==='apply'||operation.startsWith('breakglass_')||operation==='jit_start'||operation==='jit_end'||operation==='prompt_browser'||operation==='rights_change'||operation==='audit_policy_enable'||operation==='agent_deploy'||operation==='security_session_logoff'||operation==='rpc_filter_apply'||operation==='rpc_filter_remove'||operation==='wef_configure'
    const attempts=mutating?1:2
    for(let attempt=0;attempt<attempts;attempt++){
      try {
        const script=remoteScript.replace('__WINFIRE_PROMPT_FUNCTIONS__',operation.startsWith('prompt_')||operation==='security_session_logoff'?mfaPromptFunctions:'').replace('__WINFIRE_AGENT_DEPLOY__',operation==='agent_deploy'?agentDeployFunctions:'').replace('__WINFIRE_SECURITY_PROCESS_OWNER__',operation.startsWith('security_')?securityProcessOwnerFunctions:'').replace('# __WINFIRE_LSA_RIGHTS__',operation.startsWith('rights')||operation.startsWith('jit_')?lsaRightsFunctions:'').replace('# __WINFIRE_ACCOUNT_INVENTORY__',()=>operation==='account_inventory'?accountInventoryFunctions:'').replace('# __WINFIRE_FIREWALL_USER__',()=>['rules','apply'].includes(operation)?firewallUserFunctions:'')
        const legacy=/^(?:5\.[12]\.|6\.[01]\.|windows (?:xp|vista|7\b|server 2003|server 2008))/i.test(String(input.osVersion||''))
        const result=process.platform==='win32'&&!legacy&&operation!=='auth' ? await pwsh(script,input) : await pywinrm(input)
        recordCredentialAuthSuccess({credentialId:credential.id,nodeId:node.id,transport:input.transport||'winrm'});recordNodeSuccess(node.id,input.transport==='winrms'?'winrms-authenticated':'winrm-authenticated')
        return result
      }
      catch(error) {
        lastError=error
        recordCredentialAuthFailure({credentialId:credential.id,nodeId:node.id,error,transport:input.transport||'winrm',operation})
        if(!transientError(error))break
        if(mutating){
          recordNodeTransportFailure(node.id)
          throw attachOnboardingError(error,{operation,transport:input.transport}) // Outcome may be ambiguous; re-read state before retrying.
        }
        if(attempt+1<attempts)await pause(300*(attempt+1))
      }
    }
  }
  if(transientError(lastError))recordNodeTransportFailure(node.id)
  throw attachOnboardingError(lastError||new Error('No credential authenticated over WinRM'),{operation,transport:node.transport})
}
export function classifyProbe(transport,rpc,winrmAuthenticated=false,netshAuthenticated=false,sshAuthenticated=false) {
  if(sshAuthenticated&&transport==='ssh')return {status:'reachable',probeStatus:'ssh-authenticated'}
  if(transport==='wmi')return typeof rpc==='string'?{status:'reachable',probeStatus:'rpc-authenticated'}:{status:'unverified',probeStatus:'rpc-unverified'}
  if(transport==='netsh'&&netshAuthenticated)return {status:'reachable',probeStatus:'netsh-authenticated'}
  if(winrmAuthenticated&&['winrm','winrms'].includes(transport))return {status:'reachable',probeStatus:`${transport}-authenticated`}
  if(transport)return {status:'port-open',probeStatus:'port-open'}
  return {status:'unreachable',probeStatus:'unreachable'}
}
export async function probeNode(node,{verifyWinrm=true,probePort=tcpProbe,authenticate=remote,authenticateRpc=rpcProbe,authenticateNetsh=netshProbe,authenticateSsh=remote}={}) {
  assertDirectManagement(node)
  const host=node.fqdn || node.ip || node.hostname
  const [winrm,winrms,wmi,smb,ssh]=await Promise.all([probePort(host,5985),probePort(host,5986),probePort(host,135),probePort(host,445),probePort(host,22)])
  const candidates=[['winrms',winrms],['winrm',winrm]].filter(([,port])=>port.status==='open')
  let transport=candidates[0]?.[0]||null
  let rpc=null
  let winrmAuthenticated=false,winrmError=null,netshAuthenticated=false,netshError=null,sshAuthenticated=false,sshError=null
  if(verifyWinrm){
    for(const [candidate] of candidates){
      try{await authenticate({...node,transport:candidate},'auth');transport=candidate;winrmAuthenticated=true;break}
      catch(error){winrmError=[winrmError,error.message].filter(Boolean).join('; ')}
    }
  }
  if(!winrmAuthenticated&&wmi.status==='open'){
    try{rpc=await authenticateRpc(host,node.id)}catch(error){rpc={error:error.message}}
    if(typeof rpc==='string'||!transport)transport='wmi'
  }
  if(!winrmAuthenticated&&smb.status==='open'&&!(transport==='wmi'&&typeof rpc==='string')){
    try{await authenticateNetsh(host,node.id);transport='netsh';netshAuthenticated=true}
    catch(error){netshError=error.message}
  }
  const linuxHint=['linux','unix','macos','freebsd'].some(value=>String(node.os_name||node.platform||node.discovery_os_family||'').toLowerCase().includes(value))||node.management_type==='ssh'||node.transport==='ssh'
  if(!winrmAuthenticated&&!netshAuthenticated&&ssh.status==='open'&&(linuxHint||node.transport==='ssh'||node.device_type==='linux')){
    try{await authenticateSsh({...node,transport:'ssh'},'auth');transport='ssh';sshAuthenticated=true}catch(error){sshError=error.message}
  }
  const {status,probeStatus}=classifyProbe(transport,rpc,winrmAuthenticated,netshAuthenticated,sshAuthenticated),probedAt=now()
  const ports={winrm,winrms,wmi,smb,ssh},diagnostic=[winrmError,netshError,sshError,rpc?.error].filter(Boolean).join('; ')
  const onboardingError=status==='reachable'?null:classifyOnboardingError(new Error(diagnostic||'No supported management port responded'),{operation:'probe',transport,ports})
  run('UPDATE nodes SET transport=?,status=?,probe_status=?,last_probe_at=?,last_seen_at=?,failures=?,next_retry_at=NULL,onboarding_error_code=?,onboarding_error_updated_at=? WHERE id=?',transport,status,probeStatus,probedAt,transport?probedAt:node.last_seen_at,transport?0:(node.failures||0)+1,onboardingError?.code||null,onboardingError?probedAt:null,node.id)
  audit(null,'node.probe','node',node.id,null,{transport,status,probeStatus})
  return {transport,status,probeStatus,ports,rpc,winrmAuthenticated,winrmError,netshAuthenticated,netshError,sshAuthenticated,sshError,onboardingError,note:transport==='wmi'?'RPC authentication checked; WMI firewall and Security log access need a credentialed query.':netshAuthenticated?'SMB service execution authenticated; netsh is being used as the legacy fallback.':sshAuthenticated?'SSH authentication confirmed and Linux management is available.':winrmAuthenticated?'WinRM authentication confirmed.':transport?'A management port responded, but authentication was not confirmed.':'No supported management port responded.'}
}
export async function collectFacts(node,{credentialId,suppliedFacts}={}) {
  assertDirectManagement(node)
  const facts=suppliedFacts||await remote(node,'facts',{}, {credentialId})
  run('INSERT INTO node_facts(node_id,snapshot_json,collected_at) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET snapshot_json=excluded.snapshot_json,collected_at=excluded.collected_at',node.id,JSON.stringify(facts),now())
  const osName=classifyOperatingSystem({caption:facts?.os?.Caption,version:facts?.os?.Version,build:facts?.os?.BuildNumber}),infrastructure=classifyInfrastructureFacts(facts),rawMac=String(facts?.network?.find(adapter=>adapter?.macAddress)?.macAddress||'').trim().toLowerCase().replaceAll('-',':'),macAddress=/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(rawMac)&&rawMac!=='00:00:00:00:00:00'?rawMac:null,managedAt=now()
  run('UPDATE nodes SET mac_address=COALESCE(?,mac_address),os_version=?,os_build=?,os_name=COALESCE(?,os_name),vendor=COALESCE(?,vendor),classification_evidence_json=COALESCE(?,classification_evidence_json),hypervisor=COALESCE(?,hypervisor),manageability=COALESCE(?,manageability),snmp_capable=CASE WHEN ? IS NULL THEN snmp_capable ELSE ? END,last_seen_at=?,last_managed_at=?,status=?,onboarding_error_code=NULL,onboarding_error_updated_at=NULL WHERE id=?',macAddress,facts?.os?.Version||null,facts?.os?.BuildNumber||null,osName,infrastructure?.vendor||null,infrastructure?.classificationEvidence?JSON.stringify(infrastructure.classificationEvidence):null,infrastructure?.hypervisorName||infrastructure?.hypervisor||null,infrastructure?.manageability||null,infrastructure?.snmpCapable===undefined?null:infrastructure.snmpCapable,infrastructure?.snmpCapable===undefined?null:infrastructure.snmpCapable,managedAt,managedAt,'reachable',node.id)
  if(node.connection_mode==='agentless'&&node.transport==='ssh')run("UPDATE nodes SET connection_mode='agentless',management_type='ssh',device_type=CASE WHEN device_type IS NULL OR device_type='auto' THEN 'linux' ELSE device_type END,agent_required=0,firewall_state='learning',firewall_backend=COALESCE(?,firewall_backend),collect_network_tables=1,manageability='managed' WHERE id=?",facts?.firewall?.backend||null,node.id)
  if(node.connection_mode==='agentless'&&['winrm','winrms'].includes(node.transport)){
    try{const {collectAccountInventory}=await import('./localAccounts.js');await collectAccountInventory(node)}
    catch(error){audit(null,'local-accounts.collect.failed','node',node.id,null,{error:error.message})}
  }
  return facts
}
export async function enrichNode(node,{probeNodeFn=probeNode,activate=activateWinrmViaWmi,collect=collectFacts}={}) {
  if(node.connection_mode==='agent')throw new Error('Agent nodes require agent-reported facts')
  const probe=await probeNodeFn(node)
  if(probe.transport==='wmi'){
    const managed={...node,transport:'wmi'}
    if(probe.probeStatus!=='rpc-authenticated'){
      // rpcclient is only a preliminary probe. When it is unavailable or
      // blocked, verify the directory credential directly through WMI before
      // attempting to change the host's WinRM configuration.
      try {
        const facts=await collect(managed)
        run("UPDATE nodes SET transport='wmi',status='reachable',probe_status='wmi-authenticated',last_probe_at=?,last_seen_at=?,next_retry_at=NULL WHERE id=?",now(),now(),node.id)
        return facts
      } catch(error) {
        audit(null,'node.agentless.wmi-fallback','node',node.id,null,{credentialedWmiError:error.message})
        throw error
      }
    }
    try{return (await activate(managed)).facts}
    catch(error){
      audit(null,'node.agentless.wmi-fallback','node',node.id,null,{winrmActivationError:error.message})
      // A credentialed WMI read is sufficient for agentless management when
      // WinRM cannot be enabled. This also covers hosts where rpcclient is
      // unavailable or blocked even though DCOM/WMI accepts the directory
      // credential.
      try {
        const facts=await collect(managed)
        run("UPDATE nodes SET transport='wmi',status='reachable',probe_status='wmi-authenticated',last_probe_at=?,last_seen_at=?,next_retry_at=NULL WHERE id=?",now(),now(),node.id)
        return facts
      } catch(fallbackError) {
        const activationMessage=String(error.message),fallbackMessage=String(fallbackError.message)
        fallbackError.message=activationMessage===fallbackMessage?fallbackMessage:`${activationMessage}; credentialed WMI facts failed: ${fallbackMessage}`
        if(error.onboardingError) fallbackError.onboardingError=error.onboardingError
        else attachOnboardingError(fallbackError,{operation:'activate_winrm',transport:'wmi'})
        throw fallbackError
      }
    }
  }
  if(probe.transport==='netsh')return collect(one('SELECT * FROM nodes WHERE id=?',node.id))
  if(!['winrm','winrms'].includes(probe.transport))throw new Error('No working WinRM transport for inventory collection')
  return collect(one('SELECT * FROM nodes WHERE id=?',node.id))
}
export async function lookupDns(node,resolver=dns) {
  let forward=[],reverse=[]
  try {forward=await resolver.lookup(node.fqdn || node.hostname,{all:true})} catch {}
  // Directory computer objects contain a name, not an address. Resolve that
  // name before checking its PTR so the inventory and source-IP matching work.
  const ipv4=[...new Set(forward.filter(result=>result.family===4).map(result=>result.address))]
  const ipv6=[...new Set(forward.filter(result=>result.family===6).map(result=>result.address))]
  const resolvedIp=ipv4.length===1?ipv4[0]:ipv4.length===0&&ipv6.length===1?ipv6[0]:null
  const ownsAddress=node.inventory_source==='ad'
  const ip=(ownsAddress||!node.ip)&&resolvedIp?resolvedIp:node.ip
  if(ip!==node.ip)run('UPDATE nodes SET ip=? WHERE id=?',ip,node.id)
  if (ip) try {reverse=await resolver.reverse(ip)} catch {}
  const expected=(node.fqdn||node.hostname).toLowerCase().replace(/\.$/,'')
  const ptrMissing=!!(ip&&!reverse.length)
  const ptrMismatch=!!(reverse.length&&!reverse.some(name=>name.toLowerCase().replace(/\.$/,'')===expected))
  const forwardMismatch=!!(ip&&forward.length&&!forward.some(address=>address.address===ip))
  const mismatch=ptrMissing||ptrMismatch||forwardMismatch
  run('INSERT INTO dns_lookups(node_id,forward_result,reverse_result,mismatch,checked_at) VALUES(?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET forward_result=excluded.forward_result,reverse_result=excluded.reverse_result,mismatch=excluded.mismatch,checked_at=excluded.checked_at',node.id,JSON.stringify(forward),JSON.stringify(reverse),Number(mismatch),now())
  return {forward,reverse,mismatch,ptrMissing,ptrMismatch,forwardMismatch,ip}
}
export function diffRules(desired,actual) {
  const normalizeAddress=value=>String(value||'Any').split(',').map(part=>{
    const match=part.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}|\d{1,3}(?:\.\d{1,3}){3}))?$/)
    if(!match)return part.trim().toLowerCase()
    if(!match[2])return `${match[1]}/255.255.255.255`
    if(match[2].includes('.'))return `${match[1]}/${match[2]}`
    if(Number(match[2])>32)return part.trim().toLowerCase()
    const prefix=Number(match[2]),mask=prefix===0?0:(0xffffffff<<(32-prefix))>>>0
    const address=match[1].split('.').map(Number).reduce((value,octet)=>(value<<8)|octet,0)>>>0
    return `${[24,16,8,0].map(shift=>((address&mask)>>>shift)&255).join('.')}/${[24,16,8,0].map(shift=>(mask>>>shift)&255).join('.')}`
  }).sort().join(',')
  const comparable=r=>JSON.stringify([r.name,r.action,r.direction==='inbound'?'in':r.direction==='outbound'?'out':r.direction,r.protocol,r.localPort,r.remotePort||'Any',normalizeAddress(r.remoteAddress),r.program,r.profile,r.localUserSid||''].map(x=>String(x).toLowerCase()))
  const wanted=new Map(desired.map(r=>[r.name,comparable(r)])), present=new Map((actual||[]).map(r=>[r.name,comparable(r)]))
  return {remove:[...present.keys()].filter(name=>!wanted.has(name)||wanted.get(name)!==present.get(name)),add:desired.filter(r=>!present.has(r.name)||present.get(r.name)!==wanted.get(r.name))}
}
export async function applyRules(node,policyId,rules) {
  assertManagementAccess(rules)
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
