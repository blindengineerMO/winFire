"""Small WSMan transport for the Node control plane. Reads one JSON request on stdin."""
import base64
import json
import os
import sys
from pathlib import Path

import winrm


POWERSHELL = r'''
$ErrorActionPreference = 'Stop'
$argsData = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())) | ConvertFrom-Json
$operation = '__OPERATION__'
function Get-WinFireAuditPolicy {
  if(-not ('WinFireAuditPolicyQuery' -as [type])) {
    $source='using System; using System.ComponentModel; using System.Runtime.InteropServices; public static class WinFireAuditPolicyQuery { [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.U1)] private static extern bool AuditQuerySystemPolicy([In] Guid[] ids, uint count, out IntPtr policy); [DllImport("advapi32.dll")] private static extern void AuditFree(IntPtr policy); public static int Read(string text) { Guid id=new Guid(text); IntPtr policy; if(!AuditQuerySystemPolicy(new Guid[]{id},1,out policy)) throw new Win32Exception(Marshal.GetLastWin32Error()); try { if(policy==IntPtr.Zero || Marshal.PtrToStructure<Guid>(policy)!=id) throw new InvalidOperationException("Audit policy query returned an unexpected subcategory"); return Marshal.ReadInt32(policy,16); } finally { if(policy!=IntPtr.Zero) AuditFree(policy); } } }'
    Add-Type -TypeDefinition $source -ErrorAction Stop
  }
  $setting=[WinFireAuditPolicyQuery]::Read('0CCE9226-69AE-11D9-BED3-505054503030')
  [pscustomobject]@{subcategoryGuid='0CCE9226-69AE-11D9-BED3-505054503030';settingValue=$setting;successEnabled=[bool]($setting -band 1);failureEnabled=[bool]($setting -band 2)}
}
# __WINFIRE_LSA_RIGHTS__
$result = switch ($operation) {
  'auth' { [Security.Principal.WindowsIdentity]::GetCurrent().Name }
  'tcp_probe' {
    $client=[System.Net.Sockets.TcpClient]::new();$watch=[Diagnostics.Stopwatch]::StartNew();$status='unreachable'
    try {
      $task=$client.ConnectAsync([string]$argsData.host,[int]$argsData.port)
      if($task.Wait([Math]::Min(5000,[Math]::Max(250,[int]$argsData.timeoutMs)))){$status='open'}else{$status='timeout'}
    } catch {
      $cause=$_.Exception;while($cause.InnerException){$cause=$cause.InnerException}
      if($cause -is [System.Net.Sockets.SocketException] -and $cause.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused){$status='refused'}
    } finally {$watch.Stop();$client.Dispose()}
    [pscustomobject]@{status=$status;latencyMs=$watch.ElapsedMilliseconds}
  }
  'facts' {
    $computer = Get-CimInstance Win32_ComputerSystem
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $biosInfo = Get-CimInstance Win32_BIOS
    $adapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
      [pscustomobject]@{description=$_.Description;macAddress=$_.MACAddress;ipAddresses=@($_.IPAddress);subnets=@($_.IPSubnet);gateways=@($_.DefaultIPGateway);dnsServers=@($_.DNSServerSearchOrder);dnsDomain=$_.DNSDomain;dnsSuffixes=@($_.DNSDomainSuffixSearchOrder);dhcpEnabled=$_.DHCPEnabled;dhcpServer=$_.DHCPServer}
    })
    $lastUser=$null; $machineGuid=$null; $machineSid=$null
    try {$lastUser=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -ErrorAction Stop).LastLoggedOnUser} catch {}
    try {$machineGuid=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction Stop).MachineGuid} catch {}
    try {$admin=Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-500'" | Select-Object -First 1; if($admin){$machineSid=$admin.SID -replace '-500$',''}} catch {}
    [pscustomobject]@{
      computer = $computer | Select-Object Name,Model,Manufacturer,Domain,PartOfDomain,UserName
      bios = $biosInfo | Select-Object SerialNumber
      os = $osInfo | Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime
      identity = [pscustomobject]@{machineGuid=$machineGuid;localMachineSid=$machineSid;domainJoined=[bool]$computer.PartOfDomain;domainName=$computer.Domain;sessionLogonServer=$env:LOGONSERVER;currentInteractiveUser=$computer.UserName;lastLoggedOnUser=$lastUser}
      network = $adapters
      dnsSuffixes = @($adapters | ForEach-Object { @($_.dnsSuffixes)+@($_.dnsDomain) } | Where-Object { $_ } | Select-Object -Unique)
      firewall = @(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction)
      service = Get-Service MpsSvc | Select-Object Status
    }
  }
  'all_rules' {
    $offset=[Math]::Max(0,[int]$argsData.offset); $limit=[Math]::Min(200,[Math]::Max(1,[int]$argsData.limit))
    $total=(Get-NetFirewallRule | Measure-Object).Count
    $page=@(Get-NetFirewallRule | Select-Object -Skip $offset -First $limit | ForEach-Object {
      $r=$_; $p=$r | Get-NetFirewallPortFilter; $a=$r | Get-NetFirewallAddressFilter; $app=$r | Get-NetFirewallApplicationFilter
      [pscustomobject]@{name=$r.Name;displayName=$r.DisplayName;group=$r.Group;enabled=[bool]($r.Enabled -eq 'True');action=[string]$r.Action;direction=[string]$r.Direction;profile=[string]$r.Profile;protocol=[string]$p.Protocol;localPort=[string]$p.LocalPort;remotePort=[string]$p.RemotePort;remoteAddress=[string]$a.RemoteAddress;program=[string]$app.Program;source=[string]$r.PolicyStoreSourceType}
    })
    [pscustomobject]@{total=$total;offset=$offset;rules=$page}
  }
  'rules' {
    @(Get-NetFirewallRule -Group $argsData.group -ErrorAction SilentlyContinue | ForEach-Object {
      $r = $_; $p = $r | Get-NetFirewallPortFilter
      $a = $r | Get-NetFirewallAddressFilter; $app = $r | Get-NetFirewallApplicationFilter
      [pscustomobject]@{
        name = $r.DisplayName; group = $r.Group
        action = ([string]$r.Action).ToLower(); direction = $(if($r.Direction -eq 'Inbound'){'in'}else{'out'})
        protocol = [string]$p.Protocol; localPort = [string]$p.LocalPort; remotePort = [string]$p.RemotePort
        remoteAddress = [string]$a.RemoteAddress; program = [string]$app.Program
        profile = [string]$r.Profile
      }
    })
  }
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
      foreach($name in $created){try{if(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue){Remove-NetFirewallRule -Name $name -ErrorAction Stop}}catch{$rollbackErrors+=,"remove new rule ${name}: $($_.Exception.Message)"}}
      foreach($r in $old){
        try{if(-not (Get-NetFirewallRule -Name $r.internalName -ErrorAction SilentlyContinue)){New-NetFirewallRule -DisplayName $r.name -Group $argsData.group -Direction $r.direction -Action $r.action -Protocol $r.protocol -LocalPort $r.localPort -RemotePort $r.remotePort -RemoteAddress $r.remoteAddress -Program $r.program -Profile $r.profile -ErrorAction Stop | Out-Null}}
        catch{$rollbackErrors+=,"restore old rule $($r.name): $($_.Exception.Message)"}
      }
      if($rollbackErrors.Count){throw "Firewall apply failed: $($applyError.Exception.Message); rollback incomplete: $($rollbackErrors -join '; ')"}
      throw $applyError
    }
    @{applied = $true}
  }
  'events' {
    $after=[long]$argsData.after
    $xpath="*[System[((EventID=5156 or EventID=5157 or EventID=5150 or EventID=5151 or EventID=4624 or EventID=4625 or EventID=5712) and EventRecordID > $after)]]"
    @(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object {
      $event=$_; $xml=[xml]$event.ToXml(); $fields=@{}
      foreach($data in @($xml.Event.EventData.Data)) { if($data.Name) {$fields[$data.Name]=[string]$data.'#text'} }
      [pscustomobject]@{RecordId=$event.RecordId;Id=$event.Id;TimeCreated=$event.TimeCreated.ToUniversalTime().ToString('o');Fields=$fields}
    })
  }
  'audit_policy' { Get-WinFireAuditPolicy }
  'audit_policy_enable' {
    $before=Get-WinFireAuditPolicy
    if($before.successEnabled -and $before.failureEnabled){$before}
    else {
      try {
        auditpol /set '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
        if($LASTEXITCODE -ne 0){throw "auditpol update failed with exit code $LASTEXITCODE"}
        $after=Get-WinFireAuditPolicy
        if(-not ($after.successEnabled -and $after.failureEnabled)){throw 'Audit policy readback did not confirm success and failure auditing'}
        $after
      } catch {
        $cause=$_.Exception.Message
        $successArg=if($before.successEnabled){'/success:enable'}else{'/success:disable'}
        $failureArg=if($before.failureEnabled){'/failure:enable'}else{'/failure:disable'}
        auditpol /set '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' $successArg $failureArg | Out-Null
        if($LASTEXITCODE -ne 0){throw "Audit policy update failed: $cause; rollback failed with exit code $LASTEXITCODE"}
        $restored=Get-WinFireAuditPolicy
        if($restored.settingValue -ne $before.settingValue){throw "Audit policy update failed: $cause; rollback readback differs from prior state"}
        throw "Audit policy update failed: $cause; prior state restored"
      }
    }
  }
  'rights' { @(Get-WinFireLogonRights) }
  default { throw 'Unsupported operation' }
}
$result | ConvertTo-Json -Depth 12 -Compress
'''

SHARED_POWERSHELL = r'''
$ErrorActionPreference='Stop'
$argsData=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())) | ConvertFrom-Json
__WINFIRE_SHARED_FUNCTIONS__
$result=__WINFIRE_CALL__
$result | ConvertTo-Json -Depth 12 -Compress
'''


def main():
    payload = json.load(sys.stdin)
    operation = payload['operation']
    if operation not in {'auth', 'tcp_probe', 'facts', 'all_rules', 'rules', 'apply', 'events', 'audit_policy', 'audit_policy_enable', 'rights', 'breakglass_start', 'breakglass_end', 'jit_preflight', 'jit_start', 'jit_end', 'prompt_browser', 'prompt_session'}:
        raise ValueError('Unsupported operation')
    host = payload['host']
    secure = payload.get('transport') == 'winrms'
    endpoint = f"{'https' if secure else 'http'}://{host}:{5986 if secure else 5985}/wsman"
    args = base64.b64encode(json.dumps(payload.get('args') or {}).encode()).decode()
    shared_root = Path(__file__).resolve().parents[2] / 'packages' / 'shared'
    calls = {'jit_preflight':'Test-WinFireJitGate $argsData','jit_start':'Start-WinFireJitAccess $argsData','jit_end':'End-WinFireJitAccess $argsData',
             'breakglass_start':'Start-WinFireBreakGlass $argsData','breakglass_end':'End-WinFireBreakGlass $argsData',
             'prompt_browser':'Open-WinFireMfaPortal $argsData','prompt_session':'@(Get-WinFireActiveSession)'}
    if operation in calls:
        source = 'jitAccess.ps1' if operation.startswith('jit_') else 'mfaPrompt.ps1' if operation.startswith('prompt_') else 'breakGlass.ps1'
        script = SHARED_POWERSHELL.replace('__WINFIRE_SHARED_FUNCTIONS__',(shared_root / source).read_text()).replace('__WINFIRE_CALL__',calls[operation])
    else:
        script = POWERSHELL.replace('__OPERATION__', operation).replace('# __WINFIRE_LSA_RIGHTS__', (Path(__file__).resolve().parent / 'lsa_rights.ps1').read_text() if operation == 'rights' else '')
    script = script.replace('[Console]::In.ReadToEnd()', f"'{args}'")
    session = winrm.Session(
        endpoint,
        auth=(payload['username'], payload['password']),
        transport='ntlm',
        server_cert_validation='ignore' if os.environ.get('WINRM_TLS_VERIFY') == 'false' else 'validate',
        read_timeout_sec=90 if operation in calls else 45 if operation == 'rights' else 25,
        operation_timeout_sec=80 if operation in calls else 40 if operation == 'rights' else 20,
    )
    loader = "$encoded=[Console]::In.ReadToEnd(); Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded)))"
    encoded_loader = base64.b64encode(loader.encode('utf-16le')).decode()
    encoded_script = base64.b64encode(script.encode('utf-16le'))
    protocol = session.protocol
    shell_id = protocol.open_shell()
    try:
        command_id = protocol.run_command(shell_id, 'powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded_loader])
        try:
            protocol.send_command_input(shell_id, command_id, encoded_script, end=True)
            stdout, stderr, status = protocol.get_command_output(shell_id, command_id)
        finally:
            protocol.cleanup_command(shell_id, command_id)
    finally:
        protocol.close_shell(shell_id)
    if status != 0:
        raise RuntimeError(stderr.decode('utf-8', 'replace').strip() or f'WinRM exited {status}')
    output = stdout.decode('utf-8-sig').strip()
    if operation == 'rights' and (not output or output == 'null'):
        raise RuntimeError('LSA logon-rights query returned no data; baseline was not collected')
    print(output or 'null')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'WinRM operation failed: {exc}', file=sys.stderr)
        sys.exit(1)
