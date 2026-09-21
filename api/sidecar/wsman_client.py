"""Small WSMan transport for the Node control plane. Reads one JSON request on stdin."""
import base64
import gzip
import json
import os
import re
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
# __WINFIRE_ACCOUNT_INVENTORY__
# __WINFIRE_FIREWALL_USER__
$result = switch ($operation) {
  'account_inventory' { Get-WinFireAccountInventory $argsData }
  'auth' { [Security.Principal.WindowsIdentity]::GetCurrent().Name }
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
        internalName = $r.Name; name = $r.DisplayName; group = $r.Group
        action = ([string]$r.Action).ToLower(); direction = $(if($r.Direction -eq 'Inbound'){'in'}else{'out'})
        protocol = [string]$p.Protocol; localPort = [string]$p.LocalPort; remotePort = [string]$p.RemotePort
        remoteAddress = [string]$a.RemoteAddress; program = [string]$app.Program
        profile = [string]$r.Profile; localUserSid = Get-WinFireLocalUserSid $r
      }
    })
  }
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
      foreach($name in $created){try{if(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue){Remove-NetFirewallRule -Name $name -ErrorAction Stop}}catch{$rollbackErrors+=,"remove new rule ${name}: $($_.Exception.Message)"}}
      foreach($r in $old){
        try{if(-not (Get-NetFirewallRule -Name $r.internalName -ErrorAction SilentlyContinue)){New-WinFireFirewallRule $r $argsData.group | Out-Null}}
        catch{$rollbackErrors+=,"restore old rule $($r.name): $($_.Exception.Message)"}
      }
      if($rollbackErrors.Count){throw "Firewall apply failed: $($applyError.Exception.Message); rollback incomplete: $($rollbackErrors -join '; ')"}
      throw $applyError
    }
    @{applied = $true}
  }
  'events' {
    $after=[long]$argsData.after
    $xpath="*[System[((EventID=5156 or EventID=5157 or EventID=5150 or EventID=5151 or EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=5712) and EventRecordID > $after)]]"
    @(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object {
      $event=$_; $xml=[xml]$event.ToXml(); $fields=@{}
      foreach($data in @($xml.Event.EventData.Data)) { if($data.Name) {$fields[$data.Name]=[string]$data.'#text'} }
      [pscustomobject]@{RecordId=$event.RecordId;Id=$event.Id;TimeCreated=$event.TimeCreated.ToUniversalTime().ToString('o');Fields=$fields}
    })
  }
  'events_recent' {
    $firewall=@(Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=5156 or EventID=5157 or EventID=5150 or EventID=5151)]]' -MaxEvents 500 -ErrorAction SilentlyContinue)
    $other=@(Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=5712)]]' -MaxEvents 100 -ErrorAction SilentlyContinue)
    @($firewall+$other | Sort-Object RecordId | ForEach-Object {
      $event=$_; $xml=[xml]$event.ToXml(); $fields=@{}
      foreach($data in @($xml.Event.EventData.Data)) { if($data.Name) {$fields[$data.Name]=[string]$data.'#text'} }
      [pscustomobject]@{RecordId=$event.RecordId;Id=$event.Id;TimeCreated=$event.TimeCreated.ToUniversalTime().ToString('o');Fields=$fields}
    })
  }
  'events_probe' {
    @(Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=5157]]' -MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object {
      $event=$_; $xml=[xml]$event.ToXml(); $fields=@{}
      foreach($data in @($xml.Event.EventData.Data)) { if($data.Name) {$fields[$data.Name]=[string]$data.'#text'} }
      [pscustomobject]@{RecordId=$event.RecordId;Id=$event.Id;TimeCreated=$event.TimeCreated.ToUniversalTime().ToString('o');Fields=$fields}
    })
  }
  'event_cursor' { [long](Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop).RecordId }
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
  'rights_change' { Set-WinFireLogonRight $argsData }
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


def legacy_ps2(session, payload):
    """PowerShell 2 compatible operations for XP through Server 2008 R2."""
    operation = payload['operation']
    if operation == 'auth':
        script = '[Security.Principal.WindowsIdentity]::GetCurrent().Name'
    elif operation == 'facts':
        script = (Path(__file__).resolve().parent / 'wmi_facts.ps1').read_text()
    elif operation == 'account_inventory':
        source = (Path(__file__).resolve().parent / 'account_inventory.ps1').read_text()
        sids = [str(item) for item in (payload.get('args') or {}).get('sids', []) if isinstance(item, str) and len(item) <= 128][:500]
        encoded = ','.join("'" + base64.b64encode(item.encode()).decode() + "'" for item in sids)
        script = source + "\n$values=@(" + encoded + ");$sids=@($values | ForEach-Object {[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))});$result=Get-WinFireAccountInventory (New-Object PSObject -Property @{sids=$sids});function Enc($value){[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$value))};Write-Output ('HOST|'+(Enc $result.computerName)+'|'+(Enc $result.domainController));foreach($item in @($result.accounts)){Write-Output ('ACCOUNT|'+((@($item.sid,$item.username,$item.fullName,$item.description,$item.enabled,$item.locked,$item.passwordRequired) | ForEach-Object {Enc $_}) -join '|'))};foreach($item in @($result.resolutions)){Write-Output ('SID|'+(Enc $item.sid)+'|'+(Enc $item.qualifiedName))}\n"
    elif operation in {'rights', 'rights_change'}:
        source = (Path(__file__).resolve().parent / 'lsa_rights.ps1').read_text()
        if operation == 'rights':
            script = source + '\nGet-WinFireLogonRights\n'
        else:
            args = payload.get('args') or {}
            sid = base64.b64encode(str(args.get('accountSid') or '').encode()).decode()
            right = base64.b64encode(str(args.get('right') or '').encode()).decode()
            present = '$true' if args.get('present') else '$false'
            script = source + f"\n$sid=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{sid}'));$right=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{right}'));$result=Set-WinFireLogonRight @{{accountSid=$sid;right=$right;present={present}}};Write-Output ($result.accountSid+'|'+$result.right+'|'+$result.before+'|'+$result.present+'|'+$result.changed)\n"
    elif operation == 'all_rules' and windows_dialect(payload.get('osVersion')) == 'xp':
        args = payload.get('args') or {}
        offset = min(1000000, max(0, int(args.get('offset') or 0)))
        limit = min(200, max(1, int(args.get('limit') or 100)))
        source = (Path(__file__).resolve().parent / 'xp_firewall.ps1').read_text()
        script = source + f'\nGet-WinFireXpRules {offset} {limit}\n'
    elif operation in {'events', 'events_recent', 'events_probe', 'event_cursor'} and windows_dialect(payload.get('osVersion')) == 'xp':
        after = int((payload.get('args') or {}).get('after') or 0)
        if after < 0 or after > 9223372036854775807:
            raise ValueError('Invalid event cursor')
        source = (Path(__file__).resolve().parent / 'xp_events.ps1').read_text()
        script = source + f"\nGet-WinFireXpEvents '{operation}' {after}\n"
    elif operation in {'all_rules', 'rules', 'apply'} and windows_dialect(payload.get('osVersion')) == 'advfirewall':
        args = payload.get('args') or {}
        group = str(args.get('group') or '')
        if operation in {'rules', 'apply'} and not re.fullmatch(r'WinFireSecure:[A-Za-z0-9_.:-]{1,160}', group):
            raise ValueError('Managed firewall group is required')
        offset = min(1000000, max(0, int(args.get('offset') or 0))) if operation == 'all_rules' else 0
        limit = min(200, max(1, int(args.get('limit') or 100))) if operation == 'all_rules' else 10000
        group_encoded = base64.b64encode(group.encode('utf-8')).decode('ascii')
        source = (Path(__file__).resolve().parent / 'legacy_firewall.ps1').read_text()
        if operation == 'apply':
            script = legacy_apply_script(args, group)
        else:
            script = source + f"\n$group=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{group_encoded}'));Get-WinFireLegacyRules '{operation}' $group {offset} {limit}\n"
    else:
        raise RuntimeError(f'{operation} is unavailable on this older Windows host; firewall writes require a compatible adapter')
    # LSA P/Invoke source exceeds Windows' command-line limit. Send a short
    # PowerShell 2 loader, then stream the compressed script through stdin.
    loader = "$encoded=[Console]::In.ReadToEnd();$bytes=[Convert]::FromBase64String($encoded);$buffer=New-Object IO.MemoryStream;$buffer.Write($bytes,0,$bytes.Length);$buffer.Position=0;$zip=New-Object IO.Compression.GzipStream -ArgumentList $buffer,([IO.Compression.CompressionMode]::Decompress);$reader=New-Object IO.StreamReader -ArgumentList $zip,([Text.Encoding]::UTF8);try{Invoke-Expression $reader.ReadToEnd()}finally{$reader.Dispose();$zip.Dispose();$buffer.Dispose()}"
    encoded_loader = base64.b64encode(loader.encode('utf-16le')).decode()
    encoded_script = base64.b64encode(gzip.compress(script.encode('utf-8')))
    protocol = session.protocol
    shell_id = protocol.open_shell()
    try:
        command_id = protocol.run_command(shell_id, 'powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded_loader])
        try:
            for offset in range(0, len(encoded_script), 4096):
                protocol.send_command_input(shell_id, command_id, encoded_script[offset:offset + 4096], end=offset + 4096 >= len(encoded_script))
            stdout, stderr, status = protocol.get_command_output(shell_id, command_id)
        finally:
            protocol.cleanup_command(shell_id, command_id)
    finally:
        protocol.close_shell(shell_id)
    if status != 0:
        raise RuntimeError(stderr.decode('utf-8', 'replace').strip() or f'Older Windows WinRM operation exited {status}')
    output = stdout.decode('utf-8-sig', 'replace').strip()
    if operation == 'auth':
        return output
    if operation in {'events', 'events_recent', 'events_probe', 'event_cursor'}:
        return parse_legacy_events(output, operation)
    if operation in {'all_rules', 'rules'}:
        return parse_legacy_firewall(output, operation)
    if operation == 'apply':
        if output != 'APPLIED|true':
            raise RuntimeError('Older Windows firewall apply returned no success confirmation')
        return {'applied': True}
    if operation == 'rights':
        if not output:
            raise RuntimeError('LSA logon-rights query returned no data')
        return output.splitlines()
    if operation == 'rights_change':
        parts = output.splitlines()[-1].split('|')
        if len(parts) != 5:
            raise RuntimeError('LSA change returned an invalid response')
        return {'accountSid':parts[0], 'right':parts[1], 'before':parts[2].lower() == 'true', 'present':parts[3].lower() == 'true', 'changed':parts[4].lower() == 'true'}
    if operation == 'account_inventory':
        inventory = {'computerName':None,'domainController':False,'accounts':[],'resolutions':[]}
        for line in output.splitlines():
            parts = line.split('|')
            if parts[0] not in {'HOST','ACCOUNT','SID'}:
                continue
            values = [base64.b64decode(value).decode('utf-8', 'replace') for value in parts[1:]]
            if parts[0] == 'HOST' and len(values) == 2:
                inventory['computerName'],inventory['domainController'] = values[0],values[1].lower() == 'true'
            elif parts[0] == 'ACCOUNT' and len(values) == 7:
                inventory['accounts'].append({'sid':values[0],'username':values[1],'fullName':values[2],'description':values[3],'enabled':values[4].lower() == 'true','locked':values[5].lower() == 'true','passwordRequired':values[6].lower() == 'true'})
            elif parts[0] == 'SID' and len(values) == 2:
                inventory['resolutions'].append({'sid':values[0],'qualifiedName':values[1]})
        if inventory['computerName'] is None:
            raise RuntimeError('Account inventory returned no host record')
        return inventory
    return parse_legacy_facts(output)


def parse_legacy_events(output, operation):
    if operation == 'event_cursor':
        if not re.fullmatch(r'CURSOR\|\d+', output):
            raise RuntimeError('Legacy Security event cursor returned an invalid response')
        return int(output.split('|', 1)[1])
    events = []
    allowed = {528, 540, 529, 530, 531, 532, 533, 534, 535, 536, 537, 539, 538, 551}
    for line in output.splitlines():
        parts = line.split('|')
        if len(parts) != 5 or parts[0] != 'XPEVENT' or not parts[1].isdigit() or not parts[2].isdigit():
            raise RuntimeError('Legacy Security event returned an invalid frame')
        record_id, event_id = int(parts[1]), int(parts[2])
        if record_id < 0 or event_id not in allowed:
            raise RuntimeError('Legacy Security event returned an unexpected ID')
        try:
            from datetime import datetime
            datetime.fromisoformat(parts[3].replace('Z', '+00:00'))
            sid = base64.b64decode(parts[4], validate=True).decode('utf-8')
        except (ValueError, UnicodeError) as error:
            raise RuntimeError('Legacy Security event returned invalid data') from error
        if sid and not re.fullmatch(r'S-1-\d+(?:-\d+)+', sid):
            raise RuntimeError('Legacy Security event returned an invalid SID')
        events.append({'RecordId': record_id, 'Id': event_id, 'TimeCreated': parts[3],
                       'Fields': {'TargetUserSid': sid} if sid else {}})
    if len(events) > 500 or any(events[index]['RecordId'] >= events[index + 1]['RecordId'] for index in range(len(events) - 1)):
        raise RuntimeError('Legacy Security event page is not ordered or exceeds 500 records')
    return events


def parse_legacy_facts(output):
    fields = {}
    adapters = []
    for line in output.splitlines():
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        decoded = base64.b64decode(value).decode('utf-8', 'replace')
        if key == 'NET':
            parts = decoded.split('|')
            if len(parts) == 6:
                adapters.append({'description':parts[0], 'macAddress':parts[1], 'ipAddresses':parts[2].split(',') if parts[2] else [], 'gateways':parts[3].split(',') if parts[3] else [], 'dnsServers':parts[4].split(',') if parts[4] else [], 'dnsDomain':parts[5]})
        else:
            fields[key] = decoded
    return {'computer':{'Name':fields.get('NAME'), 'Domain':fields.get('DOMAIN'), 'PartOfDomain':fields.get('JOINED', '').lower() == 'true', 'UserName':fields.get('USER'), 'Model':fields.get('MODEL'), 'Manufacturer':fields.get('MANUFACTURER')},
            'os':{'Caption':fields.get('CAPTION'), 'Version':fields.get('VERSION'), 'BuildNumber':fields.get('BUILD'), 'OSArchitecture':fields.get('ARCH')},
            'bios':{'SerialNumber':fields.get('SERIAL')}, 'identity':{'machineGuid':fields.get('GUID'), 'domainJoined':fields.get('JOINED', '').lower() == 'true', 'domainName':fields.get('DOMAIN'), 'currentInteractiveUser':fields.get('USER')},
            'network':adapters, 'dnsSuffixes':[item['dnsDomain'] for item in adapters if item['dnsDomain']], 'firewall':[], 'service':None}


def validate_legacy_apply(args, group):
    add = args.get('add') or []
    remove = args.get('remove') or []
    if not isinstance(add, list) or not isinstance(remove, list) or len(add) + len(remove) > 500:
        raise ValueError('Invalid legacy firewall diff size')
    fields = ('name', 'action', 'direction', 'protocol', 'localPort', 'remotePort', 'remoteAddress', 'program', 'profile')
    normalized = []
    for raw in add:
        if not isinstance(raw, dict) or raw.get('localUserSid') or (raw.get('group') and raw['group'] != group):
            raise ValueError('Unsupported legacy firewall rule scope')
        rule = {field: str(raw.get(field) or 'Any') for field in fields}
        if not 1 <= len(rule['name']) <= 180 or '|' in rule['name'] or '\n' in rule['name']:
            raise ValueError('Invalid legacy firewall rule name')
        for field, allowed in [('action', {'allow', 'block'}), ('direction', {'in', 'out'}),
                               ('protocol', {'TCP', 'UDP', 'Any'}), ('profile', {'Any', 'Domain', 'Private', 'Public'})]:
            if rule[field] not in allowed:
                raise ValueError(f'Invalid legacy firewall {field}')
        if rule['protocol'] == 'Any' and (rule['localPort'] != 'Any' or rule['remotePort'] != 'Any'):
            raise ValueError('Specific ports require TCP or UDP')
        for field in ('localPort', 'remotePort'):
            expression = rule[field]
            if expression == 'Any':
                continue
            if not re.fullmatch(r'[0-9,-]+', expression) or any(
                not all(1 <= int(value) <= 65535 for value in part.split('-')) or
                (len(part.split('-')) == 2 and int(part.split('-')[0]) > int(part.split('-')[1])) or
                len(part.split('-')) > 2
                for part in expression.split(',') if part
            ) or ',,' in expression or expression.startswith(',') or expression.endswith(','):
                raise ValueError(f'Invalid legacy firewall {field}')
        if len(rule['remoteAddress']) > 2000 or len(rule['program']) > 1024:
            raise ValueError('Legacy firewall rule field is too long')
        normalized.append(rule)
    if len({rule['name'] for rule in normalized}) != len(normalized):
        raise ValueError('Duplicate legacy firewall rule names')
    if any(not isinstance(name, str) or not 1 <= len(name) <= 180 for name in remove) or len(set(remove)) != len(remove):
        raise ValueError('Invalid legacy firewall removal names')
    return normalized, remove


def legacy_apply_script(args, group):
    add, remove = validate_legacy_apply(args, group)
    source = (Path(__file__).resolve().parent / 'legacy_firewall.ps1').read_text()
    group_encoded = base64.b64encode(group.encode('utf-8')).decode('ascii')
    script = source + "\nfunction Dec($s){[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))}\n"
    script += f"$group=Dec '{group_encoded}';$add=@();$remove=@()\n"
    for rule in add:
        entries = ';'.join(f"{key}=(Dec '{base64.b64encode(value.encode('utf-8')).decode('ascii')}')" for key, value in rule.items())
        script += f"$add+=,(New-Object PSObject -Property @{{{entries}}})\n"
    for name in remove:
        script += f"$remove+=,(Dec '{base64.b64encode(name.encode('utf-8')).decode('ascii')}')\n"
    return script + 'Set-WinFireLegacyRules $group $add $remove\n'


def parse_legacy_firewall(output, operation):
    header = None
    rules = []
    for line in output.splitlines():
        parts = line.split('|')
        if parts[0] == 'HEADER' and len(parts) == 3:
            header = (int(parts[1]), int(parts[2]))
        elif parts[0] == 'RULE' and len(parts) == 13:
            values = [base64.b64decode(value, validate=True).decode('utf-8') for value in parts[1:]]
            if values[3].lower() not in {'true', 'false'} or values[4] not in {'allow', 'block'} or values[5] not in {'in', 'out'}:
                raise RuntimeError('Older Windows firewall rule returned an invalid state, action, or direction')
            rules.append({'internalName': values[0], 'name': values[1], 'displayName': values[1],
                          'group': values[2], 'enabled': values[3].lower() == 'true',
                          'action': values[4], 'direction': values[5], 'protocol': values[6],
                          'localPort': values[7], 'remotePort': values[8],
                          'remoteAddress': values[9], 'program': values[10],
                          'profile': values[11], 'localUserSid': None, 'source': 'Local'})
        elif line.strip():
            raise RuntimeError('Older Windows firewall inventory returned an invalid record')
    if header is None or len(rules) > header[0] or (operation == 'rules' and len(rules) != header[0]):
        raise RuntimeError('Older Windows firewall inventory returned an invalid header')
    if operation == 'rules':
        return rules
    return {'total': header[0], 'offset': header[1], 'rules': rules}


def windows_dialect(value):
    version = str(value or '').strip().lower()
    if 'windows xp' in version or 'windows server 2003' in version or version.startswith(('5.1.', '5.2.')):
        return 'xp'
    if any(label in version for label in ('windows vista', 'windows 7', 'windows server 2008')) or version.startswith(('6.0.', '6.1.')):
        return 'advfirewall'
    return 'netsecurity'


def main():
    payload = json.load(sys.stdin)
    operation = payload['operation']
    if operation not in {'auth', 'tcp_probe', 'facts', 'all_rules', 'rules', 'apply', 'events', 'events_recent', 'events_probe', 'event_cursor', 'audit_policy', 'audit_policy_enable', 'rights', 'rights_change', 'account_inventory', 'breakglass_start', 'breakglass_end', 'jit_preflight', 'jit_start', 'jit_end', 'prompt_browser', 'prompt_session', 'agent_deploy', 'security_process_owner', 'security_session_logoff'}:
        raise ValueError('Unsupported operation')
    host = payload['host']
    secure = payload.get('transport') == 'winrms'
    endpoint = f"{'https' if secure else 'http'}://{host}:{5986 if secure else 5985}/wsman"
    slow = operation.startswith(('rights', 'jit_', 'breakglass_', 'prompt_')) or operation in {'agent_deploy','security_session_logoff'}
    session = winrm.Session(
        endpoint,
        auth=(payload['username'], payload['password']),
        transport='ntlm',
        server_cert_validation='ignore' if os.environ.get('WINRM_TLS_VERIFY') == 'false' else 'validate',
        read_timeout_sec=90 if slow else 25,
        operation_timeout_sec=80 if slow else 20,
    )
    os_version = str(payload.get('osVersion') or '')
    if not os_version and operation in {'facts', 'rights', 'rights_change', 'account_inventory', 'all_rules', 'rules', 'apply', 'events', 'events_recent', 'events_probe', 'event_cursor'}:
        detected = session.run_ps('(Get-WmiObject Win32_OperatingSystem).Caption')
        if detected.status_code == 0:
            os_version = detected.std_out.decode('utf-8-sig', 'replace').strip()
    payload['osVersion'] = os_version
    if operation == 'auth' or windows_dialect(os_version) != 'netsecurity':
        print(json.dumps(legacy_ps2(session, payload)))
        return
    args = base64.b64encode(json.dumps(payload.get('args') or {}).encode()).decode()
    shared_root = Path(__file__).resolve().parents[2] / 'packages' / 'shared'
    calls = {'jit_preflight':'Test-WinFireJitGate $argsData','jit_start':'Start-WinFireJitAccess $argsData','jit_end':'End-WinFireJitAccess $argsData',
             'breakglass_start':'Start-WinFireBreakGlass $argsData','breakglass_end':'End-WinFireBreakGlass $argsData',
             'prompt_browser':'Open-WinFireMfaPortal $argsData','prompt_session':'@(Get-WinFireActiveSession)',
             'agent_deploy':'Install-WinFireAgentRemote $argsData','security_process_owner':'Get-WinFireProcessOwner $argsData',
             'security_session_logoff':'End-WinFireClientSession $argsData'}
    if operation in calls:
        source = (Path(__file__).resolve().parent / ('agent_deploy.ps1' if operation == 'agent_deploy' else 'security_process_owner.ps1')) if operation in {'agent_deploy','security_process_owner','security_session_logoff'} else shared_root / ('jitAccess.ps1' if operation.startswith('jit_') else 'mfaPrompt.ps1' if operation.startswith('prompt_') else 'breakGlass.ps1')
        functions = source.read_text()
        if operation.startswith('jit_'):
            functions = (Path(__file__).resolve().parent / 'lsa_rights.ps1').read_text() + '\n' + functions
        if operation == 'security_session_logoff':
            functions = (shared_root / 'mfaPrompt.ps1').read_text() + '\n' + functions
        script = SHARED_POWERSHELL.replace('__WINFIRE_SHARED_FUNCTIONS__',functions).replace('__WINFIRE_CALL__',calls[operation])
    else:
        script = POWERSHELL.replace('__OPERATION__', operation).replace('# __WINFIRE_LSA_RIGHTS__', (Path(__file__).resolve().parent / 'lsa_rights.ps1').read_text() if operation.startswith('rights') else '').replace('# __WINFIRE_ACCOUNT_INVENTORY__', (Path(__file__).resolve().parent / 'account_inventory.ps1').read_text() if operation == 'account_inventory' else '').replace('# __WINFIRE_FIREWALL_USER__', (Path(__file__).resolve().parent / 'firewall_user.ps1').read_text() if operation in {'rules','apply'} else '')
    script = script.replace('[Console]::In.ReadToEnd()', f"'{args}'")
    loader = "$encoded=[Console]::In.ReadToEnd();$buffer=[IO.MemoryStream]::new([Convert]::FromBase64String($encoded));$zip=[IO.Compression.GzipStream]::new($buffer,[IO.Compression.CompressionMode]::Decompress);$reader=[IO.StreamReader]::new($zip,[Text.Encoding]::UTF8);try{Invoke-Expression $reader.ReadToEnd()}finally{$reader.Dispose();$zip.Dispose();$buffer.Dispose()}"
    encoded_loader = base64.b64encode(loader.encode('utf-16le')).decode()
    encoded_script = base64.b64encode(gzip.compress(script.encode('utf-8')))
    protocol = session.protocol
    shell_id = protocol.open_shell()
    try:
        command_id = protocol.run_command(shell_id, 'powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded_loader])
        try:
            # Keep WS-Man input envelopes small. Even compressed scripts may
            # exceed a host's per-envelope input limit when sent at once.
            for offset in range(0, len(encoded_script), 4096):
                chunk = encoded_script[offset:offset + 4096]
                protocol.send_command_input(shell_id, command_id, chunk, end=offset + 4096 >= len(encoded_script))
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
