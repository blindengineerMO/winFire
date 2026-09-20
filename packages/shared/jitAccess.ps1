function Get-WinFireJitIdentity($grantId) {
  $guid=[guid]::Parse([string]$grantId)
  [pscustomobject]@{group=('WinFireSecure:JIT:'+$guid.ToString('D'));task=('WinFireJIT-'+$guid.ToString('D'))}
}
function Get-WinFireJitPorts($data) {
  $values=@($data.port)
  if($null -ne $data.ports) {$values+=@($data.ports)}
  $ports=New-Object 'System.Collections.Generic.List[int]'
  foreach($value in $values) {
    if($null -eq $value -or [string]$value -notmatch '^\d{1,5}$') {throw 'Invalid JIT port'}
    $port=[int]$value
    if($port -lt 1 -or $port -gt 65535) {throw 'Invalid JIT port'}
    if(-not $ports.Contains($port)) {$ports.Add($port)}
  }
  if($ports.Count -gt 101) {throw 'Too many JIT ports'}
  return @($ports.ToArray())
}
function Test-WinFireJitGate($data) {
  $ports=@(Get-WinFireJitPorts $data)
  $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [pscustomobject]@{Name=[string]$_.Name;Enabled=($_.Enabled -eq 'True');DefaultInboundAction=[string]$_.DefaultInboundAction} })
  $closed=$profiles.Count -eq 3 -and @($profiles | Where-Object { -not $_.Enabled -or $_.DefaultInboundAction -ne 'Block' }).Count -eq 0
  $overlaps=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -ErrorAction Stop | Where-Object { $_.Group -notlike 'WinFireSecure:JIT:*' -and $_.Group -ne 'WinFireSecure:system-loopback' } | ForEach-Object {
    $rule=$_
    $filter=$rule | Get-NetFirewallPortFilter
    $protocol=[string]$filter.Protocol
    if($protocol -notin @('TCP','6','Any')) {return}
    $matched=$false
    foreach($port in $ports) {
      foreach($part in @($filter.LocalPort | ForEach-Object { [string]$_ -split '[,\s]+' })) {
        $token=$part.Trim()
        if($token -eq 'Any' -or $token -eq [string]$port) {$matched=$true;break}
        if($token -match '^(\d+)-(\d+)$') {
          if($port -ge [int]$Matches[1] -and $port -le [int]$Matches[2]) {$matched=$true;break}
          continue
        }
        if($token -notmatch '^\d+$') {$matched=$true;break}
      }
      if($matched){break}
    }
    if($matched) {[pscustomobject]@{name=$rule.DisplayName;group=$rule.Group;action=[string]$rule.Action}}
  } | Select-Object -First 20)
  $allows=@($overlaps | Where-Object action -eq 'Allow')
  $blocks=@($overlaps | Where-Object action -eq 'Block')
  [pscustomobject]@{safe=($closed -and $overlaps.Count -eq 0);profileReady=$closed;profiles=$profiles;conflictingAllows=$allows;conflictingBlocks=$blocks;ports=$ports}
}
function Start-WinFireJitAccess($data) {
  $identity=Get-WinFireJitIdentity $data.grantId
  $ports=@(Get-WinFireJitPorts $data)
  $expiry=[datetimeoffset]::Parse([string]$data.expiresAt)
  if($expiry.UtcDateTime -le [datetime]::UtcNow.AddMinutes(1) -or $expiry.UtcDateTime -gt [datetime]::UtcNow.AddDays(8)) {throw 'JIT expiry is outside the allowed window'}
  $source=[ipaddress]::None
  if(-not [ipaddress]::TryParse([string]$data.sourceIp,[ref]$source)) {throw 'JIT source must be one IP address'}
  if(Get-ScheduledTask -TaskName $identity.task -ErrorAction SilentlyContinue) {throw 'JIT grant already exists on host'}
  if(@(Get-NetFirewallRule -Group $identity.group -ErrorAction SilentlyContinue).Count) {throw 'JIT firewall rule already exists on host'}
  $gate=Test-WinFireJitGate $data
  if(-not $gate.safe) {throw 'MFA firewall preflight failed: inbound profile defaults or overlapping active rules do not permit a scoped temporary grant'}
  $cleanup='$ErrorActionPreference="Stop"; Get-NetFirewallRule -Group "'+$identity.group+'" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop; Unregister-ScheduledTask -TaskName "'+$identity.task+'" -Confirm:$false -ErrorAction SilentlyContinue'
  $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanup))
  $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
  $trigger=New-ScheduledTaskTrigger -Once -At $expiry.LocalDateTime
  $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable
  $registered=$false
  try {
    Register-ScheduledTask -TaskName $identity.task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
    $registered=$true
    New-NetFirewallRule -DisplayName ('WinFire MFA '+$identity.group) -Group $identity.group -Direction Inbound -Action Allow -Protocol TCP -LocalPort $ports -RemoteAddress ([string]$source) -Profile Any -ErrorAction Stop | Out-Null
    $readback=@(Get-NetFirewallRule -Group $identity.group -ErrorAction Stop)
    if($readback.Count -ne 1) {throw 'JIT rule readback did not confirm one rule'}
    $portFilter=$readback[0] | Get-NetFirewallPortFilter -ErrorAction Stop
    $addressFilter=$readback[0] | Get-NetFirewallAddressFilter -ErrorAction Stop
    $actualPorts=@($portFilter.LocalPort | ForEach-Object { [string]$_ -split '[,\s]+' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $expectedPorts=@($ports | ForEach-Object { [string]$_ })
    if([string]$portFilter.Protocol -notin @('TCP','6') -or
      (($actualPorts | Sort-Object) -join ',') -ne (($expectedPorts | Sort-Object) -join ',') -or
      @($addressFilter.RemoteAddress).Count -ne 1 -or [string]$addressFilter.RemoteAddress -ne [string]$source) {
      throw 'JIT rule readback did not confirm TCP port and source IP scope'
    }
    [pscustomobject]@{active=$true;group=$identity.group;task=$identity.task;ports=$ports;expiresAt=$expiry.UtcDateTime.ToString('o')}
  } catch {
    $cause=$_
    Get-NetFirewallRule -Group $identity.group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    if($registered) {Unregister-ScheduledTask -TaskName $identity.task -Confirm:$false -ErrorAction SilentlyContinue}
    throw $cause
  }
}
function End-WinFireJitAccess($data) {
  $identity=Get-WinFireJitIdentity $data.grantId
  Get-NetFirewallRule -Group $identity.group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
  if(Get-ScheduledTask -TaskName $identity.task -ErrorAction SilentlyContinue) {Unregister-ScheduledTask -TaskName $identity.task -Confirm:$false -ErrorAction Stop}
  if(@(Get-NetFirewallRule -Group $identity.group -ErrorAction SilentlyContinue).Count -ne 0) {throw 'JIT firewall rule remains after removal'}
  if(Get-ScheduledTask -TaskName $identity.task -ErrorAction SilentlyContinue) {throw 'JIT expiry task remains after removal'}
  [pscustomobject]@{revoked=$true;group=$identity.group}
}
