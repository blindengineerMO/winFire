function Get-WinFireJitIdentity($grantId) {
  $guid=[guid]::Parse([string]$grantId)
  $base=[string]$env:ProgramData
  if(-not $base){$base=[IO.Path]::GetTempPath()}
  $root=Join-Path $base 'WinFire\Jit'
  [pscustomobject]@{group=('WinFireSecure:JIT:'+$guid.ToString('D'));task=('WinFireJIT-'+$guid.ToString('D'));root=$root;cleanup=(Join-Path $root ($guid.ToString('D')+'.ps1'))}
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
  $lsaReady=$true
  if($data.accountSid) {
    $sid=[string]$data.accountSid;$allow=[string]$data.allowRight;$deny=[string]$data.denyRight
    if($sid -notmatch '^S-1-\d+-\d+(?:-\d+)+$' -or $allow -notin @('SeNetworkLogonRight','SeRemoteInteractiveLogonRight') -or $deny -notin @('SeDenyNetworkLogonRight','SeDenyRemoteInteractiveLogonRight')) {throw 'Invalid JIT LSA scope'}
    $lines=@(Get-WinFireLogonRights)
    $lsaReady=Test-WinFireLogonRight $lines $sid $deny
  }
  [pscustomobject]@{safe=($closed -and $overlaps.Count -eq 0 -and $lsaReady);profileReady=$closed;lsaReady=$lsaReady;profiles=$profiles;conflictingAllows=$allows;conflictingBlocks=$blocks;ports=$ports}
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
  $lsa=$null
  if($data.accountSid) {
    $lines=@(Get-WinFireLogonRights)
    $lsa=[pscustomobject]@{accountSid=[string]$data.accountSid;allowRight=[string]$data.allowRight;denyRight=[string]$data.denyRight;allowWasPresent=(Test-WinFireLogonRight $lines ([string]$data.accountSid) ([string]$data.allowRight));denyWasPresent=(Test-WinFireLogonRight $lines ([string]$data.accountSid) ([string]$data.denyRight))}
    if(-not $lsa.denyWasPresent){throw 'The enforced LSA deny baseline is missing'}
  }
  New-Item -ItemType Directory -Path $identity.root -Force -ErrorAction Stop | Out-Null
  $cleanupFunctions=''
  if($lsa){$cleanupFunctions='function Get-WinFireLogonRights {'+${function:Get-WinFireLogonRights}.ToString()+"}`r`nfunction Test-WinFireLogonRight {"+${function:Test-WinFireLogonRight}.ToString()+"}`r`nfunction Set-WinFireLogonRight {"+${function:Set-WinFireLogonRight}.ToString()+"}`r`n"}
  $cleanup='$ErrorActionPreference="Continue"'+"`r`n"+$cleanupFunctions
  if($lsa) {
    $cleanup+='$sid="'+$lsa.accountSid+'"; Set-WinFireLogonRight ([pscustomobject]@{accountSid=$sid;right="'+$lsa.allowRight+'";present=$'+([string]$lsa.allowWasPresent).ToLower()+'}) | Out-Null; Set-WinFireLogonRight ([pscustomobject]@{accountSid=$sid;right="'+$lsa.denyRight+'";present=$'+([string]$lsa.denyWasPresent).ToLower()+'}) | Out-Null'+"`r`n"
  }
  $cleanup+='Get-NetFirewallRule -Group "'+$identity.group+'" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue'+"`r`n"+'Unregister-ScheduledTask -TaskName "'+$identity.task+'" -Confirm:$false -ErrorAction SilentlyContinue'+"`r`n"+'Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue'
  [IO.File]::WriteAllText($identity.cleanup,$cleanup,[Text.Encoding]::Unicode)
  $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$identity.cleanup+'"')
  $trigger=New-ScheduledTaskTrigger -Once -At $expiry.LocalDateTime
  $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable
  $registered=$false
  $lsaChanged=$false
  try {
    Register-ScheduledTask -TaskName $identity.task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
    $registered=$true
    if($lsa) {
      Set-WinFireLogonRight ([pscustomobject]@{accountSid=$lsa.accountSid;right=$lsa.denyRight;present=$false}) | Out-Null
      Set-WinFireLogonRight ([pscustomobject]@{accountSid=$lsa.accountSid;right=$lsa.allowRight;present=$true}) | Out-Null
      $lsaChanged=$true
    }
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
    [pscustomobject]@{active=$true;group=$identity.group;task=$identity.task;ports=$ports;expiresAt=$expiry.UtcDateTime.ToString('o');lsaTemporary=[bool]$lsa}
  } catch {
    $cause=$_
    Get-NetFirewallRule -Group $identity.group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    if($lsa -and $lsaChanged) {
      try{Set-WinFireLogonRight ([pscustomobject]@{accountSid=$lsa.accountSid;right=$lsa.allowRight;present=$lsa.allowWasPresent}) | Out-Null}catch{}
      try{Set-WinFireLogonRight ([pscustomobject]@{accountSid=$lsa.accountSid;right=$lsa.denyRight;present=$lsa.denyWasPresent}) | Out-Null}catch{}
    }
    if($registered) {Unregister-ScheduledTask -TaskName $identity.task -Confirm:$false -ErrorAction SilentlyContinue}
    Remove-Item -LiteralPath $identity.cleanup -Force -ErrorAction SilentlyContinue
    throw $cause
  }
}
function End-WinFireJitAccess($data) {
  $identity=Get-WinFireJitIdentity $data.grantId
  if($data.accountSid -and (Test-Path -LiteralPath $identity.cleanup)) {& $identity.cleanup}
  else {
    Get-NetFirewallRule -Group $identity.group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
    if(Get-ScheduledTask -TaskName $identity.task -ErrorAction SilentlyContinue) {Unregister-ScheduledTask -TaskName $identity.task -Confirm:$false -ErrorAction Stop}
    Remove-Item -LiteralPath $identity.cleanup -Force -ErrorAction SilentlyContinue
  }
  if(@(Get-NetFirewallRule -Group $identity.group -ErrorAction SilentlyContinue).Count -ne 0) {throw 'JIT firewall rule remains after removal'}
  if(Get-ScheduledTask -TaskName $identity.task -ErrorAction SilentlyContinue) {throw 'JIT expiry task remains after removal'}
  if(Test-Path -LiteralPath $identity.cleanup) {throw 'JIT cleanup script remains after removal'}
  $lsaRestored=$null
  if($data.accountSid) {
    $lines=@(Get-WinFireLogonRights)
    $lsaRestored=(Test-WinFireLogonRight $lines ([string]$data.accountSid) ([string]$data.denyRight)) -and -not (Test-WinFireLogonRight $lines ([string]$data.accountSid) ([string]$data.allowRight))
    if(-not $lsaRestored){throw 'JIT LSA deny baseline was not restored'}
  }
  [pscustomobject]@{revoked=$true;group=$identity.group;lsaRestored=$lsaRestored}
}
