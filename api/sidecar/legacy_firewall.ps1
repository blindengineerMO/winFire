# Windows Firewall with Advanced Security adapter for PowerShell 2 hosts.
# Only rules with WinFire-generated names inside the requested group are changed.
$ErrorActionPreference='Stop'
function Get-WinFireLegacyPolicy { New-Object -ComObject HNetCfg.FwPolicy2 }
function New-WinFireLegacyRuleObject { New-Object -ComObject HNetCfg.FWRule }
function Get-WinFireLegacyRuleCollection($policy) { @($policy.Rules) }
function Add-WinFireLegacyRule($policy,$rule) { $null=$policy.Rules.Add($rule) }
function Remove-WinFireLegacyRule($policy,$name) { $null=$policy.Rules.Remove($name) }
function Encode-WinFireField($value) {
  [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$value))
}
function Get-WinFireLegacyProfile($mask) {
  $number=[int64]$mask
  if($number -eq 2147483647 -or ($number -band 7) -eq 7){return 'Any'}
  $names=@()
  if($number -band 1){$names+=,'Domain'}
  if($number -band 2){$names+=,'Private'}
  if($number -band 4){$names+=,'Public'}
  if(-not $names.Count){return 'Any'}
  return ($names -join ', ')
}
function Get-WinFireLegacyRules($operation,$group,$offset,$limit) {
  $policy=Get-WinFireLegacyPolicy
  $all=@(Get-WinFireLegacyRuleCollection $policy)
  if($operation -eq 'rules'){$all=@($all | Where-Object { [string]$_.Grouping -ceq $group })}
  $total=$all.Count
  Write-Output ('HEADER|'+$total+'|'+$offset)
  for($index=$offset;$index -lt [Math]::Min($total,$offset+$limit);$index++) {
    $r=$all[$index]
    $protocol=switch([int]$r.Protocol){6 {'TCP'} 17 {'UDP'} 256 {'Any'} default {[string]$r.Protocol}}
    $displayName=[string]$r.Name
    if([string]$r.Grouping -like 'WinFireSecure:*' -and [string]$r.Name -like ([string]$r.Grouping+':wf:*') -and $r.Description){$displayName=[string]$r.Description}
    $fields=@(
      [string]$r.Name,$displayName,[string]$r.Grouping,[string]$r.Enabled,
      $(if([int]$r.Action -eq 1){'allow'}else{'block'}),
      $(if([int]$r.Direction -eq 1){'in'}else{'out'}),
      $protocol,
      $(if($r.LocalPorts -and $r.LocalPorts -ne '*'){[string]$r.LocalPorts}else{'Any'}),
      $(if($r.RemotePorts -and $r.RemotePorts -ne '*'){[string]$r.RemotePorts}else{'Any'}),
      $(if($r.RemoteAddresses -and $r.RemoteAddresses -ne '*'){[string]$r.RemoteAddresses}else{'Any'}),
      $(if($r.ApplicationName -and $r.ApplicationName -ne '*'){[string]$r.ApplicationName}else{'Any'}),
      (Get-WinFireLegacyProfile $r.Profiles)
    )
    Write-Output ('RULE|'+(($fields | ForEach-Object { Encode-WinFireField $_ }) -join '|'))
  }
}

function Copy-WinFireLegacyRule($source) {
  $copy=New-WinFireLegacyRuleObject
  $copy.Name=[string]$source.Name
  $copy.Description=[string]$source.Description
  $copy.Grouping=[string]$source.Grouping
  $copy.Protocol=[int]$source.Protocol
  if($source.LocalPorts){$copy.LocalPorts=[string]$source.LocalPorts}
  if($source.RemotePorts){$copy.RemotePorts=[string]$source.RemotePorts}
  if($source.RemoteAddresses){$copy.RemoteAddresses=[string]$source.RemoteAddresses}
  if($source.ApplicationName){$copy.ApplicationName=[string]$source.ApplicationName}
  $copy.Profiles=[int]$source.Profiles
  $copy.Direction=[int]$source.Direction
  $copy.Action=[int]$source.Action
  $copy.Enabled=[bool]$source.Enabled
  return $copy
}

function New-WinFireLegacyManagedRule($item,$group) {
  $rule=New-WinFireLegacyRuleObject
  $rule.Name=$group+':wf:'+([guid]::NewGuid().ToString('N'))
  $rule.Description=[string]$item.name
  $rule.Grouping=$group
  $rule.Protocol=switch([string]$item.protocol){'TCP' {6} 'UDP' {17} 'Any' {256} default {throw 'Unsupported protocol'}}
  if($item.localPort -ne 'Any'){$rule.LocalPorts=[string]$item.localPort}
  if($item.remotePort -ne 'Any'){$rule.RemotePorts=[string]$item.remotePort}
  if($item.remoteAddress -ne 'Any'){$rule.RemoteAddresses=[string]$item.remoteAddress}
  if($item.program -ne 'Any'){$rule.ApplicationName=[string]$item.program}
  $rule.Profiles=switch([string]$item.profile){'Domain' {1} 'Private' {2} 'Public' {4} 'Any' {2147483647} default {throw 'Unsupported profile'}}
  $rule.Direction=if($item.direction -eq 'in'){1}else{2}
  $rule.Action=if($item.action -eq 'allow'){1}else{0}
  $rule.Enabled=$true
  return $rule
}

function Set-WinFireLegacyRules($group,$add,$remove) {
  $policy=Get-WinFireLegacyPolicy
  $managed=@(Get-WinFireLegacyRuleCollection $policy | Where-Object { [string]$_.Grouping -ceq $group })
  foreach($item in @($add)) {
    $matches=@($managed | Where-Object { $(if([string]$_.Name -like ($group+':wf:*')){[string]$_.Description}else{[string]$_.Name}) -ceq [string]$item.name })
    if($matches.Count -gt 1 -or ($matches.Count -eq 1 -and @($remove) -cnotcontains [string]$item.name)){
      throw "Managed firewall rule changed before apply: $($item.name)"
    }
  }
  $toRemove=@()
  foreach($name in @($remove)) {
    $matches=@($managed | Where-Object { $(if([string]$_.Name -like ($group+':wf:*')){[string]$_.Description}else{[string]$_.Name}) -ceq $name })
    if($matches.Count -ne 1){throw "Managed firewall rule changed before apply: $name"}
    if([string]$matches[0].Name -notlike ($group+':wf:*')){throw "Firewall rule is not owned by the legacy adapter: $name"}
    $toRemove+=,(Copy-WinFireLegacyRule $matches[0])
  }
  $created=@()
  $removed=@()
  try {
    foreach($item in @($add)) {
      $new=New-WinFireLegacyManagedRule $item $group
      Add-WinFireLegacyRule $policy $new
      $created+=,[string]$new.Name
    }
    foreach($old in $toRemove) {
      Remove-WinFireLegacyRule $policy ([string]$old.Name)
      $removed+=,$old
    }
  } catch {
    $cause=$_.Exception.Message
    $rollbackErrors=@()
    foreach($name in $created){try{Remove-WinFireLegacyRule $policy $name}catch{$rollbackErrors+=,"remove new rule ${name}: $($_.Exception.Message)"}}
    foreach($old in $removed){try{Add-WinFireLegacyRule $policy $old}catch{$rollbackErrors+=,"restore prior rule $($old.Name): $($_.Exception.Message)"}}
    if($rollbackErrors.Count){throw "Legacy firewall apply failed: $cause; rollback incomplete: $($rollbackErrors -join '; ')"}
    throw "Legacy firewall apply failed: $cause; prior state restored"
  }
  Write-Output 'APPLIED|true'
}
