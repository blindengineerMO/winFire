function Invoke-WinFirePolicySafety {
 param($Data,[string]$Operation)
 $ErrorActionPreference='Stop'
 $job=[Guid]::Empty
 if(-not [Guid]::TryParse([string]$Data.id,[ref]$job)){throw 'Invalid policy transaction ID'}
 $key=$job.ToString('N');$task="WinFireSafety-$key"
 $directory=Join-Path $env:ProgramData "WinFire\PolicySafety\$key"
 $statePath=Join-Path $directory 'state.json'
 $mutex=New-Object Threading.Mutex($false,"Global\WinFireSafety-$key")
 if(-not $mutex.WaitOne(30000)){throw 'Policy transaction is busy'}
 try {
  function Write-State($value){$value|ConvertTo-Json -Depth 20|Set-Content -LiteralPath ($statePath+'.tmp') -Encoding UTF8;Move-Item -LiteralPath ($statePath+'.tmp') -Destination $statePath -Force}
  function Read-Spec($rule){
   $port=$rule|Get-NetFirewallPortFilter;$address=$rule|Get-NetFirewallAddressFilter;$application=$rule|Get-NetFirewallApplicationFilter;$service=$rule|Get-NetFirewallServiceFilter;$security=$rule|Get-NetFirewallSecurityFilter;$interface=$rule|Get-NetFirewallInterfaceFilter;$interfaceType=$rule|Get-NetFirewallInterfaceTypeFilter
   if([string]$rule.EdgeTraversalPolicy -notin @('Block','') -or [string]$interfaceType.InterfaceType -notin @('Any','') -or [string]$port.IcmpType -notin @('Any','') -or [string]$security.Encryption -notin @('NotRequired','') -or [string]$service.Service -ne 'Any' -or [string]$address.LocalAddress -ne 'Any' -or [string]$application.Package -notin @('Any','') -or [string]$security.Authentication -notin @('NotRequired','') -or [string]$security.LocalUser -notin @('Any','') -or [string]$security.RemoteUser -notin @('Any','') -or [string]$security.RemoteMachine -notin @('Any','') -or [string]$security.OverrideBlockRules -eq 'True' -or [string]$interface.InterfaceAlias -notin @('Any','')){throw 'This policy contains qualifiers that cannot be recovered by this transaction adapter'}
   [pscustomobject]@{internalName=[string]$rule.Name;name=[string]$rule.DisplayName;direction=[string]$rule.Direction;action=[string]$rule.Action;enabled=[string]$rule.Enabled;profile=[string]$rule.Profile;protocol=[string]$port.Protocol;localPort=@($port.LocalPort);remotePort=@($port.RemotePort);remoteAddress=@($address.RemoteAddress);program=[string]$application.Program}
  }
  function Read-Group([string]$group){@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop|Where-Object {$_.Group -eq $group}|Sort-Object Name|ForEach-Object {Read-Spec $_})}
  function Fingerprint($value){$bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $value -Depth 20 -Compress));$sha=[Security.Cryptography.SHA256]::Create();try{[Convert]::ToBase64String($sha.ComputeHash($bytes))}finally{$sha.Dispose()}}
  function Add-Spec($rule,[string]$group){
   $args=@{Name=[string]$rule.internalName;DisplayName=[string]$rule.name;Group=$group;Direction=[string]$rule.direction;Action=[string]$rule.action;Enabled=[string]$rule.enabled;Profile=([string]$rule.profile -split ',\s*');Protocol=[string]$rule.protocol;LocalPort=@($rule.localPort);RemotePort=@($rule.remotePort);RemoteAddress=@($rule.remoteAddress);Program=[string]$rule.program;PolicyStore='PersistentStore';ErrorAction='Stop'}
   New-NetFirewallRule @args|Out-Null
  }
  function Register-Recovery($state){
   $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -File `"$(Join-Path $directory 'recover.ps1')`""
   $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1)
   Register-ScheduledTask -TaskName $task -Action $action -Trigger (New-ScheduledTaskTrigger -Once -At ([DateTime]::Parse($state.expiresAt))) -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force -ErrorAction Stop|Out-Null
   if(-not(Get-ScheduledTask -TaskName $task -ErrorAction Stop)){throw 'Recovery task readback failed'}
  }
  if($Operation -eq 'arm'){
   if(Test-Path -LiteralPath $statePath){$existing=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json;if($existing.phase -eq 'armed'){Register-Recovery $existing};return $existing}
   $policy=[Guid]::Empty;if(-not[Guid]::TryParse([string]$Data.policyId,[ref]$policy)){throw 'Invalid policy ID'}
   if([int]$Data.seconds -lt 120 -or [int]$Data.seconds -gt 3600){throw 'Recovery duration must be 120–3600 seconds'}
   $group="WinFireSecure:$($policy.ToString())"
   New-Item -ItemType Directory -Path $directory -Force|Out-Null
   $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
   foreach($sid in @('S-1-5-18','S-1-5-32-544')){$identity=New-Object Security.Principal.SecurityIdentifier($sid);$access=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($access)}
   Set-Acl -LiteralPath $directory -AclObject $acl
   $definition=$MyInvocation.MyCommand.Definition
   "function Invoke-WinFirePolicySafety {`n$definition`n}`nInvoke-WinFirePolicySafety ([pscustomobject]@{id='$($job.ToString())'}) 'restore'"|Set-Content -LiteralPath (Join-Path $directory 'recover.ps1') -Encoding UTF8
   if($Data.requireContainment){
    if((Get-Service MpsSvc -ErrorAction Stop).Status -ne 'Running'){throw 'Windows Firewall service must be running for containment'}
    if(Get-NetFirewallProfile -PolicyStore ActiveStore|Where-Object {$_.Enabled -ne 'True'}){throw 'Containment requires all firewall profiles enabled'}
    if(Get-NetFirewallRule -PolicyStore ActiveStore|Where-Object {$_.Enabled -eq 'True'}|Get-NetFirewallSecurityFilter|Where-Object {$_.OverrideBlockRules -eq 'True'}){throw 'Authenticated bypass rules prevent a reliable containment guarantee'}
   }
   $before=@(Read-Group $group)
   $state=[pscustomobject]@{id=$job.ToString();policyId=$policy.ToString();group=$group;phase='armed';before=$before;beforeHash=(Fingerprint $before);afterHash=$null;createdNames=@();expiresAt=(Get-Date).AddSeconds([int]$Data.seconds).ToUniversalTime().ToString('o');nativeRecovery=$true;containment=[bool]$Data.requireContainment;error=$null}
   Write-State $state;Register-Recovery $state;return $state
  }
  if(-not(Test-Path -LiteralPath $statePath)){throw 'Policy recovery snapshot does not exist'}
  $state=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
  if($Operation -in @('status','commit') -and $state.phase -in @('applied','committed') -and (Fingerprint @(Read-Group $state.group)) -ne $state.afterHash){throw 'Owned rules changed since transaction readback'}
  if($Operation -eq 'status'){return $state}
  if($Operation -eq 'apply'){
   if($state.phase -eq 'applied'){return $state}
   if(-not(Get-ScheduledTask -TaskName $task -ErrorAction Stop)){throw 'Recovery task is missing'}
   if($state.phase -ne 'armed' -or [DateTime]::Parse($state.expiresAt) -le (Get-Date).AddSeconds(30)){throw 'Recovery lease is not ready for a new change'}
   if((Fingerprint @(Read-Group $state.group)) -ne $state.beforeHash){throw 'Owned rules changed after recovery was armed'}
   if(@($Data.rules).Count -gt 1000){throw 'Too many rules'}
   $specs=@();$index=0
   foreach($rule in @($Data.rules)){
    if($rule.localUserSid -or $rule.schedule){throw 'Scheduled and identity-qualified rules are not supported by staged deployment'}
    if($rule.action -notin @('allow','block') -or $rule.direction -notin @('in','out')){throw 'Invalid staged firewall rule'}
    $specs += [pscustomobject]@{internalName="WinFireSafety-$key-$index";name=[string]$rule.name;direction=$(if($rule.direction -eq 'in'){'Inbound'}else{'Outbound'});action=$(if($rule.action -eq 'block'){'Block'}else{'Allow'});enabled='True';profile=[string]$rule.profile;protocol=[string]$rule.protocol;localPort=([string]$rule.localPort -split ',');remotePort=([string]$rule.remotePort -split ',');remoteAddress=([string]$rule.remoteAddress -split ',');program=[string]$rule.program};$index++
   }
   $state.createdNames=@($specs|ForEach-Object {$_.internalName});$state.phase='applying';Write-State $state
   foreach($rule in @($state.before)){Get-NetFirewallRule -PolicyStore PersistentStore -Name $rule.internalName -ErrorAction Stop|Remove-NetFirewallRule -ErrorAction Stop}
   foreach($rule in $specs){Add-Spec $rule $state.group}
   if($state.containment){$effective=@(Get-NetFirewallRule -PolicyStore ActiveStore|Where-Object {$_.Group -eq $state.group -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block'});if($effective.Count -ne $specs.Count){throw 'Containment rules are not present in effective firewall policy'}}
   $state.afterHash=Fingerprint @(Read-Group $state.group);$state.phase='applied';Write-State $state;return $state
  }
  if($Operation -eq 'commit'){
   if($state.phase -eq 'committed'){return $state}
   if($state.phase -ne 'applied' -or [DateTime]::Parse($state.expiresAt) -le (Get-Date)){throw 'Transaction expired or is not applied'}
   if((Fingerprint @(Read-Group $state.group)) -ne $state.afterHash){throw 'Rule readback changed before commit'}
   $state.phase='committed';Write-State $state
   Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop;return $state
  }
  if($Operation -eq 'restore'){
   if($state.phase -eq 'restored'){return $state}
   # A scheduled task left after a lost commit reply must not undo a committed transaction.
   if($state.phase -eq 'committed' -and -not $Data.manual){return $state}
   $current=@(Read-Group $state.group)
   if($state.afterHash -and (Fingerprint $current) -ne $state.afterHash){throw 'Concurrent owned-rule changes prevent automatic restore'}
   $known=@($state.createdNames)+@($state.before|ForEach-Object {$_.internalName})
   foreach($rule in $current){if($known -notcontains $rule.internalName){throw 'Unexpected rule in managed group; refusing to overwrite concurrent changes'}}
   $state.afterHash=$null;$state.phase='restoring';$state.expiresAt=(Get-Date).AddSeconds(120).ToUniversalTime().ToString('o');Write-State $state;Register-Recovery $state
   foreach($rule in $current){if($state.createdNames -contains $rule.internalName){Get-NetFirewallRule -PolicyStore PersistentStore -Name $rule.internalName -ErrorAction Stop|Remove-NetFirewallRule -ErrorAction Stop}}
   foreach($rule in @($state.before)){
    $existing=Get-NetFirewallRule -PolicyStore PersistentStore -Name $rule.internalName -ErrorAction SilentlyContinue
    if($existing){if((Fingerprint (Read-Spec $existing)) -ne (Fingerprint $rule)){throw 'A prior rule changed; refusing to overwrite it'}}else{Add-Spec $rule $state.group}
   }
   if((Fingerprint @(Read-Group $state.group)) -ne $state.beforeHash){throw 'Recovery readback did not match the prior snapshot'}
   $state.phase='restored';Write-State $state
   if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop};return $state
  }
  throw 'Unknown policy safety operation'
 }catch{$errorMessage=$_.Exception.Message;if(Test-Path -LiteralPath $statePath){try{$failure=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json;$failure.error=$errorMessage;$failure|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $statePath -Encoding UTF8}catch{}};throw}
 finally{$mutex.ReleaseMutex();$mutex.Dispose()}
}

function Get-WinFirePolicyContext {
 $ErrorActionPreference='Stop'
 $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore|ForEach-Object {[pscustomobject]@{name=[string]$_.Name;enabled=($_.Enabled -eq 'True');inbound=([string]$_.DefaultInboundAction).ToLower();outbound=([string]$_.DefaultOutboundAction).ToLower();localRules=([string]$_.AllowLocalFirewallRules -ne 'False');inboundRules=([string]$_.AllowInboundRules -ne 'False')}})
 $enabled=@(Get-NetFirewallRule -PolicyStore ActiveStore|Where-Object {$_.Enabled -eq 'True'})
 if($enabled.Count -gt 2000){throw 'Effective policy exceeds the bounded 2000-rule replay model'}
 $bypass=$false
 $rules=@($enabled|ForEach-Object {
  $r=$_;$p=$r|Get-NetFirewallPortFilter;$a=$r|Get-NetFirewallAddressFilter;$app=$r|Get-NetFirewallApplicationFilter;$service=$r|Get-NetFirewallServiceFilter;$security=$r|Get-NetFirewallSecurityFilter;$interface=$r|Get-NetFirewallInterfaceFilter;$interfaceType=$r|Get-NetFirewallInterfaceTypeFilter
  if([string]$security.OverrideBlockRules -eq 'True'){$bypass=$true}
  $unsupported=[string]$service.Service -ne 'Any' -or [string]$app.Package -notin @('Any','') -or [string]$security.Authentication -notin @('NotRequired','') -or [string]$security.Encryption -notin @('NotRequired','') -or [string]$security.LocalUser -notin @('Any','') -or [string]$security.RemoteUser -notin @('Any','') -or [string]$security.RemoteMachine -notin @('Any','') -or [string]$interface.InterfaceAlias -notin @('Any','') -or [string]$interfaceType.InterfaceType -notin @('Any','') -or [string]$r.EdgeTraversalPolicy -notin @('Block','') -or [string]$p.IcmpType -notin @('Any','')
  [pscustomobject]@{name=[string]$r.Name;group=[string]$r.Group;action=([string]$r.Action).ToLower();direction=$(if($r.Direction -eq 'Inbound'){'in'}else{'out'});protocol=[string]$p.Protocol;localPort=(@($p.LocalPort)-join ',');remotePort=(@($p.RemotePort)-join ',');localAddress=(@($a.LocalAddress)-join ',');remoteAddress=(@($a.RemoteAddress)-join ',');program=[string]$app.Program;profile=[string]$r.Profile;unsupportedQualifiers=[bool]$unsupported}
 })
 [pscustomobject]@{platform='windows';serviceRunning=((Get-Service MpsSvc -ErrorAction Stop).Status -eq 'Running');profiles=$profiles;rules=$rules;complete=$true;authenticatedBypassExcluded=(-not $bypass);capturedAt=(Get-Date).ToUniversalTime().ToString('o')}
}
