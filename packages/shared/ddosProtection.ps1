function Invoke-WinFireDdos {
 param($Data,[bool]$Remove)
 $ErrorActionPreference='Stop'
 $parsed=[Guid]::Empty
 if(-not [Guid]::TryParse([string]$Data.id,[ref]$parsed)){throw 'Invalid DDoS block identifier'}
 $key=$parsed.ToString('N');$group="WinFireDDoS:$key";$task="WinFireDDoS-$key"
 if($Remove){
  Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Group -eq $group } | Remove-NetFirewallRule -ErrorAction Stop
  if(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $_.Group -eq $group }){throw 'Temporary block remains in effective firewall policy'}
  if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop}
  return @{removed=$true;active=$false}
 }
 if($Data.protocol -notin @('TCP','UDP') -or [int]$Data.seconds -lt 30 -or [int]$Data.seconds -gt 86400){throw 'Invalid DDoS protocol or expiry'}
 $ports=@($Data.ports);$sources=@($Data.sources)
 if($ports.Count -lt 1 -or $ports.Count -gt 32 -or $sources.Count -lt 1 -or $sources.Count -gt 100){throw 'Invalid DDoS scope'}
 foreach($port in $ports){if([int]$port -lt 1 -or [int]$port -gt 65535 -or [int]$port -in @(22,135,139,445,3389,5985,5986)){throw 'Invalid or protected DDoS port'}}
 foreach($source in $sources){$ip=$null;if(-not [Net.IPAddress]::TryParse([string]$source,[ref]$ip)){throw 'Invalid DDoS source'}}
 if(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue){throw 'DDoS block already exists; release it before retrying'}
 $expires=(Get-Date).AddSeconds([int]$Data.seconds)
 $cleanup="Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { `$_.Group -eq '$group' } | Remove-NetFirewallRule -ErrorAction Stop; Unregister-ScheduledTask -TaskName '$task' -Confirm:`$false -ErrorAction SilentlyContinue"
 $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanup))
 $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
 $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
 Register-ScheduledTask -TaskName $task -Action $action -Trigger (New-ScheduledTaskTrigger -Once -At $expires) -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force -ErrorAction Stop | Out-Null
 try{
  New-NetFirewallRule -Name $task -DisplayName $task -Group $group -Direction Inbound -Action Block -Protocol $Data.protocol -LocalPort $ports -RemoteAddress $sources -Profile Any -Enabled True -ErrorAction Stop | Out-Null
  if(-not (Get-NetFirewallRule -PolicyStore ActiveStore -Name $task -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })){throw 'DDoS rule readback failed'}
 }catch{
  Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  # Keep the cleanup task when the result is uncertain.
  throw
 }
 return @{active=$true;nativeExpiry=$true;expiresAt=$expires.ToUniversalTime().ToString('o')}
}
