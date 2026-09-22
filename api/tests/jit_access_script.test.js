import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {spawnSync} from 'node:child_process'
import crypto from 'node:crypto'

const source=readFileSync(new URL('../../packages/shared/jitAccess.ps1',import.meta.url),'utf8')
const hasPwsh=spawnSync('pwsh',['-NoProfile','-Command','$PSVersionTable.PSVersion.Major'],{encoding:'utf8'}).status===0

test('JIT firewall grant registers host-local expiry first and rejects an open gate',{skip:!hasPwsh},()=>{
  const grantId=crypto.randomUUID(),expiresAt=new Date(Date.now()+180_000).toISOString()
  const script=`
$ErrorActionPreference='Stop'
$env:SystemRoot='/tmp'
$global:task=$false; $global:rule=$null; $global:defaultInbound='Block'; $global:existingAllow=$false; $global:existingAllowPort='3389'; $global:badReadback=$false; $global:taskFirst=$false; $global:cleanup=''
$global:allowRight=$false; $global:denyRight=$true
function Get-NetFirewallProfile { param($PolicyStore) @('Domain','Private','Public') | ForEach-Object {[pscustomobject]@{Name=$_;Enabled='True';DefaultInboundAction=$global:defaultInbound}} }
function Get-NetFirewallRule { param($PolicyStore,$Enabled,$Direction,$Action,$Group,$ErrorAction)
  if($PolicyStore){if($global:existingAllow){[pscustomobject]@{DisplayName='Existing rule';Group='Other';Action='Allow';Protocol='TCP';LocalPort=$global:existingAllowPort}};return}
  if($Group -and $global:rule){$global:rule}
}
function Get-NetFirewallPortFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process{[pscustomobject]@{Protocol=$InputObject.Protocol;LocalPort=$(if($global:badReadback){'9999'}else{$InputObject.LocalPort})}} }
function Get-NetFirewallAddressFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process{[pscustomobject]@{RemoteAddress=$InputObject.RemoteAddress}} }
function Get-ScheduledTask { param($TaskName,$ErrorAction) if($global:task){[pscustomobject]@{TaskName=$TaskName}} }
function New-ScheduledTaskAction { param($Execute,$Argument) $global:cleanup=$Argument; [pscustomobject]@{Argument=$Argument} }
function New-ScheduledTaskTrigger { param([switch]$Once,$At) [pscustomobject]@{At=$At} }
function New-ScheduledTaskPrincipal { param($UserId,$LogonType,$RunLevel) [pscustomobject]@{UserId=$UserId} }
function New-ScheduledTaskSettingsSet { param([switch]$StartWhenAvailable) [pscustomobject]@{} }
function Register-ScheduledTask { param($TaskName,$Action,$Trigger,$Principal,$Settings,$ErrorAction) $global:task=$true; [pscustomobject]@{TaskName=$TaskName} }
function Unregister-ScheduledTask { param($TaskName,$Confirm,$ErrorAction) $global:task=$false }
function New-NetFirewallRule { param($DisplayName,$Group,$Direction,$Action,$Protocol,$LocalPort,$RemoteAddress,$Profile,$ErrorAction)
  $global:taskFirst=$global:task; $global:rule=[pscustomobject]@{DisplayName=$DisplayName;Group=$Group;Protocol=$Protocol;LocalPort=@($LocalPort);RemoteAddress=$RemoteAddress};$global:rule
}
function Remove-NetFirewallRule { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process{$global:rule=$null} }
function Get-WinFireLogonRights { $rows=@();if($global:allowRight){$rows+=,'SeRemoteInteractiveLogonRight = *S-1-5-21-1-2-3-1001'};if($global:denyRight){$rows+=,'SeDenyRemoteInteractiveLogonRight = *S-1-5-21-1-2-3-1001'};@($rows) }
function Test-WinFireLogonRight([string[]]$lines,[string]$accountSid,[string]$right) { @($lines|Where-Object {$_ -like "$right = *$accountSid*"}).Count -gt 0 }
function Set-WinFireLogonRight($argsData) { $before=if($argsData.right -eq 'SeRemoteInteractiveLogonRight'){$global:allowRight}else{$global:denyRight};if($argsData.right -eq 'SeRemoteInteractiveLogonRight'){$global:allowRight=[bool]$argsData.present}else{$global:denyRight=[bool]$argsData.present};[pscustomobject]@{accountSid=$argsData.accountSid;right=$argsData.right;before=$before;present=[bool]$argsData.present;changed=($before -ne [bool]$argsData.present)} }
${source}
$data=[pscustomobject]@{grantId='${grantId}';port=3389;sourceIp='192.0.2.7';expiresAt='${expiresAt}'}
$started=Start-WinFireJitAccess $data
$active=($started.active -and $global:taskFirst -and $global:task -and $global:rule.RemoteAddress -eq '192.0.2.7')
$decoded=[IO.File]::ReadAllText((Get-WinFireJitIdentity $data.grantId).cleanup,[Text.Encoding]::Unicode)
$hasLocalExpiry=($decoded -match 'Remove-NetFirewallRule' -and $decoded -match 'Unregister-ScheduledTask')
End-WinFireJitAccess $data | Out-Null
$clean=(!$global:task -and !$global:rule)
$data | Add-Member -NotePropertyName ports -NotePropertyValue @(22)
$multi=Start-WinFireJitAccess $data
$multiPorts=($multi.ports.Count -eq 2 -and $global:rule.LocalPort -match '3389' -and $global:rule.LocalPort -match '22')
End-WinFireJitAccess $data | Out-Null
$global:defaultInbound='Allow'
try {Start-WinFireJitAccess $data | Out-Null; $openRejected=$false} catch {$openRejected=$true}
$global:defaultInbound='Block';$global:existingAllow=$true
try {Start-WinFireJitAccess $data | Out-Null; $allowRejected=$false} catch {$allowRejected=$true}
$global:existingAllowPort=@('443','22')
try {Start-WinFireJitAccess $data | Out-Null; $extraPortRejected=$false} catch {$extraPortRejected=$true}
$global:existingAllow=$false;$global:badReadback=$true
try {Start-WinFireJitAccess $data | Out-Null; $badReadbackRejected=$false} catch {$badReadbackRejected=$true}
$global:badReadback=$false
$lsaData=[pscustomobject]@{grantId='${crypto.randomUUID()}';port=3389;sourceIp='192.0.2.8';expiresAt='${expiresAt}';accountSid='S-1-5-21-1-2-3-1001';allowRight='SeRemoteInteractiveLogonRight';denyRight='SeDenyRemoteInteractiveLogonRight'}
$lsaStarted=Start-WinFireJitAccess $lsaData
$lsaOpened=($lsaStarted.lsaTemporary -and $global:allowRight -and -not $global:denyRight)
End-WinFireJitAccess $lsaData | Out-Null
$lsaRestored=(-not $global:allowRight -and $global:denyRight)
[pscustomobject]@{active=$active;localExpiry=$hasLocalExpiry;clean=$clean;multiPorts=$multiPorts;openRejected=$openRejected;allowRejected=$allowRejected;extraPortRejected=$extraPortRejected;badReadbackRejected=$badReadbackRejected;lsaOpened=$lsaOpened;lsaRestored=$lsaRestored;noResidual=(!$global:task -and !$global:rule)} | ConvertTo-Json -Compress
`
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  const observed=JSON.parse(result.stdout.trim().split('\n').at(-1))
  assert.deepEqual(observed,{active:true,localExpiry:true,clean:true,multiPorts:true,openRejected:true,allowRejected:true,extraPortRejected:true,badReadbackRejected:true,lsaOpened:true,lsaRestored:true,noResidual:true})
})
