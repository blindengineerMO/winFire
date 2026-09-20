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
$script:task=$false; $script:rule=$null; $script:defaultInbound='Block'; $script:existingAllow=$false; $script:taskFirst=$false; $script:cleanup=''
function Get-NetFirewallProfile { param($PolicyStore) @('Domain','Private','Public') | ForEach-Object {[pscustomobject]@{Name=$_;Enabled='True';DefaultInboundAction=$script:defaultInbound}} }
function Get-NetFirewallRule { param($PolicyStore,$Enabled,$Direction,$Action,$Group,$ErrorAction)
  if($PolicyStore){if($script:existingAllow){[pscustomobject]@{DisplayName='Existing RDP';Group='Other';Action='Allow';Protocol='TCP';LocalPort='3389'}};return}
  if($Group -and $script:rule){$script:rule}
}
function Get-NetFirewallPortFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process{[pscustomobject]@{Protocol=$InputObject.Protocol;LocalPort=$InputObject.LocalPort}} }
function Get-ScheduledTask { param($TaskName,$ErrorAction) if($script:task){[pscustomobject]@{TaskName=$TaskName}} }
function New-ScheduledTaskAction { param($Execute,$Argument) $script:cleanup=$Argument; [pscustomobject]@{Argument=$Argument} }
function New-ScheduledTaskTrigger { param([switch]$Once,$At) [pscustomobject]@{At=$At} }
function New-ScheduledTaskPrincipal { param($UserId,$LogonType,$RunLevel) [pscustomobject]@{UserId=$UserId} }
function New-ScheduledTaskSettingsSet { param([switch]$StartWhenAvailable) [pscustomobject]@{} }
function Register-ScheduledTask { param($TaskName,$Action,$Trigger,$Principal,$Settings,$ErrorAction) $script:task=$true; [pscustomobject]@{TaskName=$TaskName} }
function Unregister-ScheduledTask { param($TaskName,$Confirm,$ErrorAction) $script:task=$false }
function New-NetFirewallRule { param($DisplayName,$Group,$Direction,$Action,$Protocol,$LocalPort,$RemoteAddress,$Profile,$ErrorAction)
  $script:taskFirst=$script:task; $script:rule=[pscustomobject]@{DisplayName=$DisplayName;Group=$Group;Protocol=$Protocol;LocalPort=[string]$LocalPort;RemoteAddress=$RemoteAddress};$script:rule
}
function Remove-NetFirewallRule { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process{$script:rule=$null} }
${source}
$data=[pscustomobject]@{grantId='${grantId}';port=3389;sourceIp='192.0.2.7';expiresAt='${expiresAt}'}
$started=Start-WinFireJitAccess $data
$active=($started.active -and $script:taskFirst -and $script:task -and $script:rule.RemoteAddress -eq '192.0.2.7')
$decoded=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(($script:cleanup -split ' ')[-1]))
$hasLocalExpiry=($decoded -match 'Remove-NetFirewallRule' -and $decoded -match 'Unregister-ScheduledTask')
End-WinFireJitAccess $data | Out-Null
$clean=(!$script:task -and !$script:rule)
$script:defaultInbound='Allow'
try {Start-WinFireJitAccess $data | Out-Null; $openRejected=$false} catch {$openRejected=$true}
$script:defaultInbound='Block';$script:existingAllow=$true
try {Start-WinFireJitAccess $data | Out-Null; $allowRejected=$false} catch {$allowRejected=$true}
[pscustomobject]@{active=$active;localExpiry=$hasLocalExpiry;clean=$clean;openRejected=$openRejected;allowRejected=$allowRejected;noResidual=(!$script:task -and !$script:rule)} | ConvertTo-Json -Compress
`
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  const observed=JSON.parse(result.stdout.trim().split('\n').at(-1))
  assert.deepEqual(observed,{active:true,localExpiry:true,clean:true,openRejected:true,allowRejected:true,noResidual:true})
})
