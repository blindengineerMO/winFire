import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import {spawnSync} from 'node:child_process'

const hasPwsh=spawnSync('pwsh',['-NoProfile','-Command','$PSVersionTable.PSVersion.Major'],{encoding:'utf8'}).status===0
const source=fs.readFileSync(new URL('../../packages/shared/breakGlass.ps1',import.meta.url),'utf8')
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-break-glass-script-'))
test.after(()=>fs.rmSync(dir,{recursive:true,force:true}))
const psPath=dir.replace(/'/g,"''")
const mocks=String.raw`
$env:ProgramData='${psPath}'
$env:SystemRoot='${psPath}'
$global:profiles=@([pscustomobject]@{Name='Domain';Enabled=$true},[pscustomobject]@{Name='Private';Enabled=$false},[pscustomobject]@{Name='Public';Enabled=$true})
$global:task=$null
$global:failDisable=$false
$global:forceActive=$false
function Get-NetFirewallProfile { param($PolicyStore)
  if($PolicyStore -eq 'ActiveStore' -and $global:forceActive){@($global:profiles | ForEach-Object {[pscustomobject]@{Name=$_.Name;Enabled=$true}})}
  else {@($global:profiles)}
}
function Set-NetFirewallProfile { [CmdletBinding()] param([string[]]$Profile,[string]$Enabled)
  $value=$Enabled -eq 'True'
  foreach($name in $Profile){($global:profiles | Where-Object Name -eq $name).Enabled=$value}
  if(!$value -and $global:failDisable){$global:failDisable=$false;throw 'Injected disable failure'}
}
function Get-ScheduledTask { [CmdletBinding()] param($TaskName) if($global:task -and $global:task.name -eq $TaskName){$global:task} }
function New-ScheduledTaskAction { param($Execute,$Argument) [pscustomobject]@{execute=$Execute;argument=$Argument} }
function New-ScheduledTaskTrigger { param([switch]$Once,$At) [pscustomobject]@{at=$At} }
function New-ScheduledTaskPrincipal { param($UserId,$LogonType,$RunLevel) [pscustomobject]@{user=$UserId} }
function New-ScheduledTaskSettingsSet { param([switch]$StartWhenAvailable) [pscustomobject]@{startWhenAvailable=$true} }
function Register-ScheduledTask { [CmdletBinding()] param($TaskName,$Action,$Trigger,$Principal,$Settings)
  $global:task=[pscustomobject]@{name=$TaskName;action=$Action;trigger=$Trigger;principal=$Principal}; $global:task
}
function Unregister-ScheduledTask { [CmdletBinding()] param($TaskName,[switch]$Confirm) $global:task=$null }
`
function run(script){
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(`${mocks}\n${source}\n${script}`,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  return JSON.parse(result.stdout.trim().split('\n').at(-1))
}
const snapshot="@($global:profiles | Sort-Object Name | ForEach-Object { [pscustomobject]@{Name=$_.Name;Enabled=$_.Enabled} })"

test('host rollback task restores the original three profile states', {skip:!hasPwsh},()=>{
  const sessionId=crypto.randomUUID(),expiresAt=new Date(Date.now()+5*60_000).toISOString()
  const outcome=run(`$started=Start-WinFireBreakGlass ([pscustomobject]@{sessionId='${sessionId}';expiresAt='${expiresAt}'})\n$open=@($global:profiles | Where-Object Enabled).Count\n$encoded=$global:task.action.argument.Split(' ')[-1]\nInvoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded)))\n[pscustomobject]@{active=$started.active;openCount=$open;taskRemaining=[bool]$global:task;profiles=${snapshot}} | ConvertTo-Json -Compress -Depth 5`)
  assert.equal(outcome.active,true)
  assert.equal(outcome.openCount,0)
  assert.equal(outcome.taskRemaining,false)
  assert.deepEqual(outcome.profiles.map(item=>[item.Name,item.Enabled]),[['Domain',true],['Private',false],['Public',true]])
})

test('manual restore and partial activation failure leave original profile states', {skip:!hasPwsh},()=>{
  const firstId=crypto.randomUUID(),secondId=crypto.randomUUID(),expiresAt=new Date(Date.now()+5*60_000).toISOString()
  const outcome=run(`$started=Start-WinFireBreakGlass ([pscustomobject]@{sessionId='${firstId}';expiresAt='${expiresAt}'})\n$ended=End-WinFireBreakGlass ([pscustomobject]@{sessionId='${firstId}';profiles=$started.profiles})\n$global:failDisable=$true\ntry {Start-WinFireBreakGlass ([pscustomobject]@{sessionId='${secondId}';expiresAt='${expiresAt}'}) | Out-Null} catch {$failure=$_.Exception.Message}\n[pscustomobject]@{restored=$ended.restored;failure=$failure;taskRemaining=[bool]$global:task;profiles=${snapshot}} | ConvertTo-Json -Compress -Depth 5`)
  assert.equal(outcome.restored,true)
  assert.match(outcome.failure,/Injected disable failure/)
  assert.equal(outcome.taskRemaining,false)
  assert.deepEqual(outcome.profiles.map(item=>[item.Name,item.Enabled]),[['Domain',true],['Private',false],['Public',true]])
})

test('host refuses break glass when effective Group Policy keeps the firewall enabled', {skip:!hasPwsh},()=>{
  const sessionId=crypto.randomUUID(),expiresAt=new Date(Date.now()+5*60_000).toISOString()
  const outcome=run(`$global:forceActive=$true\ntry {Start-WinFireBreakGlass ([pscustomobject]@{sessionId='${sessionId}';expiresAt='${expiresAt}'}) | Out-Null} catch {$failure=$_.Exception.Message}\n[pscustomobject]@{failure=$failure;taskRemaining=[bool]$global:task;profiles=${snapshot}} | ConvertTo-Json -Compress -Depth 5`)
  assert.match(outcome.failure,/readback did not confirm/)
  assert.equal(outcome.taskRemaining,false)
  assert.deepEqual(outcome.profiles.map(item=>[item.Name,item.Enabled]),[['Domain',true],['Private',false],['Public',true]])
})
