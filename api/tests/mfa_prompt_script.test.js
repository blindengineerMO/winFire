import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {spawnSync} from 'node:child_process'
import crypto from 'node:crypto'

const source=readFileSync(new URL('../../packages/shared/mfaPrompt.ps1',import.meta.url),'utf8')
const hasPwsh=spawnSync('pwsh',['-NoProfile','-Command','$PSVersionTable.PSVersion.Major'],{encoding:'utf8'}).status===0

test('interactive MFA prompt requires source evidence and one user session',{skip:!hasPwsh},()=>{
  const promptId=crypto.randomUUID()
  const script=`
$ErrorActionPreference='Stop';$env:SystemRoot='/tmp';$script:events=$true;$script:sessions=2;$script:sameUser=$false;$script:registered=$false;$script:opened=$false
${source}
function Get-WinFireActiveSession {@([pscustomobject]@{Id=3;User='TEST\\operator'},[pscustomobject]@{Id=4;User=$(if($script:sameUser){'TEST\\operator'}else{'TEST\\other'})})}
function Get-WinEvent {if($script:events){$event=[pscustomobject]@{TimeCreated=(Get-Date);RecordId=55};$event | Add-Member ScriptMethod ToXml { '<Event><EventData><Data Name="Direction">%%14593</Data><Data Name="Protocol">6</Data><Data Name="ProcessID">120</Data><Data Name="SourceAddress">192.0.2.10</Data><Data Name="SourcePort">54000</Data><Data Name="DestAddress">192.0.2.20</Data><Data Name="DestPort">3389</Data></EventData></Event>' };$event}}
function Get-CimInstance { [pscustomobject]@{SessionId=3;CreationDate=(Get-Date).AddMinutes(-10)} }
function Invoke-CimMethod { [pscustomobject]@{ReturnValue=0;Domain='TEST';User='operator'} }
function New-ScheduledTaskAction {param($Execute,$Argument) [pscustomobject]@{Execute=$Execute;Argument=$Argument}}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel) [pscustomobject]@{UserId=$UserId;LogonType=$LogonType}}
function New-ScheduledTaskSettingsSet {param($ExecutionTimeLimit) [pscustomobject]@{}}
function Register-ScheduledTask {param($TaskName,$Action,$Principal,$Settings,$ErrorAction) $script:registered=$true;$script:principal=$Principal;$script:action=$Action}
function Start-ScheduledTask {param($TaskName,$ErrorAction) $script:opened=$true}
function Get-ScheduledTaskInfo {param($TaskName,$ErrorAction) [pscustomobject]@{LastRunTime=(Get-Date)}}
function Unregister-ScheduledTask {param($TaskName,$Confirm,$ErrorAction) $script:registered=$false}
$data=[pscustomobject]@{promptId='${promptId}';url='https://portal.example.test/mfa/${promptId}';sourceIp='192.0.2.10';sourcePort=54000;targetIp='192.0.2.20';port=3389}
$success=Open-WinFireMfaPortal $data
$script:events=$false;$noEvidence=Open-WinFireMfaPortal $data
$script:events=$true;$script:sameUser=$true;$ambiguous=Open-WinFireMfaPortal $data
[pscustomobject]@{opened=$success.opened;selectedSession=($success.sessionId -eq 3);interactive=$script:principal.LogonType -eq 'Interactive';taskClean=(!$script:registered);noEvidence=(!$noEvidence.opened);ambiguous=(!$ambiguous.opened);browserStarted=$script:opened} | ConvertTo-Json -Compress
`
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  assert.deepEqual(JSON.parse(result.stdout.trim().split('\n').at(-1)),{opened:true,selectedSession:true,interactive:true,taskClean:true,noEvidence:true,ambiguous:true,browserStarted:true})
})
