import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {spawnSync} from 'node:child_process'

const source=readFileSync(new URL('../sidecar/security_process_owner.ps1',import.meta.url),'utf8')
const hasPwsh=spawnSync('pwsh',['-NoProfile','-Command','$PSVersionTable.PSVersion.Major'],{encoding:'utf8'}).status===0

test('client logoff rejects a changed process owner and an inactive session before touching WTS',{skip:!hasPwsh},()=>{
  const script=`
$ErrorActionPreference='Stop'
${source}
function Get-WinFireProcessOwner { [pscustomobject]@{sid='S-1-5-21-100-200-300-501';sessionId=3;processId=120} }
function Get-WinFireActiveSession { @() }
function Get-WmiObject { throw 'WMI should not run' }
$sidMismatch=$false;$inactive=$false
try { End-WinFireClientSession ([pscustomobject]@{processId=120;eventTime=(Get-Date).ToString('o');sessionId=3;accountSid='S-1-5-21-100-200-300-999'}) } catch { $sidMismatch=$_.Exception.Message -match 'no longer matches' }
try { End-WinFireClientSession ([pscustomobject]@{processId=120;eventTime=(Get-Date).ToString('o');sessionId=3;accountSid='S-1-5-21-100-200-300-501'}) } catch { $inactive=$_.Exception.Message -match 'no longer active' }
if(-not ($sidMismatch -and $inactive)){throw 'Logoff guards failed'}
Write-Output 'guarded'
`
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  assert.match(result.stdout,/guarded/)
})
