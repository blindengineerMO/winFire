import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {spawnSync} from 'node:child_process'
import {normalizeWindowsEvent} from '../src/eventNormalizer.js'

const sidecar=new URL('../sidecar/wsman_client.py',import.meta.url).pathname
const script=readFileSync(new URL('../sidecar/xp_events.ps1',import.meta.url),'utf8')
const hasPwsh=spawnSync('pwsh',['-NoProfile','-Command','$PSVersionTable.PSVersion.Major'],{encoding:'utf8'}).status===0

function parse(output,mode){
  const python=String.raw`
import importlib.util,json,sys,types
sys.modules['winrm']=types.ModuleType('winrm')
spec=importlib.util.spec_from_file_location('wsman_client',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
print(json.dumps(module.parse_legacy_events(sys.stdin.read(),sys.argv[2])))
`
  const result=spawnSync('python3',['-c',python,sidecar,mode],{input:output,encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  return JSON.parse(result.stdout)
}

test('XP Security events keep original IDs and logon meaning',{skip:!hasPwsh},()=>{
  const mock=String.raw`
function Convert-WinFireLegacyEventTime($value) { '2026-09-21T01:02:03.0000000Z' }
function Get-WmiObject {
  param($Query,[switch]$EnableAllPrivileges)
  if(-not $EnableAllPrivileges) { throw 'Security privilege was not enabled' }
  if($Query -notmatch "Logfile='Security'" -or $Query -notmatch "SourceName='Security'" -or $Query -notmatch 'RecordNumber > 10') { throw 'Unscoped event query' }
  @(
    [pscustomobject]@{RecordNumber=12;EventCode=529;TimeGenerated='20260921010203.000000+000';User='EXAMPLE\alice'},
    [pscustomobject]@{RecordNumber=11;EventCode=528;TimeGenerated='20260921010202.000000+000';User='S-1-5-21-1-2-3-4'}
  )
}
`
  const command=`${script}\n${mock}\nGet-WinFireXpEvents 'events' 10`
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(command,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  const rows=parse(result.stdout.trim(),'events')
  assert.deepEqual(rows.map(row=>row.RecordId),[11,12])
  assert.deepEqual(rows.map(row=>normalizeWindowsEvent(row).action),['success','failure'])
  assert.equal(normalizeWindowsEvent(rows[0]).accountSid,'S-1-5-21-1-2-3-4')
  assert.equal(normalizeWindowsEvent(rows[1]).accountSid,null)
  assert.equal(normalizeWindowsEvent(rows[0]).eventType,'logon')
})

test('legacy event parser rejects malformed frames and keeps a bounded ordered page',()=>{
  assert.throws(()=>parse('XPEVENT|1|5157|2026-09-21T00:00:00Z|','events'),/unexpected ID/)
  assert.throws(()=>parse('XPEVENT|1|528|2026-09-21T00:00:00Z|\nXPEVENT|1|529|2026-09-21T00:00:01Z|','events'),/not ordered/)
  assert.equal(parse('CURSOR|33','event_cursor'),33)
  assert.throws(()=>parse('CURSOR|bad','event_cursor'),/invalid response/)
})
