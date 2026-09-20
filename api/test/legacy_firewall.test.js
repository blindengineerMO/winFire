import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {spawnSync} from 'node:child_process'

const script=readFileSync(new URL('../sidecar/legacy_firewall.ps1',import.meta.url),'utf8')
const xpScript=readFileSync(new URL('../sidecar/xp_firewall.ps1',import.meta.url),'utf8')
const sidecar=new URL('../sidecar/wsman_client.py',import.meta.url).pathname
const hasPwsh=spawnSync('pwsh',['-NoProfile','-Command','$PSVersionTable.PSVersion.Major'],{encoding:'utf8'}).status===0

function parse(output,operation){
  const python=String.raw`
import importlib.util,json,sys,types
sys.modules['winrm']=types.ModuleType('winrm')
spec=importlib.util.spec_from_file_location('wsman_client',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
print(json.dumps(module.parse_legacy_firewall(sys.stdin.read(),sys.argv[2])))
`
  const result=spawnSync('python3',['-c',python,sidecar,operation],{input:output,encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  return JSON.parse(result.stdout)
}

function inventory(operation,group='',offset=0,limit=100){
  const mock=String.raw`
function Get-WinFireLegacyPolicy {
  [pscustomobject]@{Rules=@(
    [pscustomobject]@{Name='Plain RDP';Grouping='';Enabled=$true;Action=1;Direction=1;Protocol=6;LocalPorts='3389';RemotePorts='*';RemoteAddresses='*';ApplicationName='';Profiles=7},
    [pscustomobject]@{Name='WinFireSecure:test:wf:0123456789abcdef0123456789abcdef';Description='École allow';Grouping='WinFireSecure:test';Enabled=$false;Action=0;Direction=2;Protocol=17;LocalPorts='53';RemotePorts='*';RemoteAddresses='192.0.2.0/24';ApplicationName='C:\app.exe';Profiles=1}
  )}
}
`
  const command=`${script}\n${mock}\nGet-WinFireLegacyRules '${operation}' '${group}' ${offset} ${limit}`
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(command,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  return parse(result.stdout,operation)
}

test('PowerShell 2 firewall inventory pages COM rules and preserves normalized fields',{skip:!hasPwsh},()=>{
  const page=inventory('all_rules','',1,1)
  assert.equal(page.total,2)
  assert.equal(page.offset,1)
  assert.deepEqual(page.rules.map(rule=>[rule.name,rule.enabled,rule.action,rule.direction,rule.protocol,rule.localPort,rule.profile]),[
    ['École allow',false,'block','out','UDP','53','Domain']
  ])
  assert.equal(page.rules[0].program,'C:\\app.exe')
  assert.match(page.rules[0].internalName,/^WinFireSecure:test:wf:/)
  const managed=inventory('rules','WinFireSecure:test')
  assert.equal(managed.length,1)
  assert.equal(managed[0].group,'WinFireSecure:test')
  assert.equal(managed[0].remoteAddress,'192.0.2.0/24')
  assert.deepEqual(inventory('rules','WinFireSecure:missing'),[])
})

test('older firewall parser rejects incomplete or malformed readback',()=>{
  assert.throws(()=>parse('HEADER|2|0\n','rules'),/invalid header/)
  assert.throws(()=>parse('HEADER|0|0\nunexpected\n','all_rules'),/invalid record/)
})

test('OS dialect chooses XP and Server 2008 compatibility paths',()=>{
  const python=String.raw`
import importlib.util,json,sys,types
sys.modules['winrm']=types.ModuleType('winrm')
spec=importlib.util.spec_from_file_location('wsman_client',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
print(json.dumps([module.windows_dialect(value) for value in ['Windows XP Professional','5.2.3790','Windows Server 2008 R2','6.1.7601','Windows 7','Windows Server 2016','10.0.20348']]))
`
  const result=spawnSync('python3',['-c',python,sidecar],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  assert.deepEqual(JSON.parse(result.stdout),['xp','xp','advfirewall','advfirewall','advfirewall','netsecurity','netsecurity'])
})

test('XP rejects firewall policy writes before opening a remote shell',()=>{
  const python=String.raw`
import importlib.util,sys,types
sys.modules['winrm']=types.ModuleType('winrm')
spec=importlib.util.spec_from_file_location('wsman_client',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
try:
    module.legacy_ps2(None,{'operation':'apply','osVersion':'Windows XP','args':{'group':'WinFireSecure:test'}})
except RuntimeError as error:
    assert 'firewall writes require' in str(error)
else:
    raise AssertionError('XP accepted a policy write')
`
  const result=spawnSync('python3',['-c',python,sidecar],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
})

function applyLegacy({failRemoval=false,foreign=false}={}){
  const mocks=String.raw`
$global:rules=@(
  [pscustomobject]@{Name='WinFireSecure:test:wf:old-a';Description='A';Grouping='WinFireSecure:test';Enabled=$true;Action=1;Direction=1;Protocol=6;LocalPorts='3389';RemotePorts='';RemoteAddresses='';ApplicationName='';Profiles=7},
  [pscustomobject]@{Name='WinFireSecure:test:wf:old-b';Description='B';Grouping='WinFireSecure:test';Enabled=$true;Action=1;Direction=1;Protocol=6;LocalPorts='5985';RemotePorts='';RemoteAddresses='';ApplicationName='';Profiles=7}
)
function Get-WinFireLegacyPolicy { [pscustomobject]@{} }
function New-WinFireLegacyRuleObject {
  [pscustomobject]@{Name='';Description='';Grouping='';Enabled=$false;Action=0;Direction=0;Protocol=256;LocalPorts='';RemotePorts='';RemoteAddresses='';ApplicationName='';Profiles=0}
}
function Get-WinFireLegacyRuleCollection($policy) { $global:rules }
function Add-WinFireLegacyRule($policy,$rule) { $global:rules+=,$rule }
function Remove-WinFireLegacyRule($policy,$name) {
  if($global:failRemoval -and $name -eq 'WinFireSecure:test:wf:old-b'){$global:failRemoval=$false;throw 'Injected removal failure'}
  $global:rules=@($global:rules | Where-Object Name -ne $name)
}
`
  const setup=`$global:failRemoval=$${failRemoval?'true':'false'}\n${foreign?"$global:rules+=,[pscustomobject]@{Name='Foreign';Description='';Grouping='WinFireSecure:test';Enabled=$true;Action=1;Direction=1;Protocol=6;LocalPorts='445';RemotePorts='';RemoteAddresses='';ApplicationName='';Profiles=7}\n":''}`
  const command=`${script}\n${mocks}\n${setup}\n$add=@(${foreign?'':"[pscustomobject]@{name='A';action='allow';direction='in';protocol='TCP';localPort='8443';remotePort='Any';remoteAddress='Any';program='Any';profile='Any'},[pscustomobject]@{name='C';action='allow';direction='in';protocol='TCP';localPort='443';remotePort='Any';remoteAddress='Any';program='Any';profile='Any'}"})\n$remove=@(${foreign?"'Foreign'":"'A','B'"})\ntry { Set-WinFireLegacyRules 'WinFireSecure:test' $add $remove | Out-Null } catch { $global:failure=$_.Exception.Message }\n[pscustomobject]@{failure=$global:failure;rules=@($global:rules | Sort-Object Description | Select-Object Name,Description,LocalPorts)} | ConvertTo-Json -Compress -Depth 5`
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(command,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  return JSON.parse(result.stdout.trim().split('\n').at(-1))
}

test('legacy COM apply adds unique internal names before removing old managed rules',{skip:!hasPwsh},()=>{
  const result=applyLegacy()
  assert.equal(result.failure,null)
  assert.deepEqual(result.rules.map(rule=>[rule.Description,rule.LocalPorts]),[['A','8443'],['C','443']])
  assert.ok(result.rules.every(rule=>/^WinFireSecure:test:wf:[0-9a-f]{32}$/.test(rule.Name)))
})

test('legacy COM apply restores prior managed rules after partial removal',{skip:!hasPwsh},()=>{
  const result=applyLegacy({failRemoval:true})
  assert.match(result.failure,/Injected removal failure.*prior state restored/)
  assert.deepEqual(result.rules.map(rule=>[rule.Name,rule.LocalPorts]),[
    ['WinFireSecure:test:wf:old-a','3389'],['WinFireSecure:test:wf:old-b','5985']
  ])
})

test('legacy COM apply refuses a foreign rule in the managed group',{skip:!hasPwsh},()=>{
  const result=applyLegacy({foreign:true})
  assert.match(result.failure,/not owned by the legacy adapter/)
  assert.equal(result.rules.length,3)
})

test('legacy write validation rejects account scopes and malformed ports',()=>{
  const python=String.raw`
import importlib.util,sys,types
sys.modules['winrm']=types.ModuleType('winrm')
spec=importlib.util.spec_from_file_location('wsman_client',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
group='WinFireSecure:test'
rule={'name':'Test','group':group,'action':'allow','direction':'in','protocol':'TCP','localPort':'3389','remotePort':'Any','remoteAddress':'Any','program':'Any','profile':'Any'}
assert module.validate_legacy_apply({'add':[rule],'remove':[]},group)[0][0]['localPort']=='3389'
for change in ({'localUserSid':'S-1-5-21-1'},{'localPort':'0'},{'localPort':'65536'},{'localPort':'80-'},{'protocol':'Any'},{'group':'WinFireSecure:other'}):
    try:
        module.validate_legacy_apply({'add':[dict(rule,**change)]},group)
    except ValueError:
        pass
    else:
        raise AssertionError(str(change)+' was accepted')
`
  const result=spawnSync('python3',['-c',python,sidecar],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
})

test('XP current-profile exceptions are paged without claiming modern firewall capabilities',{skip:!hasPwsh},()=>{
  const mock=String.raw`
function Get-WinFireXpProfile {
  New-Object PSObject -Property @{
    GloballyOpenPorts=@(New-Object PSObject -Property @{Name='Remote assistance';Enabled=$true;Protocol=6;Port=3389;Scope=1;RemoteAddresses=''})
    AuthorizedApplications=@(New-Object PSObject -Property @{Name='Legacy app';Enabled=$false;Scope=2;RemoteAddresses='192.0.2.0/255.255.255.0';ProcessImageFileName='C:\legacy.exe'})
  }
}
`
  const command=`${xpScript}\n${mock}\nGet-WinFireXpRules 0 10`
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(command,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  const inventory=parse(result.stdout,'all_rules')
  assert.equal(inventory.total,2)
  assert.deepEqual(inventory.rules.map(rule=>[rule.name,rule.enabled,rule.protocol,rule.localPort,rule.remoteAddress]),[
    ['XP port: Remote assistance [TCP/3389]',true,'TCP','3389','LocalSubnet'],
    ['XP program: Legacy app',false,'Any','Any','192.0.2.0/255.255.255.0']
  ])
  assert.equal(inventory.rules[1].program,'C:\\legacy.exe')
  const page=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(`${xpScript}\n${mock}\nGet-WinFireXpRules 1 1`,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(page.status,0,page.stderr)
  assert.deepEqual(parse(page.stdout,'all_rules').rules.map(rule=>rule.name),['XP program: Legacy app'])
})
