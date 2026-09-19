import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {spawnSync} from 'node:child_process'

const sidecar=readFileSync(new URL('../sidecar/wsman_client.py',import.meta.url),'utf8')
const connector=readFileSync(new URL('../src/connector.js',import.meta.url),'utf8')
const sidecarScript=sidecar.match(/POWERSHELL = r'''([\s\S]*?)'''/)?.[1]
const factBlock=connector.slice(connector.indexOf("      'facts' {"),connector.indexOf("      'all_rules' {"))
const ruleBlock=connector.slice(connector.indexOf("      'all_rules' {"),connector.indexOf("      'rules' {"))
const hasPwsh=spawnSync('pwsh',['-NoProfile','-Command','$PSVersionTable.PSVersion.Major'],{encoding:'utf8'}).status===0

const mocks=String.raw`
$env:LOGONSERVER='\DC01'
function Get-CimInstance { param($ClassName,$Filter)
  switch($ClassName) {
    'Win32_ComputerSystem' {[pscustomobject]@{Name='TEST01';Model='VM';Manufacturer='Example';Domain='example.test';PartOfDomain=$true;UserName='EXAMPLE\alice'}}
    'Win32_OperatingSystem' {[pscustomobject]@{Caption='Windows Server';Version='10.0';BuildNumber='20348';OSArchitecture='64-bit';InstallDate='2025-01-01';LastBootUpTime='2026-01-01'}}
    'Win32_BIOS' {[pscustomobject]@{SerialNumber='SERIAL-1'}}
    'Win32_NetworkAdapterConfiguration' {[pscustomobject]@{Description='Ethernet';MACAddress='00:11:22:33:44:55';IPAddress=@('192.0.2.10');IPSubnet=@('255.255.255.0');DefaultIPGateway=@('192.0.2.1');DNSServerSearchOrder=@('192.0.2.53');DNSDomain='example.test';DNSDomainSuffixSearchOrder=@('example.test');DHCPEnabled=$false;DHCPServer=$null}}
    'Win32_UserAccount' {[pscustomobject]@{SID='S-1-5-21-100-200-300-500'}}
  }
}
function Get-ItemProperty { param($Path) if($Path -match 'LogonUI'){[pscustomobject]@{LastLoggedOnUser='EXAMPLE\alice'}}else{[pscustomobject]@{MachineGuid='12345678-9abc-def0-1234-56789abcdef0'}} }
function Get-NetFirewallProfile { [pscustomobject]@{Name='Domain';Enabled=$true;DefaultInboundAction='Block';DefaultOutboundAction='Allow'} }
function Get-Service { param($Name) [pscustomobject]@{Status='Running'} }
function Get-NetFirewallRule { [pscustomobject]@{Name='test-rule';DisplayName='Test RDP';Group='WinFireSecure:test';Enabled='True';Action='Allow';Direction='Inbound';Profile='Domain';PolicyStoreSourceType='Local';Protocol='TCP';LocalPort='3389';RemotePort='Any';RemoteAddress='192.0.2.0/24';Program='Any'} }
function Get-NetFirewallPortFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process{[pscustomobject]@{Protocol=$InputObject.Protocol;LocalPort=$InputObject.LocalPort;RemotePort=$InputObject.RemotePort}} }
function Get-NetFirewallAddressFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process{[pscustomobject]@{RemoteAddress=$InputObject.RemoteAddress}} }
function Get-NetFirewallApplicationFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject) process{[pscustomobject]@{Program=$InputObject.Program}} }
`
function execute(script){
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(`${mocks}\n${script}`,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  return JSON.parse(result.stdout.trim().split('\n').at(-1))
}

test('Linux and Windows WinRM fact scripts return rich host identity and network details',{skip:!hasPwsh},()=>{
  const encoded=Buffer.from('{}').toString('base64')
  const scripts=[sidecarScript.replace('__OPERATION__','facts').replace('[Console]::In.ReadToEnd()',`'${encoded}'`),`$result=switch('facts'){${factBlock}}; $result | ConvertTo-Json -Compress -Depth 12`]
  for(const script of scripts){
    const result=execute(script)
    assert.equal(result.identity.domainJoined,true)
    assert.equal(result.identity.domainName,'example.test')
    assert.equal(result.identity.localMachineSid,'S-1-5-21-100-200-300')
    assert.equal(result.identity.machineGuid,'12345678-9abc-def0-1234-56789abcdef0')
    assert.equal(result.network[0].ipAddresses[0],'192.0.2.10')
    assert.equal(result.os.BuildNumber,'20348')
  }
})

test('Linux and Windows WinRM rule inventory scripts return paged normalized rules',{skip:!hasPwsh},()=>{
  const encoded=Buffer.from(JSON.stringify({offset:0,limit:10})).toString('base64')
  const scripts=[sidecarScript.replace('__OPERATION__','all_rules').replace('[Console]::In.ReadToEnd()',`'${encoded}'`),`$argsData=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')) | ConvertFrom-Json; $result=switch('all_rules'){${ruleBlock}}; $result | ConvertTo-Json -Compress -Depth 12`]
  for(const script of scripts){
    const result=execute(script)
    assert.equal(result.total,1)
    assert.equal(result.rules[0].displayName,'Test RDP')
    assert.equal(result.rules[0].localPort,'3389')
    assert.equal(result.rules[0].enabled,true)
  }
})
