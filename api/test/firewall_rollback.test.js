import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {spawnSync} from 'node:child_process'

const sidecar=readFileSync(new URL('../sidecar/wsman_client.py',import.meta.url),'utf8')
const connector=readFileSync(new URL('../src/connector.js',import.meta.url),'utf8')
const agent=readFileSync(new URL('../../agent/WinFire.Agent/Firewall.cs',import.meta.url),'utf8')
const sidecarScript=sidecar.match(/POWERSHELL = r'''([\s\S]*?)'''/)?.[1].replace('__WINFIRE_SHARED_FUNCTIONS__','')
const connectorApply=connector.slice(connector.indexOf("  'apply' {"),connector.indexOf("  'events' {",connector.indexOf("  'apply' {")))
const agentScript=agent.match(/private const string ApplyScript = """([\s\S]*?)""";/)?.[1]
const hasPwsh=spawnSync('pwsh',['-NoProfile','-Command','$PSVersionTable.PSVersion.Major'],{encoding:'utf8'}).status===0

const mocks=String.raw`
$global:rules=@(
  [pscustomobject]@{Name='old-a';DisplayName='A';Group='WinFireSecure:test';Action='Allow';Direction='Inbound';Protocol='TCP';LocalPort='3389';RemotePort='Any';RemoteAddress='Any';Program='Any';Profile='Any'},
  [pscustomobject]@{Name='old-b';DisplayName='B';Group='WinFireSecure:test';Action='Allow';Direction='Inbound';Protocol='TCP';LocalPort='5985';RemotePort='Any';RemoteAddress='Any';Program='Any';Profile='Any'}
)
$global:serial=0
$global:failOnce=$true
function Get-NetFirewallRule { [CmdletBinding()] param($Group,$Name)
  if($Name){$global:rules | Where-Object Name -eq $Name}
  else{$global:rules | Where-Object Group -eq $Group}
}
function Get-NetFirewallPortFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject)
  process{[pscustomobject]@{Protocol=$InputObject.Protocol;LocalPort=$InputObject.LocalPort;RemotePort=$InputObject.RemotePort}}
}
function Get-NetFirewallAddressFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject)
  process{[pscustomobject]@{RemoteAddress=$InputObject.RemoteAddress}}
}
function Get-NetFirewallApplicationFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject)
  process{[pscustomobject]@{Program=$InputObject.Program}}
}
function New-NetFirewallRule { [CmdletBinding()] param($DisplayName,$Group,$Direction,$Action,$Protocol,$LocalPort,$RemotePort,$RemoteAddress,$Program,$Profile)
  $global:serial++
  $row=[pscustomobject]@{Name="new-$global:serial";DisplayName=$DisplayName;Group=$Group;Action=$Action;Direction=$(if($Direction -eq 'in'){'Inbound'}else{'Outbound'});Protocol=$Protocol;LocalPort=$LocalPort;RemotePort=$RemotePort;RemoteAddress=$RemoteAddress;Program=$Program;Profile=$Profile}
  $global:rules+=,$row
  $row
}
function Remove-NetFirewallRule { [CmdletBinding()] param($Name)
  $global:rules=@($global:rules | Where-Object Name -ne $Name)
  if($Name -eq 'old-b' -and $global:failOnce){$global:failOnce=$false;throw 'Injected removal failure'}
}
`

function execute(script){
  const wrapped=`${mocks}\ntry { ${script} } catch { $global:failure=$_.Exception.Message }\n[pscustomobject]@{failure=$global:failure;rules=@($global:rules | Sort-Object DisplayName | Select-Object DisplayName,LocalPort)} | ConvertTo-Json -Compress -Depth 8`
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(wrapped,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  return JSON.parse(result.stdout.trim().split('\n').at(-1))
}

test('WinRM and agent firewall scripts restore old rules after partial removal', {skip:!hasPwsh},()=>{
  assert.ok(sidecarScript&&connectorApply&&agentScript)
  const group='WinFireSecure:test'
  const updated={name:'A',group,action:'allow',direction:'in',protocol:'TCP',localPort:'8443',remotePort:'Any',remoteAddress:'Any',program:'Any',profile:'Any'}
  const added={...updated,name:'C',localPort:'443'}
  const args={group,add:[updated,added],remove:['A','B']}
  const encoded=Buffer.from(JSON.stringify(args)).toString('base64')
  const remote=execute(sidecarScript.replace('__OPERATION__','apply').replace('[Console]::In.ReadToEnd()',`'${encoded}'`))
  const windowsConnector=execute(`$argsData=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')) | ConvertFrom-Json; $result=switch('apply'){${connectorApply}}; $result | ConvertTo-Json -Compress`)
  const payload=JSON.stringify({group,rules:[updated,added]})
  const local=execute(agentScript.replace('[Console]::In.ReadToEnd()',`'${payload}'`))
  for(const outcome of [remote,windowsConnector,local]){
    assert.match(outcome.failure,/Injected removal failure/)
    assert.deepEqual(outcome.rules,[{DisplayName:'A',LocalPort:'3389'},{DisplayName:'B',LocalPort:'5985'}])
  }
})

test('agent readback returns normalized managed firewall rules', {skip:!hasPwsh},()=>{
  const script=agentScript.replace('[Console]::In.ReadToEnd()',`'${JSON.stringify({group:'WinFireSecure:test',readOnly:true})}'`)
  const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(`${mocks}\n${script}`,'utf16le').toString('base64')],{encoding:'utf8'})
  assert.equal(result.status,0,result.stderr)
  const output=JSON.parse(result.stdout.trim().split('\n').at(-1))
  assert.equal(output.rules.length,2)
  assert.deepEqual(output.rules.map(rule=>[rule.name,rule.direction,rule.localPort]),[['A','in','3389'],['B','in','5985']])
})
