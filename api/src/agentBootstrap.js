import fs from 'node:fs'
import crypto from 'node:crypto'

const psQuote=value=>`'${String(value).replaceAll("'","''")}'`
export function normalizeSignerThumbprint(value){
  if(!value)return ''
  const normalized=String(value).replace(/[\s:]/g,'').toUpperCase()
  if(!/^[A-F0-9]{40}$/.test(normalized))throw new Error('AGENT_SIGNER_THUMBPRINT must be a 40-character hexadecimal certificate thumbprint')
  return normalized
}

export async function agentBootstrapScript(packagePath,serverBaseUrl,signerThumbprint=''){
  const server=new URL(serverBaseUrl)
  if(server.protocol!=='https:'||server.username||server.password)throw new Error('An HTTPS PUBLIC_BASE_URL without embedded credentials is required')
  const base=server.origin
  const digest=crypto.createHash('sha256')
  for await(const chunk of fs.createReadStream(packagePath))digest.update(chunk)
  const expectedHash=digest.digest('hex')
  const expectedSigner=normalizeSignerThumbprint(signerThumbprint)
  const installer=fs.readFileSync(new URL('../../agent/Install-WinFireAgent.ps1',import.meta.url),'utf8')
  return `$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT') { throw 'WinFire Agent requires Windows.' }
$serverUrl=${psQuote(base)}
$packageUrl=${psQuote(new URL('/api/v1/agent-package/WinFire.Agent.exe',base).toString())}
$expectedHash=${psQuote(expectedHash)}
$expectedSigner=${psQuote(expectedSigner)}
$packagePath=Join-Path ([IO.Path]::GetTempPath()) ('WinFire.Agent.'+[Guid]::NewGuid().ToString('N')+'.exe')
try {
  Invoke-WebRequest -Uri $packageUrl -OutFile $packagePath -UseBasicParsing
  $actualHash=(Get-FileHash -Path $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
  if($actualHash -ne $expectedHash) { throw 'Agent package SHA-256 mismatch; installation stopped.' }
  $installer={
${installer}
  }
  & $installer -PackagePath $packagePath -ServerUrl $serverUrl -ExpectedSignerThumbprint $expectedSigner
} finally {
  Remove-Item -LiteralPath $packagePath -Force -ErrorAction SilentlyContinue
}
`
}
