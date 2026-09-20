function Install-WinFireAgentRemote($argsData) {
  if(-not ([string]$argsData.serverUrl).StartsWith('https://')) { throw 'Agent enrollment requires HTTPS' }
  if(Get-Service -Name WinFireAgent -ErrorAction SilentlyContinue) { throw 'WinFire Agent is already installed' }
  $targetDirectory=Join-Path $env:ProgramFiles 'WinFire'
  $target=Join-Path $targetDirectory 'WinFire.Agent.exe'
  $temporary=Join-Path $env:TEMP ('WinFire-Agent-'+[guid]::NewGuid().ToString('N')+'.exe')
  $serviceCreated=$false
  try {
    $client=New-Object System.Net.WebClient
    try { $client.DownloadFile([string]$argsData.packageUrl,$temporary) } finally { $client.Dispose() }
    $actual=(Get-FileHash -Path $temporary -Algorithm SHA256).Hash
    if($actual -ine [string]$argsData.sha256) { throw 'Downloaded agent SHA-256 does not match the server package' }
    $signature=Get-AuthenticodeSignature -FilePath $temporary
    if($signature.Status -ne 'Valid') { throw "Agent Authenticode signature is $($signature.Status)" }
    New-Item -ItemType Directory -Force -Path $targetDirectory | Out-Null
    Copy-Item -Path $temporary -Destination $target -Force
    [string]$argsData.token | & $target enroll ([string]$argsData.serverUrl) | Out-Null
    if($LASTEXITCODE -ne 0) { throw "Agent enrollment exited with code $LASTEXITCODE" }
    New-Service -Name WinFireAgent -DisplayName 'WinFire Agent' -BinaryPathName ('"'+$target+'"') -StartupType Automatic | Out-Null
    $serviceCreated=$true
    Start-Service -Name WinFireAgent -ErrorAction Stop
    $service=Get-Service -Name WinFireAgent -ErrorAction Stop
    if($service.Status -ne 'Running') { throw 'WinFire Agent service did not start' }
    [pscustomobject]@{installed=$true;service='WinFireAgent';status=[string]$service.Status;sha256=$actual}
  } catch {
    if($serviceCreated) { try { Stop-Service -Name WinFireAgent -Force -ErrorAction SilentlyContinue; sc.exe delete WinFireAgent | Out-Null } catch {} }
    throw
  } finally {
    Remove-Item -Path $temporary -Force -ErrorAction SilentlyContinue
  }
}
