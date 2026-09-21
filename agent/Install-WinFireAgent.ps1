param(
  [Parameter(Mandatory=$true)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$PackagePath,
  [Parameter(Mandatory=$true)][ValidatePattern('^https://')][string]$ServerUrl,
  [string]$ExpectedSignerThumbprint=''
)
$ErrorActionPreference='Stop'
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this installer from an elevated PowerShell window.'
}
$service=Get-Service -Name 'WinFireAgent' -ErrorAction SilentlyContinue
if($service) {throw 'WinFire Agent is already installed; use the signed update workflow.'}
$signature=Get-AuthenticodeSignature -FilePath $PackagePath
if($signature.Status -ne 'Valid') {throw "Agent binary signature is $($signature.Status); installation stopped."}
if($ExpectedSignerThumbprint) {
  $expected=($ExpectedSignerThumbprint -replace '[^0-9A-Fa-f]','').ToUpperInvariant()
  $actual=([string]$signature.SignerCertificate.Thumbprint -replace '[^0-9A-Fa-f]','').ToUpperInvariant()
  if($expected -notmatch '^[0-9A-F]{40}$' -or $actual -ne $expected) {throw 'Agent signer certificate does not match the configured publisher.'}
}
$target=Join-Path $env:ProgramFiles 'WinFire\WinFire.Agent.exe'
$copied=$false
$serviceCreated=$false
try {
  New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
  Copy-Item -Path $PackagePath -Destination $target -Force
  $copied=$true
  $secureToken=Read-Host 'Short-lived WinFire enrollment token' -AsSecureString
  $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
  try {
    $token=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    $token | & $target enroll $ServerUrl
    if($LASTEXITCODE -ne 0) {throw "Agent enrollment exited with code $LASTEXITCODE"}
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    $token=$null
  }
  New-Service -Name 'WinFireAgent' -DisplayName 'WinFire Agent' -BinaryPathName "`"$target`"" -StartupType Automatic | Out-Null
  $serviceCreated=$true
  Start-Service -Name 'WinFireAgent' -ErrorAction Stop
  Write-Host 'WinFire Agent installed and started.'
} catch {
  if($serviceCreated) {
    try {
      Stop-Service -Name 'WinFireAgent' -Force -ErrorAction SilentlyContinue
      sc.exe delete WinFireAgent | Out-Null
    } catch {}
  }
  if($copied) { Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue }
  throw
}
