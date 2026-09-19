param(
  [Parameter(Mandatory=$true)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$PackagePath,
  [Parameter(Mandatory=$true)][ValidatePattern('^https://')][string]$ServerUrl
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
$target=Join-Path $env:ProgramFiles 'WinFire\WinFire.Agent.exe'
New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
Copy-Item -Path $PackagePath -Destination $target -Force
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
Start-Service -Name 'WinFireAgent'
Write-Host 'WinFire Agent installed and started.'
