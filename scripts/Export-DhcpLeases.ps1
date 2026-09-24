<#
.SYNOPSIS
Exports Windows DHCP IPv4 leases for WinFire's passive DHCP import.
.EXAMPLE
.\Export-DhcpLeases.ps1 -ComputerName dhcp.example.com -OutputDirectory .\leases
.NOTES
Requires the DhcpServer PowerShell module and permission to read DHCP leases.
No WinFire credentials are used. No discovered hosts are contacted.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ComputerName,
  [string[]]$ScopeId,
  [string]$OutputDirectory = '.',
  [ValidateRange(1,2000)][int]$BatchSize = 2000
)
$ErrorActionPreference = 'Stop'
Import-Module DhcpServer -ErrorAction Stop
$observedAt = [DateTime]::UtcNow.ToString('o')
$scopes = if ($ScopeId) { $ScopeId } else { @(Get-DhcpServerv4Scope -ComputerName $ComputerName | ForEach-Object { $_.ScopeId.IPAddressToString }) }
$leases = @(foreach ($scope in $scopes) {
  Get-DhcpServerv4Lease -ComputerName $ComputerName -ScopeId $scope | ForEach-Object {
    [ordered]@{
      ip = $_.IPAddress.IPAddressToString
      mac = [string]$_.ClientId
      hostname = [string]$_.HostName
      leaseExpiry = $_.LeaseExpiryTime.ToUniversalTime().ToString('o')
      state = [string]$_.AddressState
    }
  }
})
if ($leases.Count -eq 0) { Write-Output 'No active leases found. No files written.'; return }
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory
for ($offset = 0; $offset -lt $leases.Count; $offset += $BatchSize) {
  $last = [Math]::Min($offset + $BatchSize - 1, $leases.Count - 1)
  $payload = [ordered]@{source=$ComputerName; observedAt=$observedAt; leases=@($leases[$offset..$last])}
  $file = Join-Path $OutputDirectory ('winfire-dhcp-{0:000}.json' -f (1 + [int][Math]::Floor($offset / $BatchSize)))
  $payload | ConvertTo-Json -Depth 5 | Set-Content -Path $file -Encoding UTF8
  Write-Output $file
}
