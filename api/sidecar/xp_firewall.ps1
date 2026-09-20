# Windows XP SP2 / Server 2003 SP1 current-profile exception inventory.
# This API cannot express modern outbound blocks or per-rule grouping, so it
# is intentionally read-only. The caller sends the resulting frames to the UI.
$ErrorActionPreference='Stop'
function Get-WinFireXpProfile { (New-Object -ComObject HNetCfg.FwMgr).LocalPolicy.CurrentProfile }
function Encode-WinFireXpField($value) {
  [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$value))
}
function Get-WinFireXpRemoteScope($item) {
  if([int]$item.Scope -eq 1){return 'LocalSubnet'}
  if([int]$item.Scope -eq 2 -and $item.RemoteAddresses){return [string]$item.RemoteAddresses}
  return 'Any'
}
function Get-WinFireXpRules($offset,$limit) {
  $profile=Get-WinFireXpProfile
  $rows=@()
  foreach($port in @($profile.GloballyOpenPorts)) {
    $protocol=if([int]$port.Protocol -eq 17){'UDP'}else{'TCP'}
    $rows+=,(New-Object PSObject -Property @{
      name=('XP port: '+[string]$port.Name+' ['+$protocol+'/'+[string]$port.Port+']')
      enabled=[bool]$port.Enabled;protocol=$protocol;localPort=[string]$port.Port
      remoteAddress=(Get-WinFireXpRemoteScope $port);program='Any'
    })
  }
  foreach($application in @($profile.AuthorizedApplications)) {
    $rows+=,(New-Object PSObject -Property @{
      name=('XP program: '+[string]$application.Name)
      enabled=[bool]$application.Enabled;protocol='Any';localPort='Any'
      remoteAddress=(Get-WinFireXpRemoteScope $application)
      program=[string]$application.ProcessImageFileName
    })
  }
  Write-Output ('HEADER|'+$rows.Count+'|'+$offset)
  for($index=$offset;$index -lt [Math]::Min($rows.Count,$offset+$limit);$index++) {
    $item=$rows[$index]
    $fields=@(
      [string]$item.name,[string]$item.name,'Windows XP current profile',
      [string]$item.enabled,'allow','in',[string]$item.protocol,
      [string]$item.localPort,'Any',[string]$item.remoteAddress,
      $(if($item.program){[string]$item.program}else{'Any'}),'Any'
    )
    Write-Output ('RULE|'+(($fields | ForEach-Object { Encode-WinFireXpField $_ }) -join '|'))
  }
}
