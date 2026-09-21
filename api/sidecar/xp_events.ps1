# Read-only Security log collection for XP/Server 2003 (PowerShell 2 + WMI).
# These hosts do not expose Vista's Get-WinEvent/WFP 515x event schema.
$ErrorActionPreference='Stop'
function Convert-WinFireLegacyEventTime($value) {
  [Management.ManagementDateTimeConverter]::ToDateTime([string]$value).ToUniversalTime().ToString('o')
}
function Get-WinFireXpEvents($mode, [long]$after) {
  if ($after -lt 0) { throw 'Invalid event cursor' }
  if ($mode -eq 'events_probe') { return }
  $codes = @(528,540,529,530,531,532,533,534,535,536,537,539,538,551)
  $conditions = @($codes | ForEach-Object { 'EventCode=' + $_ }) -join ' OR '
  $query = "SELECT RecordNumber,EventCode,TimeGenerated,User,SourceName FROM Win32_NTLogEvent WHERE Logfile='Security' AND SourceName='Security' AND ($conditions)"
  if ($mode -eq 'events') { $query += ' AND RecordNumber > ' + $after }
  $rows = @(Get-WmiObject -Query $query -EnableAllPrivileges -ErrorAction Stop | Sort-Object RecordNumber)
  if ($mode -eq 'event_cursor') {
    if ($rows.Count) { Write-Output ('CURSOR|' + [long]$rows[-1].RecordNumber) }
    else { Write-Output 'CURSOR|0' }
    return
  }
  if ($mode -eq 'events_recent' -and $rows.Count -gt 500) { $rows = @($rows | Select-Object -Last 500) }
  if ($mode -eq 'events' -and $rows.Count -gt 500) { $rows = @($rows | Select-Object -First 500) }
  foreach ($row in $rows) {
    $record = [long]$row.RecordNumber
    $code = [int]$row.EventCode
    if ($record -lt 0 -or -not ($codes -contains $code)) { throw 'Unexpected legacy Security event' }
    $time = Convert-WinFireLegacyEventTime $row.TimeGenerated
    $sid = ''
    if ([string]$row.User -match '^S-1-\d+(?:-\d+)+$') { $sid = [string]$row.User }
    $encodedSid = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sid))
    Write-Output ('XPEVENT|' + $record + '|' + $code + '|' + $time + '|' + $encodedSid)
  }
}
