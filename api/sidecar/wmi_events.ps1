$ErrorActionPreference='Stop'
function Write-WinFireEvent($event) {
  $xml=$event.ToXml()
  Write-Output ('EVENT|'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($xml)))
}
if($mode -eq 'event_cursor') {
  $newest=Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
  Write-Output ('CURSOR|'+$(if($newest){[long]$newest.RecordId}else{0}))
} elseif($mode -eq 'events') {
  $xpath="*[System[((EventID=5156 or EventID=5157 or EventID=5150 or EventID=5151 or EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=5712) and EventRecordID > $after)]]"
  @(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents 500 -ErrorAction SilentlyContinue) | ForEach-Object {Write-WinFireEvent $_}
} elseif($mode -eq 'events_recent') {
  $firewall=@(Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=5156 or EventID=5157 or EventID=5150 or EventID=5151)]]' -MaxEvents 500 -ErrorAction SilentlyContinue)
  $other=@(Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=5712)]]' -MaxEvents 100 -ErrorAction SilentlyContinue)
  @($firewall+$other | Sort-Object RecordId) | ForEach-Object {Write-WinFireEvent $_}
} elseif($mode -eq 'events_probe') {
  @(Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=5157]]' -MaxEvents 500 -ErrorAction SilentlyContinue) | ForEach-Object {Write-WinFireEvent $_}
} else {
  throw 'Unsupported event query'
}
