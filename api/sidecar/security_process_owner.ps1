function Get-WinFireProcessOwner($data) {
  $processId=[int]$data.processId
  if($processId -le 0){throw 'A positive process ID is required'}
  $eventTime=[datetime]::Parse([string]$data.eventTime,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AdjustToUniversal)
  if($eventTime -lt (Get-Date).ToUniversalTime().AddMinutes(-5) -or $eventTime -gt (Get-Date).ToUniversalTime().AddSeconds(10)){throw 'The firewall event is too old or in the future to verify a process owner'}
  $process=Get-WmiObject Win32_Process -Filter "ProcessId=$processId" -ErrorAction Stop
  if(-not $process -or [int]$process.SessionId -le 0){throw 'The client process no longer has an interactive session'}
  $created=[Management.ManagementDateTimeConverter]::ToDateTime([string]$process.CreationDate).ToUniversalTime()
  if($created -gt $eventTime.AddSeconds(1)){throw 'The process ID was reused after the firewall event'}
  $owner=$process.GetOwnerSid()
  if(-not $owner -or $owner.ReturnValue -ne 0 -or [string]$owner.Sid -notmatch '^S-1-'){throw 'The process owner SID could not be verified'}
  [pscustomobject]@{sid=[string]$owner.Sid;processId=$processId;sessionId=[int]$process.SessionId;createdAt=$created.ToString('o')}
}
function End-WinFireClientSession($data) {
  $owner=Get-WinFireProcessOwner $data
  $sessionId=[int]$data.sessionId
  if($sessionId -le 0 -or $owner.sessionId -ne $sessionId -or $owner.sid -ne [string]$data.accountSid){throw 'The active process owner no longer matches the requested user session'}
  $active=@(Get-WinFireActiveSession | Where-Object { $_.Id -eq $sessionId })
  if($active.Count -ne 1){throw 'The source user session is no longer active'}
  $process=Get-WmiObject Win32_Process -Filter "ProcessId=$($owner.processId)" -ErrorAction Stop
  $name=$process.GetOwner()
  if(-not $name -or $name.ReturnValue -ne 0 -or -not $name.User){throw 'The source session owner could not be confirmed'}
  $qualified=if($name.Domain){[string]$name.Domain+'\'+[string]$name.User}else{[string]$name.User}
  if($active[0].User -ine $qualified){throw 'The active session user does not own the matched process'}
  if(-not ('WinFireSessionLogoff' -as [type])){
    Add-Type -TypeDefinition 'using System; using System.ComponentModel; using System.Runtime.InteropServices; public static class WinFireSessionLogoff { [DllImport("wtsapi32.dll", SetLastError=true)] static extern bool WTSLogoffSession(IntPtr server, int sessionId, bool wait); public static void End(int id) { if(!WTSLogoffSession(IntPtr.Zero,id,true)) throw new Win32Exception(Marshal.GetLastWin32Error()); } }' -ErrorAction Stop
  }
  [WinFireSessionLogoff]::End($sessionId)
  if(@(Get-WinFireActiveSession | Where-Object { $_.Id -eq $sessionId }).Count){throw 'Logoff returned but the user session remains active'}
  [pscustomobject]@{loggedOff=$true;sessionId=$sessionId;accountSid=$owner.sid}
}
