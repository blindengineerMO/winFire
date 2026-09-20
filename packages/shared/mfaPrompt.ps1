function Get-WinFireActiveSession {
  if(-not ('WinFireTerminalSessions' -as [type])) {
    $code=@'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class WinFireTerminalSessions {
  [StructLayout(LayoutKind.Sequential)] struct Session { public int Id; public IntPtr Station; public int State; }
  [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
  [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr value, out int bytes);
  [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr value);
  static string Read(int id, int field) { IntPtr value; int bytes; if (!WTSQuerySessionInformationW(IntPtr.Zero,id,field,out value,out bytes)) return ""; try { return Marshal.PtrToStringUni(value) ?? ""; } finally { if(value!=IntPtr.Zero) WTSFreeMemory(value); } }
  public static object[] Active() {
    IntPtr sessions; int count;
    if(!WTSEnumerateSessionsW(IntPtr.Zero,0,1,out sessions,out count)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    try {
      var results=new List<object>(); int size=Marshal.SizeOf(typeof(Session));
      for(int i=0;i<count;i++) {
        var session=(Session)Marshal.PtrToStructure(IntPtr.Add(sessions,i*size),typeof(Session));
        if(session.Id<=0 || session.State!=0) continue;
        string user=Read(session.Id,5),domain=Read(session.Id,7);
        if(user.Length>0) results.Add(new {Id=session.Id,User=domain.Length>0?domain+"\\"+user:user});
      }
      return results.ToArray();
    } finally { if(sessions!=IntPtr.Zero) WTSFreeMemory(sessions); }
  }
}
'@
    Add-Type -TypeDefinition $code -ErrorAction Stop
  }
  @([WinFireTerminalSessions]::Active())
}
function Open-WinFireMfaPortal($data) {
  $promptId=[guid]::Parse([string]$data.promptId)
  $url=[uri]([string]$data.url)
  if($url.Scheme -ne 'https' -or $url.UserInfo -or $url.Fragment -or $url.AbsolutePath -ne '/identity' -or $url.Query -ne ('?prompt='+$promptId.ToString('D'))) {throw 'Invalid MFA portal URL'}
  $targetIp=[ipaddress]::Parse([string]$data.targetIp).ToString()
  $sourceIp=[ipaddress]::Parse([string]$data.sourceIp).ToString()
  $port=[int]$data.port
  $sourcePort=[int]$data.sourcePort
  if($port -lt 1 -or $port -gt 65535) {throw 'Invalid MFA target port'}
  if($sourcePort -lt 1 -or $sourcePort -gt 65535) {throw 'Invalid MFA source port'}
  $confirmed=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=5156;StartTime=(Get-Date).AddMinutes(-2)} -MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object {
    $xml=[xml]$_.ToXml();$fields=@{}
    foreach($field in @($xml.Event.EventData.Data)) {if($field.Name){$fields[$field.Name]=[string]$field.'#text'}}
    if($fields.Direction -eq '%%14593' -and $fields.Protocol -eq '6' -and $fields.DestAddress -eq $targetIp -and $fields.SourceAddress -eq $sourceIp -and [string]$fields.DestPort -eq [string]$port -and [string]$fields.SourcePort -eq [string]$sourcePort -and [int]$fields.ProcessID -gt 0) {
      [pscustomobject]@{processId=[int]$fields.ProcessID;time=$_.TimeCreated;recordId=$_.RecordId}
    }
  })
  if(-not $confirmed.Count) {return [pscustomobject]@{opened=$false;reason='Source host has no matching recent outbound TCP WFP event'}}
  $sessions=@(Get-WinFireActiveSession)
  $matches=@()
  foreach($evidence in $confirmed){
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$($evidence.processId)" -ErrorAction SilentlyContinue
    if(-not $process -or [int]$process.SessionId -le 0 -or ([datetime]$process.CreationDate) -gt ([datetime]$evidence.time).AddSeconds(1)) {continue}
    $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction SilentlyContinue
    if(-not $owner -or $owner.ReturnValue -ne 0 -or -not $owner.User) {continue}
    $name=if($owner.Domain){"$($owner.Domain)\$($owner.User)"}else{[string]$owner.User}
    $matching=@($sessions | Where-Object { $_.Id -eq $process.SessionId -and $_.User -ieq $name })
    if($matching.Count -eq 1){$matches+=,[pscustomobject]@{session=$matching[0];processId=$evidence.processId;recordId=$evidence.recordId}}
  }
  $sessionIds=@($matches | ForEach-Object { $_.session.Id } | Select-Object -Unique)
  if($sessionIds.Count -ne 1) {return [pscustomobject]@{opened=$false;reason='No single active session owns the matching client process';activeSessions=$sessions.Count}}
  $session=$matches[0].session
  if(@($sessions | Where-Object { $_.User -ieq $session.User }).Count -ne 1) {return [pscustomobject]@{opened=$false;reason='The matched user has multiple active sessions';activeSessions=$sessions.Count}}
  $name='WinFireMfaPrompt-'+$promptId.ToString('D')
  $encodedUrl=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($url.AbsoluteUri))
  $browserScript="Start-Process -FilePath ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$encodedUrl')))"
  $encodedScript=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($browserScript))
  $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encodedScript)
  $principal=New-ScheduledTaskPrincipal -UserId $session.User -LogonType Interactive -RunLevel Limited
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
  try {
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $name -ErrorAction Stop
    Start-Sleep -Milliseconds 800
    $info=Get-ScheduledTaskInfo -TaskName $name -ErrorAction Stop
    if($info.LastRunTime -lt (Get-Date).AddMinutes(-1)) {throw 'Interactive browser task did not run'}
    [pscustomobject]@{opened=$true;sessionId=$session.Id;user=$session.User;processId=$matches[0].processId;sourceEventRecordId=$matches[0].recordId;task=$name}
  } finally {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
  }
}
