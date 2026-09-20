function Get-WinFireLocalUserSid {
  param($rule)
  $filter=$rule | Get-NetFirewallSecurityFilter -ErrorAction Stop
  $value=[string]$filter.LocalUser
  if($value -match 'S-1-\d+-\d+(?:-\d+)+') { return $Matches[0] }
  return $null
}

function New-WinFireFirewallRule {
  param($rule,$group)
  $options=@{
    DisplayName=$rule.name;Group=$group;Direction=$rule.direction;Action=$rule.action
    Protocol=$rule.protocol;LocalPort=$rule.localPort
    RemotePort=$(if($rule.remotePort){$rule.remotePort}else{'Any'})
    RemoteAddress=$rule.remoteAddress;Program=$rule.program;Profile=$rule.profile
    ErrorAction='Stop'
  }
  if($rule.localUserSid) {
    $sid=[string]$rule.localUserSid
    if($sid -notmatch '^S-1-\d+-\d+(?:-\d+)+$' -or [string]$rule.direction -notmatch '^(out|outbound)$' -or [string]$rule.action -notmatch '^block$') { throw 'Invalid local user firewall restriction' }
    $options.LocalUser="D:(A;;CC;;;$sid)"
  }
  New-NetFirewallRule @options
}
