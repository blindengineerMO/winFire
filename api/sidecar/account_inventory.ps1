function Get-WinFireAccountInventory {
  param($argsData)
  $computer=Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
  $isDomainController=([int]$computer.DomainRole -ge 4)
  $accounts=@()
  if(-not $isDomainController) {
    foreach($account in @(Get-WmiObject Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)) {
      if([string]$account.SID -notmatch '^S-1-\d+-\d+(?:-\d+)+$'){continue}
      $accounts+=New-Object PSObject -Property @{
        sid=[string]$account.SID;username=[string]$account.Name
        qualifiedName=([string]$computer.Name+'\'+[string]$account.Name)
        fullName=[string]$account.FullName;description=[string]$account.Description
        enabled=(-not [bool]$account.Disabled);locked=[bool]$account.Lockout
        passwordRequired=[bool]$account.PasswordRequired
      }
    }
  }
  $resolutions=@()
  foreach($sidText in @($argsData.sids | Select-Object -Unique | Select-Object -First 500)) {
    if([string]$sidText -notmatch '^S-1-\d+-\d+(?:-\d+)+$'){continue}
    try {
      $sid=New-Object Security.Principal.SecurityIdentifier -ArgumentList ([string]$sidText)
      $name=$sid.Translate([Security.Principal.NTAccount]).Value
      if($name -and $name -ne [string]$sidText){$resolutions+=New-Object PSObject -Property @{sid=[string]$sidText;qualifiedName=[string]$name}}
    } catch [Security.Principal.IdentityNotMappedException] {}
  }
  New-Object PSObject -Property @{computerName=[string]$computer.Name;domainController=$isDomainController;accounts=@($accounts);resolutions=@($resolutions)}
}
