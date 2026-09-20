
    function Get-WinFireBreakGlassPaths($sessionId) {
      $guid=[guid]::Parse([string]$sessionId)
      $name='WinFireBreakGlass-'+$guid.ToString('D')
      $folder=Join-Path $env:ProgramData 'WinFire\BreakGlass'
      [pscustomobject]@{name=$name;folder=$folder;file=(Join-Path $folder ($guid.ToString('D')+'.json'))}
    }
    function Get-WinFireProfiles($store='PersistentStore') {
      @(Get-NetFirewallProfile -PolicyStore $store | ForEach-Object { [pscustomobject]@{Name=[string]$_.Name;Enabled=($_.Enabled -eq 'True')} })
    }
    function Restore-WinFireProfiles($profiles) {
      foreach($profile in @($profiles)) {
        $name=[string]$profile.Name
        if($name -notin @('Domain','Private','Public')) {throw 'Invalid firewall profile snapshot'}
        if([bool]$profile.Enabled) {Set-NetFirewallProfile -Profile $name -Enabled True -ErrorAction Stop}
        else {Set-NetFirewallProfile -Profile $name -Enabled False -ErrorAction Stop}
      }
      $after=@(Get-WinFireProfiles)
      foreach($profile in @($profiles)) {
        $current=$after | Where-Object Name -eq $profile.Name | Select-Object -First 1
        if(!$current -or [bool]$current.Enabled -ne [bool]$profile.Enabled) {throw "Firewall profile $($profile.Name) was not restored"}
      }
      return $after
    }
    function Start-WinFireBreakGlass($data) {
      $paths=Get-WinFireBreakGlassPaths $data.sessionId
      $expiry=[datetimeoffset]::Parse([string]$data.expiresAt)
      if($expiry.UtcDateTime -le [datetime]::UtcNow.AddMinutes(1)) {throw 'Break-glass expiry must be in the future'}
      if(Test-Path -LiteralPath $paths.file) {throw 'Break-glass session already exists on host'}
      if(Get-ScheduledTask -TaskName $paths.name -ErrorAction SilentlyContinue) {throw 'Break-glass rollback task already exists'}
      $before=@(Get-WinFireProfiles)
      if($before.Count -ne 3) {throw 'Could not snapshot all firewall profiles'}
      New-Item -ItemType Directory -Path $paths.folder -Force | Out-Null
      $before | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $paths.file -Encoding UTF8 -ErrorAction Stop
      $path64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($paths.file))
      $restoreScript='$ErrorActionPreference="Stop"; $path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("'+$path64+'")); $profiles=@(Get-Content -Raw -LiteralPath $path | ConvertFrom-Json); foreach($p in $profiles){if($p.Name -notin @("Domain","Private","Public")){throw "Invalid firewall profile"}; if($p.Enabled){Set-NetFirewallProfile -Profile $p.Name -Enabled True -ErrorAction Stop}else{Set-NetFirewallProfile -Profile $p.Name -Enabled False -ErrorAction Stop}}; Remove-Item -LiteralPath $path -Force; Unregister-ScheduledTask -TaskName "'+$paths.name+'" -Confirm:$false'
      $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($restoreScript))
      $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
      $trigger=New-ScheduledTaskTrigger -Once -At $expiry.LocalDateTime
      $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
      $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable
      $registered=$false
      try {
        Register-ScheduledTask -TaskName $paths.name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
        $registered=$true
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False -ErrorAction Stop
        $after=@(Get-WinFireProfiles 'ActiveStore')
        if(@($after | Where-Object Enabled).Count) {throw 'Firewall profile readback did not confirm break glass'}
        [pscustomobject]@{active=$true;profiles=$before;expiresAt=$expiry.UtcDateTime.ToString('o');rollbackTask=$paths.name}
      } catch {
        $cause=$_
        try {Restore-WinFireProfiles $before | Out-Null} catch {throw "Break glass failed: $($cause.Exception.Message); profile rollback failed: $($_.Exception.Message)"}
        if($registered) {Unregister-ScheduledTask -TaskName $paths.name -Confirm:$false -ErrorAction SilentlyContinue}
        Remove-Item -LiteralPath $paths.file -Force -ErrorAction SilentlyContinue
        throw $cause
      }
    }
    function End-WinFireBreakGlass($data) {
      $paths=Get-WinFireBreakGlassPaths $data.sessionId
      $profiles=if(Test-Path -LiteralPath $paths.file) {@(Get-Content -Raw -LiteralPath $paths.file | ConvertFrom-Json)} else {@($data.profiles)}
      if(@($profiles).Count -ne 3) {throw 'Break-glass profile snapshot is unavailable'}
      $after=@(Restore-WinFireProfiles $profiles)
      if(Get-ScheduledTask -TaskName $paths.name -ErrorAction SilentlyContinue) {Unregister-ScheduledTask -TaskName $paths.name -Confirm:$false -ErrorAction Stop}
      Remove-Item -LiteralPath $paths.file -Force -ErrorAction SilentlyContinue
      [pscustomobject]@{restored=$true;profiles=$after}
    }
