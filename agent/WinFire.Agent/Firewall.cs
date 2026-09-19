using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace WinFire.Agent;

public static class Firewall
{
    private const string ApplyScript = """
        $ErrorActionPreference='Stop'
        $payload=[Console]::In.ReadToEnd() | ConvertFrom-Json
        $desired=@($payload.rules)
        function ReadManaged {
          @(Get-NetFirewallRule -Group $payload.group -ErrorAction SilentlyContinue | ForEach-Object {
            $rule=$_
            $port=$rule | Get-NetFirewallPortFilter
            $address=$rule | Get-NetFirewallAddressFilter
            $application=$rule | Get-NetFirewallApplicationFilter
            [pscustomobject]@{
              internalName=$rule.Name; name=$rule.DisplayName; action=([string]$rule.Action).ToLowerInvariant()
              direction=$(if($rule.Direction -eq 'Inbound'){'in'}else{'out'}); protocol=[string]$port.Protocol
              localPort=[string]$port.LocalPort; remotePort=[string]$port.RemotePort; remoteAddress=[string]$address.RemoteAddress
              program=[string]$application.Program; profile=[string]$rule.Profile
            }
          })
        }
        $existing=@(ReadManaged)
        function SameRule($left,$right) {
          foreach($field in @('name','action','direction','protocol','localPort','remotePort','remoteAddress','program','profile')) {
            $leftValue=if($field -eq 'remotePort' -and !$left.$field){'Any'}else{[string]$left.$field}
            $rightValue=if($field -eq 'remotePort' -and !$right.$field){'Any'}else{[string]$right.$field}
            if($leftValue.ToLowerInvariant() -ne $rightValue.ToLowerInvariant()) {return $false}
          }
          return $true
        }
        $toAdd=@($desired | Where-Object { $candidate=$_; -not @($existing | Where-Object {SameRule $_ $candidate}).Count })
        $toRemove=@($existing | Where-Object { $candidate=$_; -not @($desired | Where-Object {SameRule $_ $candidate}).Count })
        $created=@()
        try {
          foreach($rule in $toAdd) {
            $new=New-NetFirewallRule -DisplayName $rule.name -Group $payload.group -Direction $rule.direction -Action $rule.action -Protocol $rule.protocol -LocalPort $rule.localPort -RemotePort $(if($rule.remotePort){$rule.remotePort}else{'Any'}) -RemoteAddress $rule.remoteAddress -Program $rule.program -Profile $rule.profile -ErrorAction Stop
            $created+=,$new.Name
          }
          foreach($rule in $toRemove) {Remove-NetFirewallRule -Name $rule.internalName -ErrorAction Stop}
          $actual=@(ReadManaged)
          $pendingAdd=@($desired | Where-Object { $candidate=$_; -not @($actual | Where-Object {SameRule $_ $candidate}).Count })
          $pendingRemove=@($actual | Where-Object { $candidate=$_; -not @($desired | Where-Object {SameRule $_ $candidate}).Count })
          if($pendingAdd.Count -or $pendingRemove.Count){throw 'Firewall state differs from the requested policy after apply'}
        } catch {
          $applyError=$_; $rollbackErrors=@()
          foreach($name in $created) {try{if(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue){Remove-NetFirewallRule -Name $name -ErrorAction Stop}}catch{$rollbackErrors+=,"remove new rule $($name): $($_.Exception.Message)"}}
          foreach($rule in $toRemove) {
            try{if(-not (Get-NetFirewallRule -Name $rule.internalName -ErrorAction SilentlyContinue)){New-NetFirewallRule -DisplayName $rule.name -Group $payload.group -Direction $rule.direction -Action $rule.action -Protocol $rule.protocol -LocalPort $rule.localPort -RemotePort $rule.remotePort -RemoteAddress $rule.remoteAddress -Program $rule.program -Profile $rule.profile -ErrorAction Stop | Out-Null}}
            catch{$rollbackErrors+=,"restore old rule $($rule.name): $($_.Exception.Message)"}
          }
          if($rollbackErrors.Count){throw "Firewall apply failed: $($applyError.Exception.Message); rollback incomplete: $($rollbackErrors -join '; ')"}
          throw $applyError
        }
        [pscustomobject]@{add=@($toAdd | ForEach-Object name);remove=@($toRemove | ForEach-Object name)} | ConvertTo-Json -Depth 6 -Compress
        """;

    public static async Task<JsonElement> ApplyAsync(JsonElement payload, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows Firewall is required");
        if (!payload.TryGetProperty("group", out var group) || !group.GetString()!.StartsWith("WinFireSecure:", StringComparison.Ordinal))
            throw new InvalidDataException("Policy job has an invalid firewall group");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(90));
        var start = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-EncodedCommand");
        start.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(ApplyScript)));
        using var process = Process.Start(start) ?? throw new InvalidOperationException("PowerShell could not start");
        var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
        var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
        await process.StandardInput.WriteAsync(payload.GetRawText().AsMemory(), timeout.Token);
        process.StandardInput.Close();
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw; }
        var output = await stdout;
        var error = await stderr;
        if (process.ExitCode != 0) throw new InvalidOperationException(error.Trim());
        return JsonSerializer.Deserialize<JsonElement>(output);
    }
}
