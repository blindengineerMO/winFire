using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.Json;

namespace WinFire.Agent;

public static class BreakGlass
{
    private static readonly string Script = LoadScript();

    private static string LoadScript()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("WinFire.Agent.BreakGlass.ps1")
            ?? throw new InvalidOperationException("Break-glass PowerShell resource is missing");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    public static async Task<JsonElement> RunAsync(JsonElement payload, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows Firewall is required");
        if (!payload.TryGetProperty("sessionId", out var sessionId) || !Guid.TryParse(sessionId.GetString(), out _))
            throw new InvalidDataException("Break-glass session ID is invalid");
        if (!payload.TryGetProperty("action", out var action) || action.GetString() is not ("start" or "end"))
            throw new InvalidDataException("Break-glass action is invalid");
        if (action.GetString() == "start")
        {
            if (!payload.TryGetProperty("expiresAt", out var expiresAt) || !DateTimeOffset.TryParse(expiresAt.GetString(), out var expiry)
                || expiry <= DateTimeOffset.UtcNow.AddMinutes(1) || expiry > DateTimeOffset.UtcNow.AddHours(4))
                throw new InvalidDataException("Break-glass expiry is outside the allowed window");
        }
        const string entry = """
            $ErrorActionPreference='Stop'
            $payload=[Console]::In.ReadToEnd() | ConvertFrom-Json
            if($payload.action -eq 'start') {$result=Start-WinFireBreakGlass $payload}
            elseif($payload.action -eq 'end') {$result=End-WinFireBreakGlass $payload}
            else {throw 'Invalid break-glass action'}
            $result | ConvertTo-Json -Depth 6 -Compress
            """;
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
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(Script + "\n" + entry)) })
            start.ArgumentList.Add(argument);
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
