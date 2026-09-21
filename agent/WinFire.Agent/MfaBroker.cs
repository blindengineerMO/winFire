using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;

namespace WinFire.Agent;

/// <summary>
/// Opens a source-scoped WinFire MFA portal in the active user's session.
/// The service runs as LocalSystem, so the embedded PowerShell launcher creates a
/// short-lived interactive scheduled task after validating the matching WFP event
/// and process owner. WinDivert packet interception and native MSAL/WAM remain a
/// separate optional broker layer.
/// </summary>
internal static class MfaBroker
{
    private const int TimeoutSeconds = 130;

    public static async Task<JsonElement> OpenAsync(JsonElement payload, CancellationToken cancellationToken)
    {
        Validate(payload);
        var functions = await LoadFunctionsAsync(cancellationToken);
        var payloadJson = payload.GetRawText();
        var payloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson));
        var script = $"{functions}\n$data=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payloadBase64}'))|ConvertFrom-Json; Open-WinFireMfaPortal $data | ConvertTo-Json -Compress -Depth 8";
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell\\v1.0\\powershell.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoLogo");
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-EncodedCommand");
        start.ArgumentList.Add(encoded);

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start the MFA browser launcher");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(TimeoutSeconds));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
            throw new TimeoutException("The MFA browser launcher timed out");
        }

        var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = await process.StandardError.ReadToEndAsync(cancellationToken);
        if (process.ExitCode != 0)
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? "The MFA browser launcher failed" : error.Trim()[..Math.Min(error.Trim().Length, 2000)]);

        var line = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).LastOrDefault(line => line.TrimStart().StartsWith('{'));
        if (line is null) throw new InvalidDataException("The MFA browser launcher returned no result");
        using var document = JsonDocument.Parse(line);
        return document.RootElement.Clone();
    }

    private static void Validate(JsonElement payload)
    {
        var promptId = payload.GetProperty("promptId").GetString();
        if (!Guid.TryParse(promptId, out var id)) throw new InvalidDataException("Invalid MFA prompt id");
        var url = payload.GetProperty("url").GetString();
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0 || uri.AbsolutePath != $"/mfa/{id:D}")
            throw new InvalidDataException("MFA prompt URL is not a valid HTTPS WinFire portal URL");
        ValidateIp(payload.GetProperty("sourceIp"));
        ValidateIp(payload.GetProperty("targetIp"));
        ValidatePort(payload.GetProperty("sourcePort"));
        ValidatePort(payload.GetProperty("port"));
    }

    private static void ValidateIp(JsonElement value)
    {
        if (!IPAddress.TryParse(value.GetString(), out _)) throw new InvalidDataException("Invalid MFA prompt address");
    }

    private static void ValidatePort(JsonElement value)
    {
        if (!value.TryGetInt32(out var port) || port is < 1 or > 65535) throw new InvalidDataException("Invalid MFA prompt port");
    }

    private static async Task<string> LoadFunctionsAsync(CancellationToken cancellationToken)
    {
        await using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("WinFire.Agent.MfaPrompt.ps1")
            ?? throw new InvalidOperationException("The MFA prompt launcher is missing from the agent package");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync(cancellationToken);
    }
}
