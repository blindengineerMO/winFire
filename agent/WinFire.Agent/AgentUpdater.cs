using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WinFire.Agent;

public static class AgentUpdater
{
    private const long MaximumPackageBytes = 250L * 1024 * 1024;

    public static async Task<bool> StageAndRestartAsync(
        HttpClient client,
        AgentUpdateManifest manifest,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        if (!manifest.Available || string.IsNullOrWhiteSpace(manifest.PackageUrl) ||
            string.IsNullOrWhiteSpace(manifest.Sha256) || string.IsNullOrWhiteSpace(manifest.SignerThumbprint))
            return false;
        if (manifest.Size is <= 0 or > MaximumPackageBytes)
            throw new InvalidDataException("Agent update package size is outside the permitted range");
        try { if (Convert.FromHexString(manifest.Sha256).Length != 32) throw new FormatException(); }
        catch (FormatException) { throw new InvalidDataException("Agent update manifest has an invalid SHA-256"); }
        if (!IsThumbprint(manifest.SignerThumbprint))
            throw new InvalidDataException("Agent update manifest has an invalid signer thumbprint");

        var updateDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WinFire", "updates");
        Directory.CreateDirectory(updateDirectory);
        var id = Guid.NewGuid().ToString("N");
        var staged = Path.Combine(updateDirectory, $"WinFire.Agent.{id}.exe");
        var script = Path.Combine(updateDirectory, $"apply.{id}.ps1");
        try
        {
            using var response = await client.GetAsync(manifest.PackageUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is long length && length > MaximumPackageBytes)
                throw new InvalidDataException("Agent update package is too large");
            await using (var input = await response.Content.ReadAsStreamAsync(cancellationToken))
            await using (var output = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None, 128 * 1024, FileOptions.SequentialScan))
            {
                var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[128 * 1024];
                long total = 0;
                int read;
                while ((read = await input.ReadAsync(buffer, cancellationToken)) > 0)
                {
                    total += read;
                    if (total > MaximumPackageBytes) throw new InvalidDataException("Agent update package is too large");
                    digest.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
                if (total != manifest.Size) throw new InvalidDataException("Agent update package size does not match the control-plane manifest");
                var actual = Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();
                if (!CryptographicOperations.FixedTimeEquals(
                        Encoding.UTF8.GetBytes(actual), Encoding.UTF8.GetBytes(manifest.Sha256.ToLowerInvariant())))
                    throw new CryptographicException("Agent update SHA-256 does not match the control-plane manifest");
            }

            var target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinFire", "WinFire.Agent.exe");
            await File.WriteAllTextAsync(script, UpdateScript, Encoding.UTF8, cancellationToken);
            var start = new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true
            };
            start.ArgumentList.Add("-NoLogo");
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-NonInteractive");
            start.ArgumentList.Add("-ExecutionPolicy");
            start.ArgumentList.Add("Bypass");
            start.ArgumentList.Add("-File");
            start.ArgumentList.Add(script);
            start.ArgumentList.Add("-StagedPath");
            start.ArgumentList.Add(staged);
            start.ArgumentList.Add("-TargetPath");
            start.ArgumentList.Add(target);
            start.ArgumentList.Add("-ExpectedSigner");
            start.ArgumentList.Add(manifest.SignerThumbprint);
            start.ArgumentList.Add("-ServiceName");
            start.ArgumentList.Add("WinFireAgent");
            Process.Start(start)?.Dispose();
            logger.LogInformation("Staged signed agent update {Version}; the Windows service will restart", manifest.Version);
            return true;
        }
        catch
        {
            TryDelete(staged);
            TryDelete(script);
            throw;
        }
    }

    private static bool IsThumbprint(string value) => value.Length == 40 && value.All(Uri.IsHexDigit);
    private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }

    private const string UpdateScript = @"
param([Parameter(Mandatory=$true)][string]$StagedPath,[Parameter(Mandatory=$true)][string]$TargetPath,[Parameter(Mandatory=$true)][string]$ExpectedSigner,[Parameter(Mandatory=$true)][string]$ServiceName)
$ErrorActionPreference='Stop'
try {
  $signature=Get-AuthenticodeSignature -FilePath $StagedPath
  if($signature.Status -ne 'Valid'){ throw 'Agent update Authenticode signature is not valid.' }
  $actual=([string]$signature.SignerCertificate.Thumbprint -replace '[^0-9A-Fa-f]','').ToUpperInvariant()
  if($actual -ne $ExpectedSigner.ToUpperInvariant()){ throw 'Agent update signer does not match the control-plane pin.' }
  for($attempt=0;$attempt -lt 30;$attempt++) {
    try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 500 }
  }
  Start-Sleep -Milliseconds 500
  Move-Item -LiteralPath $StagedPath -Destination $TargetPath -Force
  Start-Service -Name $ServiceName -ErrorAction Stop
} finally {
  Remove-Item -LiteralPath $StagedPath -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
}
";
}

public sealed record AgentUpdateManifest(bool Available, string? Version, string? Sha256, long Size, string? SignerThumbprint, string? PackageUrl);
