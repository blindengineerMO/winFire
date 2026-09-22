using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace WinFire.Agent;

public sealed class Worker(ILogger<Worker> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly string AgentVersion = typeof(Worker).Assembly.GetName().Version?.ToString(3) ?? "unknown";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var pollSeconds = 30;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (!AgentConfig.Exists)
                {
                    await EnrollFromInstallerAsync();
                    logger.LogInformation("Agent enrolled from the MSI bootstrap values");
                }
                var config = AgentConfig.Load();
                using var cert = AgentConfig.LoadCertificate(config.CertificateThumbprint);
                using var handler = new HttpClientHandler { ClientCertificateOptions = ClientCertificateOption.Manual };
                handler.ClientCertificates.Add(cert);
                using var client = new HttpClient(handler)
                {
                    BaseAddress = new Uri(config.ServerUrl.TrimEnd('/') + "/"),
                    Timeout = TimeSpan.FromSeconds(90)
                };
                if (cert.NotAfter.ToUniversalTime() < DateTime.UtcNow.AddDays(1))
                {
                    await Enrollment.RenewAsync(config, client, stoppingToken);
                    logger.LogInformation("Agent certificate renewed");
                    continue;
                }
                var firewallBackend = OperatingSystem.IsWindows() ? "windows-filtering-platform" : await CrossPlatformFirewall.BackendNameAsync(stoppingToken) ?? "unavailable";
                using var heartbeat = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/heartbeat",
                    new { version = AgentVersion, mode = "pull", platform = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsMacOS() ? "macos" : "other", osVersion = Environment.OSVersion.VersionString, firewallBackend, capabilities = new[] { "network-telemetry", "arp" } }, JsonOptions, stoppingToken);
                heartbeat.EnsureSuccessStatusCode();
                var heartbeatSettings = await heartbeat.Content.ReadFromJsonAsync<HeartbeatSettings>(JsonOptions, stoppingToken);
                if (heartbeatSettings?.PollSeconds is >= 15 and <= 300) pollSeconds = heartbeatSettings.PollSeconds;
                if (OperatingSystem.IsWindows() && heartbeatSettings?.Update is { Available: true } update)
                {
                    await AgentUpdater.StageAndRestartAsync(client, update, logger, stoppingToken);
                    return;
                }
                if (heartbeatSettings?.ChannelMode == "push")
                {
                    await RunPushAsync(client, config, heartbeatSettings.PushUrl ?? $"api/v1/agents/{config.AgentId}/stream", stoppingToken);
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                    continue;
                }
                var pending = await client.GetFromJsonAsync<JobResponse>($"api/v1/agents/{config.AgentId}/jobs", JsonOptions, stoppingToken);
                foreach (var job in pending?.Jobs ?? [])
                    await RunJobAsync(client, config, job, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error) { logger.LogError(error, "Agent cycle failed"); }
            await Task.Delay(TimeSpan.FromSeconds(pollSeconds), stoppingToken);
        }
    }

    private async Task RunPushAsync(HttpClient client, AgentConfig config, string streamUrl, CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync(streamUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var reader = new StreamReader(stream);
        var data = new StringBuilder();
        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null) break;
            if (line.StartsWith("data: ", StringComparison.Ordinal)) data.Append(line[6..]);
            if (line.Length != 0 || data.Length == 0) continue;
            using var document = JsonDocument.Parse(data.ToString());
            if (document.RootElement.TryGetProperty("id", out _))
            {
                var job = document.RootElement.Deserialize<AgentJob>(JsonOptions)
                    ?? throw new InvalidDataException("Push job payload is empty");
                await RunJobAsync(client, config, job, cancellationToken);
            }
            data.Clear();
        }
    }

    private static async Task EnrollFromInstallerAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            var unixServerUrl = Environment.GetEnvironmentVariable("WINFIRE_SERVER_URL");
            var unixToken = Environment.GetEnvironmentVariable("WINFIRE_ENROLLMENT_TOKEN");
            if (string.IsNullOrWhiteSpace(unixServerUrl) || string.IsNullOrWhiteSpace(unixToken)) throw new InvalidOperationException("Agent is not enrolled; set WINFIRE_SERVER_URL and WINFIRE_ENROLLMENT_TOKEN");
            await Enrollment.EnrollAsync(unixServerUrl, unixToken);
            return;
        }
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WinFire", writable: true)
            ?? throw new InvalidOperationException("Agent is not enrolled and MSI bootstrap values are missing");
        var serverUrl = key.GetValue("BootstrapServer") as string;
        var token = key.GetValue("BootstrapToken") as string;
        if (string.IsNullOrWhiteSpace(serverUrl) || string.IsNullOrWhiteSpace(token))
            throw new InvalidOperationException("Agent is not enrolled and MSI bootstrap values are incomplete");
        await Enrollment.EnrollAsync(serverUrl, token);
        key.DeleteValue("BootstrapToken", throwOnMissingValue: false);
        key.DeleteValue("BootstrapServer", throwOnMissingValue: false);
    }

    private async Task RunJobAsync(HttpClient client, AgentConfig config, AgentJob job, CancellationToken cancellationToken)
    {
        try
        {
            HttpResponseMessage response;
            if (job.Type == "policy.apply")
            {
                var diff = await Firewall.ApplyAsync(job.Payload, cancellationToken);
                response = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/jobs/{job.Id}/result",
                    new { leaseToken = job.LeaseToken, success = true, diff }, JsonOptions, cancellationToken);
            }
            else if (job.Type == "policy.read")
            {
                var result = await Firewall.ReadAsync(job.Payload, cancellationToken);
                response = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/jobs/{job.Id}/result",
                    new { leaseToken = job.LeaseToken, success = true, result }, JsonOptions, cancellationToken);
            }
            else if (job.Type is "breakglass.start" or "breakglass.end")
            {
                var result = await BreakGlass.RunAsync(job.Payload, cancellationToken);
                response = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/jobs/{job.Id}/result",
                    new { leaseToken = job.LeaseToken, success = true, result }, JsonOptions, cancellationToken);
            }
            else if (job.Type == "mfa.prompt")
            {
                var result = await MfaBroker.OpenAsync(job.Payload, cancellationToken);
                response = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/jobs/{job.Id}/result",
                    new { leaseToken = job.LeaseToken, success = true, result }, JsonOptions, cancellationToken);
            }
            else if (job.Type == "arp.collect")
            {
                var arp = await NetworkTelemetryWorker.ReadArpAsync(cancellationToken);
                response = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/jobs/{job.Id}/result",
                    new { leaseToken = job.LeaseToken, success = true, result = new { arp } }, JsonOptions, cancellationToken);
            }
            else throw new InvalidOperationException($"Unsupported job type: {job.Type}");
            using (response) response.EnsureSuccessStatusCode();
            logger.LogInformation("Completed agent job {JobId}", job.Id);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            logger.LogError(error, "Agent job {JobId} failed", job.Id);
            using var response = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/jobs/{job.Id}/result",
                new { leaseToken = job.LeaseToken, success = false, error = error.Message[..Math.Min(error.Message.Length, 2000)] }, JsonOptions, cancellationToken);
            response.EnsureSuccessStatusCode();
        }
    }

    private sealed record JobResponse(List<AgentJob> Jobs);
    private sealed record HeartbeatSettings(int PollSeconds, string? ChannelMode, string? PushUrl, AgentUpdateManifest? Update);
    private sealed record AgentJob(string Id, string Type, JsonElement Payload, int Attempt, string LeaseToken);
}
