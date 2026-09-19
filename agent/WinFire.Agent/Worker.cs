using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace WinFire.Agent;

public sealed class Worker(ILogger<Worker> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The WinFire agent runs as a Windows Service");
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
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
                using var heartbeat = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/heartbeat",
                    new { version = "0.1.0", mode = "pull" }, JsonOptions, stoppingToken);
                heartbeat.EnsureSuccessStatusCode();
                var pending = await client.GetFromJsonAsync<JobResponse>($"api/v1/agents/{config.AgentId}/jobs", JsonOptions, stoppingToken);
                foreach (var job in pending?.Jobs ?? [])
                    await RunJobAsync(client, config, job, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error) { logger.LogError(error, "Agent cycle failed"); }
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }

    private async Task RunJobAsync(HttpClient client, AgentConfig config, AgentJob job, CancellationToken cancellationToken)
    {
        try
        {
            if (job.Type != "policy.apply") throw new InvalidOperationException($"Unsupported job type: {job.Type}");
            var diff = await Firewall.ApplyAsync(job.Payload, cancellationToken);
            using var response = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/jobs/{job.Id}/result",
                new { leaseToken = job.LeaseToken, success = true, diff }, JsonOptions, cancellationToken);
            response.EnsureSuccessStatusCode();
            logger.LogInformation("Applied policy job {JobId}", job.Id);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            logger.LogError(error, "Policy job {JobId} failed", job.Id);
            using var response = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/jobs/{job.Id}/result",
                new { leaseToken = job.LeaseToken, success = false, error = error.Message[..Math.Min(error.Message.Length, 2000)] }, JsonOptions, cancellationToken);
            response.EnsureSuccessStatusCode();
        }
    }

    private sealed record JobResponse(List<AgentJob> Jobs);
    private sealed record AgentJob(string Id, string Type, JsonElement Payload, int Attempt, string LeaseToken);
}
