using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;

namespace WinFire.Agent;

/// <summary>Collects a bounded view of active sockets and neighbor discovery on
/// Linux, macOS, and Windows. It intentionally sends metadata only; packet
/// capture remains outside the universal agent.</summary>
public sealed class NetworkTelemetryWorker(ILogger<NetworkTelemetryWorker> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (AgentConfig.Exists)
                {
                    var config = AgentConfig.Load();
                    using var cert = AgentConfig.LoadCertificate(config.CertificateThumbprint);
                    using var handler = new HttpClientHandler { ClientCertificateOptions = ClientCertificateOption.Manual };
                    handler.ClientCertificates.Add(cert);
                    using var client = new HttpClient(handler) { BaseAddress = new Uri(config.ServerUrl.TrimEnd('/') + "/"), Timeout = TimeSpan.FromSeconds(30) };
                    var flows = await ReadFlowsAsync(stoppingToken); var arp = await ReadArpAsync(stoppingToken);
                    if (flows.Count != 0 || arp.Count != 0)
                    {
                        using var response = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/network", new { flows, arp }, JsonOptions, stoppingToken);
                        response.EnsureSuccessStatusCode();
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error) { logger.LogDebug(error, "Network telemetry collection failed"); }
            await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);
        }
    }

    private static async Task<List<Flow>> ReadFlowsAsync(CancellationToken token)
    {
        var lines = OperatingSystem.IsWindows() ? await CommandAsync("netstat", ["-ano"], token) : await CommandAsync("ss", ["-Htun"], token);
        var result = new List<Flow>();
        foreach (var line in lines.Split('\n', StringSplitOptions.RemoveEmptyEntries).Take(2000))
        {
            var fields = line.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 4) continue;
            var protocol = fields[0].ToUpperInvariant();
            var local = OperatingSystem.IsWindows() ? fields.ElementAtOrDefault(1) ?? "" : fields.ElementAtOrDefault(4) ?? "";
            var remote = OperatingSystem.IsWindows() ? fields.ElementAtOrDefault(2) ?? "" : fields.ElementAtOrDefault(5) ?? "";
            if (!TryEndpoint(local, out var srcIp, out var srcPort) || !TryEndpoint(remote, out var dstIp, out var dstPort)) continue;
            result.Add(new Flow(srcIp, dstIp, srcPort, dstPort, protocol.StartsWith("TCP") ? "TCP" : "UDP", "out", null, "firewall", DateTimeOffset.UtcNow));
        }
        return result;
    }
    internal static async Task<List<ArpObservation>> ReadArpAsync(CancellationToken token)
    {
        var output = OperatingSystem.IsWindows() ? await CommandAsync("arp", ["-a"], token) : OperatingSystem.IsMacOS() ? await CommandAsync("ndp", ["-an"], token) : await CommandAsync("ip", ["neigh"], token);
        var result = new List<ArpObservation>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Take(5000))
        {
            var fields = line.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries); if (fields.Length < 2) continue;
            var ip = fields.FirstOrDefault(value => System.Net.IPAddress.TryParse(value.Trim('(', ')'), out _)); if (ip is null) continue;
            var mac = fields.FirstOrDefault(value => value.Count(c => c == ':') == 5 || value.Count(c => c == '-') == 5);
            var iface = fields.FirstOrDefault(value => value is "dev" or "on") is { } marker ? fields.ElementAtOrDefault(Array.IndexOf(fields, marker) + 1) : null;
            result.Add(new ArpObservation(ip, mac, null, iface, fields.LastOrDefault(), DateTimeOffset.UtcNow));
        }
        return result;
    }
    private static bool TryEndpoint(string value, out string ip, out int port)
    {
        ip = ""; port = 0; value = value.Trim(); if (value == "*:*" || value == "0.0.0.0:0") return false;
        var split = value.LastIndexOf(':'); if (split < 0) return false; ip = value[..split].Trim('[', ']'); return int.TryParse(value[(split + 1)..], out port) && port > 0 && System.Net.IPAddress.TryParse(ip, out _);
    }
    private static async Task<string> CommandAsync(string file, IEnumerable<string> args, CancellationToken token)
    {
        try { var start = new ProcessStartInfo(file) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true }; foreach (var arg in args) start.ArgumentList.Add(arg); using var process = Process.Start(start); if (process is null) return ""; using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(10)); var output = await process.StandardOutput.ReadToEndAsync(timeout.Token); await process.WaitForExitAsync(timeout.Token); return output; } catch { return ""; }
    }
    private sealed record Flow(string SrcIp, string DstIp, int SrcPort, int DstPort, string Protocol, string Direction, string? Program, string EventType, DateTimeOffset EventTime);
    internal sealed record ArpObservation(string Ip, string? Mac, string? Hostname, string? Interface, string? State, DateTimeOffset ObservedAt);
}
