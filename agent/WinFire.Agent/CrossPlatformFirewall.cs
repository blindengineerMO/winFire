using System.Diagnostics;
using System.Text.Json;

namespace WinFire.Agent;

/// <summary>Portable firewall adapter. Windows continues to use WFP/PowerShell;
/// Unix hosts use the firewall already installed by the operator.</summary>
internal static class CrossPlatformFirewall
{
    internal static async Task<string?> BackendNameAsync(CancellationToken cancellationToken) => (await DetectAsync(cancellationToken))?.Name;
    public static async Task<JsonElement> RunAsync(JsonElement payload, CancellationToken cancellationToken)
    {
        var backend = await DetectAsync(cancellationToken);
        if (backend is null) throw new PlatformNotSupportedException("No supported UFW, iptables, ipchains, or macOS pf firewall was found");
        var readOnly = payload.TryGetProperty("readOnly", out var ro) && ro.GetBoolean();
        if (readOnly)
        {
            var output = await RunCommandAsync(backend.Value.Command, backend.Value.ReadArguments, cancellationToken);
            return JsonSerializer.SerializeToElement(new { backend = backend.Value.Name, rules = Array.Empty<object>(), raw = output });
        }
        if (!payload.TryGetProperty("rules", out var rules) || rules.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Portable firewall policy has no rules");
        var applied = 0;
        foreach (var rule in rules.EnumerateArray())
        {
            var action = Get(rule, "action").ToLowerInvariant();
            var direction = Get(rule, "direction").ToLowerInvariant();
            var protocol = Get(rule, "protocol").ToLowerInvariant();
            var port = Get(rule, direction == "in" ? "localPort" : "remotePort");
            var address = Get(rule, "remoteAddress");
            if (action is not ("allow" or "block") || direction is not ("in" or "out") || protocol is not ("tcp" or "udp") || !ValidPort(port))
                throw new InvalidDataException("Portable firewall rules require allow/block, in/out, TCP/UDP, and one port");
            if (backend.Value.Name == "ufw")
            {
                var verb = action == "allow" ? "allow" : "deny";
                var args = new List<string> { verb };
                if (direction == "out") args.Add("out");
                if (direction == "in") { args.Add("from"); args.Add(address is "" or "Any" ? "any" : address); args.Add("to"); args.Add("any"); }
                else { args.Add("from"); args.Add("any"); args.Add("to"); args.Add(address is "" or "Any" ? "any" : address); }
                args.Add("port"); args.Add(port); args.Add("proto"); args.Add(protocol);
                await RunCommandAsync("ufw", args, cancellationToken); applied++;
            }
            else if (backend.Value.Name == "iptables")
            {
                var chain = direction == "in" ? "INPUT" : "OUTPUT";
                var target = action == "allow" ? "ACCEPT" : "DROP";
                var args = new List<string> { "-A", chain, "-p", protocol, "--dport", port, "-j", target, "-m", "comment", "--comment", "WinFire" };
                if (address is not ("" or "Any")) args.InsertRange(3, new[] { direction == "in" ? "-s" : "-d", address });
                await RunCommandAsync("iptables", args, cancellationToken); applied++;
            }
            else throw new PlatformNotSupportedException("ipchains and pf are currently read-only; use the host firewall manager to apply a policy");
        }
        return JsonSerializer.SerializeToElement(new { backend = backend.Value.Name, applied });
    }

    private static bool ValidPort(string value) => int.TryParse(value, out var port) && port is > 0 and <= 65535;
    private static string Get(JsonElement value, string name) => value.TryGetProperty(name, out var item) ? item.ToString() : "";
    private static async Task<(string Name, string Command, string[] ReadArguments)?> DetectAsync(CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsLinux())
        {
            if (await ExistsAsync("ufw", cancellationToken)) return ("ufw", "ufw", ["status", "verbose"]);
            if (await ExistsAsync("iptables", cancellationToken)) return ("iptables", "iptables", ["-S"]);
            if (await ExistsAsync("ipchains", cancellationToken)) return ("ipchains", "ipchains", ["-L", "-n"]);
        }
        if (OperatingSystem.IsMacOS() && await ExistsAsync("pfctl", cancellationToken)) return ("pf", "pfctl", ["-sr"]);
        return null;
    }
    private static async Task<bool> ExistsAsync(string command, CancellationToken token)
    { try { await RunCommandAsync("which", [command], token); return true; } catch { return false; } }
    private static async Task<string> RunCommandAsync(string command, IEnumerable<string> arguments, CancellationToken token)
    {
        var start = new ProcessStartInfo(command) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Unable to start {command}");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token); var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
        await process.WaitForExitAsync(timeout.Token); var output = await stdout; var error = await stderr;
        if (process.ExitCode != 0) throw new InvalidOperationException(error.Trim().Length == 0 ? $"{command} exited with {process.ExitCode}" : error.Trim());
        return output.Trim();
    }
}
