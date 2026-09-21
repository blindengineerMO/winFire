using System.Diagnostics.Eventing.Reader;
using System.Net.Http.Json;
using System.Text.Json;
using System.Xml.Linq;

namespace WinFire.Agent;

public sealed class EventLogWorker(ILogger<EventLogWorker> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly string CursorPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WinFire", "events.cursor");
    private const string EventIds = "(EventID=5156 or EventID=5157 or EventID=5150 or EventID=5151 or EventID=4624 or EventID=4625 or EventID=5712)";
    private readonly SemaphoreSlim _changed = new(0, 1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows()) return;
        EventLogWatcher? watcher = null;
        try
        {
            watcher = new EventLogWatcher(new EventLogQuery("Security", PathType.LogName, $"*[System[{EventIds}]]"));
            watcher.EventRecordWritten += (_, args) =>
            {
                args.EventRecord?.Dispose();
                if (args.EventException is not null) logger.LogWarning(args.EventException, "Security event watcher failed");
                if (_changed.CurrentCount == 0) _changed.Release();
            };
            watcher.Enabled = true;
        }
        catch (Exception error)
        {
            watcher?.Dispose();
            watcher = null;
            logger.LogWarning(error, "Security event watcher unavailable; using periodic reads");
        }

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var config = AgentConfig.Load();
                    using var cert = AgentConfig.LoadCertificate(config.CertificateThumbprint);
                    using var handler = new HttpClientHandler { ClientCertificateOptions = ClientCertificateOption.Manual };
                    handler.ClientCertificates.Add(cert);
                    using var client = new HttpClient(handler) { BaseAddress = new Uri(config.ServerUrl.TrimEnd('/') + "/"), Timeout = TimeSpan.FromSeconds(90) };
                    var cursor = ReadCursor(config.NodeId);
                    var fullBatch = false;
                    for (var page = 0; page < 5; page++)
                    {
                        var events = ReadEvents(cursor);
                        if (events.Count == 0) { fullBatch = false; break; }
                        using var response = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/events", new { events }, JsonOptions, stoppingToken);
                        response.EnsureSuccessStatusCode();
                        cursor = events[^1].RecordId;
                        WriteCursor(config.NodeId, cursor);
                        fullBatch = events.Count == 500;
                        if (!fullBatch) break;
                    }
                    if (fullBatch) continue;
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception error) { logger.LogError(error, "Security event shipment failed; cursor retained for retry"); }
                await _changed.WaitAsync(TimeSpan.FromSeconds(30), stoppingToken);
            }
        }
        finally { watcher?.Dispose(); _changed.Dispose(); }
    }

    private static List<SecurityEvent> ReadEvents(long cursor)
    {
        var query = new EventLogQuery("Security", PathType.LogName, $"*[System[{EventIds} and EventRecordID > {cursor}]]");
        using var reader = new EventLogReader(query);
        var events = new List<SecurityEvent>(500);
        var driveMappings = WindowsProgramPath.GetMappings();
        while (events.Count < 500)
        {
            using var record = reader.ReadEvent();
            if (record is null) break;
            if (record.RecordId is not long recordId || recordId <= cursor) continue;
            var fields = new Dictionary<string, string>();
            var xml = XDocument.Parse(record.ToXml());
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            foreach (var data in xml.Root?.Element(ns + "EventData")?.Elements(ns + "Data") ?? [])
            {
                var name = (string?)data.Attribute("Name");
                if (!string.IsNullOrEmpty(name)) fields[name] = data.Value;
            }
            if (fields.TryGetValue("Application", out var application))
                fields["Application"] = WindowsProgramPath.Normalize(application, driveMappings);
            if (fields.TryGetValue("ProcessName", out var processName))
                fields["ProcessName"] = WindowsProgramPath.Normalize(processName, driveMappings);
            events.Add(new SecurityEvent(recordId, record.Id,
                (record.TimeCreated ?? DateTime.UtcNow).ToUniversalTime().ToString("o"), fields));
        }
        return events;
    }

    private static long ReadCursor(string nodeId)
    {
        if (!File.Exists(CursorPath)) return 0;
        var parts = File.ReadAllText(CursorPath).Split(':', 2);
        return parts.Length == 2 && parts[0] == nodeId && long.TryParse(parts[1], out var cursor) ? cursor : 0;
    }

    private static void WriteCursor(string nodeId, long cursor)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(CursorPath)!);
        var temporary = CursorPath + ".tmp";
        File.WriteAllText(temporary, $"{nodeId}:{cursor}");
        File.Move(temporary, CursorPath, true);
    }

    private sealed record SecurityEvent(long RecordId, int Id, string TimeCreated, Dictionary<string, string> Fields);
}
