using WinFire.Agent;

if (args.Length > 0 && args[0].Equals("enroll", StringComparison.OrdinalIgnoreCase))
{
    if (args.Length != 2)
    {
        Console.Error.WriteLine("Usage: WinFire.Agent enroll <https://server:port> (token on stdin)");
        return 2;
    }
    var token = await Console.In.ReadLineAsync();
    if (string.IsNullOrWhiteSpace(token)) throw new ArgumentException("Enrollment token is required on stdin");
    await Enrollment.EnrollAsync(args[1], token);
    return 0;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "WinFireAgent");
builder.Services.AddHostedService<Worker>();
builder.Services.AddHostedService<EventLogWorker>();
await builder.Build().RunAsync();
return 0;
