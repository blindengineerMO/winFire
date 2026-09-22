using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace WinFire.Agent;

public static class Enrollment
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task EnrollAsync(string serverUrl, string token)
    {
        var baseUri = new Uri(serverUrl.TrimEnd('/') + "/");
        if (baseUri.Scheme != Uri.UriSchemeHttps) throw new ArgumentException("Agent enrollment requires HTTPS");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = CreateCsr(key);
        using var http = new HttpClient { BaseAddress = baseUri, Timeout = TimeSpan.FromSeconds(30) };
        using var response = await http.PostAsJsonAsync("api/v1/agents/enroll", new { token, csr }, JsonOptions);
        response.EnsureSuccessStatusCode();
        var signed = await response.Content.ReadFromJsonAsync<EnrollmentResponse>(JsonOptions)
            ?? throw new InvalidDataException("Enrollment response is empty");
        using var certificate = AgentConfig.PersistCertificate(signed.Certificate, key);
        new AgentConfig(baseUri.ToString().TrimEnd('/'), signed.AgentId, signed.NodeId, certificate.Thumbprint).Save();
        Console.WriteLine($"Enrolled agent {signed.AgentId} for node {signed.NodeId}; certificate expires {signed.ExpiresAt:u}");
    }

    public static async Task<AgentConfig> RenewAsync(AgentConfig config, HttpClient client, CancellationToken cancellationToken)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var response = await client.PostAsJsonAsync($"api/v1/agents/{config.AgentId}/renew", new { csr = CreateCsr(key) }, JsonOptions, cancellationToken);
        response.EnsureSuccessStatusCode();
        var signed = await response.Content.ReadFromJsonAsync<EnrollmentResponse>(JsonOptions, cancellationToken)
            ?? throw new InvalidDataException("Renewal response is empty");
        using var certificate = AgentConfig.PersistCertificate(signed.Certificate, key);
        var renewed = config with { CertificateThumbprint = certificate.Thumbprint };
        renewed.Save();
        return renewed;
    }

    private static string CreateCsr(ECDsa key)
    {
        var request = new CertificateRequest("CN=WinFire agent", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        return PemEncoding.WriteString("CERTIFICATE REQUEST", request.CreateSigningRequest());
    }

    private sealed record EnrollmentResponse(string AgentId, string NodeId, string Certificate, string CaCertificate, DateTimeOffset ExpiresAt);
}
