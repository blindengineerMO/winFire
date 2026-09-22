using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace WinFire.Agent;

public sealed record AgentConfig(string ServerUrl, string AgentId, string NodeId, string CertificateThumbprint)
{
    internal static readonly string DirectoryPath = OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WinFire")
        : (Environment.GetEnvironmentVariable("WINFIRE_DATA_DIR") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "winfire"));
    private static readonly string ConfigPath = Path.Combine(DirectoryPath, "agent.json");
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static bool Exists => File.Exists(ConfigPath);

    public static AgentConfig Load() => JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(ConfigPath), JsonOptions)
        ?? throw new InvalidDataException("Agent configuration is empty");

    public void Save()
    {
        Directory.CreateDirectory(DirectoryPath);
        var temporary = ConfigPath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(this, JsonOptions));
        File.Move(temporary, ConfigPath, true);
    }

    public static X509Certificate2 LoadCertificate(string thumbprint)
    {
        if (!OperatingSystem.IsWindows())
        {
            var path = Path.Combine(DirectoryPath, "agent.pfx");
            if (!File.Exists(path)) throw new CryptographicException("Enrolled client certificate is missing");
            return X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(path), null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
            .OfType<X509Certificate2>()
            .FirstOrDefault(cert => cert.HasPrivateKey && cert.NotAfter > DateTime.Now)
            ?? throw new CryptographicException("Enrolled client certificate is missing or expired");
    }

    public static X509Certificate2 PersistCertificate(string certificatePem, ECDsa key)
    {
        using var withKey = X509Certificate2.CreateFromPem(certificatePem, key.ExportPkcs8PrivateKeyPem());
        Directory.CreateDirectory(DirectoryPath);
        if (!OperatingSystem.IsWindows())
        {
            var unixPfx = withKey.Export(X509ContentType.Pkcs12);
            File.WriteAllBytes(Path.Combine(DirectoryPath, "agent.pfx"), unixPfx);
            try { File.SetUnixFileMode(Path.Combine(DirectoryPath, "agent.pfx"), UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
            CryptographicOperations.ZeroMemory(unixPfx);
            return X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(Path.Combine(DirectoryPath, "agent.pfx")), null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }
        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var pfx = withKey.Export(X509ContentType.Pkcs12, password);
        var persisted = X509CertificateLoader.LoadPkcs12(pfx, password,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        store.Add(persisted);
        CryptographicOperations.ZeroMemory(pfx);
        return persisted;
    }
}
