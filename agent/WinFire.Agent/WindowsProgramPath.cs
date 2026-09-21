using System.Runtime.InteropServices;
using System.Text;

namespace WinFire.Agent;

internal static class WindowsProgramPath
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryDosDeviceW", SetLastError = true)]
    private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, uint capacity);

    internal static IReadOnlyList<(string Device, string Drive)> GetMappings()
    {
        if (!OperatingSystem.IsWindows()) return [];
        var mappings = new List<(string Device, string Drive)>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.Name.Length < 2 || drive.Name[1] != ':') continue;
            try
            {
                var target = new StringBuilder(4096);
                if (QueryDosDevice(drive.Name[..2], target, (uint)target.Capacity) == 0) continue;
                var device = target.ToString().Split('\0', 2)[0];
                if (device.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                    mappings.Add((device, drive.Name[..2]));
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                // An inaccessible drive must not stop Security log delivery.
            }
        }
        return mappings.OrderByDescending(item => item.Device.Length).ToArray();
    }

    internal static string Normalize(string path, IEnumerable<(string Device, string Drive)> mappings)
    {
        if (!path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) return path;
        foreach (var (device, drive) in mappings)
        {
            if (path.Length > device.Length && path.StartsWith(device, StringComparison.OrdinalIgnoreCase) && path[device.Length] == '\\')
                return drive + path[device.Length..];
        }
        return path;
    }
}
