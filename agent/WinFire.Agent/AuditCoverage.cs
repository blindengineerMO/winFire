using System.Runtime.InteropServices;

namespace WinFire.Agent;

internal static class AuditCoverage
{
    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid Subcategory;
        public uint Information;
        public Guid Category;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQuerySystemPolicy(ref Guid subcategory, uint count, out IntPtr policy);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

    internal static bool? SuccessAuditingEnabled()
    {
        if (!OperatingSystem.IsWindows()) return null;
        var subcategory = new Guid("0cce9226-69ae-11d9-bed3-505054503030");
        if (!AuditQuerySystemPolicy(ref subcategory, 1, out var buffer)) return null;
        try { return (Marshal.PtrToStructure<AuditPolicyInformation>(buffer).Information & 1) != 0; }
        finally { AuditFree(buffer); }
    }
}
