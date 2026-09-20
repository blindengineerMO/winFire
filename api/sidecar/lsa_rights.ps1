function Get-WinFireLogonRights {
  if (-not ('WinFireLsaRights' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class WinFireLsaRights {
    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("advapi32.dll")]
    private static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attributes, uint access, out IntPtr policy);
    [DllImport("advapi32.dll")]
    private static extern uint LsaEnumerateAccountsWithUserRight(IntPtr policy, ref LSA_UNICODE_STRING right, out IntPtr buffer, out uint count);
    [DllImport("advapi32.dll")]
    private static extern uint LsaFreeMemory(IntPtr buffer);
    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr policy);
    [DllImport("advapi32.dll")]
    private static extern uint LsaNtStatusToWinError(uint status);

    private static readonly string[] Rights = {
        "SeNetworkLogonRight", "SeDenyNetworkLogonRight",
        "SeRemoteInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight",
        "SeInteractiveLogonRight", "SeDenyInteractiveLogonRight",
        "SeBatchLogonRight", "SeDenyBatchLogonRight",
        "SeServiceLogonRight", "SeDenyServiceLogonRight"
    };

    public static string[] Read() {
        var attributes = new LSA_OBJECT_ATTRIBUTES();
        attributes.Length = (uint)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
        IntPtr policy;
        // POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION
        uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x801, out policy);
        if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status), "LsaOpenPolicy failed");
        var rows = new List<string>();
        try {
            foreach (var name in Rights) {
                IntPtr nameBuffer = Marshal.StringToHGlobalUni(name);
                IntPtr entries = IntPtr.Zero;
                try {
                    var right = new LSA_UNICODE_STRING {
                        Length = checked((ushort)(name.Length * 2)),
                        MaximumLength = checked((ushort)((name.Length + 1) * 2)),
                        Buffer = nameBuffer
                    };
                    uint count;
                    status = LsaEnumerateAccountsWithUserRight(policy, ref right, out entries, out count);
                    if (status == 0x8000001A) continue; // STATUS_NO_MORE_ENTRIES
                    if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status), "Cannot read " + name);
                    var sids = new List<string>();
                    for (uint i = 0; i < count; i++) {
                        IntPtr sid = Marshal.ReadIntPtr(entries, checked((int)i * IntPtr.Size));
                        sids.Add("*" + new SecurityIdentifier(sid).Value);
                    }
                    if (sids.Count > 0) rows.Add(name + " = " + string.Join(",", sids));
                } finally {
                    if (entries != IntPtr.Zero) LsaFreeMemory(entries);
                    Marshal.FreeHGlobal(nameBuffer);
                }
            }
            return rows.ToArray();
        } finally { LsaClose(policy); }
    }
}
'@ -ErrorAction Stop
  }
  @([WinFireLsaRights]::Read())
}
