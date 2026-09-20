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
    private static extern uint LsaAddAccountRights(IntPtr policy, IntPtr accountSid, ref LSA_UNICODE_STRING rights, uint count);
    [DllImport("advapi32.dll")]
    private static extern uint LsaRemoveAccountRights(IntPtr policy, IntPtr accountSid, [MarshalAs(UnmanagedType.U1)] bool allRights, ref LSA_UNICODE_STRING rights, uint count);
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
        LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
        attributes.Length = (uint)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
        IntPtr policy;
        // POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION
        uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x801, out policy);
        if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status), "LsaOpenPolicy failed");
        List<string> rows = new List<string>();
        try {
            foreach (string name in Rights) {
                IntPtr nameBuffer = Marshal.StringToHGlobalUni(name);
                IntPtr entries = IntPtr.Zero;
                try {
                    LSA_UNICODE_STRING right = new LSA_UNICODE_STRING();
                    right.Length = checked((ushort)(name.Length * 2));
                    right.MaximumLength = checked((ushort)((name.Length + 1) * 2));
                    right.Buffer = nameBuffer;
                    uint count;
                    status = LsaEnumerateAccountsWithUserRight(policy, ref right, out entries, out count);
                    if (status == 0x8000001A) continue; // STATUS_NO_MORE_ENTRIES
                    if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status), "Cannot read " + name);
                    List<string> sids = new List<string>();
                    for (uint i = 0; i < count; i++) {
                        IntPtr sid = Marshal.ReadIntPtr(entries, checked((int)i * IntPtr.Size));
                        sids.Add("*" + new SecurityIdentifier(sid).Value);
                    }
                    if (sids.Count > 0) rows.Add(name + " = " + string.Join(",", sids.ToArray()));
                } finally {
                    if (entries != IntPtr.Zero) LsaFreeMemory(entries);
                    Marshal.FreeHGlobal(nameBuffer);
                }
            }
            return rows.ToArray();
        } finally { LsaClose(policy); }
    }

    public static void Change(string sidText, string rightName, bool present) {
        if (Array.IndexOf(Rights, rightName) < 0) throw new ArgumentException("Unsupported logon right", "rightName");
        SecurityIdentifier sidValue = new SecurityIdentifier(sidText);
        byte[] sidBytes = new byte[sidValue.BinaryLength];
        sidValue.GetBinaryForm(sidBytes, 0);
        IntPtr sid = Marshal.AllocHGlobal(sidBytes.Length);
        IntPtr nameBuffer = Marshal.StringToHGlobalUni(rightName);
        IntPtr policy = IntPtr.Zero;
        try {
            Marshal.Copy(sidBytes, 0, sid, sidBytes.Length);
            LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
            attributes.Length = (uint)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            // POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x810, out policy);
            if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status), "LsaOpenPolicy failed");
            LSA_UNICODE_STRING right = new LSA_UNICODE_STRING();
            right.Length = checked((ushort)(rightName.Length * 2));
            right.MaximumLength = checked((ushort)((rightName.Length + 1) * 2));
            right.Buffer = nameBuffer;
            status = present ? LsaAddAccountRights(policy, sid, ref right, 1) : LsaRemoveAccountRights(policy, sid, false, ref right, 1);
            if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status), "Cannot change " + rightName);
        } finally {
            if (policy != IntPtr.Zero) LsaClose(policy);
            Marshal.FreeHGlobal(nameBuffer);
            Marshal.FreeHGlobal(sid);
            Array.Clear(sidBytes, 0, sidBytes.Length);
        }
    }
}
'@ -ErrorAction Stop
  }
  @([WinFireLsaRights]::Read())
}

function Test-WinFireLogonRight([string[]]$lines,[string]$accountSid,[string]$right) {
  $entry=@($lines | Where-Object { $_ -like "$right = *" } | Select-Object -First 1)
  if(-not $entry.Count){return $false}
  $members=($entry[0] -split ' = ',2)[1] -split ','
  return @($members | Where-Object { $_.TrimStart('*') -eq $accountSid }).Count -gt 0
}

function Set-WinFireLogonRight($argsData) {
  $sid=[string]$argsData.accountSid; $right=[string]$argsData.right; $present=[bool]$argsData.present
  if($sid -notmatch '^S-1-\d+-\d+(?:-\d+)+$'){throw 'A valid account SID is required'}
  $allowed=@('SeNetworkLogonRight','SeDenyNetworkLogonRight','SeRemoteInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight','SeBatchLogonRight','SeDenyBatchLogonRight','SeServiceLogonRight','SeDenyServiceLogonRight')
  if([Array]::IndexOf($allowed,$right) -lt 0){throw 'Unsupported logon right'}
  $before=Test-WinFireLogonRight (Get-WinFireLogonRights) $sid $right
  if($before -eq $present){return (New-Object PSObject -Property @{accountSid=$sid;right=$right;before=$before;present=$before;changed=$false})}
  [WinFireLsaRights]::Change($sid,$right,$present)
  $after=Test-WinFireLogonRight (Get-WinFireLogonRights) $sid $right
  if($after -ne $present){
    try{[WinFireLsaRights]::Change($sid,$right,$before)}catch{throw "Logon right readback failed; rollback also failed: $($_.Exception.Message)"}
    throw 'Logon right readback failed; prior assignment restored'
  }
  New-Object PSObject -Property @{accountSid=$sid;right=$right;before=$before;present=$after;changed=$true}
}
