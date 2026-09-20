$ErrorActionPreference='Stop'
function Get-WinFireAuditSetting {
  if(-not ('WinFireAuditPolicyQuery' -as [type])) {
    $source='using System; using System.ComponentModel; using System.Runtime.InteropServices; public static class WinFireAuditPolicyQuery { [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.U1)] private static extern bool AuditQuerySystemPolicy([In] Guid[] ids, uint count, out IntPtr policy); [DllImport("advapi32.dll")] private static extern void AuditFree(IntPtr policy); public static int Read(string text) { Guid id=new Guid(text); IntPtr policy; if(!AuditQuerySystemPolicy(new Guid[]{id},1,out policy)) throw new Win32Exception(Marshal.GetLastWin32Error()); try { if(policy==IntPtr.Zero || (Guid)Marshal.PtrToStructure(policy, typeof(Guid))!=id) throw new InvalidOperationException("Audit policy query returned an unexpected subcategory"); return Marshal.ReadInt32(policy,16); } finally { if(policy!=IntPtr.Zero) AuditFree(policy); } } }'
    Add-Type -TypeDefinition $source -ErrorAction Stop
  }
  [WinFireAuditPolicyQuery]::Read('0CCE9226-69AE-11D9-BED3-505054503030')
}
$before=Get-WinFireAuditSetting
if($mode -eq 'audit_policy_enable' -and (($before -band 3) -ne 3)) {
  try {
    auditpol /set '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
    if($LASTEXITCODE -ne 0){throw "auditpol update failed with exit code $LASTEXITCODE"}
    $after=Get-WinFireAuditSetting
    if(($after -band 3) -ne 3){throw 'Audit policy readback did not confirm both settings'}
  } catch {
    $cause=$_.Exception.Message
    $successArg=if($before -band 1){'/success:enable'}else{'/success:disable'}
    $failureArg=if($before -band 2){'/failure:enable'}else{'/failure:disable'}
    auditpol /set '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' $successArg $failureArg | Out-Null
    if($LASTEXITCODE -ne 0){throw "Audit policy update failed: $cause; rollback failed with exit code $LASTEXITCODE"}
    if((Get-WinFireAuditSetting) -ne $before){throw "Audit policy update failed: $cause; rollback readback differs from prior state"}
    throw "Audit policy update failed: $cause; prior state restored"
  }
}
Write-Output ('AUDIT|'+(Get-WinFireAuditSetting))
