$ErrorActionPreference='Stop'
function Out-Field($name,$value) {Write-Output ($name+'='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$value)))}
$computer=Get-WmiObject Win32_ComputerSystem
$os=Get-WmiObject Win32_OperatingSystem
$bios=Get-WmiObject Win32_BIOS
Out-Field 'NAME' $computer.Name; Out-Field 'DOMAIN' $computer.Domain; Out-Field 'JOINED' $computer.PartOfDomain
Out-Field 'USER' $computer.UserName; Out-Field 'MODEL' $computer.Model; Out-Field 'MANUFACTURER' $computer.Manufacturer
Out-Field 'CAPTION' $os.Caption; Out-Field 'VERSION' $os.Version; Out-Field 'BUILD' $os.BuildNumber
Out-Field 'ARCH' $os.OSArchitecture; Out-Field 'SERIAL' $bios.SerialNumber
try {Out-Field 'GUID' (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid} catch {}
foreach($adapter in @(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')) {
  Out-Field 'NET' ((@([string]$adapter.Description,[string]$adapter.MACAddress,([string[]]$adapter.IPAddress -join ','),([string[]]$adapter.DefaultIPGateway -join ','),([string[]]$adapter.DNSServerSearchOrder -join ','),[string]$adapter.DNSDomain)) -join '|')
}
