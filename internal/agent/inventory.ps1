# ControlZit agent inventory: prints one JSON object (proto.Inventory).
# Windows PowerShell 4.0+ (Windows 8.1 / Server 2012 R2 and newer).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$errs = New-Object System.Collections.ArrayList
function T($s) { if ($null -eq $s) { '' } else { ([string]$s).Trim() } }
function D($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString('o') } else { '0001-01-01T00:00:00Z' } }
$r = [ordered]@{}

try {
  $os = Get-CimInstance Win32_OperatingSystem
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $build = T $cv.CurrentBuild
  if ($cv.UBR -ne $null) { $build = "$build.$($cv.UBR)" }
  $r.os = [ordered]@{ name = T $os.Caption; version = T $os.Version; build = $build; display_version = T $cv.DisplayVersion
    arch = T $os.OSArchitecture; install_date = D $os.InstallDate; boot_time = D $os.LastBootUpTime }
} catch { [void]$errs.Add("os: $_") }

try {
  $cs = Get-CimInstance Win32_ComputerSystem
  $bios = Get-CimInstance Win32_BIOS
  $cpu = @(Get-CimInstance Win32_Processor)
  $r.hostname = T $cs.DNSHostName
  $r.domain = T $cs.Domain
  $r.part_of_domain = [bool]$cs.PartOfDomain
  $r.logged_on_user = T $cs.UserName
  $r.hardware = [ordered]@{ manufacturer = T $cs.Manufacturer; model = T $cs.Model; serial = T $bios.SerialNumber
    bios = T $bios.SMBIOSBIOSVersion; cpu = T $cpu[0].Name
    cores = [int](($cpu | Measure-Object -Property NumberOfCores -Sum).Sum)
    threads = [int](($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum)
    memory_bytes = [uint64]$cs.TotalPhysicalMemory
    virtual = [bool](($cs.Model -match 'Virtual|VMware|KVM|QEMU|HVM|Xen|Standard PC') -or ($cs.Manufacturer -match 'QEMU|Xen|innotek|Parallels|VMware')) }
} catch { [void]$errs.Add("computer: $_") }

try {
  $r.disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    [ordered]@{ drive = T $_.DeviceID; label = T $_.VolumeName; fs = T $_.FileSystem; size = [uint64]$_.Size; free = [uint64]$_.FreeSpace } })
} catch { [void]$errs.Add("disks: $_"); $r.disks = @() }

try {
  $r.network = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
    [ordered]@{ name = T $_.Description; mac = T $_.MACAddress; ips = @($_.IPAddress | Where-Object { $_ })
      gateways = @($_.DefaultIPGateway | Where-Object { $_ }); dns = @($_.DNSServerSearchOrder | Where-Object { $_ }); dhcp = [bool]$_.DHCPEnabled } })
} catch { [void]$errs.Add("network: $_"); $r.network = @() }

try {
  $seen = @{}
  $sw = New-Object System.Collections.ArrayList
  foreach ($p in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
    Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName } | ForEach-Object {
      $k = "$($_.DisplayName)|$($_.DisplayVersion)"
      if (-not $seen.ContainsKey($k)) {
        $seen[$k] = 1
        [void]$sw.Add([ordered]@{ name = T $_.DisplayName; version = T $_.DisplayVersion; publisher = T $_.Publisher; install_date = T $_.InstallDate })
      }
    }
  }
  $r.software = @($sw | Sort-Object { $_.name })
} catch { [void]$errs.Add("software: $_"); $r.software = @() }

try {
  $prot = @{ 0 = 'off'; 1 = 'on'; 2 = 'unknown' }
  $conv = @{ 0 = 'fully decrypted'; 1 = 'fully encrypted'; 2 = 'encrypting'; 3 = 'decrypting'; 4 = 'encryption paused'; 5 = 'decryption paused' }
  $r.bitlocker = @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume | Where-Object { $_.DriveLetter } | ForEach-Object {
    [ordered]@{ drive = T $_.DriveLetter; protection = $prot[[int]$_.ProtectionStatus]; status = $conv[[int]$_.ConversionStatus] } })
} catch { [void]$errs.Add("bitlocker: $_"); $r.bitlocker = @() }

try {
  if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    $mp = Get-MpComputerStatus
    $r.defender = [ordered]@{ antivirus = [bool]$mp.AntivirusEnabled; real_time = [bool]$mp.RealTimeProtectionEnabled
      tamper = [bool]$mp.IsTamperProtected; signature_version = T $mp.AntivirusSignatureVersion; signature_updated = D $mp.AntivirusSignatureLastUpdated }
  }
} catch { [void]$errs.Add("defender: $_") }

try {
  $r.firewall = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ profile = T $_.Name; enabled = [bool]("$($_.Enabled)" -eq 'True') } })
} catch { [void]$errs.Add("firewall: $_"); $r.firewall = @() }

try {
  $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
  if (-not $pending) {
    $sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
    if ($sm -and $sm.PendingFileRenameOperations) { $pending = $true }
  }
  $r.pending_reboot = [bool]$pending
} catch { [void]$errs.Add("pending reboot: $_") }

$r.errors = @($errs)
$r.collected_at = (Get-Date).ToUniversalTime().ToString('o')
# A service has no console: write UTF-8 ourselves (OutputEncoding is ignored).
$w = New-Object IO.StreamWriter([Console]::OpenStandardOutput(), (New-Object System.Text.UTF8Encoding $false))
$w.Write(($r | ConvertTo-Json -Depth 6 -Compress))
$w.Flush()
