# Read-only: current state of Windows' built-in protections for `gotchu harden`. Changes nothing.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$p = Get-MpPreference
$s = Get-MpComputerStatus
$os = Get-CimInstance Win32_OperatingSystem
$asr = @()
for ($i = 0; $i -lt @($p.AttackSurfaceReductionRules_Ids).Count; $i++) {
    if (@($p.AttackSurfaceReductionRules_Actions)[$i] -eq 1) { $asr += "$(@($p.AttackSurfaceReductionRules_Ids)[$i])".ToLower() }
}
$o = [ordered]@{
    edition          = "$($os.Caption)"
    build            = "$($os.BuildNumber)"
    defender_active  = [bool]($s.AntivirusEnabled -and $s.RealTimeProtectionEnabled)
    smart_app_control = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState
    asr_blocking     = @($asr)
    folder_protection = $p.EnableControlledFolderAccess
    network_protection = $p.EnableNetworkProtection
    cloud_level      = $p.CloudBlockLevel
    unwanted_apps    = $p.PUAProtection
    memory_integrity = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity').Enabled
    # Full path: other shells (Git Bash) ship a different whoami that has no /groups.
    is_admin         = [bool](& "$env:windir\System32\whoami.exe" /groups | Select-String 'S-1-5-32-544')
    # Not the FileHistory registry key: it exists on PCs where File History was never set up (seen on
    # Windows 11 build 26200). Its configuration file is written only once File History is set up.
    file_history     = Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\FileHistory\Configuration\Config1.xml')
}
$o | ConvertTo-Json -Compress
