# Read-only snapshot of this PC for `gotchu scan`. Prints one JSON object; changes nothing.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$o = [ordered]@{}

$o.processes = @(Get-CimInstance Win32_Process | ForEach-Object {
    @{ pid = $_.ProcessId; name = $_.Name; path = $_.ExecutablePath; cmd = $_.CommandLine }
})

$o.tasks = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $t = $_
    foreach ($a in $t.Actions) {
        if ($a.Execute) {
            $exe = [Environment]::ExpandEnvironmentVariables($a.Execute.Trim('"'))
            @{ name = $t.TaskPath + $t.TaskName; hidden = [bool]$t.Settings.Hidden
               highest = ("$($t.Principal.RunLevel)" -eq 'Highest'); exe = $exe
               exists = (Test-Path -LiteralPath $exe); enabled = ("$($t.State)" -ne 'Disabled') }
        }
    }
})

$runKeys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
$o.run = @(foreach ($k in $runKeys) {
    $p = Get-ItemProperty $k
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { @{ key = $k; name = $_.Name; value = "$($_.Value)" } } }
})

# Start-up folders (yours and all users'): everything in them runs at sign-in. Shortcuts are resolved to
# the program they start and its arguments.
$shell = New-Object -ComObject WScript.Shell
$o.startup = @(foreach ($dir in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) {
    if ($dir -and (Test-Path -LiteralPath $dir)) {
        Get-ChildItem -LiteralPath $dir -File -Force | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
            $e = @{ name = $_.Name; path = $_.FullName; target = ''; args = '' }
            if ($_.Extension -eq '.lnk' -and $shell) {
                $link = $shell.CreateShortcut($_.FullName)
                $e.target = [Environment]::ExpandEnvironmentVariables("$($link.TargetPath)"); $e.args = "$($link.Arguments)"
            }
            $e
        }
    }
})

$i = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$o.proxy = @{ enabled = [bool]$i.ProxyEnable; server = "$($i.ProxyServer)"; pac = "$($i.AutoConfigURL)" }

$d = Get-MpComputerStatus
$o.defender = @{ known = [bool]$d; realtime = [bool]$d.RealTimeProtectionEnabled }

$forceKeys = 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist',
             'HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist', 'HKCU:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist'
$o.forced_extensions = @(foreach ($k in $forceKeys) {
    if (Test-Path $k) { (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "$($_.Value)" } }
})

$o | ConvertTo-Json -Depth 4 -Compress
