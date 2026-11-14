# Turns the tripwire on or off, or lifts its internet blocks. Runs elevated from Program Files\gotchu
# (Windows asks first). Everything it changes is put back by -Action off.
# Exit code 0 means done; otherwise the reason is in last-error.txt beside this script.
param(
    [ValidateSet('on', 'off', 'restore')][string]$Action,
    [string]$PlanFile,      # JSON: { decoys: [path], roots: [path], stores: [{ path, dir, name, owners, signer }], readers: [{ name, signer }] }
    [string]$PlanHash,      # SHA-256 of the plan as gotchu wrote it
    [switch]$Cut
)
$FS = '{0CCE921D-69AE-11D9-BED3-505054503030}'   # "File System" audit subcategory, same in every language
$auditpol = "$env:windir\System32\auditpol.exe"
$dest = $PSScriptRoot                           # Program Files\gotchu: admin-only, as is the watcher beside this script
$config = Join-Path $dest 'tripwire.json'
$errorFile = Join-Path $dest 'last-error.txt'
$task = 'gotchu tripwire'

function Remove-Cuts { & "$env:windir\System32\netsh.exe" advfirewall firewall delete rule name="gotchu cut" | Out-Null }

# Adds or removes "record who reads this" on one file, or on the files inside one folder.
# Only the audit part of the file's security is read and written; its permissions are not touched.
function Set-Watch([string]$path, [bool]$isDir, [bool]$remove) {
    $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $audit = [System.Security.AccessControl.AccessControlSections]::Audit
    if ($isDir) {
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, 'ReadData', 'ObjectInherit', 'InheritOnly', 'Success')
        $sec = [System.IO.Directory]::GetAccessControl($path, $audit)
    } else {
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, 'ReadData', 'Success')
        $sec = [System.IO.File]::GetAccessControl($path, $audit)
    }
    if ($remove) { [void]$sec.RemoveAuditRule($rule) } else { $sec.AddAuditRule($rule) }
    if ($isDir) { [System.IO.Directory]::SetAccessControl($path, $sec) } else { [System.IO.File]::SetAccessControl($path, $sec) }
}

# The plan sits in a folder any program can change. It is read once and used only if those bytes are
# exactly what gotchu wrote, so nothing can swap in its own list in between.
function Read-Plan {
    $bytes = [System.IO.File]::ReadAllBytes($PlanFile)
    $hash = -join ([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
    if ($hash -ne "$PlanHash".ToLower()) { throw 'The list of files to watch changed after gotchu wrote it, so nothing was changed.' }
    return [System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
}

try {
    Remove-Item -LiteralPath $errorFile -Force -ErrorAction SilentlyContinue
    if ($Action -eq 'restore') {
        Remove-Cuts
        # The alarm has been dealt with: keep it as history, stop showing it as current.
        # The list of programs to review stays until the tripwire is switched off.
        $log = Join-Path $dest 'alerts.jsonl'
        if (Test-Path $log) { Get-Content $log | Add-Content (Join-Path $dest 'alerts.old.jsonl') -Encoding utf8; Remove-Item $log }
    }
    elseif ($Action -eq 'on') {
        if (-not (Test-Path -LiteralPath (Join-Path $dest 'tripwire_watch.ps1'))) { throw 'The watcher is missing. Run: gotchu setup' }
        $plan = Read-Plan

        # Remember the audit setting from before the first switch-on, so off restores it exactly.
        $before = (& $auditpol /get /subcategory:$FS /r | ConvertFrom-Csv).'Inclusion Setting'
        if (Test-Path $config) { $before = (Get-Content $config -Raw | ConvertFrom-Json).audit_before }
        & $auditpol /set /subcategory:$FS /success:enable | Out-Null

        # Stop watching whatever an earlier switch-on watched, so nothing is left behind if the list changed.
        if (Test-Path $config) {
            foreach ($s in @((Get-Content $config -Raw | ConvertFrom-Json).stores)) {
                try { Set-Watch $s.path ([bool]$s.dir) $true } catch { }
            }
        }
        $decoys = @($plan.decoys | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | ForEach-Object { "$_" })
        foreach ($d in $decoys) { Set-Watch $d $false $false }
        # The folder each decoy was planted in, so the watcher can tell when a real app has moved in since.
        $roots = @(foreach ($r in @($plan.roots)) {
            $low = "$r".ToLower()
            if ($r -and ($decoys | Where-Object { $_.ToLower().StartsWith($low + '\') })) { "$r" }
        })
        # A real store that cannot be watched (in use, or gone) is skipped, not fatal: the decoys still work.
        $stores = @()
        foreach ($s in @($plan.stores)) {
            try { Set-Watch $s.path ([bool]$s.dir) $false; $stores += $s } catch { }
        }
        @{ decoys = $decoys; decoy_roots = $roots; stores = $stores; readers = @($plan.readers | Where-Object { $_ })
           cut = [bool]$Cut; audit_before = $before } |
            ConvertTo-Json -Depth 5 | Set-Content $config -Encoding utf8

        # The watcher runs as SYSTEM from start-up. Reading the Security log needs administrator rights, so this is
        # what lets it work on a standard account, whichever account approved the permission prompt.
        # SYSTEM is named from its SID, so the name is right in every Windows language.
        $system = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')).Translate([System.Security.Principal.NTAccount]).Value
        $ps = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
        $run = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$dest\tripwire_watch.ps1`""
        $when = New-ScheduledTaskTrigger -AtStartup
        $who = New-ScheduledTaskPrincipal -UserId $system -LogonType ServiceAccount -RunLevel Highest
        $how = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $task -Action $run -Trigger $when -Principal $who -Settings $how -Force | Out-Null
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue   # restart so a changed setting is read
        Start-ScheduledTask -TaskName $task
    }
    else {
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Cuts
        if (Test-Path $config) {
            $old = Get-Content $config -Raw | ConvertFrom-Json
            foreach ($s in @($old.stores)) {
                try { Set-Watch $s.path ([bool]$s.dir) $true } catch { }
            }
            $before = $old.audit_before
            if ($before -notlike '*Success*') { & $auditpol /set /subcategory:$FS /success:disable | Out-Null }
        }
        # Only the tripwire's own files: the helpers stay for harden and for switching on again (gotchu setup --remove).
        foreach ($name in 'tripwire.json', 'heartbeat', 'alerts.jsonl', 'alerts.old.jsonl', 'sightings.jsonl', 'sightings.old.jsonl') {
            Remove-Item -LiteralPath (Join-Path $dest $name) -Force -ErrorAction SilentlyContinue
        }
    }
} catch {
    "$_" | Set-Content -LiteralPath $errorFile -Encoding utf8
    exit 1
}
exit 0
