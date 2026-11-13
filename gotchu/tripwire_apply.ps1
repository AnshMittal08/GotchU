# Turns the tripwire on or off, or lifts its internet blocks. Runs elevated (Windows asks first).
# Everything it changes is put back by -Action off.
param(
    [ValidateSet('on', 'off', 'restore')][string]$Action,
    [string]$Source,        # folder holding tripwire_watch.ps1
    [string]$DecoyFile,     # text file: one decoy path per line
    [string]$ResultFile,
    [switch]$Cut
)
$FS = '{0CCE921D-69AE-11D9-BED3-505054503030}'   # "File System" audit subcategory, same in every language
$auditpol = "$env:windir\System32\auditpol.exe"
$dest = Join-Path $env:ProgramFiles 'gotchu'    # admin-only: an ordinary program cannot change what runs elevated
$config = Join-Path $dest 'tripwire.json'
$task = 'gotchu tripwire'

function Remove-Cuts { & "$env:windir\System32\netsh.exe" advfirewall firewall delete rule name="gotchu cut" | Out-Null }

try {
    if ($Action -eq 'restore') {
        Remove-Cuts
        # The alarm has been dealt with: keep it as history, stop showing it as current.
        $log = Join-Path $dest 'alerts.jsonl'
        if (Test-Path $log) { Get-Content $log | Add-Content (Join-Path $dest 'alerts.old.jsonl') -Encoding utf8; Remove-Item $log }
    }
    elseif ($Action -eq 'on') {
        New-Item -ItemType Directory -Force $dest | Out-Null
        Copy-Item (Join-Path $Source 'tripwire_watch.ps1') $dest -Force

        # Remember the audit setting from before the first switch-on, so off restores it exactly.
        $before = (& $auditpol /get /subcategory:$FS /r | ConvertFrom-Csv).'Inclusion Setting'
        if (Test-Path $config) { $before = (Get-Content $config -Raw | ConvertFrom-Json).audit_before }
        & $auditpol /set /subcategory:$FS /success:enable | Out-Null

        # "$_" makes plain strings; Get-Content's strings carry extra properties that would end up in the JSON.
        $decoys = @(Get-Content $DecoyFile | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | ForEach-Object { "$_" })
        $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
        foreach ($d in $decoys) {
            $acl = Get-Acl -LiteralPath $d -Audit
            $acl.AddAuditRule((New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, 'ReadData', 'Success')))
            Set-Acl -LiteralPath $d -AclObject $acl
        }
        @{ decoys = $decoys; cut = [bool]$Cut; audit_before = $before } | ConvertTo-Json | Set-Content $config -Encoding utf8

        $user = "$env:USERDOMAIN\$env:USERNAME"
        $ps = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
        $run = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$dest\tripwire_watch.ps1`""
        $when = New-ScheduledTaskTrigger -AtLogOn -User $user
        $who = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
        $how = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $task -Action $run -Trigger $when -Principal $who -Settings $how -Force | Out-Null
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue   # restart so a changed setting is read
        Start-ScheduledTask -TaskName $task
    }
    else {
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Cuts
        if (Test-Path $config) {
            $before = (Get-Content $config -Raw | ConvertFrom-Json).audit_before
            if ($before -notlike '*Success*') { & $auditpol /set /subcategory:$FS /success:disable | Out-Null }
        }
        Remove-Item -Recurse -Force $dest -ErrorAction SilentlyContinue
    }
    'ok' | Set-Content $ResultFile -Encoding utf8
} catch {
    "error: $_" | Set-Content $ResultFile -Encoding utf8
}
