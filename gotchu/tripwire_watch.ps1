# gotchu tripwire watcher. Runs with administrator rights from an admin-only folder
# (Program Files\gotchu), because only an administrator can read Windows' file-read record.
# Kept small on purpose: it is the only gotchu code that runs elevated in the background.
#
# It waits for Windows to record that a program read one of the decoy files. No honest program
# opens those, so a read means something is sweeping the PC for secrets.
$cfg = Get-Content (Join-Path $PSScriptRoot 'tripwire.json') -Raw | ConvertFrom-Json
$log = Join-Path $PSScriptRoot 'alerts.jsonl'
$decoys = @{}
foreach ($d in $cfg.decoys) { $decoys[$d.ToLower()] = $true }

# Windows' own readers of every new file: antivirus and search. Matched on full path, not name.
function Test-Expected([string]$p) {
    $l = $p.ToLower()
    return ($l -eq "$env:windir\System32\SearchProtocolHost.exe".ToLower()) -or
           ($l -eq "$env:windir\System32\SearchIndexer.exe".ToLower()) -or
           ($l -eq "$env:ProgramFiles\Windows Defender\MsMpEng.exe".ToLower()) -or
           ($l -like "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe".ToLower())
}

function Show-Alarm([string]$text) {
    $safe = $text.Replace("'", "''")
    $code = "Add-Type -AssemblyName System.Windows.Forms; " +
            "`$top = New-Object System.Windows.Forms.Form -Property @{TopMost=`$true}; " +
            "[System.Windows.Forms.MessageBox]::Show(`$top, '$safe', 'GotchU alarm', 'OK', 'Warning') | Out-Null"
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    Start-Process "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden `
        -ArgumentList '-NoProfile', '-STA', '-EncodedCommand', $b64
}

function Find-Store([string]$file) {
    $l = $file.ToLower()
    foreach ($s in @($cfg.stores)) {
        $p = "$($s.path)".ToLower()
        if ($l -eq $p -or ($s.dir -and $l.StartsWith($p + '\'))) { return $s }
    }
}

# The owner is recognised by file name AND, where the map knows it, by who signed the program -
# so malware that merely calls itself chrome.exe does not pass.
$signers = @{}
function Test-Owner([string]$proc, $store) {
    $name = [System.IO.Path]::GetFileName($proc)
    if (-not (@($store.owners) | Where-Object { $_ -ieq $name })) { return $false }
    if (-not $store.signer) { return $true }
    if (-not $signers.ContainsKey($proc)) {
        $sig = Get-AuthenticodeSignature -LiteralPath $proc -ErrorAction SilentlyContinue
        $signers[$proc] = if ($sig -and $sig.Status -eq 'Valid') { $sig.SignerCertificate.Subject } else { '' }
    }
    return $signers[$proc] -like "*O=$($store.signer),*"
}

$query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
    'Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*[System[(EventID=4663)]]')
$watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($query)
Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -SourceIdentifier gotchu
$watcher.Enabled = $true

$seen = @{}
while ($true) {
    $e = Wait-Event -SourceIdentifier gotchu
    Remove-Event -EventIdentifier $e.EventIdentifier
    $rec = $e.SourceEventArgs.EventRecord
    if (-not $rec) { continue }
    $data = @{}
    foreach ($d in ([xml]$rec.ToXml()).Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    $file = "$($data.ObjectName)"
    $proc = "$($data.ProcessName)"
    if (Test-Expected $proc) { continue }
    if (-not $decoys.ContainsKey($file.ToLower())) {
        # A real store (browser, chat app). Its owner reading it is normal. Anything else is written
        # down for review - no alarm yet, until we know how often honest programs do this.
        $store = Find-Store $file
        if (-not $store -or (Test-Owner $proc $store)) { continue }
        $key = "$proc|$($store.path)"
        if ($seen[$key] -and ((Get-Date) - $seen[$key]).TotalMinutes -lt 60) { continue }
        $seen[$key] = Get-Date
        @{ time = (Get-Date).ToString('s'); program = $proc; store = $store.name; file = $file } |
            ConvertTo-Json -Compress | Add-Content -Path (Join-Path $PSScriptRoot 'sightings.jsonl') -Encoding utf8
        continue
    }
    if ($seen[$proc] -and ((Get-Date) - $seen[$proc]).TotalSeconds -lt 60) { continue }   # one alarm per program per minute
    $seen[$proc] = Get-Date

    $cut = $false
    # Never cut svchost: it carries Windows' own networking, and blocking it takes the whole PC offline.
    if ($cfg.cut -and $proc -and $proc -ne "$env:windir\System32\svchost.exe") {
        & "$env:windir\System32\netsh.exe" advfirewall firewall add rule name="gotchu cut" dir=out action=block program="$proc" enable=yes | Out-Null
        $cut = ($LASTEXITCODE -eq 0)
    }
    @{ time = (Get-Date).ToString('s'); program = $proc; file = $file; cut = $cut } |
        ConvertTo-Json -Compress | Add-Content -Path $log -Encoding utf8

    $text = "A program just opened a decoy wallet file that no honest program touches.`n`nProgram: $proc`n`n"
    if ($cut) { $text += "gotchu has blocked this program from the internet. To unblock it: gotchu tripwire --restore`n`n" }
    $text += "If you did not do this yourself, disconnect from the internet now and run: gotchu scan"
    Show-Alarm $text
}
