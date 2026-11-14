# gotchu tripwire watcher. Runs as SYSTEM from start-up, from an admin-only folder (Program Files\gotchu),
# because only an administrator can read Windows' file-read record - and so it works for standard
# accounts too. Kept small on purpose: it is the only gotchu code that runs elevated in the background.
#
# It waits for Windows to record that a program read one of the decoy files. No honest program
# opens those, so a read means something is sweeping the PC for secrets.
$cfg = Get-Content (Join-Path $PSScriptRoot 'tripwire.json') -Raw | ConvertFrom-Json
$log = Join-Path $PSScriptRoot 'alerts.jsonl'
$decoys = @{}
foreach ($d in $cfg.decoys) { $decoys[$d.ToLower()] = $true }
$roots = @($cfg.decoy_roots | Where-Object { $_ } | ForEach-Object { "$_" })

# Windows' own readers of every new file: antivirus and search. Matched on full path, not name.
function Test-Expected([string]$p) {
    $l = $p.ToLower()
    return ($l -eq "$env:windir\System32\SearchProtocolHost.exe".ToLower()) -or
           ($l -eq "$env:windir\System32\SearchIndexer.exe".ToLower()) -or
           ($l -eq "$env:ProgramFiles\Windows Defender\MsMpEng.exe".ToLower()) -or
           ($l -like "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe".ToLower())
}

# The watcher runs as SYSTEM, outside anyone's desktop, so the warning goes to the session at the screen
# through Windows' own message service (the one msg.exe uses; it is there on Home editions too).
try {
    Add-Type -Namespace GotchU -Name Session -MemberDefinition @'
[DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool WTSSendMessage(IntPtr server, uint session, string title, uint titleBytes,
    string message, uint messageBytes, uint style, uint timeout, out uint response, bool wait);
[DllImport("kernel32.dll")]
public static extern uint WTSGetActiveConsoleSessionId();
'@
} catch { }

function Show-Alarm([string]$text) {
    if (-not ('GotchU.Session' -as [type])) { return }    # the alarm is still written to alerts.jsonl
    $session = [GotchU.Session]::WTSGetActiveConsoleSessionId()
    if ($session -eq [uint32]::MaxValue) { return }        # nobody is signed in at the screen
    $title = 'GotchU alarm'
    $response = [uint32]0
    # 0x30 warning icon, 0x10000 brought to the front, 0x40000 kept on top; no time-out; do not wait for OK.
    [void][GotchU.Session]::WTSSendMessage([IntPtr]::Zero, $session, $title, [uint32]($title.Length * 2),
        $text, [uint32]($text.Length * 2), [uint32]0x50030, [uint32]0, [ref]$response, $false)
}

function Find-Store([string]$file) {
    $l = $file.ToLower()
    foreach ($s in @($cfg.stores)) {
        $p = "$($s.path)".ToLower()
        if ($l -eq $p -or ($s.dir -and $l.StartsWith($p + '\'))) { return $s }
    }
}

# Other browsers, which read each other's logins when they offer to import them: known by name, by who
# signed them, and by being installed in Program Files.
function Test-Reader([string]$proc) {
    $name = [System.IO.Path]::GetFileName($proc)
    foreach ($r in @($cfg.readers)) {
        if ($r.name -ieq $name -and (Get-Signer $proc) -like "*O=$($r.signer),*" -and (Test-Installed $proc)) { return $true }
    }
    return $false
}

# Who signed a program, if the signature is valid; '' otherwise. Remembered per program.
$signers = @{}
function Get-Signer([string]$proc) {
    if (-not $signers.ContainsKey($proc)) {
        $sig = Get-AuthenticodeSignature -LiteralPath $proc -ErrorAction SilentlyContinue
        $signers[$proc] = if ($sig -and $sig.Status -eq 'Valid') { $sig.SignerCertificate.Subject } else { '' }
    }
    return $signers[$proc]
}

# The owner is recognised by file name AND, where the map knows it, by who signed the program -
# so malware that merely calls itself chrome.exe does not pass.
function Test-Owner([string]$proc, $store) {
    $name = [System.IO.Path]::GetFileName($proc)
    if (-not (@($store.owners) | Where-Object { $_ -ieq $name })) { return $false }
    if (-not $store.signer) { return $true }
    return (Get-Signer $proc) -like "*O=$($store.signer),*"
}

# Antivirus and backup tools read every file, decoys included. A signed program installed in Program Files
# (which takes administrator rights) is listed for review instead of raising the alarm and losing its internet.
$installed = @($env:ProgramFiles, ${env:ProgramFiles(x86)} | Where-Object { $_ } | ForEach-Object { $_.ToLower() + '\' })
function Test-Installed([string]$proc) {
    $l = $proc.ToLower()
    if (-not ($installed | Where-Object { $l.StartsWith($_) })) { return $false }
    return [bool](Get-Signer $proc)
}

# A decoy whose folder now holds files gotchu did not put there: the real wallet app has most likely been
# installed since, and reads it. Listed for review until `gotchu tripwire --on` retires that decoy.
function Test-MovedIn([string]$file) {
    $l = $file.ToLower()
    foreach ($r in $roots) {
        if (-not $l.StartsWith($r.ToLower() + '\')) { continue }
        $other = Get-ChildItem -LiteralPath $r -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { -not $decoys.ContainsKey($_.FullName.ToLower()) } | Select-Object -First 1
        return [bool]$other
    }
    return $false
}

$query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
    'Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*[System[(EventID=4663)]]')
$watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($query)
Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -SourceIdentifier gotchu
$watcher.Enabled = $true

$seen = @{}
$beat = Join-Path $PSScriptRoot 'heartbeat'    # marked every 30 seconds, so gotchu can tell the watcher is alive
$lastBeat = [datetime]::MinValue
while ($true) {
  if (((Get-Date) - $lastBeat).TotalSeconds -ge 30) {
      Set-Content -LiteralPath $beat -Value (Get-Date).ToString('s') -Encoding ascii -ErrorAction SilentlyContinue
      $lastBeat = Get-Date
  }
  $e = Wait-Event -SourceIdentifier gotchu -Timeout 30
  if (-not $e) { continue }
  Remove-Event -EventIdentifier $e.EventIdentifier
  try {     # one event that cannot be handled must not stop the watching
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
        @{ time = (Get-Date).ToString('s'); program = $proc; store = $store.name; file = $file
           signed = [bool](Get-Signer $proc); known = (Test-Reader $proc) } |
            ConvertTo-Json -Compress | Add-Content -Path (Join-Path $PSScriptRoot 'sightings.jsonl') -Encoding utf8
        continue
    }
    $reason = if (Test-MovedIn $file) { 'moved_in' } elseif (Test-Installed $proc) { 'installed' } else { '' }
    if ($reason) {
        $key = "$proc|$file"
        if ($seen[$key] -and ((Get-Date) - $seen[$key]).TotalMinutes -lt 60) { continue }
        $seen[$key] = Get-Date
        @{ time = (Get-Date).ToString('s'); program = $proc; store = 'a decoy file'; file = $file; kind = 'decoy'; reason = $reason } |
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

    $text = "A program just opened a decoy file that no honest program touches.`n`nProgram: $proc`n`n"
    if ($cut) { $text += "gotchu has blocked this program from the internet. To unblock it: gotchu tripwire --restore`n`n" }
    $text += "If you did not do this yourself, disconnect from the internet now and run: gotchu scan`n`n"
    $text += "If you have just installed a wallet app or a new browser, it may be the app itself: run gotchu tripwire --restore, then gotchu tripwire --on to retire the decoy."
    Show-Alarm $text
  } catch { }
}
