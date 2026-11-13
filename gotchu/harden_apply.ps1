# Turns one protection on, or puts it back. Runs elevated from Program Files\gotchu (Windows asks the user first).
# The previous setting is saved in journal\<Lock>.json beside this script before any change, so undo is exact.
# That folder is admin-only, so no ordinary program can change what undo puts back.
# Exit code 0 means done; otherwise the reason is in last-error.txt beside this script.
param([string]$Lock, [string]$AsrIds, [string]$Legacy, [switch]$Undo)
$ErrorActionPreference = 'Stop'
$journalDir = Join-Path $PSScriptRoot 'journal'
$journal = Join-Path $journalDir "$Lock.json"
$errorFile = Join-Path $PSScriptRoot 'last-error.txt'

# The values Windows uses for each setting. A saved value outside these is refused, never applied.
$simple = @{
    network_protection = @{ name = 'EnableNetworkProtection'; on = 1; allowed = @(0, 1, 2) }
    folder_protection  = @{ name = 'EnableControlledFolderAccess'; on = 1; allowed = @(0, 1, 2, 3, 4) }
    cloud_level        = @{ name = 'CloudBlockLevel'; on = 2; allowed = @(0, 1, 2, 4, 6) }
}
$asrActions = @(0, 1, 2, 5, 6)

function Test-Value($value, $allowed) {
    return ("$value" -match '^\d+$') -and ($allowed -contains [int]"$value")
}

# Keeps the setting from before GotchU first changed it; a later switch-on never overwrites it.
function Save-Journal($values) {
    if ($Undo -or (Test-Path -LiteralPath $journal)) { return }
    New-Item -ItemType Directory -Force -Path $journalDir | Out-Null
    $values | ConvertTo-Json | Set-Content -LiteralPath $journal -Encoding utf8
}

try {
    Remove-Item -LiteralPath $errorFile -Force -ErrorAction SilentlyContinue
    # The setting from before: from the journal, or handed over from an older version's journal. That one
    # was kept in a folder any program can change, so every value in it is checked like the rest.
    $saved = $null
    if (Test-Path -LiteralPath $journal) { $saved = Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json }
    elseif ($Legacy) {
        $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Legacy)).TrimStart([char]0xFEFF)
        $saved = $text | ConvertFrom-Json
    }
    if ($Undo -and -not $saved) { throw 'GotchU has no record of the setting from before, so it was left as it is.' }
    $p = Get-MpPreference

    if ($simple.ContainsKey($Lock)) {
        $s = $simple[$Lock]
        if (-not $saved) { $saved = [pscustomobject]@{ previous = [int]$p.($s.name) } }
        if (-not (Test-Value $saved.previous $s.allowed)) { throw "The saved setting for $Lock is not one Windows uses, so it was not applied." }
        Save-Journal @{ previous = [int]$saved.previous }
        $value = if ($Undo) { [int]$saved.previous } else { $s.on }
        $arg = @{ $s.name = $value }
        Set-MpPreference @arg
    } elseif ($Lock -eq 'asr') {
        $ids = @("$AsrIds".ToLower() -split ',' | Where-Object { $_ -match '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' })
        if ($ids.Count -eq 0) { throw 'No attack-surface-reduction rules were given.' }
        if (-not $saved) {
            $before = @{}
            for ($i = 0; $i -lt @($p.AttackSurfaceReductionRules_Ids).Count; $i++) {
                $before["$(@($p.AttackSurfaceReductionRules_Ids)[$i])".ToLower()] = [int]@($p.AttackSurfaceReductionRules_Actions)[$i]
            }
            $saved = [pscustomobject]$before
        }
        $was = @{}
        foreach ($prop in $saved.PSObject.Properties) {
            if (-not (Test-Value $prop.Value $asrActions)) { throw "The saved setting for rule $($prop.Name) is not one Windows uses, so nothing was applied." }
            $was[$prop.Name.ToLower()] = [int]"$($prop.Value)"
        }
        Save-Journal $was
        foreach ($id in $ids) {
            if (-not $Undo) { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions 1 }
            elseif ($was.ContainsKey($id)) { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $was[$id] }
            else { Remove-MpPreference -AttackSurfaceReductionRules_Ids $id }
        }
    } else {
        throw "Unknown protection: $Lock"
    }
    if ($Undo) { Remove-Item -LiteralPath $journal -Force -ErrorAction SilentlyContinue }
} catch {
    "$($_.Exception.Message)" | Set-Content -LiteralPath $errorFile -Encoding utf8
    exit 1
}
exit 0
