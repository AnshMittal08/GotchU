# Turns one protection on, or puts it back. Runs elevated (Windows asks the user first).
# The previous setting is saved in <JournalDir>\<Lock>.json before any change, so undo is exact.
param([string]$Lock, [string]$JournalDir, [string]$AsrIds, [switch]$Undo)
$ErrorActionPreference = 'Stop'
$journal = Join-Path $JournalDir "$Lock.json"
$resultFile = Join-Path $JournalDir "$Lock.result"
try {
    $p = Get-MpPreference
    $simple = @{
        network_protection = @{ name = 'EnableNetworkProtection'; on = 1 }
        folder_protection  = @{ name = 'EnableControlledFolderAccess'; on = 1 }
        cloud_level        = @{ name = 'CloudBlockLevel'; on = 2 }
    }
    if ($simple.ContainsKey($Lock)) {
        $setting = $simple[$Lock].name
        if ($Undo) {
            $previous = [int](Get-Content $journal -Raw | ConvertFrom-Json).previous
            $arg = @{ $setting = $previous }
            Set-MpPreference @arg
            Remove-Item $journal
        } else {
            if (-not (Test-Path $journal)) { @{ previous = [int]$p.$setting } | ConvertTo-Json | Set-Content $journal -Encoding utf8 }
            $arg = @{ $setting = $simple[$Lock].on }
            Set-MpPreference @arg
        }
    } elseif ($Lock -eq 'asr') {
        $ids = $AsrIds -split ','
        if ($Undo) {
            $previous = Get-Content $journal -Raw | ConvertFrom-Json
            foreach ($id in $ids) {
                $was = $previous.$id
                if ($null -eq $was) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $id }
                else { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions ([int]$was) }
            }
            Remove-Item $journal
        } else {
            if (-not (Test-Path $journal)) {
                $before = @{}
                for ($i = 0; $i -lt @($p.AttackSurfaceReductionRules_Ids).Count; $i++) {
                    $before["$(@($p.AttackSurfaceReductionRules_Ids)[$i])".ToLower()] = [int]@($p.AttackSurfaceReductionRules_Actions)[$i]
                }
                $before | ConvertTo-Json | Set-Content $journal -Encoding utf8
            }
            foreach ($id in $ids) { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions 1 }
        }
    } else {
        throw "Unknown protection: $Lock"
    }
    'ok' | Set-Content $resultFile -Encoding utf8
} catch {
    "error: $($_.Exception.Message)" | Set-Content $resultFile -Encoding utf8
}
