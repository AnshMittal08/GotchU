# Adds or removes the GotchU shortcuts in the Start menu and on the desktop, for this user only.
# No administrator rights. Windows is asked where those folders are, so a desktop kept in OneDrive works too.
param([string]$Target, [string]$Icon, [switch]$Remove)
$ErrorActionPreference = 'Stop'
$places = @([Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('Desktop')) | Where-Object { $_ }
try {
    foreach ($folder in $places) {
        $link = Join-Path $folder 'GotchU.lnk'
        if ($Remove) { Remove-Item -LiteralPath $link -Force -ErrorAction SilentlyContinue; continue }
        $shell = New-Object -ComObject WScript.Shell
        $s = $shell.CreateShortcut($link)
        $s.TargetPath = $Target
        $s.Arguments = '-m gotchu app'
        $s.IconLocation = $Icon
        $s.Description = 'GotchU: guards your saved passwords, logins and wallets'
        $s.WorkingDirectory = $env:USERPROFILE
        $s.Save()
    }
} catch { exit 1 }
exit 0
