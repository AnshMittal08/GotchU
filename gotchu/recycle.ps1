# Moves one file to the Recycle Bin (not a permanent delete: it can be put back from there).
param([string]$Path)
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName Microsoft.VisualBasic
    [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($Path, 'OnlyErrorDialogs', 'SendToRecycleBin')
} catch { exit 1 }
exit 0
