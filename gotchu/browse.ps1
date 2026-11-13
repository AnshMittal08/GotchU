# Shows the standard Windows "pick a file / folder" window and prints the chosen path.
param([switch]$Folder)
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
$owner = New-Object System.Windows.Forms.Form -Property @{ TopMost = $true; ShowInTaskbar = $false; Opacity = 0 }
$owner.Show()
if ($Folder) {
    $d = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($d.ShowDialog($owner) -eq 'OK') { $d.SelectedPath }
} else {
    $d = New-Object System.Windows.Forms.OpenFileDialog
    $d.InitialDirectory = Join-Path $env:USERPROFILE 'Downloads'
    if ($d.ShowDialog($owner) -eq 'OK') { $d.FileName }
}
$owner.Close()
