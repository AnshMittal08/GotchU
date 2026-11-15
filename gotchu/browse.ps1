# Shows the standard Windows "pick a file / folder" window and prints the chosen path (one per line with -Multi).
param([switch]$Folder, [switch]$Multi, [string]$Title, [string]$Start)
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
$owner = New-Object System.Windows.Forms.Form -Property @{ TopMost = $true; ShowInTaskbar = $false; Opacity = 0 }
$owner.Show()
if ($Folder) {
    $d = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($Title) { $d.Description = $Title }
    $d.ShowNewFolderButton = $true
    if ($d.ShowDialog($owner) -eq 'OK') { $d.SelectedPath }
} else {
    $d = New-Object System.Windows.Forms.OpenFileDialog
    $d.InitialDirectory = if ($Start -and (Test-Path -LiteralPath $Start)) { $Start } else { Join-Path $env:USERPROFILE 'Downloads' }
    $d.Multiselect = [bool]$Multi
    if ($Title) { $d.Title = $Title }
    if ($d.ShowDialog($owner) -eq 'OK') { $d.FileNames }
}
$owner.Close()
