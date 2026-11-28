[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$roamingAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
$programsDirectory = [IO.Path]::GetFullPath((Join-Path $localAppData "Programs"))
$installDirectory = [IO.Path]::GetFullPath((Join-Path $programsDirectory "SAFELY-AI"))
$startMenuDirectory = Join-Path $roamingAppData "Microsoft\Windows\Start Menu\Programs\SAFELY AI"
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SAFELY-AI"

$expectedInstallDirectory = [IO.Path]::GetFullPath((Join-Path $programsDirectory "SAFELY-AI"))
if (-not $installDirectory.Equals($expectedInstallDirectory, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Le chemin de désinstallation n’est pas dans le dossier Programmes de cet utilisateur."
}

if (-not $Force) {
    $answer = Read-Host "Désinstaller SAFELY AI ? Les historiques, signatures et éléments de quarantaine locaux seront conservés. (o/N)"
    if ($answer -notin @("o", "O", "oui", "Oui", "OUI")) {
        Write-Host "Désinstallation annulée."
        exit 0
    }
}

$running = Get-Process -Name "SafelyAI.Desktop" -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and [IO.Path]::GetFullPath($_.Path).StartsWith($installDirectory + '\', [StringComparison]::OrdinalIgnoreCase) }
if ($running) {
    throw "Fermez SAFELY AI avant de le désinstaller. Aucun fichier n’a été supprimé."
}

if (Test-Path -LiteralPath $installDirectory) {
    $attributes = [IO.File]::GetAttributes($installDirectory)
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Le dossier d’installation est un point de réanalyse; suppression refusée."
    }
    Remove-Item -LiteralPath $installDirectory -Recurse -Force
}

if (Test-Path -LiteralPath $startMenuDirectory) {
    Remove-Item -LiteralPath $startMenuDirectory -Recurse -Force
}
if (Test-Path -LiteralPath $registryPath) {
    Remove-Item -LiteralPath $registryPath -Recurse -Force
}

Write-Host "SAFELY AI a été désinstallé. Les données sous %LOCALAPPDATA%\SafelyAI ont été conservées."
