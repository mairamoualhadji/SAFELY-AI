[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$roamingAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
$installDirectory = Join-Path $localAppData "Programs\SAFELY-AI"
$supportDirectory = Join-Path $localAppData "SafelyAI\Support"
$startMenuDirectory = Join-Path $roamingAppData "Microsoft\Windows\Start Menu\Programs\SAFELY AI"
$application = Join-Path $installDirectory "SafelyAI.Desktop.exe"
$uninstallerSource = Join-Path $PSScriptRoot "Uninstall-SafelyAI.ps1"
$uninstaller = Join-Path $supportDirectory "Uninstall-SafelyAI.ps1"
$shortcutPath = Join-Path $startMenuDirectory "SAFELY AI.lnk"
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SAFELY-AI"

if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot "SafelyAI.Desktop.exe") -PathType Leaf)) {
    throw "Archive invalide : SafelyAI.Desktop.exe doit se trouver dans le même dossier que ce script."
}
if (-not (Test-Path -LiteralPath $uninstallerSource -PathType Leaf)) {
    throw "Archive incomplète : le script de désinstallation est absent."
}

$fullInstallDirectory = [IO.Path]::GetFullPath($installDirectory)
$programsDirectory = [IO.Path]::GetFullPath((Join-Path $localAppData "Programs"))
if (-not $fullInstallDirectory.StartsWith($programsDirectory.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Le dossier d’installation sort du répertoire utilisateur autorisé."
}

$running = Get-Process -Name "SafelyAI.Desktop" -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and [IO.Path]::GetFullPath($_.Path).StartsWith($fullInstallDirectory + '\', [StringComparison]::OrdinalIgnoreCase) }
if ($running) {
    throw "Fermez SAFELY AI avant d’installer ou de mettre à jour l’application. Aucun fichier n’a été remplacé."
}

New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $supportDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $startMenuDirectory -Force | Out-Null
Get-ChildItem -LiteralPath $PSScriptRoot -Force | Copy-Item -Destination $installDirectory -Recurse -Force
Copy-Item -LiteralPath $uninstallerSource -Destination $uninstaller -Force

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $application
$shortcut.WorkingDirectory = $installDirectory
$shortcut.IconLocation = $application
$shortcut.Description = "Tableau de bord de sécurité SAFELY AI"
$shortcut.Save()

New-Item -Path $registryPath -Force | Out-Null
New-ItemProperty -Path $registryPath -Name "DisplayName" -Value "SAFELY AI" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $registryPath -Name "DisplayVersion" -Value "1.0.0" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $registryPath -Name "Publisher" -Value "SAFELY AI" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $registryPath -Name "InstallLocation" -Value $installDirectory -PropertyType String -Force | Out-Null
New-ItemProperty -Path $registryPath -Name "UninstallString" -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninstaller`"" -PropertyType String -Force | Out-Null

Write-Host "SAFELY AI est installé pour cet utilisateur. Lancez-le depuis le menu Démarrer."
Write-Host "Aucun droit administrateur n’a été demandé; l’agent de fond reste désactivé jusqu’à votre activation dans Paramètres."
