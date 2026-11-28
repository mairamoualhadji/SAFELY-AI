[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [ValidateSet("win-x64", "win-arm64")]
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$project = Join-Path $repoRoot "SafelyAI.Desktop\SafelyAI.Desktop.csproj"
$artifactRoot = Join-Path $repoRoot "artifacts\publish"
$buildStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$publishDirectory = Join-Path $artifactRoot "$Runtime-$buildStamp"
$archivePath = Join-Path $repoRoot "artifacts\SAFELY-AI-$Runtime.zip"

if (-not (Test-Path -LiteralPath $project -PathType Leaf)) {
    throw "Projet WPF introuvable : $project"
}

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
dotnet publish $project --configuration $Configuration --runtime $Runtime --self-contained true `
    -p:UseAppHost=true -p:PublishSingleFile=false -o $publishDirectory
if ($LASTEXITCODE -ne 0) {
    throw "La publication .NET a échoué (code $LASTEXITCODE)."
}

$application = Join-Path $publishDirectory "SafelyAI.Desktop.exe"
if (-not (Test-Path -LiteralPath $application -PathType Leaf)) {
    throw "L’exécutable publié est absent : $application"
}

Copy-Item -LiteralPath (Join-Path $PSScriptRoot "Install-SafelyAI.ps1") -Destination $publishDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "Uninstall-SafelyAI.ps1") -Destination $publishDirectory -Force

Compress-Archive -Path (Join-Path $publishDirectory "*") -DestinationPath $archivePath -Force
Write-Host "Publication prête : $archivePath"
Write-Host "Extraire l’archive puis exécuter Install-SafelyAI.ps1 pour installer sans droits administrateur. Runtime .NET inclus."
