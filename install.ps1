# BlockVault Windows Native Installer (PowerShell)
# Usage: irm https://raw.githubusercontent.com/chronoarchon/blockvault/main/install.ps1 | iex

param(
    [switch]$BuildFromSource,
    [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Installing BlockVault (Windows Native Edition) ===" -ForegroundColor Cyan

$InstallDir = Join-Path $env:USERPROFILE ".blockvault\bin"
$Repo = "chronoarchon/blockvault"

# Build from source if explicitly requested
if ($BuildFromSource) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Error "Cargo/Rust is required to build from source. Install Rust from https://rustup.rs"
        exit 1
    }
    Write-Host "Building from source with Cargo..." -ForegroundColor Cyan
    cargo install --git "https://github.com/$Repo.git"
    exit 0
}

# 1. Ensure installation directory exists
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 2. Determine download URL
if ($Version -eq "latest") {
    $DownloadUrl = "https://github.com/$Repo/releases/latest/download/blockvault-windows-x86_64.zip"
} else {
    $DownloadUrl = "https://github.com/$Repo/releases/download/$Version/blockvault-windows-x86_64.zip"
}

Write-Host "Downloading BlockVault native binary from GitHub Releases..." -ForegroundColor DarkGray
$TempZip = Join-Path $env:TEMP "blockvault-windows.zip"
$TempExtract = Join-Path $env:TEMP "blockvault-extract"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
} catch {
    Write-Host "Notice: Release download failed. Falling back to Cargo install..." -ForegroundColor Yellow
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        cargo install --git "https://github.com/$Repo.git"
        exit 0
    }
    Write-Error "Failed to download BlockVault release: $_"
    exit 1
}

# 3. Extract blockvault.exe
if (Test-Path $TempExtract) { Remove-Item -Recurse -Force $TempExtract }
Expand-Archive -Path $TempZip -DestinationPath $TempExtract -Force

$ExeSource = Get-ChildItem -Path $TempExtract -Filter "blockvault.exe" -Recurse | Select-Object -First 1
if (-not $ExeSource) {
    Write-Error "blockvault.exe not found in release archive."
    exit 1
}

$TargetExe = Join-Path $InstallDir "blockvault.exe"
Copy-Item $ExeSource.FullName -Destination $TargetExe -Force

# Also install into .cargo\bin if present for instant command recognition
$CargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path $CargoBin) {
    Copy-Item $ExeSource.FullName -Destination (Join-Path $CargoBin "blockvault.exe") -Force -ErrorAction SilentlyContinue
}

# Clean up temporary files
Remove-Item -Force $TempZip -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $TempExtract -ErrorAction SilentlyContinue

# 4. Permanently add $InstallDir to User PATH if not already present
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    $NewPath = if ($UserPath) { "$UserPath;$InstallDir" } else { $InstallDir }
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
    Write-Host "Added $InstallDir to User PATH." -ForegroundColor DarkGray
}

# Add to current session PATH
if ($env:PATH -notlike "*$InstallDir*") {
    $env:PATH = "$env:PATH;$InstallDir"
}

Write-Host ""
Write-Host "=== BlockVault installed successfully ===" -ForegroundColor Green
try {
    & "$TargetExe" --version
} catch {}
Write-Host "Run 'blockvault --help' to get started." -ForegroundColor Green
