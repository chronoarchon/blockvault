# BlockVault Windows PowerShell Installer
# Usage: irm https://raw.githubusercontent.com/chronoarchon/blockvault/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host "=== Installing BlockVault (Windows Native Edition) ===" -ForegroundColor Cyan

$InstallDir = Join-Path $env:USERPROFILE ".blockvault"
$BinDir = Join-Path $env:USERPROFILE ".cargo\bin"
$RepoUrl = "https://github.com/chronoarchon/blockvault.git"

# Ensure Rust/Cargo is installed
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "Cargo/Rust not found. Please install Rust from https://rustup.rs or run: winget install Rustlang.Rustup" -ForegroundColor Yellow
    exit 1
}

# Clone or update
if (Test-Path "$InstallDir\.git") {
    Write-Host "Updating existing installation in $InstallDir..." -ForegroundColor DarkGray
    Push-Location $InstallDir
    try {
        git fetch --depth 1 origin main 2>$null
        git reset --hard origin/main 2>$null
    } catch {
        Pop-Location
        Remove-Item -Recurse -Force $InstallDir
        git clone --depth 1 --quiet $RepoUrl $InstallDir
        Push-Location $InstallDir
    }
} else {
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
    }
    Write-Host "Downloading BlockVault to $InstallDir..." -ForegroundColor DarkGray
    git clone --depth 1 --quiet $RepoUrl $InstallDir
    Push-Location $InstallDir
}

# Build release binary
Write-Host "Compiling optimized native binary with Cargo..." -ForegroundColor Cyan
cargo build --release --quiet

# Install
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}
Copy-Item "target\release\blockvault.exe" -Destination "$BinDir\blockvault.exe" -Force
Pop-Location

Write-Host ""
Write-Host "=== BlockVault installed successfully ===" -ForegroundColor Green
Write-Host "Run 'blockvault --help' to get started." -ForegroundColor Green
