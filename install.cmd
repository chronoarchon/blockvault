@echo off
setlocal
echo === Installing BlockVault (Windows Native Edition) ===
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/chronoarchon/blockvault/main/install.ps1 | iex"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] BlockVault installation encountered an issue (Code: %ERRORLEVEL%).
) else (
    echo.
    echo [SUCCESS] BlockVault installation complete.
)
pause
