@echo off
setlocal
title LoginEye Uninstaller

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitare permisiuni Administrator...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c `\"%~dp0uninstall.bat`\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"

echo.
pause
