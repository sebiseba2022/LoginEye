@echo off
setlocal EnableDelayedExpansion
title LoginEye Installer

:: Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ========================================================
    echo  Solicitare permisiuni Administrator...
    echo ========================================================
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c `\"%~dp0install.bat`\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"

echo.
pause
