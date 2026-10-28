@echo off
setlocal
title Build LoginEye Executable
cd /d "%~dp0"

echo ========================================================
echo        Compilare logineye.exe cu PyInstaller
echo ========================================================

python -m PyInstaller --onefile --noconsole --name logineye main.py

if exist "dist\logineye.exe" (
    copy /y "dist\logineye.exe" "logineye.exe"
    rmdir /s /q build dist 2>nul
    del logineye.spec 2>nul
    echo.
    echo [OK] Compilare reusita! logineye.exe este gata.
) else (
    echo.
    echo [EROARE] Compilarea a esuat.
)

pause
