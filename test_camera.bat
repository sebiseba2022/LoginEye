@echo off
setlocal
title LoginEye Camera Self-Test
cd /d "%~dp0"

echo ========================================================
echo         LoginEye - Test Foto Camera Web
echo ========================================================
echo Se captureaza doua poze de test (PASS si FAIL)...
echo.

if exist "logineye.exe" (
    logineye.exe --test
) else (
    python main.py --test
)

echo.
echo ========================================================
echo Deschidere folder capturi pentru vizualizare...
echo ========================================================
start "" explorer.exe "%~dp0captures"
pause
