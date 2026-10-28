$ErrorActionPreference = "SilentlyContinue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "               LoginEye Uninstaller                       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

Write-Host "[*] Oprire procese LoginEye active..." -ForegroundColor Yellow
Stop-Process -Name "logineye" -Force -ErrorAction SilentlyContinue

Write-Host "[*] Stergere pornire automata (Registry Run & Scheduled Tasks)..." -ForegroundColor Yellow
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "LoginEye" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "LoginEye_Daemon" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "LoginEye_BootGuard" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "LoginEye_OnFailedLogin" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "LoginEye_OnSuccessLogin" -Confirm:$false -ErrorAction SilentlyContinue
schtasks /delete /tn "LoginEye_BootGuard" /f >$null 2>&1
schtasks /delete /tn "LoginEye_OnFailedLogin" /f >$null 2>&1

Write-Host "[+] LoginEye a fost dezinstalat din fundal." -ForegroundColor Green
Write-Host "[i] Pozele din folderul 'captures/' au fost pastrate." -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
