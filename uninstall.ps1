#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "               LoginEye Uninstaller                       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

Write-Host "[*] Stopping running processes..." -ForegroundColor Yellow
Stop-Process -Name "logineye" -Force
Get-Process | Where-Object { $_.ProcessName -like "*python*" -and $_.CommandLine -like "*logineye*" } | Stop-Process -Force

Write-Host "[*] Removing Scheduled Tasks..." -ForegroundColor Yellow
Unregister-ScheduledTask -TaskName "LoginEye_Daemon" -Confirm:$false
Unregister-ScheduledTask -TaskName "LoginEye_OnFailedLogin" -Confirm:$false
Unregister-ScheduledTask -TaskName "LoginEye_OnSuccessLogin" -Confirm:$false

Write-Host "[+] LoginEye background tasks and processes removed." -ForegroundColor Green
Write-Host "[i] Note: Captured photos in 'captures/' folder were preserved." -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
