#Requires -RunAsAdministrator
<#
.SYNOPSIS
    LoginEye Installer - Configures Windows Audit Policies & Task Scheduler.
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "               LoginEye Installer & Setup                 " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verify Executable or Python
$ExePath = Join-Path $ScriptDir "logineye.exe"
$UseExe = Test-Path $ExePath

if (-not $UseExe) {
    Write-Host "[*] Standalone logineye.exe not found, checking Python..." -ForegroundColor Yellow
    $PythonwPath = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
    if (-not $PythonwPath) {
        $PythonPath = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
        $PythonwPath = $PythonPath.Replace("python.exe", "pythonw.exe")
    }
    if (-not (Test-Path $PythonwPath)) {
        Write-Host "[ERROR] Neither logineye.exe nor pythonw.exe found!" -ForegroundColor Red
        Exit 1
    }
    $TargetCmd = $PythonwPath
    $TargetArg = "`"$ScriptDir\main.py`""
    Write-Host "[+] Using Python runtime: $TargetCmd" -ForegroundColor Green
} else {
    $TargetCmd = $ExePath
    $TargetArg = ""
    Write-Host "[+] Using compiled executable: $TargetCmd" -ForegroundColor Green
}

# 2. Ensure Directories
$CapturesDir = Join-Path $ScriptDir "captures"
$LogsDir = Join-Path $ScriptDir "logs"
New-Item -ItemType Directory -Force -Path $CapturesDir, $LogsDir | Out-Null

# 3. Enable Windows Audit Policies for Logon
Write-Host "[*] Enabling Windows Security Auditing for Logon events..." -ForegroundColor Yellow
try {
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable | Out-Null
    Write-Host "[+] Logon Audit Policies enabled successfully (Success & Failure)." -ForegroundColor Green
} catch {
    Write-Host "[-] Warning: Failed to set auditpol automatically. You may need to verify in secpol.msc." -ForegroundColor Yellow
}

# 4. Stop any previous instance of LoginEye
Write-Host "[*] Stopping any existing instances..." -ForegroundColor Yellow
Stop-Process -Name "logineye" -Force -ErrorAction SilentlyContinue
Get-Process | Where-Object { $_.ProcessName -like "*python*" -and $_.CommandLine -like "*logineye*" } | Stop-Process -Force -ErrorAction SilentlyContinue

# 5. Remove existing scheduled tasks
Unregister-ScheduledTask -TaskName "LoginEye_Daemon" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "LoginEye_OnFailedLogin" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "LoginEye_OnSuccessLogin" -Confirm:$false -ErrorAction SilentlyContinue

# 6. Create Task 1: Background Daemon (Runs at Startup and at Logon)
Write-Host "[*] Registering Scheduled Task: LoginEye_Daemon..." -ForegroundColor Yellow

$ActionDaemon = if ($UseExe) {
    New-ScheduledTaskAction -Execute $TargetCmd -Argument "--daemon" -WorkingDirectory $ScriptDir
} else {
    New-ScheduledTaskAction -Execute $TargetCmd -Argument "$TargetArg --daemon" -WorkingDirectory $ScriptDir
}

$TriggerLogon = New-ScheduledTaskTrigger -AtLogOn
$TriggerBoot  = New-ScheduledTaskTrigger -AtStartup

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Days 0) `
    -MultipleInstances IgnoreNew `
    -Priority 4 `
    -Hidden

$Principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel HighestAvailable

Register-ScheduledTask `
    -TaskName "LoginEye_Daemon" `
    -Action $ActionDaemon `
    -Trigger @($TriggerLogon, $TriggerBoot) `
    -Settings $Settings `
    -Principal $Principal `
    -Description "LoginEye Background Monitor - Detects failed and successful login attempts via webcam." `
    -Force | Out-Null

Write-Host "[+] Task 'LoginEye_Daemon' registered successfully." -ForegroundColor Green

# 7. Create Task 2: Immediate Event Trigger for Failed Logins (Event 4625)
Write-Host "[*] Registering Event Trigger for Failed Password Attempts (Event 4625)..." -ForegroundColor Yellow

$ActionFail = if ($UseExe) {
    New-ScheduledTaskAction -Execute $TargetCmd -Argument "--trigger FAIL --reason `"Bad Password Attempt`"" -WorkingDirectory $ScriptDir
} else {
    New-ScheduledTaskAction -Execute $TargetCmd -Argument "$TargetArg --trigger FAIL --reason `"Bad Password Attempt`"" -WorkingDirectory $ScriptDir
}

# XML for Security Event 4625 Trigger
$FailXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>LoginEye - Snaps webcam picture when an incorrect password is entered.</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select Path="Security"&gt;*[System[(EventID=4625)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$env:USERDOMAIN\$env:USERNAME</UserId>
      <LogonType>Interactive</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$($ActionFail.Execute)</Command>
      <Arguments>$($ActionFail.Arguments)</Arguments>
      <WorkingDirectory>$ScriptDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

$TempFailXml = Join-Path $env:TEMP "LoginEye_FailTask.xml"
$FailXml | Out-File -FilePath $TempFailXml -Encoding Unicode
schtasks /create /tn "LoginEye_OnFailedLogin" /xml $TempFailXml /f | Out-Null
Remove-Item $TempFailXml -Force -ErrorAction SilentlyContinue
Write-Host "[+] Task 'LoginEye_OnFailedLogin' registered successfully." -ForegroundColor Green

# 8. Start the Daemon now
Write-Host "[*] Starting LoginEye in background..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName "LoginEye_Daemon"
Start-Sleep -Seconds 1

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         LoginEye Installed and Activated!                " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Photos are automatically saved to: $CapturesDir" -ForegroundColor White
Write-Host "Logs are saved to                : $LogsDir\logineye.log" -ForegroundColor White
Write-Host "To test anytime, run             : test_camera.bat" -ForegroundColor White
Write-Host "To view photos, run              : view_captures.bat" -ForegroundColor White
Write-Host "To uninstall, run                : uninstall.bat" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
