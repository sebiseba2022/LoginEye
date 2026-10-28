<#
.SYNOPSIS
    LoginEye Installer - Configures Boot-time Pre-Login Guard, Session Daemon, Audit Policies & Camera Verification.
#>
param(
    [switch]$ElevatedOnly
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

function Enable-AdminSecurityFeatures {
    param($TargetCmd, $TargetArg, $UseExe, $ScriptDir)

    Write-Host "[*] Activare politici Windows Audit pentru Logon (Event 4625)..." -ForegroundColor Yellow
    try {
        auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable >$null 2>&1
        auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable >$null 2>&1
        Write-Host "[+] Politici Audit Logon activate cu succes." -ForegroundColor Green
    } catch {
        Write-Host "[-] Avertisment: Nu s-a putut seta auditpol automat." -ForegroundColor Yellow
    }

    # Grant Interactive Users read access to Security Event Log so user-session daemon can also read Event 4625
    try {
        wevtutil sl Security /ca:"O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;IU)" >$null 2>&1
    } catch {}

    # 1. Register Boot-Time Pre-Login Guard (Runs as SYSTEM at Startup / Fast Boot BEFORE any user logs in!)
    Write-Host "[*] Inregistrare 'LoginEye_BootGuard' (Protectie inainte de Login, la pornirea laptopului)..." -ForegroundColor Yellow
    $BootArg = if ($UseExe) { "--daemon --boot" } else { "$TargetArg --daemon --boot" }
    $BootXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>LoginEye Boot Guard - Runs at Windows Startup BEFORE user login to capture pre-login FAIL and initial PASS photos.</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-Biometrics/Operational"&gt;&lt;Select Path="Microsoft-Windows-Biometrics/Operational"&gt;*[System[(EventID=1108)]]&lt;/Select&gt;&lt;/Query&gt;&lt;Query Id="1" Path="Microsoft-Windows-HelloForBusiness/Operational"&gt;&lt;Select Path="Microsoft-Windows-HelloForBusiness/Operational"&gt;*[System[(EventID=5000)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
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
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>1</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$TargetCmd</Command>
      <Arguments>$BootArg</Arguments>
      <WorkingDirectory>$ScriptDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
    $TempBootXml = Join-Path $env:TEMP "LoginEye_BootGuard.xml"
    $BootXml | Out-File -FilePath $TempBootXml -Encoding Unicode -Force
    schtasks /create /tn "LoginEye_BootGuard" /xml $TempBootXml /f >$null 2>&1
    Remove-Item $TempBootXml -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Task 'LoginEye_BootGuard' (AtStartup / Pre-Login) inregistrat cu succes." -ForegroundColor Green

    # 2. Register Session Daemon with Priority 1 (Zero startup delay at Logon)
    Write-Host "[*] Inregistrare 'LoginEye_Daemon' cu prioritate maxima (fara intarziere la Logon)..." -ForegroundColor Yellow
    $DaemonArg = if ($UseExe) { "--daemon" } else { "$TargetArg --daemon" }
    $DaemonXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>LoginEye Session Daemon - Guards workstation lock/unlock and login events.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>$env:USERDOMAIN\$env:USERNAME</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$env:USERDOMAIN\$env:USERNAME</UserId>
      <LogonType>InteractiveToken</LogonType>
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
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>1</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$TargetCmd</Command>
      <Arguments>$DaemonArg</Arguments>
      <WorkingDirectory>$ScriptDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
    $TempDaemonXml = Join-Path $env:TEMP "LoginEye_Daemon.xml"
    $DaemonXml | Out-File -FilePath $TempDaemonXml -Encoding Unicode -Force
    schtasks /create /tn "LoginEye_Daemon" /xml $TempDaemonXml /f >$null 2>&1
    Remove-Item $TempDaemonXml -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Task 'LoginEye_Daemon' (Priority 1) inregistrat cu succes." -ForegroundColor Green

    # 3. Register Event 4625 Task
    $ActionFailArg = if ($UseExe) {
        "--trigger FAIL --reason `"Incorrect Password Attempt`""
    } else {
        "$TargetArg --trigger FAIL --reason `"Incorrect Password Attempt`""
    }

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
      <UserId>S-1-5-18</UserId>
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
    <Priority>1</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$TargetCmd</Command>
      <Arguments>$ActionFailArg</Arguments>
      <WorkingDirectory>$ScriptDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

    $TempFailXml = Join-Path $env:TEMP "LoginEye_FailTask.xml"
    $FailXml | Out-File -FilePath $TempFailXml -Encoding Unicode -Force
    schtasks /create /tn "LoginEye_OnFailedLogin" /xml $TempFailXml /f >$null 2>&1
    Remove-Item $TempFailXml -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Task 'LoginEye_OnFailedLogin' (Event 4625) inregistrat cu succes." -ForegroundColor Green
}

# 1. Verify Executable or Python
$ExePath = Join-Path $ScriptDir "logineye.exe"
$UseExe = Test-Path $ExePath
$PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source

if ($UseExe) {
    $TargetCmd = $ExePath
    $TargetArg = ""
} else {
    $PythonwPath = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
    if (-not $PythonwPath -and $PythonExe) {
        $PythonwPath = $PythonExe.Replace("python.exe", "pythonw.exe")
    }
    if (-not $PythonwPath -or -not (Test-Path $PythonwPath)) {
        Write-Host "[EROARE] Nu s-a gasit nici logineye.exe, nici pythonw.exe!" -ForegroundColor Red
        exit 1
    }
    $TargetCmd = $PythonwPath
    $TargetArg = "`"$ScriptDir\main.py`""
}

# If invoked solely for the elevated child step, run Admin config and exit
if ($ElevatedOnly) {
    if ($IsAdmin) {
        Stop-Process -Name "logineye" -Force -ErrorAction SilentlyContinue
        Enable-AdminSecurityFeatures -TargetCmd $TargetCmd -TargetArg $TargetArg -UseExe $UseExe -ScriptDir $ScriptDir
        Start-ScheduledTask -TaskName "LoginEye_Daemon" -ErrorAction SilentlyContinue
    }
    exit 0
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "               LoginEye Installer & Setup                 " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[+] Director proiect: $ScriptDir" -ForegroundColor Green
Write-Host "[+] Executabil activ: $TargetCmd" -ForegroundColor Green

# 2. Ensure Directories
$CapturesDir = Join-Path $ScriptDir "captures"
$LogsDir = Join-Path $ScriptDir "logs"
New-Item -ItemType Directory -Force -Path $CapturesDir, $LogsDir | Out-Null

# 3. Stop any previous instance of LoginEye
Write-Host "[*] Oprire instante anterioare LoginEye..." -ForegroundColor Yellow
Stop-Process -Name "logineye" -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

# 4. Register Startup in HKCU Run
Write-Host "[*] Inregistrare pornire automata (Registry Run & Task Scheduler)..." -ForegroundColor Yellow
try {
    $RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $RunValue = if ($UseExe) { "`"$ExePath`" --daemon" } else { "`"$TargetCmd`" $TargetArg --daemon" }
    Set-ItemProperty -Path $RunKey -Name "LoginEye" -Value $RunValue -Force
    Write-Host "[+] Pornire automata inregistrata in Windows Startup (HKCU\...\Run)." -ForegroundColor Green
} catch {
    Write-Host "[-] Avertisment la setarea cheii Registry Run: $_" -ForegroundColor Yellow
}

# 5. Configure Admin Security & Boot-Time Pre-Login features (directly if Admin, or via UAC helper)
if ($IsAdmin) {
    Enable-AdminSecurityFeatures -TargetCmd $TargetCmd -TargetArg $TargetArg -UseExe $UseExe -ScriptDir $ScriptDir
} else {
    Write-Host "[*] Se solicita permisiuni Administrator (UAC) pentru protectia la Boot (inainte de Login)..." -ForegroundColor Yellow
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ElevatedOnly" -Wait -ErrorAction Stop
        Write-Host "[+] Protectia la Boot (LoginEye_BootGuard) si Task-urile Administrator au fost activate!" -ForegroundColor Green
    } catch {
        Write-Host "[i] Continuare fara UAC..." -ForegroundColor Yellow
    }
}

# 6. Start the Background Daemon
Write-Host ""
Write-Host "[*] Pornire serviciu de monitorizare LoginEye in fundal..." -ForegroundColor Yellow
try {
    Start-ScheduledTask -TaskName "LoginEye_Daemon" -ErrorAction Stop
} catch {
    if ($UseExe) {
        Start-Process -FilePath $ExePath -ArgumentList "--daemon" -WorkingDirectory $ScriptDir
    } else {
        Start-Process -FilePath $TargetCmd -ArgumentList "$TargetArg --daemon" -WorkingDirectory $ScriptDir
    }
}
Start-Sleep -Seconds 2

$Proc = Get-Process -Name "logineye", "python*" -ErrorAction SilentlyContinue
if ($Proc) {
    Write-Host "[+] Serviciul LoginEye ESTE ACTIV in fundal si pazeste PC-ul!" -ForegroundColor Green
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         LoginEye Instalat si Activat cu Succes!          " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Pozele sunt salvate automat in : $CapturesDir" -ForegroundColor White
Write-Host "Jurnalul (log) se afla in      : $LogsDir\logineye.log" -ForegroundColor White
Write-Host ""
Write-Host "Ce este monitorizat acum in timp real:" -ForegroundColor Yellow
Write-Host "  [BOOT] Protectie inainte de primul Login (la aprinderea / restartul laptopului)" -ForegroundColor Cyan
Write-Host "  [PASS] Login initial si Deblocare PC (Amprenta / PIN / Parola)" -ForegroundColor Green
Write-Host "  [FAIL] Amprenta gresita / PIN gresit / Parola gresita" -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Cyan

Start-Process explorer.exe $CapturesDir
