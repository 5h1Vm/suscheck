@echo off
setlocal enabledelayedexpansion

:: =============================
:: Check for Admin Privileges
:: =============================
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( 
    goto gotAdmin 
)

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"

:: =============================
:: Main Cleanup Script
:: =============================
echo.
echo ================================
echo Running comprehensive cleanup...
echo ================================
echo.

call :CleanupTask "Temp Folders" "%TEMP%\*.*" "C:\Windows\Temp\*.*"
call :CleanupTask "Prefetch" "C:\Windows\Prefetch\*.*"
call :CleanupTask "Windows Update Cache" "C:\Windows\SoftwareDistribution\*.*"
call :CleanupTask "Delivery Optimization" "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache\*.*"
call :CleanupTask "Internet Explorer Cache" "%localappdata%\Microsoft\Windows\INetCache\*.*" "%localappdata%\Microsoft\Windows\WebCache\*.*"
call :CleanupTask "Chrome Cache" "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\*"
call :CleanupTask "Edge Cache" "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache\*"
call :CleanupTask "DirectX Shader Cache" "%localappdata%\NVIDIA\DXCache\*.*" "%localappdata%\AMD\DXCache\*.*" "%localappdata%\D3DSCache\*.*"
call :CleanupTask "Thumbnails Cache" "%localappdata%\Microsoft\Windows\Explorer\thumbcache_*.db"
call :CleanupTask "Windows Error Reporting" "C:\ProgramData\Microsoft\Windows\WER\*.*" "%localappdata%\Microsoft\Windows\WER\*.*" "%SystemRoot%\System32\config\systemprofile\AppData\Local\Microsoft\Windows\WER\ReportQueue\*" "%SystemRoot%\System32\config\systemprofile\AppData\Local\Microsoft\Windows\WER\ReportArchive\*" "%SystemRoot%\System32\config\systemprofile\AppData\Local\Microsoft\Windows\WER\Temp\*"
call :CleanupTask "Windows Defender Logs" "C:\ProgramData\Microsoft\Windows Defender\Scans\History\*.*"

:: Special cases
call :ClearRecycleBin
call :ClearEventLogs
call :ClearDNSCache
call :StopStartServices
call :RunDiskCleanup

echo.
echo ================================
echo Cleanup completed successfully!
echo ================================
echo.
pause
exit /b 0

:: =============================
:: Cleanup Functions
:: =============================
:CleanupTask
echo Clearing %~1...
for %%a in (%*) do (
    if not "%%a"=="%~1" (
        del /q /f /s "%%a" 2>nul
    )
)
goto :eof

:ClearRecycleBin
echo Clearing Recycle Bin...
rd /s /q %systemdrive%\$Recycle.bin 2>nul
goto :eof

:ClearEventLogs
echo Clearing Event Logs...
for /F "tokens=*" %%G in ('wevtutil el') do (wevtutil cl "%%G" 2>nul)
goto :eof

:ClearDNSCache
echo Clearing DNS Cache...
ipconfig /flushdns >nul
goto :eof

:StopStartServices
echo Managing Services...
net stop wuauserv >nul 2>&1
net stop bits >nul 2>&1
net start wuauserv >nul 2>&1
net start bits >nul 2>&1
goto :eof

:RunDiskCleanup
echo Running Disk Cleanup...
start /wait cleanmgr /sagerun:1
goto :eof