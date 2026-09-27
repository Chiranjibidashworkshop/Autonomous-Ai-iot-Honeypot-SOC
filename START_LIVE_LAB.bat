@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_live_lab.ps1"
if errorlevel 1 (
  echo.
  echo LIVE LAB STARTUP FAILED. Read the message above.
  pause
)
endlocal
