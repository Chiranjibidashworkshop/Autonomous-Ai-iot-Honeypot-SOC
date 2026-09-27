@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_and_start.ps1"
if errorlevel 1 (
  echo.
  echo STARTUP FAILED. Read the message above.
  pause
)
endlocal
