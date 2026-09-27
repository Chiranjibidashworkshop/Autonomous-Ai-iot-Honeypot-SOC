@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$files=@('run\honeypot.pid','run\streamlit.pid'); foreach($f in $files){ if(Test-Path $f){ $id=Get-Content $f -ErrorAction SilentlyContinue; if($id){ Stop-Process -Id ([int]$id) -Force -ErrorAction SilentlyContinue } Remove-Item $f -Force -ErrorAction SilentlyContinue } }; Write-Host 'Project processes stopped.' -ForegroundColor Green"
endlocal
