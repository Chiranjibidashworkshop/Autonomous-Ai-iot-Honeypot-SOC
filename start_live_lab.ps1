$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPython)) { throw 'Run START_HERE.bat once first so the environment is prepared.' }
if (-not (Test-Path '.env')) { Copy-Item '.env.example' '.env' }
$text = Get-Content '.env' -Raw
$text = $text -replace '(?m)^DEMO_MODE=.*$', 'DEMO_MODE=false'
$text = $text -replace '(?m)^MITIGATION_ENABLED=.*$', 'MITIGATION_ENABLED=false'
$text = $text -replace '(?m)^DRY_RUN=.*$', 'DRY_RUN=true'
Set-Content '.env' $text -Encoding UTF8
New-Item -ItemType Directory -Force -Path 'logs','run' | Out-Null
Start-Process -FilePath $venvPython -ArgumentList '-m','src.iot_honeypot.main' -WorkingDirectory $PSScriptRoot -PassThru | ForEach-Object { $_.Id | Set-Content 'run\honeypot.pid' }
Start-Sleep -Seconds 2
Start-Process -FilePath $venvPython -ArgumentList '-m','streamlit','run','src/soc_dashboard/app.py','--server.address','127.0.0.1','--server.port','8501' -WorkingDirectory $PSScriptRoot -PassThru | ForEach-Object { $_.Id | Set-Content 'run\streamlit.pid' }
Start-Sleep -Seconds 5
Start-Process 'http://127.0.0.1:8501'
Write-Host 'LIVE LAB MODE started. Demo telemetry is disabled.' -ForegroundColor Green
Write-Host 'For real iptables enforcement, run on Linux/WSL2 and review .env first.' -ForegroundColor Yellow
