$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Find-Python {
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $paths = @(
        "$env:LocalAppData\Programs\Python\Python313\python.exe",
        "$env:LocalAppData\Programs\Python\Python312\python.exe",
        "$env:LocalAppData\Programs\Python\Python311\python.exe",
        "$env:ProgramFiles\Python313\python.exe",
        "$env:ProgramFiles\Python312\python.exe",
        "$env:ProgramFiles\Python311\python.exe"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    return $null
}

$python = Find-Python
if (-not $python) {
    Write-Host 'Python was not found. Installing Python 3.11 with winget...' -ForegroundColor Yellow
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw 'Python is missing and winget is unavailable. Install Python 3.11+ from python.org, then run START_HERE.bat again.'
    }
    & winget install --id Python.Python.3.11 -e --accept-package-agreements --accept-source-agreements
    Start-Sleep -Seconds 3
    $python = Find-Python
    if (-not $python) { throw 'Python was installed but could not be located. Close/reopen VS Code and run START_HERE.bat again.' }
}

Write-Host "Using Python: $python" -ForegroundColor Cyan
& $python --version

$venv = Join-Path $PSScriptRoot '.venv'
$venvPython = if ($IsWindows -or $env:OS -eq 'Windows_NT') { Join-Path $venv 'Scripts\python.exe' } else { Join-Path $venv 'bin/python' }

if (-not (Test-Path $venvPython)) {
    Write-Host 'Creating local virtual environment...' -ForegroundColor Cyan
    & $python -m venv $venv
}

Write-Host 'Installing/repairing dependencies...' -ForegroundColor Cyan
& $venvPython -m pip install --disable-pip-version-check --upgrade pip
& $venvPython -m pip install --disable-pip-version-check -r requirements.txt

if (-not (Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
}

# Force the safe presentation profile for the one-click launcher.
$envText = Get-Content '.env' -Raw
$envText = $envText -replace '(?m)^DEMO_MODE=.*$', 'DEMO_MODE=true'
$envText = $envText -replace '(?m)^MITIGATION_ENABLED=.*$', 'MITIGATION_ENABLED=false'
$envText = $envText -replace '(?m)^DRY_RUN=.*$', 'DRY_RUN=true'
Set-Content '.env' $envText -Encoding UTF8

New-Item -ItemType Directory -Force -Path 'data','logs','models','run' | Out-Null

# Stop only processes previously launched by this project.
if (Test-Path 'run\honeypot.pid') {
    $old = Get-Content 'run\honeypot.pid' -ErrorAction SilentlyContinue
    if ($old) { Stop-Process -Id ([int]$old) -Force -ErrorAction SilentlyContinue }
}
if (Test-Path 'run\streamlit.pid') {
    $old = Get-Content 'run\streamlit.pid' -ErrorAction SilentlyContinue
    if ($old) { Stop-Process -Id ([int]$old) -Force -ErrorAction SilentlyContinue }
}

Write-Host 'Training ML model...' -ForegroundColor Cyan
& $venvPython scripts\train_model.py | Tee-Object -FilePath 'run\training.log'

Write-Host 'Seeding presentation telemetry...' -ForegroundColor Cyan
& $venvPython scripts\seed_demo.py | Tee-Object -FilePath 'run\seed.log'

$honeypotOut = Join-Path $PSScriptRoot 'logs\honeypot_stdout.log'
$honeypotErr = Join-Path $PSScriptRoot 'logs\honeypot_stderr.log'
$streamOut = Join-Path $PSScriptRoot 'logs\streamlit_stdout.log'
$streamErr = Join-Path $PSScriptRoot 'logs\streamlit_stderr.log'

Write-Host 'Starting IoT deception core...' -ForegroundColor Green
$h = Start-Process -FilePath $venvPython -ArgumentList '-m','src.iot_honeypot.main' -WorkingDirectory $PSScriptRoot -PassThru -RedirectStandardOutput $honeypotOut -RedirectStandardError $honeypotErr
$h.Id | Set-Content 'run\honeypot.pid'

Start-Sleep -Seconds 3

Write-Host 'Starting Streamlit SOC...' -ForegroundColor Green
$s = Start-Process -FilePath $venvPython -ArgumentList '-m','streamlit','run','src/soc_dashboard/app.py','--server.address','127.0.0.1','--server.port','8501' -WorkingDirectory $PSScriptRoot -PassThru -RedirectStandardOutput $streamOut -RedirectStandardError $streamErr
$s.Id | Set-Content 'run\streamlit.pid'

Start-Sleep -Seconds 7
Start-Process 'http://127.0.0.1:8501'

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' AUTONOMOUS AI-DRIVEN IoT HONEYPOT SOC - SHOWCASE READY' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' Dashboard : http://127.0.0.1:8501' -ForegroundColor White
Write-Host ' HTTP      : 8080' -ForegroundColor White
Write-Host ' SSH       : 2222' -ForegroundColor White
Write-Host ' TELNET    : 2323' -ForegroundColor White
Write-Host ' MQTT      : 1883' -ForegroundColor White
Write-Host ' FTP       : 2121' -ForegroundColor White
Write-Host ' Demo mode : ON (synthetic telemetry)' -ForegroundColor Yellow
Write-Host ' Mitigation: OFF / DRY-RUN' -ForegroundColor Yellow
Write-Host ''
Write-Host 'Anyone can open the dashboard and immediately see live synthetic SOC data.' -ForegroundColor Green
Write-Host 'Use STOP_PROJECT.bat to close both processes.' -ForegroundColor Gray
