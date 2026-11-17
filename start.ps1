# PhishGuard one-command start (Windows PowerShell 5.1+).
#
#   .\start.ps1               # set up everything, start API + web app, open the browser
#   .\start.ps1 -Dev          # run the web app with hot reload (next dev) instead of a build
#   .\start.ps1 -Retrain      # download the datasets and retrain the model first
#   .\start.ps1 -NoBrowser    # do not open the browser at the end
#
# First run: creates the Python venv, installs packages and builds the web app
# (a few minutes). Later runs start in seconds. Stop everything with .\stop.ps1
param(
    [switch]$Dev,
    [switch]$Retrain,
    [switch]$NoBrowser,
    [int]$ApiPort = 8000,
    [int]$WebPort = 3100   # 3000 is often taken by other dev servers
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"
$env:PYTHONUTF8 = "1"   # utf-8 for all Python file I/O on Windows

function Step($message) { Write-Host "`n==> $message" -ForegroundColor Cyan }
function Assert-Ok($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE)" } }

# --- 1. Python environment ----------------------------------------------------
if (-not (Test-Path $python)) {
    Step "Creating the Python virtual environment"
    if (Get-Command py -ErrorAction SilentlyContinue) { py -3 -m venv (Join-Path $root ".venv") }
    else { python -m venv (Join-Path $root ".venv") }
    Assert-Ok "venv creation"
    Step "Installing Python packages"
    & $python -m pip install --quiet --upgrade pip
    & $python -m pip install --quiet -r (Join-Path $backend "requirements.txt")
    Assert-Ok "pip install"
}

# --- 2. Model (a trained model is committed; retrain only when asked) --------
if ($Retrain -or -not (Test-Path (Join-Path $backend "models\model.json"))) {
    Push-Location $backend
    Step "Downloading the public datasets (about 19 MB, checksums verified)"
    & $python scripts\download_datasets.py
    Assert-Ok "dataset download"
    Step "Training the model (about one minute)"
    & $python -m phishguard.model.train
    Assert-Ok "training"
    Pop-Location
}

# --- 3. Web app packages and build --------------------------------------------
if (-not (Test-Path (Join-Path $frontend "node_modules"))) {
    Step "Installing web app packages"
    Push-Location $frontend
    npm install --no-fund --no-audit
    Pop-Location
    Assert-Ok "npm install"
}
if (-not $Dev -and -not (Test-Path (Join-Path $frontend ".next\BUILD_ID"))) {
    Step "Building the web app"
    Push-Location $frontend
    npm run build
    Pop-Location
    Assert-Ok "npm run build"
}

# --- 4. Start the API and the web app, each in its own window -----------------
Step "Starting the API on port $ApiPort and the web app on port $WebPort"
$apiCommand = "`$env:PYTHONUTF8='1'; Set-Location '$backend'; " +
    "& '$python' -m uvicorn phishguard.main:app --host 127.0.0.1 --port $ApiPort"
$webScript = if ($Dev) { "dev" } else { "start" }
$webCommand = "`$env:NEXT_PUBLIC_API_BASE='http://127.0.0.1:$ApiPort'; Set-Location '$frontend'; " +
    "npx next $webScript --port $WebPort"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $apiCommand
Start-Process powershell -ArgumentList "-NoExit", "-Command", $webCommand

# --- 5. Wait for the API, then open the scanner ------------------------------
$ready = $false
foreach ($attempt in 1..60) {
    try {
        # WHY 127.0.0.1 and not localhost: PowerShell tries IPv6 (::1) first,
        # the API listens on IPv4 only, and the IPv6 attempt eats the timeout.
        Invoke-RestMethod "http://127.0.0.1:$ApiPort/api/health" -TimeoutSec 3 | Out-Null
        $ready = $true
        break
    } catch { Start-Sleep -Seconds 1 }
}
if (-not $ready) { throw "The API did not start. Check the API window for the error." }

if (-not $NoBrowser) { Start-Process "http://localhost:$WebPort" }
Write-Host "`nPhishGuard is running" -ForegroundColor Green
Write-Host "  Scanner:   http://localhost:$WebPort"
Write-Host "  Dashboard: http://localhost:$WebPort/admin"
Write-Host "  API docs:  http://127.0.0.1:$ApiPort/docs"
Write-Host "`nChrome extension: open chrome://extensions, turn on Developer mode,"
Write-Host "click 'Load unpacked' and choose the folder: $root\extension"
Write-Host "Fill the dashboard with sample scans:  .venv\Scripts\python.exe backend\scripts\demo_scans.py"
Write-Host "Stop everything:  .\stop.ps1"
