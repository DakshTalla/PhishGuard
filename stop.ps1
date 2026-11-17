# Stop the PhishGuard API and web app started by start.ps1.
param([int]$ApiPort = 8000, [int]$WebPort = 3100)

foreach ($port in @($ApiPort, $WebPort)) {
    $listeners = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($conn in $listeners) {
        Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
        Write-Host "Stopped process $($conn.OwningProcess) on port $port"
    }
}
Write-Host "Done. (The two PowerShell windows can now be closed.)"
