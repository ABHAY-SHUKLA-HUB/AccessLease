# ==============================================================================
# AccessLease Backend Test Suite & Health Verification Runner
# ==============================================================================

param(
    [string]$Server = "(localdb)\MSSQLLocalDB",
    [string]$Database = "AccessLease_TestDB"
)

$ErrorActionPreference = "Stop"

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "AccessLease Backend Foundation Verification & Test Execution" -ForegroundColor Cyan
Write-Host "Node Version: $(node -v) | npm Version: $(npm -v)" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# 1. Start LocalDB if available
Write-Host "`n1. Verifying SQL Server LocalDB service..." -ForegroundColor Yellow
try {
    sqllocaldb start MSSQLLocalDB | Out-Null
    Write-Host "   LocalDB instance 'MSSQLLocalDB' is running." -ForegroundColor Green
} catch {
    Write-Host "   LocalDB is not detected or could not be started." -ForegroundColor Gray
}

# 2. Run Unit Tests
Write-Host "`n2. Executing Unit Tests (Isolated from database)..." -ForegroundColor Yellow
Set-Location "$PSScriptRoot/.."
npm run test:unit
if ($LASTEXITCODE -ne 0) {
    Write-Error "Unit tests failed."
}

# 3. Run Integration Tests
Write-Host "`n3. Executing Integration Tests (Live SQL Server connectivity)..." -ForegroundColor Yellow
$env:SQL_SERVER = $Server
$env:SQL_DATABASE = $Database
npm run test:integration
if ($LASTEXITCODE -ne 0) {
    Write-Error "Integration tests failed."
}

Write-Host "`n==================================================================" -ForegroundColor Green
Write-Host "ALL BACKEND TESTS PASSED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green

