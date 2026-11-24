# ==============================================================================
# AccessLease Database Migration & Automated Test Runner
# Target: (localdb)\MSSQLLocalDB / SQLCMD
# ==============================================================================

param(
    [string]$Server = "(localdb)\MSSQLLocalDB",
    [string]$Database = "AccessLease_ValidationDB"
)

$ErrorActionPreference = "Stop"

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "AccessLease Database Migration & Test Execution" -ForegroundColor Cyan
Write-Host "Server: $Server | Database: $Database" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# Ensure LocalDB is running
Write-Host "1. Verifying LocalDB service status..." -ForegroundColor Yellow
sqllocaldb start MSSQLLocalDB | Out-Null

# Drop and recreate clean test database
Write-Host "2. Creating clean test database [$Database]..." -ForegroundColor Yellow
$createDbSql = @"
IF DB_ID('$Database') IS NOT NULL
BEGIN
    ALTER DATABASE [$Database] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE [$Database];
END;
CREATE DATABASE [$Database];
ALTER DATABASE [$Database] SET ANSI_NULL_DEFAULT ON, ANSI_NULLS ON, ANSI_PADDING ON, ANSI_WARNINGS ON, ARITHABORT ON, CONCAT_NULL_YIELDS_NULL ON, QUOTED_IDENTIFIER ON;
"@
sqlcmd -S $Server -Q $createDbSql -b

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to initialize test database."
}

# Ordered migration files (all 15 sequential migrations + canonical roles seed)
$migrationFiles = @(
    "database/migrations/001_create_core_tables.sql",
    "database/migrations/002_add_relationships_and_constraints.sql",
    "database/migrations/003_create_indexes.sql",
    "database/migrations/004_create_access_exposure_view.sql",
    "database/migrations/005_create_activation_procedure.sql",
    "database/migrations/006_create_contractor_expiry_trigger.sql",
    "database/migrations/007_create_external_identities_and_provisioning_jobs.sql",
    "database/migrations/008_create_oauth_states.sql",
    "database/migrations/009_expand_provisioning_event_types.sql",
    "database/migrations/010_add_provider_audit_events.sql",
    "database/migrations/011_enhance_revocation_jobs.sql",
    "database/migrations/012_revocation_hardening.sql",
    "database/migrations/013_membership_coordination.sql",
    "database/migrations/014_orphan_access_findings.sql",
    "database/migrations/015_orphan_index_hardening.sql",
    "database/seeds/001_system_roles_seed.sql"
)

Write-Host "3. Applying sequential migrations..." -ForegroundColor Yellow
foreach ($file in $migrationFiles) {
    Write-Host "   -> Executing: $file" -ForegroundColor Gray
    sqlcmd -S $Server -d $Database -i $file -b
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Migration execution failed for file: $file"
    }
}
Write-Host "   All migrations applied successfully." -ForegroundColor Green

# Execute Test Suite
Write-Host "4. Running full automated validation test suite..." -ForegroundColor Yellow
sqlcmd -S $Server -d $Database -i "database/tests/test_suite.sql" -b

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nAll 12 database validation tests PASSED successfully against Microsoft SQL Server!" -ForegroundColor Green
} else {
    Write-Error "Test suite execution failed."
}
