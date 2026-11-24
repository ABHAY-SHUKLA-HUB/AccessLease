# AccessLease — Database Migration Guide

**Target RDBMS:** Microsoft SQL Server 2019+ / Azure SQL Database  
**Phase:** STEP 01 — Database Design & Schema Migration  
**Document Version:** 1.0.0  

---

## 1. Overview & Directory Layout

AccessLease migrations are designed to be reproducible, idempotent, and version-controlled. All migration files are located under [`database/migrations/`](file:///d:/access/database/migrations/) and partitioned into modular files following a strict execution sequence:

```text
database/
├── schema/
│   ├── 001_create_core_tables.sql
│   ├── 002_add_relationships_and_constraints.sql
│   └── 003_create_indexes.sql
├── migrations/
│   ├── 001_create_core_tables.sql
│   ├── 002_add_relationships_and_constraints.sql
│   ├── 003_create_indexes.sql
│   ├── 004_create_access_exposure_view.sql
│   ├── 005_create_activation_procedure.sql
│   ├── 006_create_contractor_expiry_trigger.sql
│   ├── 007_create_external_identities_and_provisioning_jobs.sql
│   ├── 008_create_oauth_states.sql
│   ├── 009_expand_provisioning_event_types.sql
│   ├── 010_add_provider_audit_events.sql
│   ├── 011_enhance_revocation_jobs.sql
│   ├── 012_revocation_hardening.sql
│   ├── 013_membership_coordination.sql
│   ├── 014_orphan_access_findings.sql
│   └── 015_orphan_index_hardening.sql
├── seeds/
│   ├── 001_system_roles_seed.sql
│   ├── 002_user_provisioning_seed.sql
│   ├── 003_access_workflow_seed.sql
│   └── 004_github_provisioning_seed.sql
├── scripts/
│   └── setup_managed_identity_user.sql
└── tests/
    ├── test_suite.sql
    └── run_tests.ps1
```

---

## 2. Migration Execution Sequence

Migrations must be executed in strict numerical order:

| Step | Script File | Description | Dependency Prerequisite |
| :--- | :--- | :--- | :--- |
| **001** | `001_create_core_tables.sql` | Instantiates all 15 core governance tables with clustered primary keys and basic defaults. | Target database exists. |
| **002** | `002_add_relationships_and_constraints.sql` | Establishes all PK/FK foreign keys, UNIQUE constraints, and CHECK constraints. | Step 001 completed. |
| **003** | `003_create_indexes.sql` | Builds governance, performance, and filtered unique indexes across all entities. | Step 002 completed. |
| **004** | `004_create_access_exposure_view.sql` | Compiles the `v_AccessExposureQueue` view for monitoring exposed and expiring grants. | Steps 001 & 002 completed. |
| **005** | `005_create_activation_procedure.sql` | Compiles `sp_ActivateApprovedGrant` stored procedure for atomic grant activation. | Steps 001–003 completed. |
| **006** | `006_create_contractor_expiry_trigger.sql` | Installs set-based `tr_ContractorGrantMustExpire` trigger on `access_grants`. | Steps 001–005 completed. |
| **007** | `007_create_external_identities_and_provisioning_jobs.sql` | Creates `user_external_identities`, `connector_resource_mappings`, and `provisioning_jobs` tables. | Steps 001–006 completed. |
| **008** | `008_create_oauth_states.sql` | Creates `oauth_states` table for secure PKCE state tracking and OAuth lifecycle management. | Step 007 completed. |
| **009** | `009_expand_provisioning_event_types.sql` | Expands allowed CHECK constraints for `provisioning_events` with connector-specific types. | Step 007 completed. |
| **010** | `010_add_provider_audit_events.sql` | Adds provider-side audit evidence tracking columns and constraints. | Steps 007 & 009 completed. |
| **011** | `011_enhance_revocation_jobs.sql` | Adds retry count, backoff calculation, and failure classification to `revocation_jobs`. | Steps 001–006 completed. |
| **012** | `012_revocation_hardening.sql` | Adds worker lease ownership columns (`locked_by_worker_id`, `lock_expires_at`) to revocation jobs. | Step 011 completed. |
| **013** | `013_membership_coordination.sql` | Creates `membership_coordination` table for distributed lease fencing and applock coordination. | Steps 001–012 completed. |
| **014** | `014_orphan_access_findings.sql` | Creates `orphan_access_findings` table for continuous orphan account detection. | Steps 001–013 completed. |
| **015** | `015_orphan_index_hardening.sql` | Builds filtered unique and performance indexes on `orphan_access_findings`. | Step 014 completed. |
| **Seed**| `001_system_roles_seed.sql` | Seeds reference application roles (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, etc.) via idempotent `MERGE`. | Step 002 completed. |

---

## 3. Local Development Execution (LocalDB / SQLCMD)

### 3.1 Automated Execution via PowerShell Runner
AccessLease includes an automated script [`database/tests/run_tests.ps1`](file:///d:/access/database/tests/run_tests.ps1) that starts the local SQL Server instance, builds a clean test database (`AccessLease_ValidationDB`), applies all 15 sequential migrations + system roles seed, and executes the complete 12-test validation suite:

```powershell
pwsh -File database/tests/run_tests.ps1
```

### 3.2 Manual CLI Execution via `sqlcmd`
To apply all migrations sequentially to any SQL Server or Azure SQL Database:

```powershell
# Set connection parameters
$Server = "(localdb)\MSSQLLocalDB"
$Database = "AccessLease_DB"

# Run all 15 migrations in numerical order
Get-ChildItem -Path "database/migrations/*.sql" | Sort-Object Name | ForEach-Object {
    Write-Host "Applying $($_.Name)..."
    sqlcmd -b -S $Server -d $Database -i $_.FullName
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Migration $($_.Name) failed with exit code $LASTEXITCODE."
        exit $LASTEXITCODE
    }
}

# Seed canonical system roles (reference lookup data)
sqlcmd -b -S $Server -d $Database -i database/seeds/001_system_roles_seed.sql
```

---

## 4. Azure SQL Database Execution

When deploying to Azure SQL Database:

1. Retrieve the connection string from your `.env` or Azure Portal (`<server>.database.windows.net`).
2. Execute via Azure CLI or Azure Data Studio:
   ```bash
   sqlcmd -S "<server>.database.windows.net" -d "<database>" -U "<admin-user>" -P "<password>" -G -i database/migrations/001_create_core_tables.sql -b
   # (Repeat for migrations 002 through 006)
   ```
3. All scripts are 100% compliant with Azure SQL Database engine features (ANSI standards, UTF-8/NVARCHAR, `DATETIMEOFFSET`, `NEWSEQUENTIALID()`, clustered columnstore/B-trees).

---

## 5. Verification & Test Execution

Run the automated test suite against the target database:

```powershell
sqlcmd -S "(localdb)\MSSQLLocalDB" -d "AccessLease_TestDB" -i database/tests/test_suite.sql -b
```

Expected output indicates 100% pass across all 12 validation tests:
* Test 1: Successful Table Creation (All 15 Core Tables)
* Test 2: PK/FK Referential Integrity Enforcement
* Test 3: UNIQUE Constraint Enforcement
* Test 4: Invalid Contractor Expiry Rejection
* Test 5: Expiry Later Than Engagement End Date Rejection
* Test 6: Rejection of Grant Activation Without Required Approvals
* Test 7: Duplicate Active Grant Prevention
* Test 8: Stored Procedure Transaction Behavior & Atomic Rollback
* Test 9: Trigger Multi-Row Behavior
* Test 10: View Correctness (`v_AccessExposureQueue`)
* Test 11: Index Creation Verification
* Test 12: Migration Execution Order & Idempotency

---

## 6. Azure Managed Identity Permissions Setup (Production)

Once Azure resources are provisioned:
1. Connect to `accesslease-db` as an authorized **Microsoft Entra Administrator** (using Entra authentication).
2. Execute [`database/scripts/setup_managed_identity_user.sql`](file:///d:/access/database/scripts/setup_managed_identity_user.sql) using one of the following methods:

**Method A — sqlcmd CLI (Recommended):**
```powershell
sqlcmd -S "<server>.database.windows.net" -d "accesslease-db" --authentication-method ActiveDirectoryDefault `
  -v FUNCTION_APP_NAME="func-accesslease-dev-uniqueid" `
  -v MANAGED_IDENTITY_CLIENT_ID="<functionAppClientId-from-az-ad-sp-show>" `
  -i database/scripts/setup_managed_identity_user.sql
```
*Note: Passing the Client ID converts the Application ID into a SQL Server `varbinary(16)` SID (`WITH SID = ..., TYPE = E`), creating the user without querying Microsoft Graph.*

**Method B — SSMS / Azure Data Studio:**
1. Connect to `<server>.database.windows.net`, database `accesslease-db`, using **Azure Active Directory / Microsoft Entra** authentication.
2. Open [`database/scripts/setup_managed_identity_user.sql`](file:///d:/access/database/scripts/setup_managed_identity_user.sql).
3. Enable SQLCMD Mode via **Query** -> **SQLCMD Mode**, OR replace `$(FUNCTION_APP_NAME)` and `$(MANAGED_IDENTITY_CLIENT_ID)` directly in the script variable declarations.
4. Execute the query.

**Method C — PowerShell 7+ / ADO.NET (Single-Batch Execution):**
```powershell
# 1. Obtain Entra access token for Azure SQL
$token = (Get-AzAccessToken -ResourceUrl "https://database.windows.net").Token

# 2. Read and substitute script variables
$sql = Get-Content -Raw "database/scripts/setup_managed_identity_user.sql"
$sql = $sql.Replace('$(FUNCTION_APP_NAME)', $FunctionAppName)
$sql = $sql.Replace('$(MANAGED_IDENTITY_CLIENT_ID)', $FunctionAppClientId)

# 3. Connect via System.Data.SqlClient and execute single batch
$conn = New-Object System.Data.SqlClient.SqlConnection("Server=$SqlServerFqdn;Database=accesslease-db;Encrypt=True;TrustServerCertificate=False;")
$conn.AccessToken = $token
$conn.Open()

$cmd = $conn.CreateCommand()
$cmd.CommandText = $sql
$null = $cmd.ExecuteNonQuery()
$conn.Close()
```
*Note: The script contains no trailing `GO` delimiter and executes as a single atomic transaction with `SET XACT_ABORT ON` and `TRY...CATCH` rollback.*

This provisions the least-privilege role `[db_accesslease_app]`, creates the external database user for the Function App's System-Assigned Managed Identity (using its Client ID as the SID), validates that any existing principal has matching SID and type `E` (`EXTERNAL_USER`), and adds the user to the role in a single atomic transaction with strictly zero broad or destructive privileges (`db_owner`, `db_securityadmin`, `CONTROL`).
