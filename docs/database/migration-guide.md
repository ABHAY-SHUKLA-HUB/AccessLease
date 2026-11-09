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
│   └── 006_create_contractor_expiry_trigger.sql
├── seeds/
│   └── 001_system_roles_seed.sql
├── views/
│   └── 004_create_access_exposure_view.sql
├── procedures/
│   └── 005_create_activation_procedure.sql
├── triggers/
│   └── 006_create_contractor_expiry_trigger.sql
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
| **Seed**| `001_system_roles_seed.sql` | Seeds reference application roles (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, etc.) via idempotent `MERGE`. | Step 002 completed. |

---

## 3. Local Development Execution (LocalDB / SQLCMD)

### 3.1 Automated Execution via PowerShell Runner
AccessLease includes an automated script [`database/tests/run_tests.ps1`](file:///d:/access/database/tests/run_tests.ps1) that starts the local SQL Server instance, builds the clean test database, applies all migrations in sequence, and executes the complete 12-test validation suite:

```powershell
pwsh -File database/tests/run_tests.ps1
```

### 3.2 Manual CLI Execution via `sqlcmd`
To apply migrations manually to any SQL Server or Azure SQL Database:

```powershell
# Set connection parameters
$Server = "(localdb)\MSSQLLocalDB"
$Database = "AccessLease_DB"

# Run migrations sequentially
sqlcmd -S $Server -d $Database -i database/migrations/001_create_core_tables.sql -b
sqlcmd -S $Server -d $Database -i database/migrations/002_add_relationships_and_constraints.sql -b
sqlcmd -S $Server -d $Database -i database/migrations/003_create_indexes.sql -b
sqlcmd -S $Server -d $Database -i database/migrations/004_create_access_exposure_view.sql -b
sqlcmd -S $Server -d $Database -i database/migrations/005_create_activation_procedure.sql -b
sqlcmd -S $Server -d $Database -i database/migrations/006_create_contractor_expiry_trigger.sql -b
sqlcmd -S $Server -d $Database -i database/seeds/001_system_roles_seed.sql -b
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
