# AccessLease — Step 02 Repository Audit Report

**Date:** 2026-11-09  
**Role:** Senior Full-Stack Engineer  
**Scope:** Repository Inspection, Artifact Audit, and Backend Gap Analysis  
**Repository Root:** `d:\access`  

---

## 1. Executive Summary

A comprehensive repository audit was conducted across the codebase, database artifacts, configuration templates, version control status, and existing test suites. The objective of this audit is to distinguish verified working assets from missing implementations and establish a clean foundation for the real Node.js Azure Functions backend.

---

## 2. Inventory of Existing Implementation

### 2.1 Database & Persistence (Verified Working)
* **15 Core Tables in 3NF:** [`database/migrations/001_create_core_tables.sql`](file:///d:/access/database/migrations/001_create_core_tables.sql) defines `users`, `contractor_engagements`, `roles`, `user_roles`, `resources`, `entitlements`, `resource_owners`, `access_requests`, `approval_steps`, `access_grants`, `provisioning_events`, `revocation_jobs`, `access_reviews`, `review_items`, and `audit_events`.
* **Referential Integrity & Constraints:** [`002_add_relationships_and_constraints.sql`](file:///d:/access/database/migrations/002_add_relationships_and_constraints.sql) establishes PK/FK relationships, CHECK constraints, and UNIQUE constraints.
* **Indexes:** [`003_create_indexes.sql`](file:///d:/access/database/migrations/003_create_indexes.sql) establishes governance indexes including a filtered unique index preventing duplicate active grants.
* **Governance View:** [`004_create_access_exposure_view.sql`](file:///d:/access/database/migrations/004_create_access_exposure_view.sql) creates `v_AccessExposureQueue`.
* **Stored Procedure:** [`005_create_activation_procedure.sql`](file:///d:/access/database/migrations/005_create_activation_procedure.sql) creates `sp_ActivateApprovedGrant` with transactional integrity.
* **Set-Based Trigger:** [`006_create_contractor_expiry_trigger.sql`](file:///d:/access/database/migrations/006_create_contractor_expiry_trigger.sql) enforces hard contractor lease boundaries across single and multi-row operations.
* **Test Suite:** [`database/tests/run_tests.ps1`](file:///d:/access/database/tests/run_tests.ps1) and [`test_suite.sql`](file:///d:/access/database/tests/test_suite.sql) execute 12 automated verification tests against Microsoft SQL Server LocalDB (`(localdb)\MSSQLLocalDB`), achieving 100% pass status.

### 2.2 Documentation & Specifications (Verified Present)
* **Database Documentation:** [`docs/database/data-dictionary.md`](file:///d:/access/docs/database/data-dictionary.md), [`database-design.md`](file:///d:/access/docs/database/database-design.md), [`relationships.md`](file:///d:/access/docs/database/relationships.md), [`migration-guide.md`](file:///d:/access/docs/database/migration-guide.md).
* **Architecture Specifications:** [`docs/architecture/system-architecture.md`](file:///d:/access/docs/architecture/system-architecture.md), [`component-design.md`](file:///d:/access/docs/architecture/component-design.md), [`data-flow.md`](file:///d:/access/docs/architecture/data-flow.md), [`security-architecture.md`](file:///d:/access/docs/architecture/security-architecture.md), [`design-decisions.md`](file:///d:/access/docs/architecture/design-decisions.md).
* **API Contract:** [`docs/api/api-specification.md`](file:///d:/access/docs/api/api-specification.md).

### 2.3 Frontend Foundation (Static Baseline)
* Basic HTML5 entry point in [`frontend/index.html`](file:///d:/access/frontend/index.html), CSS in [`frontend/assets/css/main.css`](file:///d:/access/frontend/assets/css/main.css), and script baseline in [`frontend/assets/js/main.js`](file:///d:/access/frontend/assets/js/main.js).

---

## 3. Audit Findings: Gaps, Issues & Deficiencies

### 3.1 Missing Backend Implementation
1. **No `package.json`:** Neither the project root nor the `backend/` directory possesses a `package.json` manifest.
2. **Missing Dependencies:** `@azure/functions`, `mssql`, and `dotenv` are uninstalled.
3. **Empty Source Folders:** All subdirectories under `backend/src/` (`config`, `functions`, `middleware`, `repositories`, `services`, `utils`) and `backend/tests/` contain only `.gitkeep` placeholders.
4. **No Serverless Configuration:** Missing `backend/host.json` and `backend/local.settings.json` required by the Azure Functions host.
5. **No Health APIs:** Endpoints `GET /api/health` and `GET /api/health/db` are entirely unimplemented.
6. **No Backend Tests:** Zero unit or integration test files exist for JavaScript/Node.js logic.

### 3.2 Duplicate Artifacts Identified
1. **Schema vs. Migrations Duplication:** Exact duplicate SQL files exist across two directory trees:
   * `database/schema/001_create_core_tables.sql` $\leftrightarrow$ `database/migrations/001_create_core_tables.sql`
   * `database/schema/002_add_relationships_and_constraints.sql` $\leftrightarrow$ `database/migrations/002_add_relationships_and_constraints.sql`
   * `database/schema/003_create_indexes.sql` $\leftrightarrow$ `database/migrations/003_create_indexes.sql`
   * `database/views/004_create_access_exposure_view.sql` $\leftrightarrow$ `database/migrations/004_create_access_exposure_view.sql`
   * `database/procedures/005_create_activation_procedure.sql` $\leftrightarrow$ `database/migrations/005_create_activation_procedure.sql`
   * `database/triggers/006_create_contractor_expiry_trigger.sql` $\leftrightarrow$ `database/migrations/006_create_contractor_expiry_trigger.sql`
   * *Assessment:* While having modular directories (`views`, `procedures`, `triggers`) is useful for individual object inspection, `database/migrations/` must remain the single canonical source of truth for versioned schema changes to prevent configuration drift.

### 3.3 Environment Variable Inconsistencies
* [`.env.example`](file:///d:/access/.env.example) uses `AZURE_SQL_SERVER`, `AZURE_SQL_DATABASE`, `AZURE_SQL_USER`, and `AZURE_SQL_PASSWORD`.
* Common enterprise deployments and local SQL Server tooling often provide `SQL_SERVER`, `SQL_DATABASE`, `SQL_USER`, and `SQL_PASSWORD`.
* *Remediation:* Centralized environment configuration must support both naming variants transparently with sensible precedence.

### 3.4 Tooling & Environment Status
* **Node.js:** `v24.14.0` (Operational).
* **npm:** `11.9.0` (Operational).
* **Git:** `2.53.0.windows.1` (Operational, clean working tree on `main`).
* **SQL Server LocalDB:** `Microsoft SQL Server 2019 (15.0.4382.1)` active on `(localdb)\MSSQLLocalDB` with database `AccessLease_TestDB` initialized and verified.
* **Azure Functions Core Tools (`func`):** The global npm link reports `MODULE_NOT_FOUND` in npm's AppData directory. However, Node.js can execute Azure Functions modules directly via code, and tests run via native Node.js test runner.

---

## 4. Implementation Action Plan for Step 02

1. **Initialize `backend/package.json`:** Define `@azure/functions` (v4 model), `mssql`, and `dotenv` with a native test runner script.
2. **Install Dependencies:** Execute `npm install` in `backend/`.
3. **Configure Azure Functions Runtime:** Create `backend/host.json` and `backend/local.settings.json` (git-ignored template in `local.settings.json.example`).
4. **Implement Centralized Configuration:** Create `backend/src/config/environment.js` with validation and fallback support for both `SQL_SERVER` and `AZURE_SQL_SERVER`.
5. **Implement Connection Pool Manager:** Create `backend/src/config/database.js` managing a resilient singleton connection pool with timeout protection and clean teardown.
6. **Implement API Utilities:** Create `backend/src/utils/response.js` (standardized envelope), `backend/src/utils/errors.js` (custom error hierarchy), and `backend/src/utils/logger.js` (sanitized logging).
7. **Implement Health Function Handlers:**
   * `GET /api/health` — Application availability and safe environment metadata.
   * `GET /api/health/db` — Live SQL connectivity check executing `SELECT 1 AS is_healthy` against SQL Server without leaking credentials.
8. **Register Functions Entry Point:** Register handlers using `@azure/functions` v4 `app.http()`.
9. **Build Test Suite:** Implement unit and integration tests in `backend/tests/` covering configuration, pooling, health checks, error formatting, and secret exposure prevention.
10. **Execute Tests & Validate:** Run all backend tests and verify against real SQL Server LocalDB.

