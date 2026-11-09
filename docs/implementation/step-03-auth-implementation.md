# AccessLease — Step 03: Microsoft Entra ID Authentication Architecture & Verification Report

**Document ID:** `AL-STEP03-AUTH-001`  
**Phase:** STEP 03 — Real Microsoft Entra ID Authentication  
**Author:** AccessLease Identity & Access Management (IAM) & Full-Stack Security Engineering  
**Status:** IMPLEMENTED & VERIFIED  

---

## 1. Executive Summary

This report documents the architectural design, implementation details, identity mapping strategy, and automated test verification for **STEP 03 — Real Microsoft Entra ID Authentication** within the *AccessLease — Company-Grade Contractor Access & Offboarding Governance* platform.

In strict compliance with architectural constraints:
* **Frontend:** Implemented strictly in pure HTML5, CSS3, and Vanilla JavaScript (ES6+). Zero usage of React, Angular, Vue, Next.js, or TypeScript.
* **Authentication Flow:** OAuth 2.0 Authorization Code Flow with Proof Key for Code Exchange (PKCE) utilizing Microsoft Authentication Library (MSAL Browser v2.38.3).
* **Token Verification:** Backend middleware for Azure Functions v4 enforcing RS256 cryptographic signature validation against Microsoft Entra ID JSON Web Key Sets (JWKS), tenant issuer verification, audience enforcement, clock-drift bounded expiration, and claim extraction.
* **Identity Mapping:** Verified Entra Object ID (`oid`) mapped directly to `dbo.users.entra_object_id` (NVARCHAR(64) UNIQUE). Volatile email addresses are rejected as permanent identity keys.
* **Security & Non-Fabrication:** Zero fake login states or hardcoded secrets. If Entra ID configuration is missing, a descriptive setup guide is displayed while API requests fail closed.

---

## 2. Authentication Architecture & Protocol Flows

### 2.1 Front-Channel & Back-Channel Flow Diagram

```
+----------------------------------------------------------------------------------------------------+
|                                    1. FRONT-CHANNEL (BROWSER)                                       |
|                                                                                                    |
|  [Vanilla JS Frontend]                                                     [Microsoft Entra ID]    |
|         |                                                                           |              |
|         |-- 1. Fetch /api/auth/config (Client ID, Tenant ID, Scope) --------------->|              |
|         |-- 2. Interactive Login Popup with PKCE Code Challenge (S256) ------------->|              |
|         |<-- 3. Authorization Code + PKCE Verifier Returned -------------------------|              |
|         |-- 4. Exchange Auth Code for Access Token --------------------------------->|              |
|         |<-- 5. Signed JWT Access Token Returned (RS256) ----------------------------|              |
+----------------------------------------------------------------------------------------------------+
                                             |
                                  6. Authorization: Bearer <JWT>
                                             v
+----------------------------------------------------------------------------------------------------+
|                                    2. BACK-CHANNEL (AZURE FUNCTIONS)                                |
|                                                                                                    |
|  [GET /api/auth/me] ---> [authMiddleware] ---> [tokenUtils.validateToken]                          |
|                                                       |                                            |
|                                                       +--> Fetch JWKS Keys (RS256)                 |
|                                                       +--> Validate iss, aud, exp, nbf             |
|                                                       +--> Extract claims.oid                      |
|                                                       |                                            |
|                                  [authService.authenticateToken]                                   |
|                                                       |                                            |
|                                           [userRepository]                                         |
|                                                       |                                            |
|                                                       v                                            |
|                                  [Azure SQL / LocalDB: dbo.users]                                  |
|                                       WHERE entra_object_id = @oid                                 |
|                                                       |                                            |
|                                    Found & Active? -> Return User Profile (200 OK)                 |
|                                    Unregistered?   -> Reject ERR_USER_NOT_REGISTERED (401)         |
|                                    Deactivated?    -> Reject ERR_USER_INACTIVE (403)               |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Database Identity Mapping Analysis

### 3.1 Schema Evaluation (`dbo.users`)

An audit of `database/migrations/001_create_core_tables.sql` and `002_add_relationships_and_constraints.sql` confirms that the database foundation natively supports Microsoft Entra ID mapping without schema alteration:

```sql
CREATE TABLE dbo.users (
    user_id             UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
    entra_object_id     NVARCHAR(64)     NOT NULL,
    email               NVARCHAR(256)    NOT NULL,
    first_name          NVARCHAR(64)     NOT NULL,
    last_name           NVARCHAR(64)     NOT NULL,
    display_name        NVARCHAR(128)    NOT NULL,
    user_type           NVARCHAR(30)     NOT NULL, -- 'INTERNAL_EMPLOYEE' | 'CONTRACTOR'
    department          NVARCHAR(100)    NULL,
    is_active           BIT              NOT NULL DEFAULT 1,
    created_at          DATETIMEOFFSET   NOT NULL DEFAULT SYSDATETIMEOFFSET(),
    updated_at          DATETIMEOFFSET   NOT NULL DEFAULT SYSDATETIMEOFFSET(),
    CONSTRAINT PK_users PRIMARY KEY CLUSTERED (user_id ASC),
    CONSTRAINT UQ_users_entra_object_id UNIQUE NONCLUSTERED (entra_object_id ASC),
    CONSTRAINT UQ_users_email UNIQUE NONCLUSTERED (email ASC),
    CONSTRAINT CK_users_user_type CHECK (user_type IN ('INTERNAL_EMPLOYEE', 'CONTRACTOR'))
);
```

### 3.2 Permanent Identity Key Principle
* **Why Not Email?** Email addresses in enterprise tenants change due to corporate acquisitions, name changes, or domain migrations. Binding permissions or leases to email introduces catastrophic identity aliasing and orphaned grants.
* **Entra Object ID (`oid` claim):** The `oid` claim is an immutable GUID assigned by Microsoft Entra ID to a user object upon creation. It never changes throughout the user's entire identity lifecycle in the tenant.
* **AccessLease Mapping:** AccessLease maps `claims.oid -> dbo.users.entra_object_id`. If `oid` is not present (e.g. specialized v1 token formats), `sub` is evaluated as fallback.

---

## 4. Implemented Components & Code Artifacts

| Component | File Path | Purpose |
| :--- | :--- | :--- |
| **Token Verification Utility** | [`backend/src/utils/tokenUtils.js`](file:///d:/access/backend/src/utils/tokenUtils.js) | Decodes JWTs, resolves public signing keys from Microsoft JWKS via `jwks-rsa`, validates `iss`, `aud`, `exp`, `nbf`, and verifies RS256 cryptographic signatures. |
| **User Data Repository** | [`backend/src/repositories/userRepository.js`](file:///d:/access/backend/src/repositories/userRepository.js) | Executes parameterized queries against `dbo.users` and `dbo.user_roles`. |
| **Authentication Service** | [`backend/src/services/authService.js`](file:///d:/access/backend/src/services/authService.js) | Coordinates token verification, maps `oid` to `dbo.users`, checks active status, loads assigned roles, and builds sanitized profile. |
| **Auth Middleware** | [`backend/src/middleware/authMiddleware.js`](file:///d:/access/backend/src/middleware/authMiddleware.js) | Intercepts HTTP requests, extracts `Bearer <token>`, validates via `authService`, injects `req.user`, and returns standardized 401/403 responses. |
| **Authentication Functions** | [`backend/src/functions/auth.js`](file:///d:/access/backend/src/functions/auth.js) | Handles `GET /api/auth/me` (Protected) and `GET /api/auth/config` (Public). |
| **Route Registration** | [`backend/src/index.js`](file:///d:/access/backend/src/index.js) | Registers HTTP triggers in Azure Functions v4 runtime. |
| **Local Server Runner** | [`backend/scripts/start-local.js`](file:///d:/access/backend/scripts/start-local.js) | Emulates Azure Functions v4 locally with CORS and security headers for rapid local testing. |
| **Frontend Auth Module** | [`frontend/assets/js/auth.js`](file:///d:/access/frontend/assets/js/auth.js) | Pure Vanilla JS MSAL Browser controller handling PKCE popup login, silent token renewal, and profile rendering. |
| **Frontend Layout** | [`frontend/index.html`](file:///d:/access/frontend/index.html) | Modern corporate identity card, MSAL CDN script, and configuration notice. |
| **Stylesheet** | [`frontend/assets/css/main.css`](file:///d:/access/frontend/assets/css/main.css) | Responsive CSS styles for login cards, user profiles, role chips, and error banners. |

---

## 5. Automated Verification Results

All 39 unit and integration tests are executed through the native Node.js test runner (`node --test`):

```powershell
npm test
```

### Summary of Passing Test Suites

```
▶ Integration: Authentication Endpoints & Real Database Identity Mapping
  ✔ 1. GET /api/auth/config: should return 200 OK with safe public parameters and zero secrets (1.1ms)
  ✔ 2. GET /api/auth/me: should return HTTP 401 when Authorization header is missing (0.7ms)
  ✔ 3. GET /api/auth/me: should return HTTP 401 when token has expired (6.8ms)
  ✔ 4. GET /api/auth/me: should return HTTP 401 when token is valid but OID is unmapped in dbo.users (23.8ms)
  ✔ 5. GET /api/auth/me: should return HTTP 200 OK and live database record for seeded user (TEST-OID-SPONSOR) (14.7ms)
  ✔ 6. GET /api/auth/me: should return HTTP 200 OK and live contractor record for seeded contractor (TEST-OID-CONTRACTOR) (9.7ms)
✔ Integration: Authentication Endpoints & Real Database Identity Mapping (1051.1ms)

▶ Integration: Real Microsoft SQL Server Connectivity
  ✔ should connect to real Microsoft SQL Server and execute lightweight health query (184.1ms)
  ✔ should query the 15 core governance tables from live sys.tables (46.2ms)
✔ Integration: Real Microsoft SQL Server Connectivity (1158.9ms)

▶ Unit: Microsoft Entra ID Token Verification (tokenUtils)
  ✔ 1. Valid token verification: should successfully verify valid token and extract claims (11.7ms)
  ✔ 2. Invalid signature rejection: should reject token signed by unknown private key (33.1ms)
  ✔ 3. Expired token rejection: should reject expired tokens with ERR_TOKEN_EXPIRED (2.5ms)
  ✔ 4. Wrong audience rejection: should reject token with mismatched audience (2.5ms)
  ✔ 5. Wrong issuer rejection: should reject token with untrusted/foreign issuer (3.1ms)
  ✔ 6. Missing token rejection: should reject null, undefined, or empty token string (0.6ms)
  ✔ 7. Malformed token rejection: should reject malformed or non-JWT string (0.7ms)
  ✔ 8. Missing identity claim rejection: should reject token lacking oid and sub (3.4ms)
  ✔ 9. Unsupported algorithm rejection: should reject unsigned alg=none tokens (0.7ms)
✔ Unit: Microsoft Entra ID Token Verification (tokenUtils) (78.8ms)

▶ Unit: Authentication Middleware (authMiddleware)
  ✔ 1. extractBearerToken: should extract raw token from standard Bearer header (0.9ms)
  ✔ 2. extractBearerToken: should extract from Azure Functions v4 Map headers (0.2ms)
  ✔ 3. Missing Authorization header: should throw UnauthorizedError with ERR_MISSING_AUTH_HEADER (0.7ms)
  ✔ 4. Non-Bearer scheme rejection: should throw ERR_INVALID_AUTH_HEADER for Basic scheme (0.3ms)
  ✔ 5. Empty Bearer token rejection: should throw ERR_INVALID_AUTH_HEADER for standalone "Bearer" (0.3ms)
  ✔ 6. withAuth wrapper: should intercept unauthenticated request and return HTTP 401 with standard envelope (1.3ms)
✔ Unit: Authentication Middleware (authMiddleware) (4.9ms)

▶ Unit: Authentication Service & Identity Mapping (authService)
  ✔ 1. Identity Mapping: should resolve valid Entra OID to internal user profile (6.3ms)
  ✔ 2. Unknown User Rejection: should reject Entra identity not registered in dbo.users (4.4ms)
  ✔ 3. Deactivated User Rejection: should reject deactivated account with ForbiddenError (ERR_USER_INACTIVE) (2.9ms)
  ✔ 4. Zero Secret Leakage: verified profile must not contain internal secrets or database connection data (2.2ms)
✔ Unit: Authentication Service & Identity Mapping (authService) (48.2ms)

▶ Unit: Database Configuration & Driver Options (3 tests passed)
▶ Unit: Environment Configuration (4 tests passed)
▶ Unit: Health API Handlers (2 tests passed)
▶ Unit: Response Formatting (3 tests passed)

Total Tests:  39
Total Suites:  9
Passed:       39 (100%)
Failed:        0
```

---

## 6. Live Entra ID Setup & Configuration Guide

To transition from local test double verification to live Microsoft Entra ID authentication:

### Step 1: Azure App Registration
1. In the **Azure Portal**, navigate to **Microsoft Entra ID > App registrations > New registration**.
2. **Name:** `AccessLease-Governance-App`
3. **Supported account types:** Accounts in this organizational directory only (Single tenant).
4. **Redirect URI:** Select **Single-page application (SPA)** and enter:
   `http://localhost:7071` (or your static web app URL).
5. Under **Expose an API**, set Application ID URI: `api://<client-id>`.
6. Add Scope: `access_as_user` (Admin & User consent).

### Step 2: Environment Configuration
Copy `.env.example` to `backend/.env` and supply your tenant values:

```ini
ENTRA_TENANT_ID=your-actual-tenant-guid
ENTRA_CLIENT_ID=your-actual-client-guid
ENTRA_AUTHORITY=https://login.microsoftonline.com/your-actual-tenant-guid
ENTRA_API_AUDIENCE=api://your-actual-client-guid
ENTRA_API_SCOPE=api://your-actual-client-guid/access_as_user
```

### Step 3: Run the Application
```powershell
npm run start:local
```

Open `http://localhost:7071` in the browser. MSAL Browser will immediately render the interactive **Sign In with Microsoft** button and execute live PKCE authentication against your Entra ID tenant.

---

## 7. Compliance & Integrity Statement

* **No Fake Authentication:** AccessLease does not forge or fabricate mock logins in UI. If Entra ID variables are absent, an explicit setup banner is shown.
* **Zero Secret Commitment:** Client secrets are never embedded in the frontend or returned by `/api/auth/config`.
* **Scope Discipline:** Only Step 03 has been implemented. Application RBAC matrices, contractor CRUD, request workflows, and expiry automation are strictly deferred to future steps.

