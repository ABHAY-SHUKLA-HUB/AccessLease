# AccessLease — Company-Grade Contractor Access & Offboarding Governance

[![Status](https://img.shields.io/badge/Status-STEP%2000%20Initialized-blue.svg)](#)
[![Stack](https://img.shields.io/badge/Stack-Vanilla%20JS%20%7C%20Node.js%20%7C%20Azure%20Functions%20%7C%20Azure%20SQL-informational.svg)](#)
[![Security](https://img.shields.io/badge/Security-Zero%20Secrets%20%7C%20Entra%20ID%20Ready-green.svg)](#)

---

## 1. Project Overview

**AccessLease** is an enterprise-grade contractor access governance and automated lifecycle management platform. Built to meet stringent internal security, regulatory compliance, and corporate audit standards, AccessLease governs how temporary contractors, external consultants, and third-party vendors request, receive, utilize, and forfeit access to critical organizational resources.

---

## 2. Problem Statement

Modern enterprise environments routinely engage third-party contractors and service providers who require temporary access to internal systems, databases, cloud resources, and repositories. However, traditional identity and access management operations suffer from several failure modes:

* **Contractor Sprawl & Orphan Accounts:** After contract expiration or milestone completion, contractor accounts frequently remain active indefinitely due to manual, disjointed offboarding procedures.
* **Lack of Clear Ownership:** Access grants are often issued without a designated, accountable internal business sponsor or resource owner.
* **Absence of Hard Expiration:** Grants are granted without strict, deterministic time boundaries, leading to perpetual access creep.
* **Audit Blindspots:** Compliance teams cannot easily verify whether contractor permissions were reviewed, recertified, or safely revoked.
* **Unverifiable Revocation:** Organizations lack cryptographically verifiable and auditable proof that credentials, group memberships, and resource permissions were terminated at the scheduled second.

---

## 3. Project Objectives

AccessLease enforces a strict **Five-Pillar Governance Model** where every single contractor access entitlement is:

1. **Owned:** Every grant must have an identified internal sponsor and system owner responsible for recertification.
2. **Approved:** Multi-tiered approval workflows require explicit authorization before access can be provisioned.
3. **Time-Bound:** Access leases are issued with fixed validity windows and immutable expiration timestamps.
4. **Reviewable:** Continuous auditing and periodic recertification workflows keep entitlements visible and accountable.
5. **Verifiably Revoked:** Automated deprovisioning workers execute revocation, capture execution proofs, and persist tamper-resistant audit logs in Azure Blob Storage.

---

## 4. Mandatory Technology Stack

| Layer | Technology | Rationale & Governance Rules |
| :--- | :--- | :--- |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript (ES6+) | Strictly no frontend frameworks (React, Angular, Vue, Next.js, etc.) and no TypeScript. Kept in clean, modular, separate `.html`, `.css`, and `.js` files. |
| **Backend** | Node.js, Azure Functions (Serverless) | Modular serverless execution model with clean separation across functions, controllers, middleware, services, and repositories. |
| **Database** | Azure SQL Database | Relational integrity, temporal tables, stored procedures, audit triggers, and ACID compliance for access leases and entitlements. |
| **Storage** | Azure Blob Storage | Secure, immutable storage for revocation proof artifacts, contractor agreement documentation, and exported audit packages. |
| **Authentication** | Microsoft Entra ID (formerly Azure AD) | Enterprise identity provider for single sign-on (SSO), JWT bearer verification, and role-based access control (RBAC). |
| **Analytics & BI** | Microsoft Power BI | Executive compliance dashboards, lease aging reports, expiration heatmaps, and audit metric visualizations. |
| **Cloud Platform** | Microsoft Azure | Enterprise hosting, automated monitoring, secure secret management, and serverless compute infrastructure. |
| **Version Control**| Git & GitHub | Distributed version control with strict commit hygiene and branch protection policies. |

---

## 5. Initial Folder Structure

```text
AccessLease/
├── frontend/
│   ├── assets/
│   │   ├── css/            # Vanilla CSS stylesheets (main.css, modular themes)
│   │   ├── js/             # Vanilla JavaScript modules (ES6+, DOM handlers, API clients)
│   │   └── images/         # Static imagery, icons, and diagrams
│   ├── pages/              # Individual HTML pages for functional views
│   └── index.html          # Application entry point and baseline UI
│
├── backend/
│   ├── src/
│   │   ├── functions/      # Azure Functions HTTP and Timer triggers
│   │   ├── config/         # Environment, database, and auth configuration
│   │   ├── middleware/     # JWT validation, error handling, role authorization
│   │   ├── services/       # Core business logic (lease management, expiration engine)
│   │   ├── repositories/   # Azure SQL data access layer and queries
│   │   └── utils/          # Logging, validation, and cryptographic helpers
│   └── tests/              # Unit, integration, and security tests
│
├── database/
│   ├── schema/             # DDL table creation and schema definitions
│   ├── migrations/         # Sequential database migration scripts
│   ├── seeds/              # Initial seed data (lookup values, system roles)
│   ├── views/              # Reporting and audit query views
│   ├── procedures/         # Stored procedures for atomic lease operations
│   └── triggers/           # Audit triggers and security enforcement rules
│
├── docs/
│   ├── architecture/       # System architecture diagrams and technical RFCs
│   ├── api/                # REST API contract specifications (OpenAPI/Swagger)
│   ├── database/           # Data dictionary, ER diagrams, and normalization docs
│   ├── security/           # Threat models, Entra ID configuration, compliance checks
│   └── testing/            # Test strategies, test plans, and verification reports
│
├── infrastructure/
│   └── azure/              # ARM/Bicep templates and deployment scripts
│
├── .gitignore              # Production-grade git exclusion rules
├── .env.example            # Sanitized environment configuration template
└── README.md               # Master engineering documentation
```

### Architectural Structure Notes:
* The current workspace root serves as the repository root `AccessLease/`.
* Empty folders are preserved in Git using `.gitkeep` placeholders to maintain project skeleton consistency.
* Backend modules strictly separate transport (`functions`), business domain (`services`), and persistence (`repositories`).

---

## 6. Strict Development Rules

1. **No Frontend Frameworks:** No React, Angular, Vue, Svelte, Next.js, or similar frameworks are permitted.
2. **Vanilla JavaScript Only:** No TypeScript on the frontend. Use clean, native browser APIs.
3. **Separation of Concerns:** Keep frontend markup (HTML), presentation (CSS), and behavior (JavaScript) in separate dedicated files.
4. **Modular Backend:** Organize Node.js backend logic into decoupled layers (functions, services, repositories).
5. **Zero Secrets in Code:** Passwords, API keys, client secrets, and connection strings must never be hardcoded or committed to version control.
6. **Environment Variable Configuration:** All operational credentials and target endpoints must be loaded from environment variables (`.env` locally, App Settings in Azure).
7. **Secure Coding Standards:** Implement parameterized SQL queries, strict input validation, authorization checks on all endpoints, and secure HTTP headers.
8. **No Fake Functionality:** Do not produce mock implementations or misleading fake demo data masquerading as functional features.
9. **Requirement Completeness:** Every governance and architectural requirement must be fully addressed.
10. **Disciplined Phase Execution:** Do not jump ahead into subsequent implementation steps until explicitly designated.

---

## 7. Development Prerequisites

To develop, run, and test AccessLease locally, ensure the following tooling is installed on your workstation:

* **Node.js:** v18.x or v20.x+ LTS (Runtime for backend and development tooling)
* **npm:** v9.x or v10.x+ (Package management)
* **Git:** v2.30+ (Version control)
* **Azure Functions Core Tools:** v4.x (`npm install -g azure-functions-core-tools@4 --unsafe-perm true`)
* **Azure CLI:** `az` CLI for managing cloud resources and service principals
* **SQL Server Tools:** Azure Data Studio or SQL Server Management Studio (SSMS) for executing database migrations against Azure SQL
* **Web Browser:** Modern standards-compliant browser (Chrome, Edge, Firefox) with Developer Tools enabled

---

## 8. Local Setup Instructions

### Step 1: Clone the Repository
```bash
git clone <repository-url> AccessLease
cd AccessLease
```

### Step 2: Configure Environment Variables
Copy the template configuration file to create your local development settings:
```bash
cp .env.example .env
```
Populate the placeholder values in `.env` with your development database and Entra ID development tenant identifiers. **Never commit `.env` to Git.**

### Step 3: Serve the Frontend
Because the frontend is built with pure HTML5, CSS3, and Vanilla JavaScript, it requires no build compilation or bundler. Serve the `frontend/` directory using any local static HTTP server (e.g., Live Server in VS Code, Python `http.server`, or Node `serve`):
```bash
# Example using Node.js npx:
npx serve frontend -l 3000

# Or using Python:
python -m http.server 3000 --directory frontend
```
Navigate to `http://localhost:3000` to inspect the frontend entry point.

### Step 4: Backend Initialization (Coming in Subsequent Steps)
Backend dependencies and Azure Functions triggers will be installed and configured in Step 02.

---

## 9. Future Implementation Roadmap

* [x] **STEP 00 — Project Initialization:** Repository setup, architecture layout, baseline UI, `.gitignore`, `.env.example`, and documentation.
* [x] **STEP 01 — Database Design & Schema Migration:** Azure SQL / Microsoft SQL Server 3NF relational schema (15 core tables), constraints, indexes, `v_AccessExposureQueue` view, `sp_ActivateApprovedGrant` procedure, `tr_ContractorGrantMustExpire` set-based trigger, and test suite.
* [x] **STEP 02 — System Architecture & Technical Design:** Comprehensive cloud system architecture, Azure component design, deployment topology, trust boundaries, canonical REST API specification, 12 governance data flows, Zero-Trust security architecture, and design trade-off analysis.
* [ ] **STEP 03 — Identity & Authentication (Entra ID):** Microsoft Entra ID token verification middleware, role assignments, and permission validation.
* [ ] **STEP 04 — Contractor Lifecycle & Automated Expiration Engine:** Time-bound lease scheduling, background timer triggers for automatic deprovisioning, and recertification workflows.
* [ ] **STEP 05 — Cryptographic Revocation Proofs & Azure Blob Storage:** Audit report generation, proof bundle packaging, and upload to Azure Blob Storage.
* [ ] **STEP 06 — Governance Analytics & Power BI Integration:** Real-time metrics, lease aging views, and embedded compliance dashboards.
* [ ] **STEP 07 — Vanilla JS Governance Portal:** Responsive contractor management dashboard, approval queue UI, and audit exploration interface.
* [ ] **STEP 08 — End-to-End Testing, Infrastructure as Code, & Azure Deployment:** Automated tests, Bicep templates, and production deployment pipeline.

