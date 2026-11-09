# AccessLease — Architectural Design Decisions & Trade-Off Analysis

**Document Version:** 1.0.0  
**Phase:** STEP 02 — System Architecture & Technical Design  
**Author:** Senior Solution Architect & Cloud Architect  
**Classification:** Enterprise Engineering Specification  

---

## 1. Overview

Every enterprise architectural choice involves trade-offs between speed, cost, complexity, maintainability, compliance, and security. This document details the architectural decisions and evaluations that justify the technology stack of AccessLease.

---

## 2. Decision Matrix Summary

| Decision Area | Selected Approach | Alternative Evaluated | Primary Decision Drivers |
| :--- | :--- | :--- | :--- |
| **Frontend Architecture** | **HTML5 / CSS3 / Vanilla JS** | React, Angular, Vue, Next.js | Zero framework supply chain risk, zero build complexity, long-term longevity, strict compliance. |
| **Backend Compute** | **Azure Functions (Serverless)** | Continuously running VMs / Containers | Event-driven scaling, zero idle cost, native Azure timer triggers, automatic scaling under peak load. |
| **Data Persistence** | **Azure SQL Database (3NF)** | NoSQL (Azure Cosmos DB, MongoDB) | Strict relational integrity, foreign key cascading, set-based triggers, ACID transaction compliance. |
| **Document & Proof Store** | **Azure Blob Storage** | Storing binary payloads directly in SQL | Low-cost tiering, immutable WORM policies, SQL database page bloat prevention. |
| **Identity & Authentication** | **Microsoft Entra ID** | Custom user database & JWT generator | Enterprise SSO, automated MFA, zero password liability, SOC2/ISO compliance alignment. |
| **Workflow Orchestration** | **Azure Logic Apps** | Coding all notification/escalation in API | Visual workflow auditing, native Teams/Outlook integration, resilience against mail server timeouts. |

---

## 3. Deep-Dive Trade-Off Analysis

### 3.1 Frontend: HTML5 / CSS3 / Vanilla JS vs. Modern Frontend Frameworks

#### Selected Approach: HTML5, CSS3, and Vanilla JavaScript (ES6+)
* **Advantages:**
  * **Zero Build Pipeline Dependencies:** Native browser execution eliminates massive `node_modules` trees, Webpack/Vite bundler maintenance, Babel polyfills, and breaking framework updates.
  * **Immunity to Supply Chain Vulnerabilities:** Eliminates dependencies on dozens of nested npm packages that frequently introduce critical security vulnerabilities (CVEs).
  * **Exceptional Performance & Instant Load:** Lightweight static assets ($\approx 50\text{ KB}$ total bundle size) load instantly on edge networks without framework hydration delays.
  * **Decade-Long Longevity:** Pure web standards (HTML5/CSS3/DOM APIs) remain backward-compatible across browser generations for decades.
* **Limitations:**
  * Requires discipline to organize state and DOM updates without JSX or two-way data-binding.
  * Reusable UI components require custom vanilla JavaScript rendering patterns.
* **Why Selected for AccessLease:**
  AccessLease is a critical enterprise governance application. Prioritizing zero dependency risk, pure auditability, and absolute stability over developer-convenience frameworks aligns directly with enterprise security governance.

---

### 3.2 Compute: Azure Functions vs. Continuously Running Application Servers

#### Selected Approach: Azure Functions (Serverless Node.js v4)
* **Advantages:**
  * **Consumption Economics:** Scales down to zero during nights and weekends; organizations pay exclusively per millisecond of actual execution.
  * **Native Event-Driven Scheduling:** Timer triggers natively drive the 5-minute lease expiration sweeps and daily orphan scans without dedicated cron infrastructure.
  * **Frictionless Azure Integration:** Out-of-the-box Managed Identity integration with Key Vault and private virtual networks.
* **Limitations:**
  * Cold start latency on consumption plans (mitigated by configuring Azure Functions Flex Consumption or min-instances).
  * Maximum execution time limit (default 10 minutes on consumption; sufficient since all requests execute in $< 500\text{ ms}$).
* **Why Selected for AccessLease:**
  AccessLease traffic is bursty: spikes occur during morning logins, contract onboarding, and quarterly recertifications, interspersed with idle periods. Serverless architecture provides cost efficiency and eliminates server OS patching.

---

### 3.3 Persistence: Azure SQL Database (3NF) vs. NoSQL Document Stores

#### Selected Approach: Azure SQL Database (Relational 3NF with Stored Procedures & Triggers)
* **Advantages:**
  * **ACID Transactions:** Grant activation requires multi-table atomic operations (validating requests, verifying approvals, writing active grants, and emitting audit logs) that must strictly succeed or fail together.
  * **Database-Level Integrity Constraints:** Critical governance rules (e.g. `tr_ContractorGrantMustExpire` and filtered unique indexes) are enforced at the database engine level, making it physically impossible for buggy application code to create an unexpired contractor grant.
  * **Complex Relational Views:** The governance view `v_AccessExposureQueue` joins 6 relational tables with complex time mathematics, which is difficult and expensive to maintain in NoSQL document stores.
* **Limitations:**
  * Horizontal partitioning requires deliberate sharding compared to native distributed NoSQL.
* **Why Selected for AccessLease:**
  Access governance is fundamentally relational and requires non-negotiable relational integrity. Storing entitlements across unlinked NoSQL documents risks data inconsistency and orphan grants.

---

### 3.4 Storage: Azure Blob Storage vs. Storing Binary Files in SQL Server

#### Selected Approach: Azure Blob Storage for Revocation Proofs and Documents
* **Advantages:**
  * **Database Performance Protection:** Storing large JSON payloads and PDF contracts directly in SQL `VARBINARY(MAX)` causes database buffer pool thrashing, index fragmentation, and massive backup file bloat.
  * **Cost Efficiency:** Blob storage costs a fraction of premium Azure SQL vCore storage per gigabyte.
  * **WORM & Compliance Immutability:** Azure Blob Storage supports legal hold and Write-Once-Read-Many (WORM) time-based retention policies, cryptographically preventing deletion or tampering.
* **Limitations:**
  * Requires managing references between SQL rows (`proof_blob_url`) and Blob URIs.
* **Why Selected for AccessLease:**
  Storing only the SHA-256 cryptographic hash and Blob URI in Azure SQL while delegating raw JSON receipts to Blob Storage provides optimal query speed and regulatory non-repudiation.

---

### 3.5 Identity: Microsoft Entra ID vs. Custom Database Authentication

#### Selected Approach: Microsoft Entra ID (OAuth 2.0 / OpenID Connect)
* **Advantages:**
  * **Zero Password Liability:** The database never stores password hashes or salt keys, eliminating credential breach liabilities.
  * **Enterprise SSO & MFA:** Leverages existing corporate tenant infrastructure, device compliance checks, and hardware token MFA.
  * **Centralized Deprovisioning:** When an employee or contractor is terminated in Entra ID, access to AccessLease is cut off automatically across all devices.
* **Limitations:**
  * Requires an active Microsoft Azure tenant.
* **Why Selected for AccessLease:**
  Corporate enterprises require seamless single sign-on with Azure AD/Entra ID. Building custom user authentication for an enterprise governance application would violate compliance standards.

---

### 3.6 Orchestration: Azure Logic Apps vs. Hardcoding Workflows in the API

#### Selected Approach: Azure Logic Apps for Multi-Stage Approval Notifications & Escalations
* **Advantages:**
  * **Pre-Built Enterprise Connectors:** Native support for Microsoft Teams Actionable Cards, Outlook interactive emails, and SMS alerts.
  * **Visual Process Auditing:** Compliance officers and auditors can visually inspect running workflow instances, delivery receipts, and step delays without grepping code logs.
  * **Resilience Against External Timeouts:** If an email server is temporarily down, Logic Apps handles retries automatically without hanging API threads.
* **Limitations:**
  * Minor execution cost per action execution.
* **Why Selected for AccessLease:**
  Decoupling notification and escalation orchestration from core transactional grant processing prevents external communication delays from slowing down database operations.
