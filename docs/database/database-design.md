# AccessLease — Database Architecture & Design Specification

**Document Version:** 1.0.0  
**Target RDBMS:** Microsoft SQL Server 2019+ / Azure SQL Database  
**Phase:** STEP 01 — Database Design & Schema Migration  
**Author:** Senior Database Architect & Engineering Lead  

---

## 1. Executive Summary & Design Philosophy

AccessLease is an enterprise-grade contractor access and offboarding governance platform. The relational database is the single source of truth for all identity linkages, resource authorizations, time-bound access grants, multi-tiered approval workflows, and immutable audit trails.

The database architecture is engineered according to three foundational pillars:
1. **Mathematical Normalization (3NF):** Eliminates update, insert, and deletion anomalies. No transitive functional dependencies exist on non-prime attributes.
2. **Deterministic Time Governance:** Contractor access is structurally incapable of persisting indefinitely. Hard temporal boundaries, check constraints, and set-based triggers guarantee that access leases are strictly bounded by contractor engagement dates and maximum resource policy limits.
3. **Forensic Auditability:** All state transitions, approvals, revocations, and connector syncs produce immutable, append-only audit records with microsecond-level UTC precision (`DATETIMEOFFSET`).

---

## 2. Normalization Analysis (Third Normal Form — 3NF)

Every relation in the AccessLease schema satisfies 3NF criteria:

### 2.1 First Normal Form (1NF)
* Every column stores atomic, scalar values (no array columns, comma-separated lists, or multi-valued attributes).
* Each table has a designated primary key (`user_id`, `grant_id`, `request_id`, etc.) enforcing row uniqueness.
* JSON payloads in `audit_events` and `provisioning_events` are used exclusively for opaque downstream audit receipts, not for modeling relational domain attributes.

### 2.2 Second Normal Form (2NF)
* All tables are in 1NF.
* In compound primary key tables (`user_roles` with `(user_id, role_id)`, `review_items` with unique `(review_id, grant_id)`), every non-key column is fully functionally dependent on the entire composite key, with zero partial key dependencies.

### 2.3 Third Normal Form (3NF)
* All tables are in 2NF.
* Non-key columns depend directly on the primary key, and only on the primary key (no transitive dependencies $X \rightarrow Y \rightarrow Z$).
  * *Example:* `contractor_engagements` stores the contractor's `sponsor_user_id` (foreign key to `users`). Sponsor attributes (name, email, department) are not duplicated in `contractor_engagements`.
  * *Example:* `access_grants` links to `entitlement_id`, which links to `resource_id`. Resource-level policy attributes (`max_lease_duration_days`, `risk_level`) reside exclusively on `resources`.

---

## 3. The 15 Core Tables

The schema is partitioned into functional governance modules comprising exactly 15 core tables:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                  AccessLease Schema                                    │
├─────────────────────┬──────────────────────┬────────────────────┬──────────────────────┤
│ Identity & Contract │ Catalog & Entitlement│ Workflow & Grants  │ Audit & Verification │
├─────────────────────┼──────────────────────┼────────────────────┼──────────────────────┤
│ 1. users            │ 5. resources         │ 8. access_requests │ 11. provisioning_    │
│ 2. contractor_      │ 6. entitlements      │ 9. approval_steps  │     events           │
│    engagements      │ 7. resource_owners   │ 10. access_grants  │ 12. revocation_jobs  │
│ 3. roles            │                      │                    │ 13. access_reviews   │
│ 4. user_roles       │                      │                    │ 14. review_items     │
│                     │                      │                    │ 15. audit_events     │
└─────────────────────┴──────────────────────┴────────────────────┴──────────────────────┘
```

1. **`users`:** Unified identity principal repository covering internal sponsors, managers, approvers, auditors, and contractors.
2. **`contractor_engagements`:** Binds a contractor user to an external vendor firm, legal contract reference, and internal accountable business sponsor.
3. **`roles`:** Canonical RBAC application roles (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, `RESOURCE_OWNER`, etc.).
4. **`user_roles`:** Junction table for role assignments with assignment audit tracking.
5. **`resources`:** Governed assets (databases, cloud subscriptions, SaaS apps, repositories, VPNs) with risk tiers.
6. **`entitlements`:** Discrete permissions and security scopes tied to a specific resource.
7. **`resource_owners`:** Primary, delegate, and technical contacts designated as accountable approvers for each resource.
8. **`access_requests`:** Formal requests submitted for contractor access detailing dates and justification.
9. **`approval_steps`:** Multi-tiered workflow approval instances (`SPONSOR_APPROVAL`, `RESOURCE_OWNER_APPROVAL`, `SECURITY_APPROVAL`).
10. **`access_grants`:** Central entitlement lease table enforcing time-bound, reviewable, and revocable access grants.
11. **`provisioning_events`:** Integration event log tracking downstream provisioning API calls and connector payloads.
12. **`revocation_jobs`:** Resilient queue managing automated and manual revocation workflows with retry tracking.
13. **`access_reviews`:** Periodic and event-triggered access recertification campaigns.
14. **`review_items`:** Line-item grant attestations assigned to reviewers with decisions (`MAINTAIN`, `REVOKE`).
15. **`audit_events`:** Append-only, tamper-resistant audit trail capturing every lifecycle operation across the system.

---

## 4. Critical Business Rule Enforcement Matrix

| Rule Code | Business Requirement | Database Enforcement Mechanism | Application / API Layer Role |
| :--- | :--- | :--- | :--- |
| **Rule A** | Contractor access must always be time-bound. | `access_grants.expires_at` is `NOT NULL`. Constraint `CK_access_grants_dates` (`expires_at > granted_at`). | UI prevents submission without valid date picker values. |
| **Rule B** | Access expiry must never exceed engagement end date. | Set-based trigger `tr_ContractorGrantMustExpire` rolls back any transaction violating this bound. Also enforced by `sp_ActivateApprovedGrant`. | Validation during request submission; visual date constraints in portal. |
| **Rule C** | Permanent contractor access is strictly prohibited. | `CK_access_grants_dates` and `tr_ContractorGrantMustExpire` reject null or infinite expirations. | API rejects null expiration timestamps. |
| **Rule D** | Access must not be granted before all required approvals complete. | Stored procedure `sp_ActivateApprovedGrant` verifies all steps in `approval_steps` are `APPROVED` before inserting grant. | Approval orchestration worker blocks grant activation until approval gate closes. |
| **Rule E** | High-risk access requires additional Security approval. | `sp_ActivateApprovedGrant` checks `requires_security_approval = 1` and verifies `SECURITY_APPROVAL` step is `APPROVED`. | Workflow engine injects `SECURITY_APPROVAL` step upon request creation. |
| **Rule F** | Revocation is complete only after downstream connector confirmation. | `revocation_jobs.status` remains `QUEUED` or `IN_PROGRESS` until connector returns confirmation, updating status to `CONFIRMED`. | Revocation worker polls connector or listens to webhook callback before finalizing job. |
| **Rule G** | Failed revocation keeps grant in `REVOKE_PENDING`. | `access_grants.status` transitions to `REVOKE_PENDING` upon revocation trigger and cannot transition to `REVOKED` until confirmed. | Retry scheduler retries failed revocation jobs up to `max_retries`. |
| **Rule H** | Preserve audit history for important access lifecycle events. | `audit_events` table with immutable rows, indexed by timestamp and entity. Stored procedure automatically writes audit entries. | Background timer engines and API controllers write structured audit payloads. |
| **Rule I** | Prevent invalid, duplicate or contradictory access grants. | Filtered Unique Index `UQ_access_grants_active_contractor_entitlement` on `(contractor_engagement_id, entitlement_id)` WHERE `status IN ('ACTIVE', 'PROVISIONING_PENDING')`. | Pre-submission check in API returns user-friendly conflict message. |

---

## 5. Storage & Precision Decisions

* **Timestamps:** All temporal attributes use `DATETIMEOFFSET` stored via `SYSDATETIMEOFFSET()`. This eliminates timezone ambiguity, preserves daylight saving offset context (+00:00 UTC), and supports global multi-region deployments.
* **Identifiers:** Primary keys utilize `UNIQUEIDENTIFIER` with `DEFAULT NEWSEQUENTIALID()`. This minimizes index page fragmentation in clustered B-trees while preserving globally unique, non-enumerable GUIDs compatible with Microsoft Entra ID object identifiers.
* **Audit Identifiers:** `audit_events.event_id` utilizes `BIGINT IDENTITY(1,1)` to guarantee monotonically increasing sequence order for high-throughput temporal log ingestion.
