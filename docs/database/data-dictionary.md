# AccessLease — Complete Data Dictionary

**Target RDBMS:** Microsoft SQL Server 2019+ / Azure SQL Database  
**Phase:** STEP 01 — Database Design & Schema Migration  
**Standard Schema:** `dbo`

---

## Table of Contents
1. [users](#1-table-users)
2. [contractor_engagements](#2-table-contractor_engagements)
3. [roles](#3-table-roles)
4. [user_roles](#4-table-user_roles)
5. [resources](#5-table-resources)
6. [entitlements](#6-table-entitlements)
7. [resource_owners](#7-table-resource_owners)
8. [access_requests](#8-table-access_requests)
9. [approval_steps](#9-table-approval_steps)
10. [access_grants](#10-table-access_grants)
11. [provisioning_events](#11-table-provisioning_events)
12. [revocation_jobs](#12-table-revocation_jobs)
13. [access_reviews](#13-table-access_reviews)
14. [review_items](#14-table-review_items)
15. [audit_events](#15-table-audit_events)

---

### 1. Table: `users`
**Purpose:** Master identity principal record for internal employees and external contractors.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `user_id` | `UNIQUEIDENTIFIER` | NO | `NEWSEQUENTIALID()` | `PK_users` | Primary key UUID for the user identity |
| `entra_object_id` | `NVARCHAR(64)` | NO | None | `UQ_users_entra_object_id` | Microsoft Entra ID (Azure AD) Object ID (`oid`) |
| `email` | `NVARCHAR(256)` | NO | None | `UQ_users_email` | Corporate or external contractor email address |
| `first_name` | `NVARCHAR(64)` | NO | None | None | First name |
| `last_name` | `NVARCHAR(64)` | NO | None | None | Last name |
| `display_name` | `NVARCHAR(128)` | NO | None | None | Full formatted display name |
| `user_type` | `NVARCHAR(30)` | NO | None | `CK_users_user_type` | Identity type: `'INTERNAL_EMPLOYEE'`, `'CONTRACTOR'` |
| `department` | `NVARCHAR(100)` | YES | None | None | Corporate organizational department |
| `is_active` | `BIT` | NO | `1` | None | Operational flag indicating active directory status |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Record creation timestamp in UTC |
| `updated_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Last record modification timestamp in UTC |

---

### 2. Table: `contractor_engagements`
**Purpose:** Governs the contract period, vendor affiliation, and accountable sponsor for each contractor.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `engagement_id` | `UNIQUEIDENTIFIER` | NO | `NEWSEQUENTIALID()` | `PK_contractor_engagements` | Primary key UUID for the engagement |
| `contractor_user_id`| `UNIQUEIDENTIFIER` | NO | None | `FK_contractor_engagements_contractor` | Foreign key referencing `users(user_id)` |
| `sponsor_user_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_contractor_engagements_sponsor` | Foreign key referencing accountable internal employee |
| `vendor_name` | `NVARCHAR(150)` | NO | None | None | Third-party vendor or staffing agency name |
| `contract_reference`| `NVARCHAR(100)` | NO | None | `UQ_contractor_contract_ref` (composite) | SOW, Purchase Order, or Master Services Agreement ref |
| `start_date` | `DATE` | NO | None | None | Legal commencement date of contractor engagement |
| `end_date` | `DATE` | NO | None | `CK_contractor_engagements_dates` | Hard expiration date of engagement (`>= start_date`) |
| `status` | `NVARCHAR(30)` | NO | `'ACTIVE'` | `CK_contractor_engagements_status` | Status: `'PENDING'`, `'ACTIVE'`, `'COMPLETED'`, `'TERMINATED'` |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Record creation timestamp in UTC |
| `updated_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Record modification timestamp in UTC |

---

### 3. Table: `roles`
**Purpose:** Canonical catalog of internal RBAC roles governing permissions within AccessLease.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `role_id` | `INT` | NO | `IDENTITY(1,1)` | `PK_roles` | Surrogate primary key for role |
| `role_code` | `NVARCHAR(50)` | NO | None | `UQ_roles_role_code` | Unique role identifier (e.g. `'SYSTEM_ADMIN'`) |
| `role_name` | `NVARCHAR(100)` | NO | None | None | Human-readable role title |
| `description` | `NVARCHAR(256)` | YES | None | None | Functional description of role responsibilities |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Record creation timestamp in UTC |

---

### 4. Table: `user_roles`
**Purpose:** Junction table mapping users to RBAC roles with assignment audit attribution.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `user_id` | `UNIQUEIDENTIFIER` | NO | None | `PK_user_roles`, `FK_user_roles_user` | User receiving role assignment |
| `role_id` | `INT` | NO | None | `PK_user_roles`, `FK_user_roles_role` | Role granted to user |
| `assigned_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Timestamp when role was assigned |
| `assigned_by_user_id`| `UNIQUEIDENTIFIER`| YES | None | `FK_user_roles_assigned_by` | User identity who granted the role |

---

### 5. Table: `resources`
**Purpose:** Catalog of systems, cloud subscriptions, repositories, and applications governed by AccessLease.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `resource_id` | `UNIQUEIDENTIFIER` | NO | `NEWSEQUENTIALID()` | `PK_resources` | Unique resource UUID |
| `resource_code` | `NVARCHAR(50)` | NO | None | `UQ_resources_code` | Business resource mnemonic (e.g. `'RES-SQL-PROD'`) |
| `resource_name` | `NVARCHAR(150)` | NO | None | None | Descriptive name of resource |
| `resource_type` | `NVARCHAR(50)` | NO | None | `CK_resources_type` | Type: `'SAAS'`, `'CLOUD_SUBSCRIPTION'`, `'DATABASE'`, etc. |
| `description` | `NVARCHAR(500)` | YES | None | None | Purpose and scope of target resource |
| `risk_level` | `NVARCHAR(20)` | NO | `'MEDIUM'` | `CK_resources_risk_level` | Criticality: `'LOW'`, `'MEDIUM'`, `'HIGH'`, `'CRITICAL'` |
| `requires_security_approval`| `BIT` | NO | `0` | None | Flag requiring explicit Security Officer signoff |
| `max_lease_duration_days` | `INT` | NO | `90` | `CK_resources_max_duration` | Hard policy cap on lease duration (1 to 365 days) |
| `is_active` | `BIT` | NO | `1` | None | Operational availability flag |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Creation timestamp in UTC |
| `updated_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Modification timestamp in UTC |

---

### 6. Table: `entitlements`
**Purpose:** Fine-grained permissions, roles, or group scopes within a specific resource.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `entitlement_id` | `UNIQUEIDENTIFIER` | NO | `NEWSEQUENTIALID()` | `PK_entitlements` | Unique entitlement UUID |
| `resource_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_entitlements_resource` | Foreign key referencing parent resource |
| `entitlement_code`| `NVARCHAR(50)` | NO | None | `UQ_entitlements_resource_code` (composite) | Short permission code (e.g. `'READ_ONLY'`, `'DBA'`) |
| `entitlement_name`| `NVARCHAR(150)` | NO | None | None | Descriptive name of entitlement |
| `description` | `NVARCHAR(500)` | YES | None | None | Scope of permission granted |
| `sensitivity_level`| `NVARCHAR(20)`| NO | `'MEDIUM'` | `CK_entitlements_sensitivity` | Sensitivity tier: `'LOW'`, `'MEDIUM'`, `'HIGH'`, `'CRITICAL'` |
| `is_active` | `BIT` | NO | `1` | None | Operational status of entitlement |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Creation timestamp in UTC |
| `updated_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Modification timestamp in UTC |

---

### 7. Table: `resource_owners`
**Purpose:** Accountable business and technical owners designated to review and approve access for a resource.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `resource_owner_id`| `UNIQUEIDENTIFIER`| NO | `NEWSEQUENTIALID()` | `PK_resource_owners` | Surrogate primary key |
| `resource_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_resource_owners_resource` | Governed resource |
| `owner_user_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_resource_owners_user` | Designated employee owner |
| `ownership_type` | `NVARCHAR(30)` | NO | `'PRIMARY'` | `CK_resource_owners_type`, `UQ_resource_owners` | Type: `'PRIMARY'`, `'DELEGATE'`, `'TECHNICAL_CONTACT'` |
| `assigned_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Ownership assignment timestamp |

---

### 8. Table: `access_requests`
**Purpose:** Formal submission record for contractor access containing justification and requested dates.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `request_id` | `UNIQUEIDENTIFIER` | NO | `NEWSEQUENTIALID()` | `PK_access_requests` | Unique request UUID |
| `request_number` | `NVARCHAR(30)` | NO | None | `UQ_access_requests_number` | Human-friendly reference (e.g. `'AR-2026-00001'`) |
| `contractor_engagement_id`| `UNIQUEIDENTIFIER`| NO | None | `FK_access_requests_engagement` | Target contractor engagement |
| `requested_by_user_id` | `UNIQUEIDENTIFIER`| NO | None | `FK_access_requests_requested_by` | Internal user who submitted the request |
| `resource_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_access_requests_resource` | Target resource requested |
| `entitlement_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_access_requests_entitlement` | Target entitlement requested |
| `requested_start_date`| `DATETIMEOFFSET` | NO | None | None | Requested commencement timestamp |
| `requested_end_date` | `DATETIMEOFFSET` | NO | None | `CK_access_requests_dates` | Requested termination timestamp (`> start_date`) |
| `business_justification`| `NVARCHAR(1000)`| NO | None | None | Documented business need for access |
| `status` | `NVARCHAR(30)` | NO | `'SUBMITTED'` | `CK_access_requests_status` | Status: `'SUBMITTED'`, `'PENDING_APPROVAL'`, `'APPROVED'`, `'REJECTED'`, `'CANCELLED'` |
| `requires_security_approval`| `BIT` | NO | `0` | None | Flag requiring Security signoff |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Submission timestamp in UTC |
| `updated_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Last update timestamp in UTC |

---

### 9. Table: `approval_steps`
**Purpose:** Workflow step instances tracking multi-stage approvals for an access request.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `approval_step_id`| `UNIQUEIDENTIFIER`| NO | `NEWSEQUENTIALID()` | `PK_approval_steps` | Unique step UUID |
| `request_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_approval_steps_request`, `UQ_approval_steps_req_step` | Associated access request |
| `step_number` | `INT` | NO | None | `UQ_approval_steps_req_step` (composite) | Sequential step index (1, 2, 3) |
| `step_type` | `NVARCHAR(50)` | NO | None | `CK_approval_steps_type` | Type: `'SPONSOR_APPROVAL'`, `'RESOURCE_OWNER_APPROVAL'`, `'SECURITY_APPROVAL'` |
| `assigned_approver_user_id`| `UNIQUEIDENTIFIER`| NO | None | `FK_approval_steps_approver` | Designated approver user |
| `status` | `NVARCHAR(30)` | NO | `'PENDING'` | `CK_approval_steps_status` | Step state: `'PENDING'`, `'APPROVED'`, `'REJECTED'`, `'SKIPPED'` |
| `decision_comments`| `NVARCHAR(1000)`| YES | None | None | Approver rationale or rejection notes |
| `decided_at` | `DATETIMEOFFSET` | YES | None | None | Timestamp when approver rendered decision |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Step creation timestamp in UTC |

---

### 10. Table: `access_grants`
**Purpose:** Central entitlement lease record governing active, expired, or revoked access.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `grant_id` | `UNIQUEIDENTIFIER` | NO | `NEWSEQUENTIALID()` | `PK_access_grants` | Unique access grant UUID |
| `grant_number` | `NVARCHAR(30)` | NO | None | `UQ_access_grants_number` | Human-friendly grant code (e.g. `'AG-2026-00001'`) |
| `request_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_access_grants_request` | Authorizing access request |
| `contractor_engagement_id`| `UNIQUEIDENTIFIER`| NO | None | `FK_access_grants_engagement`, `UQ_access_grants_active_contractor_entitlement` | Target contractor engagement |
| `resource_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_access_grants_resource` | Target resource |
| `entitlement_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_access_grants_entitlement`, `UQ_access_grants_active_contractor_entitlement` | Target entitlement |
| `granted_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Active lease commencement timestamp |
| `expires_at` | `DATETIMEOFFSET` | NO | None | `CK_access_grants_dates`, `tr_ContractorGrantMustExpire` | Hard lease termination timestamp |
| `status` | `NVARCHAR(30)` | NO | `'ACTIVE'` | `CK_access_grants_status` | Lifecycle status: `'PROVISIONING_PENDING'`, `'ACTIVE'`, `'REVOKE_PENDING'`, `'REVOKED'`, `'EXPIRED'` |
| `revoked_at` | `DATETIMEOFFSET` | YES | None | None | Timestamp when access was verifiably terminated |
| `revocation_reason`| `NVARCHAR(500)`| YES | None | None | Rationale for deprovisioning |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Record creation timestamp in UTC |
| `updated_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Last modification timestamp in UTC |

---

### 11. Table: `provisioning_events`
**Purpose:** Log of automated provisioning connector actions executed against target platforms.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `event_id` | `UNIQUEIDENTIFIER` | NO | `NEWSEQUENTIALID()` | `PK_provisioning_events` | Unique event UUID |
| `grant_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_provisioning_events_grant` | Associated access grant |
| `event_type` | `NVARCHAR(50)` | NO | None | `CK_provisioning_events_type` | Event: `'PROVISION_REQUESTED'`, `'PROVISION_SUCCEEDED'`, `'PROVISION_FAILED'` |
| `connector_name` | `NVARCHAR(100)` | NO | None | None | Connector identifier (e.g. `'AZURE_ENTRA_ID'`) |
| `payload` | `NVARCHAR(MAX)` | YES | None | None | JSON payload receipt from downstream system |
| `status_code` | `NVARCHAR(50)` | YES | None | None | HTTP or connector exit response code |
| `error_message` | `NVARCHAR(MAX)` | YES | None | None | Detailed error trace if provisioning failed |
| `executed_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Execution timestamp in UTC |

---

### 12. Table: `revocation_jobs`
**Purpose:** Resilient queue managing automated deprovisioning jobs, confirmations, and cryptographic proofs.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `job_id` | `UNIQUEIDENTIFIER` | NO | `NEWSEQUENTIALID()` | `PK_revocation_jobs` | Unique job UUID |
| `grant_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_revocation_jobs_grant` | Associated access grant to revoke |
| `trigger_source` | `NVARCHAR(50)` | NO | None | `CK_revocation_jobs_trigger` | Source: `'SCHEDULED_EXPIRATION'`, `'ENGAGEMENT_TERMINATION'`, `'REVIEW_REJECTION'`, etc. |
| `status` | `NVARCHAR(30)` | NO | `'QUEUED'` | `CK_revocation_jobs_status` | Status: `'QUEUED'`, `'IN_PROGRESS'`, `'FAILED_RETRY'`, `'CONFIRMED'` |
| `retry_count` | `INT` | NO | `0` | None | Current count of attempted execution retries |
| `max_retries` | `INT` | NO | `5` | None | Maximum allowed retries before alerting |
| `connector_name` | `NVARCHAR(100)` | NO | None | None | Downstream target connector |
| `connector_response`| `NVARCHAR(MAX)`| YES | None | None | Receipt payload returned by connector |
| `error_details` | `NVARCHAR(MAX)` | YES | None | None | Exception details on failed attempts |
| `cryptographic_proof_hash`| `NVARCHAR(64)`| YES| None| None | SHA-256 verification hash of receipt bundle |
| `proof_blob_url` | `NVARCHAR(2048)`| YES | None | None | Azure Blob Storage URI for proof receipt |
| `confirmed_at` | `DATETIMEOFFSET` | YES | None | None | Timestamp when revocation was confirmed |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Job enqueue timestamp in UTC |
| `updated_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Job state modification timestamp in UTC |

---

### 13. Table: `access_reviews`
**Purpose:** Header record for periodic or event-triggered contractor access recertification campaigns.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `review_id` | `UNIQUEIDENTIFIER` | NO | `NEWSEQUENTIALID()` | `PK_access_reviews` | Unique campaign UUID |
| `review_name` | `NVARCHAR(150)` | NO | None | None | Title of recertification campaign |
| `description` | `NVARCHAR(500)` | YES | None | None | Scope and compliance objective |
| `campaign_type` | `NVARCHAR(50)` | NO | `'PERIODIC_RECERTIFICATION'` | `CK_access_reviews_campaign` | Type: `'PERIODIC_RECERTIFICATION'`, `'TRIGGERED_OFFBOARDING'`, `'SECURITY_AUDIT'` |
| `start_date` | `DATETIMEOFFSET` | NO | None | None | Campaign commencement timestamp |
| `due_date` | `DATETIMEOFFSET` | NO | None | `CK_access_reviews_dates` | Regulatory compliance completion deadline |
| `status` | `NVARCHAR(30)` | NO | `'ACTIVE'` | `CK_access_reviews_status` | Status: `'DRAFT'`, `'ACTIVE'`, `'COMPLETED'`, `'EXPIRED'` |
| `initiated_by_user_id`| `UNIQUEIDENTIFIER`| NO | None | `FK_access_reviews_initiator` | Compliance officer or admin who launched review |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Creation timestamp in UTC |
| `updated_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Modification timestamp in UTC |

---

### 14. Table: `review_items`
**Purpose:** Individual grant line-item evaluations within an access recertification campaign.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `review_item_id` | `UNIQUEIDENTIFIER` | NO | `NEWSEQUENTIALID()` | `PK_review_items` | Unique line-item UUID |
| `review_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_review_items_review`, `UQ_review_items_review_grant` | Associated review campaign |
| `grant_id` | `UNIQUEIDENTIFIER` | NO | None | `FK_review_items_grant`, `UQ_review_items_review_grant` | Specific access grant under review |
| `reviewer_user_id`| `UNIQUEIDENTIFIER`| NO | None | `FK_review_items_reviewer` | Accountable manager or resource owner |
| `decision` | `NVARCHAR(30)` | NO | `'PENDING'` | `CK_review_items_decision` | Attestation: `'PENDING'`, `'MAINTAIN'`, `'REVOKE'` |
| `decision_notes` | `NVARCHAR(1000)`| YES | None | None | Justification for recertification or revocation |
| `decided_at` | `DATETIMEOFFSET` | YES | None | None | Timestamp when decision was recorded |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Creation timestamp in UTC |

---

### 15. Table: `audit_events`
**Purpose:** Immutable, append-only security and governance audit trail capturing all system operations.

| Column | Data Type | Nullable | Default | Constraints & Keys | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `event_id` | `BIGINT` | NO | `IDENTITY(1,1)` | `PK_audit_events` | Monotonically increasing 64-bit integer ID |
| `event_category` | `NVARCHAR(50)` | NO | None | `CK_audit_events_category` | Category: `'ACCESS_REQUEST'`, `'APPROVAL'`, `'GRANT'`, `'REVOCATION'`, etc. |
| `event_action` | `NVARCHAR(100)` | NO | None | None | Action: `'GRANT_ACTIVATED'`, `'STEP_APPROVED'`, etc. |
| `entity_type` | `NVARCHAR(50)` | NO | None | None | Affected entity table name |
| `entity_id` | `NVARCHAR(64)` | NO | None | None | String representation of affected entity primary key |
| `actor_user_id` | `UNIQUEIDENTIFIER` | YES | None | `FK_audit_events_actor` | User who initiated action (`NULL` for automated system) |
| `actor_type` | `NVARCHAR(30)` | NO | `'USER'` | `CK_audit_events_actor_type` | Actor type: `'USER'`, `'SYSTEM_TIMER'`, `'CONNECTOR_CALLBACK'` |
| `event_payload` | `NVARCHAR(MAX)` | NO | None | None | Structured JSON capture of before/after state or event parameters |
| `ip_address` | `VARCHAR(45)` | YES | None | None | Client IPv4 or IPv6 address |
| `created_at` | `DATETIMEOFFSET` | NO | `SYSDATETIMEOFFSET()` | None | Event occurrence timestamp in UTC |
