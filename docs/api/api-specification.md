# AccessLease — Canonical REST API Specification

**API Version:** `v1`  
**Base URL:** `https://{host}/api/v1`  
**Protocol:** HTTPS / TLS 1.3  
**Authentication:** HTTP Authorization Header with Bearer JWT (`Authorization: Bearer <token>`)  
**Format:** JSON (`Content-Type: application/json; charset=utf-8`)  
**Phase:** STEP 02 — System Architecture & Technical Design  
**Author:** Senior Solution Architect & Cloud Architect  

---

## 1. Global Conventions & Protocols

### 1.1 Standard Response Envelope
All API endpoints return JSON conforming to a standardized response wrapper:

#### Success Envelope (`200 OK`, `201 Created`, `202 Accepted`)
```json
{
  "success": true,
  "data": {},
  "meta": {
    "correlation_id": "c7a8b9d0-1234-5678-9abc-def012345678",
    "timestamp": "2026-11-09T21:30:00.000Z",
    "page": 1,
    "page_size": 50,
    "total_count": 150
  }
}
```

#### Error Envelope (`4xx Client Error`, `5xx Server Error`)
```json
{
  "success": false,
  "error": {
    "code": "ERR_VALIDATION_FAILED",
    "message": "The access expiry timestamp cannot exceed the contractor engagement end date.",
    "details": [
      {
        "field": "requested_end_date",
        "issue": "Requested end date '2027-01-01' exceeds engagement end date '2026-12-31'."
      }
    ]
  },
  "meta": {
    "correlation_id": "c7a8b9d0-1234-5678-9abc-def012345678",
    "timestamp": "2026-11-09T21:30:00.000Z"
  }
}
```

### 1.2 Standard HTTP Status Codes
* `200 OK`: Request succeeded; returned resource representation.
* `201 Created`: Resource successfully created (includes `Location` header).
* `202 Accepted`: Asynchronous task successfully queued (e.g., revocation job).
* `400 Bad Request`: Malformed JSON or failed structural validation.
* `401 Unauthorized`: Missing, expired, or cryptographically invalid Bearer JWT.
* `403 Forbidden`: Authenticated identity lacks required RBAC role.
* `404 Not Found`: Target entity identifier does not exist.
* `409 Conflict`: Conflict with current state (e.g., duplicate active grant).
* `422 Unprocessable Entity`: Semantic business rule violation (e.g. lease exceeds policy cap).
* `500 Internal Server Error`: Unhandled server exception.

---

## 2. API Endpoints Catalogue

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 API Endpoints Summary                                  │
├─────────────────────┬──────────────────────┬────────────────────┬──────────────────────┤
│ Identity & Profile  │ Catalogues           │ Requests & Grants  │ Governance & Ops     │
├─────────────────────┼──────────────────────┼────────────────────┼──────────────────────┤
│ GET /auth/me        │ GET /resources       │ POST /requests     │ GET /exposure-queue  │
│ GET /users          │ POST /resources      │ GET /requests      │ POST /offboard       │
│ POST /engagements   │ GET /entitlements    │ GET /approvals     │ POST /reviews        │
│ GET /engagements    │ GET /resource-owners │ POST /approvals    │ GET /audit-events    │
│                     │                      │ POST /grants/act   │ GET /analytics       │
└─────────────────────┴──────────────────────┴────────────────────┴──────────────────────┘
```

---

### 2.1 Identity & Profile Endpoints

#### `GET /auth/me`
* **Purpose:** Returns the authenticated user's profile, tenant attributes, and assigned AccessLease application roles.
* **Required Role:** Any valid authenticated user (`INTERNAL_EMPLOYEE` or `CONTRACTOR`).
* **Request Body:** None.
* **Response Structure (`200 OK`):**
  ```json
  {
    "user_id": "b1a2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "entra_object_id": "00000000-0000-0000-0000-000000000000",
    "email": "sarah.sponsor@company.com",
    "display_name": "Sarah Sponsor",
    "user_type": "INTERNAL_EMPLOYEE",
    "department": "Engineering Operations",
    "roles": ["INTERNAL_SPONSOR", "RESOURCE_OWNER"]
  }
  ```
* **Validation Rules:** Valid Entra ID Bearer JWT in `Authorization` header.
* **Status Codes:** `200 OK`, `401 Unauthorized`.
* **Relevant Entities:** `users`, `user_roles`, `roles`.

---

### 2.2 Contractor Engagement Endpoints

#### `POST /engagements`
* **Purpose:** Onboard a new contractor engagement tied to a vendor and accountable sponsor.
* **Required Role:** `INTERNAL_SPONSOR` or `SYSTEM_ADMIN`.
* **Request Body:**
  ```json
  {
    "contractor_email": "carlos.consultant@vendor.com",
    "first_name": "Carlos",
    "last_name": "Consultant",
    "vendor_name": "Apex Technology Consulting",
    "contract_reference": "SOW-2026-ENG-088",
    "start_date": "2026-11-15",
    "end_date": "2027-05-15"
  }
  ```
* **Response Structure (`201 Created`):**
  ```json
  {
    "engagement_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "contractor_user_id": "e4f5a6b7-c8d9-4e0f-1a2b-3c4d5e6f7a8b",
    "contract_reference": "SOW-2026-ENG-088",
    "status": "ACTIVE",
    "created_at": "2026-11-09T21:30:00Z"
  }
  ```
* **Validation Rules:**
  * `end_date >= start_date`.
  * `contractor_email` must be a valid email format.
  * `contract_reference` must be non-empty string ($\le 100$ characters).
* **Status Codes:** `201 Created`, `400 Bad Request`, `409 Conflict` (duplicate reference), `403 Forbidden`.
* **Relevant Entities:** `contractor_engagements`, `users`, `audit_events`.

#### `GET /engagements`
* **Purpose:** List contractor engagements with filtering by status and vendor.
* **Required Role:** `INTERNAL_SPONSOR`, `SYSTEM_ADMIN`, `SECURITY_OFFICER`, `COMPLIANCE_AUDITOR`.
* **Query Parameters:** `status` (optional), `vendor` (optional), `page`, `page_size`.
* **Status Codes:** `200 OK`, `401 Unauthorized`.
* **Relevant Entities:** `contractor_engagements`, `users`.

---

### 2.3 Resource & Entitlement Catalogues

#### `GET /resources`
* **Purpose:** Retrieve the catalog of governed enterprise systems.
* **Required Role:** Any authenticated user.
* **Response Structure (`200 OK`):**
  ```json
  [
    {
      "resource_id": "f1e2d3c4-b5a6-7890-1234-56789abcdef0",
      "resource_code": "RES-SQL-PROD",
      "resource_name": "Production Database Cluster",
      "resource_type": "DATABASE",
      "risk_level": "CRITICAL",
      "requires_security_approval": true,
      "max_lease_duration_days": 30,
      "is_active": true
    }
  ]
  ```
* **Status Codes:** `200 OK`, `401 Unauthorized`.
* **Relevant Entities:** `resources`.

#### `GET /resources/{id}/entitlements`
* **Purpose:** Retrieve available fine-grained permission scopes for a target resource.
* **Required Role:** Any authenticated user.
* **Path Parameter:** `id` (UUID) — Resource ID.
* **Status Codes:** `200 OK`, `404 Not Found`.
* **Relevant Entities:** `entitlements`, `resources`.

---

### 2.4 Access Requests & Policy Evaluation

#### `POST /requests`
* **Purpose:** Submit a formal time-bound access request for a contractor.
* **Required Role:** `INTERNAL_SPONSOR` or `SYSTEM_ADMIN`.
* **Request Body:**
  ```json
  {
    "contractor_engagement_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "resource_id": "f1e2d3c4-b5a6-7890-1234-56789abcdef0",
    "entitlement_id": "a1b2c3d4-e5f6-7890-1234-56789abcdef1",
    "requested_start_date": "2026-11-15T08:00:00Z",
    "requested_end_date": "2026-12-15T18:00:00Z",
    "business_justification": "Required for Q4 data migration and ETL optimization."
  }
  ```
* **Response Structure (`201 Created`):**
  ```json
  {
    "request_id": "d1c2b3a4-e5f6-7890-1234-56789abcdef2",
    "request_number": "AR-20261109-0012",
    "status": "PENDING_APPROVAL",
    "requires_security_approval": true,
    "approval_steps_count": 3
  }
  ```
* **Validation Rules:**
  * **Critical Rule A & C:** `requested_end_date > requested_start_date` (cannot be null or unbounded).
  * **Critical Rule B:** `requested_end_date` $\le$ contractor engagement `end_date`.
  * `business_justification` minimum 15 characters, maximum 1000 characters.
  * No existing `ACTIVE` grant or `PENDING_APPROVAL` request for the same contractor and entitlement.
* **Status Codes:** `201 Created`, `400 Bad Request`, `409 Conflict`, `422 Unprocessable Entity`.
* **Relevant Entities:** `access_requests`, `approval_steps`, `contractor_engagements`, `resources`, `entitlements`, `audit_events`.

#### `GET /requests/{id}`
* **Purpose:** Inspect request status and approval step progression.
* **Status Codes:** `200 OK`, `404 Not Found`.
* **Relevant Entities:** `access_requests`, `approval_steps`.

---

### 2.5 Approval Actions

#### `GET /approvals/pending`
* **Purpose:** Retrieve pending approval steps assigned to the calling approver.
* **Required Role:** `RESOURCE_OWNER`, `INTERNAL_SPONSOR`, `SECURITY_OFFICER`.
* **Response Structure (`200 OK`):**
  ```json
  [
    {
      "approval_step_id": "e1f2a3b4-c5d6-7890-1234-56789abcdef3",
      "request_id": "d1c2b3a4-e5f6-7890-1234-56789abcdef2",
      "request_number": "AR-20261109-0012",
      "step_number": 2,
      "step_type": "RESOURCE_OWNER_APPROVAL",
      "contractor_name": "Carlos Consultant",
      "resource_name": "Production Database Cluster",
      "entitlement_name": "Database ReadOnly",
      "requested_end_date": "2026-12-15T18:00:00Z",
      "business_justification": "Required for Q4 data migration."
    }
  ]
  ```
* **Status Codes:** `200 OK`, `401 Unauthorized`.
* **Relevant Entities:** `approval_steps`, `access_requests`, `v_AccessExposureQueue`.

#### `POST /approvals/{stepId}/decision`
* **Purpose:** Record an approval or rejection decision on an assigned step.
* **Required Role:** Assigned Approver, Authorized Delegate, or `SECURITY_OFFICER`.
* **Request Body:**
  ```json
  {
    "decision": "APPROVED",
    "decision_comments": "Verified active SOW. Access approved for 30-day window."
  }
  ```
* **Response Structure (`200 OK`):**
  ```json
  {
    "approval_step_id": "e1f2a3b4-c5d6-7890-1234-56789abcdef3",
    "decision": "APPROVED",
    "request_status": "APPROVED",
    "all_steps_completed": true,
    "grant_activated": true
  }
  ```
* **Validation Rules:**
  * `decision` must be either `'APPROVED'` or `'REJECTED'`.
  * Step must be in `'PENDING'` status.
  * Caller must match `assigned_approver_user_id` or possess `SECURITY_OFFICER` override authority.
* **Status Codes:** `200 OK`, `400 Bad Request`, `403 Forbidden`, `404 Not Found`.
* **Relevant Entities:** `approval_steps`, `access_requests`, `access_grants`, `audit_events`.

---

### 2.6 Access Grants & Provisioning

#### `GET /grants`
* **Purpose:** Query active and historical access grants.
* **Required Role:** Any authenticated user (contractors see own grants; sponsors see sponsored; admins see all).
* **Query Parameters:** `status` (`ACTIVE`, `EXPIRED`, `REVOKED`), `contractor_id`, `page`, `page_size`.
* **Response Structure (`200 OK`):**
  ```json
  [
    {
      "grant_id": "c3b5d1a2-8f4e-4b6c-9a1d-7e8f9a0b1c2d",
      "grant_number": "AG-20261109-213000-A1B2",
      "contractor_name": "Carlos Consultant",
      "resource_name": "Production Database Cluster",
      "entitlement_name": "Database ReadOnly",
      "granted_at": "2026-11-09T21:30:00Z",
      "expires_at": "2026-12-09T21:30:00Z",
      "status": "ACTIVE"
    }
  ]
  ```
* **Status Codes:** `200 OK`, `401 Unauthorized`.
* **Relevant Entities:** `access_grants`, `contractor_engagements`, `resources`, `entitlements`.

#### `POST /grants/{id}/revoke`
* **Purpose:** Initiate immediate, emergency revocation of an active grant prior to scheduled expiration.
* **Required Role:** `RESOURCE_OWNER`, `INTERNAL_SPONSOR`, `SECURITY_OFFICER`, `SYSTEM_ADMIN`.
* **Request Body:**
  ```json
  {
    "revocation_reason": "Contractor reassigned to non-database project milestone."
  }
  ```
* **Response Structure (`202 Accepted`):**
  ```json
  {
    "grant_id": "c3b5d1a2-8f4e-4b6c-9a1d-7e8f9a0b1c2d",
    "status": "REVOKE_PENDING",
    "job_id": "7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2e",
    "message": "Revocation job queued. Grant remains in REVOKE_PENDING until connector confirmation."
  }
  ```
* **Status Codes:** `202 Accepted`, `400 Bad Request`, `403 Forbidden`, `404 Not Found`.
* **Relevant Entities:** `access_grants`, `revocation_jobs`, `audit_events`.

---

### 2.7 Exposure Queue & Orphan Detection

#### `GET /exposure-queue`
* **Purpose:** Query the `v_AccessExposureQueue` view for exposed, expiring, or overdue contractor access records.
* **Required Role:** `SECURITY_OFFICER`, `COMPLIANCE_AUDITOR`, `SYSTEM_ADMIN`.
* **Query Parameters:** `severity` (`CRITICAL`, `HIGH`, `MEDIUM`), `category` (`EXPIRED_STILL_ACTIVE`, `REVOCATION_PENDING_CONFIRMATION`, etc.).
* **Response Structure (`200 OK`):**
  ```json
  [
    {
      "grant_id": "c3b5d1a2-8f4e-4b6c-9a1d-7e8f9a0b1c2d",
      "grant_number": "AG-20261109-213000-A1B2",
      "contractor_name": "Carlos Consultant",
      "vendor_name": "Apex Technology Consulting",
      "resource_name": "Production Database Cluster",
      "grant_status": "REVOKE_PENDING",
      "exposure_category": "REVOCATION_PENDING_CONFIRMATION",
      "exposure_severity": "CRITICAL",
      "minutes_until_grant_expiry": -120,
      "days_until_engagement_expiry": 180
    }
  ]
  ```
* **Status Codes:** `200 OK`, `403 Forbidden`.
* **Relevant Entities:** `v_AccessExposureQueue`.

---

### 2.8 Offboarding Orchestration

#### `POST /engagements/{id}/offboard`
* **Purpose:** Terminate a contractor engagement early and immediately schedule revocation for all active grants.
* **Required Role:** `INTERNAL_SPONSOR`, `SYSTEM_ADMIN`, `SECURITY_OFFICER`.
* **Request Body:**
  ```json
  {
    "termination_reason": "Immediate departure due to contract milestone completion."
  }
  ```
* **Response Structure (`200 OK`):**
  ```json
  {
    "engagement_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "engagement_status": "TERMINATED",
    "revocation_jobs_queued": 4,
    "grants_pending_revocation": [
      "AG-20261109-0001",
      "AG-20261109-0002"
    ]
  }
  ```
* **Status Codes:** `200 OK`, `403 Forbidden`, `404 Not Found`.
* **Relevant Entities:** `contractor_engagements`, `access_grants`, `revocation_jobs`, `audit_events`.

---

### 2.9 Access Reviews & Recertifications

#### `POST /reviews`
* **Purpose:** Launch a periodic or targeted recertification campaign.
* **Required Role:** `COMPLIANCE_AUDITOR` or `SYSTEM_ADMIN`.
* **Request Body:**
  ```json
  {
    "review_name": "Q4 2026 Critical Infrastructure Contractor Audit",
    "campaign_type": "PERIODIC_RECERTIFICATION",
    "due_date": "2026-12-15T23:59:59Z",
    "description": "Quarterly recertification of all database and cloud subscriptions."
  }
  ```
* **Response Structure (`201 Created`):**
  ```json
  {
    "review_id": "3a4b5c6d-7e8f-9a0b-1c2d-3e4f5a6b7c8d",
    "status": "ACTIVE",
    "review_items_generated": 48
  }
  ```
* **Status Codes:** `201 Created`, `400 Bad Request`, `403 Forbidden`.
* **Relevant Entities:** `access_reviews`, `review_items`, `access_grants`, `audit_events`.

#### `POST /reviews/items/{itemId}/attest`
* **Purpose:** Record a reviewer's attestation decision (`MAINTAIN` or `REVOKE`) on a grant.
* **Required Role:** Assigned Reviewer or `COMPLIANCE_AUDITOR`.
* **Request Body:**
  ```json
  {
    "decision": "REVOKE",
    "decision_notes": "Contractor no longer assigned to this database component."
  }
  ```
* **Status Codes:** `200 OK`, `400 Bad Request`, `403 Forbidden`.
* **Relevant Entities:** `review_items`, `access_grants`, `revocation_jobs`, `audit_events`.

---

### 2.10 Audit Events & Forensics

#### `GET /audit-events`
* **Purpose:** Retrieve immutable forensic audit history with multi-field filtering.
* **Required Role:** `COMPLIANCE_AUDITOR`, `SECURITY_OFFICER`, `SYSTEM_ADMIN`.
* **Query Parameters:** `category`, `entity_type`, `entity_id`, `actor_id`, `start_date`, `end_date`, `page`, `page_size`.
* **Response Structure (`200 OK`):**
  ```json
  [
    {
      "event_id": 1042,
      "event_category": "GRANT",
      "event_action": "GRANT_ACTIVATED",
      "entity_type": "access_grants",
      "entity_id": "c3b5d1a2-8f4e-4b6c-9a1d-7e8f9a0b1c2d",
      "actor_user_id": "b1a2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
      "actor_type": "USER",
      "event_payload": {
        "grant_number": "AG-20261109-213000-A1B2",
        "expires_at": "2026-12-09T21:30:00Z"
      },
      "ip_address": "198.51.100.42",
      "created_at": "2026-11-09T21:30:00.123Z"
    }
  ]
  ```
* **Status Codes:** `200 OK`, `403 Forbidden`.
* **Relevant Entities:** `audit_events`.

---

### 2.11 Governance Analytics

#### `GET /analytics/summary`
* **Purpose:** Returns high-level metrics for executive and compliance dashboards.
* **Required Role:** `COMPLIANCE_AUDITOR`, `SECURITY_OFFICER`, `SYSTEM_ADMIN`.
* **Response Structure (`200 OK`):**
  ```json
  {
    "active_contractors": 142,
    "active_grants": 310,
    "grants_expiring_48h": 8,
    "grants_pending_revocation": 2,
    "orphan_grants_detected": 0,
    "on_time_revocation_rate_pct": 99.8
  }
  ```
* **Status Codes:** `200 OK`, `403 Forbidden`.
* **Relevant Entities:** `v_AccessExposureQueue`, `access_grants`, `contractor_engagements`.
