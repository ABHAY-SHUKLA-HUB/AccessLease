-- ==============================================================================
-- AccessLease Schema Migration: 011_enhance_revocation_jobs.sql
-- Description: Enhances dbo.revocation_jobs with lease locking, idempotency,
--              retry management, and expanded status/trigger CHECK constraints.
--              Also expands dbo.access_grants and dbo.provisioning_events.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- 1. Add worker leasing, retry and idempotency columns to dbo.revocation_jobs
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.revocation_jobs') AND name = N'lease_owner')
    ALTER TABLE dbo.revocation_jobs ADD lease_owner NVARCHAR(100) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.revocation_jobs') AND name = N'lease_expires_at')
    ALTER TABLE dbo.revocation_jobs ADD lease_expires_at DATETIMEOFFSET NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.revocation_jobs') AND name = N'next_retry_at')
    ALTER TABLE dbo.revocation_jobs ADD next_retry_at DATETIMEOFFSET NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.revocation_jobs') AND name = N'last_error_category')
    ALTER TABLE dbo.revocation_jobs ADD last_error_category NVARCHAR(50) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.revocation_jobs') AND name = N'last_error_message')
    ALTER TABLE dbo.revocation_jobs ADD last_error_message NVARCHAR(MAX) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.revocation_jobs') AND name = N'idempotency_key')
    ALTER TABLE dbo.revocation_jobs ADD idempotency_key NVARCHAR(150) NULL;
GO

-- 2. Unique index for idempotency_key on dbo.revocation_jobs
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UQ_rev_jobs_idempotency' AND object_id = OBJECT_ID('dbo.revocation_jobs'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX UQ_rev_jobs_idempotency
    ON dbo.revocation_jobs (idempotency_key ASC)
    WHERE idempotency_key IS NOT NULL;
END;
GO

-- 3. Claiming index for background worker
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_rev_jobs_claiming' AND object_id = OBJECT_ID('dbo.revocation_jobs'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_rev_jobs_claiming
    ON dbo.revocation_jobs (status ASC, next_retry_at ASC, lease_expires_at ASC)
    INCLUDE (job_id, grant_id, retry_count);
END;
GO

-- 4. Expand dbo.revocation_jobs status CHECK constraint
IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_revocation_jobs_status')
    ALTER TABLE dbo.revocation_jobs DROP CONSTRAINT CK_revocation_jobs_status;
GO

ALTER TABLE dbo.revocation_jobs ADD CONSTRAINT CK_revocation_jobs_status
    CHECK (status IN (
        'QUEUED',
        'PROCESSING',
        'IN_PROGRESS',
        'REVOKE_PENDING',
        'REVOKED',
        'CONFIRMED',
        'FAILED_RETRY',
        'PERMANENT_FAILURE',
        'MANUAL_REVIEW_REQUIRED'
    ));
GO

-- 5. Expand dbo.revocation_jobs trigger_source CHECK constraint
IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_revocation_jobs_trigger')
    ALTER TABLE dbo.revocation_jobs DROP CONSTRAINT CK_revocation_jobs_trigger;
GO

ALTER TABLE dbo.revocation_jobs ADD CONSTRAINT CK_revocation_jobs_trigger
    CHECK (trigger_source IN (
        'SCHEDULED_EXPIRATION',
        'ENGAGEMENT_TERMINATION',
        'REVIEW_REJECTION',
        'MANUAL_EMERGENCY',
        'ADMIN_OFFBOARDING',
        'MANUAL_RETRY'
    ));
GO

-- 6. Expand dbo.access_grants status CHECK constraint to support MANUAL_REVIEW_REQUIRED and add numeric_account_id
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.access_grants') AND name = N'numeric_account_id')
    ALTER TABLE dbo.access_grants ADD numeric_account_id NVARCHAR(100) NULL;
GO

IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_access_grants_status')
    ALTER TABLE dbo.access_grants DROP CONSTRAINT CK_access_grants_status;
GO

ALTER TABLE dbo.access_grants ADD CONSTRAINT CK_access_grants_status
    CHECK (status IN (
        'PROVISIONING_PENDING',
        'PROVISIONING_IN_PROGRESS',
        'PENDING_ACCEPTANCE',
        'ACTIVE',
        'PROVISIONING_FAILED',
        'REVOKE_PENDING',
        'REVOKED',
        'EXPIRED',
        'MANUAL_REVIEW_REQUIRED'
    ));
GO

-- 7. Expand dbo.provisioning_events event_type CHECK constraint to support revocation event types
IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_provisioning_events_type')
    ALTER TABLE dbo.provisioning_events DROP CONSTRAINT CK_provisioning_events_type;
GO

ALTER TABLE dbo.provisioning_events ADD CONSTRAINT CK_provisioning_events_type
    CHECK (event_type IN (
        'PROVISION_REQUESTED',
        'PROVISION_IN_PROGRESS',
        'MEMBERSHIP_DISCOVERED',
        'MEMBERSHIP_MUTATION_CONFIRMED',
        'MEMBERSHIP_MUTATION_LOCAL_CONFIRMED',
        'PROVIDER_AUDIT_CONFIRMED',
        'AUDIT_VERIFICATION_FAILED',
        'INVITATION_PENDING',
        'PROVISION_SUCCEEDED',
        'PROVISION_FAILED',
        'RETRY_SCHEDULED',
        'MANUAL_RETRY',
        'REVOCATION_REQUESTED',
        'REVOCATION_IN_PROGRESS',
        'REVOCATION_SUCCEEDED',
        'REVOCATION_FAILED',
        'SHARED_MEMBERSHIP_RETAINED',
        'MANUAL_REVIEW_REQUIRED'
    ));
GO
