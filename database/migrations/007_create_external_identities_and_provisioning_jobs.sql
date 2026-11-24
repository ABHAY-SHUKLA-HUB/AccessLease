-- ==============================================================================
-- AccessLease Schema Migration: 007_create_external_identities_and_provisioning_jobs.sql
-- Description: Establishes contractor external identity mappings (GitHub),
--              resource connector catalogue mappings, durable provisioning jobs/outbox,
--              and expands grant lifecycle statuses for asynchronous provisioning.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ------------------------------------------------------------------------------
-- 1. dbo.user_external_identities (Phase 4: Verified External Contractor Identities)
-- ------------------------------------------------------------------------------
IF OBJECT_ID(N'dbo.user_external_identities', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.user_external_identities (
        identity_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        user_id UNIQUEIDENTIFIER NOT NULL,
        provider NVARCHAR(50) NOT NULL, -- e.g. 'GITHUB'
        external_account_id NVARCHAR(100) NULL, -- e.g. numeric GitHub user ID
        external_username NVARCHAR(100) NOT NULL, -- e.g. GitHub handle/login
        verification_status NVARCHAR(30) NOT NULL DEFAULT 'UNVERIFIED',
        verified_at DATETIMEOFFSET NULL,
        verified_by_user_id UNIQUEIDENTIFIER NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_user_external_identities PRIMARY KEY CLUSTERED (identity_id ASC),
        CONSTRAINT FK_user_ext_id_user FOREIGN KEY (user_id) REFERENCES dbo.users (user_id) ON DELETE CASCADE,
        CONSTRAINT FK_user_ext_id_verifier FOREIGN KEY (verified_by_user_id) REFERENCES dbo.users (user_id) ON DELETE NO ACTION,
        CONSTRAINT UQ_user_ext_id_user_provider UNIQUE NONCLUSTERED (user_id ASC, provider ASC),
        CONSTRAINT UQ_user_ext_id_provider_username UNIQUE NONCLUSTERED (provider ASC, external_username ASC),
        CONSTRAINT CK_user_ext_id_status CHECK (verification_status IN ('UNVERIFIED', 'VERIFIED', 'REVOKED'))
    );
END;
GO

-- ------------------------------------------------------------------------------
-- 2. dbo.connector_resource_mappings (Phase 2: Catalogue to GitHub Mapping)
-- ------------------------------------------------------------------------------
IF OBJECT_ID(N'dbo.connector_resource_mappings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.connector_resource_mappings (
        mapping_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        resource_id UNIQUEIDENTIFIER NOT NULL,
        entitlement_id UNIQUEIDENTIFIER NOT NULL,
        connector_type NVARCHAR(50) NOT NULL DEFAULT 'GITHUB',
        github_org NVARCHAR(100) NOT NULL,
        github_team_slug NVARCHAR(100) NOT NULL,
        github_repo_owner NVARCHAR(100) NOT NULL,
        github_repo_name NVARCHAR(100) NOT NULL,
        required_permission NVARCHAR(50) NOT NULL DEFAULT 'pull',
        is_active BIT NOT NULL DEFAULT 1,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_connector_resource_mappings PRIMARY KEY CLUSTERED (mapping_id ASC),
        CONSTRAINT FK_crm_resource FOREIGN KEY (resource_id) REFERENCES dbo.resources (resource_id) ON DELETE CASCADE,
        CONSTRAINT FK_crm_entitlement FOREIGN KEY (entitlement_id) REFERENCES dbo.entitlements (entitlement_id) ON DELETE NO ACTION,
        CONSTRAINT UQ_crm_res_ent_connector UNIQUE NONCLUSTERED (resource_id ASC, entitlement_id ASC, connector_type ASC),
        CONSTRAINT CK_crm_permission CHECK (required_permission IN ('pull', 'triage', 'push', 'maintain', 'admin'))
    );
END;
GO

-- ------------------------------------------------------------------------------
-- 3. dbo.provisioning_jobs (Phase 5: Durable Provisioning Outbox / Queue)
-- ------------------------------------------------------------------------------
IF OBJECT_ID(N'dbo.provisioning_jobs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.provisioning_jobs (
        job_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        request_id UNIQUEIDENTIFIER NOT NULL,
        grant_id UNIQUEIDENTIFIER NULL,
        connector_type NVARCHAR(50) NOT NULL DEFAULT 'GITHUB',
        target_resource NVARCHAR(200) NOT NULL,
        idempotency_key NVARCHAR(150) NOT NULL,
        job_status NVARCHAR(30) NOT NULL DEFAULT 'QUEUED',
        attempt_count INT NOT NULL DEFAULT 0,
        max_attempts INT NOT NULL DEFAULT 5,
        next_retry_at DATETIMEOFFSET NULL,
        lease_owner NVARCHAR(100) NULL,
        lease_expires_at DATETIMEOFFSET NULL,
        last_error_category NVARCHAR(50) NULL,
        last_error_message NVARCHAR(MAX) NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_provisioning_jobs PRIMARY KEY CLUSTERED (job_id ASC),
        CONSTRAINT FK_prov_jobs_request FOREIGN KEY (request_id) REFERENCES dbo.access_requests (request_id) ON DELETE CASCADE,
        CONSTRAINT FK_prov_jobs_grant FOREIGN KEY (grant_id) REFERENCES dbo.access_grants (grant_id) ON DELETE NO ACTION,
        CONSTRAINT UQ_prov_jobs_idempotency UNIQUE NONCLUSTERED (idempotency_key ASC),
        CONSTRAINT CK_prov_jobs_status CHECK (job_status IN ('QUEUED', 'PROCESSING', 'SUCCEEDED', 'FAILED_RETRY', 'PERMANENT_FAILURE', 'PENDING_ACCEPTANCE'))
    );
END;
GO

-- Index for background worker claiming
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_prov_jobs_claiming' AND object_id = OBJECT_ID('dbo.provisioning_jobs'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_prov_jobs_claiming
    ON dbo.provisioning_jobs (job_status ASC, next_retry_at ASC, lease_expires_at ASC)
    INCLUDE (job_id, request_id, connector_type, attempt_count);
END;
GO

-- ------------------------------------------------------------------------------
-- 4. Expand dbo.access_grants Lifecycle and Metadata Columns (Phase 7)
-- ------------------------------------------------------------------------------
-- Add metadata columns if not present
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.access_grants') AND name = N'connector_type')
    ALTER TABLE dbo.access_grants ADD connector_type NVARCHAR(50) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.access_grants') AND name = N'target_org')
    ALTER TABLE dbo.access_grants ADD target_org NVARCHAR(100) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.access_grants') AND name = N'target_team_slug')
    ALTER TABLE dbo.access_grants ADD target_team_slug NVARCHAR(100) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.access_grants') AND name = N'target_repo')
    ALTER TABLE dbo.access_grants ADD target_repo NVARCHAR(150) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.access_grants') AND name = N'external_username')
    ALTER TABLE dbo.access_grants ADD external_username NVARCHAR(100) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.access_grants') AND name = N'membership_provenance')
    ALTER TABLE dbo.access_grants ADD membership_provenance NVARCHAR(30) NULL DEFAULT 'CREATED_BY_ACCESSLEASE';
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.access_grants') AND name = N'verified_at')
    ALTER TABLE dbo.access_grants ADD verified_at DATETIMEOFFSET NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.access_grants') AND name = N'failure_category')
    ALTER TABLE dbo.access_grants ADD failure_category NVARCHAR(50) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'dbo.access_grants') AND name = N'connector_metadata')
    ALTER TABLE dbo.access_grants ADD connector_metadata NVARCHAR(MAX) NULL;
GO

-- Update CHECK constraint for access_grants.status to include all lifecycle states
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
        'EXPIRED'
    ));
GO

-- ------------------------------------------------------------------------------
-- 5. Expand dbo.provisioning_events event_type CHECK Constraint
-- ------------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_provisioning_events_type')
    ALTER TABLE dbo.provisioning_events DROP CONSTRAINT CK_provisioning_events_type;
GO

ALTER TABLE dbo.provisioning_events ADD CONSTRAINT CK_provisioning_events_type
    CHECK (event_type IN (
        'PROVISION_REQUESTED',
        'PROVISION_IN_PROGRESS',
        'MEMBERSHIP_DISCOVERED',
        'INVITATION_PENDING',
        'PROVISION_SUCCEEDED',
        'PROVISION_FAILED',
        'RETRY_SCHEDULED',
        'MANUAL_RETRY'
    ));
GO
