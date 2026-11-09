-- ==============================================================================
-- AccessLease Schema Definition: 001_create_core_tables.sql
-- Description: Core DDL definitions for the 15 governance tables in 3NF.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- 1. users
IF OBJECT_ID(N'dbo.users', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.users (
        user_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        entra_object_id NVARCHAR(64) NOT NULL,
        email NVARCHAR(256) NOT NULL,
        first_name NVARCHAR(64) NOT NULL,
        last_name NVARCHAR(64) NOT NULL,
        display_name NVARCHAR(128) NOT NULL,
        user_type NVARCHAR(30) NOT NULL,
        department NVARCHAR(100) NULL,
        is_active BIT NOT NULL DEFAULT 1,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_users PRIMARY KEY CLUSTERED (user_id ASC)
    );
END;
GO

-- 2. contractor_engagements
IF OBJECT_ID(N'dbo.contractor_engagements', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.contractor_engagements (
        engagement_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        contractor_user_id UNIQUEIDENTIFIER NOT NULL,
        sponsor_user_id UNIQUEIDENTIFIER NOT NULL,
        vendor_name NVARCHAR(150) NOT NULL,
        contract_reference NVARCHAR(100) NOT NULL,
        start_date DATE NOT NULL,
        end_date DATE NOT NULL,
        status NVARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_contractor_engagements PRIMARY KEY CLUSTERED (engagement_id ASC)
    );
END;
GO

-- 3. roles
IF OBJECT_ID(N'dbo.roles', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.roles (
        role_id INT IDENTITY(1,1) NOT NULL,
        role_code NVARCHAR(50) NOT NULL,
        role_name NVARCHAR(100) NOT NULL,
        description NVARCHAR(256) NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_roles PRIMARY KEY CLUSTERED (role_id ASC)
    );
END;
GO

-- 4. user_roles
IF OBJECT_ID(N'dbo.user_roles', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.user_roles (
        user_id UNIQUEIDENTIFIER NOT NULL,
        role_id INT NOT NULL,
        assigned_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        assigned_by_user_id UNIQUEIDENTIFIER NULL,
        CONSTRAINT PK_user_roles PRIMARY KEY CLUSTERED (user_id ASC, role_id ASC)
    );
END;
GO

-- 5. resources
IF OBJECT_ID(N'dbo.resources', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.resources (
        resource_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        resource_code NVARCHAR(50) NOT NULL,
        resource_name NVARCHAR(150) NOT NULL,
        resource_type NVARCHAR(50) NOT NULL,
        description NVARCHAR(500) NULL,
        risk_level NVARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
        requires_security_approval BIT NOT NULL DEFAULT 0,
        max_lease_duration_days INT NOT NULL DEFAULT 90,
        is_active BIT NOT NULL DEFAULT 1,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_resources PRIMARY KEY CLUSTERED (resource_id ASC)
    );
END;
GO

-- 6. entitlements
IF OBJECT_ID(N'dbo.entitlements', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.entitlements (
        entitlement_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        resource_id UNIQUEIDENTIFIER NOT NULL,
        entitlement_code NVARCHAR(50) NOT NULL,
        entitlement_name NVARCHAR(150) NOT NULL,
        description NVARCHAR(500) NULL,
        sensitivity_level NVARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
        is_active BIT NOT NULL DEFAULT 1,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_entitlements PRIMARY KEY CLUSTERED (entitlement_id ASC)
    );
END;
GO

-- 7. resource_owners
IF OBJECT_ID(N'dbo.resource_owners', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.resource_owners (
        resource_owner_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        resource_id UNIQUEIDENTIFIER NOT NULL,
        owner_user_id UNIQUEIDENTIFIER NOT NULL,
        ownership_type NVARCHAR(30) NOT NULL DEFAULT 'PRIMARY',
        assigned_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_resource_owners PRIMARY KEY CLUSTERED (resource_owner_id ASC)
    );
END;
GO

-- 8. access_requests
IF OBJECT_ID(N'dbo.access_requests', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.access_requests (
        request_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        request_number NVARCHAR(30) NOT NULL,
        contractor_engagement_id UNIQUEIDENTIFIER NOT NULL,
        requested_by_user_id UNIQUEIDENTIFIER NOT NULL,
        resource_id UNIQUEIDENTIFIER NOT NULL,
        entitlement_id UNIQUEIDENTIFIER NOT NULL,
        requested_start_date DATETIMEOFFSET NOT NULL,
        requested_end_date DATETIMEOFFSET NOT NULL,
        business_justification NVARCHAR(1000) NOT NULL,
        status NVARCHAR(30) NOT NULL DEFAULT 'SUBMITTED',
        requires_security_approval BIT NOT NULL DEFAULT 0,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_access_requests PRIMARY KEY CLUSTERED (request_id ASC)
    );
END;
GO

-- 9. approval_steps
IF OBJECT_ID(N'dbo.approval_steps', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.approval_steps (
        approval_step_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        request_id UNIQUEIDENTIFIER NOT NULL,
        step_number INT NOT NULL,
        step_type NVARCHAR(50) NOT NULL,
        assigned_approver_user_id UNIQUEIDENTIFIER NOT NULL,
        status NVARCHAR(30) NOT NULL DEFAULT 'PENDING',
        decision_comments NVARCHAR(1000) NULL,
        decided_at DATETIMEOFFSET NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_approval_steps PRIMARY KEY CLUSTERED (approval_step_id ASC)
    );
END;
GO

-- 10. access_grants
IF OBJECT_ID(N'dbo.access_grants', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.access_grants (
        grant_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        grant_number NVARCHAR(30) NOT NULL,
        request_id UNIQUEIDENTIFIER NOT NULL,
        contractor_engagement_id UNIQUEIDENTIFIER NOT NULL,
        resource_id UNIQUEIDENTIFIER NOT NULL,
        entitlement_id UNIQUEIDENTIFIER NOT NULL,
        granted_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        expires_at DATETIMEOFFSET NOT NULL,
        status NVARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
        revoked_at DATETIMEOFFSET NULL,
        revocation_reason NVARCHAR(500) NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_access_grants PRIMARY KEY CLUSTERED (grant_id ASC)
    );
END;
GO

-- 11. provisioning_events
IF OBJECT_ID(N'dbo.provisioning_events', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.provisioning_events (
        event_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        grant_id UNIQUEIDENTIFIER NOT NULL,
        event_type NVARCHAR(50) NOT NULL,
        connector_name NVARCHAR(100) NOT NULL,
        payload NVARCHAR(MAX) NULL,
        status_code NVARCHAR(50) NULL,
        error_message NVARCHAR(MAX) NULL,
        executed_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_provisioning_events PRIMARY KEY CLUSTERED (event_id ASC)
    );
END;
GO

-- 12. revocation_jobs
IF OBJECT_ID(N'dbo.revocation_jobs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.revocation_jobs (
        job_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        grant_id UNIQUEIDENTIFIER NOT NULL,
        trigger_source NVARCHAR(50) NOT NULL,
        status NVARCHAR(30) NOT NULL DEFAULT 'QUEUED',
        retry_count INT NOT NULL DEFAULT 0,
        max_retries INT NOT NULL DEFAULT 5,
        connector_name NVARCHAR(100) NOT NULL,
        connector_response NVARCHAR(MAX) NULL,
        error_details NVARCHAR(MAX) NULL,
        cryptographic_proof_hash NVARCHAR(64) NULL,
        proof_blob_url NVARCHAR(2048) NULL,
        confirmed_at DATETIMEOFFSET NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_revocation_jobs PRIMARY KEY CLUSTERED (job_id ASC)
    );
END;
GO

-- 13. access_reviews
IF OBJECT_ID(N'dbo.access_reviews', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.access_reviews (
        review_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        review_name NVARCHAR(150) NOT NULL,
        description NVARCHAR(500) NULL,
        campaign_type NVARCHAR(50) NOT NULL DEFAULT 'PERIODIC_RECERTIFICATION',
        start_date DATETIMEOFFSET NOT NULL,
        due_date DATETIMEOFFSET NOT NULL,
        status NVARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
        initiated_by_user_id UNIQUEIDENTIFIER NOT NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_access_reviews PRIMARY KEY CLUSTERED (review_id ASC)
    );
END;
GO

-- 14. review_items
IF OBJECT_ID(N'dbo.review_items', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.review_items (
        review_item_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        review_id UNIQUEIDENTIFIER NOT NULL,
        grant_id UNIQUEIDENTIFIER NOT NULL,
        reviewer_user_id UNIQUEIDENTIFIER NOT NULL,
        decision NVARCHAR(30) NOT NULL DEFAULT 'PENDING',
        decision_notes NVARCHAR(1000) NULL,
        decided_at DATETIMEOFFSET NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_review_items PRIMARY KEY CLUSTERED (review_item_id ASC)
    );
END;
GO

-- 15. audit_events
IF OBJECT_ID(N'dbo.audit_events', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.audit_events (
        event_id BIGINT IDENTITY(1,1) NOT NULL,
        event_category NVARCHAR(50) NOT NULL,
        event_action NVARCHAR(100) NOT NULL,
        entity_type NVARCHAR(50) NOT NULL,
        entity_id NVARCHAR(64) NOT NULL,
        actor_user_id UNIQUEIDENTIFIER NULL,
        actor_type NVARCHAR(30) NOT NULL DEFAULT 'USER',
        event_payload NVARCHAR(MAX) NOT NULL,
        ip_address VARCHAR(45) NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_audit_events PRIMARY KEY CLUSTERED (event_id ASC)
    );
END;
GO
