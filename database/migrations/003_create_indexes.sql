-- ==============================================================================
-- AccessLease Database Migration: 003_create_indexes.sql
-- Description: Creates targeted governance and performance indexes.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ------------------------------------------------------------------------------
-- 1. Contractor Engagement End Dates
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_contractor_engagements_end_date' AND object_id = OBJECT_ID('dbo.contractor_engagements'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_contractor_engagements_end_date
        ON dbo.contractor_engagements (end_date ASC, status ASC)
        INCLUDE (contractor_user_id, sponsor_user_id, vendor_name, contract_reference);
END;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_contractor_engagements_contractor' AND object_id = OBJECT_ID('dbo.contractor_engagements'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_contractor_engagements_contractor
        ON dbo.contractor_engagements (contractor_user_id ASC, status ASC);
END;
GO

-- ------------------------------------------------------------------------------
-- 2. Active and Expiring Access Grants
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_access_grants_status_expires_at' AND object_id = OBJECT_ID('dbo.access_grants'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_access_grants_status_expires_at
        ON dbo.access_grants (status ASC, expires_at ASC)
        INCLUDE (contractor_engagement_id, resource_id, entitlement_id, granted_at, grant_number);
END;
GO

-- Targeted filtered index for background automated expiration workers
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_access_grants_active_expiry' AND object_id = OBJECT_ID('dbo.access_grants'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_access_grants_active_expiry
        ON dbo.access_grants (expires_at ASC)
        INCLUDE (grant_id, grant_number, contractor_engagement_id, resource_id, entitlement_id)
        WHERE status = 'ACTIVE';
END;
GO

-- Critical Business Rule I: Prevent duplicate active grants for same contractor + entitlement
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UQ_access_grants_active_contractor_entitlement' AND object_id = OBJECT_ID('dbo.access_grants'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX UQ_access_grants_active_contractor_entitlement
        ON dbo.access_grants (contractor_engagement_id ASC, entitlement_id ASC)
        WHERE status IN ('ACTIVE', 'PROVISIONING_PENDING');
END;
GO

-- ------------------------------------------------------------------------------
-- 3. Pending Approval Requests
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_approval_steps_approver_status' AND object_id = OBJECT_ID('dbo.approval_steps'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_approval_steps_approver_status
        ON dbo.approval_steps (assigned_approver_user_id ASC, status ASC)
        INCLUDE (request_id, step_number, step_type, created_at)
        WHERE status = 'PENDING';
END;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_access_requests_status' AND object_id = OBJECT_ID('dbo.access_requests'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_access_requests_status
        ON dbo.access_requests (status ASC, created_at DESC)
        INCLUDE (request_number, contractor_engagement_id, requested_by_user_id, resource_id, entitlement_id);
END;
GO

-- ------------------------------------------------------------------------------
-- 4. Pending Revocation Jobs
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_revocation_jobs_pending' AND object_id = OBJECT_ID('dbo.revocation_jobs'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_revocation_jobs_pending
        ON dbo.revocation_jobs (status ASC, retry_count ASC, created_at ASC)
        INCLUDE (job_id, grant_id, trigger_source, connector_name)
        WHERE status IN ('QUEUED', 'FAILED_RETRY', 'IN_PROGRESS');
END;
GO

-- ------------------------------------------------------------------------------
-- 5. Resource Ownership Lookups
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_resource_owners_owner' AND object_id = OBJECT_ID('dbo.resource_owners'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_resource_owners_owner
        ON dbo.resource_owners (owner_user_id ASC, resource_id ASC)
        INCLUDE (ownership_type, assigned_at);
END;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_resource_owners_resource' AND object_id = OBJECT_ID('dbo.resource_owners'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_resource_owners_resource
        ON dbo.resource_owners (resource_id ASC, ownership_type ASC)
        INCLUDE (owner_user_id, assigned_at);
END;
GO

-- ------------------------------------------------------------------------------
-- 6. Audit Event Searches
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_audit_events_created_category' AND object_id = OBJECT_ID('dbo.audit_events'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_audit_events_created_category
        ON dbo.audit_events (created_at DESC, event_category ASC)
        INCLUDE (event_action, entity_type, entity_id, actor_user_id);
END;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_audit_events_entity' AND object_id = OBJECT_ID('dbo.audit_events'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_audit_events_entity
        ON dbo.audit_events (entity_type ASC, entity_id ASC, created_at DESC)
        INCLUDE (event_category, event_action, actor_user_id);
END;
GO
