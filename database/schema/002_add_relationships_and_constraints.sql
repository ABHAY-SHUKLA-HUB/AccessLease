-- ==============================================================================
-- AccessLease Schema Definition: 002_add_relationships_and_constraints.sql
-- Description: Establishes PK/FK referential integrity and strict governance CHECK/UNIQUE constraints.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ------------------------------------------------------------------------------
-- 1. users Constraints
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_users_entra_object_id')
    ALTER TABLE dbo.users ADD CONSTRAINT UQ_users_entra_object_id UNIQUE NONCLUSTERED (entra_object_id ASC);
GO

IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_users_email')
    ALTER TABLE dbo.users ADD CONSTRAINT UQ_users_email UNIQUE NONCLUSTERED (email ASC);
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_users_user_type')
    ALTER TABLE dbo.users ADD CONSTRAINT CK_users_user_type CHECK (user_type IN ('INTERNAL_EMPLOYEE', 'CONTRACTOR'));
GO

-- ------------------------------------------------------------------------------
-- 2. contractor_engagements Constraints & Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_contractor_engagements_contractor')
    ALTER TABLE dbo.contractor_engagements ADD CONSTRAINT FK_contractor_engagements_contractor
        FOREIGN KEY (contractor_user_id) REFERENCES dbo.users (user_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_contractor_engagements_sponsor')
    ALTER TABLE dbo.contractor_engagements ADD CONSTRAINT FK_contractor_engagements_sponsor
        FOREIGN KEY (sponsor_user_id) REFERENCES dbo.users (user_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_contractor_engagements_dates')
    ALTER TABLE dbo.contractor_engagements ADD CONSTRAINT CK_contractor_engagements_dates
        CHECK (end_date >= start_date);
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_contractor_engagements_status')
    ALTER TABLE dbo.contractor_engagements ADD CONSTRAINT CK_contractor_engagements_status
        CHECK (status IN ('PENDING', 'ACTIVE', 'COMPLETED', 'TERMINATED'));
GO

IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_contractor_contract_ref')
    ALTER TABLE dbo.contractor_engagements ADD CONSTRAINT UQ_contractor_contract_ref
        UNIQUE NONCLUSTERED (contractor_user_id ASC, contract_reference ASC);
GO

-- ------------------------------------------------------------------------------
-- 3. roles Constraints
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_roles_role_code')
    ALTER TABLE dbo.roles ADD CONSTRAINT UQ_roles_role_code UNIQUE NONCLUSTERED (role_code ASC);
GO

-- ------------------------------------------------------------------------------
-- 4. user_roles Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_user_roles_user')
    ALTER TABLE dbo.user_roles ADD CONSTRAINT FK_user_roles_user
        FOREIGN KEY (user_id) REFERENCES dbo.users (user_id) ON DELETE CASCADE;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_user_roles_role')
    ALTER TABLE dbo.user_roles ADD CONSTRAINT FK_user_roles_role
        FOREIGN KEY (role_id) REFERENCES dbo.roles (role_id) ON DELETE CASCADE;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_user_roles_assigned_by')
    ALTER TABLE dbo.user_roles ADD CONSTRAINT FK_user_roles_assigned_by
        FOREIGN KEY (assigned_by_user_id) REFERENCES dbo.users (user_id) ON DELETE NO ACTION;
GO

-- ------------------------------------------------------------------------------
-- 5. resources Constraints
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_resources_code')
    ALTER TABLE dbo.resources ADD CONSTRAINT UQ_resources_code UNIQUE NONCLUSTERED (resource_code ASC);
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_resources_risk_level')
    ALTER TABLE dbo.resources ADD CONSTRAINT CK_resources_risk_level
        CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'));
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_resources_type')
    ALTER TABLE dbo.resources ADD CONSTRAINT CK_resources_type
        CHECK (resource_type IN ('SAAS', 'CLOUD_SUBSCRIPTION', 'DATABASE', 'REPOSITORY', 'NETWORK_VPN', 'INTERNAL_APP'));
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_resources_max_duration')
    ALTER TABLE dbo.resources ADD CONSTRAINT CK_resources_max_duration
        CHECK (max_lease_duration_days > 0 AND max_lease_duration_days <= 365);
GO

-- ------------------------------------------------------------------------------
-- 6. entitlements Constraints & Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_entitlements_resource')
    ALTER TABLE dbo.entitlements ADD CONSTRAINT FK_entitlements_resource
        FOREIGN KEY (resource_id) REFERENCES dbo.resources (resource_id) ON DELETE CASCADE;
GO

IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_entitlements_resource_code')
    ALTER TABLE dbo.entitlements ADD CONSTRAINT UQ_entitlements_resource_code
        UNIQUE NONCLUSTERED (resource_id ASC, entitlement_code ASC);
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_entitlements_sensitivity')
    ALTER TABLE dbo.entitlements ADD CONSTRAINT CK_entitlements_sensitivity
        CHECK (sensitivity_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'));
GO

-- ------------------------------------------------------------------------------
-- 7. resource_owners Constraints & Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_resource_owners_resource')
    ALTER TABLE dbo.resource_owners ADD CONSTRAINT FK_resource_owners_resource
        FOREIGN KEY (resource_id) REFERENCES dbo.resources (resource_id) ON DELETE CASCADE;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_resource_owners_user')
    ALTER TABLE dbo.resource_owners ADD CONSTRAINT FK_resource_owners_user
        FOREIGN KEY (owner_user_id) REFERENCES dbo.users (user_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_resource_owners')
    ALTER TABLE dbo.resource_owners ADD CONSTRAINT UQ_resource_owners
        UNIQUE NONCLUSTERED (resource_id ASC, owner_user_id ASC, ownership_type ASC);
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_resource_owners_type')
    ALTER TABLE dbo.resource_owners ADD CONSTRAINT CK_resource_owners_type
        CHECK (ownership_type IN ('PRIMARY', 'DELEGATE', 'TECHNICAL_CONTACT'));
GO

-- ------------------------------------------------------------------------------
-- 8. access_requests Constraints & Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_access_requests_number')
    ALTER TABLE dbo.access_requests ADD CONSTRAINT UQ_access_requests_number UNIQUE NONCLUSTERED (request_number ASC);
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_access_requests_engagement')
    ALTER TABLE dbo.access_requests ADD CONSTRAINT FK_access_requests_engagement
        FOREIGN KEY (contractor_engagement_id) REFERENCES dbo.contractor_engagements (engagement_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_access_requests_requested_by')
    ALTER TABLE dbo.access_requests ADD CONSTRAINT FK_access_requests_requested_by
        FOREIGN KEY (requested_by_user_id) REFERENCES dbo.users (user_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_access_requests_resource')
    ALTER TABLE dbo.access_requests ADD CONSTRAINT FK_access_requests_resource
        FOREIGN KEY (resource_id) REFERENCES dbo.resources (resource_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_access_requests_entitlement')
    ALTER TABLE dbo.access_requests ADD CONSTRAINT FK_access_requests_entitlement
        FOREIGN KEY (entitlement_id) REFERENCES dbo.entitlements (entitlement_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_access_requests_dates')
    ALTER TABLE dbo.access_requests ADD CONSTRAINT CK_access_requests_dates
        CHECK (requested_end_date > requested_start_date);
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_access_requests_status')
    ALTER TABLE dbo.access_requests ADD CONSTRAINT CK_access_requests_status
        CHECK (status IN ('SUBMITTED', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'CANCELLED'));
GO

-- ------------------------------------------------------------------------------
-- 9. approval_steps Constraints & Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_approval_steps_request')
    ALTER TABLE dbo.approval_steps ADD CONSTRAINT FK_approval_steps_request
        FOREIGN KEY (request_id) REFERENCES dbo.access_requests (request_id) ON DELETE CASCADE;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_approval_steps_approver')
    ALTER TABLE dbo.approval_steps ADD CONSTRAINT FK_approval_steps_approver
        FOREIGN KEY (assigned_approver_user_id) REFERENCES dbo.users (user_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_approval_steps_req_step')
    ALTER TABLE dbo.approval_steps ADD CONSTRAINT UQ_approval_steps_req_step
        UNIQUE NONCLUSTERED (request_id ASC, step_number ASC);
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_approval_steps_type')
    ALTER TABLE dbo.approval_steps ADD CONSTRAINT CK_approval_steps_type
        CHECK (step_type IN ('SPONSOR_APPROVAL', 'RESOURCE_OWNER_APPROVAL', 'SECURITY_APPROVAL'));
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_approval_steps_status')
    ALTER TABLE dbo.approval_steps ADD CONSTRAINT CK_approval_steps_status
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'SKIPPED'));
GO

-- ------------------------------------------------------------------------------
-- 10. access_grants Constraints & Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_access_grants_number')
    ALTER TABLE dbo.access_grants ADD CONSTRAINT UQ_access_grants_number UNIQUE NONCLUSTERED (grant_number ASC);
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_access_grants_request')
    ALTER TABLE dbo.access_grants ADD CONSTRAINT FK_access_grants_request
        FOREIGN KEY (request_id) REFERENCES dbo.access_requests (request_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_access_grants_engagement')
    ALTER TABLE dbo.access_grants ADD CONSTRAINT FK_access_grants_engagement
        FOREIGN KEY (contractor_engagement_id) REFERENCES dbo.contractor_engagements (engagement_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_access_grants_resource')
    ALTER TABLE dbo.access_grants ADD CONSTRAINT FK_access_grants_resource
        FOREIGN KEY (resource_id) REFERENCES dbo.resources (resource_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_access_grants_entitlement')
    ALTER TABLE dbo.access_grants ADD CONSTRAINT FK_access_grants_entitlement
        FOREIGN KEY (entitlement_id) REFERENCES dbo.entitlements (entitlement_id) ON DELETE NO ACTION;
GO

-- Rules A & C: Time-bound access only, permanent prohibited
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_access_grants_dates')
    ALTER TABLE dbo.access_grants ADD CONSTRAINT CK_access_grants_dates
        CHECK (expires_at > granted_at);
GO

-- Rules F & G: Explicit status transitions including REVOKE_PENDING
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_access_grants_status')
    ALTER TABLE dbo.access_grants ADD CONSTRAINT CK_access_grants_status
        CHECK (status IN ('PROVISIONING_PENDING', 'ACTIVE', 'REVOKE_PENDING', 'REVOKED', 'EXPIRED'));
GO

-- ------------------------------------------------------------------------------
-- 11. provisioning_events Constraints & Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_provisioning_events_grant')
    ALTER TABLE dbo.provisioning_events ADD CONSTRAINT FK_provisioning_events_grant
        FOREIGN KEY (grant_id) REFERENCES dbo.access_grants (grant_id) ON DELETE CASCADE;
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_provisioning_events_type')
    ALTER TABLE dbo.provisioning_events ADD CONSTRAINT CK_provisioning_events_type
        CHECK (event_type IN ('PROVISION_REQUESTED', 'PROVISION_SUCCEEDED', 'PROVISION_FAILED'));
GO

-- ------------------------------------------------------------------------------
-- 12. revocation_jobs Constraints & Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_revocation_jobs_grant')
    ALTER TABLE dbo.revocation_jobs ADD CONSTRAINT FK_revocation_jobs_grant
        FOREIGN KEY (grant_id) REFERENCES dbo.access_grants (grant_id) ON DELETE CASCADE;
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_revocation_jobs_trigger')
    ALTER TABLE dbo.revocation_jobs ADD CONSTRAINT CK_revocation_jobs_trigger
        CHECK (trigger_source IN ('SCHEDULED_EXPIRATION', 'ENGAGEMENT_TERMINATION', 'REVIEW_REJECTION', 'MANUAL_EMERGENCY'));
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_revocation_jobs_status')
    ALTER TABLE dbo.revocation_jobs ADD CONSTRAINT CK_revocation_jobs_status
        CHECK (status IN ('QUEUED', 'IN_PROGRESS', 'FAILED_RETRY', 'CONFIRMED'));
GO

-- ------------------------------------------------------------------------------
-- 13. access_reviews Constraints & Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_access_reviews_initiator')
    ALTER TABLE dbo.access_reviews ADD CONSTRAINT FK_access_reviews_initiator
        FOREIGN KEY (initiated_by_user_id) REFERENCES dbo.users (user_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_access_reviews_dates')
    ALTER TABLE dbo.access_reviews ADD CONSTRAINT CK_access_reviews_dates
        CHECK (due_date > start_date);
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_access_reviews_status')
    ALTER TABLE dbo.access_reviews ADD CONSTRAINT CK_access_reviews_status
        CHECK (status IN ('DRAFT', 'ACTIVE', 'COMPLETED', 'EXPIRED'));
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_access_reviews_campaign')
    ALTER TABLE dbo.access_reviews ADD CONSTRAINT CK_access_reviews_campaign
        CHECK (campaign_type IN ('PERIODIC_RECERTIFICATION', 'TRIGGERED_OFFBOARDING', 'SECURITY_AUDIT'));
GO

-- ------------------------------------------------------------------------------
-- 14. review_items Constraints & Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_review_items_review')
    ALTER TABLE dbo.review_items ADD CONSTRAINT FK_review_items_review
        FOREIGN KEY (review_id) REFERENCES dbo.access_reviews (review_id) ON DELETE CASCADE;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_review_items_grant')
    ALTER TABLE dbo.review_items ADD CONSTRAINT FK_review_items_grant
        FOREIGN KEY (grant_id) REFERENCES dbo.access_grants (grant_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_review_items_reviewer')
    ALTER TABLE dbo.review_items ADD CONSTRAINT FK_review_items_reviewer
        FOREIGN KEY (reviewer_user_id) REFERENCES dbo.users (user_id) ON DELETE NO ACTION;
GO

IF NOT EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UQ_review_items_review_grant')
    ALTER TABLE dbo.review_items ADD CONSTRAINT UQ_review_items_review_grant
        UNIQUE NONCLUSTERED (review_id ASC, grant_id ASC);
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_review_items_decision')
    ALTER TABLE dbo.review_items ADD CONSTRAINT CK_review_items_decision
        CHECK (decision IN ('PENDING', 'MAINTAIN', 'REVOKE'));
GO

-- ------------------------------------------------------------------------------
-- 15. audit_events Constraints & Foreign Keys
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_audit_events_actor')
    ALTER TABLE dbo.audit_events ADD CONSTRAINT FK_audit_events_actor
        FOREIGN KEY (actor_user_id) REFERENCES dbo.users (user_id) ON DELETE SET NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_audit_events_actor_type')
    ALTER TABLE dbo.audit_events ADD CONSTRAINT CK_audit_events_actor_type
        CHECK (actor_type IN ('USER', 'SYSTEM_TIMER', 'CONNECTOR_CALLBACK'));
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_audit_events_category')
    ALTER TABLE dbo.audit_events ADD CONSTRAINT CK_audit_events_category
        CHECK (event_category IN ('ACCESS_REQUEST', 'APPROVAL', 'GRANT', 'PROVISIONING', 'REVOCATION', 'RECERTIFICATION', 'SECURITY_POLICY'));
GO
