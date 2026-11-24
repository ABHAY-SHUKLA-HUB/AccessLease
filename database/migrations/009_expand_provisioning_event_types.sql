-- ==============================================================================
-- AccessLease Schema Migration: 009_expand_provisioning_event_types.sql
-- Description: Expands dbo.provisioning_events event_type CHECK constraint to include
--              MEMBERSHIP_MUTATION_CONFIRMED for safe membership provenance tracking.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_provisioning_events_type')
    ALTER TABLE dbo.provisioning_events DROP CONSTRAINT CK_provisioning_events_type;
GO

ALTER TABLE dbo.provisioning_events ADD CONSTRAINT CK_provisioning_events_type
    CHECK (event_type IN (
        'PROVISION_REQUESTED',
        'PROVISION_IN_PROGRESS',
        'MEMBERSHIP_DISCOVERED',
        'MEMBERSHIP_MUTATION_CONFIRMED',
        'INVITATION_PENDING',
        'PROVISION_SUCCEEDED',
        'PROVISION_FAILED',
        'RETRY_SCHEDULED',
        'MANUAL_RETRY'
    ));
GO

