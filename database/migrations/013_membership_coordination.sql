-- ==============================================================================
-- AccessLease Schema Migration: 013_membership_coordination.sql
-- Description: Creates dbo.membership_coordination table for cross-connector
--              membership coordination between provisioning and revocation engines.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID(N'dbo.membership_coordination', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.membership_coordination (
        coordination_key NVARCHAR(100) NOT NULL,
        target_org NVARCHAR(100) NOT NULL,
        target_team_slug NVARCHAR(100) NOT NULL,
        account_identifier NVARCHAR(100) NOT NULL,
        active_operation NVARCHAR(30) NOT NULL DEFAULT 'IDLE',
        operation_job_id UNIQUEIDENTIFIER NULL,
        worker_id NVARCHAR(100) NULL,
        lease_expires_at DATETIMEOFFSET NULL,
        last_reconciled_at DATETIMEOFFSET NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_membership_coordination PRIMARY KEY CLUSTERED (coordination_key ASC),
        CONSTRAINT CK_membership_coord_op CHECK (active_operation IN ('IDLE', 'PROVISIONING', 'REVOCATION'))
    );

    CREATE NONCLUSTERED INDEX IX_membership_coord_lease
    ON dbo.membership_coordination (active_operation ASC, lease_expires_at ASC)
    INCLUDE (operation_job_id, worker_id);
END;
GO

