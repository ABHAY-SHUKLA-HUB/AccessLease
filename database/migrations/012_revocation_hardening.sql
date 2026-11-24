-- ==============================================================================
-- AccessLease Schema Migration: 012_revocation_hardening.sql
-- Description: Adds filtered unique index on dbo.revocation_jobs to strictly enforce
--              single active job per grant across all trigger sources.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- 1. Unique filtered index to prevent duplicate active revocation jobs per grant
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UQ_rev_jobs_active_grant' AND object_id = OBJECT_ID('dbo.revocation_jobs'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX UQ_rev_jobs_active_grant
    ON dbo.revocation_jobs (grant_id ASC)
    WHERE status IN ('QUEUED', 'PROCESSING', 'IN_PROGRESS', 'FAILED_RETRY', 'MANUAL_REVIEW_REQUIRED');
END;
GO

