-- ==============================================================================
-- AccessLease Schema Migration: 015_orphan_index_hardening.sql
-- Description: Hardens orphan access findings deduplication index by including
--              REVOCATION_INITIATED status in the unique filtered index.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- 1. Drop existing filtered index if present
IF EXISTS (
    SELECT 1 FROM sys.indexes
    WHERE name = N'UQ_orphan_findings_active_reason'
      AND object_id = OBJECT_ID(N'dbo.orphan_access_findings', N'U')
)
BEGIN
    DROP INDEX UQ_orphan_findings_active_reason ON dbo.orphan_access_findings;
END;
GO

-- 2. Create hardened unique filtered index covering OPEN, INVESTIGATING, and REVOCATION_INITIATED
CREATE UNIQUE NONCLUSTERED INDEX UQ_orphan_findings_active_reason
ON dbo.orphan_access_findings (grant_id ASC, finding_reason ASC)
WHERE status IN ('OPEN', 'INVESTIGATING', 'REVOCATION_INITIATED');
GO

