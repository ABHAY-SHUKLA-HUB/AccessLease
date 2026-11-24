-- ==============================================================================
-- AccessLease Schema Migration: 014_orphan_access_findings.sql
-- Description: Creates dbo.orphan_access_findings table and enhances access review
--              and revocation trigger status constraints.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- 1. Create dbo.orphan_access_findings
IF OBJECT_ID(N'dbo.orphan_access_findings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.orphan_access_findings (
        finding_id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWSEQUENTIALID(),
        grant_id UNIQUEIDENTIFIER NOT NULL,
        finding_reason NVARCHAR(100) NOT NULL,
        severity NVARCHAR(30) NOT NULL,
        status NVARCHAR(30) NOT NULL DEFAULT 'OPEN',
        details NVARCHAR(MAX) NULL,
        first_detected_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        last_detected_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        resolved_at DATETIMEOFFSET NULL,
        resolved_by_user_id UNIQUEIDENTIFIER NULL,
        resolution_notes NVARCHAR(1000) NULL,
        revocation_job_id UNIQUEIDENTIFIER NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_orphan_access_findings PRIMARY KEY CLUSTERED (finding_id ASC),
        CONSTRAINT FK_orphan_findings_grant FOREIGN KEY (grant_id) REFERENCES dbo.access_grants (grant_id) ON DELETE NO ACTION,
        CONSTRAINT FK_orphan_findings_resolver FOREIGN KEY (resolved_by_user_id) REFERENCES dbo.users (user_id) ON DELETE NO ACTION,
        CONSTRAINT FK_orphan_findings_rev_job FOREIGN KEY (revocation_job_id) REFERENCES dbo.revocation_jobs (job_id) ON DELETE NO ACTION,
        CONSTRAINT CK_orphan_findings_severity CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
        CONSTRAINT CK_orphan_findings_status CHECK (status IN ('OPEN', 'RESOLVED', 'FALSE_POSITIVE', 'INVESTIGATING', 'REVOCATION_INITIATED'))
    );

    -- Enforce uniqueness of active findings per grant and reason (prevents duplicate findings on repeated scans)
    CREATE UNIQUE NONCLUSTERED INDEX UQ_orphan_findings_active_reason
    ON dbo.orphan_access_findings (grant_id ASC, finding_reason ASC)
    WHERE status IN ('OPEN', 'INVESTIGATING');

    -- Performance index for filtered queries and security analytics
    CREATE NONCLUSTERED INDEX IX_orphan_findings_status_severity
    ON dbo.orphan_access_findings (status ASC, severity ASC, last_detected_at DESC)
    INCLUDE (finding_reason, grant_id);
END;
GO

-- 2. Expand access_reviews status constraint to accept IN_PROGRESS and CANCELLED
IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_access_reviews_status')
BEGIN
    ALTER TABLE dbo.access_reviews DROP CONSTRAINT CK_access_reviews_status;
    ALTER TABLE dbo.access_reviews ADD CONSTRAINT CK_access_reviews_status
        CHECK (status IN ('DRAFT', 'ACTIVE', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'EXPIRED'));
END;
GO

-- 3. Expand revocation_jobs trigger constraint to accept ORPHAN_DETECTION
IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_revocation_jobs_trigger')
BEGIN
    ALTER TABLE dbo.revocation_jobs DROP CONSTRAINT CK_revocation_jobs_trigger;
    ALTER TABLE dbo.revocation_jobs ADD CONSTRAINT CK_revocation_jobs_trigger
        CHECK (trigger_source IN ('SCHEDULED_EXPIRATION', 'ENGAGEMENT_TERMINATION', 'REVIEW_REJECTION', 'MANUAL_EMERGENCY', 'ORPHAN_DETECTION'));
END;
GO
