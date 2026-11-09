-- ==============================================================================
-- AccessLease Database Migration: 006_create_contractor_expiry_trigger.sql
-- Description: Set-based trigger tr_ContractorGrantMustExpire enforcing mandatory time boundaries.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID(N'dbo.tr_ContractorGrantMustExpire', N'TR') IS NOT NULL
    DROP TRIGGER dbo.tr_ContractorGrantMustExpire;
GO

CREATE TRIGGER dbo.tr_ContractorGrantMustExpire
ON dbo.access_grants
AFTER INSERT, UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    -- Optimization: Exit early if no rows were affected
    IF NOT EXISTS (SELECT 1 FROM inserted)
        RETURN;

    -- Enforce Critical Business Rules A & C:
    -- Every grant must have a valid expiration date strictly in the future relative to grant date.
    IF EXISTS (
        SELECT 1
        FROM inserted i
        WHERE i.expires_at IS NULL
           OR i.expires_at <= i.granted_at
    )
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 51001, 'Trigger Violation: Contractor access grants must have a valid future expiration timestamp (expires_at > granted_at). Permanent access is strictly prohibited.', 1;
        RETURN;
    END;

    -- Enforce Critical Business Rule B:
    -- Access grant expiry must never exceed the contractor engagement end date (end of engagement day).
    IF EXISTS (
        SELECT 1
        FROM inserted i
        INNER JOIN dbo.contractor_engagements ce ON ce.engagement_id = i.contractor_engagement_id
        WHERE i.expires_at > TODATETIMEOFFSET(DATEADD(SECOND, 86399, CAST(ce.end_date AS DATETIME2)), '+00:00')
    )
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 51002, 'Trigger Violation: Contractor access grant expiration cannot exceed the contractor engagement end date.', 1;
        RETURN;
    END;
END;
GO
