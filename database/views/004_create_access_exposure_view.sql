-- ==============================================================================
-- AccessLease View Definition: 004_create_access_exposure_view.sql
-- Description: Creates the governance view v_AccessExposureQueue.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID(N'dbo.v_AccessExposureQueue', N'V') IS NOT NULL
    DROP VIEW dbo.v_AccessExposureQueue;
GO

CREATE VIEW dbo.v_AccessExposureQueue
AS
SELECT
    ag.grant_id,
    ag.grant_number,
    ag.status AS grant_status,
    ag.granted_at,
    ag.expires_at,

    -- Contractor details
    cu.user_id AS contractor_user_id,
    cu.display_name AS contractor_name,
    cu.email AS contractor_email,
    cu.entra_object_id AS contractor_entra_id,
    ce.vendor_name,
    ce.contract_reference,

    -- Engagement details
    ce.engagement_id,
    ce.status AS engagement_status,
    ce.start_date AS engagement_start_date,
    ce.end_date AS engagement_end_date,

    -- Internal Accountable Sponsor details (Owned requirement)
    su.user_id AS sponsor_user_id,
    su.display_name AS sponsor_name,
    su.email AS sponsor_email,
    su.department AS sponsor_department,

    -- Resource & Entitlement details
    r.resource_id,
    r.resource_code,
    r.resource_name,
    r.resource_type,
    r.risk_level AS resource_risk_level,
    e.entitlement_id,
    e.entitlement_code,
    e.entitlement_name,
    e.sensitivity_level AS entitlement_sensitivity,

    -- Quantitative exposure metrics (time calculation in UTC)
    DATEDIFF(MINUTE, SYSDATETIMEOFFSET(), ag.expires_at) AS minutes_until_grant_expiry,
    DATEDIFF(DAY, CAST(SYSDATETIMEOFFSET() AS DATE), ce.end_date) AS days_until_engagement_expiry,

    -- Exposure Classification Category
    CASE
        -- Exposure 1: Access grant is marked ACTIVE but current timestamp has exceeded expires_at
        WHEN ag.status = 'ACTIVE' AND ag.expires_at < SYSDATETIMEOFFSET()
            THEN 'EXPIRED_STILL_ACTIVE'

        -- Exposure 2: Contractor engagement has ended or terminated, yet access grant remains ACTIVE
        WHEN ag.status = 'ACTIVE' AND (ce.status IN ('TERMINATED', 'COMPLETED') OR CAST(SYSDATETIMEOFFSET() AS DATE) > ce.end_date)
            THEN 'ENGAGEMENT_TERMINATED_ACCESS_ACTIVE'

        -- Exposure 3: Grant marked for revocation but downstream connector has not confirmed completion
        WHEN ag.status = 'REVOKE_PENDING'
            THEN 'REVOCATION_PENDING_CONFIRMATION'

        -- Exposure 4: Access expires within 48 hours
        WHEN ag.status = 'ACTIVE' AND ag.expires_at <= DATEADD(HOUR, 48, SYSDATETIMEOFFSET())
            THEN 'EXPIRING_WITHIN_48H'

        -- Exposure 5: Access expires within 7 days
        WHEN ag.status = 'ACTIVE' AND ag.expires_at <= DATEADD(DAY, 7, SYSDATETIMEOFFSET())
            THEN 'EXPIRING_WITHIN_7D'

        -- Exposure 6: Critical risk resource currently held
        WHEN ag.status = 'ACTIVE' AND (r.risk_level = 'CRITICAL' OR e.sensitivity_level = 'CRITICAL')
            THEN 'CRITICAL_RISK_ACTIVE'

        -- Baseline active grant
        WHEN ag.status = 'ACTIVE'
            THEN 'ACTIVE_GOVERNED'

        ELSE ag.status
    END AS exposure_category,

    -- Exposure Severity Ranking
    CASE
        WHEN (ag.status = 'ACTIVE' AND ag.expires_at < SYSDATETIMEOFFSET())
          OR (ag.status = 'ACTIVE' AND (ce.status IN ('TERMINATED', 'COMPLETED') OR CAST(SYSDATETIMEOFFSET() AS DATE) > ce.end_date))
          OR (ag.status = 'REVOKE_PENDING')
            THEN 'CRITICAL'

        WHEN (ag.status = 'ACTIVE' AND ag.expires_at <= DATEADD(HOUR, 48, SYSDATETIMEOFFSET()))
          OR (ag.status = 'ACTIVE' AND r.risk_level = 'CRITICAL')
            THEN 'HIGH'

        WHEN (ag.status = 'ACTIVE' AND ag.expires_at <= DATEADD(DAY, 7, SYSDATETIMEOFFSET()))
          OR (ag.status = 'ACTIVE' AND r.risk_level = 'HIGH')
            THEN 'MEDIUM'

        ELSE 'LOW'
    END AS exposure_severity

FROM dbo.access_grants ag
INNER JOIN dbo.contractor_engagements ce ON ce.engagement_id = ag.contractor_engagement_id
INNER JOIN dbo.users cu ON cu.user_id = ce.contractor_user_id
INNER JOIN dbo.users su ON su.user_id = ce.sponsor_user_id
INNER JOIN dbo.resources r ON r.resource_id = ag.resource_id
INNER JOIN dbo.entitlements e ON e.entitlement_id = ag.entitlement_id;
GO
