-- ==============================================================================
-- AccessLease Database Migration: 005_create_activation_procedure.sql
-- Description: Stored procedure sp_ActivateApprovedGrant for atomic, validated grant activation.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID(N'dbo.sp_ActivateApprovedGrant', N'P') IS NOT NULL
    DROP PROCEDURE dbo.sp_ActivateApprovedGrant;
GO

CREATE PROCEDURE dbo.sp_ActivateApprovedGrant
    @RequestId UNIQUEIDENTIFIER,
    @ActorUserId UNIQUEIDENTIFIER = NULL,
    @GrantId UNIQUEIDENTIFIER = NULL OUTPUT,
    @GrantNumber NVARCHAR(30) = NULL OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @EngagementId UNIQUEIDENTIFIER;
    DECLARE @ResourceId UNIQUEIDENTIFIER;
    DECLARE @EntitlementId UNIQUEIDENTIFIER;
    DECLARE @RequestStatus NVARCHAR(30);
    DECLARE @RequiresSecurityApproval BIT;
    DECLARE @RequestedEndDate DATETIMEOFFSET;

    DECLARE @EngagementStatus NVARCHAR(30);
    DECLARE @EngagementEndDate DATE;
    DECLARE @MaxDurationDays INT;

    DECLARE @EffectiveExpiry DATETIMEOFFSET;
    DECLARE @MaxResourceExpiry DATETIMEOFFSET;
    DECLARE @EngagementEndOffset DATETIMEOFFSET;

    DECLARE @NewGrantId UNIQUEIDENTIFIER;
    DECLARE @NewGrantNumber NVARCHAR(30);
    DECLARE @CurrentTime DATETIMEOFFSET = SYSDATETIMEOFFSET();

    BEGIN TRY
        BEGIN TRANSACTION;

        -- 1. Validate Access Request Existence and acquire exclusive update lock
        SELECT
            @EngagementId = ar.contractor_engagement_id,
            @ResourceId = ar.resource_id,
            @EntitlementId = ar.entitlement_id,
            @RequestStatus = ar.status,
            @RequiresSecurityApproval = ar.requires_security_approval,
            @RequestedEndDate = ar.requested_end_date
        FROM dbo.access_requests ar WITH (UPDLOCK, HOLDLOCK)
        WHERE ar.request_id = @RequestId;

        IF @EngagementId IS NULL
        BEGIN
            THROW 50001, 'Validation Failed: The specified access request ID does not exist.', 1;
        END;

        -- 2. Validate Request Status is APPROVED
        IF @RequestStatus <> 'APPROVED'
        BEGIN
            THROW 50002, 'Validation Failed: Access request cannot be activated because its status is not APPROVED.', 1;
        END;

        -- 3. Verify All Required Approvals Completed
        DECLARE @TotalSteps INT;
        DECLARE @ApprovedSteps INT;

        SELECT
            @TotalSteps = COUNT(*),
            @ApprovedSteps = SUM(CASE WHEN status = 'APPROVED' THEN 1 ELSE 0 END)
        FROM dbo.approval_steps
        WHERE request_id = @RequestId;

        IF @TotalSteps = 0 OR @TotalSteps <> @ApprovedSteps
        BEGIN
            THROW 50003, 'Validation Failed: Not all required approval workflow steps have been approved.', 1;
        END;

        -- Rule E: High-risk access request must have completed Security approval
        IF @RequiresSecurityApproval = 1
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM dbo.approval_steps
                WHERE request_id = @RequestId
                  AND step_type = 'SECURITY_APPROVAL'
                  AND status = 'APPROVED'
            )
            BEGIN
                THROW 50004, 'Validation Failed: High-risk resource requires an explicit, approved SECURITY_APPROVAL step.', 1;
            END;
        END;

        -- 4. Validate Contractor Engagement Status and Dates
        SELECT
            @EngagementStatus = ce.status,
            @EngagementEndDate = ce.end_date
        FROM dbo.contractor_engagements ce
        WHERE ce.engagement_id = @EngagementId;

        IF @EngagementStatus <> 'ACTIVE'
        BEGIN
            THROW 50005, 'Validation Failed: The associated contractor engagement is not in ACTIVE status.', 1;
        END;

        IF CAST(@CurrentTime AS DATE) > @EngagementEndDate
        BEGIN
            THROW 50006, 'Validation Failed: The contractor engagement has already passed its scheduled end date.', 1;
        END;

        -- 5. Calculate and Enforce Deterministic Maximum Allowed Expiry
        SELECT @MaxDurationDays = r.max_lease_duration_days
        FROM dbo.resources r
        WHERE r.resource_id = @ResourceId;

        IF @MaxDurationDays IS NULL OR @MaxDurationDays <= 0
            SET @MaxDurationDays = 90;

        SET @MaxResourceExpiry = DATEADD(DAY, @MaxDurationDays, @CurrentTime);
        SET @EngagementEndOffset = TODATETIMEOFFSET(DATEADD(SECOND, 86399, CAST(@EngagementEndDate AS DATETIME2)), '+00:00');

        -- Start with the requested end date
        SET @EffectiveExpiry = @RequestedEndDate;

        -- Bound by maximum policy duration
        IF @EffectiveExpiry > @MaxResourceExpiry
            SET @EffectiveExpiry = @MaxResourceExpiry;

        -- Critical Rule B: Access expiry must never exceed contractor engagement end date
        IF @EffectiveExpiry > @EngagementEndOffset
            SET @EffectiveExpiry = @EngagementEndOffset;

        IF @EffectiveExpiry <= @CurrentTime
        BEGIN
            THROW 50007, 'Validation Failed: Calculated access expiry timestamp is in the past or invalid.', 1;
        END;

        -- 6. Prevent Duplicate Active Grants (Rule I)
        IF EXISTS (
            SELECT 1
            FROM dbo.access_grants WITH (UPDLOCK, HOLDLOCK)
            WHERE contractor_engagement_id = @EngagementId
              AND entitlement_id = @EntitlementId
              AND status IN ('ACTIVE', 'PROVISIONING_PENDING')
        )
        BEGIN
            THROW 50008, 'Conflict: An active or provisioning grant already exists for this contractor and entitlement.', 1;
        END;

        -- 7. Generate Grant Identifiers and Persist
        SET @NewGrantId = NEWID();
        SET @NewGrantNumber = N'AG-' + FORMAT(@CurrentTime, N'yyyyMMdd-HHmmss-') + RIGHT(CAST(@NewGrantId AS NVARCHAR(36)), 4);

        INSERT INTO dbo.access_grants (
            grant_id,
            grant_number,
            request_id,
            contractor_engagement_id,
            resource_id,
            entitlement_id,
            granted_at,
            expires_at,
            status,
            created_at,
            updated_at
        )
        VALUES (
            @NewGrantId,
            @NewGrantNumber,
            @RequestId,
            @EngagementId,
            @ResourceId,
            @EntitlementId,
            @CurrentTime,
            @EffectiveExpiry,
            'ACTIVE',
            @CurrentTime,
            @CurrentTime
        );

        -- 8. Record Immutable Audit Event
        INSERT INTO dbo.audit_events (
            event_category,
            event_action,
            entity_type,
            entity_id,
            actor_user_id,
            actor_type,
            event_payload,
            created_at
        )
        VALUES (
            'GRANT',
            'GRANT_ACTIVATED',
            'access_grants',
            CAST(@NewGrantId AS NVARCHAR(64)),
            @ActorUserId,
            CASE WHEN @ActorUserId IS NULL THEN 'SYSTEM_TIMER' ELSE 'USER' END,
            CONCAT(
                N'{"grant_number":"', @NewGrantNumber,
                N'","request_id":"', CAST(@RequestId AS NVARCHAR(36)),
                N'","expires_at":"', CONVERT(NVARCHAR(33), @EffectiveExpiry, 127),
                N'","max_duration_days":', @MaxDurationDays,
                N'}'
            ),
            @CurrentTime
        );

        -- Set output parameters
        SET @GrantId = @NewGrantId;
        SET @GrantNumber = @NewGrantNumber;

        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0
            ROLLBACK TRANSACTION;

        THROW;
    END CATCH;
END;
GO
