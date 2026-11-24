-- ==============================================================================
-- AccessLease Seed Script: 004_github_provisioning_seed.sql
-- Description: Seeds GitHub repository resource, entitlement, connector mapping,
--              and verified contractor external identity for testing Prompt 06.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- Production Safety Guardrail
DECLARE @DbName NVARCHAR(128) = DB_NAME();
IF @DbName NOT LIKE '%Test%' AND @DbName NOT LIKE '%Dev%' AND @DbName NOT LIKE '%Local%'
BEGIN
    RAISERROR(N'SAFETY CHECK BLOCKED: 004_github_provisioning_seed.sql contains test data and cannot be executed against production database %s.', 16, 1, @DbName);
    RETURN;
END;
GO

-- 1. Resolve Required Test Identities
DECLARE @ContractorUserId UNIQUEIDENTIFIER, @OwnerUserId UNIQUEIDENTIFIER, @SecurityUserId UNIQUEIDENTIFIER;
SELECT @ContractorUserId = user_id FROM dbo.users WHERE entra_object_id = N'TEST-OID-CONTRACTOR';
SELECT @OwnerUserId = user_id FROM dbo.users WHERE entra_object_id = N'TEST-OID-OWNER';
SELECT @SecurityUserId = user_id FROM dbo.users WHERE entra_object_id = N'TEST-OID-SECURITY';

-- 2. Seed Verified GitHub External Identity for Test Contractor
IF @ContractorUserId IS NOT NULL
BEGIN
    IF NOT EXISTS (SELECT 1 FROM dbo.user_external_identities WHERE user_id = @ContractorUserId AND provider = N'GITHUB')
    BEGIN
        INSERT INTO dbo.user_external_identities (
            user_id,
            provider,
            external_account_id,
            external_username,
            verification_status,
            verified_by_user_id,
            verified_at,
            created_at,
            updated_at
        )
        VALUES (
            @ContractorUserId,
            N'GITHUB',
            N'99182374',
            N'contractor-governance-test',
            N'VERIFIED',
            @SecurityUserId,
            SYSDATETIMEOFFSET(),
            SYSDATETIMEOFFSET(),
            SYSDATETIMEOFFSET()
        );
    END;
END;

-- 3. Seed GitHub Repository Resource (RES-GH-CORE-REPO)
DECLARE @RepoResourceId UNIQUEIDENTIFIER;
SELECT @RepoResourceId = resource_id FROM dbo.resources WHERE resource_code = N'RES-GH-CORE-REPO';

IF @RepoResourceId IS NULL
BEGIN
    INSERT INTO dbo.resources (
        resource_code,
        resource_name,
        resource_type,
        description,
        risk_level,
        requires_security_approval,
        max_lease_duration_days,
        is_active,
        created_at,
        updated_at
    )
    VALUES (
        N'RES-GH-CORE-REPO',
        N'AccessLease Core Governance Platform Repository',
        N'REPOSITORY',
        N'GitHub organization repository hosting primary enterprise governance codebase.',
        N'HIGH',
        1,
        60,
        1,
        SYSDATETIMEOFFSET(),
        SYSDATETIMEOFFSET()
    );
    SELECT @RepoResourceId = resource_id FROM dbo.resources WHERE resource_code = N'RES-GH-CORE-REPO';
END;

-- Assign Rachel Owner as PRIMARY owner
IF @RepoResourceId IS NOT NULL AND @OwnerUserId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM dbo.resource_owners WHERE resource_id = @RepoResourceId AND owner_user_id = @OwnerUserId
)
BEGIN
    INSERT INTO dbo.resource_owners (resource_id, owner_user_id, ownership_type, assigned_at)
    VALUES (@RepoResourceId, @OwnerUserId, N'PRIMARY', SYSDATETIMEOFFSET());
END;

-- 4. Seed Repository Entitlement (REPO_CORE_CONTRIBUTOR)
DECLARE @RepoEntitlementId UNIQUEIDENTIFIER;
SELECT @RepoEntitlementId = entitlement_id FROM dbo.entitlements WHERE resource_id = @RepoResourceId AND entitlement_code = N'REPO_CORE_CONTRIBUTOR';

IF @RepoEntitlementId IS NULL AND @RepoResourceId IS NOT NULL
BEGIN
    INSERT INTO dbo.entitlements (
        resource_id,
        entitlement_code,
        entitlement_name,
        description,
        sensitivity_level,
        is_active,
        created_at,
        updated_at
    )
    VALUES (
        @RepoResourceId,
        N'REPO_CORE_CONTRIBUTOR',
        N'Core Governance Repository Contributor',
        N'Write and commit access to the core platform repository via designated team.',
        N'HIGH',
        1,
        SYSDATETIMEOFFSET(),
        SYSDATETIMEOFFSET()
    );
    SELECT @RepoEntitlementId = entitlement_id FROM dbo.entitlements WHERE resource_id = @RepoResourceId AND entitlement_code = N'REPO_CORE_CONTRIBUTOR';
END;

-- 5. Seed Connector Resource Mapping in dbo.connector_resource_mappings
IF @RepoResourceId IS NOT NULL AND @RepoEntitlementId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM dbo.connector_resource_mappings WHERE resource_id = @RepoResourceId AND entitlement_id = @RepoEntitlementId AND connector_type = N'GITHUB'
)
BEGIN
    INSERT INTO dbo.connector_resource_mappings (
        resource_id,
        entitlement_id,
        connector_type,
        github_org,
        github_team_slug,
        github_repo_owner,
        github_repo_name,
        required_permission,
        is_active,
        created_at,
        updated_at
    )
    VALUES (
        @RepoResourceId,
        @RepoEntitlementId,
        N'GITHUB',
        N'accesslease-org',
        N'contractor-engineering-team',
        N'accesslease-org',
        N'accesslease-governance',
        N'push',
        1,
        SYSDATETIMEOFFSET(),
        SYSDATETIMEOFFSET()
    );
END;
GO
