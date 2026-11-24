-- ==============================================================================
-- AccessLease Seed Script: 003_access_workflow_seed.sql
-- Description: Seeds resource owners, high-risk catalogue resources, entitlements,
--              and role assignments for the multi-stage approval workflow.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- ==============================================================================
-- Production Safety Guardrail:
-- Prevents accidental execution of test user seeding on production databases.
-- ==============================================================================
DECLARE @DbName NVARCHAR(128) = DB_NAME();
IF @DbName NOT LIKE '%Test%' AND @DbName NOT LIKE '%Dev%' AND @DbName NOT LIKE '%Local%'
BEGIN
    RAISERROR(N'SAFETY CHECK BLOCKED: 003_access_workflow_seed.sql contains test-only Entra IDs and cannot be executed against production database %s.', 16, 1, @DbName);
    RETURN;
END;
GO

-- 1. Ensure Roles Exist (Lookup)
DECLARE @OwnerRoleId INT, @SecurityRoleId INT;
SELECT @OwnerRoleId = role_id FROM dbo.roles WHERE role_code = N'RESOURCE_OWNER';
SELECT @SecurityRoleId = role_id FROM dbo.roles WHERE role_code = N'SECURITY_OFFICER';

-- 2. Seed Resource Owner Identity (Rachel Owner)
DECLARE @OwnerUserId UNIQUEIDENTIFIER;
SELECT @OwnerUserId = user_id FROM dbo.users WHERE entra_object_id = N'TEST-OID-OWNER';

IF @OwnerUserId IS NULL
BEGIN
    INSERT INTO dbo.users (
        entra_object_id,
        email,
        first_name,
        last_name,
        display_name,
        user_type,
        department,
        is_active,
        created_at,
        updated_at
    )
    VALUES (
        N'TEST-OID-OWNER',
        N'owner@example.com',
        N'Rachel',
        N'Owner',
        N'Rachel Resource Owner',
        N'INTERNAL_EMPLOYEE',
        N'Data Platform Engineering',
        1,
        SYSDATETIMEOFFSET(),
        SYSDATETIMEOFFSET()
    );
    SELECT @OwnerUserId = user_id FROM dbo.users WHERE entra_object_id = N'TEST-OID-OWNER';
END;

IF @OwnerUserId IS NOT NULL AND @OwnerRoleId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM dbo.user_roles WHERE user_id = @OwnerUserId AND role_id = @OwnerRoleId
)
BEGIN
    INSERT INTO dbo.user_roles (user_id, role_id, assigned_at)
    VALUES (@OwnerUserId, @OwnerRoleId, SYSDATETIMEOFFSET());
END;

-- 3. Seed Security Officer Identity (Sam Security)
DECLARE @SecurityUserId UNIQUEIDENTIFIER;
SELECT @SecurityUserId = user_id FROM dbo.users WHERE entra_object_id = N'TEST-OID-SECURITY';

IF @SecurityUserId IS NULL
BEGIN
    INSERT INTO dbo.users (
        entra_object_id,
        email,
        first_name,
        last_name,
        display_name,
        user_type,
        department,
        is_active,
        created_at,
        updated_at
    )
    VALUES (
        N'TEST-OID-SECURITY',
        N'security@example.com',
        N'Sam',
        N'Security',
        N'Sam Security Officer',
        N'INTERNAL_EMPLOYEE',
        N'Information Security',
        1,
        SYSDATETIMEOFFSET(),
        SYSDATETIMEOFFSET()
    );
    SELECT @SecurityUserId = user_id FROM dbo.users WHERE entra_object_id = N'TEST-OID-SECURITY';
END;

IF @SecurityUserId IS NOT NULL AND @SecurityRoleId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM dbo.user_roles WHERE user_id = @SecurityUserId AND role_id = @SecurityRoleId
)
BEGIN
    INSERT INTO dbo.user_roles (user_id, role_id, assigned_at)
    VALUES (@SecurityUserId, @SecurityRoleId, SYSDATETIMEOFFSET());
END;

-- 4. Assign Rachel Owner as PRIMARY owner of RES-DB-TEST
DECLARE @DbResourceId UNIQUEIDENTIFIER;
SELECT @DbResourceId = resource_id FROM dbo.resources WHERE resource_code = N'RES-DB-TEST';

IF @DbResourceId IS NOT NULL AND @OwnerUserId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM dbo.resource_owners WHERE resource_id = @DbResourceId AND owner_user_id = @OwnerUserId
)
BEGIN
    INSERT INTO dbo.resource_owners (resource_id, owner_user_id, ownership_type, assigned_at)
    VALUES (@DbResourceId, @OwnerUserId, N'PRIMARY', SYSDATETIMEOFFSET());
END;

-- 5. Seed High-Risk Resource: RES-PROD-KUBE (Kubernetes Production Cluster)
DECLARE @KubeResourceId UNIQUEIDENTIFIER;
SELECT @KubeResourceId = resource_id FROM dbo.resources WHERE resource_code = N'RES-PROD-KUBE';

IF @KubeResourceId IS NULL
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
        N'RES-PROD-KUBE',
        N'Production Kubernetes Cluster (EKS/AKS)',
        N'CLOUD_SUBSCRIPTION',
        N'Production workload infrastructure. Access restricted to certified cloud engineers.',
        N'CRITICAL',
        1,
        30,
        1,
        SYSDATETIMEOFFSET(),
        SYSDATETIMEOFFSET()
    );
    SELECT @KubeResourceId = resource_id FROM dbo.resources WHERE resource_code = N'RES-PROD-KUBE';
END;

-- Assign Rachel Owner to RES-PROD-KUBE
IF @KubeResourceId IS NOT NULL AND @OwnerUserId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM dbo.resource_owners WHERE resource_id = @KubeResourceId AND owner_user_id = @OwnerUserId
)
BEGIN
    INSERT INTO dbo.resource_owners (resource_id, owner_user_id, ownership_type, assigned_at)
    VALUES (@KubeResourceId, @OwnerUserId, N'PRIMARY', SYSDATETIMEOFFSET());
END;

-- Seed Entitlement for RES-PROD-KUBE
DECLARE @KubeEntitlementId UNIQUEIDENTIFIER;
SELECT @KubeEntitlementId = entitlement_id FROM dbo.entitlements WHERE resource_id = @KubeResourceId AND entitlement_code = N'CLUSTER_ADMIN';

IF @KubeEntitlementId IS NULL AND @KubeResourceId IS NOT NULL
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
        @KubeResourceId,
        N'CLUSTER_ADMIN',
        N'Cluster Administrator',
        N'Full administrative privileges on the Kubernetes production cluster.',
        N'CRITICAL',
        1,
        SYSDATETIMEOFFSET(),
        SYSDATETIMEOFFSET()
    );
END;

-- 6. Seed Standard Low-Risk Resource: RES-CORP-WIKI (Internal Documentation Wiki)
DECLARE @WikiResourceId UNIQUEIDENTIFIER;
SELECT @WikiResourceId = resource_id FROM dbo.resources WHERE resource_code = N'RES-CORP-WIKI';

IF @WikiResourceId IS NULL
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
        N'RES-CORP-WIKI',
        N'Corporate Engineering Wiki & Documentation',
        N'INTERNAL_APP',
        N'Standard internal documentation repository and runbooks.',
        N'LOW',
        0,
        90,
        1,
        SYSDATETIMEOFFSET(),
        SYSDATETIMEOFFSET()
    );
    SELECT @WikiResourceId = resource_id FROM dbo.resources WHERE resource_code = N'RES-CORP-WIKI';
END;

IF @WikiResourceId IS NOT NULL AND @OwnerUserId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM dbo.resource_owners WHERE resource_id = @WikiResourceId AND owner_user_id = @OwnerUserId
)
BEGIN
    INSERT INTO dbo.resource_owners (resource_id, owner_user_id, ownership_type, assigned_at)
    VALUES (@WikiResourceId, @OwnerUserId, N'PRIMARY', SYSDATETIMEOFFSET());
END;

-- Seed Entitlement for RES-CORP-WIKI
DECLARE @WikiEntitlementId UNIQUEIDENTIFIER;
SELECT @WikiEntitlementId = entitlement_id FROM dbo.entitlements WHERE resource_id = @WikiResourceId AND entitlement_code = N'WIKI_CONTRIBUTOR';

IF @WikiEntitlementId IS NULL AND @WikiResourceId IS NOT NULL
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
        @WikiResourceId,
        N'WIKI_CONTRIBUTOR',
        N'Wiki Contributor',
        N'Read and edit access to engineering documentation and runbooks.',
        N'LOW',
        1,
        SYSDATETIMEOFFSET(),
        SYSDATETIMEOFFSET()
    );
END;
GO

