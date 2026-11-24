-- ==============================================================================
-- AccessLease Seed Script: 002_user_provisioning_seed.sql
-- Description: Provisions the corporate administrator / identity sponsor identity
--              and assigns SYSTEM_ADMIN and INTERNAL_SPONSOR roles.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @EntraObjectId NVARCHAR(64) = N'f2bba284-9dba-4570-b865-875a009870ed';
DECLARE @Email NVARCHAR(256) = N'shuklaabhayas0@gmail.com';
DECLARE @FirstName NVARCHAR(64) = N'Abhay';
DECLARE @LastName NVARCHAR(64) = N'Shukla';
DECLARE @DisplayName NVARCHAR(128) = N'Abhay Shukla';
DECLARE @UserType NVARCHAR(30) = N'INTERNAL_EMPLOYEE';
DECLARE @Department NVARCHAR(100) = N'Identity & Access Management';

DECLARE @UserId UNIQUEIDENTIFIER;

-- 1. Upsert User Record
SELECT @UserId = user_id FROM dbo.users WHERE entra_object_id = @EntraObjectId;

IF @UserId IS NULL
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
        @EntraObjectId,
        @Email,
        @FirstName,
        @LastName,
        @DisplayName,
        @UserType,
        @Department,
        1,
        SYSDATETIMEOFFSET(),
        SYSDATETIMEOFFSET()
    );

    SELECT @UserId = user_id FROM dbo.users WHERE entra_object_id = @EntraObjectId;
END
ELSE
BEGIN
    UPDATE dbo.users
    SET is_active = 1,
        email = @Email,
        first_name = @FirstName,
        last_name = @LastName,
        display_name = @DisplayName,
        department = @Department,
        updated_at = SYSDATETIMEOFFSET()
    WHERE user_id = @UserId;
END;

-- 2. Assign SYSTEM_ADMIN Role (role_code = 'SYSTEM_ADMIN')
DECLARE @AdminRoleId INT;
SELECT @AdminRoleId = role_id FROM dbo.roles WHERE role_code = N'SYSTEM_ADMIN';

IF @AdminRoleId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM dbo.user_roles WHERE user_id = @UserId AND role_id = @AdminRoleId)
BEGIN
    INSERT INTO dbo.user_roles (user_id, role_id, assigned_at, assigned_by_user_id)
    VALUES (@UserId, @AdminRoleId, SYSDATETIMEOFFSET(), NULL);
END;

-- 3. Assign INTERNAL_SPONSOR Role (role_code = 'INTERNAL_SPONSOR')
DECLARE @SponsorRoleId INT;
SELECT @SponsorRoleId = role_id FROM dbo.roles WHERE role_code = N'INTERNAL_SPONSOR';

IF @SponsorRoleId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM dbo.user_roles WHERE user_id = @UserId AND role_id = @SponsorRoleId)
BEGIN
    INSERT INTO dbo.user_roles (user_id, role_id, assigned_at, assigned_by_user_id)
    VALUES (@UserId, @SponsorRoleId, SYSDATETIMEOFFSET(), NULL);
END;

-- 4. Seed roles for local development and integration test identities
DECLARE @TestSponsorUserId UNIQUEIDENTIFIER, @TestContractorUserId UNIQUEIDENTIFIER;
SELECT @TestSponsorUserId = user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-SPONSOR';
SELECT @TestContractorUserId = user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-CONTRACTOR';

DECLARE @ContractorRoleId INT;
SELECT @ContractorRoleId = role_id FROM dbo.roles WHERE role_code = N'CONTRACTOR';

IF @TestSponsorUserId IS NOT NULL AND @SponsorRoleId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM dbo.user_roles WHERE user_id = @TestSponsorUserId AND role_id = @SponsorRoleId)
BEGIN
    INSERT INTO dbo.user_roles (user_id, role_id, assigned_at)
    VALUES (@TestSponsorUserId, @SponsorRoleId, SYSDATETIMEOFFSET());
END;

IF @TestContractorUserId IS NOT NULL AND @ContractorRoleId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM dbo.user_roles WHERE user_id = @TestContractorUserId AND role_id = @ContractorRoleId)
BEGIN
    INSERT INTO dbo.user_roles (user_id, role_id, assigned_at)
    VALUES (@TestContractorUserId, @ContractorRoleId, SYSDATETIMEOFFSET());
END;
GO

