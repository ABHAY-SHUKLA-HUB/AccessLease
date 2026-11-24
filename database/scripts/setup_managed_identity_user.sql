-- ==============================================================================
-- AccessLease — Production Azure SQL Database Setup Script
-- Managed Identity Database Principal & Least-Privilege Role Provisioning
-- Target: Azure SQL Database (accesslease-db)
-- Driver / Auth: Microsoft Entra System-Assigned Managed Identity
-- ==============================================================================
--
-- PREREQUISITES & EXECUTION INSTRUCTIONS:
-- 1. This script MUST be executed by an authorized Microsoft Entra administrator
--    (e.g., the identity configured via sqlEntraAdminLogin / sqlEntraAdminSid in Bicep).
--    SQL administrator logins (e.g. 'sqladmin') CANNOT create users FROM EXTERNAL PROVIDER
--    or WITH SID ... TYPE = E.
--
-- 2. The Azure Function App MUST already be provisioned so that its System-Assigned
--    Managed Identity exists in Microsoft Entra ID.
--
-- 3. Identifiers required from deployment / Entra ID:
--    - FUNCTION_APP_NAME: Resource name (Bicep output: functionAppName)
--    - MANAGED_IDENTITY_CLIENT_ID: Client ID / Application ID (resolved via az ad sp show from principalId)
--    * CRITICAL IDENTITY DISTINCTION:
--      - Client ID (Application ID): Converted to varbinary(16) SID for CREATE USER ... WITH SID = ..., TYPE = E.
--        Bypasses Microsoft Graph lookups; requires zero Directory Readers permissions.
--        Note: Insecure fallback to CREATE USER ... FROM EXTERNAL PROVIDER is strictly disabled to prevent
--        Graph-lookup failure or unintentional directory role dependency.
--      - Principal ID (Object ID): Reserved for Azure RBAC role assignments (Key Vault Secrets User). NOT the database SID.
--      - Tenant ID: The Microsoft Entra directory ID.
--
-- 4. Execution environments & SQLCMD variables:
--    - SQLCMD CLI: Pass variables via -v parameters:
--        sqlcmd -S "<server>.database.windows.net" -d "accesslease-db" --authentication-method ActiveDirectoryDefault \
--          -v FUNCTION_APP_NAME="func-accesslease-dev-uniqueid" \
--          -v MANAGED_IDENTITY_CLIENT_ID="<functionAppClientId-guid>" \
--          -i database/scripts/setup_managed_identity_user.sql
--    - SSMS / Azure Data Studio: Enable SQLCMD Mode ("Query" -> "SQLCMD Mode") before executing,
--        or replace placeholders directly in DECLARE statements on lines 54-55.
--    - ADO.NET / PowerShell: Replace placeholders in text and execute directly as a single batch (no GO delimiter).
--
-- 5. Execute this script against the target application database 'accesslease-db',
--    NOT against the 'master' database.
-- ==============================================================================

SET NOCOUNT ON;
SET XACT_ABORT ON;

-- Guardrail: Ensure not executing against master
IF DB_NAME() = N'master'
BEGIN
    RAISERROR(N'ERROR: This script must be executed in the application database (accesslease-db), not in master.', 16, 1);
    RETURN;
END;

PRINT N'==============================================================================';
PRINT N'AccessLease — Provisioning Managed Identity Least-Privilege Permissions';
PRINT N'Current Database: ' + DB_NAME();
PRINT N'Current User:     ' + SUSER_SNAME();
PRINT N'==============================================================================';

-- -----------------------------------------------------------------------------
-- Step 1: Input Validation & SID Derivation (Pre-Execution Validation)
-- -----------------------------------------------------------------------------
DECLARE @ManagedIdentityName NVARCHAR(128) = N'$(FUNCTION_APP_NAME)';
DECLARE @ManagedIdentityClientId NVARCHAR(64) = N'$(MANAGED_IDENTITY_CLIENT_ID)';

-- 1.1 Validate Function App name is not empty
IF @ManagedIdentityName IS NULL OR LTRIM(RTRIM(@ManagedIdentityName)) = N''
BEGIN
    RAISERROR(N'ERROR: Function App Managed Identity name ($(FUNCTION_APP_NAME)) cannot be empty.', 16, 1);
    RETURN;
END;

-- 1.2 Validate Client ID is a valid UNIQUEIDENTIFIER (Strict: No fallback to live Graph lookup)
IF TRY_CAST(@ManagedIdentityClientId AS UNIQUEIDENTIFIER) IS NULL
BEGIN
    RAISERROR(N'ERROR: Managed Identity Client ID ($(MANAGED_IDENTITY_CLIENT_ID)) is missing, empty, or not a valid UNIQUEIDENTIFIER GUID. Live directory fallback is disabled.', 16, 1);
    RETURN;
END;

-- 1.3 Calculate expected binary SID and hexadecimal representation before any modifications
-- Note: CONVERT(VARCHAR(34), @binSid, 1) is used instead of deprecated sys.fn_varbintohexstr for Azure SQL compatibility.
DECLARE @binSid VARBINARY(16) = CAST(CAST(@ManagedIdentityClientId AS UNIQUEIDENTIFIER) AS VARBINARY(16));
DECLARE @hexSid VARCHAR(34) = CONVERT(VARCHAR(34), @binSid, 1);

PRINT N'[OK] Validated parameters. Derived Client ID SID: ' + @hexSid;

-- -----------------------------------------------------------------------------
-- Step 2: Validate Existing Managed Identity Principal (Pre-Execution Verification)
-- -----------------------------------------------------------------------------
DECLARE @ExistingPrincipalId INT;
DECLARE @ExistingType CHAR(1);
DECLARE @ExistingTypeDesc NVARCHAR(60);
DECLARE @ExistingAuthTypeDesc NVARCHAR(60);
DECLARE @ExistingSid VARBINARY(85);

SELECT 
    @ExistingPrincipalId = principal_id,
    @ExistingType = type,
    @ExistingTypeDesc = type_desc,
    @ExistingAuthTypeDesc = authentication_type_desc,
    @ExistingSid = sid
FROM sys.database_principals 
WHERE name = @ManagedIdentityName;

IF @ExistingPrincipalId IS NOT NULL
BEGIN
    -- Verify principal type is 'E' (EXTERNAL_USER) (reject NULL or non-E types)
    IF @ExistingType IS NULL OR @ExistingType <> 'E'
    BEGIN
        DECLARE @PrintType NVARCHAR(60) = ISNULL(CAST(@ExistingType AS NVARCHAR(60)), N'NULL');
        DECLARE @PrintTypeDesc NVARCHAR(60) = ISNULL(@ExistingTypeDesc, N'UNKNOWN');
        RAISERROR(N'ERROR: Principal [%s] already exists but is of type %s (%s). Expected type E (EXTERNAL_USER). Halting setup before making any database modifications.', 16, 1, @ManagedIdentityName, @PrintType, @PrintTypeDesc);
        RETURN;
    END;

    -- Verify authentication type is 'EXTERNAL' (reject NULL or non-EXTERNAL authentication)
    IF @ExistingAuthTypeDesc IS NULL OR @ExistingAuthTypeDesc <> N'EXTERNAL'
    BEGIN
        DECLARE @PrintAuthTypeDesc NVARCHAR(60) = ISNULL(@ExistingAuthTypeDesc, N'NULL');
        RAISERROR(N'ERROR: Principal [%s] already exists but has authentication type %s. Expected EXTERNAL. Halting setup before making any database modifications.', 16, 1, @ManagedIdentityName, @PrintAuthTypeDesc);
        RETURN;
    END;

    -- Verify SID exactly matches expected Client ID binary SID (reject NULL or mismatched SID)
    IF @ExistingSid IS NULL OR @ExistingSid <> @binSid
    BEGIN
        DECLARE @ExistingSidHex VARCHAR(174) = ISNULL(CONVERT(VARCHAR(174), @ExistingSid, 1), N'NULL');
        RAISERROR(N'ERROR: Principal [%s] already exists but its SID (%s) does not match expected Client ID SID (%s). Halting setup to prevent misconfigured authentication.', 16, 1, @ManagedIdentityName, @ExistingSidHex, @hexSid);
        RETURN;
    END;

    PRINT N'[INFO] Verified existing principal [' + @ManagedIdentityName + N'] has matching Client ID SID (' + @hexSid + N') and EXTERNAL_USER type.';
END;

-- -----------------------------------------------------------------------------
-- Step 3: Transactional Execution of Role, Grants, User & Role Membership
-- -----------------------------------------------------------------------------
BEGIN TRANSACTION;

BEGIN TRY
    -- 3.1 Create Dedicated Least-Privilege Database Role
    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'db_accesslease_app' AND type = 'R')
    BEGIN
        CREATE ROLE [db_accesslease_app];
        PRINT N'[OK] Created custom database role: db_accesslease_app';
    END
    ELSE
    BEGIN
        PRINT N'[INFO] Database role db_accesslease_app already exists.';
    END;

    -- 3.2 Grant Explicit Object-Level Table Permissions to db_accesslease_app
    -- Strict least-privilege: Grants only required SELECT, INSERT, UPDATE, DELETE.
    -- Explicitly prohibits: DROP, ALTER, TRUNCATE, CONTROL, db_owner, db_securityadmin.

    -- Core Identity, Roles, and Governance Tables
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.users TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.contractor_engagements TO [db_accesslease_app];
    GRANT SELECT ON dbo.roles TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.user_roles TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.resources TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.entitlements TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.resource_owners TO [db_accesslease_app];

    -- Request, Workflow, and Lifecycle Tables
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.access_requests TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.approval_steps TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.access_grants TO [db_accesslease_app];
    GRANT SELECT, INSERT ON dbo.provisioning_events TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.revocation_jobs TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.access_reviews TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.review_items TO [db_accesslease_app];
    GRANT SELECT, INSERT ON dbo.audit_events TO [db_accesslease_app];

    -- Connector, Provisioning, and Fencing Coordination Tables
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.user_external_identities TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.connector_resource_mappings TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.provisioning_jobs TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.oauth_states TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.membership_coordination TO [db_accesslease_app];
    GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.orphan_access_findings TO [db_accesslease_app];

    PRINT N'[OK] Granted table-level DML permissions to db_accesslease_app.';

    -- 3.3 Grant View Permissions
    IF OBJECT_ID(N'dbo.v_AccessExposureQueue', N'V') IS NOT NULL
    BEGIN
        GRANT SELECT ON dbo.v_AccessExposureQueue TO [db_accesslease_app];
        PRINT N'[OK] Granted SELECT on view dbo.v_AccessExposureQueue to db_accesslease_app.';
    END;

    -- 3.4 Grant Stored Procedure Execution Permissions
    IF OBJECT_ID(N'dbo.sp_ActivateApprovedGrant', N'P') IS NOT NULL
    BEGIN
        GRANT EXECUTE ON dbo.sp_ActivateApprovedGrant TO [db_accesslease_app];
        PRINT N'[OK] Granted EXECUTE on procedure dbo.sp_ActivateApprovedGrant to db_accesslease_app.';
    END;

    -- Note: sys.sp_getapplock and sys.sp_releaseapplock (used for distributed lease fencing)
    -- are system stored procedures granted to the 'public' database role by default in SQL Server.

    -- 3.5 Create Microsoft Entra External Database Principal with Client ID SID
    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @ManagedIdentityName)
    BEGIN
        DECLARE @createWithSidSql NVARCHAR(MAX) = N'CREATE USER [' + REPLACE(@ManagedIdentityName, ']', ']]') + N'] WITH SID = ' + @hexSid + N', TYPE = E;';
        EXEC sp_executesql @createWithSidSql;
        PRINT N'[OK] Created Microsoft Entra user for: [' + @ManagedIdentityName + N'] using Client ID SID (' + @hexSid + N') [bypassed live directory lookup].';
    END
    ELSE
    BEGIN
        PRINT N'[INFO] Database principal already exists for: [' + @ManagedIdentityName + N'].';
    END;

    -- 3.6 Add Principal to db_accesslease_app Role if not already a member
    IF EXISTS (
        SELECT 1
        FROM sys.database_role_members rm
        JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
        JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id
        WHERE r.name = N'db_accesslease_app' AND m.name = @ManagedIdentityName
    )
    BEGIN
        PRINT N'[INFO] Principal [' + @ManagedIdentityName + N'] is already a member of role [db_accesslease_app].';
    END
    ELSE
    BEGIN
        DECLARE @roleMemberSql NVARCHAR(MAX) = N'ALTER ROLE [db_accesslease_app] ADD MEMBER [' + REPLACE(@ManagedIdentityName, ']', ']]') + N'];';
        EXEC sp_executesql @roleMemberSql;
        PRINT N'[OK] Added [' + @ManagedIdentityName + N'] to database role [db_accesslease_app].';
    END;

    -- All operations succeeded: Commit transaction
    COMMIT TRANSACTION;
    PRINT N'[SUCCESS] Managed Identity database setup committed successfully.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0
    BEGIN
        ROLLBACK TRANSACTION;
    END;

    PRINT N'[ERROR] Transaction failed and was rolled back cleanly. Zero changes committed to ' + DB_NAME();
    THROW;
END CATCH;

-- -----------------------------------------------------------------------------
-- Step 4: Verification Summary Query
-- -----------------------------------------------------------------------------
PRINT N'';
PRINT N'==============================================================================';
PRINT N'Role Members of db_accesslease_app:';
PRINT N'==============================================================================';
SELECT 
    r.name AS [RoleName],
    m.name AS [MemberName],
    m.type_desc AS [MemberType],
    m.authentication_type_desc AS [AuthenticationType]
FROM sys.database_role_members rm
JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id
WHERE r.name = N'db_accesslease_app';
PRINT N'==============================================================================';
PRINT N'[SUCCESS] Setup script finished successfully.';
PRINT N'==============================================================================';
