-- ==============================================================================
-- AccessLease Seed Script: 001_system_roles_seed.sql
-- Description: Canonical system RBAC roles (Reference Lookup Data).
-- Note: Does NOT contain dummy users, fake contractors, or fabricated grants.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

MERGE dbo.roles AS target
USING (
    VALUES
        (N'SYSTEM_ADMIN', N'System Administrator', N'Full administrative control over AccessLease system configuration and connectors'),
        (N'SECURITY_OFFICER', N'Security Officer', N'Authorized to review and approve high-risk access requests and emergency interventions'),
        (N'COMPLIANCE_AUDITOR', N'Compliance Auditor', N'Read-only access to audit events, reports, and recertification records'),
        (N'RESOURCE_OWNER', N'Resource Owner', N'Authorized to approve access requests and conduct reviews for assigned resources'),
        (N'INTERNAL_SPONSOR', N'Internal Business Sponsor', N'Internal employee responsible for contractor oversight and lease sponsorship'),
        (N'CONTRACTOR', N'External Contractor', N'Temporary external contractor identity with time-bound access entitlements')
) AS source (role_code, role_name, description)
ON target.role_code = source.role_code
WHEN MATCHED THEN
    UPDATE SET
        target.role_name = source.role_name,
        target.description = source.description
WHEN NOT MATCHED THEN
    INSERT (role_code, role_name, description, created_at)
    VALUES (source.role_code, source.role_name, source.description, SYSDATETIMEOFFSET());
GO
