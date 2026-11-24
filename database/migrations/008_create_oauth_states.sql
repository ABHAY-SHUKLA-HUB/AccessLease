-- ==============================================================================
-- AccessLease Schema Migration: 008_create_oauth_states.sql
-- Description: Establishes durable server-side OAuth state storage for one-time
--              atomic consumption, PKCE code_verifier persistence, and replay protection.
-- Target: Microsoft SQL Server 2019+ / Azure SQL Database
-- ==============================================================================

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID(N'dbo.oauth_states', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.oauth_states (
        state_nonce NVARCHAR(100) NOT NULL,
        user_id UNIQUEIDENTIFIER NOT NULL,
        code_verifier NVARCHAR(200) NULL,
        expires_at DATETIMEOFFSET NOT NULL,
        is_consumed BIT NOT NULL DEFAULT 0,
        consumed_at DATETIMEOFFSET NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_oauth_states PRIMARY KEY CLUSTERED (state_nonce ASC),
        CONSTRAINT FK_oauth_states_user FOREIGN KEY (user_id) REFERENCES dbo.users (user_id) ON DELETE CASCADE
    );

    CREATE NONCLUSTERED INDEX IX_oauth_states_user_expiry
        ON dbo.oauth_states (user_id ASC, expires_at ASC)
        INCLUDE (is_consumed);
END;
GO

