/**
 * AccessLease — Contractor External Identity Repository
 * Handles data access for dbo.user_external_identities.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Finds external identity by user ID and provider.
 * @param {string} userId GUID
 * @param {string} [provider='GITHUB']
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findIdentityByUserAndProvider(userId, provider = 'GITHUB', transaction = null) {
    if (!userId || typeof userId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('userId', sql.UniqueIdentifier, userId.trim())
            .input('provider', sql.NVarChar(50), provider.trim().toUpperCase())
            .query(`
                SELECT TOP 1
                    uei.identity_id,
                    uei.user_id,
                    uei.provider,
                    uei.external_account_id,
                    uei.external_username,
                    uei.verification_status,
                    uei.verified_at,
                    uei.verified_by_user_id,
                    uei.created_at,
                    uei.updated_at,
                    u.email,
                    u.display_name,
                    u.user_type
                FROM dbo.user_external_identities uei
                INNER JOIN dbo.users u ON uei.user_id = u.user_id
                WHERE uei.user_id = @userId AND uei.provider = @provider;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findIdentityByUserAndProvider', { userId, provider, error: err.message });
        throw new DatabaseError('Failed to query contractor external identity.', err);
    }
}

/**
 * Finds user and identity by provider and external username.
 * @param {string} provider 'GITHUB'
 * @param {string} externalUsername External login/handle
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findUserByExternalUsername(provider, externalUsername, transaction = null) {
    if (!externalUsername || typeof externalUsername !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('provider', sql.NVarChar(50), (provider || 'GITHUB').trim().toUpperCase())
            .input('externalUsername', sql.NVarChar(100), externalUsername.trim().toLowerCase())
            .query(`
                SELECT TOP 1
                    uei.identity_id,
                    uei.user_id,
                    uei.provider,
                    uei.external_account_id,
                    uei.external_username,
                    uei.verification_status,
                    uei.verified_at,
                    uei.verified_by_user_id,
                    u.email,
                    u.display_name,
                    u.user_type,
                    u.is_active
                FROM dbo.user_external_identities uei
                INNER JOIN dbo.users u ON uei.user_id = u.user_id
                WHERE uei.provider = @provider AND LOWER(uei.external_username) = @externalUsername;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findUserByExternalUsername', { provider, externalUsername, error: err.message });
        throw new DatabaseError('Failed to query user by external username.', err);
    }
}

/**
 * Creates or updates an external identity record.
 * @param {object} identityData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function upsertExternalIdentity(identityData, transaction = null) {
    const {
        userId,
        provider = 'GITHUB',
        externalAccountId = null,
        externalUsername,
        verificationStatus = 'UNVERIFIED',
        verifiedByUserId = null
    } = identityData;

    try {
        const runner = transaction || await getPool();
        const verifiedAt = verificationStatus === 'VERIFIED' ? new Date() : null;

        const result = await runner.request()
            .input('userId', sql.UniqueIdentifier, userId.trim())
            .input('provider', sql.NVarChar(50), provider.trim().toUpperCase())
            .input('externalAccountId', sql.NVarChar(100), externalAccountId ? String(externalAccountId).trim() : null)
            .input('externalUsername', sql.NVarChar(100), externalUsername.trim())
            .input('verificationStatus', sql.NVarChar(30), verificationStatus.trim().toUpperCase())
            .input('verifiedByUserId', sql.UniqueIdentifier, verifiedByUserId ? verifiedByUserId.trim() : null)
            .input('verifiedAt', sql.DateTimeOffset, verifiedAt)
            .query(`
                MERGE dbo.user_external_identities WITH (HOLDLOCK) AS target
                USING (SELECT @userId AS user_id, @provider AS provider) AS source
                ON (target.user_id = source.user_id AND target.provider = source.provider)
                WHEN MATCHED THEN
                    UPDATE SET
                        external_account_id = @externalAccountId,
                        external_username = @externalUsername,
                        verification_status = @verificationStatus,
                        verified_by_user_id = @verifiedByUserId,
                        verified_at = COALESCE(@verifiedAt, target.verified_at),
                        updated_at = SYSDATETIMEOFFSET()
                WHEN NOT MATCHED THEN
                    INSERT (
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
                        @userId,
                        @provider,
                        @externalAccountId,
                        @externalUsername,
                        @verificationStatus,
                        @verifiedByUserId,
                        @verifiedAt,
                        SYSDATETIMEOFFSET(),
                        SYSDATETIMEOFFSET()
                    )
                OUTPUT
                    INSERTED.identity_id,
                    INSERTED.user_id,
                    INSERTED.provider,
                    INSERTED.external_account_id,
                    INSERTED.external_username,
                    INSERTED.verification_status,
                    INSERTED.verified_at,
                    INSERTED.verified_by_user_id,
                    INSERTED.created_at,
                    INSERTED.updated_at;
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database query failed in upsertExternalIdentity', { userId, provider, error: err.message });
        throw new DatabaseError('Failed to upsert contractor external identity.', err);
    }
}

/**
 * Marks an external identity as VERIFIED by an authorized user.
 * @param {string} identityId GUID
 * @param {string} verifiedByUserId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function verifyExternalIdentity(identityId, verifiedByUserId, transaction = null) {
    if (!identityId || !verifiedByUserId) return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('identityId', sql.UniqueIdentifier, identityId.trim())
            .input('verifiedByUserId', sql.UniqueIdentifier, verifiedByUserId.trim())
            .query(`
                UPDATE dbo.user_external_identities
                SET
                    verification_status = 'VERIFIED',
                    verified_by_user_id = @verifiedByUserId,
                    verified_at = SYSDATETIMEOFFSET(),
                    updated_at = SYSDATETIMEOFFSET()
                OUTPUT
                    INSERTED.identity_id,
                    INSERTED.user_id,
                    INSERTED.provider,
                    INSERTED.external_username,
                    INSERTED.verification_status,
                    INSERTED.verified_at,
                    INSERTED.verified_by_user_id
                WHERE identity_id = @identityId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in verifyExternalIdentity', { identityId, error: err.message });
        throw new DatabaseError('Failed to verify external identity.', err);
    }
}

/**
 * Finds external identity by provider and external account ID (e.g. numeric GitHub ID).
 * @param {string} provider 'GITHUB'
 * @param {string} externalAccountId
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findIdentityByProviderAndAccountId(provider, externalAccountId, transaction = null) {
    if (!externalAccountId) return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('provider', sql.NVarChar(50), (provider || 'GITHUB').trim().toUpperCase())
            .input('externalAccountId', sql.NVarChar(100), String(externalAccountId).trim())
            .query(`
                SELECT TOP 1
                    identity_id,
                    user_id,
                    provider,
                    external_account_id,
                    external_username,
                    verification_status,
                    verified_at,
                    verified_by_user_id,
                    created_at,
                    updated_at
                FROM dbo.user_external_identities
                WHERE provider = @provider AND external_account_id = @externalAccountId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findIdentityByProviderAndAccountId', { provider, externalAccountId, error: err.message });
        throw new DatabaseError('Failed to query external identity by account ID.', err);
    }
}

/**
 * Revokes / unlinks an external identity.
 * @param {string} identityId GUID
 * @param {string} actorUserId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function revokeExternalIdentity(identityId, actorUserId, transaction = null) {
    if (!identityId) return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('identityId', sql.UniqueIdentifier, identityId.trim())
            .input('actorUserId', sql.UniqueIdentifier, actorUserId ? actorUserId.trim() : null)
            .query(`
                UPDATE dbo.user_external_identities
                SET
                    verification_status = 'REVOKED',
                    updated_at = SYSDATETIMEOFFSET()
                OUTPUT
                    INSERTED.identity_id,
                    INSERTED.user_id,
                    INSERTED.provider,
                    INSERTED.external_account_id,
                    INSERTED.external_username,
                    INSERTED.verification_status,
                    INSERTED.verified_at,
                    INSERTED.updated_at
                WHERE identity_id = @identityId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in revokeExternalIdentity', { identityId, error: err.message });
        throw new DatabaseError('Failed to revoke external identity.', err);
    }
}

/**
 * Permanently deletes an external identity record (e.g. for full unlink/cleanup).
 * @param {string} identityId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<boolean>}
 */
async function deleteExternalIdentity(identityId, transaction = null) {
    if (!identityId) return false;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('identityId', sql.UniqueIdentifier, identityId.trim())
            .query(`DELETE FROM dbo.user_external_identities WHERE identity_id = @identityId;`);

        return (result.rowsAffected && result.rowsAffected[0] > 0);
    } catch (err) {
        logger.error('Database query failed in deleteExternalIdentity', { identityId, error: err.message });
        throw new DatabaseError('Failed to delete external identity.', err);
    }
}

module.exports = {
    findIdentityByUserAndProvider,
    findUserByExternalUsername,
    findIdentityByProviderAndAccountId,
    upsertExternalIdentity,
    verifyExternalIdentity,
    revokeExternalIdentity,
    deleteExternalIdentity
};

