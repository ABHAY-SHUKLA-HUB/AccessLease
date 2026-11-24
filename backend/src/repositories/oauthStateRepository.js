/**
 * AccessLease — OAuth State Repository
 * Handles persistent, server-side OAuth 2.0 state and PKCE verifier storage.
 * Enforces atomic one-time consumption to prevent replay attacks across distributed instances.
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Persists an OAuth state nonce with PKCE code_verifier and TTL.
 * @param {object} params
 * @param {string} params.stateNonce Unique cryptographic nonce
 * @param {string} params.userId GUID of authenticated contractor
 * @param {string} [params.codeVerifier=null] PKCE code_verifier
 * @param {Date} params.expiresAt Expiration timestamp
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function saveOAuthState(params, transaction = null) {
    const { stateNonce, userId, codeVerifier = null, expiresAt } = params;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('stateNonce', sql.NVarChar(100), stateNonce.trim())
            .input('userId', sql.UniqueIdentifier, userId.trim())
            .input('codeVerifier', sql.NVarChar(200), codeVerifier ? codeVerifier.trim() : null)
            .input('expiresAt', sql.DateTimeOffset, expiresAt)
            .query(`
                INSERT INTO dbo.oauth_states (
                    state_nonce,
                    user_id,
                    code_verifier,
                    expires_at,
                    is_consumed
                )
                VALUES (
                    @stateNonce,
                    @userId,
                    @codeVerifier,
                    @expiresAt,
                    0
                );
            `);

        return { stateNonce, userId, expiresAt };
    } catch (err) {
        logger.error('Database query failed in saveOAuthState', { stateNonce, userId, error: err.message });
        throw new DatabaseError('Failed to record OAuth state.', err);
    }
}

/**
 * Atomically consumes an OAuth state token.
 * Prevents replay attacks by ensuring a state can be consumed exactly once.
 * @param {string} stateNonce
 * @param {string} userId
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<{ outcome: 'CONSUMED'|'ALREADY_CONSUMED'|'EXPIRED'|'NOT_FOUND', state: object|null }>}
 */
async function consumeOAuthState(stateNonce, userId, transaction = null) {
    if (!stateNonce || !userId) {
        return { outcome: 'NOT_FOUND', state: null };
    }

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('stateNonce', sql.NVarChar(100), stateNonce.trim())
            .input('userId', sql.UniqueIdentifier, userId.trim())
            .query(`
                DECLARE @consumedTable TABLE (
                    state_nonce NVARCHAR(100),
                    user_id UNIQUEIDENTIFIER,
                    code_verifier NVARCHAR(200),
                    expires_at DATETIMEOFFSET,
                    was_consumed BIT
                );

                UPDATE dbo.oauth_states
                SET is_consumed = 1,
                    consumed_at = SYSDATETIMEOFFSET()
                OUTPUT
                    INSERTED.state_nonce,
                    INSERTED.user_id,
                    INSERTED.code_verifier,
                    INSERTED.expires_at,
                    DELETED.is_consumed AS was_consumed
                INTO @consumedTable
                WHERE state_nonce = @stateNonce AND user_id = @userId;

                SELECT * FROM @consumedTable;
            `);

        if (result.recordset.length === 0) {
            return { outcome: 'NOT_FOUND', state: null };
        }

        const row = result.recordset[0];
        if (row.was_consumed === true || row.was_consumed === 1) {
            return { outcome: 'ALREADY_CONSUMED', state: row };
        }

        const now = new Date();
        if (new Date(row.expires_at) <= now) {
            return { outcome: 'EXPIRED', state: row };
        }

        return {
            outcome: 'CONSUMED',
            state: {
                stateNonce: row.state_nonce,
                userId: row.user_id,
                codeVerifier: row.code_verifier,
                expiresAt: row.expires_at
            }
        };
    } catch (err) {
        logger.error('Database query failed in consumeOAuthState', { stateNonce, userId, error: err.message });
        throw new DatabaseError('Failed to consume OAuth state.', err);
    }
}

/**
 * Removes expired states older than a given number of days.
 * @param {number} [daysOld=1]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<number>} Number of deleted rows
 */
async function deleteExpiredStates(daysOld = 1, transaction = null) {
    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('daysOld', sql.Int, daysOld)
            .query(`
                DELETE FROM dbo.oauth_states
                WHERE expires_at < DATEADD(DAY, -@daysOld, SYSDATETIMEOFFSET());
            `);

        return result.rowsAffected ? result.rowsAffected[0] : 0;
    } catch (err) {
        logger.error('Database query failed in deleteExpiredStates', { error: err.message });
        throw new DatabaseError('Failed to cleanup expired OAuth states.', err);
    }
}

module.exports = {
    saveOAuthState,
    consumeOAuthState,
    deleteExpiredStates
};

