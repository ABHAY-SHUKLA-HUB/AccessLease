/**
 * AccessLease — Access Grant & Exposure Queue Repository
 * Handles data access for dbo.access_grants, view dbo.v_AccessExposureQueue,
 * and stored procedure dbo.sp_ActivateApprovedGrant.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Finds an access grant by primary key grant_id.
 * @param {string} grantId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findGrantById(grantId, transaction = null) {
    if (!grantId || typeof grantId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('grantId', sql.UniqueIdentifier, grantId.trim())
            .query(`
                SELECT TOP 1
                    ag.grant_id,
                    ag.grant_number,
                    ag.request_id,
                    ag.contractor_engagement_id,
                    ag.resource_id,
                    ag.entitlement_id,
                    ag.granted_at,
                    ag.expires_at,
                    ag.status,
                    ag.revoked_at,
                    ag.revocation_reason,
                    ag.connector_type,
                    ag.target_org,
                    ag.target_team_slug,
                    ag.target_repo,
                    ag.external_username,
                    ag.numeric_account_id,
                    ag.membership_provenance,
                    ag.verified_at,
                    ag.failure_category,
                    ag.connector_metadata,
                    ag.created_at,
                    ag.updated_at,
                    r.resource_code,
                    r.resource_name,
                    r.risk_level AS resource_risk_level,
                    e.entitlement_code,
                    e.entitlement_name,
                    ce.vendor_name,
                    ce.contract_reference,
                    cu.user_id AS contractor_user_id,
                    cu.display_name AS contractor_name,
                    cu.email AS contractor_email,
                    su.display_name AS sponsor_name
                FROM dbo.access_grants ag
                INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
                INNER JOIN dbo.entitlements e ON ag.entitlement_id = e.entitlement_id
                INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
                INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
                INNER JOIN dbo.users su ON ce.sponsor_user_id = su.user_id
                WHERE ag.grant_id = @grantId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findGrantById', { grantId, error: err.message });
        throw new DatabaseError('Failed to find access grant by ID.', err);
    }
}

/**
 * Finds an access grant by unique grant_number.
 * @param {string} grantNumber E.g. 'AG-LEGIT-001'
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findGrantByNumber(grantNumber, transaction = null) {
    if (!grantNumber || typeof grantNumber !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('grantNumber', sql.NVarChar(30), grantNumber.trim())
            .query(`
                SELECT TOP 1
                    ag.grant_id,
                    ag.grant_number,
                    ag.request_id,
                    ag.contractor_engagement_id,
                    ag.resource_id,
                    ag.entitlement_id,
                    ag.granted_at,
                    ag.expires_at,
                    ag.status,
                    ag.revoked_at,
                    ag.revocation_reason,
                    ag.created_at,
                    ag.updated_at
                FROM dbo.access_grants ag
                WHERE ag.grant_number = @grantNumber;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findGrantByNumber', { grantNumber, error: err.message });
        throw new DatabaseError('Failed to find access grant by number.', err);
    }
}

/**
 * Lists access grants with optional filtering.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listGrants(filter = {}, transaction = null) {
    const { status, contractorEngagementId, resourceId, limit = 50, offset = 0 } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
                ag.grant_id,
                ag.grant_number,
                ag.request_id,
                ag.contractor_engagement_id,
                ag.resource_id,
                ag.entitlement_id,
                ag.granted_at,
                ag.expires_at,
                ag.status,
                ag.revoked_at,
                ag.revocation_reason,
                ag.created_at,
                ag.updated_at,
                r.resource_name,
                e.entitlement_name,
                cu.display_name AS contractor_name,
                ce.vendor_name
            FROM dbo.access_grants ag
            INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
            INNER JOIN dbo.entitlements e ON ag.entitlement_id = e.entitlement_id
            INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
            INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
            WHERE 1=1
        `;

        if (status) {
            sqlQuery += ` AND ag.status = @status`;
            request.input('status', sql.NVarChar(30), status);
        }

        if (contractorEngagementId) {
            sqlQuery += ` AND ag.contractor_engagement_id = @contractorEngagementId`;
            request.input('contractorEngagementId', sql.UniqueIdentifier, contractorEngagementId.trim());
        }

        if (resourceId) {
            sqlQuery += ` AND ag.resource_id = @resourceId`;
            request.input('resourceId', sql.UniqueIdentifier, resourceId.trim());
        }

        sqlQuery += ` ORDER BY ag.expires_at ASC OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;`;
        request.input('offset', sql.Int, Math.max(0, offset));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, limit)));

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listGrants', { error: err.message });
        throw new DatabaseError('Failed to list access grants.', err);
    }
}

/**
 * Creates an access grant record directly (e.g. for provisioning preparation or testing).
 * Note: Business activations should typically call activateApprovedGrant().
 * @param {object} grantData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function createGrant(grantData, transaction = null) {
    const {
        grantNumber,
        requestId,
        contractorEngagementId,
        resourceId,
        entitlementId,
        grantedAt = new Date(),
        expiresAt,
        status = 'ACTIVE',
        connectorType = null,
        targetOrg = null,
        targetTeamSlug = null,
        targetRepo = null,
        externalUsername = null,
        membershipProvenance = 'CREATED_BY_ACCESSLEASE',
        verifiedAt = null,
        failureCategory = null,
        connectorMetadata = null
    } = grantData;

    try {
        const runner = transaction || await getPool();
        const metadataStr = connectorMetadata && typeof connectorMetadata === 'object'
            ? JSON.stringify(connectorMetadata)
            : connectorMetadata;

        const result = await runner.request()
            .input('grantNumber', sql.NVarChar(30), grantNumber.trim())
            .input('requestId', sql.UniqueIdentifier, requestId.trim())
            .input('contractorEngagementId', sql.UniqueIdentifier, contractorEngagementId.trim())
            .input('resourceId', sql.UniqueIdentifier, resourceId.trim())
            .input('entitlementId', sql.UniqueIdentifier, entitlementId.trim())
            .input('grantedAt', sql.DateTimeOffset, grantedAt)
            .input('expiresAt', sql.DateTimeOffset, expiresAt)
            .input('status', sql.NVarChar(30), status)
            .input('connectorType', sql.NVarChar(50), connectorType)
            .input('targetOrg', sql.NVarChar(100), targetOrg)
            .input('targetTeamSlug', sql.NVarChar(100), targetTeamSlug)
            .input('targetRepo', sql.NVarChar(150), targetRepo)
            .input('externalUsername', sql.NVarChar(100), externalUsername)
            .input('membershipProvenance', sql.NVarChar(30), membershipProvenance)
            .input('verifiedAt', sql.DateTimeOffset, verifiedAt)
            .input('failureCategory', sql.NVarChar(50), failureCategory)
            .input('connectorMetadata', sql.NVarChar(sql.MAX), metadataStr)
            .query(`
                DECLARE @InsertedGrant TABLE (
                    grant_id UNIQUEIDENTIFIER,
                    grant_number NVARCHAR(30),
                    request_id UNIQUEIDENTIFIER,
                    contractor_engagement_id UNIQUEIDENTIFIER,
                    resource_id UNIQUEIDENTIFIER,
                    entitlement_id UNIQUEIDENTIFIER,
                    granted_at DATETIMEOFFSET,
                    expires_at DATETIMEOFFSET,
                    status NVARCHAR(30),
                    connector_type NVARCHAR(50),
                    target_org NVARCHAR(100),
                    target_team_slug NVARCHAR(100),
                    target_repo NVARCHAR(150),
                    external_username NVARCHAR(100),
                    membership_provenance NVARCHAR(30),
                    verified_at DATETIMEOFFSET,
                    failure_category NVARCHAR(50),
                    created_at DATETIMEOFFSET,
                    updated_at DATETIMEOFFSET
                );

                INSERT INTO dbo.access_grants (
                    grant_number,
                    request_id,
                    contractor_engagement_id,
                    resource_id,
                    entitlement_id,
                    granted_at,
                    expires_at,
                    status,
                    connector_type,
                    target_org,
                    target_team_slug,
                    target_repo,
                    external_username,
                    membership_provenance,
                    verified_at,
                    failure_category,
                    connector_metadata
                )
                OUTPUT
                    INSERTED.grant_id,
                    INSERTED.grant_number,
                    INSERTED.request_id,
                    INSERTED.contractor_engagement_id,
                    INSERTED.resource_id,
                    INSERTED.entitlement_id,
                    INSERTED.granted_at,
                    INSERTED.expires_at,
                    INSERTED.status,
                    INSERTED.connector_type,
                    INSERTED.target_org,
                    INSERTED.target_team_slug,
                    INSERTED.target_repo,
                    INSERTED.external_username,
                    INSERTED.membership_provenance,
                    INSERTED.verified_at,
                    INSERTED.failure_category,
                    INSERTED.created_at,
                    INSERTED.updated_at
                INTO @InsertedGrant
                VALUES (
                    @grantNumber,
                    @requestId,
                    @contractorEngagementId,
                    @resourceId,
                    @entitlementId,
                    @grantedAt,
                    @expiresAt,
                    @status,
                    @connectorType,
                    @targetOrg,
                    @targetTeamSlug,
                    @targetRepo,
                    @externalUsername,
                    @membershipProvenance,
                    @verifiedAt,
                    @failureCategory,
                    @connectorMetadata
                );

                SELECT * FROM @InsertedGrant;
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in createGrant', { grantNumber, error: err.message });
        throw new DatabaseError('Failed to create access grant.', err);
    }
}

/**
 * Updates grant status and records revocation/provenance/verification details.
 * @param {string} grantId GUID
 * @param {string} status 'PROVISIONING_PENDING', 'PROVISIONING_IN_PROGRESS', 'PENDING_ACCEPTANCE', 'ACTIVE', 'PROVISIONING_FAILED', 'REVOKE_PENDING', 'REVOKED', 'EXPIRED'
 * @param {object} [details={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function updateGrantStatus(grantId, status, details = {}, transaction = null) {
    const {
        revokedAt = null,
        revocationReason = null,
        verifiedAt = null,
        membershipProvenance = null,
        failureCategory = null,
        connectorMetadata = null
    } = details;

    try {
        const runner = transaction || await getPool();
        const request = runner.request()
            .input('grantId', sql.UniqueIdentifier, grantId.trim())
            .input('status', sql.NVarChar(30), status);

        let updateClause = 'status = @status, updated_at = SYSDATETIMEOFFSET()';

        if (status === 'REVOKED' || revokedAt) {
            updateClause += ', revoked_at = @revokedAt, revocation_reason = @revocationReason';
            request.input('revokedAt', sql.DateTimeOffset, revokedAt || new Date());
            request.input('revocationReason', sql.NVarChar(500), revocationReason);
        }

        if (verifiedAt) {
            updateClause += ', verified_at = @verifiedAt';
            request.input('verifiedAt', sql.DateTimeOffset, verifiedAt);
        }

        if (membershipProvenance) {
            updateClause += ', membership_provenance = @membershipProvenance';
            request.input('membershipProvenance', sql.NVarChar(30), membershipProvenance);
        }

        if (failureCategory) {
            updateClause += ', failure_category = @failureCategory';
            request.input('failureCategory', sql.NVarChar(50), failureCategory);
        }

        if (connectorMetadata) {
            const metaStr = typeof connectorMetadata === 'object' ? JSON.stringify(connectorMetadata) : connectorMetadata;
            updateClause += ', connector_metadata = @connectorMetadata';
            request.input('connectorMetadata', sql.NVarChar(sql.MAX), metaStr);
        }

        const result = await request.query(`
            DECLARE @UpdatedGrant TABLE (
                grant_id UNIQUEIDENTIFIER,
                grant_number NVARCHAR(30),
                status NVARCHAR(30),
                membership_provenance NVARCHAR(30),
                verified_at DATETIMEOFFSET,
                failure_category NVARCHAR(50),
                revoked_at DATETIMEOFFSET,
                revocation_reason NVARCHAR(500),
                updated_at DATETIMEOFFSET
            );

            UPDATE dbo.access_grants
            SET ${updateClause}
            OUTPUT
                INSERTED.grant_id,
                INSERTED.grant_number,
                INSERTED.status,
                INSERTED.membership_provenance,
                INSERTED.verified_at,
                INSERTED.failure_category,
                INSERTED.revoked_at,
                INSERTED.revocation_reason,
                INSERTED.updated_at
            INTO @UpdatedGrant
            WHERE grant_id = @grantId;

            SELECT * FROM @UpdatedGrant;
        `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database update failed in updateGrantStatus', { grantId, status, error: err.message });
        throw new DatabaseError('Failed to update grant status.', err);
    }
}

/**
 * Queries the active governance exposure queue from dbo.v_AccessExposureQueue.
 * @param {object} [filter={}] { severity, exposureCategory, limit, offset }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function getAccessExposureQueue(filter = {}, transaction = null) {
    const { severity, exposureCategory, limit = 50, offset = 0 } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
                q.grant_id,
                q.grant_number,
                q.grant_status,
                q.granted_at,
                q.expires_at,
                q.contractor_user_id,
                q.contractor_name,
                q.contractor_email,
                q.contractor_entra_id,
                q.vendor_name,
                q.contract_reference,
                q.engagement_id,
                q.engagement_status,
                q.engagement_start_date,
                q.engagement_end_date,
                q.sponsor_user_id,
                q.sponsor_name,
                q.sponsor_email,
                q.sponsor_department,
                q.resource_id,
                q.resource_code,
                q.resource_name,
                q.resource_type,
                q.resource_risk_level,
                q.entitlement_id,
                q.entitlement_code,
                q.entitlement_name,
                q.entitlement_sensitivity,
                q.minutes_until_grant_expiry,
                q.days_until_engagement_expiry,
                q.exposure_category,
                q.exposure_severity
            FROM dbo.v_AccessExposureQueue q
            WHERE 1=1
        `;

        if (severity) {
            sqlQuery += ` AND q.exposure_severity = @severity`;
            request.input('severity', sql.NVarChar(20), severity);
        }

        if (exposureCategory) {
            sqlQuery += ` AND q.exposure_category = @exposureCategory`;
            request.input('exposureCategory', sql.NVarChar(50), exposureCategory);
        }

        sqlQuery += ` ORDER BY q.minutes_until_grant_expiry ASC OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;`;
        request.input('offset', sql.Int, Math.max(0, offset));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, limit)));

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in getAccessExposureQueue', { error: err.message });
        throw new DatabaseError('Failed to query access exposure queue.', err);
    }
}

/**
 * Invokes stored procedure sp_ActivateApprovedGrant to atomically activate an approved grant.
 * @param {string} requestId GUID of approved access request
 * @param {string} [actorUserId=null] GUID of user or system activating grant
 * @returns {Promise<{ grantId: string, grantNumber: string }>}
 */
async function activateApprovedGrant(requestId, actorUserId = null) {
    if (!requestId || typeof requestId !== 'string') {
        throw new DatabaseError('requestId is required to activate an approved grant.');
    }

    try {
        const pool = await getPool();
        const request = pool.request()
            .input('RequestId', sql.UniqueIdentifier, requestId.trim())
            .input('ActorUserId', sql.UniqueIdentifier, actorUserId ? actorUserId.trim() : null)
            .output('GrantId', sql.UniqueIdentifier)
            .output('GrantNumber', sql.NVarChar(30));

        const result = await request.execute('dbo.sp_ActivateApprovedGrant');

        return {
            grantId: result.output.GrantId,
            grantNumber: result.output.GrantNumber
        };
    } catch (err) {
        logger.error('Stored procedure sp_ActivateApprovedGrant execution failed', {
            requestId,
            error: err.message
        });
        throw new DatabaseError(`Failed to activate grant: ${err.message}`, err);
    }
}

module.exports = {
    findGrantById,
    findGrantByNumber,
    listGrants,
    createGrant,
    updateGrantStatus,
    getAccessExposureQueue,
    activateApprovedGrant
};

