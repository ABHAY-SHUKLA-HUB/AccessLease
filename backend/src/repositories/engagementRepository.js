/**
 * AccessLease — Contractor Engagement Repository
 * Handles data access for dbo.contractor_engagements.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Finds a contractor engagement by primary key.
 * @param {string} engagementId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findEngagementById(engagementId, transaction = null) {
    if (!engagementId || typeof engagementId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('engagementId', sql.UniqueIdentifier, engagementId.trim())
            .query(`
                SELECT TOP 1
                    ce.engagement_id,
                    ce.contractor_user_id,
                    ce.sponsor_user_id,
                    ce.vendor_name,
                    ce.contract_reference,
                    ce.start_date,
                    ce.end_date,
                    ce.status,
                    ce.created_at,
                    ce.updated_at,
                    cu.display_name AS contractor_name,
                    cu.email AS contractor_email,
                    su.display_name AS sponsor_name,
                    su.email AS sponsor_email
                FROM dbo.contractor_engagements ce
                INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
                INNER JOIN dbo.users su ON ce.sponsor_user_id = su.user_id
                WHERE ce.engagement_id = @engagementId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findEngagementById', { engagementId, error: err.message });
        throw new DatabaseError('Failed to retrieve contractor engagement by ID.', err);
    }
}

/**
 * Finds all engagements for a contractor.
 * @param {string} contractorUserId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function findEngagementsByContractorId(contractorUserId, transaction = null) {
    if (!contractorUserId || typeof contractorUserId !== 'string') return [];

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('contractorUserId', sql.UniqueIdentifier, contractorUserId.trim())
            .query(`
                SELECT
                    ce.engagement_id,
                    ce.contractor_user_id,
                    ce.sponsor_user_id,
                    ce.vendor_name,
                    ce.contract_reference,
                    ce.start_date,
                    ce.end_date,
                    ce.status,
                    ce.created_at,
                    ce.updated_at,
                    su.display_name AS sponsor_name,
                    su.email AS sponsor_email
                FROM dbo.contractor_engagements ce
                INNER JOIN dbo.users su ON ce.sponsor_user_id = su.user_id
                WHERE ce.contractor_user_id = @contractorUserId
                ORDER BY ce.start_date DESC;
            `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in findEngagementsByContractorId', { contractorUserId, error: err.message });
        throw new DatabaseError('Failed to retrieve engagements for contractor.', err);
    }
}

/**
 * Lists contractor engagements with optional filters.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listEngagements(filter = {}, transaction = null) {
    const { status, sponsorUserId, contractorUserId, search, limit = 50, offset = 0 } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
                ce.engagement_id,
                ce.contractor_user_id,
                ce.sponsor_user_id,
                ce.vendor_name,
                ce.contract_reference,
                ce.start_date,
                ce.end_date,
                ce.status,
                ce.created_at,
                ce.updated_at,
                cu.display_name AS contractor_name,
                cu.email AS contractor_email,
                su.display_name AS sponsor_name,
                su.email AS sponsor_email
            FROM dbo.contractor_engagements ce
            INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
            INNER JOIN dbo.users su ON ce.sponsor_user_id = su.user_id
            WHERE 1=1
        `;

        if (status) {
            sqlQuery += ` AND ce.status = @status`;
            request.input('status', sql.NVarChar(30), status);
        }

        if (sponsorUserId) {
            sqlQuery += ` AND ce.sponsor_user_id = @sponsorUserId`;
            request.input('sponsorUserId', sql.UniqueIdentifier, sponsorUserId.trim());
        }

        if (contractorUserId) {
            sqlQuery += ` AND ce.contractor_user_id = @contractorUserId`;
            request.input('contractorUserId', sql.UniqueIdentifier, contractorUserId.trim());
        }

        if (search && typeof search === 'string' && search.trim()) {
            sqlQuery += ` AND (ce.contract_reference LIKE @search OR ce.vendor_name LIKE @search OR cu.display_name LIKE @search OR cu.email LIKE @search)`;
            request.input('search', sql.NVarChar(128), `%${search.trim()}%`);
        }

        sqlQuery += ` ORDER BY ce.created_at DESC OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;`;
        request.input('offset', sql.Int, Math.max(0, offset));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, limit)));

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listEngagements', { error: err.message });
        throw new DatabaseError('Failed to list contractor engagements.', err);
    }
}

/**
 * Counts contractor engagements matching filter.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<number>}
 */
async function countEngagements(filter = {}, transaction = null) {
    const { status, sponsorUserId, contractorUserId, search } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT COUNT(1) AS total
            FROM dbo.contractor_engagements ce
            INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
            INNER JOIN dbo.users su ON ce.sponsor_user_id = su.user_id
            WHERE 1=1
        `;

        if (status) {
            sqlQuery += ` AND ce.status = @status`;
            request.input('status', sql.NVarChar(30), status);
        }

        if (sponsorUserId) {
            sqlQuery += ` AND ce.sponsor_user_id = @sponsorUserId`;
            request.input('sponsorUserId', sql.UniqueIdentifier, sponsorUserId.trim());
        }

        if (contractorUserId) {
            sqlQuery += ` AND ce.contractor_user_id = @contractorUserId`;
            request.input('contractorUserId', sql.UniqueIdentifier, contractorUserId.trim());
        }

        if (search && typeof search === 'string' && search.trim()) {
            sqlQuery += ` AND (ce.contract_reference LIKE @search OR ce.vendor_name LIKE @search OR cu.display_name LIKE @search OR cu.email LIKE @search)`;
            request.input('search', sql.NVarChar(128), `%${search.trim()}%`);
        }

        const result = await request.query(sqlQuery);
        return result.recordset && result.recordset[0] ? result.recordset[0].total : 0;
    } catch (err) {
        logger.error('Database query failed in countEngagements', { error: err.message });
        throw new DatabaseError('Failed to count contractor engagements.', err);
    }
}

/**
 * Finds an engagement by contractor user ID and contract reference (checks uniqueness constraint).
 * @param {string} contractorUserId GUID
 * @param {string} contractReference SOW or contract code
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findEngagementByContractReference(contractorUserId, contractReference, transaction = null) {
    if (!contractorUserId || !contractReference) return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('contractorUserId', sql.UniqueIdentifier, contractorUserId.trim())
            .input('contractReference', sql.NVarChar(100), contractReference.trim())
            .query(`
                SELECT TOP 1
                    ce.engagement_id,
                    ce.contractor_user_id,
                    ce.sponsor_user_id,
                    ce.vendor_name,
                    ce.contract_reference,
                    ce.start_date,
                    ce.end_date,
                    ce.status,
                    ce.created_at,
                    ce.updated_at
                FROM dbo.contractor_engagements ce
                WHERE ce.contractor_user_id = @contractorUserId
                  AND ce.contract_reference = @contractReference;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findEngagementByContractReference', { error: err.message });
        throw new DatabaseError('Failed to check contract reference uniqueness.', err);
    }
}

/**
 * Creates a new contractor engagement.
 * @param {object} engagementData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function createEngagement(engagementData, transaction = null) {
    const {
        contractorUserId,
        sponsorUserId,
        vendorName,
        contractReference,
        startDate,
        endDate,
        status = 'ACTIVE'
    } = engagementData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('contractorUserId', sql.UniqueIdentifier, contractorUserId.trim())
            .input('sponsorUserId', sql.UniqueIdentifier, sponsorUserId.trim())
            .input('vendorName', sql.NVarChar(150), vendorName.trim())
            .input('contractReference', sql.NVarChar(100), contractReference.trim())
            .input('startDate', sql.Date, startDate)
            .input('endDate', sql.Date, endDate)
            .input('status', sql.NVarChar(30), status)
            .query(`
                INSERT INTO dbo.contractor_engagements (
                    contractor_user_id,
                    sponsor_user_id,
                    vendor_name,
                    contract_reference,
                    start_date,
                    end_date,
                    status
                )
                OUTPUT
                    INSERTED.engagement_id,
                    INSERTED.contractor_user_id,
                    INSERTED.sponsor_user_id,
                    INSERTED.vendor_name,
                    INSERTED.contract_reference,
                    INSERTED.start_date,
                    INSERTED.end_date,
                    INSERTED.status,
                    INSERTED.created_at,
                    INSERTED.updated_at
                VALUES (
                    @contractorUserId,
                    @sponsorUserId,
                    @vendorName,
                    @contractReference,
                    @startDate,
                    @endDate,
                    @status
                );
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in createEngagement', { error: err.message });
        throw new DatabaseError('Failed to create contractor engagement.', err);
    }
}

/**
 * Updates permitted mutable fields of a contractor engagement.
 * @param {string} engagementId GUID
 * @param {object} updates { vendorName, contractReference, startDate, endDate }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function updateEngagement(engagementId, updates, transaction = null) {
    if (!engagementId || !updates) return null;

    const { vendorName, contractReference, startDate, endDate } = updates;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let setClauses = ['updated_at = SYSDATETIMEOFFSET()'];
        request.input('engagementId', sql.UniqueIdentifier, engagementId.trim());

        if (vendorName !== undefined) {
            setClauses.push('vendor_name = @vendorName');
            request.input('vendorName', sql.NVarChar(150), vendorName.trim());
        }

        if (contractReference !== undefined) {
            setClauses.push('contract_reference = @contractReference');
            request.input('contractReference', sql.NVarChar(100), contractReference.trim());
        }

        if (startDate !== undefined) {
            setClauses.push('start_date = @startDate');
            request.input('startDate', sql.Date, startDate);
        }

        if (endDate !== undefined) {
            setClauses.push('end_date = @endDate');
            request.input('endDate', sql.Date, endDate);
        }

        const sqlQuery = `
            UPDATE dbo.contractor_engagements
            SET ${setClauses.join(', ')}
            OUTPUT
                INSERTED.engagement_id,
                INSERTED.contractor_user_id,
                INSERTED.sponsor_user_id,
                INSERTED.vendor_name,
                INSERTED.contract_reference,
                INSERTED.start_date,
                INSERTED.end_date,
                INSERTED.status,
                INSERTED.created_at,
                INSERTED.updated_at
            WHERE engagement_id = @engagementId;
        `;

        const result = await request.query(sqlQuery);
        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database update failed in updateEngagement', { engagementId, error: err.message });
        throw new DatabaseError('Failed to update contractor engagement fields.', err);
    }
}

/**
 * Updates status of an engagement.
 * @param {string} engagementId GUID
 * @param {string} status 'PENDING', 'ACTIVE', 'COMPLETED', 'TERMINATED'
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function updateEngagementStatus(engagementId, status, transaction = null) {
    if (!engagementId || !status) return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('engagementId', sql.UniqueIdentifier, engagementId.trim())
            .input('status', sql.NVarChar(30), status)
            .query(`
                UPDATE dbo.contractor_engagements
                SET status = @status, updated_at = SYSDATETIMEOFFSET()
                OUTPUT
                    INSERTED.engagement_id,
                    INSERTED.contractor_user_id,
                    INSERTED.sponsor_user_id,
                    INSERTED.vendor_name,
                    INSERTED.contract_reference,
                    INSERTED.start_date,
                    INSERTED.end_date,
                    INSERTED.status,
                    INSERTED.created_at,
                    INSERTED.updated_at
                WHERE engagement_id = @engagementId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database update failed in updateEngagementStatus', { engagementId, status, error: err.message });
        throw new DatabaseError('Failed to update engagement status.', err);
    }
}

module.exports = {
    findEngagementById,
    findEngagementsByContractorId,
    findEngagementByContractReference,
    listEngagements,
    countEngagements,
    createEngagement,
    updateEngagement,
    updateEngagementStatus
};

