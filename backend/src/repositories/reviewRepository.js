/**
 * AccessLease — Access Review & Recertification Repository
 * Handles data access for dbo.access_reviews and dbo.review_items.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Finds an access review campaign by primary key review_id.
 * @param {string} reviewId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findAccessReviewById(reviewId, transaction = null) {
    if (!reviewId || typeof reviewId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('reviewId', sql.UniqueIdentifier, reviewId.trim())
            .query(`
                SELECT TOP 1
                    ar.review_id,
                    ar.review_name,
                    ar.description,
                    ar.campaign_type,
                    ar.start_date,
                    ar.due_date,
                    ar.status,
                    ar.initiated_by_user_id,
                    ar.created_at,
                    ar.updated_at,
                    u.display_name AS initiator_name,
                    u.email AS initiator_email,
                    (SELECT COUNT(*) FROM dbo.review_items ri WHERE ri.review_id = ar.review_id) AS total_items,
                    (SELECT COUNT(*) FROM dbo.review_items ri WHERE ri.review_id = ar.review_id AND ri.decision <> 'PENDING') AS decided_items,
                    (SELECT COUNT(*) FROM dbo.review_items ri WHERE ri.review_id = ar.review_id AND ri.decision = 'PENDING') AS pending_items
                FROM dbo.access_reviews ar
                INNER JOIN dbo.users u ON ar.initiated_by_user_id = u.user_id
                WHERE ar.review_id = @reviewId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findAccessReviewById', { reviewId, error: err.message });
        throw new DatabaseError('Failed to find access review by ID.', err);
    }
}

/**
 * Lists access review campaigns with optional filtering.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listAccessReviews(filter = {}, transaction = null) {
    const { status, campaignType, limit = 50, offset = 0 } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
                ar.review_id,
                ar.review_name,
                ar.description,
                ar.campaign_type,
                ar.start_date,
                ar.due_date,
                ar.status,
                ar.initiated_by_user_id,
                ar.created_at,
                ar.updated_at,
                u.display_name AS initiator_name,
                (SELECT COUNT(*) FROM dbo.review_items ri WHERE ri.review_id = ar.review_id) AS total_items,
                (SELECT COUNT(*) FROM dbo.review_items ri WHERE ri.review_id = ar.review_id AND ri.decision <> 'PENDING') AS decided_items,
                (SELECT COUNT(*) FROM dbo.review_items ri WHERE ri.review_id = ar.review_id AND ri.decision = 'PENDING') AS pending_items
            FROM dbo.access_reviews ar
            INNER JOIN dbo.users u ON ar.initiated_by_user_id = u.user_id
            WHERE 1=1
        `;

        if (status) {
            sqlQuery += ` AND ar.status = @status`;
            request.input('status', sql.NVarChar(30), status);
        }

        if (campaignType) {
            sqlQuery += ` AND ar.campaign_type = @campaignType`;
            request.input('campaignType', sql.NVarChar(50), campaignType);
        }

        sqlQuery += ` ORDER BY ar.due_date ASC OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;`;
        request.input('offset', sql.Int, Math.max(0, offset));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, limit)));

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listAccessReviews', { error: err.message });
        throw new DatabaseError('Failed to list access reviews.', err);
    }
}

/**
 * Creates a new access review campaign.
 * @param {object} reviewData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function createAccessReview(reviewData, transaction = null) {
    const {
        reviewName,
        description = null,
        campaignType = 'PERIODIC_RECERTIFICATION',
        startDate,
        dueDate,
        status = 'ACTIVE',
        initiatedByUserId
    } = reviewData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('reviewName', sql.NVarChar(150), reviewName.trim())
            .input('description', sql.NVarChar(500), description)
            .input('campaignType', sql.NVarChar(50), campaignType)
            .input('startDate', sql.DateTimeOffset, startDate)
            .input('dueDate', sql.DateTimeOffset, dueDate)
            .input('status', sql.NVarChar(30), status)
            .input('initiatedByUserId', sql.UniqueIdentifier, initiatedByUserId.trim())
            .query(`
                INSERT INTO dbo.access_reviews (
                    review_name,
                    description,
                    campaign_type,
                    start_date,
                    due_date,
                    status,
                    initiated_by_user_id
                )
                OUTPUT
                    INSERTED.review_id,
                    INSERTED.review_name,
                    INSERTED.description,
                    INSERTED.campaign_type,
                    INSERTED.start_date,
                    INSERTED.due_date,
                    INSERTED.status,
                    INSERTED.initiated_by_user_id,
                    INSERTED.created_at,
                    INSERTED.updated_at
                VALUES (
                    @reviewName,
                    @description,
                    @campaignType,
                    @startDate,
                    @dueDate,
                    @status,
                    @initiatedByUserId
                );
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in createAccessReview', { reviewName, error: err.message });
        throw new DatabaseError('Failed to create access review campaign.', err);
    }
}

/**
 * Updates status of an access review campaign.
 * @param {string} reviewId GUID
 * @param {string} status 'DRAFT', 'ACTIVE', 'COMPLETED', 'EXPIRED'
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function updateAccessReviewStatus(reviewId, status, transaction = null) {
    if (!reviewId || !status) return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('reviewId', sql.UniqueIdentifier, reviewId.trim())
            .input('status', sql.NVarChar(30), status)
            .query(`
                UPDATE dbo.access_reviews
                SET status = @status, updated_at = SYSDATETIMEOFFSET()
                OUTPUT
                    INSERTED.review_id,
                    INSERTED.review_name,
                    INSERTED.status,
                    INSERTED.updated_at
                WHERE review_id = @reviewId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database update failed in updateAccessReviewStatus', { reviewId, status, error: err.message });
        throw new DatabaseError('Failed to update access review status.', err);
    }
}

/**
 * Creates an item for review in an access review campaign.
 * @param {object} itemData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function createReviewItem(itemData, transaction = null) {
    const {
        reviewId,
        grantId,
        reviewerUserId,
        decision = 'PENDING'
    } = itemData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('reviewId', sql.UniqueIdentifier, reviewId.trim())
            .input('grantId', sql.UniqueIdentifier, grantId.trim())
            .input('reviewerUserId', sql.UniqueIdentifier, reviewerUserId.trim())
            .input('decision', sql.NVarChar(30), decision)
            .query(`
                INSERT INTO dbo.review_items (
                    review_id,
                    grant_id,
                    reviewer_user_id,
                    decision
                )
                OUTPUT
                    INSERTED.review_item_id,
                    INSERTED.review_id,
                    INSERTED.grant_id,
                    INSERTED.reviewer_user_id,
                    INSERTED.decision,
                    INSERTED.created_at
                VALUES (
                    @reviewId,
                    @grantId,
                    @reviewerUserId,
                    @decision
                );
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in createReviewItem', { reviewId, grantId, error: err.message });
        throw new DatabaseError('Failed to create review item.', err);
    }
}

/**
 * Retrieves all review items belonging to a review campaign.
 * @param {string} reviewId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function getReviewItemsByReviewId(reviewId, transaction = null) {
    if (!reviewId || typeof reviewId !== 'string') return [];

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('reviewId', sql.UniqueIdentifier, reviewId.trim())
            .query(`
                SELECT
                    ri.review_item_id,
                    ri.review_id,
                    ri.grant_id,
                    ri.reviewer_user_id,
                    ri.decision,
                    ri.decision_notes,
                    ri.decided_at,
                    ri.created_at,
                    ag.grant_number,
                    ag.expires_at,
                    r.resource_id,
                    r.resource_name,
                    e.entitlement_name,
                    cu.user_id AS contractor_user_id,
                    cu.display_name AS contractor_name,
                    ce.engagement_id,
                    ce.sponsor_user_id,
                    ce.status AS engagement_status,
                    ce.end_date AS engagement_end_date,
                    ru.display_name AS reviewer_name
                FROM dbo.review_items ri
                INNER JOIN dbo.access_grants ag ON ri.grant_id = ag.grant_id
                INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
                INNER JOIN dbo.entitlements e ON ag.entitlement_id = e.entitlement_id
                INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
                INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
                INNER JOIN dbo.users ru ON ri.reviewer_user_id = ru.user_id
                WHERE ri.review_id = @reviewId
                ORDER BY ri.created_at ASC;
            `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in getReviewItemsByReviewId', { reviewId, error: err.message });
        throw new DatabaseError('Failed to retrieve review items for campaign.', err);
    }
}

/**
 * Records a reviewer's decision on a review item.
 * @param {string} reviewItemId GUID
 * @param {object} decisionData { decision, decisionNotes, decidedAt }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function updateReviewItemDecision(reviewItemId, decisionData, transaction = null) {
    const { decision, decisionNotes = null, decidedAt = new Date() } = decisionData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('reviewItemId', sql.UniqueIdentifier, reviewItemId.trim())
            .input('decision', sql.NVarChar(30), decision)
            .input('decisionNotes', sql.NVarChar(1000), decisionNotes)
            .input('decidedAt', sql.DateTimeOffset, decidedAt)
            .query(`
                UPDATE dbo.review_items
                SET decision = @decision,
                    decision_notes = @decisionNotes,
                    decided_at = @decidedAt
                OUTPUT
                    INSERTED.review_item_id,
                    INSERTED.review_id,
                    INSERTED.grant_id,
                    INSERTED.reviewer_user_id,
                    INSERTED.decision,
                    INSERTED.decision_notes,
                    INSERTED.decided_at
                WHERE review_item_id = @reviewItemId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database update failed in updateReviewItemDecision', { reviewItemId, decision, error: err.message });
        throw new DatabaseError('Failed to update review item decision.', err);
    }
}

/**
 * Finds a single review item by ID with full joined grant, contractor, and resource details.
 * @param {string} reviewItemId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findReviewItemById(reviewItemId, transaction = null) {
    if (!reviewItemId || typeof reviewItemId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('reviewItemId', sql.UniqueIdentifier, reviewItemId.trim())
            .query(`
                SELECT
                    ri.review_item_id,
                    ri.review_id,
                    ri.grant_id,
                    ri.reviewer_user_id,
                    ri.decision,
                    ri.decision_notes,
                    ri.decided_at,
                    ri.created_at,
                    ag.grant_number,
                    ag.status AS grant_status,
                    ag.expires_at,
                    cu.user_id AS contractor_user_id,
                    cu.display_name AS contractor_name,
                    cu.email AS contractor_email,
                    r.resource_id,
                    r.resource_name,
                    e.entitlement_id,
                    e.entitlement_name,
                    ce.engagement_id,
                    ce.sponsor_user_id,
                    ce.status AS engagement_status,
                    ce.end_date AS engagement_end_date,
                    SYSUTCDATETIME() AS db_current_time_utc,
                    CAST(SYSUTCDATETIME() AS DATE) AS db_current_date_utc,
                    ar.review_name,
                    ar.status AS review_status,
                    ru.display_name AS reviewer_name,
                    ru.email AS reviewer_email
                FROM dbo.review_items ri
                INNER JOIN dbo.access_reviews ar ON ri.review_id = ar.review_id
                INNER JOIN dbo.access_grants ag ON ri.grant_id = ag.grant_id
                INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
                INNER JOIN dbo.entitlements e ON ag.entitlement_id = e.entitlement_id
                INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
                INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
                INNER JOIN dbo.users ru ON ri.reviewer_user_id = ru.user_id
                WHERE ri.review_item_id = @reviewItemId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findReviewItemById', { reviewItemId, error: err.message });
        throw new DatabaseError('Failed to find review item by ID.', err);
    }
}

/**
 * Counts the remaining PENDING items for a given review campaign.
 * @param {string} reviewId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<number>}
 */
async function countPendingItemsInReview(reviewId, transaction = null) {
    if (!reviewId) return 0;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('reviewId', sql.UniqueIdentifier, reviewId.trim())
            .query(`
                SELECT COUNT(*) AS pending_count
                FROM dbo.review_items
                WHERE review_id = @reviewId AND decision = 'PENDING';
            `);

        return result.recordset[0]?.pending_count || 0;
    } catch (err) {
        logger.error('Database query failed in countPendingItemsInReview', { reviewId, error: err.message });
        throw new DatabaseError('Failed to count pending items in review.', err);
    }
}

/**
 * Finds candidate active grants for inclusion in a new review campaign based on scope.
 * @param {object} scope { resourceId, contractorEngagementId, contractorUserId }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function findGrantsForReviewScope(scope = {}, transaction = null) {
    const { resourceId, contractorEngagementId, contractorUserId } = scope;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
                ag.grant_id,
                ag.grant_number,
                ag.expires_at,
                ag.resource_id,
                ag.contractor_engagement_id,
                ce.contractor_user_id,
                ce.sponsor_user_id,
                cu.display_name AS contractor_name,
                r.resource_name,
                e.entitlement_name
            FROM dbo.access_grants ag
            INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
            INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
            INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
            INNER JOIN dbo.entitlements e ON ag.entitlement_id = e.entitlement_id
            WHERE ag.status = 'ACTIVE'
        `;

        if (resourceId) {
            sqlQuery += ` AND ag.resource_id = @resourceId`;
            request.input('resourceId', sql.UniqueIdentifier, resourceId.trim());
        }

        if (contractorEngagementId) {
            sqlQuery += ` AND ag.contractor_engagement_id = @engagementId`;
            request.input('engagementId', sql.UniqueIdentifier, contractorEngagementId.trim());
        }

        if (contractorUserId) {
            sqlQuery += ` AND ce.contractor_user_id = @contractorUserId`;
            request.input('contractorUserId', sql.UniqueIdentifier, contractorUserId.trim());
        }

        sqlQuery += ` ORDER BY ag.expires_at ASC;`;

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in findGrantsForReviewScope', { error: err.message });
        throw new DatabaseError('Failed to find grants for review scope.', err);
    }
}

module.exports = {
    findAccessReviewById,
    listAccessReviews,
    createAccessReview,
    updateAccessReviewStatus,
    createReviewItem,
    getReviewItemsByReviewId,
    updateReviewItemDecision,
    findReviewItemById,
    countPendingItemsInReview,
    findGrantsForReviewScope
};

