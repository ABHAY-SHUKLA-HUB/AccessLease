/**
 * AccessLease — Audit Trail & Compliance Repository
 * Handles data access for dbo.audit_events (immutable audit log).
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Creates an immutable audit event record.
 * @param {object} auditData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>} Created audit record
 */
async function createAuditEvent(auditData, transaction = null) {
    const {
        eventCategory,
        eventAction,
        entityType,
        entityId,
        actorUserId = null,
        actorType = 'USER',
        eventPayload,
        ipAddress = null
    } = auditData;

    try {
        const runner = transaction || await getPool();
        const payloadStr = typeof eventPayload === 'object' ? JSON.stringify(eventPayload) : String(eventPayload);

        const result = await runner.request()
            .input('eventCategory', sql.NVarChar(50), eventCategory)
            .input('eventAction', sql.NVarChar(100), eventAction.trim())
            .input('entityType', sql.NVarChar(50), entityType.trim())
            .input('entityId', sql.NVarChar(64), String(entityId).trim())
            .input('actorUserId', sql.UniqueIdentifier, actorUserId ? actorUserId.trim() : null)
            .input('actorType', sql.NVarChar(30), actorType)
            .input('eventPayload', sql.NVarChar(sql.MAX), payloadStr)
            .input('ipAddress', sql.VarChar(45), ipAddress)
            .query(`
                INSERT INTO dbo.audit_events (
                    event_category,
                    event_action,
                    entity_type,
                    entity_id,
                    actor_user_id,
                    actor_type,
                    event_payload,
                    ip_address
                )
                OUTPUT
                    INSERTED.event_id,
                    INSERTED.event_category,
                    INSERTED.event_action,
                    INSERTED.entity_type,
                    INSERTED.entity_id,
                    INSERTED.actor_user_id,
                    INSERTED.actor_type,
                    INSERTED.event_payload,
                    INSERTED.ip_address,
                    INSERTED.created_at
                VALUES (
                    @eventCategory,
                    @eventAction,
                    @entityType,
                    @entityId,
                    @actorUserId,
                    @actorType,
                    @eventPayload,
                    @ipAddress
                );
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in createAuditEvent', {
            eventCategory,
            eventAction,
            error: err.message
        });
        throw new DatabaseError('Failed to record audit event.', err);
    }
}

/**
 * Lists audit events with optional filtering.
 * @param {object} [filter={}] { eventCategory, entityType, entityId, actorUserId, search, limit, offset }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listAuditEvents(filter = {}, transaction = null) {
    const { eventCategory, entityType, entityId, actorUserId, search, limit = 50, offset = 0 } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
                ae.event_id,
                ae.event_category,
                ae.event_action,
                ae.entity_type,
                ae.entity_id,
                ae.actor_user_id,
                ae.actor_type,
                ae.event_payload,
                ae.ip_address,
                ae.created_at,
                u.display_name AS actor_name,
                u.email AS actor_email,
                COUNT(*) OVER() AS total_count
            FROM dbo.audit_events ae
            LEFT JOIN dbo.users u ON ae.actor_user_id = u.user_id
            WHERE 1=1
        `;

        if (eventCategory) {
            sqlQuery += ` AND ae.event_category = @eventCategory`;
            request.input('eventCategory', sql.NVarChar(50), eventCategory);
        }

        if (entityType) {
            sqlQuery += ` AND ae.entity_type = @entityType`;
            request.input('entityType', sql.NVarChar(50), entityType);
        }

        if (entityId) {
            sqlQuery += ` AND ae.entity_id = @entityId`;
            request.input('entityId', sql.NVarChar(64), String(entityId).trim());
        }

        if (actorUserId) {
            sqlQuery += ` AND ae.actor_user_id = @actorUserId`;
            request.input('actorUserId', sql.UniqueIdentifier, actorUserId.trim());
        }

        if (search && typeof search === 'string' && search.trim()) {
            sqlQuery += ` AND (ae.event_action LIKE @search OR ae.entity_type LIKE @search OR ae.entity_id LIKE @search OR u.display_name LIKE @search)`;
            request.input('search', sql.NVarChar(100), `%${search.trim()}%`);
        }

        sqlQuery += ` ORDER BY ae.event_id DESC OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;`;
        request.input('offset', sql.Int, Math.max(0, offset));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, limit)));

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listAuditEvents', { error: err.message });
        throw new DatabaseError('Failed to list audit events.', err);
    }
}

/**
 * Returns total count of audit events matching filter.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<number>}
 */
async function getAuditCount(filter = {}, transaction = null) {
    const { eventCategory, entityType, entityId, actorUserId, search } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT COUNT(*) AS total
            FROM dbo.audit_events ae
            LEFT JOIN dbo.users u ON ae.actor_user_id = u.user_id
            WHERE 1=1
        `;

        if (eventCategory) {
            sqlQuery += ` AND ae.event_category = @eventCategory`;
            request.input('eventCategory', sql.NVarChar(50), eventCategory);
        }

        if (entityType) {
            sqlQuery += ` AND ae.entity_type = @entityType`;
            request.input('entityType', sql.NVarChar(50), entityType);
        }

        if (entityId) {
            sqlQuery += ` AND ae.entity_id = @entityId`;
            request.input('entityId', sql.NVarChar(64), String(entityId).trim());
        }

        if (actorUserId) {
            sqlQuery += ` AND ae.actor_user_id = @actorUserId`;
            request.input('actorUserId', sql.UniqueIdentifier, actorUserId.trim());
        }

        if (search && typeof search === 'string' && search.trim()) {
            sqlQuery += ` AND (ae.event_action LIKE @search OR ae.entity_type LIKE @search OR ae.entity_id LIKE @search OR u.display_name LIKE @search)`;
            request.input('search', sql.NVarChar(100), `%${search.trim()}%`);
        }

        const result = await request.query(sqlQuery);
        return result.recordset[0]?.total || 0;
    } catch (err) {
        logger.error('Database query failed in getAuditCount', { error: err.message });
        return 0;
    }
}

/**
 * Returns aggregated statistics for the compliance trail dashboard.
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function getAuditStats(transaction = null) {
    try {
        const runner = transaction || await getPool();
        const result = await runner.request().query(`
            SELECT
                COUNT(*) AS total_events,
                COUNT(DISTINCT ae.actor_user_id) AS distinct_actors,
                SUM(CASE WHEN ae.created_at >= CAST(CAST(SYSUTCDATETIME() AS DATE) AS DATETIMEOFFSET) THEN 1 ELSE 0 END) AS today_events,
                SUM(CASE WHEN ae.event_category IN ('APPROVAL', 'SECURITY') THEN 1 ELSE 0 END) AS security_events,
                SUM(CASE WHEN ae.event_category = 'REVOCATION' THEN 1 ELSE 0 END) AS revocation_events,
                SUM(CASE WHEN ae.event_category = 'ACCESS_REQUEST' THEN 1 ELSE 0 END) AS request_events
            FROM dbo.audit_events ae;
        `);

        const row = result.recordset[0] || {};
        return {
            totalEvents: row.total_events || 0,
            distinctActors: row.distinct_actors || 0,
            todayEvents: row.today_events || 0,
            securityEvents: row.security_events || 0,
            revocationEvents: row.revocation_events || 0,
            requestEvents: row.request_events || 0
        };
    } catch (err) {
        logger.error('Database query failed in getAuditStats', { error: err.message });
        throw new DatabaseError('Failed to retrieve audit statistics.', err);
    }
}

/**
 * Retrieves a single audit event by primary key event_id.
 * @param {number|string} eventId
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function getAuditEventById(eventId, transaction = null) {
    if (!eventId) return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('eventId', sql.BigInt, eventId)
            .query(`
                SELECT TOP 1
                    ae.event_id,
                    ae.event_category,
                    ae.event_action,
                    ae.entity_type,
                    ae.entity_id,
                    ae.actor_user_id,
                    ae.actor_type,
                    ae.event_payload,
                    ae.ip_address,
                    ae.created_at,
                    u.display_name AS actor_name,
                    u.email AS actor_email
                FROM dbo.audit_events ae
                LEFT JOIN dbo.users u ON ae.actor_user_id = u.user_id
                WHERE ae.event_id = @eventId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in getAuditEventById', { eventId, error: err.message });
        throw new DatabaseError('Failed to retrieve audit event by ID.', err);
    }
}

module.exports = {
    createAuditEvent,
    listAuditEvents,
    getAuditCount,
    getAuditStats,
    getAuditEventById
};

