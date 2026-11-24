/**
 * AccessLease — Provisioning Event Repository
 * Handles data access for dbo.provisioning_events.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Normalizes a provisioning job database record.
 * Preserves canonical SQL Server column names (job_status, lease_expires_at, lease_owner)
 * while providing convenient aliases (status, locked_until, locked_by) for seamless
 * compatibility across all services and consumers without parallel DB columns.
 * @param {object|null} row
 * @returns {object|null}
 */
function formatJobRecord(row) {
    if (!row) return null;
    return {
        ...row,
        // Canonical DB columns (Primary)
        job_status: row.job_status,
        lease_expires_at: row.lease_expires_at,
        lease_owner: row.lease_owner,
        // Canonical Aliases (Secondary)
        status: row.job_status,
        locked_until: row.lease_expires_at,
        locked_by: row.lease_owner
    };
}

/**
 * Creates a provisioning event record.
 * @param {object} eventData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function createProvisioningEvent(eventData, transaction = null) {
    const {
        grantId,
        eventType,
        connectorName,
        payload = null,
        statusCode = null,
        errorMessage = null,
        executedAt = new Date()
    } = eventData;

    try {
        const runner = transaction || await getPool();
        const payloadStr = payload && typeof payload === 'object' ? JSON.stringify(payload) : payload;

        const result = await runner.request()
            .input('grantId', sql.UniqueIdentifier, grantId ? grantId.trim() : null)
            .input('eventType', sql.NVarChar(50), eventType)
            .input('connectorName', sql.NVarChar(100), (connectorName || 'UNKNOWN').trim())
            .input('payload', sql.NVarChar(sql.MAX), payloadStr)
            .input('statusCode', sql.NVarChar(50), statusCode)
            .input('errorMessage', sql.NVarChar(sql.MAX), errorMessage)
            .input('executedAt', sql.DateTimeOffset, executedAt)
            .query(`
                INSERT INTO dbo.provisioning_events (
                    grant_id,
                    event_type,
                    connector_name,
                    payload,
                    status_code,
                    error_message,
                    executed_at
                )
                OUTPUT
                    INSERTED.event_id,
                    INSERTED.grant_id,
                    INSERTED.event_type,
                    INSERTED.connector_name,
                    INSERTED.payload,
                    INSERTED.status_code,
                    INSERTED.error_message,
                    INSERTED.executed_at
                VALUES (
                    @grantId,
                    @eventType,
                    @connectorName,
                    @payload,
                    @statusCode,
                    @errorMessage,
                    @executedAt
                );
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in createProvisioningEvent', { grantId, eventType, error: err.message });
        throw new DatabaseError('Failed to record provisioning event.', err);
    }
}

/**
 * Retrieves all provisioning events for a grant.
 * @param {string} grantId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function getProvisioningEventsByGrantId(grantId, transaction = null) {
    if (!grantId || typeof grantId !== 'string') return [];

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('grantId', sql.UniqueIdentifier, grantId.trim())
            .query(`
                SELECT
                    pe.event_id,
                    pe.grant_id,
                    pe.event_type,
                    pe.connector_name,
                    pe.payload,
                    pe.status_code,
                    pe.error_message,
                    pe.executed_at
                FROM dbo.provisioning_events pe
                WHERE pe.grant_id = @grantId
                ORDER BY pe.executed_at ASC;
            `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in getProvisioningEventsByGrantId', { grantId, error: err.message });
        throw new DatabaseError('Failed to retrieve provisioning events for grant.', err);
    }
}

/**
 * Lists provisioning events with optional filters.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listProvisioningEvents(filter = {}, transaction = null) {
    const { eventType, limit = 50, offset = 0 } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
                pe.event_id,
                pe.grant_id,
                pe.event_type,
                pe.connector_name,
                pe.payload,
                pe.status_code,
                pe.error_message,
                pe.executed_at
            FROM dbo.provisioning_events pe
            WHERE 1=1
        `;

        if (eventType) {
            sqlQuery += ` AND pe.event_type = @eventType`;
            request.input('eventType', sql.NVarChar(50), eventType);
        }

        sqlQuery += ` ORDER BY pe.executed_at DESC OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;`;
        request.input('offset', sql.Int, Math.max(0, offset));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, limit)));

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listProvisioningEvents', { error: err.message });
        throw new DatabaseError('Failed to list provisioning events.', err);
    }
}

/**
 * Creates a durable provisioning job record.
 * Uses idempotency_key to prevent duplicate provisioning operations.
 * If a job with the idempotency key exists, returns the existing job.
 * @param {object} jobData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function createProvisioningJob(jobData, transaction = null) {
    const {
        requestId,
        grantId = null,
        connectorType = 'GITHUB',
        targetResource,
        idempotencyKey,
        jobStatus = 'QUEUED',
        maxAttempts = 5
    } = jobData;

    try {
        const runner = transaction || await getPool();

        // Check if an existing job matches the idempotency key under lock
        const existing = await runner.request()
            .input('idempotencyKey', sql.NVarChar(150), idempotencyKey.trim())
            .query(`
                SELECT TOP 1
                    job_id, request_id, grant_id, connector_type, target_resource,
                    idempotency_key, job_status, attempt_count, max_attempts,
                    next_retry_at, lease_owner, lease_expires_at, last_error_category,
                    last_error_message, created_at, updated_at
                FROM dbo.provisioning_jobs WITH (UPDLOCK, HOLDLOCK)
                WHERE idempotency_key = @idempotencyKey;
            `);

        if (existing.recordset.length > 0) {
            return formatJobRecord(existing.recordset[0]);
        }

        const insertResult = await runner.request()
            .input('requestId', sql.UniqueIdentifier, requestId.trim())
            .input('grantId', sql.UniqueIdentifier, grantId ? grantId.trim() : null)
            .input('connectorType', sql.NVarChar(50), connectorType.trim().toUpperCase())
            .input('targetResource', sql.NVarChar(200), targetResource.trim())
            .input('idempotencyKey', sql.NVarChar(150), idempotencyKey.trim())
            .input('jobStatus', sql.NVarChar(30), jobStatus.trim().toUpperCase())
            .input('maxAttempts', sql.Int, maxAttempts)
            .query(`
                INSERT INTO dbo.provisioning_jobs (
                    request_id,
                    grant_id,
                    connector_type,
                    target_resource,
                    idempotency_key,
                    job_status,
                    max_attempts
                )
                OUTPUT
                    INSERTED.job_id,
                    INSERTED.request_id,
                    INSERTED.grant_id,
                    INSERTED.connector_type,
                    INSERTED.target_resource,
                    INSERTED.idempotency_key,
                    INSERTED.job_status,
                    INSERTED.attempt_count,
                    INSERTED.max_attempts,
                    INSERTED.next_retry_at,
                    INSERTED.lease_owner,
                    INSERTED.lease_expires_at,
                    INSERTED.last_error_category,
                    INSERTED.last_error_message,
                    INSERTED.created_at,
                    INSERTED.updated_at
                VALUES (
                    @requestId,
                    @grantId,
                    @connectorType,
                    @targetResource,
                    @idempotencyKey,
                    @jobStatus,
                    @maxAttempts
                );
            `);

        return formatJobRecord(insertResult.recordset[0]);
    } catch (err) {
        logger.error('Database query failed in createProvisioningJob', { requestId, idempotencyKey, error: err.message });
        throw new DatabaseError('Failed to create durable provisioning job.', err);
    }
}

/**
 * Finds a provisioning job by job_id.
 * @param {string} jobId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findJobById(jobId, transaction = null) {
    if (!jobId || typeof jobId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .query(`
                SELECT TOP 1
                    pj.job_id,
                    pj.request_id,
                    pj.grant_id,
                    pj.connector_type,
                    pj.target_resource,
                    pj.idempotency_key,
                    pj.job_status,
                    pj.attempt_count,
                    pj.max_attempts,
                    pj.next_retry_at,
                    pj.lease_owner,
                    pj.lease_expires_at,
                    pj.last_error_category,
                    pj.last_error_message,
                    pj.created_at,
                    pj.updated_at,
                    ar.request_number,
                    ar.status AS request_status,
                    ag.grant_number,
                    ag.status AS grant_status,
                    ag.expires_at AS grant_expires_at,
                    ag.membership_provenance,
                    ag.verified_at AS grant_verified_at,
                    cu.display_name AS contractor_name,
                    cu.email AS contractor_email,
                    r.resource_code,
                    r.resource_name,
                    e.entitlement_code,
                    e.entitlement_name
                FROM dbo.provisioning_jobs pj
                INNER JOIN dbo.access_requests ar ON pj.request_id = ar.request_id
                LEFT JOIN dbo.access_grants ag ON pj.grant_id = ag.grant_id
                INNER JOIN dbo.users cu ON ar.requested_by_user_id = cu.user_id
                INNER JOIN dbo.resources r ON ar.resource_id = r.resource_id
                INNER JOIN dbo.entitlements e ON ar.entitlement_id = e.entitlement_id
                WHERE pj.job_id = @jobId;
            `);

        return result.recordset.length > 0 ? formatJobRecord(result.recordset[0]) : null;
    } catch (err) {
        logger.error('Database query failed in findJobById', { jobId, error: err.message });
        throw new DatabaseError('Failed to find provisioning job by ID.', err);
    }
}

/**
 * Finds a provisioning job by access request_id.
 * @param {string} requestId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findJobByRequestId(requestId, transaction = null) {
    if (!requestId || typeof requestId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('requestId', sql.UniqueIdentifier, requestId.trim())
            .query(`
                SELECT TOP 1
                    pj.job_id,
                    pj.request_id,
                    pj.grant_id,
                    pj.connector_type,
                    pj.target_resource,
                    pj.idempotency_key,
                    pj.job_status,
                    pj.attempt_count,
                    pj.max_attempts,
                    pj.next_retry_at,
                    pj.lease_owner,
                    pj.lease_expires_at,
                    pj.last_error_category,
                    pj.last_error_message,
                    pj.created_at,
                    pj.updated_at,
                    ag.grant_number,
                    ag.status AS grant_status,
                    ag.membership_provenance,
                    ag.verified_at AS grant_verified_at
                FROM dbo.provisioning_jobs pj
                LEFT JOIN dbo.access_grants ag ON pj.grant_id = ag.grant_id
                WHERE pj.request_id = @requestId
                ORDER BY pj.created_at DESC;
            `);

        return result.recordset.length > 0 ? formatJobRecord(result.recordset[0]) : null;
    } catch (err) {
        logger.error('Database query failed in findJobByRequestId', { requestId, error: err.message });
        throw new DatabaseError('Failed to find provisioning job by request ID.', err);
    }
}

/**
 * Finds a provisioning job by its unique idempotency_key.
 * @param {string} idempotencyKey
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findJobByIdempotencyKey(idempotencyKey, transaction = null) {
    if (!idempotencyKey || typeof idempotencyKey !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('idempotencyKey', sql.NVarChar(150), idempotencyKey.trim())
            .query(`
                SELECT TOP 1
                    job_id, request_id, grant_id, connector_type, target_resource,
                    idempotency_key, job_status, attempt_count, max_attempts,
                    next_retry_at, lease_owner, lease_expires_at, last_error_category,
                    last_error_message, created_at, updated_at
                FROM dbo.provisioning_jobs
                WHERE idempotency_key = @idempotencyKey;
            `);

        return result.recordset.length > 0 ? formatJobRecord(result.recordset[0]) : null;
    } catch (err) {
        logger.error('Database query failed in findJobByIdempotencyKey', { idempotencyKey, error: err.message });
        throw new DatabaseError('Failed to find provisioning job by idempotency key.', err);
    }
}

/**
 * Atomically claims the next pending provisioning job for execution.
 * Respects worker leases and next_retry_at backoff schedules.
 * Supports automatic crash recovery of abandoned jobs whose lease has expired.
 * @param {string} workerId Unique worker process identifier
 * @param {number} [leaseDurationSeconds=60] Lease duration before job becomes reclaimable
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function claimNextProvisioningJob(workerId, leaseDurationSeconds = 60, transaction = null) {
    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('workerId', sql.NVarChar(100), workerId)
            .input('leaseDurationSeconds', sql.Int, leaseDurationSeconds)
            .query(`
                WITH NextJob AS (
                    SELECT TOP 1
                        job_id,
                        request_id,
                        grant_id,
                        connector_type,
                        target_resource,
                        idempotency_key,
                        job_status,
                        attempt_count,
                        max_attempts,
                        next_retry_at,
                        lease_owner,
                        lease_expires_at,
                        created_at,
                        updated_at
                    FROM dbo.provisioning_jobs WITH (UPDLOCK, ROWLOCK, READPAST)
                    WHERE (
                        job_status IN ('QUEUED', 'FAILED_RETRY')
                        OR (job_status = 'PROCESSING' AND lease_expires_at < SYSDATETIMEOFFSET())
                    )
                      AND (next_retry_at IS NULL OR next_retry_at <= SYSDATETIMEOFFSET())
                      AND (lease_owner IS NULL OR lease_expires_at < SYSDATETIMEOFFSET())
                      AND attempt_count < max_attempts
                    ORDER BY created_at ASC
                )
                UPDATE NextJob
                SET
                    job_status = 'PROCESSING',
                    lease_owner = @workerId,
                    lease_expires_at = DATEADD(SECOND, @leaseDurationSeconds, SYSDATETIMEOFFSET()),
                    attempt_count = attempt_count + 1,
                    updated_at = SYSDATETIMEOFFSET()
                OUTPUT
                    INSERTED.job_id,
                    INSERTED.request_id,
                    INSERTED.grant_id,
                    INSERTED.connector_type,
                    INSERTED.target_resource,
                    INSERTED.idempotency_key,
                    INSERTED.job_status,
                    INSERTED.attempt_count,
                    INSERTED.max_attempts,
                    INSERTED.next_retry_at,
                    INSERTED.lease_owner,
                    INSERTED.lease_expires_at,
                    INSERTED.created_at,
                    INSERTED.updated_at;
            `);

        return result.recordset.length > 0 ? formatJobRecord(result.recordset[0]) : null;
    } catch (err) {
        logger.error('Database query failed in claimNextProvisioningJob', { workerId, error: err.message });
        throw new DatabaseError('Failed to claim next provisioning job.', err);
    }
}

/**
 * Marks a job as SUCCEEDED and clears lease.
 * @param {string} jobId GUID
 * @param {object} [details={}] { grantId }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function completeJob(jobId, details = {}, transaction = null) {
    const { grantId = null } = details;

    try {
        const runner = transaction || await getPool();
        const request = runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .input('grantId', sql.UniqueIdentifier, grantId ? grantId.trim() : null);

        const result = await request.query(`
            UPDATE dbo.provisioning_jobs
            SET
                job_status = 'SUCCEEDED',
                grant_id = COALESCE(@grantId, grant_id),
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_error_category = NULL,
                last_error_message = NULL,
                updated_at = SYSDATETIMEOFFSET()
            OUTPUT
                INSERTED.job_id,
                INSERTED.request_id,
                INSERTED.grant_id,
                INSERTED.connector_type,
                INSERTED.target_resource,
                INSERTED.idempotency_key,
                INSERTED.job_status,
                INSERTED.attempt_count,
                INSERTED.max_attempts,
                INSERTED.next_retry_at,
                INSERTED.lease_owner,
                INSERTED.lease_expires_at,
                INSERTED.created_at,
                INSERTED.updated_at
            WHERE job_id = @jobId;
        `);

        return result.recordset.length > 0 ? formatJobRecord(result.recordset[0]) : null;
    } catch (err) {
        logger.error('Database query failed in completeJob', { jobId, error: err.message });
        throw new DatabaseError('Failed to complete provisioning job.', err);
    }
}

/**
 * Updates a job with failure details, retry schedule, or permanent failure.
 * @param {string} jobId GUID
 * @param {object} failureDetails { errorCategory, errorMessage, isPermanent, nextRetryAt }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function failJob(jobId, failureDetails = {}, transaction = null) {
    const {
        errorCategory = 'CONNECTOR_ERROR',
        errorMessage = 'Provisioning operation failed',
        isPermanent = false,
        nextRetryAt = null
    } = failureDetails;

    const newStatus = isPermanent ? 'PERMANENT_FAILURE' : 'FAILED_RETRY';

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .input('jobStatus', sql.NVarChar(30), newStatus)
            .input('errorCategory', sql.NVarChar(50), errorCategory.trim())
            .input('errorMessage', sql.NVarChar(sql.MAX), errorMessage ? String(errorMessage).slice(0, 4000) : null)
            .input('nextRetryAt', sql.DateTimeOffset, nextRetryAt)
            .query(`
                UPDATE dbo.provisioning_jobs
                SET
                    job_status = @jobStatus,
                    last_error_category = @errorCategory,
                    last_error_message = @errorMessage,
                    next_retry_at = @nextRetryAt,
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    updated_at = SYSDATETIMEOFFSET()
                OUTPUT
                    INSERTED.job_id,
                    INSERTED.request_id,
                    INSERTED.grant_id,
                    INSERTED.connector_type,
                    INSERTED.target_resource,
                    INSERTED.idempotency_key,
                    INSERTED.job_status,
                    INSERTED.attempt_count,
                    INSERTED.max_attempts,
                    INSERTED.next_retry_at,
                    INSERTED.lease_owner,
                    INSERTED.lease_expires_at,
                    INSERTED.last_error_category,
                    INSERTED.last_error_message,
                    INSERTED.created_at,
                    INSERTED.updated_at
                WHERE job_id = @jobId;
            `);

        return result.recordset.length > 0 ? formatJobRecord(result.recordset[0]) : null;
    } catch (err) {
        logger.error('Database query failed in failJob', { jobId, error: err.message });
        throw new DatabaseError('Failed to record provisioning job failure.', err);
    }
}

/**
 * Updates job status (e.g. to PENDING_ACCEPTANCE or manual retry).
 * @param {string} jobId GUID
 * @param {string} status New status
 * @param {object} [details={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function updateJobStatus(jobId, status, details = {}, transaction = null) {
    const { lastErrorCategory = null, lastErrorMessage = null, nextRetryAt = null, resetAttempts = false } = details;

    try {
        const runner = transaction || await getPool();
        const request = runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .input('status', sql.NVarChar(30), status.trim().toUpperCase())
            .input('errorCategory', sql.NVarChar(50), lastErrorCategory)
            .input('errorMessage', sql.NVarChar(sql.MAX), lastErrorMessage)
            .input('nextRetryAt', sql.DateTimeOffset, nextRetryAt);

        let attemptClause = '';
        if (resetAttempts) {
            attemptClause = ', attempt_count = 0';
        }

        const result = await request.query(`
            UPDATE dbo.provisioning_jobs
            SET
                job_status = @status,
                last_error_category = @errorCategory,
                last_error_message = @errorMessage,
                next_retry_at = @nextRetryAt,
                lease_owner = NULL,
                lease_expires_at = NULL,
                updated_at = SYSDATETIMEOFFSET()
                ${attemptClause}
            OUTPUT
                INSERTED.job_id,
                INSERTED.request_id,
                INSERTED.grant_id,
                INSERTED.connector_type,
                INSERTED.target_resource,
                INSERTED.idempotency_key,
                INSERTED.job_status,
                INSERTED.attempt_count,
                INSERTED.max_attempts,
                INSERTED.next_retry_at,
                INSERTED.lease_owner,
                INSERTED.lease_expires_at,
                INSERTED.created_at,
                INSERTED.updated_at
            WHERE job_id = @jobId;
        `);

        return result.recordset.length > 0 ? formatJobRecord(result.recordset[0]) : null;
    } catch (err) {
        logger.error('Database query failed in updateJobStatus', { jobId, status, error: err.message });
        throw new DatabaseError('Failed to update provisioning job status.', err);
    }
}

/**
 * Lists provisioning jobs with filtering.
 * Supports status='FAILED' mapping to both 'FAILED_RETRY' and 'PERMANENT_FAILURE'.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listProvisioningJobs(filter = {}, transaction = null) {
    const { status, connectorType, limit = 50, offset = 0 } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
                pj.job_id,
                pj.request_id,
                pj.grant_id,
                pj.connector_type,
                pj.target_resource,
                pj.idempotency_key,
                pj.job_status,
                pj.attempt_count,
                pj.max_attempts,
                pj.next_retry_at,
                pj.lease_owner,
                pj.lease_expires_at,
                pj.last_error_category,
                pj.last_error_message,
                pj.created_at,
                pj.updated_at,
                ar.request_number,
                ar.status AS request_status,
                cu.display_name AS contractor_name,
                cu.email AS contractor_email,
                ag.grant_number,
                ag.status AS grant_status
            FROM dbo.provisioning_jobs pj
            INNER JOIN dbo.access_requests ar ON pj.request_id = ar.request_id
            INNER JOIN dbo.users cu ON ar.requested_by_user_id = cu.user_id
            LEFT JOIN dbo.access_grants ag ON pj.grant_id = ag.grant_id
            WHERE 1=1
        `;

        if (status) {
            const cleanStatus = status.trim().toUpperCase();
            if (cleanStatus === 'FAILED') {
                sqlQuery += ` AND pj.job_status IN ('FAILED_RETRY', 'PERMANENT_FAILURE')`;
            } else {
                sqlQuery += ` AND pj.job_status = @status`;
                request.input('status', sql.NVarChar(30), cleanStatus);
            }
        }

        if (connectorType) {
            sqlQuery += ` AND pj.connector_type = @connectorType`;
            request.input('connectorType', sql.NVarChar(50), connectorType.trim().toUpperCase());
        }

        sqlQuery += ` ORDER BY pj.created_at DESC OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;`;
        request.input('offset', sql.Int, Math.max(0, offset));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, limit)));

        const result = await request.query(sqlQuery);
        return (result.recordset || []).map(formatJobRecord);
    } catch (err) {
        logger.error('Database query failed in listProvisioningJobs', { error: err.message });
        throw new DatabaseError('Failed to list provisioning jobs.', err);
    }
}

module.exports = {
    createProvisioningEvent,
    getProvisioningEventsByGrantId,
    listProvisioningEvents,
    createProvisioningJob,
    findJobById,
    findJobByRequestId,
    findJobByIdempotencyKey,
    claimNextProvisioningJob,
    completeJob,
    failJob,
    updateJobStatus,
    listProvisioningJobs
};

