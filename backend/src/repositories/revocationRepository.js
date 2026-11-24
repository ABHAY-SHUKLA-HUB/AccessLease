/**
 * AccessLease — Revocation Job & Verification Proof Repository
 * Handles data access for dbo.revocation_jobs, automated expiry detection,
 * worker leasing, shared membership checking, and offboarding progress tracking.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const crypto = require('crypto');
const sql = require('mssql');
const { getPool, withTransaction } = require('../config/database');
const { DatabaseError, ValidationError, ConflictError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Validates that a worker ID is provided and is a non-empty string.
 * @param {string} workerId 
 * @param {string} methodName 
 * @returns {string} Trimmed worker ID
 * @throws {ValidationError}
 */
function validateWorkerId(workerId, methodName) {
    if (!workerId || typeof workerId !== 'string' || !workerId.trim()) {
        throw new ValidationError(
            `Worker ID is required and must be a non-empty string for ${methodName}.`,
            [],
            'ERR_WORKER_ID_REQUIRED'
        );
    }
    return workerId.trim();
}

/**
 * Generates a bounded, collision-resistant deterministic applock resource key.
 * Format: 'REV_MEM_' + SHA-256 hex digest (72 chars total, well within 255 char limit)
 * @param {string} targetOrg 
 * @param {string} targetTeamSlug 
 * @param {string|number} accountIdentifier 
 * @returns {string}
 */
function getMembershipLockKey(targetOrg, targetTeamSlug, accountIdentifier) {
    const org = String(targetOrg || '').trim().toLowerCase();
    const team = String(targetTeamSlug || '').trim().toLowerCase();
    const account = String(accountIdentifier || '').trim().toLowerCase();
    const normalized = `${org}:${team}:${account}`;
    const hash = crypto.createHash('sha256').update(normalized).digest('hex');
    return `REV_MEM_${hash}`;
}

/**
 * Resolves the immutable numeric GitHub account ID for a grant.
 * Prefers existing grant.numeric_account_id, falls back to dbo.user_external_identities
 * via contractor_user_id or external_username, and persists the resolved ID back to the grant.
 * @param {object} grant
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<string|null>} Canonical numeric account ID or null if unresolvable
 */
async function resolveCanonicalAccountId(grant, transaction = null) {
    if (!grant) return null;
    if (grant.numeric_account_id && String(grant.numeric_account_id).trim()) {
        return String(grant.numeric_account_id).trim();
    }

    try {
        const runner = transaction || await getPool();
        let externalAccountId = null;

        // 1. Try lookup by contractor_user_id
        if (grant.contractor_user_id) {
            const res = await runner.request()
                .input('userId', sql.UniqueIdentifier, grant.contractor_user_id)
                .query(`
                    SELECT TOP 1 external_account_id
                    FROM dbo.user_external_identities
                    WHERE user_id = @userId AND provider = 'GITHUB' AND external_account_id IS NOT NULL;
                `);
            if (res.recordset.length > 0 && res.recordset[0].external_account_id) {
                externalAccountId = String(res.recordset[0].external_account_id).trim();
            }
        }

        // 2. Try lookup by external_username
        if (!externalAccountId && grant.external_username) {
            const res = await runner.request()
                .input('username', sql.NVarChar(100), grant.external_username.trim().toLowerCase())
                .query(`
                    SELECT TOP 1 external_account_id
                    FROM dbo.user_external_identities
                    WHERE provider = 'GITHUB' AND LOWER(external_username) = @username AND external_account_id IS NOT NULL;
                `);
            if (res.recordset.length > 0 && res.recordset[0].external_account_id) {
                externalAccountId = String(res.recordset[0].external_account_id).trim();
            }
        }

        // 3. Persist back to access_grants if resolved
        if (externalAccountId && grant.grant_id) {
            await runner.request()
                .input('grantId', sql.UniqueIdentifier, grant.grant_id)
                .input('accountId', sql.NVarChar(100), externalAccountId)
                .query(`
                    UPDATE dbo.access_grants
                    SET numeric_account_id = @accountId,
                        updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                    WHERE grant_id = @grantId
                      AND numeric_account_id IS NULL;
                `);
            grant.numeric_account_id = externalAccountId;
        }

        return externalAccountId;
    } catch (err) {
        logger.error('Failed to resolve canonical account ID for grant', { grantId: grant.grant_id, error: err.message });
        return null;
    }
}

/**
 * Finds a revocation job by primary key job_id with joined grant, contractor, and resource details.
 * @param {string} jobId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findRevocationJobById(jobId, transaction = null) {
    if (!jobId || typeof jobId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .query(`
                SELECT TOP 1
                    rj.job_id,
                    rj.grant_id,
                    rj.trigger_source,
                    rj.status,
                    rj.retry_count,
                    rj.max_retries,
                    rj.connector_name,
                    rj.connector_response,
                    rj.error_details,
                    rj.cryptographic_proof_hash,
                    rj.proof_blob_url,
                    rj.confirmed_at,
                    rj.lease_owner,
                    rj.lease_expires_at,
                    rj.next_retry_at,
                    rj.last_error_category,
                    rj.last_error_message,
                    rj.idempotency_key,
                    rj.created_at,
                    rj.updated_at,
                    ag.grant_number,
                    ag.expires_at,
                    ag.status AS grant_status,
                    ag.target_org,
                    ag.target_team_slug,
                    ag.target_repo,
                    ag.external_username,
                    ag.numeric_account_id,
                    ag.membership_provenance,
                    r.resource_code,
                    r.resource_name,
                    ce.engagement_id,
                    ce.status AS engagement_status,
                    ce.end_date AS engagement_end_date,
                    ce.contractor_user_id,
                    cu.display_name AS contractor_name,
                    cu.email AS contractor_email
                FROM dbo.revocation_jobs rj
                INNER JOIN dbo.access_grants ag ON rj.grant_id = ag.grant_id
                INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
                INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
                INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
                WHERE rj.job_id = @jobId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findRevocationJobById', { jobId, error: err.message });
        throw new DatabaseError('Failed to find revocation job by ID.', err);
    }
}

/**
 * Retrieves revocation jobs for a specific grant.
 * @param {string} grantId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function getRevocationJobsByGrantId(grantId, transaction = null) {
    if (!grantId || typeof grantId !== 'string') return [];

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('grantId', sql.UniqueIdentifier, grantId.trim())
            .query(`
                SELECT
                    rj.job_id,
                    rj.grant_id,
                    rj.trigger_source,
                    rj.status,
                    rj.retry_count,
                    rj.max_retries,
                    rj.connector_name,
                    rj.connector_response,
                    rj.error_details,
                    rj.cryptographic_proof_hash,
                    rj.proof_blob_url,
                    rj.confirmed_at,
                    rj.lease_owner,
                    rj.lease_expires_at,
                    rj.next_retry_at,
                    rj.last_error_category,
                    rj.last_error_message,
                    rj.idempotency_key,
                    rj.created_at,
                    rj.updated_at
                FROM dbo.revocation_jobs rj
                WHERE rj.grant_id = @grantId
                ORDER BY rj.created_at DESC;
            `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in getRevocationJobsByGrantId', { grantId, error: err.message });
        throw new DatabaseError('Failed to retrieve revocation jobs for grant.', err);
    }
}

/**
 * Lists pending/queued revocation jobs awaiting processing.
 * @param {object} [filter={}] { limit }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listPendingRevocationJobs(filter = {}, transaction = null) {
    const { limit = 50 } = filter;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('limit', sql.Int, Math.min(100, Math.max(1, limit)))
            .query(`
                SELECT TOP (@limit)
                    rj.job_id,
                    rj.grant_id,
                    rj.trigger_source,
                    rj.status,
                    rj.retry_count,
                    rj.max_retries,
                    rj.connector_name,
                    rj.next_retry_at,
                    rj.created_at
                FROM dbo.revocation_jobs rj
                WHERE rj.status IN ('QUEUED', 'FAILED_RETRY')
                  AND rj.retry_count < rj.max_retries
                  AND (rj.next_retry_at IS NULL OR rj.next_retry_at <= TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                ORDER BY rj.created_at ASC;
            `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listPendingRevocationJobs', { error: err.message });
        throw new DatabaseError('Failed to list pending revocation jobs.', err);
    }
}

/**
 * Creates a new revocation job with optional idempotency key.
 * If a job with the specified idempotency_key already exists, returns the existing job.
 * @param {object} jobData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function createRevocationJob(jobData, transaction = null) {
    const {
        grantId,
        triggerSource,
        connectorName = 'GITHUB',
        status = 'QUEUED',
        maxRetries = 5,
        idempotencyKey = null
    } = jobData;

    const effectiveIdempotencyKey = (idempotencyKey && idempotencyKey.trim()) 
        ? idempotencyKey.trim() 
        : `REVOCATION_ACTIVE_${grantId.trim()}`;

    try {
        const runner = transaction || await getPool();

        // 1. Check existing job by idempotency key
        const existing = await runner.request()
            .input('idempotencyKey', sql.NVarChar(150), effectiveIdempotencyKey)
            .query(`
                SELECT TOP 1
                    job_id, grant_id, trigger_source, status, retry_count, max_retries,
                    connector_name, idempotency_key, created_at, updated_at
                FROM dbo.revocation_jobs
                WHERE idempotency_key = @idempotencyKey;
            `);
        if (existing.recordset.length > 0) {
            return existing.recordset[0];
        }

        // 2. Check existing active job by grant_id to avoid constraint race
        const existingActive = await runner.request()
            .input('grantId', sql.UniqueIdentifier, grantId.trim())
            .query(`
                SELECT TOP 1
                    job_id, grant_id, trigger_source, status, retry_count, max_retries,
                    connector_name, idempotency_key, created_at, updated_at
                FROM dbo.revocation_jobs
                WHERE grant_id = @grantId
                  AND status IN ('QUEUED', 'PROCESSING', 'IN_PROGRESS', 'FAILED_RETRY', 'MANUAL_REVIEW_REQUIRED')
                ORDER BY created_at DESC;
            `);
        if (existingActive.recordset.length > 0) {
            return existingActive.recordset[0];
        }

        const result = await runner.request()
            .input('grantId', sql.UniqueIdentifier, grantId.trim())
            .input('triggerSource', sql.NVarChar(50), triggerSource)
            .input('connectorName', sql.NVarChar(100), connectorName.trim())
            .input('status', sql.NVarChar(30), status)
            .input('maxRetries', sql.Int, maxRetries)
            .input('idempotencyKey', sql.NVarChar(150), effectiveIdempotencyKey)
            .query(`
                INSERT INTO dbo.revocation_jobs (
                    grant_id,
                    trigger_source,
                    connector_name,
                    status,
                    max_retries,
                    idempotency_key
                )
                OUTPUT
                    INSERTED.job_id,
                    INSERTED.grant_id,
                    INSERTED.trigger_source,
                    INSERTED.status,
                    INSERTED.retry_count,
                    INSERTED.max_retries,
                    INSERTED.connector_name,
                    INSERTED.idempotency_key,
                    INSERTED.created_at,
                    INSERTED.updated_at
                VALUES (
                    @grantId,
                    @triggerSource,
                    @connectorName,
                    @status,
                    @maxRetries,
                    @idempotencyKey
                );
            `);

        return result.recordset[0];
    } catch (err) {
        if (err.number === 2601 || err.number === 2627) {
            const runner = transaction || await getPool();
            const existing = await runner.request()
                .input('idempotencyKey', sql.NVarChar(150), effectiveIdempotencyKey)
                .input('grantId', sql.UniqueIdentifier, grantId.trim())
                .query(`
                    SELECT TOP 1
                        job_id, grant_id, trigger_source, status, retry_count, max_retries,
                        connector_name, idempotency_key, created_at, updated_at
                    FROM dbo.revocation_jobs
                    WHERE idempotency_key = @idempotencyKey
                       OR (grant_id = @grantId AND status IN ('QUEUED', 'PROCESSING', 'IN_PROGRESS', 'FAILED_RETRY', 'MANUAL_REVIEW_REQUIRED'))
                    ORDER BY created_at DESC;
                `);
            if (existing.recordset.length > 0) {
                return existing.recordset[0];
            }
        }

        logger.error('Database insert failed in createRevocationJob', { grantId, error: err.message });
        throw new DatabaseError('Failed to create revocation job.', err);
    }
}

/**
 * Atomically claims the next eligible revocation job with durable worker lease.
 * @param {string} workerId Unique worker identifier
 * @param {number} [leaseDurationSeconds=60] Lease timeout in seconds
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function claimNextRevocationJob(workerId, leaseDurationSeconds = 60, transaction = null) {
    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('workerId', sql.NVarChar(100), workerId)
            .input('leaseDurationSeconds', sql.Int, leaseDurationSeconds)
            .query(`
                WITH NextJob AS (
                    SELECT TOP 1
                        job_id,
                        grant_id,
                        trigger_source,
                        status,
                        retry_count,
                        max_retries,
                        connector_name,
                        lease_owner,
                        lease_expires_at,
                        next_retry_at,
                        idempotency_key,
                        created_at,
                        updated_at
                    FROM dbo.revocation_jobs WITH (UPDLOCK, ROWLOCK, READPAST)
                    WHERE (
                        status IN ('QUEUED', 'FAILED_RETRY')
                        OR (status = 'PROCESSING' AND lease_expires_at < TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                    )
                      AND (next_retry_at IS NULL OR next_retry_at <= TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                      AND (lease_owner IS NULL OR lease_expires_at < TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                      AND retry_count < max_retries
                    ORDER BY created_at ASC
                )
                UPDATE NextJob
                SET
                    status = 'PROCESSING',
                    lease_owner = @workerId,
                    lease_expires_at = DATEADD(SECOND, @leaseDurationSeconds, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')),
                    retry_count = retry_count + 1,
                    updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                OUTPUT
                    INSERTED.job_id,
                    INSERTED.grant_id,
                    INSERTED.trigger_source,
                    INSERTED.status,
                    INSERTED.retry_count,
                    INSERTED.max_retries,
                    INSERTED.connector_name,
                    INSERTED.lease_owner,
                    INSERTED.lease_expires_at,
                    INSERTED.next_retry_at,
                    INSERTED.idempotency_key,
                    INSERTED.created_at,
                    INSERTED.updated_at;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in claimNextRevocationJob', { workerId, error: err.message });
        throw new DatabaseError('Failed to claim next revocation job.', err);
    }
}

/**
 * Atomically claims a specific revocation job by ID with a durable worker lease.
 * Useful for executing targeted jobs while enforcing mandatory lease ownership.
 * @param {string} jobId Unique job identifier (GUID)
 * @param {string} workerId Unique worker identifier
 * @param {number} [leaseDurationSeconds=60] Lease timeout in seconds
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>} Claimed job record or null if job cannot be claimed
 */
async function claimRevocationJobById(jobId, workerId, leaseDurationSeconds = 60, transaction = null) {
    if (!jobId || typeof jobId !== 'string') {
        throw new ValidationError('Job ID is required for claimRevocationJobById.');
    }
    const cleanWorkerId = validateWorkerId(workerId, 'claimRevocationJobById');

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .input('workerId', sql.NVarChar(100), cleanWorkerId)
            .input('leaseDurationSeconds', sql.Int, leaseDurationSeconds)
            .query(`
                UPDATE dbo.revocation_jobs
                SET
                    status = 'PROCESSING',
                    lease_owner = @workerId,
                    lease_expires_at = DATEADD(SECOND, @leaseDurationSeconds, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')),
                    retry_count = CASE WHEN status = 'PROCESSING' AND lease_owner = @workerId THEN retry_count ELSE retry_count + 1 END,
                    updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                OUTPUT
                    INSERTED.job_id,
                    INSERTED.grant_id,
                    INSERTED.trigger_source,
                    INSERTED.status,
                    INSERTED.retry_count,
                    INSERTED.max_retries,
                    INSERTED.connector_name,
                    INSERTED.lease_owner,
                    INSERTED.lease_expires_at,
                    INSERTED.next_retry_at,
                    INSERTED.idempotency_key,
                    INSERTED.created_at,
                    INSERTED.updated_at
                WHERE job_id = @jobId
                  AND (
                      status IN ('QUEUED', 'FAILED_RETRY')
                      OR (status = 'PROCESSING' AND (lease_owner = @workerId OR lease_expires_at < TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')))
                  )
                  AND retry_count < max_retries;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        if (err instanceof ValidationError) throw err;
        logger.error('Database query failed in claimRevocationJobById', { jobId, workerId: cleanWorkerId, error: err.message });
        throw new DatabaseError('Failed to claim revocation job by ID.', err);
    }
}

/**
 * Counts other active non-expired grants that share the same organization, team, and immutable user account.
 * Used for Shared Membership Protection.
 * @param {string} currentGrantId GUID of the grant currently being revoked
 * @param {string} targetOrg GitHub Organization
 * @param {string} targetTeamSlug GitHub Team Slug
 * @param {string} externalUsername GitHub username
 * @param {string|number|null} [numericAccountId=null] Immutable numeric GitHub ID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<number>}
 */
async function countSharedActiveGrants(currentGrantId, targetOrg, targetTeamSlug, externalUsername, numericAccountId = null, transaction = null) {
    if (!currentGrantId || !targetOrg || !targetTeamSlug) return 0;

    try {
        const runner = transaction || await getPool();
        const numIdStr = numericAccountId ? String(numericAccountId) : null;

        const result = await runner.request()
            .input('currentGrantId', sql.UniqueIdentifier, currentGrantId.trim())
            .input('targetOrg', sql.NVarChar(100), targetOrg.trim().toLowerCase())
            .input('targetTeamSlug', sql.NVarChar(100), targetTeamSlug.trim().toLowerCase())
            .input('externalUsername', sql.NVarChar(100), externalUsername ? externalUsername.trim().toLowerCase() : null)
            .input('numericAccountId', sql.NVarChar(100), numIdStr)
            .query(`
                SELECT COUNT(*) AS active_count
                FROM dbo.access_grants ag
                INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
                WHERE ag.grant_id <> @currentGrantId
                  AND (
                      (ag.status IN ('ACTIVE', 'PROVISIONING_IN_PROGRESS', 'PENDING_ACCEPTANCE') AND ag.expires_at > TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                      OR (ag.status = 'MANUAL_REVIEW_REQUIRED')
                      OR (ag.membership_provenance IN ('PRE_EXISTING_ADOPTED', 'UNCERTAIN_PRE_EXISTING') AND ag.status <> 'REVOKED')
                  )
                  AND ce.status = 'ACTIVE'
                  AND ce.end_date >= CAST(SYSUTCDATETIME() AS DATE)
                  AND LOWER(ag.target_org) = @targetOrg
                  AND LOWER(ag.target_team_slug) = @targetTeamSlug
                  AND (
                      (@numericAccountId IS NOT NULL AND CAST(ag.numeric_account_id AS NVARCHAR(100)) = @numericAccountId)
                      OR (@numericAccountId IS NULL AND @externalUsername IS NOT NULL AND LOWER(ag.external_username) = @externalUsername)
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM dbo.revocation_jobs rj
                      WHERE rj.grant_id = ag.grant_id
                        AND rj.status IN ('QUEUED', 'PROCESSING', 'IN_PROGRESS', 'FAILED_RETRY')
                  );
            `);

        return result.recordset[0]?.active_count || 0;
    } catch (err) {
        logger.error('Database query failed in countSharedActiveGrants', { currentGrantId, error: err.message });
        throw new DatabaseError('Failed to check shared active grants.', err);
    }
}

/**
 * Finds grants that have expired or belong to ended/terminated engagements without existing active revocation jobs.
 * @param {number} [batchSize=50]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function findExpiredGrantsWithoutJobs(batchSize = 50, transaction = null) {
    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('batchSize', sql.Int, Math.min(200, Math.max(1, batchSize)))
            .query(`
                SELECT TOP (@batchSize)
                    ag.grant_id,
                    ag.grant_number,
                    ag.status,
                    ag.expires_at,
                    ag.target_org,
                    ag.target_team_slug,
                    ag.external_username,
                    ag.numeric_account_id,
                    ag.membership_provenance,
                    ag.contractor_engagement_id,
                    ce.status AS engagement_status,
                    ce.end_date AS engagement_end_date,
                    ce.contractor_user_id
                FROM dbo.access_grants ag
                INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
                WHERE (
                    (ag.status = 'ACTIVE' AND ag.expires_at <= TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                    OR (ag.status = 'ACTIVE' AND ce.end_date < CAST(SYSUTCDATETIME() AS DATE))
                    OR (ag.status = 'ACTIVE' AND ce.status IN ('COMPLETED', 'TERMINATED'))
                    OR (ag.status = 'REVOKE_PENDING' AND ag.expires_at <= TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                )
                AND NOT EXISTS (
                    SELECT 1 FROM dbo.revocation_jobs rj
                    WHERE rj.grant_id = ag.grant_id
                      AND rj.status IN ('QUEUED', 'PROCESSING', 'IN_PROGRESS', 'REVOKED', 'CONFIRMED')
                )
                ORDER BY ag.expires_at ASC;
            `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in findExpiredGrantsWithoutJobs', { error: err.message });
        throw new DatabaseError('Failed to find expired grants without jobs.', err);
    }
}

/**
 * Finds all active or pending grants for a specific contractor engagement.
 * @param {string} engagementId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function findActiveGrantsByEngagementId(engagementId, transaction = null) {
    if (!engagementId || typeof engagementId !== 'string') return [];

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('engagementId', sql.UniqueIdentifier, engagementId.trim())
            .query(`
                SELECT
                    ag.grant_id,
                    ag.grant_number,
                    ag.status,
                    ag.expires_at,
                    ag.target_org,
                    ag.target_team_slug,
                    ag.external_username,
                    ag.numeric_account_id,
                    ag.membership_provenance,
                    ag.contractor_engagement_id
                FROM dbo.access_grants ag
                WHERE ag.contractor_engagement_id = @engagementId
                  AND ag.status IN ('ACTIVE', 'PROVISIONING_PENDING', 'PROVISIONING_IN_PROGRESS', 'PENDING_ACCEPTANCE', 'REVOKE_PENDING')
                ORDER BY ag.created_at ASC;
            `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in findActiveGrantsByEngagementId', { engagementId, error: err.message });
        throw new DatabaseError('Failed to find active grants for engagement.', err);
    }
}

/**
 * Renews an active worker lease on a revocation job if the worker is still the legitimate lease owner.
 * Rejects null, undefined, empty, or non-matching worker IDs.
 * @param {string} jobId GUID
 * @param {string} workerId Worker identifier (mandatory non-empty string)
 * @param {number} [extensionSeconds=60] Additional lease duration in seconds
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>} Updated job lease or null if lost
 */
async function renewJobLease(jobId, workerId, extensionSeconds = 60, transaction = null) {
    if (!jobId || typeof jobId !== 'string') {
        throw new ValidationError('Job ID is required for renewJobLease.');
    }
    const cleanWorkerId = validateWorkerId(workerId, 'renewJobLease');

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .input('workerId', sql.NVarChar(100), cleanWorkerId)
            .input('extensionSeconds', sql.Int, extensionSeconds)
            .query(`
                UPDATE dbo.revocation_jobs
                SET
                    lease_expires_at = DATEADD(SECOND, @extensionSeconds, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')),
                    updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                OUTPUT
                    INSERTED.job_id,
                    INSERTED.lease_owner,
                    INSERTED.lease_expires_at,
                    INSERTED.updated_at
                WHERE job_id = @jobId
                  AND lease_owner = @workerId
                  AND lease_expires_at > TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                  AND status = 'PROCESSING';
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        if (err instanceof ValidationError) throw err;
        logger.error('Database query failed in renewJobLease', { jobId, workerId: cleanWorkerId, error: err.message });
        throw new DatabaseError('Failed to renew revocation job lease.', err);
    }
}

/**
 * Checks whether a worker currently holds an unexpired active lease on a revocation job.
 * @param {string} jobId GUID
 * @param {string} workerId Unique worker identifier
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<boolean>}
 */
async function verifyJobLeaseActive(jobId, workerId, transaction = null) {
    if (!jobId || !workerId || typeof jobId !== 'string' || typeof workerId !== 'string') {
        return false;
    }

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .input('workerId', sql.NVarChar(100), workerId.trim())
            .query(`
                SELECT 1 AS is_active
                FROM dbo.revocation_jobs
                WHERE job_id = @jobId
                  AND lease_owner = @workerId
                  AND status = 'PROCESSING'
                  AND lease_expires_at > TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00');
            `);

        return result.recordset.length > 0;
    } catch (err) {
        logger.warn('Failed to verify active job lease', { jobId, workerId, error: err.message });
        return false;
    }
}

/**
 * Completes a revocation job and marks it REVOKED, releasing worker lease.
 * Mandatory workerId enforcement: rejects null, undefined, empty, or mismatched worker IDs.
 * Verifies affected rows === 1; throws ConflictError if lease ownership was lost.
 * @param {string} jobId GUID
 * @param {string|object} arg2 workerId or details object
 * @param {object|sql.Transaction} [arg3={}] details or transaction
 * @param {sql.Transaction|string} [arg4=null] transaction or workerId
 * @param {string} [arg5=null] workerId if passed in 5th position
 * @returns {Promise<object>} Completed job record
 */
async function completeRevocationJob(jobId, arg2, arg3 = {}, arg4 = null, arg5 = null) {
    if (!jobId || typeof jobId !== 'string') {
        throw new ValidationError('Job ID is required for completeRevocationJob.');
    }

    let workerId;
    let details;
    let transaction;

    if (typeof arg2 === 'string') {
        workerId = arg2;
        details = arg3 && typeof arg3 === 'object' && !(arg3 instanceof sql.Transaction) ? arg3 : {};
        transaction = arg3 instanceof sql.Transaction ? arg3 : (arg4 instanceof sql.Transaction ? arg4 : null);
    } else {
        details = arg2 && typeof arg2 === 'object' ? arg2 : {};
        transaction = arg3 instanceof sql.Transaction ? arg3 : null;
        workerId = typeof arg4 === 'string' ? arg4 : (typeof arg5 === 'string' ? arg5 : null);
    }

    const cleanWorkerId = validateWorkerId(workerId, 'completeRevocationJob');
    const {
        connectorResponse = null,
        cryptographicProofHash = null,
        proofBlobUrl = null
    } = details;

    try {
        const runner = transaction || await getPool();
        const request = runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .input('workerId', sql.NVarChar(100), cleanWorkerId)
            .input('connectorResponse', sql.NVarChar(sql.MAX), typeof connectorResponse === 'object' ? JSON.stringify(connectorResponse) : connectorResponse)
            .input('cryptographicProofHash', sql.NVarChar(64), cryptographicProofHash)
            .input('proofBlobUrl', sql.NVarChar(2048), proofBlobUrl);

        const result = await request.query(`
            UPDATE dbo.revocation_jobs
            SET
                status = 'REVOKED',
                confirmed_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'),
                connector_response = COALESCE(@connectorResponse, connector_response),
                cryptographic_proof_hash = COALESCE(@cryptographicProofHash, cryptographic_proof_hash),
                proof_blob_url = COALESCE(@proofBlobUrl, proof_blob_url),
                lease_owner = NULL,
                lease_expires_at = NULL,
                updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
            OUTPUT
                INSERTED.job_id,
                INSERTED.grant_id,
                INSERTED.status,
                INSERTED.confirmed_at,
                INSERTED.updated_at
            WHERE job_id = @jobId
              AND lease_owner = @workerId
              AND lease_expires_at > TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
              AND status = 'PROCESSING';
        `);

        if (result.recordset.length !== 1) {
            logger.warn('Revocation job completion matched 0 rows with worker lease check', { jobId, workerId: cleanWorkerId });
            return null;
        }

        return result.recordset[0];
    } catch (err) {
        if (err instanceof ValidationError) {
            throw err;
        }
        logger.error('Database update failed in completeRevocationJob', { jobId, workerId: cleanWorkerId, error: err.message });
        throw new DatabaseError('Failed to complete revocation job.', err);
    }
}

/**
 * Fails a revocation job with retry or permanent failure classification, releasing worker lease.
 * Mandatory workerId enforcement: rejects null, undefined, empty, or mismatched worker IDs.
 * Verifies affected rows === 1; throws ConflictError if lease ownership was lost.
 * @param {string} jobId GUID
 * @param {...any} args Supports (workerId, category, message, ...) or (category, message, ..., workerId)
 * @returns {Promise<object>}
 */
async function failRevocationJob(jobId, ...args) {
    if (!jobId || typeof jobId !== 'string') {
        throw new ValidationError('Job ID is required for failRevocationJob.');
    }

    let workerId;
    let errorCategory;
    let errorMessage;
    let retryable = true;
    let nextRetryDelaySec = 30;
    let transaction = null;

    if (typeof args[0] === 'string' && typeof args[1] === 'string') {
        if (typeof args[2] === 'boolean') {
            // Signature: failRevocationJob(jobId, errorCategory, errorMessage, retryable, nextRetryDelaySec, transaction, workerId)
            errorCategory = args[0];
            errorMessage = args[1];
            retryable = args[2];
            nextRetryDelaySec = typeof args[3] === 'number' ? args[3] : 30;
            transaction = args[4] instanceof sql.Transaction ? args[4] : null;
            workerId = typeof args[5] === 'string' ? args[5] : (typeof args[6] === 'string' ? args[6] : null);
        } else {
            // Signature: failRevocationJob(jobId, workerId, errorCategory, errorMessage, retryable, nextRetryDelaySec, transaction)
            workerId = args[0];
            errorCategory = args[1];
            errorMessage = args[2];
            retryable = args[3] !== undefined ? args[3] : true;
            nextRetryDelaySec = typeof args[4] === 'number' ? args[4] : 30;
            transaction = args[5] instanceof sql.Transaction ? args[5] : null;
        }
    } else {
        errorCategory = args[0];
        errorMessage = args[1];
        retryable = args[2] !== undefined ? args[2] : true;
        nextRetryDelaySec = typeof args[3] === 'number' ? args[3] : 30;
        transaction = args[4] instanceof sql.Transaction ? args[4] : null;
        workerId = typeof args[5] === 'string' ? args[5] : null;
    }

    const cleanWorkerId = validateWorkerId(workerId, 'failRevocationJob');

    try {
        const runner = transaction || await getPool();
        const request = runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .input('workerId', sql.NVarChar(100), cleanWorkerId)
            .input('errorCategory', sql.NVarChar(50), errorCategory)
            .input('errorMessage', sql.NVarChar(sql.MAX), errorMessage)
            .input('retryable', sql.Bit, retryable ? 1 : 0)
            .input('nextRetryDelaySec', sql.Int, nextRetryDelaySec);

        const result = await request.query(`
            UPDATE dbo.revocation_jobs
            SET
                status = CASE WHEN @retryable = 1 AND retry_count < max_retries THEN 'FAILED_RETRY' ELSE 'PERMANENT_FAILURE' END,
                next_retry_at = CASE WHEN @retryable = 1 AND retry_count < max_retries THEN DATEADD(SECOND, @nextRetryDelaySec, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')) ELSE NULL END,
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_error_category = @errorCategory,
                last_error_message = @errorMessage,
                error_details = @errorMessage,
                updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
            OUTPUT
                INSERTED.job_id,
                INSERTED.grant_id,
                INSERTED.status,
                INSERTED.retry_count,
                INSERTED.max_retries,
                INSERTED.next_retry_at,
                INSERTED.last_error_category,
                INSERTED.updated_at
            WHERE job_id = @jobId
              AND lease_owner = @workerId
              AND lease_expires_at > TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
              AND status = 'PROCESSING';
        `);

        if (result.recordset.length !== 1) {
            logger.warn('Revocation job fail matched 0 rows with worker lease check', { jobId, workerId: cleanWorkerId });
            return null;
        }

        return result.recordset[0];
    } catch (err) {
        if (err instanceof ValidationError) {
            throw err;
        }
        logger.error('Database update failed in failRevocationJob', { jobId, workerId: cleanWorkerId, error: err.message });
        throw new DatabaseError('Failed to fail revocation job.', err);
    }
}

/**
 * Routes a revocation job to MANUAL_REVIEW_REQUIRED due to provenance ambiguity or policy conflict.
 * Mandatory workerId enforcement: rejects null, undefined, empty, or mismatched worker IDs.
 * Verifies affected rows === 1; throws ConflictError if lease ownership was lost.
 * @param {string} jobId GUID
 * @param {string} arg2 workerId or reason
 * @param {string|sql.Transaction} [arg3] reason or transaction
 * @param {sql.Transaction|string} [arg4=null] transaction or workerId
 * @returns {Promise<object>}
 */
async function routeToManualReview(jobId, arg2, arg3, arg4 = null) {
    if (!jobId || typeof jobId !== 'string') {
        throw new ValidationError('Job ID is required for routeToManualReview.');
    }

    let workerId;
    let reason;
    let transaction = null;

    if (typeof arg2 === 'string' && typeof arg3 === 'string') {
        workerId = arg2;
        reason = arg3;
        transaction = arg4 instanceof sql.Transaction ? arg4 : null;
    } else if (typeof arg2 === 'string') {
        reason = arg2;
        transaction = arg3 instanceof sql.Transaction ? arg3 : null;
        workerId = typeof arg4 === 'string' ? arg4 : null;
    } else {
        reason = String(arg2 || '');
        transaction = arg3 instanceof sql.Transaction ? arg3 : null;
        workerId = typeof arg4 === 'string' ? arg4 : null;
    }

    const cleanWorkerId = validateWorkerId(workerId, 'routeToManualReview');

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .input('workerId', sql.NVarChar(100), cleanWorkerId)
            .input('reason', sql.NVarChar(sql.MAX), reason)
            .query(`
                UPDATE dbo.revocation_jobs
                SET
                    status = 'MANUAL_REVIEW_REQUIRED',
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    last_error_category = 'MANUAL_REVIEW_REQUIRED',
                    last_error_message = @reason,
                    error_details = @reason,
                    updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                OUTPUT
                    INSERTED.job_id,
                    INSERTED.grant_id,
                    INSERTED.status,
                    INSERTED.last_error_category,
                    INSERTED.updated_at
                WHERE job_id = @jobId
                  AND lease_owner = @workerId
                  AND lease_expires_at > TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                  AND status = 'PROCESSING';
            `);

        if (result.recordset.length !== 1) {
            logger.warn('Revocation job route to manual review matched 0 rows with worker lease check', { jobId, workerId: cleanWorkerId });
            return null;
        }

        return result.recordset[0];
    } catch (err) {
        if (err instanceof ValidationError) {
            throw err;
        }
        logger.error('Database update failed in routeToManualReview', { jobId, workerId: cleanWorkerId, error: err.message });
        throw new DatabaseError('Failed to route revocation job to manual review.', err);
    }
}

/**
 * Requeues a job for manual retry by resetting attempts and status to QUEUED.
 * Explicit administrative action. Requires job to be in a failed or review state.
 * @param {string} jobId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function requeueJobForManualRetry(jobId, transaction = null) {
    if (!jobId || typeof jobId !== 'string') {
        throw new ValidationError('Job ID is required for requeueJobForManualRetry.');
    }

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .query(`
                UPDATE dbo.revocation_jobs
                SET
                    status = 'QUEUED',
                    retry_count = 0,
                    next_retry_at = NULL,
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    last_error_category = NULL,
                    last_error_message = NULL,
                    updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                OUTPUT
                    INSERTED.job_id,
                    INSERTED.grant_id,
                    INSERTED.status,
                    INSERTED.retry_count,
                    INSERTED.lease_owner,
                    INSERTED.next_retry_at,
                    INSERTED.updated_at
                WHERE job_id = @jobId
                  AND status IN ('FAILED_RETRY', 'PERMANENT_FAILURE', 'MANUAL_REVIEW_REQUIRED');
            `);

        if (result.recordset.length !== 1) {
            throw new ConflictError(`Cannot requeue revocation job ${jobId}: Job is not in a failed or manual review state.`);
        }

        return result.recordset[0];
    } catch (err) {
        if (err instanceof ConflictError || err instanceof ValidationError) {
            throw err;
        }
        logger.error('Database update failed in requeueJobForManualRetry', { jobId, error: err.message });
        throw new DatabaseError('Failed to requeue revocation job for manual retry.', err);
    }
}

const ALLOWED_CONFIRMATION_SOURCES = [
    'GITHUB_ORGANIZATION_AUDIT_LOG',
    'ADMINISTRATIVE_PORTAL_CONFIRMATION',
    'GITHUB_UI_INSPECTION',
    'TICKET_VERIFICATION'
];

/**
 * Resolves a job in MANUAL_REVIEW_REQUIRED with an authorized decision.
 * Explicit administrative action. Requires notes for confirmed revocation.
 * @param {string} jobId GUID
 * @param {string} decision 'CONFIRMED_REVOKED' | 'DISMISSED' | 'RETRY'
 * @param {string|object} [notes=null] Justification string or structured evidence object
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function resolveManualReviewJob(jobId, decision, notes = null, transaction = null) {
    if (!jobId || typeof jobId !== 'string') {
        throw new ValidationError('Job ID is required for resolveManualReviewJob.');
    }
    const cleanDecision = decision ? decision.toUpperCase().trim() : '';
    if (!['CONFIRMED_REVOKED', 'REVOKED', 'DISMISSED', 'RETRY'].includes(cleanDecision)) {
        throw new ValidationError(`Invalid manual review decision '${decision}'. Must be CONFIRMED_REVOKED, DISMISSED, or RETRY.`);
    }

    const justification = typeof notes === 'string' ? notes.trim() : (notes?.justification || notes?.notes || '').trim();
    if ((cleanDecision === 'CONFIRMED_REVOKED' || cleanDecision === 'REVOKED') && (!justification || justification.length < 5)) {
        throw new ValidationError('A detailed justification (minimum 5 characters) is required to confirm manual revocation.');
    }

    let confirmationSource = typeof notes === 'object' ? notes?.confirmationSource : null;
    let evidenceReference = typeof notes === 'object' ? notes?.evidenceReference : null;
    let confirmedByUserId = typeof notes === 'object' ? (notes?.confirmedByUserId || notes?.actorUserId) : null;

    if (typeof notes === 'object' && confirmationSource) {
        if (!ALLOWED_CONFIRMATION_SOURCES.includes(confirmationSource)) {
            throw new ValidationError(
                `Invalid confirmation source '${confirmationSource}'. Allowed sources: ${ALLOWED_CONFIRMATION_SOURCES.join(', ')}.`
            );
        }
        if (!evidenceReference || !String(evidenceReference).trim()) {
            throw new ValidationError('Evidence reference is required when confirmation source is specified.');
        }
    } else {
        confirmationSource = confirmationSource || 'ADMINISTRATIVE_PORTAL_CONFIRMATION';
        evidenceReference = evidenceReference || 'MANUAL_ATTESTATION_WITHOUT_EXTERNAL_PROOF';
    }

    const attestationPayload = (cleanDecision === 'CONFIRMED_REVOKED' || cleanDecision === 'REVOKED')
        ? JSON.stringify({
            confirmationType: 'MANUAL_ATTESTATION',
            confirmedByUserId: confirmedByUserId || 'SYSTEM_ADMIN_OVERRIDE',
            confirmationSource,
            evidenceReference: String(evidenceReference).trim(),
            justification,
            confirmedAt: new Date().toISOString()
        })
        : null;

    try {
        const runner = transaction || await getPool();
        let targetStatus = 'PERMANENT_FAILURE';
        let confirmedAtClause = '';
        if (cleanDecision === 'CONFIRMED_REVOKED' || cleanDecision === 'REVOKED') {
            targetStatus = 'REVOKED';
            confirmedAtClause = ', confirmed_at = TODATETIMEOFFSET(SYSUTCDATETIME(), \'+00:00\')';
        } else if (cleanDecision === 'RETRY') {
            targetStatus = 'QUEUED';
        }

        const result = await runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .input('targetStatus', sql.NVarChar(30), targetStatus)
            .input('notes', sql.NVarChar(sql.MAX), justification || null)
            .input('connectorResponse', sql.NVarChar(sql.MAX), attestationPayload)
            .query(`
                UPDATE dbo.revocation_jobs
                SET
                    status = @targetStatus,
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    last_error_category = CASE WHEN @targetStatus = 'PERMANENT_FAILURE' THEN 'MANUAL_REVIEW_DISMISSED' ELSE last_error_category END,
                    connector_response = CASE WHEN @targetStatus = 'REVOKED' THEN COALESCE(@connectorResponse, connector_response) ELSE connector_response END,
                    error_details = COALESCE(@notes, error_details),
                    last_error_message = COALESCE(@notes, last_error_message),
                    updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                    ${confirmedAtClause}
                OUTPUT
                    INSERTED.job_id,
                    INSERTED.grant_id,
                    INSERTED.status,
                    INSERTED.last_error_category,
                    INSERTED.last_error_message,
                    INSERTED.connector_response,
                    INSERTED.confirmed_at,
                    INSERTED.updated_at
                WHERE job_id = @jobId
                  AND status = 'MANUAL_REVIEW_REQUIRED';
            `);

        if (result.recordset.length !== 1) {
            throw new ConflictError(`Cannot resolve manual review: Job ${jobId} is not in MANUAL_REVIEW_REQUIRED state.`);
        }

        return result.recordset[0];
    } catch (err) {
        if (err instanceof ConflictError || err instanceof ValidationError) {
            throw err;
        }
        logger.error('Database update failed in resolveManualReviewJob', { jobId, error: err.message });
        throw new DatabaseError('Failed to resolve manual review job.', err);
    }
}

/**
 * Updates status, proofs, and responses for a revocation job.
 * @param {string} jobId GUID
 * @param {object} updateData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function updateRevocationJobStatus(jobId, updateData, transaction = null) {
    const {
        status,
        retryCount,
        connectorResponse = null,
        errorDetails = null,
        cryptographicProofHash = null,
        proofBlobUrl = null,
        confirmedAt = null
    } = updateData;

    try {
        const runner = transaction || await getPool();
        const request = runner.request()
            .input('jobId', sql.UniqueIdentifier, jobId.trim())
            .input('status', sql.NVarChar(30), status)
            .input('connectorResponse', sql.NVarChar(sql.MAX), typeof connectorResponse === 'object' ? JSON.stringify(connectorResponse) : connectorResponse)
            .input('errorDetails', sql.NVarChar(sql.MAX), errorDetails)
            .input('cryptographicProofHash', sql.NVarChar(64), cryptographicProofHash)
            .input('proofBlobUrl', sql.NVarChar(2048), proofBlobUrl)
            .input('confirmedAt', sql.DateTimeOffset, confirmedAt);

        let retryClause = '';
        if (retryCount !== undefined && retryCount !== null) {
            retryClause = ', retry_count = @retryCount';
            request.input('retryCount', sql.Int, retryCount);
        }

        const result = await request.query(`
            UPDATE dbo.revocation_jobs
            SET status = @status,
                connector_response = COALESCE(@connectorResponse, connector_response),
                error_details = COALESCE(@errorDetails, error_details),
                cryptographic_proof_hash = COALESCE(@cryptographicProofHash, cryptographic_proof_hash),
                proof_blob_url = COALESCE(@proofBlobUrl, proof_blob_url),
                confirmed_at = COALESCE(@confirmedAt, confirmed_at),
                updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                ${retryClause}
            OUTPUT
                INSERTED.job_id,
                INSERTED.grant_id,
                INSERTED.status,
                INSERTED.retry_count,
                INSERTED.cryptographic_proof_hash,
                INSERTED.proof_blob_url,
                INSERTED.confirmed_at,
                INSERTED.updated_at
            WHERE job_id = @jobId;
        `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database update failed in updateRevocationJobStatus', { jobId, status, error: err.message });
        throw new DatabaseError('Failed to update revocation job status.', err);
    }
}

/**
 * Lists revocation jobs with pagination and rich filtering for UI / API.
 * @param {object} [filter={}] { status, triggerSource, contractorUserId, limit, offset }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<{ items: Array<object>, total: number }>}
 */
async function listRevocationJobs(filter = {}, transaction = null) {
    const {
        status,
        triggerSource,
        contractorUserId,
        limit = 50,
        offset = 0
    } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request()
            .input('limit', sql.Int, Math.min(100, Math.max(1, limit)))
            .input('offset', sql.Int, Math.max(0, offset));

        let whereClauses = [];
        if (status) {
            whereClauses.push('rj.status = @status');
            request.input('status', sql.NVarChar(30), status);
        }
        if (triggerSource) {
            whereClauses.push('rj.trigger_source = @triggerSource');
            request.input('triggerSource', sql.NVarChar(50), triggerSource);
        }
        if (contractorUserId) {
            whereClauses.push('ce.contractor_user_id = @contractorUserId');
            request.input('contractorUserId', sql.UniqueIdentifier, contractorUserId);
        }

        const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        const countQuery = `
            SELECT COUNT(*) AS total
            FROM dbo.revocation_jobs rj
            INNER JOIN dbo.access_grants ag ON rj.grant_id = ag.grant_id
            INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
            ${whereSql};
        `;
        const countResult = await request.query(countQuery);
        const total = countResult.recordset[0]?.total || 0;

        const dataQuery = `
            SELECT
                rj.job_id,
                rj.grant_id,
                rj.trigger_source,
                rj.status,
                rj.retry_count,
                rj.max_retries,
                rj.connector_name,
                rj.confirmed_at,
                rj.last_error_category,
                rj.last_error_message,
                rj.created_at,
                rj.updated_at,
                ag.grant_number,
                ag.expires_at,
                ag.status AS grant_status,
                ag.target_org,
                ag.target_team_slug,
                ag.external_username,
                ag.numeric_account_id,
                ag.membership_provenance,
                r.resource_code,
                r.resource_name,
                ce.engagement_id,
                ce.contractor_user_id,
                cu.display_name AS contractor_name,
                cu.email AS contractor_email
            FROM dbo.revocation_jobs rj
            INNER JOIN dbo.access_grants ag ON rj.grant_id = ag.grant_id
            INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
            INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
            INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
            ${whereSql}
            ORDER BY rj.created_at DESC
            OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;
        `;
        const dataResult = await request.query(dataQuery);

        return {
            items: dataResult.recordset || [],
            total
        };
    } catch (err) {
        logger.error('Database query failed in listRevocationJobs', { error: err.message });
        throw new DatabaseError('Failed to list revocation jobs.', err);
    }
}

/**
 * Serializes revocation decision and execution for a specific provider team membership
 * using SQL Server application locks (sp_getapplock).
 * Uses a deterministic, bounded SHA-256 hash resource key (REV_MEM_<hash>, 72 chars).
 * Prevents concurrent workers from racing on shared memberships for the same (org, team, user).
 * Handles timeouts and error codes explicitly.
 * @param {string} targetOrg GitHub Organization
 * @param {string} targetTeamSlug GitHub Team Slug
 * @param {string|number} accountIdentifier externalUsername or numericAccountId
 * @param {Function} callback Async callback function executed while holding exclusive lock (receives transaction)
 * @param {number} [timeoutMs=5000] Lock acquisition timeout in milliseconds
 * @returns {Promise<any>} Result of callback
 */
async function serializeMembershipDecision(targetOrg, targetTeamSlug, accountIdentifier, callback, timeoutMs = 5000, externalTransaction = null) {
    if (!targetOrg || !targetTeamSlug || !accountIdentifier) {
        throw new ValidationError('targetOrg, targetTeamSlug, and accountIdentifier are required for serializeMembershipDecision.');
    }

    const resourceKey = getMembershipLockKey(targetOrg, targetTeamSlug, accountIdentifier);
    const runner = externalTransaction ? async (fn) => fn(externalTransaction) : withTransaction;

    return runner(async (transaction) => {
        const lockRes = await transaction.request()
            .input('resourceKey', sql.NVarChar(255), resourceKey)
            .input('timeoutMs', sql.Int, timeoutMs)
            .query(`
                DECLARE @res INT;
                EXEC @res = sp_getapplock
                    @Resource = @resourceKey,
                    @LockMode = 'Exclusive',
                    @LockOwner = 'Transaction',
                    @LockTimeout = @timeoutMs;
                SELECT @res AS lock_code;
            `);

        const lockCode = lockRes?.recordset?.[0]?.lock_code;
        if (lockCode === -1) {
            const err = new ConflictError(`Lock acquisition timed out after ${timeoutMs}ms for resource ${resourceKey}`, 'ERR_MEMBERSHIP_LOCK_TIMEOUT');
            err.category = 'LOCK_TIMEOUT';
            throw err;
        } else if (lockCode === -2) {
            const err = new DatabaseError(`Lock acquisition was canceled for resource ${resourceKey}`);
            err.category = 'LOCK_CANCELLED';
            err.code = 'ERR_MEMBERSHIP_LOCK_CANCELLED';
            throw err;
        } else if (lockCode === -3) {
            const err = new ConflictError(`Lock acquisition was chosen as deadlock victim for resource ${resourceKey}`, 'ERR_MEMBERSHIP_LOCK_DEADLOCK');
            err.category = 'LOCK_DEADLOCK';
            throw err;
        } else if (lockCode < 0) {
            const err = new DatabaseError(`sp_getapplock failed with code ${lockCode} for resource ${resourceKey}`);
            err.category = 'LOCK_ERROR';
            err.code = 'ERR_MEMBERSHIP_LOCK_FAILED';
            throw err;
        }

        return await callback(transaction);
    });
}

/**
 * Atomically acquires or claims coordination ownership for a provider membership operation.
 * Coordinates cross-connector concurrency between provisioning and revocation engines.
 * @param {string} targetOrg
 * @param {string} targetTeamSlug
 * @param {string|number} accountIdentifier
 * @param {string} operation 'PROVISIONING' | 'REVOCATION'
 * @param {string} jobId
 * @param {string} workerId
 * @param {number} [leaseDurationSeconds=60]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>} { acquired: boolean, ... }
 */
async function acquireMembershipCoordination(targetOrg, targetTeamSlug, accountIdentifier, operation, jobId, workerId, leaseDurationSeconds = 60, transaction = null) {
    const key = getMembershipLockKey(targetOrg, targetTeamSlug, accountIdentifier);
    const cleanWorkerId = validateWorkerId(workerId, 'acquireMembershipCoordination');
    const runner = transaction || await getPool();

    const result = await runner.request()
        .input('key', sql.NVarChar(100), key)
        .input('org', sql.NVarChar(100), String(targetOrg).trim().toLowerCase())
        .input('team', sql.NVarChar(100), String(targetTeamSlug).trim().toLowerCase())
        .input('accountId', sql.NVarChar(100), String(accountIdentifier).trim().toLowerCase())
        .input('op', sql.NVarChar(30), operation)
        .input('jobId', sql.UniqueIdentifier, jobId)
        .input('workerId', sql.NVarChar(100), cleanWorkerId)
        .input('leaseDurationSeconds', sql.Int, leaseDurationSeconds)
        .query(`
            MERGE dbo.membership_coordination WITH (HOLDLOCK) AS target
            USING (SELECT @key AS coordination_key) AS source
            ON target.coordination_key = source.coordination_key
            WHEN MATCHED AND (
                target.active_operation = 'IDLE'
                OR target.lease_expires_at < TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                OR (target.worker_id = @workerId AND target.active_operation = @op)
            ) THEN
                UPDATE SET
                    active_operation = @op,
                    operation_job_id = @jobId,
                    worker_id = @workerId,
                    lease_expires_at = DATEADD(SECOND, @leaseDurationSeconds, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')),
                    updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
            WHEN NOT MATCHED THEN
                INSERT (coordination_key, target_org, target_team_slug, account_identifier, active_operation, operation_job_id, worker_id, lease_expires_at, created_at, updated_at)
                VALUES (@key, @org, @team, @accountId, @op, @jobId, @workerId, DATEADD(SECOND, @leaseDurationSeconds, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')), TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'), TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
            OUTPUT
                $action AS merge_action,
                INSERTED.coordination_key,
                INSERTED.active_operation,
                INSERTED.operation_job_id,
                INSERTED.worker_id,
                INSERTED.lease_expires_at,
                DELETED.active_operation AS prev_operation,
                DELETED.worker_id AS prev_worker_id,
                DELETED.lease_expires_at AS prev_lease_expires_at;
        `);

    if (result.recordset.length === 1) {
        const rec = result.recordset[0];
        const wasReclaimed = !!(rec.prev_lease_expires_at && new Date(rec.prev_lease_expires_at) < new Date());
        return { acquired: true, wasReclaimed, ...rec };
    }

    const current = await runner.request()
        .input('key', sql.NVarChar(100), key)
        .query(`SELECT TOP 1 * FROM dbo.membership_coordination WHERE coordination_key = @key`);

    return {
        acquired: false,
        coordinationKey: key,
        currentOperation: current.recordset[0]?.active_operation || 'UNKNOWN',
        currentWorkerId: current.recordset[0]?.worker_id || null,
        leaseExpiresAt: current.recordset[0]?.lease_expires_at || null
    };
}

/**
 * Attempts to acquire coordination ownership, waiting with exponential/polled backoff up to maxWaitMs.
 * @param {string} targetOrg
 * @param {string} targetTeamSlug
 * @param {string|number} accountIdentifier
 * @param {string} operation
 * @param {string} jobId
 * @param {string} workerId
 * @param {number} [leaseDurationSeconds=60]
 * @param {number} [maxWaitMs=3000]
 * @param {number} [pollIntervalMs=50]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function acquireMembershipCoordinationWithWait(targetOrg, targetTeamSlug, accountIdentifier, operation, jobId, workerId, leaseDurationSeconds = 60, maxWaitMs = 3000, pollIntervalMs = 50, transaction = null) {
    const startTime = Date.now();
    while (true) {
        const coord = await acquireMembershipCoordination(
            targetOrg,
            targetTeamSlug,
            accountIdentifier,
            operation,
            jobId,
            workerId,
            leaseDurationSeconds,
            transaction
        );
        if (coord.acquired) {
            return coord;
        }

        const elapsed = Date.now() - startTime;
        if (elapsed >= maxWaitMs) {
            return coord;
        }

        const delay = Math.min(pollIntervalMs, maxWaitMs - elapsed);
        await new Promise(resolve => setTimeout(resolve, delay));
    }
}

/**
 * Renews an active coordination lease if the worker is still the legitimate lease owner.
 * Rejects null, undefined, empty, or mismatched worker IDs and expired leases.
 * @param {string} targetOrg
 * @param {string} targetTeamSlug
 * @param {string|number} accountIdentifier
 * @param {string} workerId
 * @param {number} [extensionSeconds=60]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>} Updated coordination record or null if lost
 */
async function renewMembershipCoordination(targetOrg, targetTeamSlug, accountIdentifier, workerId, extensionSeconds = 60, transaction = null) {
    const key = getMembershipLockKey(targetOrg, targetTeamSlug, accountIdentifier);
    const cleanWorkerId = validateWorkerId(workerId, 'renewMembershipCoordination');
    const runner = transaction || await getPool();

    const result = await runner.request()
        .input('key', sql.NVarChar(100), key)
        .input('workerId', sql.NVarChar(100), cleanWorkerId)
        .input('extensionSeconds', sql.Int, extensionSeconds)
        .query(`
            UPDATE dbo.membership_coordination
            SET
                lease_expires_at = DATEADD(SECOND, @extensionSeconds, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')),
                updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
            OUTPUT
                INSERTED.coordination_key,
                INSERTED.active_operation,
                INSERTED.operation_job_id,
                INSERTED.worker_id,
                INSERTED.lease_expires_at,
                INSERTED.updated_at
            WHERE coordination_key = @key
              AND worker_id = @workerId
              AND active_operation <> 'IDLE'
              AND lease_expires_at > TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00');
        `);

    return result.recordset.length > 0 ? result.recordset[0] : null;
}

/**
 * Releases coordination ownership for a provider membership operation back to IDLE.
 * Enforces ownership fencing: only the active lease owner can release.
 * Validates unexpired lease to prevent stale workers from mutating state.
 * @param {string} targetOrg
 * @param {string} targetTeamSlug
 * @param {string|number} accountIdentifier
 * @param {string} workerId
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<boolean>} True if released, false if lease was lost or already expired
 */
async function releaseMembershipCoordination(targetOrg, targetTeamSlug, accountIdentifier, workerId, transaction = null) {
    const key = getMembershipLockKey(targetOrg, targetTeamSlug, accountIdentifier);
    const cleanWorkerId = validateWorkerId(workerId, 'releaseMembershipCoordination');
    const runner = transaction || await getPool();

    const result = await runner.request()
        .input('key', sql.NVarChar(100), key)
        .input('workerId', sql.NVarChar(100), cleanWorkerId)
        .query(`
            UPDATE dbo.membership_coordination
            SET
                active_operation = 'IDLE',
                worker_id = NULL,
                operation_job_id = NULL,
                lease_expires_at = NULL,
                last_reconciled_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'),
                updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
            OUTPUT
                INSERTED.coordination_key,
                INSERTED.active_operation,
                INSERTED.last_reconciled_at
            WHERE coordination_key = @key
              AND worker_id = @workerId
              AND active_operation <> 'IDLE'
              AND lease_expires_at > TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00');
        `);

    return result.recordset.length > 0;
}

/**
 * Retrieves the current coordination state for a provider membership.
 * @param {string} targetOrg
 * @param {string} targetTeamSlug
 * @param {string|number} accountIdentifier
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function getMembershipCoordination(targetOrg, targetTeamSlug, accountIdentifier, transaction = null) {
    const key = getMembershipLockKey(targetOrg, targetTeamSlug, accountIdentifier);
    const runner = transaction || await getPool();

    const result = await runner.request()
        .input('key', sql.NVarChar(100), key)
        .query(`SELECT TOP 1 * FROM dbo.membership_coordination WHERE coordination_key = @key`);

    return result.recordset.length > 0 ? result.recordset[0] : null;
}

/**
 * Verifies that the specified worker still holds an active, unexpired coordination lease
 * on the membership. Fences stale or replaced workers from performing operations.
 * @param {string} targetOrg
 * @param {string} targetTeamSlug
 * @param {string|number} accountIdentifier
 * @param {string} workerId
 * @param {string} [expectedOperation=null] 'REVOCATION' or 'PROVISIONING'
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<boolean>}
 */
async function verifyMembershipCoordinationActive(targetOrg, targetTeamSlug, accountIdentifier, workerId, expectedOperation = null, transaction = null) {
    if (!targetOrg || !targetTeamSlug || !accountIdentifier || !workerId) {
        return false;
    }
    const cleanWorkerId = String(workerId).trim();
    if (!cleanWorkerId) return false;

    const key = getMembershipLockKey(targetOrg, targetTeamSlug, accountIdentifier);
    try {
        const runner = transaction || await getPool();
        const req = runner.request()
            .input('key', sql.NVarChar(100), key)
            .input('workerId', sql.NVarChar(100), cleanWorkerId);

        let query = `
            SELECT 1 AS is_active
            FROM dbo.membership_coordination
            WHERE coordination_key = @key
              AND worker_id = @workerId
              AND active_operation <> 'IDLE'
              AND lease_expires_at > TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
        `;

        if (expectedOperation) {
            req.input('expectedOp', sql.NVarChar(30), expectedOperation);
            query += ` AND active_operation = @expectedOp`;
        }

        const result = await req.query(query);
        return result.recordset.length > 0;
    } catch (err) {
        logger.warn('Failed to verify active membership coordination', { targetOrg, targetTeamSlug, workerId, error: err.message });
        return false;
    }
}

/**
 * Calculates contractor offboarding status and metrics.
 * @param {string} contractorUserId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function getOffboardingStatus(contractorUserId, transaction = null) {
    if (!contractorUserId || typeof contractorUserId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('contractorUserId', sql.UniqueIdentifier, contractorUserId.trim())
            .query(`
                SELECT
                    ag.grant_id,
                    ag.grant_number,
                    ag.status AS grant_status,
                    ag.target_org,
                    ag.target_team_slug,
                    ag.membership_provenance,
                    rj.job_id,
                    rj.status AS job_status,
                    rj.trigger_source,
                    rj.last_error_category,
                    rj.last_error_message,
                    rj.confirmed_at
                FROM dbo.contractor_engagements ce
                INNER JOIN dbo.access_grants ag ON ag.contractor_engagement_id = ce.engagement_id
                LEFT JOIN dbo.revocation_jobs rj ON rj.grant_id = ag.grant_id
                WHERE ce.contractor_user_id = @contractorUserId;
            `);

        const rows = result.recordset || [];
        const totalGrants = rows.length;
        const activeGrants = rows.filter(r => r.grant_status === 'ACTIVE').length;
        const revokedGrants = rows.filter(r => r.grant_status === 'REVOKED' || r.job_status === 'REVOKED').length;
        const manualReviewJobs = rows.filter(r => r.job_status === 'MANUAL_REVIEW_REQUIRED' || r.grant_status === 'MANUAL_REVIEW_REQUIRED').length;
        const failedJobs = rows.filter(r => r.job_status === 'PERMANENT_FAILURE').length;
        const pendingJobs = rows.filter(r => ['QUEUED', 'PROCESSING', 'FAILED_RETRY', 'IN_PROGRESS'].includes(r.job_status) || r.grant_status === 'REVOKE_PENDING').length;

        let overallState = 'NOT_OFFBOARDED';
        if (totalGrants === 0) {
            overallState = 'NO_ACTIVE_GRANTS';
        } else if (manualReviewJobs > 0) {
            overallState = 'BLOCKED_MANUAL_REVIEW';
        } else if (failedJobs > 0) {
            overallState = 'FAILED';
        } else if (pendingJobs > 0 || activeGrants > 0) {
            overallState = 'IN_PROGRESS';
        } else if (revokedGrants === totalGrants && manualReviewJobs === 0 && failedJobs === 0 && pendingJobs === 0 && activeGrants === 0) {
            overallState = 'COMPLETED';
        }

        return {
            contractorUserId,
            totalGrants,
            activeGrants,
            revokedGrants,
            pendingJobs,
            manualReviewJobs,
            failedJobs,
            overallState,
            grants: rows
        };
    } catch (err) {
        logger.error('Database query failed in getOffboardingStatus', { contractorUserId, error: err.message });
        throw new DatabaseError('Failed to get offboarding status.', err);
    }
}

module.exports = {
    findRevocationJobById,
    getRevocationJobsByGrantId,
    listPendingRevocationJobs,
    createRevocationJob,
    claimNextRevocationJob,
    claimRevocationJobById,
    countSharedActiveGrants,
    findExpiredGrantsWithoutJobs,
    findActiveGrantsByEngagementId,
    renewJobLease,
    verifyJobLeaseActive,
    completeRevocationJob,
    failRevocationJob,
    routeToManualReview,
    requeueJobForManualRetry,
    resolveManualReviewJob,
    updateRevocationJobStatus,
    listRevocationJobs,
    serializeMembershipDecision,
    getMembershipLockKey,
    validateWorkerId,
    acquireMembershipCoordination,
    acquireMembershipCoordinationWithWait,
    renewMembershipCoordination,
    releaseMembershipCoordination,
    getMembershipCoordination,
    verifyMembershipCoordinationActive,
    resolveCanonicalAccountId,
    getOffboardingStatus,
    ALLOWED_CONFIRMATION_SOURCES
};
