/**
 * AccessLease — Orphan & Stale Access Finding Repository
 * Data access for dbo.orphan_access_findings.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError, ValidationError, NotFoundError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Executes authoritative SQL detection queries to identify all orphan and stale access grants.
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>} List of detected raw candidate findings
 */
async function detectOrphanGrants(transaction = null) {
    try {
        const runner = transaction || await getPool();

        // Authoritative query checking all 5 detection rules in single query
        const result = await runner.request().query(`
            -- 1. Active grants for terminated, completed, or cancelled contractor engagements
            SELECT
                ag.grant_id,
                'ENDED_ENGAGEMENT_ACTIVE_GRANT' AS finding_reason,
                'CRITICAL' AS severity,
                JSON_QUERY((
                    SELECT
                        ag.grant_number,
                        ag.status AS grant_status,
                        ag.expires_at,
                        ce.engagement_id,
                        ce.status AS engagement_status,
                        ce.end_date AS engagement_end_date,
                        cu.user_id AS contractor_user_id,
                        cu.display_name AS contractor_name,
                        cu.email AS contractor_email,
                        r.resource_id,
                        r.resource_name,
                        e.entitlement_name
                    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
                )) AS details
            FROM dbo.access_grants ag
            INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
            INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
            INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
            INNER JOIN dbo.entitlements e ON ag.entitlement_id = e.entitlement_id
            WHERE ag.status IN ('ACTIVE', 'PROVISIONING_PENDING', 'PENDING_ACCEPTANCE', 'MANUAL_REVIEW_REQUIRED')
              AND ce.status IN ('TERMINATED', 'COMPLETED', 'CANCELLED')

            UNION ALL

            -- 2. Active grants whose engagement end_date has expired in UTC
            SELECT
                ag.grant_id,
                'EXPIRED_ENGAGEMENT_ACTIVE_GRANT' AS finding_reason,
                'CRITICAL' AS severity,
                JSON_QUERY((
                    SELECT
                        ag.grant_number,
                        ag.status AS grant_status,
                        ag.expires_at,
                        ce.engagement_id,
                        ce.status AS engagement_status,
                        ce.end_date AS engagement_end_date,
                        cu.user_id AS contractor_user_id,
                        cu.display_name AS contractor_name,
                        cu.email AS contractor_email,
                        r.resource_id,
                        r.resource_name,
                        e.entitlement_name
                    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
                )) AS details
            FROM dbo.access_grants ag
            INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
            INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
            INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
            INNER JOIN dbo.entitlements e ON ag.entitlement_id = e.entitlement_id
            WHERE ag.status IN ('ACTIVE', 'PROVISIONING_PENDING', 'PENDING_ACCEPTANCE', 'MANUAL_REVIEW_REQUIRED')
              AND ce.status = 'ACTIVE'
              AND ce.end_date < CAST(SYSUTCDATETIME() AS DATE)

            UNION ALL

            -- 3. Grants past their expiry date (expires_at in UTC) that remain ACTIVE
            SELECT
                ag.grant_id,
                'EXPIRED_GRANT_ACTIVE_STATUS' AS finding_reason,
                'CRITICAL' AS severity,
                JSON_QUERY((
                    SELECT
                        ag.grant_number,
                        ag.status AS grant_status,
                        ag.expires_at,
                        ce.engagement_id,
                        ce.status AS engagement_status,
                        cu.user_id AS contractor_user_id,
                        cu.display_name AS contractor_name,
                        cu.email AS contractor_email,
                        r.resource_id,
                        r.resource_name,
                        e.entitlement_name
                    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
                )) AS details
            FROM dbo.access_grants ag
            INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
            INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
            INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
            INNER JOIN dbo.entitlements e ON ag.entitlement_id = e.entitlement_id
            WHERE ag.status = 'ACTIVE'
              AND ag.expires_at <= TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')

            UNION ALL

            -- 4. Active grants referencing inactive/disabled contractor or resource
            SELECT
                ag.grant_id,
                'INVALID_OR_DELETED_REFERENCE' AS finding_reason,
                'HIGH' AS severity,
                JSON_QUERY((
                    SELECT
                        ag.grant_number,
                        ag.status AS grant_status,
                        ag.expires_at,
                        cu.is_active AS contractor_is_active,
                        r.is_active AS resource_is_active,
                        cu.user_id AS contractor_user_id,
                        cu.display_name AS contractor_name,
                        r.resource_id,
                        r.resource_name
                    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
                )) AS details
            FROM dbo.access_grants ag
            INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
            INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
            INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
            WHERE ag.status IN ('ACTIVE', 'PROVISIONING_PENDING', 'PENDING_ACCEPTANCE')
              AND (cu.is_active = 0 OR r.is_active = 0)

            UNION ALL

            -- 5. Inconsistent lifecycle states requiring investigation
            SELECT
                ag.grant_id,
                'INCONSISTENT_LIFECYCLE_STATE' AS finding_reason,
                'MEDIUM' AS severity,
                JSON_QUERY((
                    SELECT
                        ag.grant_number,
                        ag.status AS grant_status,
                        ag.expires_at,
                        ag.updated_at,
                        'Revocation pending with no active worker job for > 1 hour' AS issue_description
                    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER
                )) AS details
            FROM dbo.access_grants ag
            WHERE ag.status = 'REVOKE_PENDING'
              AND ag.updated_at < DATEADD(HOUR, -1, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
              AND NOT EXISTS (
                  SELECT 1 FROM dbo.revocation_jobs rj
                  WHERE rj.grant_id = ag.grant_id
                    AND rj.status IN ('QUEUED', 'PROCESSING', 'FAILED_RETRY')
              );
        `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in detectOrphanGrants', { error: err.message });
        throw new DatabaseError('Failed to execute orphan access detection query.', err);
    }
}

/**
 * Upserts a detected finding into dbo.orphan_access_findings.
 * If an active finding (OPEN, INVESTIGATING, or REVOCATION_INITIATED) already exists
 * for (grant_id, finding_reason), refreshes last_detected_at and details while preserving
 * current status and existing revocation job references.
 * Does not reopen RESOLVED or FALSE_POSITIVE findings unless allowReopen is explicitly true.
 * @param {object} findingData { grantId, findingReason, severity, details, allowReopen }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<{ finding: object, isNew: boolean, isSuppressed?: boolean }>}
 */
async function recordFinding(findingData, transaction = null) {
    const {
        grantId,
        findingReason,
        severity,
        details = null,
        allowReopen = false
    } = findingData;

    if (!grantId || !findingReason || !severity) {
        throw new ValidationError('grantId, findingReason, and severity are required.');
    }

    try {
        const runner = transaction || await getPool();
        const detailsJson = typeof details === 'object' && details !== null ? JSON.stringify(details) : details;

        // Check if an existing finding exists for this grant and reason
        // Use UPDLOCK, HOLDLOCK to safely serialize concurrent scans
        const existingRes = await runner.request()
            .input('grantId', sql.UniqueIdentifier, grantId)
            .input('findingReason', sql.NVarChar(100), findingReason)
            .query(`
                SELECT TOP 1
                    finding_id,
                    grant_id,
                    finding_reason,
                    severity,
                    status,
                    first_detected_at,
                    last_detected_at,
                    resolved_at,
                    resolved_by_user_id,
                    resolution_notes,
                    revocation_job_id,
                    created_at,
                    updated_at
                FROM dbo.orphan_access_findings WITH (UPDLOCK, HOLDLOCK)
                WHERE grant_id = @grantId AND finding_reason = @findingReason
                ORDER BY CASE status
                    WHEN 'OPEN' THEN 1
                    WHEN 'INVESTIGATING' THEN 2
                    WHEN 'REVOCATION_INITIATED' THEN 3
                    WHEN 'RESOLVED' THEN 4
                    WHEN 'FALSE_POSITIVE' THEN 5
                    ELSE 6
                END ASC;
            `);

        const existing = existingRes.recordset[0];

        if (existing) {
            // Case 1: Active finding (OPEN, INVESTIGATING, or REVOCATION_INITIATED)
            if (['OPEN', 'INVESTIGATING', 'REVOCATION_INITIATED'].includes(existing.status)) {
                // Update last_detected_at and details, PRESERVING status and revocation_job_id!
                const updateRes = await runner.request()
                    .input('findingId', sql.UniqueIdentifier, existing.finding_id)
                    .input('details', sql.NVarChar(sql.MAX), detailsJson)
                    .query(`
                        UPDATE dbo.orphan_access_findings
                        SET
                            last_detected_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'),
                            details = COALESCE(@details, details),
                            updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                        OUTPUT
                            'UPDATE' AS merge_action,
                            INSERTED.finding_id,
                            INSERTED.grant_id,
                            INSERTED.finding_reason,
                            INSERTED.severity,
                            INSERTED.status,
                            INSERTED.first_detected_at,
                            INSERTED.last_detected_at,
                            INSERTED.resolved_at,
                            INSERTED.resolved_by_user_id,
                            INSERTED.resolution_notes,
                            INSERTED.revocation_job_id,
                            INSERTED.created_at,
                            INSERTED.updated_at
                        WHERE finding_id = @findingId;
                    `);

                return {
                    finding: updateRes.recordset[0],
                    isNew: false
                };
            }

            // Case 2: Inactive / resolved finding (RESOLVED or FALSE_POSITIVE)
            // "Do not reopen resolved or false-positive findings automatically without an explicit new detection policy."
            if (!allowReopen) {
                return {
                    finding: existing,
                    isNew: false,
                    isSuppressed: true
                };
            }
        }

        // Case 3: No existing finding (or allowReopen is true for resolved findings)
        const insertRes = await runner.request()
            .input('grantId', sql.UniqueIdentifier, grantId)
            .input('findingReason', sql.NVarChar(100), findingReason)
            .input('severity', sql.NVarChar(30), severity)
            .input('details', sql.NVarChar(sql.MAX), detailsJson)
            .query(`
                INSERT INTO dbo.orphan_access_findings (
                    grant_id,
                    finding_reason,
                    severity,
                    status,
                    details,
                    first_detected_at,
                    last_detected_at,
                    created_at,
                    updated_at
                )
                OUTPUT
                    'INSERT' AS merge_action,
                    INSERTED.finding_id,
                    INSERTED.grant_id,
                    INSERTED.finding_reason,
                    INSERTED.severity,
                    INSERTED.status,
                    INSERTED.first_detected_at,
                    INSERTED.last_detected_at,
                    INSERTED.resolved_at,
                    INSERTED.resolved_by_user_id,
                    INSERTED.resolution_notes,
                    INSERTED.revocation_job_id,
                    INSERTED.created_at,
                    INSERTED.updated_at
                VALUES (
                    @grantId,
                    @findingReason,
                    @severity,
                    'OPEN',
                    @details,
                    TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'),
                    TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'),
                    TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'),
                    TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                );
            `);

        return {
            finding: insertRes.recordset[0],
            isNew: true
        };
    } catch (err) {
        logger.error('Database query failed in recordFinding', { grantId, findingReason, error: err.message });
        throw new DatabaseError('Failed to record orphan access finding.', err);
    }
}

/**
 * Lists findings with pagination and filtering.
 * @param {object} [filter={}] { status, severity, reason, limit, offset }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<{ findings: Array<object>, total: number }>}
 */
async function listFindings(filter = {}, transaction = null) {
    const {
        status,
        severity,
        reason,
        limit = 50,
        offset = 0
    } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let whereClause = '1=1';

        if (status) {
            whereClause += ' AND oaf.status = @status';
            request.input('status', sql.NVarChar(30), status);
        }

        if (severity) {
            whereClause += ' AND oaf.severity = @severity';
            request.input('severity', sql.NVarChar(30), severity);
        }

        if (reason) {
            whereClause += ' AND oaf.finding_reason = @reason';
            request.input('reason', sql.NVarChar(100), reason);
        }

        // Count total matching
        const countQuery = `
            SELECT COUNT(*) AS total
            FROM dbo.orphan_access_findings oaf
            WHERE ${whereClause};
        `;
        const countRes = await request.query(countQuery);
        const total = countRes.recordset[0]?.total || 0;

        // Fetch paginated results
        const dataQuery = `
            SELECT
                oaf.finding_id,
                oaf.grant_id,
                oaf.finding_reason,
                oaf.severity,
                oaf.status,
                oaf.details,
                oaf.first_detected_at,
                oaf.last_detected_at,
                oaf.resolved_at,
                oaf.resolved_by_user_id,
                oaf.resolution_notes,
                oaf.revocation_job_id,
                oaf.created_at,
                oaf.updated_at,
                ag.grant_number,
                ag.status AS grant_status,
                ag.expires_at AS grant_expires_at,
                cu.display_name AS contractor_name,
                cu.email AS contractor_email,
                su.display_name AS sponsor_name,
                r.resource_name,
                e.entitlement_name,
                ce.status AS engagement_status,
                ce.end_date AS engagement_end_date,
                res_u.display_name AS resolved_by_name
            FROM dbo.orphan_access_findings oaf
            INNER JOIN dbo.access_grants ag ON oaf.grant_id = ag.grant_id
            INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
            INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
            INNER JOIN dbo.users su ON ce.sponsor_user_id = su.user_id
            INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
            INNER JOIN dbo.entitlements e ON ag.entitlement_id = e.entitlement_id
            LEFT JOIN dbo.users res_u ON oaf.resolved_by_user_id = res_u.user_id
            WHERE ${whereClause}
            ORDER BY
                CASE oaf.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END ASC,
                oaf.last_detected_at DESC
            OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;
        `;

        request.input('offset', sql.Int, Math.max(0, parseInt(offset, 10) || 0));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, parseInt(limit, 10) || 50)));

        const dataRes = await request.query(dataQuery);

        return {
            findings: dataRes.recordset || [],
            total
        };
    } catch (err) {
        logger.error('Database query failed in listFindings', { error: err.message });
        throw new DatabaseError('Failed to list orphan access findings.', err);
    }
}

/**
 * Finds finding by primary key.
 * @param {string} findingId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findFindingById(findingId, transaction = null) {
    if (!findingId || typeof findingId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('findingId', sql.UniqueIdentifier, findingId.trim())
            .query(`
                SELECT
                    oaf.finding_id,
                    oaf.grant_id,
                    oaf.finding_reason,
                    oaf.severity,
                    oaf.status,
                    oaf.details,
                    oaf.first_detected_at,
                    oaf.last_detected_at,
                    oaf.resolved_at,
                    oaf.resolved_by_user_id,
                    oaf.resolution_notes,
                    oaf.revocation_job_id,
                    oaf.created_at,
                    oaf.updated_at,
                    ag.grant_number,
                    ag.status AS grant_status,
                    ag.expires_at AS grant_expires_at,
                    ag.target_org,
                    ag.target_team_slug,
                    ag.external_username,
                    ag.membership_provenance,
                    cu.display_name AS contractor_name,
                    cu.email AS contractor_email,
                    su.display_name AS sponsor_name,
                    su.email AS sponsor_email,
                    r.resource_name,
                    e.entitlement_name,
                    ce.engagement_id,
                    ce.status AS engagement_status,
                    ce.end_date AS engagement_end_date,
                    rj.status AS revocation_job_status,
                    res_u.display_name AS resolved_by_name
                FROM dbo.orphan_access_findings oaf
                INNER JOIN dbo.access_grants ag ON oaf.grant_id = ag.grant_id
                INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id
                INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
                INNER JOIN dbo.users su ON ce.sponsor_user_id = su.user_id
                INNER JOIN dbo.resources r ON ag.resource_id = r.resource_id
                INNER JOIN dbo.entitlements e ON ag.entitlement_id = e.entitlement_id
                LEFT JOIN dbo.revocation_jobs rj ON oaf.revocation_job_id = rj.job_id
                LEFT JOIN dbo.users res_u ON oaf.resolved_by_user_id = res_u.user_id
                WHERE oaf.finding_id = @findingId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findFindingById', { findingId, error: err.message });
        throw new DatabaseError('Failed to find orphan access finding.', err);
    }
}

/**
 * Updates status and resolution details of a finding.
 * @param {string} findingId GUID
 * @param {object} updateData { status, resolvedByUserId, resolutionNotes, revocationJobId }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>} Updated finding record
 */
async function updateFindingStatus(findingId, updateData, transaction = null) {
    if (!findingId) throw new ValidationError('Finding ID is required.');
    const {
        status,
        resolvedByUserId = null,
        resolutionNotes = null,
        revocationJobId = null
    } = updateData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('findingId', sql.UniqueIdentifier, findingId.trim())
            .input('status', sql.NVarChar(30), status)
            .input('resolvedByUserId', sql.UniqueIdentifier, resolvedByUserId)
            .input('resolutionNotes', sql.NVarChar(1000), resolutionNotes)
            .input('revocationJobId', sql.UniqueIdentifier, revocationJobId)
            .query(`
                UPDATE dbo.orphan_access_findings
                SET
                    status = @status,
                    resolved_at = CASE WHEN @status IN ('RESOLVED', 'FALSE_POSITIVE', 'REVOCATION_INITIATED') THEN TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00') ELSE resolved_at END,
                    resolved_by_user_id = COALESCE(@resolvedByUserId, resolved_by_user_id),
                    resolution_notes = COALESCE(@resolutionNotes, resolution_notes),
                    revocation_job_id = COALESCE(@revocationJobId, revocation_job_id),
                    updated_at = TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                OUTPUT
                    INSERTED.finding_id,
                    INSERTED.grant_id,
                    INSERTED.finding_reason,
                    INSERTED.severity,
                    INSERTED.status,
                    INSERTED.resolved_at,
                    INSERTED.resolved_by_user_id,
                    INSERTED.resolution_notes,
                    INSERTED.revocation_job_id,
                    INSERTED.updated_at
                WHERE finding_id = @findingId;
            `);

        if (result.recordset.length === 0) {
            throw new NotFoundError('Finding record not found.', 'ERR_FINDING_NOT_FOUND');
        }

        return result.recordset[0];
    } catch (err) {
        if (err instanceof NotFoundError || err instanceof ValidationError) throw err;
        logger.error('Database update failed in updateFindingStatus', { findingId, status, error: err.message });
        throw new DatabaseError('Failed to update finding status.', err);
    }
}

/**
 * Counts open findings grouped by severity for analytics.
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<{ critical: number, high: number, medium: number, low: number, total: number }>}
 */
async function countOpenFindingsBySeverity(transaction = null) {
    try {
        const runner = transaction || await getPool();
        const result = await runner.request().query(`
            SELECT
                severity,
                COUNT(*) AS count
            FROM dbo.orphan_access_findings
            WHERE status = 'OPEN'
            GROUP BY severity;
        `);

        const counts = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
        for (const row of result.recordset) {
            const sev = (row.severity || '').toLowerCase();
            if (counts[sev] !== undefined) {
                counts[sev] = row.count;
            }
            counts.total += row.count;
        }

        return counts;
    } catch (err) {
        logger.error('Database query failed in countOpenFindingsBySeverity', { error: err.message });
        throw new DatabaseError('Failed to count findings by severity.', err);
    }
}

module.exports = {
    detectOrphanGrants,
    recordFinding,
    listFindings,
    findFindingById,
    updateFindingStatus,
    countOpenFindingsBySeverity
};

