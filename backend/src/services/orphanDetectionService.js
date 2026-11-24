/**
 * AccessLease — Orphan & Stale Access Detection Service
 * Real database-driven governance service detecting orphaned access,
 * expired grants, and terminated contractor entitlements.
 */

const { orphanFindingRepository, auditRepository } = require('../repositories');
const revocationService = require('./revocationService');
const { hasAnyRole } = require('../security/permissionPolicy');
const { ValidationError, NotFoundError, ForbiddenError, ConflictError } = require('../utils/errors');
const logger = require('../utils/logger');

// Mutex queue to serialize concurrent scan executions safely
let scanMutex = Promise.resolve();

/**
 * Runs an on-demand or periodic orphan access detection scan against live database state.
 * Prevents duplicate active findings by upserting and refreshing existing open findings.
 * Serializes concurrent execution to prevent race conditions.
 * @param {object} [actorUser=null] Authenticated user triggering the scan, or null if system timer
 * @param {object} [options={}] Optional parameters (e.g. allowReopen)
 * @returns {Promise<{ scannedAt: string, totalDetected: number, newCount: number, updatedCount: number }>}
 */
async function runOrphanDetectionScan(actorUser = null, options = {}) {
    const currentTask = scanMutex.then(async () => {
        return await executeDetectionScan(actorUser, options);
    });
    scanMutex = currentTask.catch(() => {});
    return await currentTask;
}

/**
 * Internal execution of detection scan logic.
 */
async function executeDetectionScan(actorUser, options = {}) {
    logger.info('Starting orphan access detection scan', { actorId: actorUser?.user_id || 'SYSTEM' });

    const candidates = await orphanFindingRepository.detectOrphanGrants();
    let newCount = 0;
    let updatedCount = 0;

    for (const cand of candidates) {
        try {
            const result = await orphanFindingRepository.recordFinding({
                grantId: cand.grant_id,
                findingReason: cand.finding_reason,
                severity: cand.severity,
                details: cand.details,
                allowReopen: Boolean(options.allowReopen)
            });

            if (result.isNew) {
                newCount++;
            } else if (!result.isSuppressed) {
                updatedCount++;
            }
        } catch (err) {
            logger.error('Failed to record orphan finding for candidate', {
                grantId: cand.grant_id,
                reason: cand.finding_reason,
                error: err.message
            });
        }
    }

    const scanTimestamp = new Date().toISOString();

    // Record audit event for scan execution
    await auditRepository.createAuditEvent({
        eventCategory: 'SECURITY_POLICY',
        eventAction: 'ORPHAN_ACCESS_SCAN_COMPLETED',
        entityType: 'orphan_access_findings',
        entityId: 'SYSTEM_SCAN',
        actorUserId: actorUser ? actorUser.user_id : null,
        actorType: actorUser ? 'USER' : 'SYSTEM_TIMER',
        eventPayload: {
            scannedAt: scanTimestamp,
            totalDetected: candidates.length,
            newCount,
            updatedCount
        }
    });

    logger.info('Orphan access detection scan completed', {
        totalDetected: candidates.length,
        newCount,
        updatedCount
    });

    return {
        scannedAt: scanTimestamp,
        totalDetected: candidates.length,
        newCount,
        updatedCount
    };
}

/**
 * Lists orphan access findings with pagination and filtering.
 * @param {object} [filters={}]
 * @returns {Promise<{ findings: Array<object>, total: number }>}
 */
async function getFindings(filters = {}) {
    return await orphanFindingRepository.listFindings(filters);
}

/**
 * Retrieves details for a specific finding.
 * @param {string} findingId GUID
 * @returns {Promise<object>}
 */
async function getFindingDetails(findingId) {
    if (!findingId) throw new ValidationError('Finding ID is required.');
    const finding = await orphanFindingRepository.findFindingById(findingId);
    if (!finding) {
        throw new NotFoundError('Orphan access finding', 'ERR_FINDING_NOT_FOUND');
    }
    return finding;
}

/**
 * Initiates the formal revocation workflow for a confirmed orphan access finding.
 * Never bypasses the existing revocation engine or GitHub provider verification.
 * @param {string} findingId GUID
 * @param {object} actorUser User authorizing the revocation
 * @param {string} [resolutionNotes=null]
 * @returns {Promise<{ finding: object, revocationJob: object }>}
 */
async function initiateFindingRevocation(findingId, actorUser, resolutionNotes = null) {
    if (!findingId) throw new ValidationError('Finding ID is required.');
    if (!actorUser) throw new ForbiddenError('Actor user is required.');

    // Only Security Officers and System Admins may authorize orphan revocation
    const isAuthorized = hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER']);
    if (!isAuthorized) {
        throw new ForbiddenError(
            'Access denied: Only Security Officers or System Administrators may initiate revocation for orphan findings.',
            'ERR_FORBIDDEN_ORPHAN_REVOCATION'
        );
    }

    const finding = await orphanFindingRepository.findFindingById(findingId);
    if (!finding) {
        throw new NotFoundError('Orphan access finding', 'ERR_FINDING_NOT_FOUND');
    }

    if (!['OPEN', 'INVESTIGATING'].includes(finding.status)) {
        throw new ValidationError(
            `Finding cannot be revoked because it is in '${finding.status}' status. Only OPEN or INVESTIGATING findings may be revoked.`,
            'ERR_INVALID_FINDING_STATUS'
        );
    }

    const finalNotes = resolutionNotes
        ? resolutionNotes.trim()
        : `Orphan access confirmed by ${actorUser.display_name || actorUser.email}: ${finding.finding_reason}`;

    // Delegate to existing revocation engine
    const revResult = await revocationService.enqueueGrantRevocation(
        finding.grant_id,
        'ORPHAN_DETECTION',
        actorUser,
        {
            reason: finalNotes,
            autoProcess: true
        }
    );

    const updatedFinding = await orphanFindingRepository.updateFindingStatus(findingId, {
        status: 'REVOCATION_INITIATED',
        resolvedByUserId: actorUser.user_id,
        resolutionNotes: finalNotes,
        revocationJobId: revResult.job?.job_id || null
    });

    await auditRepository.createAuditEvent({
        eventCategory: 'SECURITY_POLICY',
        eventAction: 'ORPHAN_REVOCATION_INITIATED',
        entityType: 'orphan_access_findings',
        entityId: findingId,
        actorUserId: actorUser.user_id,
        actorType: 'USER',
        eventPayload: {
            findingId,
            grantId: finding.grant_id,
            grantNumber: finding.grant_number,
            findingReason: finding.finding_reason,
            revocationJobId: revResult.job?.job_id || null,
            resolutionNotes: finalNotes
        }
    });

    return {
        finding: updatedFinding,
        revocationJob: revResult.job
    };
}

/**
 * Resolves or dismisses an orphan access finding without revoking (e.g. marked FALSE_POSITIVE).
 * Enforces:
 * 1. Blocks resolution while an automated revocation job is actively pending or processing,
 *    unless an explicit authorized administrative override is granted.
 * 2. Prevents status contradictions between finding status and provider grant state.
 * @param {string} findingId GUID
 * @param {object} actorUser User resolving the finding
 * @param {string} status 'RESOLVED' | 'FALSE_POSITIVE'
 * @param {string} resolutionNotes Justification for resolving or marking false positive
 * @param {object} [options={}] Optional parameters (allowOverride, adminOverride)
 * @returns {Promise<object>}
 */
async function resolveFinding(findingId, actorUser, status, resolutionNotes, options = {}) {
    if (!findingId) throw new ValidationError('Finding ID is required.');
    if (!actorUser) throw new ForbiddenError('Actor user is required.');
    if (!resolutionNotes || !resolutionNotes.trim()) {
        throw new ValidationError('A resolution note / justification is required.');
    }

    if (!['RESOLVED', 'FALSE_POSITIVE'].includes(status)) {
        throw new ValidationError("Status must be either 'RESOLVED' or 'FALSE_POSITIVE'.");
    }

    const isAuthorized = hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER']);
    if (!isAuthorized) {
        throw new ForbiddenError(
            'Access denied: Only Security Officers or System Administrators may resolve orphan findings.',
            'ERR_FORBIDDEN_ORPHAN_RESOLUTION'
        );
    }

    const finding = await orphanFindingRepository.findFindingById(findingId);
    if (!finding) {
        throw new NotFoundError('Orphan access finding', 'ERR_FINDING_NOT_FOUND');
    }

    const hasOverride = Boolean(options.allowOverride || options.adminOverride);

    // 1. Block ordinary resolution if an automated revocation job is actively pending or processing
    if (finding.revocation_job_id && ['QUEUED', 'PROCESSING'].includes(finding.revocation_job_status)) {
        if (!hasOverride) {
            throw new ConflictError(
                'Cannot resolve finding while an automated revocation job is actively pending or processing.',
                'ERR_PENDING_REVOCATION_ACTIVE'
            );
        }
    }

    // 2. Prevent contradiction: A finding cannot be marked RESOLVED while the grant is still ACTIVE in the provider
    if (status === 'RESOLVED' && finding.grant_status === 'ACTIVE' && !hasOverride) {
        throw new ConflictError(
            'Cannot mark finding RESOLVED while the access grant remains ACTIVE. Revoke the grant or mark FALSE_POSITIVE with justification.',
            'ERR_FINDING_STATUS_CONTRADICTION'
        );
    }

    const updatedFinding = await orphanFindingRepository.updateFindingStatus(findingId, {
        status,
        resolvedByUserId: actorUser.user_id,
        resolutionNotes: resolutionNotes.trim()
    });

    await auditRepository.createAuditEvent({
        eventCategory: 'SECURITY_POLICY',
        eventAction: 'ORPHAN_FINDING_RESOLVED',
        entityType: 'orphan_access_findings',
        entityId: findingId,
        actorUserId: actorUser.user_id,
        actorType: 'USER',
        eventPayload: {
            findingId,
            grantId: finding.grant_id,
            grantNumber: finding.grant_number,
            newStatus: status,
            resolutionNotes: resolutionNotes.trim(),
            isAdministrativeOverride: hasOverride,
            revocationJobId: finding.revocation_job_id || null
        }
    });

    return updatedFinding;
}

module.exports = {
    runOrphanDetectionScan,
    getFindings,
    getFindingDetails,
    initiateFindingRevocation,
    resolveFinding
};

