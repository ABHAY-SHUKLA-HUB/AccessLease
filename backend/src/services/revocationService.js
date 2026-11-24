/**
 * AccessLease — Automated Expiry, Revocation & Offboarding Service
 * Orchestrates scheduled access expiry, immediate contractor offboarding,
 * manual retry authorization, manual review resolution, and offboarding progress queries.
 */

const { withTransaction } = require('../config/database');
const {
    revocationRepository,
    grantRepository,
    engagementRepository,
    auditRepository
} = require('../repositories');
const revocationWorker = require('./revocationWorker');
const { hasRole, hasAnyRole } = require('../security/permissionPolicy');
const {
    ValidationError,
    NotFoundError,
    ForbiddenError,
    ConflictError
} = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Scans for expired grants and completed/ended contractor engagements,
 * enqueuing idempotent revocation jobs for background processing.
 * @param {object} [options={}] { batchSize, autoProcess }
 * @returns {Promise<{ scannedCount: number, jobsCreated: number, workerOutcomes: Array<object> }>}
 */
async function processExpiredGrants(options = {}) {
    const { batchSize = 50, autoProcess = true } = options;

    logger.info('Running automated access expiry scan', { batchSize });

    const expiredGrants = await revocationRepository.findExpiredGrantsWithoutJobs(batchSize);
    let jobsCreated = 0;
    const createdJobIds = [];

    for (const grant of expiredGrants) {
        const idempotencyKey = `REVOCATION_ACTIVE_${grant.grant_id}`;

        try {
            const job = await withTransaction(async (transaction) => {
                const newJob = await revocationRepository.createRevocationJob({
                    grantId: grant.grant_id,
                    triggerSource: 'SCHEDULED_EXPIRATION',
                    connectorName: 'GITHUB',
                    idempotencyKey
                }, transaction);

                await grantRepository.updateGrantStatus(grant.grant_id, 'REVOKE_PENDING', {}, transaction);

                await auditRepository.createAuditEvent({
                    eventCategory: 'REVOCATION',
                    eventAction: 'GRANT_EXPIRY_DETECTED',
                    entityType: 'access_grants',
                    entityId: grant.grant_id,
                    actorType: 'SYSTEM_TIMER',
                    eventPayload: {
                        grantId: grant.grant_id,
                        grantNumber: grant.grant_number,
                        expiresAt: grant.expires_at,
                        engagementId: grant.contractor_engagement_id,
                        jobId: newJob.job_id
                    }
                }, transaction);

                return newJob;
            });

            jobsCreated++;
            createdJobIds.push(job.job_id);
        } catch (err) {
            logger.error('Failed to enqueue expiry job for grant', { grantId: grant.grant_id, error: err.message });
        }
    }

    let workerOutcomes = [];
    if (autoProcess && jobsCreated > 0) {
        const cycle = await revocationWorker.runWorkerCycle({ batchSize: jobsCreated });
        workerOutcomes = cycle.outcomes;
    }

    return {
        scannedCount: expiredGrants.length,
        jobsCreated,
        createdJobIds,
        workerOutcomes
    };
}

/**
 * Terminates a contractor engagement immediately and triggers offboarding of all active grants.
 * @param {string} engagementId GUID
 * @param {object} actorUser User initiating offboarding
 * @param {string} [reason='Administrative offboarding']
 * @returns {Promise<object>} Offboarding summary
 */
async function terminateContractorEngagement(engagementId, actorUser, reason = 'Administrative offboarding') {
    if (!engagementId) {
        throw new ValidationError('Engagement ID is required.');
    }
    if (!actorUser) {
        throw new ForbiddenError('Actor user is required for engagement termination.');
    }

    const engagement = await engagementRepository.findEngagementById(engagementId);
    if (!engagement) {
        throw new NotFoundError('Contractor engagement');
    }

    // Authorization: Must be SYSTEM_ADMIN, SECURITY_OFFICER, or the designated internal sponsor
    const isSponsor = engagement.sponsor_user_id === actorUser.user_id;
    const isPrivilegedAdmin = hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER']);

    if (!isSponsor && !isPrivilegedAdmin) {
        throw new ForbiddenError('You do not have authorization to terminate this engagement. Requires System Admin, Security Officer, or designated Sponsor.');
    }

    // Update engagement to TERMINATED and enqueue revocation jobs for all active/pending grants
    const activeGrants = await revocationRepository.findActiveGrantsByEngagementId(engagementId);

    await withTransaction(async (transaction) => {
        await engagementRepository.updateEngagementStatus(engagementId, 'TERMINATED', transaction);

        await auditRepository.createAuditEvent({
            eventCategory: 'REVOCATION',
            eventAction: 'ENGAGEMENT_TERMINATED',
            entityType: 'contractor_engagements',
            entityId: engagementId,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                engagementId,
                contractorUserId: engagement.contractor_user_id,
                reason,
                activeGrantCount: activeGrants.length
            }
        }, transaction);

        for (const grant of activeGrants) {
            const idempotencyKey = `REVOCATION_ACTIVE_${grant.grant_id}`;

            const job = await revocationRepository.createRevocationJob({
                grantId: grant.grant_id,
                triggerSource: 'ENGAGEMENT_TERMINATION',
                connectorName: 'GITHUB',
                idempotencyKey
            }, transaction);

            await grantRepository.updateGrantStatus(grant.grant_id, 'REVOKE_PENDING', {}, transaction);

            await auditRepository.createAuditEvent({
                eventCategory: 'REVOCATION',
                eventAction: 'REVOCATION_JOB_QUEUED',
                entityType: 'access_grants',
                entityId: grant.grant_id,
                actorUserId: actorUser.user_id,
                actorType: 'USER',
                eventPayload: {
                    grantId: grant.grant_id,
                    jobId: job.job_id,
                    trigger: 'ENGAGEMENT_TERMINATION',
                    engagementId
                }
            }, transaction);
        }
    });

    // Execute background worker to process eligible revocations immediately
    if (activeGrants.length > 0) {
        await revocationWorker.runWorkerCycle({ batchSize: activeGrants.length });
    }

    const offboardingStatus = await revocationRepository.getOffboardingStatus(engagement.contractor_user_id);

    return {
        engagementId,
        contractorUserId: engagement.contractor_user_id,
        engagementStatus: 'TERMINATED',
        grantsQueued: activeGrants.length,
        offboardingStatus
    };
}

/**
 * Manually retries a failed or retryable revocation job.
 * Restricted to System Administrators and Security Officers.
 * Compliance Auditors and non-privileged users are strictly denied.
 * @param {string} jobId GUID
 * @param {object} actorUser User requesting retry
 * @returns {Promise<object>} Result of retry attempt
 */
async function retryRevocationJob(jobId, actorUser) {
    if (!jobId) throw new ValidationError('Job ID is required.');
    if (!actorUser) throw new ForbiddenError('Actor user is required.');

    const canRetry = hasRole(actorUser.roles, 'SYSTEM_ADMIN') || hasRole(actorUser.roles, 'SECURITY_OFFICER');
    if (!canRetry) {
        logger.warn('Unauthorized manual retry attempt on revocation job', {
            jobId,
            userId: actorUser.user_id,
            roles: actorUser.roles
        });
        throw new ForbiddenError('Only System Administrators and Security Officers can manually retry revocation jobs.');
    }

    const job = await revocationRepository.findRevocationJobById(jobId);
    if (!job) {
        throw new NotFoundError('Revocation job');
    }

    if (job.status === 'PROCESSING' && job.lease_expires_at && new Date(job.lease_expires_at) > new Date()) {
        throw new ConflictError('Job is currently being processed by another worker lease.');
    }

    await withTransaction(async (transaction) => {
        await revocationRepository.requeueJobForManualRetry(jobId, transaction);

        await auditRepository.createAuditEvent({
            eventCategory: 'REVOCATION',
            eventAction: 'REVOCATION_MANUAL_RETRY',
            entityType: 'access_grants',
            entityId: job.grant_id,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                jobId,
                grantId: job.grant_id,
                previousStatus: job.status,
                retryCount: job.retry_count
            }
        }, transaction);
    });

    // Process immediately
    const outcome = await revocationWorker.processNextJob();
    const updatedJob = await revocationRepository.findRevocationJobById(jobId);

    return {
        job: updatedJob,
        outcome
    };
}

/**
 * Resolves a job in MANUAL_REVIEW_REQUIRED state with an authorized decision.
 * Restricted to System Administrators and Security Officers.
 * @param {string} jobId GUID
 * @param {object} actorUser
 * @param {string} decision 'CONFIRMED_REVOKED' | 'DISMISSED' | 'RETRY'
 * @param {string} [notes=null]
 * @returns {Promise<object>}
 */
async function resolveManualReview(jobId, actorUser, decision, notes = null) {
    if (!jobId) throw new ValidationError('Job ID is required.');
    if (!decision) throw new ValidationError('Decision is required.');
    if (!actorUser) throw new ForbiddenError('Actor user is required.');

    const canResolve = hasRole(actorUser.roles, 'SYSTEM_ADMIN') || hasRole(actorUser.roles, 'SECURITY_OFFICER');
    if (!canResolve) {
        throw new ForbiddenError('Only System Administrators and Security Officers can resolve manual review jobs.');
    }

    const job = await revocationRepository.findRevocationJobById(jobId);
    if (!job) {
        throw new NotFoundError('Revocation job');
    }

    if (job.status !== 'MANUAL_REVIEW_REQUIRED') {
        throw new ValidationError(`Job is currently in status '${job.status}', not awaiting manual review.`);
    }

    const options = typeof notes === 'object' && notes !== null
        ? { ...notes, actorUserId: actorUser.user_id, confirmedByUserId: actorUser.user_id }
        : { justification: notes, actorUserId: actorUser.user_id, confirmedByUserId: actorUser.user_id };

    const resolved = await withTransaction(async (transaction) => {
        const res = await revocationRepository.resolveManualReviewJob(jobId, decision, options, transaction);

        const justification = options.justification || (typeof notes === 'string' ? notes : 'No justification provided');

        if (decision.toUpperCase() === 'CONFIRMED_REVOKED' || decision.toUpperCase() === 'REVOKED') {
            await grantRepository.updateGrantStatus(job.grant_id, 'REVOKED', {
                revokedAt: new Date(),
                revocationReason: `Manually confirmed (MANUAL_ATTESTATION) by ${actorUser.email || actorUser.user_id}: ${justification}`
            }, transaction);
        }

        await auditRepository.createAuditEvent({
            eventCategory: 'REVOCATION',
            eventAction: 'REVOCATION_MANUAL_REVIEW_RESOLVED',
            entityType: 'access_grants',
            entityId: job.grant_id,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                jobId,
                grantId: job.grant_id,
                decision,
                confirmationType: 'MANUAL_ATTESTATION',
                actingUserId: actorUser.user_id,
                actingUserEmail: actorUser.email,
                confirmationSource: options.confirmationSource || 'ADMINISTRATIVE_PORTAL_CONFIRMATION',
                evidenceReference: options.evidenceReference || 'MANUAL_ATTESTATION_WITHOUT_EXTERNAL_PROOF',
                justification
            }
        }, transaction);

        return res;
    });

    return resolved;
}

/**
 * Returns comprehensive offboarding status for a contractor.
 * @param {string} contractorUserId GUID
 * @param {object} actorUser
 * @returns {Promise<object>}
 */
async function getOffboardingStatus(contractorUserId, actorUser) {
    if (!contractorUserId) throw new ValidationError('Contractor user ID is required.');

    const isAuthorized = hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR', 'INTERNAL_SPONSOR']) ||
                         actorUser.user_id === contractorUserId;

    if (!isAuthorized) {
        throw new ForbiddenError('You are not authorized to view offboarding status for this contractor.');
    }

    return await revocationRepository.getOffboardingStatus(contractorUserId);
}

/**
 * Lists revocation jobs with pagination and filters for UI / API.
 * @param {object} filter
 * @param {object} actorUser
 * @returns {Promise<object>}
 */
async function listRevocationJobs(filter = {}, actorUser) {
    const isPrivileged = hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR', 'INTERNAL_SPONSOR']);
    if (!isPrivileged) {
        // Contractors can only see their own jobs
        if (hasRole(actorUser.roles, 'CONTRACTOR')) {
            filter.contractorUserId = actorUser.user_id;
        } else {
            throw new ForbiddenError('You are not authorized to view revocation jobs.');
        }
    }

    return await revocationRepository.listRevocationJobs(filter);
}

/**
 * Retrieves details for a specific revocation job by ID.
 * @param {string} jobId GUID
 * @param {object} actorUser
 * @returns {Promise<object>}
 */
async function getRevocationJobById(jobId, actorUser) {
    if (!jobId) throw new ValidationError('Job ID is required.');

    const job = await revocationRepository.findRevocationJobById(jobId);
    if (!job) {
        throw new NotFoundError('Revocation job');
    }

    const isPrivileged = hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR', 'INTERNAL_SPONSOR']);
    if (!isPrivileged && job.contractor_user_id !== actorUser.user_id) {
        throw new ForbiddenError('You are not authorized to view this revocation job.');
    }

    return job;
}

/**
 * Enqueues a single access grant for automated revocation via existing worker engine.
 * @param {string} grantId GUID
 * @param {string} triggerSource 'REVIEW_REJECTION' | 'ORPHAN_DETECTION' | 'MANUAL_EMERGENCY'
 * @param {object} actorUser User initiating or authorizing revocation
 * @param {object} [options={}] { reason, autoProcess }
 * @returns {Promise<{ success: boolean, job: object, alreadyQueued?: boolean }>}
 */
async function enqueueGrantRevocation(grantId, triggerSource, actorUser, options = {}) {
    if (!grantId) throw new ValidationError('Grant ID is required.');
    if (!actorUser) throw new ForbiddenError('Actor user is required for revocation.');

    const grant = await grantRepository.findGrantById(grantId);
    if (!grant) {
        throw new NotFoundError('Access grant', 'ERR_GRANT_NOT_FOUND');
    }

    if (grant.status === 'REVOKED') {
        return { success: true, alreadyRevoked: true, grant };
    }

    // Check for existing active revocation job
    const existingJobs = await revocationRepository.getRevocationJobsByGrantId(grantId);
    const activeJob = existingJobs.find(j => ['QUEUED', 'PROCESSING', 'FAILED_RETRY'].includes(j.status));
    if (activeJob) {
        return { success: true, alreadyQueued: true, job: activeJob };
    }

    const { reason = 'Revocation requested', autoProcess = false } = options;
    const idempotencyKey = `REVOCATION_ACTIVE_${grantId}`;

    const job = await withTransaction(async (transaction) => {
        const newJob = await revocationRepository.createRevocationJob({
            grantId,
            triggerSource,
            connectorName: 'GITHUB',
            idempotencyKey
        }, transaction);

        await grantRepository.updateGrantStatus(grantId, 'REVOKE_PENDING', {}, transaction);

        await auditRepository.createAuditEvent({
            eventCategory: 'REVOCATION',
            eventAction: 'REVOCATION_JOB_QUEUED',
            entityType: 'access_grants',
            entityId: grantId,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                grantId,
                grantNumber: grant.grant_number,
                triggerSource,
                reason,
                jobId: newJob.job_id
            }
        }, transaction);

        return newJob;
    });

    if (autoProcess) {
        try {
            await revocationWorker.executeRevocationJob(job);
        } catch (workerErr) {
            logger.warn('Inline revocation execution failed; queued for background worker', { jobId: job.job_id, error: workerErr.message });
        }
    }

    return { success: true, job, grant };
}

module.exports = {
    processExpiredGrants,
    terminateContractorEngagement,
    retryRevocationJob,
    resolveManualReview,
    getOffboardingStatus,
    listRevocationJobs,
    getRevocationJobById,
    enqueueGrantRevocation
};

