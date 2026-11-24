/**
 * AccessLease — Durable Provisioning Worker
 * Claims queued and retryable jobs using database row-level leases,
 * dispatches them to connectors, enforces bounded exponential backoff,
 * updates grant states, and records immutable audit events.
 * 
 * Rules:
 * - Leases are row-locked via WITH (UPDLOCK, ROWLOCK, READPAST).
 * - Safe against worker crashes via lease timeouts.
 * - Confirmed GitHub state is mandatory before transitioning grant to ACTIVE.
 */

const crypto = require('crypto');
const { withTransaction } = require('../config/database');
const provisioningRepository = require('../repositories/provisioningRepository');
const revocationRepository = require('../repositories/revocationRepository');
const grantRepository = require('../repositories/grantRepository');
const requestRepository = require('../repositories/requestRepository');
const auditRepository = require('../repositories/auditRepository');
const userExternalIdentityRepository = require('../repositories/userExternalIdentityRepository');
const connectorMappingRepository = require('../repositories/connectorMappingRepository');
const githubConnector = require('../connectors/github');
const { ConnectorError, ConfigurationError } = require('../utils/errors');
const logger = require('../utils/logger');

const WORKER_ID = `worker-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
let workerTimer = null;
let isProcessing = false;

/**
 * Calculates exponential backoff with random jitter.
 * @param {number} attemptCount
 * @returns {number} Backoff in seconds (max 300s)
 */
function calculateBackoffSeconds(attemptCount) {
    const base = Math.min(300, Math.pow(2, Math.max(1, attemptCount)) * 5);
    const jitter = Math.floor(Math.random() * 5); // 0-4s random jitter
    return base + jitter;
}

/**
 * Claims and executes a single pending provisioning job.
 * @param {string} [specificJobId=null] Optional specific job ID to claim
 * @returns {Promise<object|null>} Processed job result or null if no jobs available
 */
async function processNextJob(specificJobId = null) {
    let job = null;

    if (specificJobId) {
        job = await provisioningRepository.findJobById(specificJobId);
        if (!job || (job.job_status !== 'QUEUED' && job.job_status !== 'FAILED_RETRY')) {
            return null;
        }
        // Claim the specific job
        const updated = await provisioningRepository.updateJobStatus(job.job_id, 'PROCESSING', { resetAttempts: false });
        if (updated) {
            job = { ...job, ...updated };
        }
    } else {
        // Atomic lock-free claim of next available job
        job = await provisioningRepository.claimNextProvisioningJob(WORKER_ID, 60);
    }

    if (!job) {
        return null;
    }

    logger.info('Claimed provisioning job for execution', {
        jobId: job.job_id,
        requestId: job.request_id,
        attempt: job.attempt_count,
        workerId: WORKER_ID
    });

    return await executeProvisioningJob(job);
}

/**
 * Executes a claimed provisioning job through the connector.
 * @param {object} job
 * @returns {Promise<object>} Outcome
 */
async function executeProvisioningJob(job) {
    const { job_id: jobId, request_id: requestId, grant_id: grantId, connector_type: connectorType } = job;
    let mapping = null;
    let canonicalAccountId = null;

    try {
        // 1. Resolve Access Request
        const request = await requestRepository.findRequestById(requestId);
        if (!request) {
            throw new ConnectorError(
                `Access request '${requestId}' not found. Permanent job failure.`,
                404,
                'ERR_REQUEST_NOT_FOUND',
                { category: 'TARGET_NOT_FOUND' },
                false
            );
        }

        if (request.status !== 'APPROVED') {
            throw new ConnectorError(
                `Access request status is '${request.status}' (expected 'APPROVED'). Provisioning cancelled.`,
                400,
                'ERR_REQUEST_NOT_APPROVED',
                { category: 'LIFECYCLE_CONFLICT' },
                false
            );
        }

        // 2. Resolve Connector Mapping
        mapping = await connectorMappingRepository.findMappingByResourceAndEntitlement(
            request.resource_id,
            request.entitlement_id,
            connectorType
        );

        if (!mapping) {
            throw new ConnectorError(
                `No active connector resource mapping found for resource '${request.resource_code}' and entitlement '${request.entitlement_code}'.`,
                400,
                'ERR_NO_CONNECTOR_MAPPING',
                { category: 'CONFIGURATION_ERROR' },
                false
            );
        }

        // 3. Resolve Verified External Identity (Phase 4)
        const contractorUserId = request.requested_by_user_id;
        const identity = await userExternalIdentityRepository.findIdentityByUserAndProvider(
            contractorUserId,
            connectorType
        );

        if (!identity || identity.verification_status !== 'VERIFIED') {
            const errorMsg = !identity
                ? `Contractor has no linked ${connectorType} identity. Provisioning cannot proceed.`
                : `Contractor ${connectorType} identity '${identity.external_username}' is not in VERIFIED status (status: ${identity.verification_status}).`;

            logger.warn('Provisioning blocked due to unverified external identity', {
                contractorUserId,
                connectorType,
                hasIdentity: !!identity,
                verificationStatus: identity?.verification_status
            });

            // Mark job as PERMANENT_FAILURE and grant as PROVISIONING_FAILED
            await withTransaction(async (transaction) => {
                await provisioningRepository.failJob(jobId, {
                    errorCategory: 'IDENTITY_NOT_LINKED',
                    errorMessage: errorMsg,
                    isPermanent: true
                }, transaction);

                if (grantId) {
                    await grantRepository.updateGrantStatus(grantId, 'PROVISIONING_FAILED', {
                        failureCategory: 'IDENTITY_NOT_LINKED'
                    }, transaction);
                }

                await auditRepository.createAuditEvent({
                    eventCategory: 'PROVISIONING',
                    eventAction: 'PROVISIONING_IDENTITY_BLOCKED',
                    entityType: 'access_requests',
                    entityId: requestId,
                    actorUserId: contractorUserId,
                    actorType: 'USER',
                    eventPayload: {
                        job_id: jobId,
                        grant_id: grantId,
                        reason: errorMsg,
                        error_category: 'IDENTITY_NOT_LINKED'
                    }
                }, transaction);
            });

            return { success: false, category: 'IDENTITY_NOT_LINKED', message: errorMsg };
        }

        const externalUsername = identity.external_username;
        if (connectorType === 'GITHUB' && (!identity.external_account_id || !String(identity.external_account_id).trim())) {
            const errorMsg = `Contractor GitHub identity '${externalUsername}' lacks an immutable numeric account ID. Cannot coordinate provisioning without canonical identity.`;
            logger.warn('Provisioning blocked due to missing immutable numeric account ID', {
                contractorUserId,
                externalUsername
            });
            await withTransaction(async (transaction) => {
                await provisioningRepository.failJob(jobId, {
                    errorCategory: 'IDENTITY_NOT_LINKED',
                    errorMessage: errorMsg,
                    isPermanent: true
                }, transaction);

                if (grantId) {
                    await grantRepository.updateGrantStatus(grantId, 'PROVISIONING_FAILED', {
                        failureCategory: 'IDENTITY_NOT_LINKED'
                    }, transaction);
                }
            });
            return { success: false, category: 'IDENTITY_NOT_LINKED', message: errorMsg };
        }

        canonicalAccountId = identity.external_account_id ? String(identity.external_account_id).trim() : externalUsername;
        const existingGrant = grantId ? await grantRepository.findGrantById(grantId) : null;

        // 4. Pre-Provisioning Coordination & State Transition
        if (connectorType === 'GITHUB') {
            const coord = await revocationRepository.acquireMembershipCoordinationWithWait(
                mapping.github_org,
                mapping.github_team_slug,
                canonicalAccountId,
                'PROVISIONING',
                jobId,
                WORKER_ID,
                60,
                5000,
                50
            );

            if (!coord.acquired) {
                await auditRepository.createAuditEvent({
                    eventCategory: 'PROVISIONING',
                    eventAction: 'PROVISIONING_BLOCKED_BY_REVOCATION',
                    entityType: 'access_requests',
                    entityId: requestId,
                    actorUserId: contractorUserId,
                    actorType: 'SYSTEM_TIMER',
                    eventPayload: {
                        job_id: jobId,
                        grant_id: grantId,
                        current_operation: coord.currentOperation,
                        current_worker_id: coord.currentWorkerId
                    }
                });

                throw new ConflictError(
                    `Membership coordination currently held by ${coord.currentOperation} (worker: ${coord.currentWorkerId}). Retrying later.`,
                    'ERR_MEMBERSHIP_COORDINATION_BUSY'
                );
            }

            await auditRepository.createAuditEvent({
                eventCategory: 'PROVISIONING',
                eventAction: coord.wasReclaimed ? 'COORDINATION_RECLAIMED' : 'COORDINATION_ACQUIRED',
                entityType: 'access_requests',
                entityId: requestId,
                actorUserId: contractorUserId,
                actorType: 'SYSTEM_TIMER',
                eventPayload: {
                    job_id: jobId,
                    grant_id: grantId,
                    operation: 'PROVISIONING',
                    worker_id: WORKER_ID,
                    was_reclaimed: !!coord.wasReclaimed
                }
            });

            await revocationRepository.serializeMembershipDecision(
                mapping.github_org,
                mapping.github_team_slug,
                canonicalAccountId,
                async (lockTx) => {
                    if (grantId) {
                        await grantRepository.updateGrantStatus(grantId, 'PROVISIONING_IN_PROGRESS', {}, lockTx);
                    }
                }
            );
        } else if (grantId) {
            await grantRepository.updateGrantStatus(grantId, 'PROVISIONING_IN_PROGRESS');
        }

        // 5. Execute Connector Operation (GitHub) — Zero SQL locks held during external HTTP call!
        if (connectorType === 'GITHUB') {
            // Revalidate coordination ownership immediately before initiating provider operations
            const isCoordActive = await revocationRepository.verifyMembershipCoordinationActive(
                mapping.github_org,
                mapping.github_team_slug,
                canonicalAccountId,
                WORKER_ID,
                'PROVISIONING'
            );
            if (!isCoordActive) {
                logger.warn('Provisioning worker lost coordination lease before initiating provider operations', {
                    jobId, workerId: WORKER_ID
                });
                return { success: false, category: 'LEASE_LOST', message: 'Coordination lease lost before provider call' };
            }

            let outcome;
            try {
                outcome = await githubConnector.githubVerificationService.provisionAndVerifyAccess({
                    org: mapping.github_org,
                    teamSlug: mapping.github_team_slug,
                    repoOwner: mapping.github_repo_owner,
                    repoName: mapping.github_repo_name,
                    requiredPermission: mapping.required_permission,
                    username: externalUsername,
                    isRetry: (job.attempt_count > 1),
                    existingProvenance: existingGrant ? existingGrant.membership_provenance : null,
                    grantId: grantId,
                    jobId: jobId,
                    operationId: job.idempotency_key || jobId,
                    numericAccountId: canonicalAccountId
                });
            } catch (err) {
                // Ensure coordination is released if connector operation throws
                await revocationRepository.releaseMembershipCoordination(
                    mapping.github_org,
                    mapping.github_team_slug,
                    canonicalAccountId,
                    WORKER_ID
                ).catch(() => {});
                throw err;
            }

            // 6. Record Confirmed Result in SQL Server (under short applock)
            await revocationRepository.serializeMembershipDecision(
                mapping.github_org,
                mapping.github_team_slug,
                canonicalAccountId,
                async (transaction) => {
                    // Revalidate coordination ownership inside transaction under lock
                    const coordHeld = await revocationRepository.verifyMembershipCoordinationActive(
                        mapping.github_org,
                        mapping.github_team_slug,
                        canonicalAccountId,
                        WORKER_ID,
                        'PROVISIONING',
                        transaction
                    );
                    if (!coordHeld) {
                        throw new ConflictError(`Worker '${WORKER_ID}' lost coordination lease before recording provisioning result.`, 'ERR_LEASE_OWNERSHIP_LOST');
                    }

                    const targetGrantStatus = outcome.state === 'ACTIVE' ? 'ACTIVE' : 'PENDING_ACCEPTANCE';

                    if (grantId) {
                        await grantRepository.updateGrantStatus(grantId, targetGrantStatus, {
                            verifiedAt: outcome.state === 'ACTIVE' ? new Date(outcome.verifiedAt) : null,
                            membershipProvenance: outcome.membershipProvenance,
                            numericAccountId: canonicalAccountId,
                            connectorMetadata: outcome.metadata
                        }, transaction);
                    }

                    if (outcome.state === 'ACTIVE') {
                        await provisioningRepository.completeJob(jobId, { grantId }, transaction);
                    } else {
                        // Invitation is pending
                        await provisioningRepository.updateJobStatus(jobId, 'PENDING_ACCEPTANCE', {
                            lastErrorCategory: 'INVITATION_PENDING',
                            lastErrorMessage: `Invitation pending acceptance by @${externalUsername} in team ${mapping.github_org}/${mapping.github_team_slug}`
                        }, transaction);
                    }

                    // Record Provisioning Event in dbo.provisioning_events
                    if (grantId) {
                        await provisioningRepository.createProvisioningEvent({
                            grantId,
                            eventType: outcome.state === 'ACTIVE' ? 'PROVISION_SUCCEEDED' : 'INVITATION_PENDING',
                            connectorName: 'GITHUB',
                            payload: outcome.metadata,
                            statusCode: '200',
                            executedAt: new Date()
                        }, transaction);
                    }

                    // If uncertain provenance was assigned, record a dedicated security warning audit event
                    if (outcome.membershipProvenance === 'UNCERTAIN_PRE_EXISTING') {
                        await auditRepository.createAuditEvent({
                            eventCategory: 'PROVISIONING',
                            eventAction: 'PROVISIONING_UNCERTAIN_PROVENANCE_ASSIGNED',
                            entityType: 'access_grants',
                            entityId: grantId || requestId,
                            actorUserId: contractorUserId,
                            actorType: 'SYSTEM_TIMER',
                            eventPayload: {
                                job_id: jobId,
                                grant_id: grantId,
                                warning: 'Active membership discovered on retry without durable pre-flight absence proof.',
                                provenance: 'UNCERTAIN_PRE_EXISTING',
                                protection: 'Automated offboarding revocation disabled for this grant.'
                            }
                        }, transaction);
                    }

                    // Record Immutable Audit Event
                    await auditRepository.createAuditEvent({
                        eventCategory: 'PROVISIONING',
                        eventAction: outcome.state === 'ACTIVE' ? 'PROVISIONING_CONFIRMED' : 'PROVISIONING_INVITATION_PENDING',
                        entityType: 'access_grants',
                        entityId: grantId || requestId,
                        actorUserId: contractorUserId,
                        actorType: 'USER',
                        eventPayload: {
                            job_id: jobId,
                            grant_id: grantId,
                            connector_type: connectorType,
                            target_org: mapping.github_org,
                            target_team: mapping.github_team_slug,
                            target_repo: `${mapping.github_repo_owner}/${mapping.github_repo_name}`,
                            contractor_github_username: externalUsername,
                            membership_state: outcome.state,
                            provenance: outcome.membershipProvenance,
                            pre_existing: outcome.preExisting
                        }
                    }, transaction);

                    // Release coordination back to IDLE
                    const released = await revocationRepository.releaseMembershipCoordination(
                        mapping.github_org,
                        mapping.github_team_slug,
                        canonicalAccountId,
                        WORKER_ID,
                        transaction
                    );
                    if (!released) {
                        throw new ConflictError(`Worker '${WORKER_ID}' lost coordination lease during release.`, 'ERR_LEASE_OWNERSHIP_LOST');
                    }

                    await auditRepository.createAuditEvent({
                        eventCategory: 'PROVISIONING',
                        eventAction: 'COORDINATION_RELEASED',
                        entityType: 'access_grants',
                        entityId: grantId || requestId,
                        actorUserId: contractorUserId,
                        actorType: 'SYSTEM_TIMER',
                        eventPayload: {
                            job_id: jobId,
                            grant_id: grantId,
                            target_org: mapping.github_org,
                            target_team: mapping.github_team_slug,
                            account_id: canonicalAccountId
                        }
                    }, transaction);
                }
            );

            logger.info('Provisioning job completed successfully', {
                jobId,
                grantId,
                state: outcome.state,
                provenance: outcome.membershipProvenance
            });

            return { success: true, outcome };
        } else {
            throw new ConnectorError(
                `Unsupported connector type: '${connectorType}'.`,
                400,
                'ERR_UNSUPPORTED_CONNECTOR',
                { category: 'CONFIGURATION_ERROR' },
                false
            );
        }

    } catch (err) {
        logger.error('Provisioning job execution failure', {
            jobId,
            requestId,
            error: err.message,
            category: err.category
        });

        // Release coordination if held
        if (connectorType === 'GITHUB' && canonicalAccountId && mapping?.github_org && mapping?.github_team_slug) {
            await revocationRepository.releaseMembershipCoordination(
                mapping.github_org,
                mapping.github_team_slug,
                canonicalAccountId,
                WORKER_ID
            ).catch(() => {});
        }

        const isExplicitNonRetryable = (err instanceof ConnectorError && err.isRetryable === false);
        let errorCategory = err.category || (err instanceof ConnectorError ? 'CONNECTOR_ERROR' : 'SYSTEM_ERROR');
        if (err.code === 'ERR_MEMBERSHIP_COORDINATION_BUSY') {
            errorCategory = 'COORDINATION_BUSY';
        }
        const isPermanent = isExplicitNonRetryable || (job.attempt_count >= job.max_attempts);

        let nextRetryAt = null;
        if (!isPermanent) {
            const backoffSeconds = err.retryAfterSeconds || calculateBackoffSeconds(job.attempt_count);
            nextRetryAt = new Date(Date.now() + backoffSeconds * 1000);
        }

        await withTransaction(async (transaction) => {
            await provisioningRepository.failJob(jobId, {
                errorCategory,
                errorMessage: err.message,
                isPermanent,
                nextRetryAt
            }, transaction);

            if (grantId) {
                const grantExists = await grantRepository.findGrantById(grantId, transaction);
                if (grantExists) {
                    if (isPermanent) {
                        await grantRepository.updateGrantStatus(grantId, 'PROVISIONING_FAILED', {
                            failureCategory: errorCategory
                        }, transaction);
                    }

                    await provisioningRepository.createProvisioningEvent({
                        grantId,
                        eventType: 'PROVISION_FAILED',
                        connectorName: connectorType || 'GITHUB',
                        payload: { category: errorCategory, isPermanent, attempt: job.attempt_count },
                        statusCode: String(err.statusCode || 500),
                        errorMessage: err.message
                    }, transaction);
                }
            }

            await auditRepository.createAuditEvent({
                eventCategory: 'PROVISIONING',
                eventAction: isPermanent ? 'PROVISIONING_PERMANENT_FAILURE' : 'PROVISIONING_RETRY_SCHEDULED',
                entityType: 'access_requests',
                entityId: requestId,
                actorType: 'SYSTEM_TIMER',
                eventPayload: {
                    job_id: jobId,
                    grant_id: grantId,
                    connector: connectorType,
                    attempt: job.attempt_count,
                    max_attempts: job.max_attempts,
                    error_category: errorCategory,
                    error_message: err.message,
                    next_retry_at: nextRetryAt ? nextRetryAt.toISOString() : null
                }
            }, transaction);
        });

        return { success: false, isPermanent, errorCategory, message: err.message };
    }
}

/**
 * Checks pending acceptance jobs and reconciles membership when accepted.
 */
async function reconcilePendingAcceptanceJobs() {
    const pendingJobs = await provisioningRepository.listProvisioningJobs({
        status: 'PENDING_ACCEPTANCE',
        limit: 20
    });

    for (const job of pendingJobs) {
        try {
            if (job.connector_type === 'GITHUB') {
                const request = await requestRepository.findRequestById(job.request_id);
                if (!request) continue;

                const mapping = await connectorMappingRepository.findMappingByResourceAndEntitlement(
                    request.resource_id,
                    request.entitlement_id,
                    'GITHUB'
                );
                if (!mapping) continue;

                const identity = await userExternalIdentityRepository.findIdentityByUserAndProvider(
                    request.requested_by_user_id,
                    'GITHUB'
                );
                if (!identity || identity.verification_status !== 'VERIFIED') continue;

                const membership = await githubConnector.githubTeamService.getTeamMembership(
                    mapping.github_org,
                    mapping.github_team_slug,
                    identity.external_username
                );

                if (membership && membership.state === 'active') {
                    logger.info('Contractor accepted GitHub team invitation! Activating grant.', {
                        jobId: job.job_id,
                        grantId: job.grant_id,
                        username: identity.external_username
                    });

                    await withTransaction(async (transaction) => {
                        if (job.grant_id) {
                            const currentGrant = await grantRepository.findGrantById(job.grant_id, transaction);
                            const effectiveProvenance = currentGrant?.membership_provenance || 'CREATED_BY_ACCESSLEASE';

                            await grantRepository.updateGrantStatus(job.grant_id, 'ACTIVE', {
                                verifiedAt: new Date(),
                                membershipProvenance: effectiveProvenance
                            }, transaction);

                            await provisioningRepository.createProvisioningEvent({
                                grantId: job.grant_id,
                                eventType: 'PROVISION_SUCCEEDED',
                                connectorName: 'GITHUB',
                                payload: { verifiedState: 'active', invitationAccepted: true },
                                statusCode: '200'
                            }, transaction);
                        }

                        await provisioningRepository.completeJob(job.job_id, { grantId: job.grant_id }, transaction);

                        await auditRepository.createAuditEvent({
                            eventCategory: 'PROVISIONING',
                            eventAction: 'INVITATION_ACCEPTED_ACTIVATED',
                            entityType: 'access_grants',
                            entityId: job.grant_id || job.request_id,
                            actorUserId: request.requested_by_user_id,
                            actorType: 'USER',
                            eventPayload: {
                                job_id: job.job_id,
                                grant_id: job.grant_id,
                                github_username: identity.external_username
                            }
                        }, transaction);
                    });
                }
            }
        } catch (err) {
            logger.warn('Failed reconciling pending acceptance job', { jobId: job.job_id, error: err.message });
        }
    }
}

/**
 * Runs a single worker processing pass.
 */
async function runWorkerCycle() {
    if (isProcessing) return;
    isProcessing = true;

    try {
        let processedCount = 0;
        let result = await processNextJob();
        while (result && processedCount < 5) {
            processedCount++;
            result = await processNextJob();
        }

        // Reconcile pending invitations
        await reconcilePendingAcceptanceJobs();
    } catch (err) {
        logger.error('Worker loop iteration encountered an error', { error: err.message });
    } finally {
        isProcessing = false;
    }
}

/**
 * Starts the in-process background worker timer.
 * @param {number} [intervalMs=10000]
 */
function startWorker(intervalMs = 10000) {
    if (workerTimer) return;
    logger.info('Starting AccessLease durable provisioning worker', { workerId: WORKER_ID, intervalMs });
    workerTimer = setInterval(() => {
        runWorkerCycle().catch(err => logger.error('Unhandled error in worker cycle', { error: err.message }));
    }, intervalMs);
    if (workerTimer.unref) {
        workerTimer.unref();
    }
}

/**
 * Stops the background worker timer.
 */
function stopWorker() {
    if (workerTimer) {
        clearInterval(workerTimer);
        workerTimer = null;
        logger.info('Stopped AccessLease durable provisioning worker', { workerId: WORKER_ID });
    }
}

module.exports = {
    processNextJob,
    executeProvisioningJob,
    reconcilePendingAcceptanceJobs,
    runWorkerCycle,
    startWorker,
    stopWorker,
    calculateBackoffSeconds,
    WORKER_ID
};
