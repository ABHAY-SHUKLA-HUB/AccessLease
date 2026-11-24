/**
 * AccessLease — Durable Revocation Worker
 * Claims queued and retry-eligible revocation jobs using SQL Server atomic leases,
 * enforces safety rules (provenance verification, shared membership protection),
 * executes GitHub team membership deletions, verifies absence via post-revocation GET,
 * handles transient retry backoffs, and records comprehensive audit trails.
 */

const { withTransaction } = require('../config/database');
const {
    revocationRepository,
    grantRepository,
    auditRepository,
    provisioningRepository
} = require('../repositories');
const githubConnector = require('../connectors/github');
const { isSafeForAutomatedRevocation } = require('./provisioningService');
const { ConflictError } = require('../utils/errors');
const logger = require('../utils/logger');

const WORKER_ID = `worker-revocation-${process.pid}-${Math.random().toString(36).substring(2, 8)}`;
let workerTimer = null;

/**
 * Calculates exponential backoff in seconds with jitter.
 * @param {number} retryCount
 * @returns {number} Seconds
 */
function calculateBackoffSeconds(retryCount) {
    const base = Math.min(3600, Math.pow(2, Math.max(0, retryCount)) * 15);
    const jitter = Math.floor(Math.random() * 5);
    return base + jitter;
}

/**
 * Executes a single claimed revocation job through safety checks, GitHub DELETE,
 * and post-revocation GET verification.
 * @param {object} job Claimed job record from dbo.revocation_jobs
 * @param {object} [options={}]
 * @returns {Promise<object>} Outcome summary
 */
async function executeRevocationJob(job, options = {}) {
    const { workerId = WORKER_ID } = options;
    const jobId = job.job_id;
    const grantId = job.grant_id;

    // 1. Validate mandatory workerId
    const cleanWorkerId = revocationRepository.validateWorkerId(workerId, 'executeRevocationJob');

    // Ensure worker holds active lease on the job in the database
    let activeJob = job;
    if (job.status !== 'PROCESSING' || job.lease_owner !== cleanWorkerId) {
        const claimed = await revocationRepository.claimRevocationJobById(jobId, cleanWorkerId, 60);
        if (!claimed) {
            logger.warn('Could not claim job for execution: lease held by another worker or invalid state', { jobId, workerId: cleanWorkerId });
            return {
                success: false,
                category: 'LEASE_LOST',
                message: `Worker '${cleanWorkerId}' could not claim lease on job '${jobId}'.`
            };
        }
        activeJob = claimed;
    }

    logger.info('Executing revocation job', { jobId, grantId, workerId: cleanWorkerId, retryCount: activeJob.retry_count });

    let heartbeatTimer = null;
    let leaseLost = false;
    let canonicalAccountId = null;

    const startHeartbeat = () => {
        if (heartbeatTimer) clearInterval(heartbeatTimer);
        heartbeatTimer = setInterval(async () => {
            try {
                const renewal = await revocationRepository.renewJobLease(jobId, cleanWorkerId, 60);
                if (!renewal) {
                    leaseLost = true;
                    logger.warn('Revocation worker lost job lease during heartbeat renewal', { jobId, workerId: cleanWorkerId });
                    stopHeartbeat();
                    return;
                }
                if (canonicalAccountId && grant?.target_org && grant?.target_team_slug) {
                    const coordRenewal = await revocationRepository.renewMembershipCoordination(
                        grant.target_org,
                        grant.target_team_slug,
                        canonicalAccountId,
                        cleanWorkerId,
                        60
                    );
                    if (!coordRenewal) {
                        leaseLost = true;
                        logger.warn('Revocation worker lost coordination lease during heartbeat renewal', { jobId, workerId: cleanWorkerId });
                        stopHeartbeat();
                    }
                }
            } catch (err) {
                logger.warn('Heartbeat lease renewal failed', { jobId, workerId: cleanWorkerId, error: err.message });
            }
        }, 20000);
    };

    const stopHeartbeat = () => {
        if (heartbeatTimer) {
            clearInterval(heartbeatTimer);
            heartbeatTimer = null;
        }
    };

    // Start lease renewal heartbeat
    startHeartbeat();

    let grant = null;
    try {
        // 2. Retrieve full grant record
        grant = await grantRepository.findGrantById(grantId);
        if (!grant) {
            logger.error('Grant not found for revocation job', { jobId, grantId });
            stopHeartbeat();
            await revocationRepository.failRevocationJob(jobId, cleanWorkerId, 'GRANT_NOT_FOUND', 'Grant not found in database', false, 0);
            return { success: false, category: 'GRANT_NOT_FOUND', message: 'Grant not found' };
        }

        // If grant is already REVOKED, complete the job cleanly
        if (grant.status === 'REVOKED') {
            logger.info('Grant is already marked REVOKED, completing job', { jobId, grantId });
            stopHeartbeat();
            await revocationRepository.completeRevocationJob(jobId, cleanWorkerId, {
                connectorResponse: { alreadyRevoked: true }
            });
            return { success: true, alreadyRevoked: true };
        }

        // Resolve canonical numeric GitHub account ID before any mutations
        canonicalAccountId = await revocationRepository.resolveCanonicalAccountId(grant);
        if (!canonicalAccountId) {
            logger.warn('Cannot determine canonical numeric GitHub account ID for grant, routing to manual review', {
                jobId,
                grantId,
                externalUsername: grant.external_username
            });
            stopHeartbeat();
            const reason = `Cannot determine canonical numeric GitHub account ID for user '${grant.external_username}'. Routing to manual review to prevent coordination key divergence.`;
            await withTransaction(async (transaction) => {
                const routed = await revocationRepository.routeToManualReview(jobId, cleanWorkerId, reason, transaction);
                if (!routed) {
                    throw new ConflictError(`Worker '${cleanWorkerId}' lost active lease to route job '${jobId}'.`, 'ERR_LEASE_OWNERSHIP_LOST');
                }

                await grantRepository.updateGrantStatus(grantId, 'MANUAL_REVIEW_REQUIRED', {
                    failureCategory: 'CANONICAL_IDENTITY_UNRESOLVED'
                }, transaction);

                await auditRepository.createAuditEvent({
                    eventCategory: 'REVOCATION',
                    eventAction: 'REVOCATION_MANUAL_REVIEW_ROUTED',
                    entityType: 'access_grants',
                    entityId: grantId,
                    actorType: 'SYSTEM_TIMER',
                    eventPayload: {
                        jobId,
                        grantId,
                        reason,
                        category: 'CANONICAL_IDENTITY_UNRESOLVED'
                    }
                }, transaction);

                await provisioningRepository.createProvisioningEvent({
                    grantId,
                    eventType: 'MANUAL_REVIEW_REQUIRED',
                    connectorName: 'GITHUB',
                    payload: { reason, category: 'CANONICAL_IDENTITY_UNRESOLVED' },
                    statusCode: '400',
                    executedAt: new Date()
                }, transaction);
            });

            return { success: false, manualReview: true, reason, category: 'CANONICAL_IDENTITY_UNRESOLVED' };
        }
        grant.numeric_account_id = canonicalAccountId;

        // 3. Revocation Eligibility & Provenance Policy Check
        const configuredAppId = githubConnector.githubConfig.getConfig()?.appId;
        const safetyResult = await isSafeForAutomatedRevocation(grant, {
            numericAccountId: canonicalAccountId,
            configuredAppId
        });

        if (!safetyResult.canRevoke) {
            logger.warn('Grant is not eligible for automated revocation, routing to manual review', {
                jobId,
                grantId,
                provenance: grant.membership_provenance,
                reason: safetyResult.reason
            });

            stopHeartbeat();
            await withTransaction(async (transaction) => {
                const routed = await revocationRepository.routeToManualReview(jobId, cleanWorkerId, safetyResult.reason, transaction);
                if (!routed) {
                    throw new ConflictError(`Worker '${cleanWorkerId}' does not hold active lease to route job '${jobId}'.`, 'ERR_LEASE_OWNERSHIP_LOST');
                }

                await grantRepository.updateGrantStatus(grantId, 'MANUAL_REVIEW_REQUIRED', {
                    failureCategory: 'MANUAL_REVIEW_REQUIRED'
                }, transaction);

                await auditRepository.createAuditEvent({
                    eventCategory: 'REVOCATION',
                    eventAction: 'REVOCATION_MANUAL_REVIEW_ROUTED',
                    entityType: 'access_grants',
                    entityId: grantId,
                    actorType: 'SYSTEM_TIMER',
                    eventPayload: {
                        jobId,
                        grantId,
                        provenance: grant.membership_provenance,
                        reason: safetyResult.reason
                    }
                }, transaction);

                await provisioningRepository.createProvisioningEvent({
                    grantId,
                    eventType: 'MANUAL_REVIEW_REQUIRED',
                    connectorName: 'GITHUB',
                    payload: { reason: safetyResult.reason, provenance: grant.membership_provenance },
                    statusCode: '400',
                    executedAt: new Date()
                }, transaction);
            });

            return { success: false, manualReview: true, reason: safetyResult.reason };
        }

        // 4. Concurrency Protection & Shared Membership Evaluation (Phase 1)
        // 4.1 Acquire cross-connector membership coordination with wait (outside applock to prevent lock-order deadlocks!)
        const coord = await revocationRepository.acquireMembershipCoordinationWithWait(
            grant.target_org,
            grant.target_team_slug,
            canonicalAccountId,
            'REVOCATION',
            jobId,
            cleanWorkerId,
            60,
            5000,
            50
        );

        if (!coord.acquired) {
            logger.warn('Membership coordination currently held by another operation', {
                jobId,
                targetOrg: grant.target_org,
                targetTeam: grant.target_team_slug,
                currentOperation: coord.currentOperation,
                currentWorkerId: coord.currentWorkerId
            });

            await auditRepository.createAuditEvent({
                eventCategory: 'REVOCATION',
                eventAction: 'REVOCATION_BLOCKED_BY_PROVISIONING',
                entityType: 'access_grants',
                entityId: grantId,
                actorType: 'SYSTEM_TIMER',
                eventPayload: {
                    jobId,
                    grantId,
                    currentOperation: coord.currentOperation,
                    currentWorkerId: coord.currentWorkerId
                }
            });

            throw new ConflictError(
                `Membership coordination currently held by ${coord.currentOperation} (worker: ${coord.currentWorkerId}). Retrying later.`,
                'ERR_MEMBERSHIP_COORDINATION_BUSY'
            );
        }

        await auditRepository.createAuditEvent({
            eventCategory: 'REVOCATION',
            eventAction: coord.wasReclaimed ? 'COORDINATION_RECLAIMED' : 'COORDINATION_ACQUIRED',
            entityType: 'access_grants',
            entityId: grantId,
            actorType: 'SYSTEM_TIMER',
            eventPayload: {
                jobId,
                grantId,
                operation: 'REVOCATION',
                workerId: cleanWorkerId,
                wasReclaimed: !!coord.wasReclaimed
            }
        });

        // 4.2 Checks supporting grants under short applock (~5ms). If retained, completes and releases coordination.
        // If deletion required, sets grant status to REVOKE_PENDING and commits/releases lock immediately.
        const phase1Outcome = await revocationRepository.serializeMembershipDecision(
            grant.target_org,
            grant.target_team_slug,
            canonicalAccountId,
            async (lockTx) => {
                const sharedActiveCount = await revocationRepository.countSharedActiveGrants(
                    grantId,
                    grant.target_org,
                    grant.target_team_slug,
                    grant.external_username,
                    canonicalAccountId,
                    lockTx
                );

                if (sharedActiveCount > 0) {
                    logger.info('Shared membership protection triggered: Other active grants require this team membership', {
                        jobId,
                        grantId,
                        targetOrg: grant.target_org,
                        targetTeam: grant.target_team_slug,
                        sharedActiveCount
                    });

                    await grantRepository.updateGrantStatus(grantId, 'REVOKED', {
                        revokedAt: new Date(),
                        revocationReason: `Shared membership retained for ${sharedActiveCount} other active grant(s)`
                    }, lockTx);

                    const completed = await revocationRepository.completeRevocationJob(jobId, cleanWorkerId, {
                        connectorResponse: {
                            skippedDeletion: true,
                            sharedActiveCount,
                            reason: 'SHARED_MEMBERSHIP_RETAINED'
                        }
                    }, lockTx);
                    if (!completed) {
                        throw new ConflictError(`Worker '${cleanWorkerId}' lost active lease on job '${jobId}'.`, 'ERR_LEASE_OWNERSHIP_LOST');
                    }

                    // Release coordination back to IDLE
                    await revocationRepository.releaseMembershipCoordination(
                        grant.target_org,
                        grant.target_team_slug,
                        canonicalAccountId,
                        cleanWorkerId,
                        lockTx
                    );

                    await auditRepository.createAuditEvent({
                        eventCategory: 'REVOCATION',
                        eventAction: 'COORDINATION_RELEASED',
                        entityType: 'access_grants',
                        entityId: grantId,
                        actorType: 'SYSTEM_TIMER',
                        eventPayload: {
                            jobId,
                            grantId,
                            targetOrg: grant.target_org,
                            targetTeam: grant.target_team_slug,
                            accountId: canonicalAccountId
                        }
                    }, lockTx);

                    await auditRepository.createAuditEvent({
                        eventCategory: 'REVOCATION',
                        eventAction: 'SHARED_MEMBERSHIP_RETAINED',
                        entityType: 'access_grants',
                        entityId: grantId,
                        actorType: 'SYSTEM_TIMER',
                        eventPayload: {
                            jobId,
                            grantId,
                            targetOrg: grant.target_org,
                            targetTeam: grant.target_team_slug,
                            externalUsername: grant.external_username,
                            numericAccountId: canonicalAccountId,
                            sharedActiveCount
                        }
                    }, lockTx);

                    await provisioningRepository.createProvisioningEvent({
                        grantId,
                        eventType: 'SHARED_MEMBERSHIP_RETAINED',
                        connectorName: 'GITHUB',
                        payload: { sharedActiveCount },
                        statusCode: '200',
                        executedAt: new Date()
                    }, lockTx);

                    return { action: 'RETAINED', sharedActiveCount };
                }

                await grantRepository.updateGrantStatus(grantId, 'REVOKE_PENDING', {}, lockTx);
                return { action: 'PROCEED_DELETION' };
            },
            5000
        );

        if (phase1Outcome.action === 'RETAINED') {
            stopHeartbeat();
            return { success: true, sharedRetained: true, sharedActiveCount: phase1Outcome.sharedActiveCount };
        }

        // 5. External GitHub Operations (Phase 2: ZERO SQL Transactions or DB Locks Held!)
        // Verify lease ownership before initiating network operations
        let isLeaseActive = !leaseLost && await revocationRepository.verifyJobLeaseActive(jobId, cleanWorkerId);
        if (!isLeaseActive) {
            stopHeartbeat();
            logger.warn('Worker lost lease before initiating external operations', { jobId, workerId: cleanWorkerId });
            return { success: false, category: 'LEASE_LOST', message: 'Worker lease lost before external call' };
        }

        // Step 5.1: Target validation: verify organization and team existence
        try {
            await githubConnector.githubTeamService.getTeam(
                grant.target_org,
                grant.target_team_slug
            );
        } catch (teamErr) {
            if (teamErr.statusCode === 404 || teamErr.category === 'TARGET_NOT_FOUND') {
                logger.error('Target team not found in GitHub organization, routing to manual review', {
                    jobId,
                    grantId,
                    targetOrg: grant.target_org,
                    targetTeamSlug: grant.target_team_slug
                });

                stopHeartbeat();
                const reason = `Target team '${grant.target_team_slug}' not found in GitHub organization '${grant.target_org}' (TARGET_NOT_FOUND). Cannot verify membership absence without valid team.`;

                await withTransaction(async (transaction) => {
                    const routed = await revocationRepository.routeToManualReview(jobId, cleanWorkerId, reason, transaction);
                    if (!routed) {
                        throw new ConflictError(`Worker '${cleanWorkerId}' lost active lease to route job '${jobId}'.`, 'ERR_LEASE_OWNERSHIP_LOST');
                    }

                    await grantRepository.updateGrantStatus(grantId, 'MANUAL_REVIEW_REQUIRED', {
                        failureCategory: 'TARGET_NOT_FOUND'
                    }, transaction);

                    await revocationRepository.releaseMembershipCoordination(
                        grant.target_org,
                        grant.target_team_slug,
                        canonicalAccountId,
                        cleanWorkerId,
                        transaction
                    );

                    await auditRepository.createAuditEvent({
                        eventCategory: 'REVOCATION',
                        eventAction: 'COORDINATION_RELEASED',
                        entityType: 'access_grants',
                        entityId: grantId,
                        actorType: 'SYSTEM_TIMER',
                        eventPayload: {
                            jobId,
                            grantId,
                            targetOrg: grant.target_org,
                            targetTeam: grant.target_team_slug,
                            accountId: canonicalAccountId
                        }
                    }, transaction);

                    await auditRepository.createAuditEvent({
                        eventCategory: 'REVOCATION',
                        eventAction: 'REVOCATION_MANUAL_REVIEW_ROUTED',
                        entityType: 'access_grants',
                        entityId: grantId,
                        actorType: 'SYSTEM_TIMER',
                        eventPayload: {
                            jobId,
                            grantId,
                            targetOrg: grant.target_org,
                            targetTeamSlug: grant.target_team_slug,
                            reason,
                            category: 'TARGET_NOT_FOUND'
                        }
                    }, transaction);

                    await provisioningRepository.createProvisioningEvent({
                        grantId,
                        eventType: 'MANUAL_REVIEW_REQUIRED',
                        connectorName: 'GITHUB',
                        payload: { reason, category: 'TARGET_NOT_FOUND' },
                        statusCode: '404',
                        executedAt: new Date()
                    }, transaction);
                });

                return { success: false, manualReview: true, reason, category: 'TARGET_NOT_FOUND' };
            }
            throw teamErr;
        }

        // Revalidate ownership immediately before starting provider membership lookup
        isLeaseActive = !leaseLost && await revocationRepository.verifyJobLeaseActive(jobId, cleanWorkerId);
        let isCoordActive = !leaseLost && await revocationRepository.verifyMembershipCoordinationActive(
            grant.target_org, grant.target_team_slug, canonicalAccountId, cleanWorkerId, 'REVOCATION'
        );
        if (!isLeaseActive || !isCoordActive) {
            stopHeartbeat();
            logger.warn('Worker lost lease before membership lookup', { jobId, workerId: cleanWorkerId, isLeaseActive, isCoordActive });
            return { success: false, category: 'LEASE_LOST', message: 'Worker lease lost before membership lookup' };
        }

        // Step 5.2: Query current membership at provider
        let currentMembership = null;
        try {
            currentMembership = await githubConnector.githubTeamService.getTeamMembership(
                grant.target_org,
                grant.target_team_slug,
                grant.external_username
            );
        } catch (err) {
            if (err.statusCode === 404 || err.category === 'TARGET_NOT_FOUND') {
                currentMembership = null;
            } else {
                throw err;
            }
        }

        let alreadyAbsent = false;
        let deleteResponse = null;

        if (!currentMembership) {
            alreadyAbsent = true;
            logger.info('Contractor is already absent from GitHub team, reconciling state', {
                grantId,
                username: grant.external_username
            });
        } else {
            // Revalidate ownership immediately before executing DELETE mutation
            isLeaseActive = !leaseLost && await revocationRepository.verifyJobLeaseActive(jobId, cleanWorkerId);
            isCoordActive = !leaseLost && await revocationRepository.verifyMembershipCoordinationActive(
                grant.target_org, grant.target_team_slug, canonicalAccountId, cleanWorkerId, 'REVOCATION'
            );
            if (!isLeaseActive || !isCoordActive) {
                stopHeartbeat();
                logger.warn('Worker lost lease immediately before DELETE operation', { jobId, workerId: cleanWorkerId, isLeaseActive, isCoordActive });
                return { success: false, category: 'LEASE_LOST', message: 'Worker lease lost before DELETE operation' };
            }

            // Step 5.3: Perform GitHub DELETE operation
            deleteResponse = await githubConnector.githubTeamService.removeTeamMembership(
                grant.target_org,
                grant.target_team_slug,
                grant.external_username
            );

            // Revalidate ownership after DELETE and before verification GET
            isLeaseActive = !leaseLost && await revocationRepository.verifyJobLeaseActive(jobId, cleanWorkerId);
            isCoordActive = !leaseLost && await revocationRepository.verifyMembershipCoordinationActive(
                grant.target_org, grant.target_team_slug, canonicalAccountId, cleanWorkerId, 'REVOCATION'
            );
            if (!isLeaseActive || !isCoordActive) {
                stopHeartbeat();
                logger.warn('Worker lost lease after DELETE operation; aborting post-check to avoid stale state write', { jobId, workerId: cleanWorkerId, isLeaseActive, isCoordActive });
                return { success: false, category: 'LEASE_LOST', message: 'Worker lease lost after DELETE operation' };
            }

            // Step 5.4: Post-DELETE Verification: Re-query provider to independently confirm absence
            const postCheck = await githubConnector.githubTeamService.getTeamMembership(
                grant.target_org,
                grant.target_team_slug,
                grant.external_username
            );

            if (postCheck !== null) {
                logger.error('Post-revocation verification failed: User membership still active after DELETE', {
                    grantId,
                    username: grant.external_username,
                    postState: postCheck.state
                });

                stopHeartbeat();
                await revocationRepository.failRevocationJob(
                    jobId,
                    cleanWorkerId,
                    'POST_VERIFICATION_FAILED',
                    'GitHub DELETE succeeded but post-revocation GET confirmed user membership remains present.',
                    true,
                    calculateBackoffSeconds(activeJob.retry_count)
                );

                await revocationRepository.releaseMembershipCoordination(
                    grant.target_org,
                    grant.target_team_slug,
                    canonicalAccountId,
                    cleanWorkerId
                ).catch(() => {});

                await auditRepository.createAuditEvent({
                    eventCategory: 'REVOCATION',
                    eventAction: 'REVOCATION_POST_VERIFICATION_FAILED',
                    entityType: 'access_grants',
                    entityId: grantId,
                    actorType: 'SYSTEM_TIMER',
                    eventPayload: {
                        jobId,
                        grantId,
                        postVerificationState: postCheck.state
                    }
                });

                return {
                    success: false,
                    category: 'POST_VERIFICATION_FAILED',
                    message: 'Membership still active after DELETE request.'
                };
            }
        }

        // Stop heartbeat before DB finalization so renewal does not race with completion
        stopHeartbeat();

        // Revalidate ownership immediately before state finalization
        isLeaseActive = !leaseLost && await revocationRepository.verifyJobLeaseActive(jobId, cleanWorkerId);
        isCoordActive = !leaseLost && await revocationRepository.verifyMembershipCoordinationActive(
            grant.target_org, grant.target_team_slug, canonicalAccountId, cleanWorkerId, 'REVOCATION'
        );
        if (!isLeaseActive || !isCoordActive) {
            logger.warn('Revocation worker aborted state finalization: lease lost during execution', { jobId, workerId: cleanWorkerId, isLeaseActive, isCoordActive });
            return { success: false, category: 'LEASE_LOST', message: 'Worker lease lost before state finalization' };
        }

        // 6. Reconciliation & Finalization (Phase 3)
        // Phase 3 Step 1: Atomic Supporting-Grant Evaluation & Immediate Finalization
        // Under short applock (~5ms), checks supporting grants and finalizes REVOKED in the same atomic transaction if no restoration needed!
        let restorationNeeded = false;
        let concurrentActiveCount = 0;

        const immediateOutcome = await revocationRepository.serializeMembershipDecision(
            grant.target_org,
            grant.target_team_slug,
            canonicalAccountId,
            async (lockTx) => {
                // Re-verify coordination lease inside applock
                const coordHeld = await revocationRepository.verifyMembershipCoordinationActive(
                    grant.target_org, grant.target_team_slug, canonicalAccountId, cleanWorkerId, 'REVOCATION', lockTx
                );
                if (!coordHeld) {
                    throw new ConflictError(`Worker '${cleanWorkerId}' lost coordination lease on membership.`, 'ERR_LEASE_OWNERSHIP_LOST');
                }

                concurrentActiveCount = await revocationRepository.countSharedActiveGrants(
                    grantId,
                    grant.target_org,
                    grant.target_team_slug,
                    grant.external_username,
                    canonicalAccountId,
                    lockTx
                );

                if (concurrentActiveCount > 0 && !alreadyAbsent) {
                    // Concurrent grant was provisioned! Must exit applock to execute restoration PUT and GET outside SQL locks
                    restorationNeeded = true;
                    return null;
                }

                // Normal Case: 0 supporting grants (or already absent)
                // Complete revocation and release coordination in the SAME atomic transaction!
                const reason = alreadyAbsent ? 'ALREADY_ABSENT_AT_PROVIDER' : 'AUTOMATED_REVOCATION_CONFIRMED';

                await grantRepository.updateGrantStatus(grantId, 'REVOKED', {
                    revokedAt: new Date(),
                    revocationReason: reason
                }, lockTx);

                const completed = await revocationRepository.completeRevocationJob(jobId, cleanWorkerId, {
                    connectorResponse: alreadyAbsent
                        ? { alreadyAbsent: true, status: 404 }
                        : { ...(deleteResponse || {}), restoredForConcurrentGrant: false }
                }, lockTx);
                if (!completed) {
                    throw new ConflictError(`Worker '${cleanWorkerId}' lost active lease on job '${jobId}'.`, 'ERR_LEASE_OWNERSHIP_LOST');
                }

                const released = await revocationRepository.releaseMembershipCoordination(
                    grant.target_org,
                    grant.target_team_slug,
                    canonicalAccountId,
                    cleanWorkerId,
                    lockTx
                );
                if (!released) {
                    throw new ConflictError(`Worker '${cleanWorkerId}' lost coordination lease during release.`, 'ERR_LEASE_OWNERSHIP_LOST');
                }

                await auditRepository.createAuditEvent({
                    eventCategory: 'REVOCATION',
                    eventAction: 'COORDINATION_RELEASED',
                    entityType: 'access_grants',
                    entityId: grantId,
                    actorType: 'SYSTEM_TIMER',
                    eventPayload: {
                        jobId,
                        grantId,
                        targetOrg: grant.target_org,
                        targetTeam: grant.target_team_slug,
                        accountId: canonicalAccountId
                    }
                }, lockTx);

                await auditRepository.createAuditEvent({
                    eventCategory: 'REVOCATION',
                    eventAction: 'REVOCATION_SUCCEEDED',
                    entityType: 'access_grants',
                    entityId: grantId,
                    actorType: 'SYSTEM_TIMER',
                    eventPayload: {
                        jobId,
                        grantId,
                        targetOrg: grant.target_org,
                        targetTeam: grant.target_team_slug,
                        externalUsername: grant.external_username,
                        numericAccountId: canonicalAccountId,
                        alreadyAbsent,
                        restoredForConcurrentGrant: false
                    }
                }, lockTx);

                await provisioningRepository.createProvisioningEvent({
                    grantId,
                    eventType: 'REVOCATION_SUCCEEDED',
                    connectorName: 'GITHUB',
                    payload: { deleteResponse, confirmedAbsent: true, alreadyAbsent, restoredForConcurrentGrant: false },
                    statusCode: alreadyAbsent ? '404' : '204',
                    executedAt: new Date()
                }, lockTx);

                logger.info('Revocation successfully completed and verified', { jobId, grantId, concurrentActiveCount: 0 });
                return { success: true, confirmedAbsent: true, alreadyAbsent, restoredForConcurrentGrant: false };
            },
            5000
        );

        if (!restorationNeeded) {
            return immediateOutcome;
        }

        // Phase 3 Step 2: Restoration Flow (Concurrent active grant detected)
        logger.warn('Concurrent active grant detected during revocation finalization, executing restoration flow', {
            jobId,
            grantId,
            concurrentActiveCount
        });

        // 6.1 Audit RESTORATION_ATTEMPTED
        await auditRepository.createAuditEvent({
            eventCategory: 'REVOCATION',
            eventAction: 'RESTORATION_ATTEMPTED',
            entityType: 'access_grants',
            entityId: grantId,
            actorType: 'SYSTEM_TIMER',
            eventPayload: {
                jobId,
                grantId,
                targetOrg: grant.target_org,
                targetTeam: grant.target_team_slug,
                externalUsername: grant.external_username,
                numericAccountId: canonicalAccountId,
                concurrentActiveCount
            }
        });

        // Revalidate ownership immediately before external restoration PUT
        isCoordActive = await revocationRepository.verifyMembershipCoordinationActive(
            grant.target_org, grant.target_team_slug, canonicalAccountId, cleanWorkerId, 'REVOCATION'
        );
        if (!isCoordActive) {
            logger.warn('Revocation worker lost coordination lease before restoration PUT', { jobId, workerId: cleanWorkerId });
            return { success: false, category: 'LEASE_LOST', message: 'Coordination lease lost before restoration PUT' };
        }

        // 6.2 External restoration PUT with ZERO SQL locks held!
        let restoreError = null;
        try {
            await githubConnector.githubTeamService.addOrUpdateTeamMembership(
                grant.target_org,
                grant.target_team_slug,
                grant.external_username,
                'member'
            );
        } catch (err) {
            restoreError = err;
        }

        // Revalidate ownership after restoration PUT, before verification GET
        isCoordActive = await revocationRepository.verifyMembershipCoordinationActive(
            grant.target_org, grant.target_team_slug, canonicalAccountId, cleanWorkerId, 'REVOCATION'
        );
        if (!isCoordActive) {
            logger.warn('Revocation worker lost coordination lease after restoration PUT', { jobId, workerId: cleanWorkerId });
            return { success: false, category: 'LEASE_LOST', message: 'Coordination lease lost during restoration' };
        }

        // 6.3 Independent post-restoration verification GET with ZERO SQL locks held!
        let postRestoreCheck = null;
        if (!restoreError) {
            try {
                postRestoreCheck = await githubConnector.githubTeamService.getTeamMembership(
                    grant.target_org,
                    grant.target_team_slug,
                    grant.external_username
                );
            } catch (err) {
                restoreError = err;
            }
        }

        // If restoration PUT or verification GET failed, NEVER report success!
        if (restoreError || !postRestoreCheck) {
            logger.error('Restoration verification failed: Membership could not be confirmed at provider', {
                jobId,
                grantId,
                error: restoreError?.message
            });

            await auditRepository.createAuditEvent({
                eventCategory: 'REVOCATION',
                eventAction: 'RESTORATION_FAILED',
                entityType: 'access_grants',
                entityId: grantId,
                actorType: 'SYSTEM_TIMER',
                eventPayload: {
                    jobId,
                    grantId,
                    targetOrg: grant.target_org,
                    targetTeam: grant.target_team_slug,
                    externalUsername: grant.external_username,
                    numericAccountId: canonicalAccountId,
                    concurrentActiveCount,
                    error: restoreError?.message || 'Membership absent at provider after restoration'
                }
            });

            await revocationRepository.failRevocationJob(
                jobId,
                cleanWorkerId,
                'POST_VERIFICATION_FAILED',
                `Membership restoration verification failed: ${restoreError?.message || 'Membership absent after restoration PUT'}`,
                true,
                calculateBackoffSeconds(activeJob.retry_count)
            );

            await revocationRepository.releaseMembershipCoordination(
                grant.target_org,
                grant.target_team_slug,
                canonicalAccountId,
                cleanWorkerId
            ).catch(() => {});

            return {
                success: false,
                category: 'POST_VERIFICATION_FAILED',
                message: 'Membership restoration verification failed'
            };
        }

        // 6.4 Audit RESTORATION_CONFIRMED
        await auditRepository.createAuditEvent({
            eventCategory: 'REVOCATION',
            eventAction: 'RESTORATION_CONFIRMED',
            entityType: 'access_grants',
            entityId: grantId,
            actorType: 'SYSTEM_TIMER',
            eventPayload: {
                jobId,
                grantId,
                targetOrg: grant.target_org,
                targetTeam: grant.target_team_slug,
                externalUsername: grant.external_username,
                numericAccountId: canonicalAccountId,
                concurrentActiveCount,
                restorationState: postRestoreCheck.state
            }
        });

        // Phase 3 Step 3: Finalize status and release coordination under short applock (~5ms)
        const finalOutcome = await revocationRepository.serializeMembershipDecision(
            grant.target_org,
            grant.target_team_slug,
            canonicalAccountId,
            async (lockTx) => {
                // Verify coordination lease still owned inside applock
                const coordHeld = await revocationRepository.verifyMembershipCoordinationActive(
                    grant.target_org, grant.target_team_slug, canonicalAccountId, cleanWorkerId, 'REVOCATION', lockTx
                );
                if (!coordHeld) {
                    throw new ConflictError(`Worker '${cleanWorkerId}' lost coordination lease before finalization.`, 'ERR_LEASE_OWNERSHIP_LOST');
                }

                await grantRepository.updateGrantStatus(grantId, 'REVOKED', {
                    revokedAt: new Date(),
                    revocationReason: 'CONCURRENT_GRANT_RESTORED'
                }, lockTx);

                const completed = await revocationRepository.completeRevocationJob(jobId, cleanWorkerId, {
                    connectorResponse: {
                        ...(deleteResponse || {}),
                        restoredForConcurrentGrant: true
                    }
                }, lockTx);
                if (!completed) {
                    throw new ConflictError(`Worker '${cleanWorkerId}' lost active lease on job '${jobId}'.`, 'ERR_LEASE_OWNERSHIP_LOST');
                }

                const released = await revocationRepository.releaseMembershipCoordination(
                    grant.target_org,
                    grant.target_team_slug,
                    canonicalAccountId,
                    cleanWorkerId,
                    lockTx
                );
                if (!released) {
                    throw new ConflictError(`Worker '${cleanWorkerId}' lost coordination lease during final release.`, 'ERR_LEASE_OWNERSHIP_LOST');
                }

                await auditRepository.createAuditEvent({
                    eventCategory: 'REVOCATION',
                    eventAction: 'COORDINATION_RELEASED',
                    entityType: 'access_grants',
                    entityId: grantId,
                    actorType: 'SYSTEM_TIMER',
                    eventPayload: {
                        jobId,
                        grantId,
                        targetOrg: grant.target_org,
                        targetTeam: grant.target_team_slug,
                        accountId: canonicalAccountId
                    }
                }, lockTx);

                await auditRepository.createAuditEvent({
                    eventCategory: 'REVOCATION',
                    eventAction: 'CONCURRENT_GRANT_RESTORED_DURING_REVOCATION',
                    entityType: 'access_grants',
                    entityId: grantId,
                    actorType: 'SYSTEM_TIMER',
                    eventPayload: {
                        jobId,
                        grantId,
                        concurrentActiveCount,
                        restoredMembership: true,
                        message: 'A new active grant was created concurrently during deletion; membership re-added and confirmed for active grant.'
                    }
                }, lockTx);

                await auditRepository.createAuditEvent({
                    eventCategory: 'REVOCATION',
                    eventAction: 'REVOCATION_SUCCEEDED',
                    entityType: 'access_grants',
                    entityId: grantId,
                    actorType: 'SYSTEM_TIMER',
                    eventPayload: {
                        jobId,
                        grantId,
                        targetOrg: grant.target_org,
                        targetTeam: grant.target_team_slug,
                        externalUsername: grant.external_username,
                        numericAccountId: canonicalAccountId,
                        alreadyAbsent: false,
                        restoredForConcurrentGrant: true
                    }
                }, lockTx);

                await provisioningRepository.createProvisioningEvent({
                    grantId,
                    eventType: 'REVOCATION_SUCCEEDED',
                    connectorName: 'GITHUB',
                    payload: { deleteResponse, confirmedAbsent: false, alreadyAbsent: false, restoredForConcurrentGrant: true },
                    statusCode: '204',
                    executedAt: new Date()
                }, lockTx);

                logger.info('Revocation successfully completed and verified', { jobId, grantId, concurrentActiveCount });
                return { success: true, confirmedAbsent: false, alreadyAbsent: false, restoredForConcurrentGrant: true };
            },
            5000
        );

        return finalOutcome;

    } catch (err) {
        stopHeartbeat();
        logger.error('Revocation execution encountered an error', {
            jobId,
            grantId,
            workerId: cleanWorkerId,
            error: err.message,
            category: err.category
        });

        // Release coordination if held
        if (grant) {
            const coordId = canonicalAccountId || grant.numeric_account_id || grant.external_username;
            if (coordId) {
                await revocationRepository.releaseMembershipCoordination(
                    grant.target_org,
                    grant.target_team_slug,
                    coordId,
                    cleanWorkerId
                ).catch(() => {});
            }
        }

        // If the error was due to lost lease or conflict, do NOT attempt to record failure in DB
        if (err.code === 'ERR_LEASE_OWNERSHIP_LOST' || err.category === 'ERR_LEASE_OWNERSHIP_LOST' || leaseLost) {
            logger.warn('Revocation worker aborted without updating DB: lease was lost or conflict occurred', {
                jobId,
                workerId: cleanWorkerId,
                error: err.message
            });
            return { success: false, category: 'LEASE_LOST', message: err.message };
        }

        let isRetryable = true;
        let delaySeconds = calculateBackoffSeconds(activeJob.retry_count);
        let errorCategory = err.category || 'UNKNOWN_ERROR';

        if (err.code === 'ERR_MEMBERSHIP_COORDINATION_BUSY') {
            isRetryable = true;
            delaySeconds = 15;
            errorCategory = 'COORDINATION_BUSY';
        } else if (err.category === 'RATE_LIMIT') {
            isRetryable = true;
            delaySeconds = err.retryAfterSeconds || 60;
        } else if (['PERMISSION_DENIED', 'ORGANIZATION_NOT_ALLOWED', 'VALIDATION_FAILED'].includes(err.category)) {
            isRetryable = false;
        } else if (err.code === 'ETIMEDOUT' || err.code === 'ECONNRESET' || err.code === 'ESOCKETTIMEDOUT') {
            isRetryable = true;
            errorCategory = 'NETWORK_TIMEOUT';
        }

        try {
            await revocationRepository.failRevocationJob(
                jobId,
                cleanWorkerId,
                errorCategory,
                err.message,
                isRetryable,
                delaySeconds
            );
        } catch (failErr) {
            logger.warn('Failed to record job failure in DB (possibly lease expired)', {
                jobId, workerId: cleanWorkerId, error: failErr.message
            });
        }

        await auditRepository.createAuditEvent({
            eventCategory: 'REVOCATION',
            eventAction: isRetryable ? 'REVOCATION_RETRY_SCHEDULED' : 'REVOCATION_FAILED_PERMANENT',
            entityType: 'access_grants',
            entityId: grantId,
            actorType: 'SYSTEM_TIMER',
            eventPayload: {
                jobId,
                grantId,
                errorCategory,
                errorMessage: err.message,
                isRetryable,
                delaySeconds
            }
        });

        if (grantId) {
            await provisioningRepository.createProvisioningEvent({
                grantId,
                eventType: 'REVOCATION_FAILED',
                connectorName: 'GITHUB',
                payload: { errorCategory, message: err.message, isRetryable },
                statusCode: String(err.statusCode || 500),
                executedAt: new Date()
            }).catch(() => {});
        }

        return { success: false, category: errorCategory, message: err.message, isRetryable };
    } finally {
        stopHeartbeat();
    }
}

/**
 * Claims and processes the next single eligible job from the queue.
 * @param {string} [workerId=WORKER_ID]
 * @returns {Promise<object>} Outcome
 */
async function processNextJob(workerId = WORKER_ID) {
    const job = await revocationRepository.claimNextRevocationJob(workerId);
    if (!job) {
        return { claimed: false };
    }

    const outcome = await executeRevocationJob(job, { workerId });
    return { claimed: true, jobId: job.job_id, ...outcome };
}

/**
 * Runs a worker cycle, processing available eligible jobs up to batch limit.
 * @param {object} [options={}] { batchSize, workerId }
 * @returns {Promise<{ processedCount: number, outcomes: Array<object> }>}
 */
async function runWorkerCycle(options = {}) {
    const { batchSize = 10, workerId = WORKER_ID } = options;
    const outcomes = [];

    for (let i = 0; i < batchSize; i++) {
        const res = await processNextJob(workerId);
        if (!res.claimed) {
            break;
        }
        outcomes.push(res);
    }

    return {
        processedCount: outcomes.length,
        outcomes
    };
}

/**
 * Starts the background polling worker.
 * @param {number} [intervalMs=15000]
 */
function startWorker(intervalMs = 15000) {
    if (workerTimer) return;

    logger.info('Starting AccessLease durable revocation worker', { workerId: WORKER_ID, intervalMs });
    workerTimer = setInterval(async () => {
        try {
            await runWorkerCycle();
        } catch (err) {
            logger.error('Error during revocation worker cycle', { error: err.message });
        }
    }, intervalMs);
}

/**
 * Stops the background worker timer.
 */
function stopWorker() {
    if (workerTimer) {
        clearInterval(workerTimer);
        workerTimer = null;
        logger.info('Stopped AccessLease durable revocation worker', { workerId: WORKER_ID });
    }
}

module.exports = {
    executeRevocationJob,
    processNextJob,
    runWorkerCycle,
    startWorker,
    stopWorker,
    calculateBackoffSeconds,
    WORKER_ID
};

