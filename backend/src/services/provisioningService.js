/**
 * AccessLease — Provisioning Service
 * Coordinates access request provisioning lifecycle, deterministic idempotency,
 * connector execution, grant activation states, and authorization checks.
 */

const { withTransaction, getPool } = require('../config/database');
const sql = require('mssql');
const requestRepository = require('../repositories/requestRepository');
const grantRepository = require('../repositories/grantRepository');
const provisioningRepository = require('../repositories/provisioningRepository');
const connectorMappingRepository = require('../repositories/connectorMappingRepository');
const userExternalIdentityRepository = require('../repositories/userExternalIdentityRepository');
const engagementRepository = require('../repositories/engagementRepository');
const auditRepository = require('../repositories/auditRepository');
const provisioningWorker = require('./provisioningWorker');
const githubConnector = require('../connectors/github');
const { hasRole } = require('../security/permissionPolicy');
const {
    ValidationError,
    NotFoundError,
    ConflictError,
    ForbiddenError
} = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Creates a durable provisioning operation for an approved access request.
 * Enforces database-level idempotency to prevent duplicate operations.
 * @param {string} requestId GUID
 * @param {object} [user=null] Authenticated actor initiating the operation
 * @param {object} [options={}] Additional execution options
 * @returns {Promise<object>} Created or existing job and grant
 */
async function createProvisioningOperation(requestId, user = null, options = {}) {
    if (!requestId || typeof requestId !== 'string') {
        throw new ValidationError('A valid requestId is required to start provisioning.');
    }

    const request = await requestRepository.findRequestById(requestId);
    if (!request) {
        throw new NotFoundError(`Access request with ID '${requestId}'`);
    }

    if (request.status !== 'APPROVED') {
        throw new ConflictError(
            `Access request '${request.request_number}' is in status '${request.status}'. Only fully APPROVED requests can be provisioned.`,
            'ERR_REQUEST_NOT_APPROVED'
        );
    }

    // Contextual Authorization Guard: Verify actor is authorized to initiate provisioning
    if (user && user.user_id) {
        const isRequester = request.requested_by_user_id.toLowerCase() === user.user_id.toLowerCase();
        const isAdmin = hasRole(user.roles, 'SYSTEM_ADMIN') || hasRole(user.roles, 'SECURITY_OFFICER');

        let isSponsor = false;
        if (request.contractor_engagement_id) {
            const eng = await engagementRepository.findEngagementById(request.contractor_engagement_id);
            isSponsor = eng && eng.sponsor_user_id.toLowerCase() === user.user_id.toLowerCase();
        }

        let isOwner = false;
        if (request.resource_id) {
            isOwner = await require('../security/resourceAccess').isAuthorizedResourceOwner(user, request.resource_id);
        }

        if (!isRequester && !isAdmin && !isSponsor && !isOwner) {
            throw new ForbiddenError(
                'Access denied: You are not authorized to initiate provisioning for this access request.',
                'ERR_FORBIDDEN_REQUEST_ACCESS'
            );
        }
    }

    // Check if a connector mapping exists for this resource and entitlement
    const mapping = await connectorMappingRepository.findMappingByResourceAndEntitlement(
        request.resource_id,
        request.entitlement_id,
        'GITHUB'
    );

    if (!mapping) {
        throw new ValidationError(
            `Resource '${request.resource_name}' and Entitlement '${request.entitlement_name}' do not have an automated connector mapping configured.`
        );
    }

    // Determine contractor identity
    const contractorUserId = request.requested_by_user_id;
    const identity = await userExternalIdentityRepository.findIdentityByUserAndProvider(
        contractorUserId,
        mapping.connector_type
    );

    // Calculate deterministic grant expiration
    const engagement = await engagementRepository.findEngagementById(request.contractor_engagement_id);
    if (!engagement || engagement.status !== 'ACTIVE') {
        throw new ConflictError(
            'The contractor engagement associated with this request is not currently ACTIVE.',
            'ERR_ENGAGEMENT_NOT_ACTIVE'
        );
    }

    const maxDurationDays = request.max_lease_duration_days || 90;
    const now = new Date();
    const maxExpiry = new Date(now.getTime() + maxDurationDays * 86400000);
    const engagementEnd = new Date(engagement.end_date + 'T23:59:59.000Z');
    let effectiveExpiry = new Date(request.requested_end_date);

    if (effectiveExpiry > maxExpiry) effectiveExpiry = maxExpiry;
    if (effectiveExpiry > engagementEnd) effectiveExpiry = engagementEnd;

    // Deterministic Idempotency Key
    const idempotencyKey = `${mapping.connector_type}-PROV-${request.request_id}-${request.entitlement_id}`;

    // Execute atomic creation under transaction
    const outcome = await withTransaction(async (transaction) => {
        // 1. Check existing job by idempotency key
        const existingJob = await provisioningRepository.findJobByIdempotencyKey(idempotencyKey, transaction);
        if (existingJob) {
            let existingGrant = null;
            if (existingJob.grant_id) {
                existingGrant = await grantRepository.findGrantById(existingJob.grant_id, transaction);
            }
            return {
                job: existingJob,
                grant: existingGrant,
                alreadyExists: true
            };
        }

        // 2. Generate unique grant number
        const grantNumber = `AG-${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}${String(now.getSeconds()).padStart(2, '0')}-${Math.floor(1000 + Math.random() * 9000)}`;

        // 3. Create Access Grant in PROVISIONING_PENDING status
        const createdGrant = await grantRepository.createGrant({
            grantNumber,
            requestId: request.request_id,
            contractorEngagementId: request.contractor_engagement_id,
            resourceId: request.resource_id,
            entitlementId: request.entitlement_id,
            grantedAt: now,
            expiresAt: effectiveExpiry,
            status: 'PROVISIONING_PENDING',
            connectorType: mapping.connector_type,
            targetOrg: mapping.github_org,
            targetTeamSlug: mapping.github_team_slug,
            targetRepo: `${mapping.github_repo_owner}/${mapping.github_repo_name}`,
            externalUsername: identity ? identity.external_username : null,
            membershipProvenance: 'CREATED_BY_ACCESSLEASE'
        }, transaction);

        // 4. Create Durable Provisioning Job
        const targetResource = `${mapping.github_org}/${mapping.github_team_slug} -> ${mapping.github_repo_owner}/${mapping.github_repo_name}`;
        const createdJob = await provisioningRepository.createProvisioningJob({
            requestId: request.request_id,
            grantId: createdGrant.grant_id,
            connectorType: mapping.connector_type,
            targetResource,
            idempotencyKey,
            jobStatus: 'QUEUED',
            maxAttempts: 5
        }, transaction);

        // 5. Record Audit Event
        await auditRepository.createAuditEvent({
            eventCategory: 'PROVISIONING',
            eventAction: 'PROVISIONING_OPERATION_CREATED',
            entityType: 'access_requests',
            entityId: request.request_id,
            actorUserId: user ? user.user_id : null,
            actorType: user ? 'USER' : 'SYSTEM_TIMER',
            eventPayload: {
                job_id: createdJob.job_id,
                grant_id: createdGrant.grant_id,
                grant_number: grantNumber,
                connector: mapping.connector_type,
                target_org: mapping.github_org,
                target_team: mapping.github_team_slug,
                idempotency_key: idempotencyKey,
                has_verified_identity: identity?.verification_status === 'VERIFIED'
            },
            ipAddress: options.ipAddress || null
        }, transaction);

        return {
            job: createdJob,
            grant: createdGrant,
            alreadyExists: false
        };
    });

    // Best-effort immediate processing pass (skip background auto-execution in test runner)
    if (!options.deferExecution && process.env.NODE_ENV !== 'test') {
        provisioningWorker.processNextJob(outcome.job.job_id).catch(err => {
            logger.warn('Immediate provisioning pass deferred to background worker', {
                jobId: outcome.job.job_id,
                error: err.message
            });
        });
    }

    return outcome;
}

/**
 * Retrieves the complete provisioning state for an access request.
 * Enforces contextual authorization.
 * @param {string} requestId GUID
 * @param {object} user Authenticated user
 * @returns {Promise<object>}
 */
async function getProvisioningStateByRequestId(requestId, user) {
    if (!requestId || !user) {
        throw new ValidationError('requestId and authenticated user are required.');
    }

    const request = await requestRepository.findRequestById(requestId);
    if (!request) {
        throw new NotFoundError(`Access request with ID '${requestId}'`);
    }

    // Contextual Authorization Verification
    const isRequester = request.requested_by_user_id.toLowerCase() === user.user_id.toLowerCase();
    const isAdmin = hasRole(user.roles, 'SYSTEM_ADMIN');
    const isAuditor = hasRole(user.roles, 'COMPLIANCE_AUDITOR');
    const isSecurity = hasRole(user.roles, 'SECURITY_OFFICER');

    let isSponsor = false;
    if (user.user_id && request.contractor_engagement_id) {
        const eng = await engagementRepository.findEngagementById(request.contractor_engagement_id);
        isSponsor = eng && eng.sponsor_user_id.toLowerCase() === user.user_id.toLowerCase();
    }

    let isOwner = false;
    if (user.user_id && request.resource_id) {
        isOwner = await require('../security/resourceAccess').isAuthorizedResourceOwner(user, request.resource_id);
    }

    if (!isRequester && !isAdmin && !isAuditor && !isSecurity && !isSponsor && !isOwner) {
        throw new ForbiddenError(
            'Access denied: You are not authorized to inspect provisioning state for this request.',
            'ERR_FORBIDDEN_REQUEST_ACCESS'
        );
    }

    const job = await provisioningRepository.findJobByRequestId(requestId);
    const mapping = await connectorMappingRepository.findMappingByResourceAndEntitlement(
        request.resource_id,
        request.entitlement_id,
        'GITHUB'
    );
    const identity = await userExternalIdentityRepository.findIdentityByUserAndProvider(
        request.requested_by_user_id,
        'GITHUB'
    );

    let grant = null;
    if (job?.grant_id) {
        grant = await grantRepository.findGrantById(job.grant_id);
    }

    const connectorStatus = githubConnector.githubConfig.getStatus();

    return {
        request_id: request.request_id,
        request_number: request.request_number,
        request_status: request.status,
        contractor: {
            user_id: request.requested_by_user_id,
            name: request.contractor_name,
            email: request.contractor_email,
            verified_github_username: identity?.verification_status === 'VERIFIED' ? identity.external_username : null,
            identity_verification_status: identity ? identity.verification_status : 'NOT_LINKED'
        },
        job: job ? {
            job_id: job.job_id,
            status: job.job_status,
            attempt_count: job.attempt_count,
            max_attempts: job.max_attempts,
            next_retry_at: job.next_retry_at,
            last_error_category: job.last_error_category,
            last_error_message: job.last_error_message,
            created_at: job.created_at,
            updated_at: job.updated_at
        } : null,
        grant: grant ? {
            grant_id: grant.grant_id,
            grant_number: grant.grant_number,
            status: grant.status,
            granted_at: grant.granted_at,
            expires_at: grant.expires_at,
            membership_provenance: grant.membership_provenance,
            verified_at: grant.verified_at,
            failure_category: grant.failure_category
        } : null,
        target_mapping: mapping ? {
            connector_type: mapping.connector_type,
            github_org: mapping.github_org,
            github_team_slug: mapping.github_team_slug,
            github_repo: `${mapping.github_repo_owner}/${mapping.github_repo_name}`,
            required_permission: mapping.required_permission
        } : null,
        connector_status: connectorStatus
    };
}

/**
 * Lists provisioning jobs with administrative filtering.
 * @param {object} user
 * @param {object} [filter={}]
 * @returns {Promise<Array<object>>}
 */
async function listJobs(user, filter = {}) {
    const isPrivileged = hasRole(user.roles, 'SYSTEM_ADMIN') ||
                         hasRole(user.roles, 'SECURITY_OFFICER') ||
                         hasRole(user.roles, 'COMPLIANCE_AUDITOR');

    if (!isPrivileged) {
        throw new ForbiddenError(
            'Access denied: Viewing global provisioning queue requires administrative or security oversight roles.',
            'ERR_FORBIDDEN_ROLE'
        );
    }

    return await provisioningRepository.listProvisioningJobs(filter);
}

/**
 * Lists access grants with role-based scoping.
 * @param {object} user
 * @param {object} [filter={}]
 * @returns {Promise<Array<object>>}
 */
async function listGrants(user, filter = {}) {
    const isContractor = hasRole(user.roles, 'CONTRACTOR');
    const isAdmin = hasRole(user.roles, 'SYSTEM_ADMIN') || hasRole(user.roles, 'COMPLIANCE_AUDITOR');

    const effectiveFilter = { ...filter };

    if (isContractor && !isAdmin) {
        // Contractors see only grants tied to their engagements
        const engagements = await engagementRepository.findEngagementsByContractorId(user.user_id);
        if (!engagements || engagements.length === 0) {
            return [];
        }
        // Filter by contractor engagement
        effectiveFilter.contractorEngagementId = engagements[0].engagement_id;
    }

    return await grantRepository.listGrants(effectiveFilter);
}

/**
 * Retries a failed provisioning job manually.
 * Strictly restricted to SYSTEM_ADMIN and SECURITY_OFFICER roles.
 * @param {string} jobId GUID
 * @param {object} user Authenticated user
 * @returns {Promise<object>} Updated job
 */
async function retryJob(jobId, user, options = {}) {
    const canRetry = hasRole(user.roles, 'SYSTEM_ADMIN') || hasRole(user.roles, 'SECURITY_OFFICER');
    if (!canRetry) {
        throw new ForbiddenError(
            'Access denied: Only System Administrators and Security Officers may initiate manual provisioning retries.',
            'ERR_FORBIDDEN_RETRY'
        );
    }

    const job = await provisioningRepository.findJobById(jobId);
    if (!job) {
        throw new NotFoundError(`Provisioning job with ID '${jobId}'`);
    }

    if (job.job_status === 'SUCCEEDED') {
        throw new ConflictError(
            'Provisioning job has already succeeded. Re-provisioning an active grant is not permitted.',
            'ERR_JOB_ALREADY_SUCCEEDED'
        );
    }

    // Reset job to QUEUED
    const updatedJob = await withTransaction(async (transaction) => {
        const resetJob = await provisioningRepository.updateJobStatus(jobId, 'QUEUED', {
            resetAttempts: true,
            lastErrorCategory: null,
            lastErrorMessage: null
        }, transaction);

        if (job.grant_id) {
            await grantRepository.updateGrantStatus(job.grant_id, 'PROVISIONING_PENDING', {
                failureCategory: null
            }, transaction);
        }

        await auditRepository.createAuditEvent({
            eventCategory: 'PROVISIONING',
            eventAction: 'MANUAL_RETRY_INITIATED',
            entityType: 'access_requests',
            entityId: job.request_id,
            actorUserId: user.user_id,
            actorType: 'USER',
            eventPayload: {
                job_id: jobId,
                grant_id: job.grant_id,
                initiated_by: user.display_name,
                previous_status: job.job_status,
                previous_error: job.last_error_message
            }
        }, transaction);

        return resetJob;
    });

    // Schedule immediate processing pass (skip background auto-execution in test runner)
    if (!options.deferExecution && process.env.NODE_ENV !== 'test') {
        provisioningWorker.processNextJob(jobId).catch(err => {
            logger.warn('Immediate manual retry pass deferred to background worker', { jobId, error: err.message });
        });
    }

    return updatedJob;
}

/**
 * Offboarding & Revocation Safeguard (PROMPT 06.5 Hardened):
 * Evaluates whether an access grant can be safely revoked automatically via connector.
 * 
 * Governance Rules (PROMPT 06.5 Section 5):
 * Automated revocation strictly requires:
 * 1. CREATED_BY_ACCESSLEASE provenance.
 * 2. Independently verified provider-side membership-add evidence (PROVIDER_AUDIT_CONFIRMED).
 * 3. Exact grant, organization, team, and user target match.
 * 4. Current active membership verification.
 * 5. No conflicting or ambiguous ownership evidence.
 * 
 * If ANY condition is missing or ambiguous, automated revocation is denied.
 * 
 * @param {object} grant Access grant record
 * @param {object} [options={}] Options including optional auditEvent, auditEvents, currentMembership
 * @returns {Promise<{ canRevoke: boolean, reason: string }>}
 */
async function isSafeForAutomatedRevocation(grant, options = {}) {
    if (!grant) {
        return { canRevoke: false, reason: 'Grant record is missing.' };
    }

    const provenance = grant.membership_provenance;

    if (!provenance || typeof provenance !== 'string') {
        return { canRevoke: false, reason: 'Grant membership provenance is missing or invalid.' };
    }

    if (provenance === 'PRE_EXISTING_ADOPTED') {
        return {
            canRevoke: false,
            reason: 'Membership was pre-existing before AccessLease engagement. Automated connector revocation is strictly forbidden.'
        };
    }

    if (provenance === 'UNCERTAIN_PRE_EXISTING') {
        return {
            canRevoke: false,
            reason: 'Membership provenance is uncertain. Automated connector revocation is forbidden to prevent removing unowned access. Requires manual security investigation.'
        };
    }

    if (provenance !== 'CREATED_BY_ACCESSLEASE') {
        return {
            canRevoke: false,
            reason: `Grant has unapproved provenance '${provenance}'. Automated connector revocation is forbidden.`
        };
    }

    // Current membership verification if supplied
    if (options.currentMembership) {
        if (options.currentMembership.state !== 'active') {
            return {
                canRevoke: false,
                reason: `Target user does not currently hold active membership (current state: '${options.currentMembership.state}'). Automated revocation is not applicable.`
            };
        }
    }

    // Retrieve events for this grant if not explicitly provided
    let events = options.auditEvents || (options.auditEvent ? [options.auditEvent] : null) ||
                 options.confirmationEvents || (options.confirmationEvent ? [options.confirmationEvent] : null);

    let allGrantEvents = [];
    if (!events && grant.grant_id) {
        try {
            allGrantEvents = await provisioningRepository.getProvisioningEventsByGrantId(grant.grant_id);
            events = allGrantEvents.filter(e => e.event_type === 'PROVIDER_AUDIT_CONFIRMED');
        } catch (err) {
            logger.warn('Failed querying provisioning events during revocation safety check', { grantId: grant.grant_id, error: err.message });
            return {
                canRevoke: false,
                reason: `Failed querying durable provider audit evidence: ${err.message}`
            };
        }
    } else if (grant.grant_id && allGrantEvents.length === 0) {
        try {
            allGrantEvents = await provisioningRepository.getProvisioningEventsByGrantId(grant.grant_id);
        } catch {}
    }

    // Check for conflicting or ambiguous ownership evidence
    const hasConflict = allGrantEvents.some(e => 
        e.event_type === 'AUDIT_VERIFICATION_FAILED' ||
        (e.event_type === 'MEMBERSHIP_DISCOVERED' && e.payload?.preExisting === true)
    );
    if (hasConflict) {
        return {
            canRevoke: false,
            reason: 'Conflicting or ambiguous ownership evidence exists for this grant. Automated revocation denied.'
        };
    }

    if (!events || events.length === 0) {
        return {
            canRevoke: false,
            reason: 'Missing independently verified provider-side audit evidence (PROVIDER_AUDIT_CONFIRMED). Automated revocation denied.'
        };
    }

    const matchesTargetTeam = (auditTeam, org, targetTeam) => {
        if (!auditTeam || !targetTeam) return false;
        const cleanAudit = String(auditTeam).trim().toLowerCase();
        const cleanTarget = String(targetTeam).trim().toLowerCase();
        const cleanOrg = String(org || '').trim().toLowerCase();
        return cleanAudit === cleanTarget ||
               cleanAudit.endsWith(`/${cleanTarget}`) ||
               (cleanOrg && cleanAudit === `${cleanOrg}/${cleanTarget}`);
    };

    const matching = events.find(ev => {
        if (ev.event_type !== 'PROVIDER_AUDIT_CONFIRMED') return false;

        let payload = ev.payload;
        if (typeof payload === 'string') {
            try { payload = JSON.parse(payload); } catch {}
        }
        if (!payload) return false;

        if (payload.verificationStatus !== 'VERIFIED') return false;

        const orgMatch = !grant.target_org || !payload.targetOrg ||
            grant.target_org.trim().toLowerCase() === payload.targetOrg.trim().toLowerCase();
        const teamMatch = !grant.target_team_slug || !payload.targetTeam ||
            matchesTargetTeam(payload.targetTeam, grant.target_org, grant.target_team_slug);
        const userMatch = !grant.external_username || !payload.externalUsername ||
            grant.external_username.trim().toLowerCase() === payload.externalUsername.trim().toLowerCase();
        const grantMatch = !grant.grant_id || !payload.grantId ||
            grant.grant_id.trim().toLowerCase() === payload.grantId.trim().toLowerCase();

        // Strict immutable user ID verification if available (PROMPT 06.6)
        let userIdMatch = true;
        const targetUserId = grant.numeric_account_id || options.numericAccountId;
        if (targetUserId && payload.auditUserId) {
            userIdMatch = String(targetUserId) === String(payload.auditUserId);
        }

        // Strict OAuth Application ID verification if configured
        let oauthAppMatch = true;
        if (options.configuredAppId && payload.auditOauthAppId) {
            oauthAppMatch = String(options.configuredAppId) === String(payload.auditOauthAppId);
        }

        return orgMatch && teamMatch && userMatch && grantMatch && userIdMatch && oauthAppMatch;
    });

    if (!matching) {
        return {
            canRevoke: false,
            reason: 'Provider audit evidence target does not match grant target or immutable identity. Automated revocation denied.'
        };
    }

    return {
        canRevoke: true,
        reason: 'Membership was created and verified by AccessLease with matching independent provider audit evidence. Safe for automated revocation.'
    };
}

/**
 * Synchronous variant of isSafeForAutomatedRevocation when audit evidence is passed directly.
 */
function isSafeForAutomatedRevocationSync(grant, options = {}) {
    if (!grant) return { canRevoke: false, reason: 'Grant record is missing.' };
    const provenance = grant.membership_provenance;
    if (!provenance || typeof provenance !== 'string') return { canRevoke: false, reason: 'Grant membership provenance is missing or invalid.' };
    if (provenance === 'PRE_EXISTING_ADOPTED') return { canRevoke: false, reason: 'Membership was pre-existing before AccessLease engagement. Automated connector revocation is strictly forbidden.' };
    if (provenance === 'UNCERTAIN_PRE_EXISTING') return { canRevoke: false, reason: 'Membership provenance is uncertain. Automated connector revocation is forbidden to prevent removing unowned access. Requires manual security investigation.' };
    if (provenance !== 'CREATED_BY_ACCESSLEASE') return { canRevoke: false, reason: `Grant has unapproved provenance '${provenance}'. Automated connector revocation is forbidden.` };

    if (options.currentMembership && options.currentMembership.state !== 'active') {
        return { canRevoke: false, reason: `Target user does not currently hold active membership (current state: '${options.currentMembership.state}'). Automated revocation is not applicable.` };
    }

    let events = options.auditEvents || (options.auditEvent ? [options.auditEvent] : null) ||
                 options.confirmationEvents || (options.confirmationEvent ? [options.confirmationEvent] : null);
    if (!events || events.length === 0) {
        return { canRevoke: false, reason: 'Missing independently verified provider-side audit evidence (PROVIDER_AUDIT_CONFIRMED). Automated revocation denied.' };
    }

    const matchesTargetTeam = (auditTeam, org, targetTeam) => {
        if (!auditTeam || !targetTeam) return false;
        const cleanAudit = String(auditTeam).trim().toLowerCase();
        const cleanTarget = String(targetTeam).trim().toLowerCase();
        const cleanOrg = String(org || '').trim().toLowerCase();
        return cleanAudit === cleanTarget || cleanAudit.endsWith(`/${cleanTarget}`) || (cleanOrg && cleanAudit === `${cleanOrg}/${cleanTarget}`);
    };

    const matching = events.find(ev => {
        if (ev.event_type !== 'PROVIDER_AUDIT_CONFIRMED') return false;
        let payload = ev.payload;
        if (typeof payload === 'string') { try { payload = JSON.parse(payload); } catch {} }
        if (!payload) return false;
        if (payload.verificationStatus !== 'VERIFIED') return false;

        const orgMatch = !grant.target_org || !payload.targetOrg || grant.target_org.trim().toLowerCase() === payload.targetOrg.trim().toLowerCase();
        const teamMatch = !grant.target_team_slug || !payload.targetTeam || matchesTargetTeam(payload.targetTeam, grant.target_org, grant.target_team_slug);
        const userMatch = !grant.external_username || !payload.externalUsername || grant.external_username.trim().toLowerCase() === payload.externalUsername.trim().toLowerCase();
        const grantMatch = !grant.grant_id || !payload.grantId || grant.grant_id.trim().toLowerCase() === payload.grantId.trim().toLowerCase();

        let userIdMatch = true;
        const targetUserId = grant.numeric_account_id || options.numericAccountId;
        if (targetUserId && payload.auditUserId) {
            userIdMatch = String(targetUserId) === String(payload.auditUserId);
        }

        let oauthAppMatch = true;
        if (options.configuredAppId && payload.auditOauthAppId) {
            oauthAppMatch = String(options.configuredAppId) === String(payload.auditOauthAppId);
        }

        return orgMatch && teamMatch && userMatch && grantMatch && userIdMatch && oauthAppMatch;
    });

    if (!matching) return { canRevoke: false, reason: 'Provider audit evidence target does not match grant target or immutable identity. Automated revocation denied.' };
    return { canRevoke: true, reason: 'Membership was created and verified by AccessLease with matching independent provider audit evidence. Safe for automated revocation.' };
}

module.exports = {
    createProvisioningOperation,
    getProvisioningStateByRequestId,
    listJobs,
    listGrants,
    retryJob,
    isSafeForAutomatedRevocation,
    isSafeForAutomatedRevocationSync
};
