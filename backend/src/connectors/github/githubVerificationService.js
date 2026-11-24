/**
 * AccessLease — GitHub Verification & Provisioning Service (PROMPT 06.5 Hardened)
 * Orchestrates pre-flight target validation, team repository permission checks,
 * contractor membership provisioning, confirmed post-verification, and authoritative
 * provider-side audit log verification.
 * 
 * Rules:
 * - Never reports ACTIVE access unless GitHub confirms 'active' state.
 * - Tracks provenance ('CREATED_BY_ACCESSLEASE' vs 'PRE_EXISTING_ADOPTED' vs 'UNCERTAIN_PRE_EXISTING').
 * - Per PROMPT 06.5: CREATED_BY_ACCESSLEASE may ONLY be assigned when authoritative provider-side
 *   audit evidence (team.add_member event) has been independently retrieved and validated.
 * - If audit log evidence is unavailable, missing, or mismatched, UNCERTAIN_PRE_EXISTING is assigned.
 * - Automated revocation is strictly blocked for unverified or uncertain provenance.
 */

const crypto = require('crypto');
const githubConfig = require('./githubConfig');
const githubTeamService = require('./githubTeamService');
const githubAuditService = require('./githubAuditService');
const provisioningRepository = require('../../repositories/provisioningRepository');
const { ConnectorError } = require('../../utils/errors');
const logger = require('../../utils/logger');

/**
 * Resolves and validates independent PROVIDER_AUDIT_CONFIRMED evidence from dbo.provisioning_events.
 * Enforces exact target matching across grantId, targetOrg, targetTeam, and externalUsername,
 * and verifies that provider verification status is 'VERIFIED'.
 * 
 * @param {object} params
 * @param {string} [params.grantId]
 * @param {string} params.org
 * @param {string} params.teamSlug
 * @param {string} params.username
 * @param {object} [params.providerAuditEvent] Direct injected audit event (for testing/mocking)
 * @returns {Promise<{ hasAuditEvent: boolean, matchesTarget: boolean, event: object|null }>}
 */
async function resolveProviderAuditEvidence({ grantId, org, teamSlug, username, numericAccountId = null, providerAuditEvent = null }) {
    let event = providerAuditEvent;

    if (!event && grantId) {
        try {
            const priorEvents = await provisioningRepository.getProvisioningEventsByGrantId(grantId);
            event = priorEvents.find(e => e.event_type === 'PROVIDER_AUDIT_CONFIRMED') || null;
        } catch (dbErr) {
            logger.warn('Failed querying prior provisioning events for provider audit evidence', { grantId, error: dbErr.message });
        }
    }

    if (!event) {
        return { hasAuditEvent: false, matchesTarget: false, event: null };
    }

    let payload = event.payload;
    if (typeof payload === 'string') {
        try { payload = JSON.parse(payload); } catch {}
    }

    if (!payload) {
        return { hasAuditEvent: true, matchesTarget: false, event };
    }

    // Verify exact target match: grant, org, team, user, verificationStatus, immutable numeric user_id
    const matchesOrg = payload.targetOrg && payload.targetOrg.trim().toLowerCase() === org.trim().toLowerCase();
    const matchesTeam = githubAuditService.matchesTargetTeam(payload.targetTeam, org, teamSlug);
    const matchesUser = payload.externalUsername && payload.externalUsername.trim().toLowerCase() === username.trim().toLowerCase();
    const matchesGrant = !payload.grantId || !grantId || payload.grantId.trim().toLowerCase() === grantId.trim().toLowerCase();
    const isVerified = payload.verificationStatus === 'VERIFIED';

    let matchesUserId = true;
    if (numericAccountId && payload.auditUserId) {
        matchesUserId = String(payload.auditUserId) === String(numericAccountId);
    }

    const matchesTarget = Boolean(matchesOrg && matchesTeam && matchesUser && matchesGrant && isVerified && matchesUserId);

    return {
        hasAuditEvent: true,
        matchesTarget,
        event
    };
}

/**
 * Resolves and validates local mutation confirmation evidence.
 * Retained for backward compatibility and local operation correlation.
 * 
 * @param {object} params
 * @param {string} [params.grantId]
 * @param {string} params.org
 * @param {string} params.teamSlug
 * @param {string} params.username
 * @param {object} [params.confirmedMutationEvent] Direct injected event (for testing/mocking)
 * @returns {Promise<{ hasConfirmedEvent: boolean, matchesTarget: boolean, event: object|null }>}
 */
async function resolveConfirmedMutationEvidence({ grantId, org, teamSlug, username, confirmedMutationEvent = null }) {
    let event = confirmedMutationEvent;

    if (!event && grantId) {
        try {
            const priorEvents = await provisioningRepository.getProvisioningEventsByGrantId(grantId);
            event = priorEvents.find(e => 
                e.event_type === 'MEMBERSHIP_MUTATION_LOCAL_CONFIRMED' ||
                e.event_type === 'MEMBERSHIP_MUTATION_CONFIRMED'
            ) || null;
        } catch (dbErr) {
            logger.warn('Failed querying prior provisioning events for mutation confirmation evidence', { grantId, error: dbErr.message });
        }
    }

    if (!event) {
        return { hasConfirmedEvent: false, matchesTarget: false, event: null };
    }

    let payload = event.payload;
    if (typeof payload === 'string') {
        try { payload = JSON.parse(payload); } catch {}
    }

    if (!payload) {
        return { hasConfirmedEvent: true, matchesTarget: false, event };
    }

    // Verify exact target match: grant, org, team, user
    const matchesOrg = payload.targetOrg && payload.targetOrg.trim().toLowerCase() === org.trim().toLowerCase();
    const matchesTeam = githubAuditService.matchesTargetTeam(payload.targetTeam, org, teamSlug);
    const matchesUser = payload.externalUsername && payload.externalUsername.trim().toLowerCase() === username.trim().toLowerCase();
    const matchesGrant = !payload.grantId || !grantId || payload.grantId.trim().toLowerCase() === grantId.trim().toLowerCase();

    const matchesTarget = Boolean(matchesOrg && matchesTeam && matchesUser && matchesGrant);

    return {
        hasConfirmedEvent: true,
        matchesTarget,
        event
    };
}

/**
 * Executes confirmed GitHub team access provisioning for a verified contractor.
 * @param {object} params
 * @param {string} params.org GitHub organization slug
 * @param {string} params.teamSlug GitHub team slug
 * @param {string} params.repoOwner Target repository owner
 * @param {string} params.repoName Target repository name
 * @param {string} params.requiredPermission Required permission level ('pull', 'push', etc.)
 * @param {string} params.username Verified contractor GitHub login
 * @returns {Promise<object>} Structured provisioning outcome
 */
async function provisionAndVerifyAccess(params) {
    const {
        org,
        teamSlug,
        repoOwner,
        repoName,
        requiredPermission = 'pull',
        username,
        isRetry = false,
        existingProvenance = null,
        grantId = null,
        jobId = null,
        operationId = null,
        confirmedMutationEvent = null,
        providerAuditEvent = null,
        injectedAuditEvents = null,
        numericAccountId = null,
        requireTargetUserId = false,
        oauthApplicationId = null,
        botUserId = null
    } = params;

    // 1. Assert Connector Configuration
    githubConfig.validateConfig();

    // 2. Validate Allowlisted Organization
    githubTeamService.validateOrganizationAllowlisted(org);

    // 3. Pre-Flight Validation: Verify target team exists
    const team = await githubTeamService.getTeam(org, teamSlug);
    logger.info('Verified GitHub target team existence', { org, teamSlug, teamId: team.id });

    // 4. Pre-Flight Validation: Verify team has required repository permission
    const repoPerms = await githubTeamService.getTeamRepoPermissions(org, teamSlug, repoOwner, repoName);
    if (!repoPerms) {
        throw new ConnectorError(
            `Target repository '${repoOwner}/${repoName}' is not assigned to team '${teamSlug}' in organization '${org}'. Access cannot be provisioned.`,
            400,
            'ERR_GITHUB_REPO_NOT_IN_TEAM',
            { category: 'CONFIGURATION_ERROR', org, teamSlug, repoOwner, repoName },
            false
        );
    }

    const hasPermission = githubTeamService.checkPermissionSatisfies(repoPerms.permissions, requiredPermission);
    if (!hasPermission) {
        throw new ConnectorError(
            `Team '${teamSlug}' possesses insufficient repository permission on '${repoOwner}/${repoName}'. Required: '${requiredPermission}', Actual: [${Object.entries(repoPerms.permissions).filter(([, v]) => v).map(([k]) => k).join(', ')}].`,
            400,
            'ERR_GITHUB_INSUFFICIENT_TEAM_PERMS',
            { category: 'CONFIGURATION_ERROR', requiredPermission, actualPermissions: repoPerms.permissions },
            false
        );
    }

    // 5. Check Current Membership State (Pre-Flight Lookup)
    const existingMembership = await githubTeamService.getTeamMembership(org, teamSlug, username);

    // Scenario A & D: Active membership discovered
    if (existingMembership && existingMembership.state === 'active') {
        let provenance;
        let isAdopted = false;

        if (existingProvenance === 'PRE_EXISTING_ADOPTED') {
            provenance = 'PRE_EXISTING_ADOPTED';
            isAdopted = true;
        } else if (!isRetry && existingProvenance !== 'CREATED_BY_ACCESSLEASE') {
            // Fresh discovery on initial attempt before AccessLease ever issued a mutation
            // Per Prompt 06.5 Section 2: Pre-existing membership discovered before mutation
            provenance = 'PRE_EXISTING_ADOPTED';
            isAdopted = true;
        } else {
            // Retry / Reconciliation scenario:
            // Query for durable independent PROVIDER_AUDIT_CONFIRMED evidence matching exact target
            const auditProof = await resolveProviderAuditEvidence({
                grantId,
                org,
                teamSlug,
                username,
                numericAccountId,
                providerAuditEvent
            });

            if (auditProof.hasAuditEvent && auditProof.matchesTarget) {
                // Recovered via matching independent provider audit evidence!
                provenance = 'CREATED_BY_ACCESSLEASE';
                isAdopted = false;
                logger.info('Provenance recovered via matching PROVIDER_AUDIT_CONFIRMED evidence: CREATED_BY_ACCESSLEASE', {
                    grantId,
                    username,
                    org,
                    teamSlug
                });
            } else if (auditProof.hasAuditEvent && !auditProof.matchesTarget) {
                // Target mismatch! Audit event belongs to another grant, team, org, or user
                provenance = 'UNCERTAIN_PRE_EXISTING';
                isAdopted = true;
                logger.warn('Provisioning confirmation target mismatch: Provider audit event targets different org/team/user. Assigned UNCERTAIN_PRE_EXISTING', {
                    grantId,
                    username,
                    org,
                    teamSlug,
                    eventPayload: auditProof.event?.payload
                });
            } else {
                // Distributed system crash window or unconfirmed external addition:
                // Without independent provider audit evidence, ownership CANNOT be proven!
                provenance = 'UNCERTAIN_PRE_EXISTING';
                isAdopted = true;
                logger.warn('Provenance uncertain on retry: Missing durable PROVIDER_AUDIT_CONFIRMED proof. Assigned UNCERTAIN_PRE_EXISTING to protect unowned access', {
                    grantId,
                    username,
                    org,
                    teamSlug
                });
            }
        }

        logger.info('Discovered active GitHub team membership', {
            org,
            teamSlug,
            username,
            role: existingMembership.role,
            isRetry,
            provenance
        });

        return {
            success: true,
            state: 'ACTIVE',
            membershipProvenance: provenance,
            verifiedAt: new Date().toISOString(),
            invitationPending: false,
            preExisting: isAdopted,
            metadata: {
                teamId: team.id,
                teamName: team.name,
                role: existingMembership.role,
                repoFullName: repoPerms.full_name,
                verifiedState: 'active'
            }
        };
    }

    // Pending Invitation State
    if (existingMembership && existingMembership.state === 'pending') {
        logger.info('Discovered existing pending invitation for GitHub user', { org, teamSlug, username });
        let provenance;
        let isAdopted = false;

        if (existingProvenance === 'PRE_EXISTING_ADOPTED') {
            provenance = 'PRE_EXISTING_ADOPTED';
            isAdopted = true;
        } else if (!isRetry && existingProvenance !== 'CREATED_BY_ACCESSLEASE') {
            // Pending invitation existed prior to AccessLease execution
            provenance = 'PRE_EXISTING_ADOPTED';
            isAdopted = true;
        } else {
            const auditProof = await resolveProviderAuditEvidence({
                grantId,
                org,
                teamSlug,
                username,
                numericAccountId,
                providerAuditEvent
            });

            if (auditProof.hasAuditEvent && auditProof.matchesTarget) {
                provenance = 'CREATED_BY_ACCESSLEASE';
                isAdopted = false;
            } else {
                provenance = 'UNCERTAIN_PRE_EXISTING';
                isAdopted = true;
            }
        }

        return {
            success: true,
            state: 'PENDING_ACCEPTANCE',
            membershipProvenance: provenance,
            verifiedAt: new Date().toISOString(),
            invitationPending: true,
            preExisting: isAdopted,
            metadata: {
                teamId: team.id,
                teamName: team.name,
                role: existingMembership.role,
                repoFullName: repoPerms.full_name,
                verifiedState: 'pending'
            }
        };
    }

    // 6. Execute Provisioning Mutation: Add contractor to team
    logger.info('Submitting GitHub team membership request', { org, teamSlug, username });
    const addResult = await githubTeamService.addOrUpdateTeamMembership(org, teamSlug, username, 'member');
    const operationTimestamp = new Date().toISOString();

    // 6a. Commit local mutation response event (MEMBERSHIP_MUTATION_LOCAL_CONFIRMED)
    if (grantId) {
        try {
            const existingEvents = await provisioningRepository.getProvisioningEventsByGrantId(grantId);
            const alreadyLocal = existingEvents.find(e => 
                e.event_type === 'MEMBERSHIP_MUTATION_LOCAL_CONFIRMED' ||
                e.event_type === 'MEMBERSHIP_MUTATION_CONFIRMED'
            );

            if (!alreadyLocal) {
                await provisioningRepository.createProvisioningEvent({
                    grantId,
                    eventType: 'MEMBERSHIP_MUTATION_LOCAL_CONFIRMED',
                    connectorName: 'GITHUB',
                    payload: {
                        grantId,
                        jobId: jobId || null,
                        connectorType: 'GITHUB',
                        targetOrg: org,
                        targetTeam: teamSlug,
                        externalUsername: username,
                        operationId: operationId || crypto.randomUUID(),
                        timestamp: operationTimestamp,
                        responseState: addResult.state,
                        responseRole: addResult.role || 'member'
                    },
                    statusCode: '200'
                });
                logger.info('Committed durable MEMBERSHIP_MUTATION_LOCAL_CONFIRMED event', { grantId, org, teamSlug, username });
            }
        } catch (evErr) {
            logger.error('Failed committing local mutation confirmation event', { grantId, error: evErr.message });
        }
    }

    // 6b. Independent Provider-Side Audit Verification (PROMPT 06.6 Hardened)
    // Independently retrieves and validates the team.add_member event from GitHub's audit system.
    const auditVerification = await githubAuditService.verifyMembershipAddEvent(
        org,
        teamSlug,
        username,
        {
            operationTimestamp,
            injectedEvents: injectedAuditEvents,
            numericAccountId,
            requireTargetUserId,
            oauthApplicationId,
            botUserId
        }
    );

    // 6c. Idempotently record provider audit evidence in database
    if (grantId) {
        await githubAuditService.recordProviderAuditEvidence({
            grantId,
            jobId,
            org,
            teamSlug,
            username,
            verificationResult: auditVerification
        });
    }

    // 7. Post-Verification: Re-query membership directly to confirm resulting state
    const confirmedMembership = await githubTeamService.getTeamMembership(org, teamSlug, username);
    const confirmedState = confirmedMembership ? confirmedMembership.state : addResult.state;

    logger.info('Confirmed GitHub team membership resulting state', {
        org,
        teamSlug,
        username,
        confirmedState,
        auditVerified: auditVerification.verified
    });

    // 8. Assign Provenance strictly per Prompt 06.5:
    // CREATED_BY_ACCESSLEASE may ONLY be assigned when authoritative provider-side evidence
    // proves that the membership-add event was independently retrieved and validated from GitHub's audit system.
    let provenance;
    let isAdopted;

    if (auditVerification.verified) {
        provenance = 'CREATED_BY_ACCESSLEASE';
        isAdopted = false;
        logger.info('Authoritative provider-side audit evidence verified: Assigned CREATED_BY_ACCESSLEASE', {
            grantId, org, teamSlug, username, auditEventId: auditVerification.auditEvent?.id
        });
    } else {
        provenance = 'UNCERTAIN_PRE_EXISTING';
        isAdopted = true;
        logger.warn('Provider audit evidence unavailable or unverified: Assigned UNCERTAIN_PRE_EXISTING to protect unowned access', {
            grantId, org, teamSlug, username, status: auditVerification.status, reason: auditVerification.reason
        });
    }

    return {
        success: true,
        state: confirmedState === 'active' ? 'ACTIVE' : 'PENDING_ACCEPTANCE',
        membershipProvenance: provenance,
        verifiedAt: new Date().toISOString(),
        invitationPending: confirmedState !== 'active',
        preExisting: isAdopted,
        auditVerified: auditVerification.verified,
        auditStatus: auditVerification.status,
        metadata: {
            teamId: team.id,
            teamName: team.name,
            role: confirmedMembership ? confirmedMembership.role : (addResult.role || 'member'),
            repoFullName: repoPerms.full_name,
            verifiedState: confirmedState,
            auditVerificationStatus: auditVerification.status
        }
    };
}

module.exports = {
    provisionAndVerifyAccess,
    resolveProviderAuditEvidence,
    resolveConfirmedMutationEvidence
};
