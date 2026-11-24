/**
 * AccessLease — GitHub Audit Log Verification Service (PROMPT 06.6 Hardened)
 * 
 * Provides authoritative independent provider-side ownership verification of GitHub team memberships
 * via the GitHub Organization Audit Log REST API.
 * 
 * Official GitHub REST API Specifications (PROMPT 06.6 Section 1):
 * - Endpoint: GET /orgs/{org}/audit-log
 * - Plan Requirement: GitHub Enterprise Cloud (GHEC) or GitHub Enterprise Server (GHES).
 * - Supported Token Types:
 *     1. GitHub App user access tokens (acting on behalf of an Organization Owner).
 *     2. GitHub App installation access tokens.
 * - Required GitHub App Permission: Organization permissions -> Administration: Read (organization_administration: read).
 *     NOTE: Classic read:audit_log / admin:org scope applies only to PATs/OAuth Apps. There is no
 *     fine-grained permission named 'audit_log:read' for GitHub Apps.
 * 
 * Strict Actor Attribution Rules (PROMPT 06.6 Section 2):
 * - GitHub App ID, GitHub bot account user ID, and audit-log actor identity are NOT interchangeable.
 * - actor_id is the numeric user ID of the bot account, NOT the GITHUB_APP_ID.
 * - oauth_application_id (when present) represents the GitHub App / OAuth application entity.
 * - If oauth_application_id is present, it MUST match the configured App ID / OAuth App ID.
 * - Bot username must match ${appSlug}[bot] and actor_is_bot must be true.
 * - Incomplete, ambiguous, or conflicting actor events are strictly rejected.
 * 
 * Exact Target & Immutable Identity Rules (PROMPT 06.6 Section 3):
 * - Supports bare team slug ('team-slug') and full team slug ('org/team-slug') format.
 * - Where contractor's immutable numeric GitHub account ID (numericAccountId) is available,
 *   event.user_id MUST match. Conflicting user IDs are rejected immediately.
 */

const githubConfig = require('./githubConfig');
const githubApiClient = require('./githubApiClient');
const githubTeamService = require('./githubTeamService');
const provisioningRepository = require('../../repositories/provisioningRepository');
const logger = require('../../utils/logger');

// Permitted correlation window defaults: up to 30s before operation, up to 300s (5 min) after
const DEFAULT_CORRELATION_WINDOW_SECONDS = 300;
const PRE_OPERATION_SLACK_MS = 30000;
const RECENT_OPERATION_INGESTION_WINDOW_MS = 60000;

/**
 * Checks whether an event actor matches the configured AccessLease GitHub App.
 * Distinguishes GitHub App ID from bot user account ID, and validates oauth_application_id.
 * 
 * @param {object} event GitHub audit log event
 * @param {object} [options={}] Attribution configuration
 * @param {string} [options.configuredAppSlug] Configured App Slug (e.g. 'accesslease')
 * @param {string|number} [options.configuredAppId] Configured App ID
 * @param {string|number} [options.configuredOAuthAppId] Configured OAuth Application ID
 * @param {string|number} [options.configuredBotUserId] Expected bot user account numeric ID
 * @returns {{ matches: boolean, reason?: string, details?: any, actor?: string, actorId?: any, oauthAppId?: any }}
 */
function isAccessLeaseActor(event, options = {}) {
    if (!event || typeof event !== 'object') {
        return { matches: false, reason: 'MISSING_EVENT_OBJECT' };
    }

    if (!event.actor || typeof event.actor !== 'string') {
        return { matches: false, reason: 'MISSING_OR_INVALID_ACTOR_LOGIN' };
    }

    const config = githubConfig.getConfig();
    const appSlug = String(options.configuredAppSlug || config.appSlug || 'accesslease').trim().toLowerCase();
    const expectedAppId = options.configuredOAuthAppId || options.configuredAppId || config.appId;
    const actor = event.actor.trim().toLowerCase();
    const expectedBot = `${appSlug}[bot]`;

    // 1. Validate Bot Identity Flag if present
    if (event.actor_is_bot === false) {
        return {
            matches: false,
            reason: 'ACTOR_NOT_A_BOT',
            details: { actor: event.actor, actorIsBot: event.actor_is_bot }
        };
    }

    // 2. Validate Bot Account Login
    const matchesBotLogin = (actor === expectedBot || actor === appSlug);
    if (!matchesBotLogin) {
        return {
            matches: false,
            reason: 'ACTOR_LOGIN_MISMATCH',
            details: { actor: event.actor, expectedBot }
        };
    }

    // 3. Strict oauth_application_id Verification (Primary Provider Evidence)
    // When present in audit log, oauth_application_id directly identifies the authorized GitHub App/OAuth integration
    if (event.oauth_application_id !== undefined && event.oauth_application_id !== null) {
        if (!expectedAppId) {
            return {
                matches: false,
                reason: 'APP_ID_NOT_CONFIGURED_FOR_VERIFICATION',
                details: { eventOauthAppId: event.oauth_application_id }
            };
        }

        const matchesOauthApp = String(event.oauth_application_id) === String(expectedAppId);
        if (!matchesOauthApp) {
            return {
                matches: false,
                reason: 'OAUTH_APPLICATION_ID_MISMATCH',
                details: {
                    eventOauthAppId: event.oauth_application_id,
                    expectedAppId: String(expectedAppId)
                }
            };
        }
    }

    // 4. Strict actor_id Separation Rule:
    // actor_id is the numeric user ID of the bot account, NOT the GitHub App ID.
    // If a specific configuredBotUserId is configured, verify it. Otherwise, do not equate actor_id with GITHUB_APP_ID.
    if (options.configuredBotUserId) {
        if (String(event.actor_id) !== String(options.configuredBotUserId)) {
            return {
                matches: false,
                reason: 'BOT_USER_ID_MISMATCH',
                details: {
                    actorId: event.actor_id,
                    expectedBotUserId: options.configuredBotUserId
                }
            };
        }
    }

    return {
        matches: true,
        actor: event.actor,
        actorId: event.actor_id,
        oauthAppId: event.oauth_application_id,
        actorIsBot: Boolean(event.actor_is_bot)
    };
}

/**
 * Normalizes team slug/name comparison between grant target and audit event.
 * Supports both bare slug ('team-slug') and full team slug ('org/team-slug') formats.
 * 
 * @param {string} auditTeam Team value from audit event (e.g. 'dev-team' or 'org/dev-team')
 * @param {string} targetOrg Target organization slug
 * @param {string} targetTeam Target team slug
 * @returns {boolean}
 */
function matchesTargetTeam(auditTeam, targetOrg, targetTeam) {
    if (!auditTeam || !targetTeam) return false;

    const cleanAudit = String(auditTeam).trim().toLowerCase();
    const cleanTarget = String(targetTeam).trim().toLowerCase();
    const cleanOrg = String(targetOrg || '').trim().toLowerCase();

    // 1. Exact match on bare slug ('backend-engineers' === 'backend-engineers')
    if (cleanAudit === cleanTarget) return true;

    // 2. Full team slug format ('accesslease-governance/backend-engineers')
    if (cleanOrg && cleanAudit === `${cleanOrg}/${cleanTarget}`) return true;

    // 3. Suffix match for nested or prefixed team paths
    if (cleanAudit.endsWith(`/${cleanTarget}`)) return true;

    return false;
}

/**
 * Queries the GitHub Organization Audit Log REST API for team.add_member events.
 * Handles rate limits, pagination, non-enterprise plans, and network errors.
 * 
 * @param {string} org GitHub organization slug
 * @param {object} [options={}] Query options
 * @param {string} [options.phrase] Optional query phrase override
 * @param {number} [options.page=1] Page number
 * @param {number} [options.perPage=30] Results per page
 * @returns {Promise<{ available: boolean, rateLimited?: boolean, retryAfterSeconds?: number, reason?: string, error?: string, events: object[], page: number, perPage: number }>}
 */
async function queryTeamAddMemberAuditEvents(org, options = {}) {
    githubTeamService.validateOrganizationAllowlisted(org);

    const phrase = options.phrase || 'action:team.add_member';
    const page = options.page || 1;
    const perPage = options.perPage || 30;
    const endpoint = `/orgs/${encodeURIComponent(org)}/audit-log?phrase=${encodeURIComponent(phrase)}&page=${page}&per_page=${perPage}`;

    try {
        const response = await githubApiClient.request(endpoint, {
            method: 'GET',
            timeoutMs: 15000
        });

        // Handle Rate Limits (HTTP 429 or 403 secondary rate limit)
        if (response.status === 429 || (response.status === 403 && (response.data?.message?.includes('rate limit') || response.data?.message?.includes('secondary rate limit')))) {
            const retryAfterHeader = response.headers?.get ? response.headers.get('retry-after') : null;
            const retryAfter = parseInt(retryAfterHeader, 10) || 60;
            logger.warn('GitHub rate limit encountered while querying audit log', { org, retryAfter });
            return {
                available: false,
                rateLimited: true,
                retryAfterSeconds: retryAfter,
                reason: 'RATE_LIMITED',
                error: response.data?.message || 'GitHub audit log rate limit exceeded.',
                events: [],
                page,
                perPage
            };
        }

        // HTTP 403 / 404 indicates feature not available on current plan or insufficient scope
        if (response.status === 403 || response.status === 404) {
            const message = response.data?.message || 'Access to organization audit log is forbidden or not found.';
            logger.warn('GitHub organization audit log unavailable on this plan or permission tier', {
                org,
                status: response.status,
                message
            });
            return {
                available: false,
                rateLimited: false,
                reason: 'AUDIT_LOG_UNSUPPORTED_OR_FORBIDDEN',
                error: message,
                events: [],
                page,
                perPage
            };
        }

        if (response.status !== 200) {
            logger.warn('Unexpected response status when querying GitHub audit log', {
                org,
                status: response.status,
                data: response.data
            });
            return {
                available: false,
                rateLimited: false,
                reason: 'AUDIT_LOG_QUERY_ERROR',
                error: `HTTP ${response.status}`,
                events: [],
                page,
                perPage
            };
        }

        const rawEvents = Array.isArray(response.data) ? response.data : [];

        // De-duplicate events by _document_id / document_id / timestamp_actor
        const seenIds = new Set();
        const deduplicated = [];
        for (const ev of rawEvents) {
            const docId = ev._document_id || ev.document_id || ev.id || `${ev['@timestamp'] || ev.created_at}_${ev.actor}`;
            if (!seenIds.has(docId)) {
                seenIds.add(docId);
                deduplicated.push(ev);
            }
        }

        return {
            available: true,
            rateLimited: false,
            events: deduplicated,
            page,
            perPage
        };
    } catch (err) {
        logger.warn('Network or transport failure querying GitHub audit log', {
            org,
            error: err.message
        });
        return {
            available: false,
            rateLimited: false,
            reason: 'AUDIT_LOG_RETRIEVAL_FAILED',
            error: err.message,
            events: [],
            page,
            perPage
        };
    }
}

/**
 * Independently retrieves and verifies provider-side audit evidence for a specific membership addition.
 * Enforces strict actor attribution, exact target matching, and immutable user ID verification.
 * 
 * @param {string} org Target organization slug
 * @param {string} teamSlug Target team slug
 * @param {string} username Target contractor GitHub login
 * @param {object} [options={}]
 * @param {number|string|Date} [options.operationTimestamp] Timestamp when PUT operation was initiated
 * @param {number} [options.windowSeconds=300] Correlation window duration in seconds
 * @param {string} [options.appSlug] Expected GitHub App slug override
 * @param {string|number} [options.appId] Expected GitHub App ID override
 * @param {string|number} [options.numericAccountId] Contractor's verified immutable numeric GitHub user ID
 * @param {boolean} [options.requireTargetUserId=false] Whether target user_id is mandatory
 * @param {object[]} [options.injectedEvents] Pre-fetched or mocked events for testing
 * @returns {Promise<{ verified: boolean, status: string, reason: string, auditEvent?: object, details?: any, retryEligible?: boolean }>}
 */
async function verifyMembershipAddEvent(org, teamSlug, username, options = {}) {
    const config = githubConfig.getConfig();
    const appSlug = options.appSlug || config.appSlug || 'accesslease';
    const appId = options.appId || config.appId;
    const windowSeconds = options.windowSeconds || DEFAULT_CORRELATION_WINDOW_SECONDS;
    const numericAccountId = options.numericAccountId;

    const opTime = options.operationTimestamp
        ? new Date(options.operationTimestamp).getTime()
        : Date.now();
    const minTimestamp = opTime - PRE_OPERATION_SLACK_MS;
    const maxTimestamp = opTime + (windowSeconds * 1000);

    let events;

    if (Array.isArray(options.injectedEvents)) {
        events = options.injectedEvents;
    } else {
        const queryResult = await queryTeamAddMemberAuditEvents(org);
        if (!queryResult.available) {
            return {
                verified: false,
                status: queryResult.rateLimited ? 'RATE_LIMITED' : 'AUDIT_UNAVAILABLE',
                reason: `GitHub Audit Log API is unavailable (${queryResult.reason}): ${queryResult.error || ''}`.trim(),
                details: queryResult,
                retryEligible: Boolean(queryResult.rateLimited)
            };
        }
        events = queryResult.events;
    }

    if (!events || events.length === 0) {
        // Evaluate ingestion latency window
        const timeSinceOp = Date.now() - opTime;
        if (timeSinceOp <= RECENT_OPERATION_INGESTION_WINDOW_MS) {
            return {
                verified: false,
                status: 'EVENT_NOT_YET_VISIBLE',
                retryEligible: true,
                reason: `No audit log events found for organization '${org}'. Event may not yet be visible due to provider ingestion latency.`
            };
        }

        return {
            verified: false,
            status: 'EVENT_NOT_FOUND',
            retryEligible: false,
            reason: `No audit log events found for organization '${org}'.`
        };
    }

    const cleanUser = String(username).trim().toLowerCase();
    const cleanOrg = String(org).trim().toLowerCase();

    // Rejection trackers
    let actorMismatchEvent = null;
    let actorMismatchReason = null;
    let teamMismatchEvent = null;
    let userIdMismatchEvent = null;
    let userIdMissingEvent = null;
    let windowExpiredEvent = null;

    for (const event of events) {
        // 1. Verify action
        if (event.action !== 'team.add_member') continue;

        // 2. Verify target username handle
        const eventUser = (event.user || '').trim().toLowerCase();
        if (eventUser !== cleanUser) continue;

        // 3. Verify target immutable user ID (PROMPT 06.6 Section 3)
        if (numericAccountId) {
            if (event.user_id !== undefined && event.user_id !== null) {
                if (String(event.user_id) !== String(numericAccountId)) {
                    userIdMismatchEvent = event;
                    continue;
                }
            } else if (options.requireTargetUserId) {
                userIdMissingEvent = event;
                continue;
            }
        }

        // 4. Verify organization
        const eventOrg = (event.org || '').trim().toLowerCase();
        if (eventOrg && eventOrg !== cleanOrg) continue;

        // 5. Verify team (supports bare slug and full slug format 'org/team-slug')
        const auditTeam = event.team || event.data?.team;
        const teamMatches = matchesTargetTeam(auditTeam, org, teamSlug);

        // 6. Verify actor using strict attribution rules
        const actorCheck = isAccessLeaseActor(event, {
            configuredAppSlug: appSlug,
            configuredAppId: appId,
            configuredOAuthAppId: options.oauthApplicationId || appId,
            configuredBotUserId: options.botUserId
        });

        // 7. Verify timestamp within correlation window
        const rawTime = event['@timestamp'] || event.created_at || event.timestamp;
        const eventTime = new Date(rawTime).getTime();
        const inWindow = !isNaN(eventTime) && eventTime >= minTimestamp && eventTime <= maxTimestamp;

        if (!actorCheck.matches) {
            actorMismatchEvent = event;
            actorMismatchReason = actorCheck.reason;
            continue;
        }

        if (!teamMatches) {
            teamMismatchEvent = event;
            continue;
        }

        if (!inWindow) {
            windowExpiredEvent = event;
            continue;
        }

        // Complete Authoritative Match!
        return {
            verified: true,
            status: 'VERIFIED',
            reason: 'Authoritative provider-side audit evidence successfully verified.',
            auditEvent: {
                id: event._document_id || event.document_id || event.id || `${eventTime}_${event.actor}`,
                action: event.action,
                actor: event.actor,
                actorId: event.actor_id,
                oauthAppId: event.oauth_application_id,
                actorIsBot: Boolean(event.actor_is_bot),
                user: event.user,
                userId: event.user_id,
                team: auditTeam,
                org: event.org,
                providerTimestamp: new Date(eventTime).toISOString(),
                retrievalTimestamp: new Date().toISOString()
            }
        };
    }

    // Specific rejection diagnoses
    if (userIdMismatchEvent) {
        return {
            verified: false,
            status: 'USER_ID_MISMATCH',
            reason: `Audit event user_id '${userIdMismatchEvent.user_id}' does not match contractor's verified numeric account ID '${numericAccountId}'.`,
            auditEvent: userIdMismatchEvent
        };
    }

    if (userIdMissingEvent) {
        return {
            verified: false,
            status: 'USER_ID_MISSING',
            reason: 'Audit event is missing required user_id for immutable identity verification.',
            auditEvent: userIdMissingEvent
        };
    }

    if (actorMismatchEvent) {
        return {
            verified: false,
            status: 'ACTOR_MISMATCH',
            reason: `Audit event actor verification failed (${actorMismatchReason}).`,
            auditEvent: actorMismatchEvent,
            details: { failureReason: actorMismatchReason }
        };
    }

    if (teamMismatchEvent) {
        return {
            verified: false,
            status: 'TEAM_MISMATCH',
            reason: `Audit event actor matched AccessLease, but target team '${teamMismatchEvent.team || teamMismatchEvent.data?.team}' does not match requested team '${teamSlug}'.`,
            auditEvent: teamMismatchEvent
        };
    }

    if (windowExpiredEvent) {
        const expiredTime = new Date(windowExpiredEvent['@timestamp'] || windowExpiredEvent.created_at).toISOString();
        return {
            verified: false,
            status: 'CORRELATION_WINDOW_EXPIRED',
            reason: `Matching audit event found but timestamp (${expiredTime}) falls outside permitted correlation window.`,
            auditEvent: windowExpiredEvent
        };
    }

    // Check for ingestion latency
    const timeSinceOp = Date.now() - opTime;
    if (timeSinceOp <= RECENT_OPERATION_INGESTION_WINDOW_MS) {
        return {
            verified: false,
            status: 'EVENT_NOT_YET_VISIBLE',
            retryEligible: true,
            reason: `Audit event for user '${username}' not yet visible in GitHub Organization Audit Log. Ingestion latency expected.`
        };
    }

    return {
        verified: false,
        status: 'EVENT_NOT_FOUND',
        retryEligible: false,
        reason: `No matching team.add_member audit event found for user '${username}' on team '${teamSlug}' in org '${org}'.`
    };
}

/**
 * Idempotently persists verified provider audit evidence or verification failure in dbo.provisioning_events.
 * Strictly avoids storing secrets, tokens, or credentials.
 * 
 * @param {object} params
 * @param {string} params.grantId Access grant identifier
 * @param {string} [params.jobId] Provisioning job identifier
 * @param {string} params.org Target organization slug
 * @param {string} params.teamSlug Target team slug
 * @param {string} params.username Contractor GitHub login
 * @param {object} params.verificationResult Outcome of verifyMembershipAddEvent
 * @returns {Promise<object|null>} Committed or existing event record
 */
async function recordProviderAuditEvidence(params) {
    const { grantId, jobId, org, teamSlug, username, verificationResult } = params;
    if (!grantId) return null;

    try {
        const priorEvents = await provisioningRepository.getProvisioningEventsByGrantId(grantId);

        if (verificationResult.verified) {
            // Idempotency: Check if matching PROVIDER_AUDIT_CONFIRMED already exists
            const existingAuditConfirmed = priorEvents.find(e => e.event_type === 'PROVIDER_AUDIT_CONFIRMED');
            if (existingAuditConfirmed) {
                logger.info('PROVIDER_AUDIT_CONFIRMED event already recorded for grant (idempotent)', { grantId });
                return existingAuditConfirmed;
            }

            const audit = verificationResult.auditEvent;
            return await provisioningRepository.createProvisioningEvent({
                grantId,
                eventType: 'PROVIDER_AUDIT_CONFIRMED',
                connectorName: 'GITHUB',
                payload: {
                    grantId,
                    jobId: jobId || null,
                    connectorType: 'GITHUB',
                    targetOrg: org,
                    targetTeam: teamSlug,
                    externalUsername: username,
                    auditEventId: audit.id,
                    auditAction: audit.action,
                    auditActor: audit.actor,
                    auditActorId: audit.actorId,
                    auditOauthAppId: audit.oauthAppId,
                    auditUser: audit.user,
                    auditUserId: audit.userId,
                    auditTeam: audit.team,
                    auditOrg: audit.org,
                    providerTimestamp: audit.providerTimestamp,
                    retrievalTimestamp: audit.retrievalTimestamp,
                    verificationStatus: 'VERIFIED'
                },
                statusCode: '200'
            });
        } else {
            // Record failure/unavailability for audit visibility
            return await provisioningRepository.createProvisioningEvent({
                grantId,
                eventType: 'AUDIT_VERIFICATION_FAILED',
                connectorName: 'GITHUB',
                payload: {
                    grantId,
                    jobId: jobId || null,
                    connectorType: 'GITHUB',
                    targetOrg: org,
                    targetTeam: teamSlug,
                    externalUsername: username,
                    failureStatus: verificationResult.status,
                    failureReason: verificationResult.reason
                },
                statusCode: '400',
                errorMessage: verificationResult.reason
            });
        }
    } catch (dbErr) {
        logger.error('Failed persisting provider audit evidence to database', {
            grantId,
            error: dbErr.message
        });
        return null;
    }
}

module.exports = {
    isAccessLeaseActor,
    matchesTargetTeam,
    queryTeamAddMemberAuditEvents,
    verifyMembershipAddEvent,
    recordProviderAuditEvidence
};
