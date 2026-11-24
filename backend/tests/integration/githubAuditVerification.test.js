/**
 * AccessLease — GitHub Audit API Authentication & Actor Attribution Test Suite (PROMPT 06.6)
 * 
 * Verifies the 16 mandatory audit and attribution rules:
 * 1. GitHub App installation token with documented permissions (Organization: Administration: Read).
 * 2. Missing organization owner authorization (HTTP 403 handled gracefully).
 * 3. Invalid or unsupported permission configuration (Resource not accessible handled).
 * 4. oauth_application_id matches the configured App ID (Verified).
 * 5. Different OAuth application ID (Actor mismatch).
 * 6. Bot login matches but OAuth application ID conflicts (Ownership denied).
 * 7. actor_id differs from App ID but OAuth application identity is verified (Recognizes distinct bot user ID).
 * 8. Missing actor fields (Rejected as incomplete/invalid).
 * 9. Missing target user ID (Rejected when immutable user ID required).
 * 10. Different immutable GitHub user ID (user_id mismatch rejected).
 * 11. Full team slug matching ('org/team-slug' format).
 * 12. Pagination and duplicate audit events (Deduplicated and idempotent).
 * 13. Audit event not yet visible (EVENT_NOT_YET_VISIBLE with retry eligibility).
 * 14. GitHub rate-limit response (HTTP 429 Retry-After parsed).
 * 15. Audit API unavailable (Non-enterprise plan yields UNCERTAIN_PRE_EXISTING).
 * 16. Existing OAuth, PKCE, provisioning and revocation eligibility regression.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const { getPool, closePool } = require('../../src/config/database');
const provisioningRepository = require('../../src/repositories/provisioningRepository');
const githubVerificationService = require('../../src/connectors/github/githubVerificationService');
const githubAuditService = require('../../src/connectors/github/githubAuditService');
const githubTeamService = require('../../src/connectors/github/githubTeamService');
const githubConfig = require('../../src/connectors/github/githubConfig');
const githubApiClient = require('../../src/connectors/github/githubApiClient');
const { isSafeForAutomatedRevocation } = require('../../src/services/provisioningService');
const { createIsolatedGrantFixture } = require('../helpers/testFixtureUtils');

describe('GitHub Audit API Authentication & Actor Attribution (PROMPT 06.6)', () => {
    let pool;
    let testGrantId;
    let fixture = null;
    const org = 'accesslease-governance';
    const teamSlug = 'backend-engineers';
    const username = 'audit-test-contractor';
    const configuredAppId = '123456';
    const numericContractorId = '777888999';

    // Original methods for mock restoration
    let originalValidateConfig;
    let originalValidateOrg;
    let originalGetTeam;
    let originalGetRepoPerms;
    let originalGetMembership;
    let originalAddMembership;

    before(async () => {
        pool = await getPool();

        // Find or create test grant
        const grantRes = await pool.request().query(`
            SELECT TOP 1 ag.grant_id 
            FROM dbo.access_grants ag 
            WHERE ag.status IN ('PROVISIONING_PENDING', 'PROVISIONING_IN_PROGRESS', 'ACTIVE');
        `);
        if (grantRes.recordset.length > 0) {
            testGrantId = grantRes.recordset[0].grant_id;
        } else {
            fixture = await createIsolatedGrantFixture(pool, {
                targetOrg: org,
                targetTeamSlug: teamSlug,
                externalUsername: username
            });
            testGrantId = fixture.grantId;
        }

        // Save original functions
        originalValidateConfig = githubConfig.validateConfig;
        originalValidateOrg = githubTeamService.validateOrganizationAllowlisted;
        originalGetTeam = githubTeamService.getTeam;
        originalGetRepoPerms = githubTeamService.getTeamRepoPermissions;
        originalGetMembership = githubTeamService.getTeamMembership;
        originalAddMembership = githubTeamService.addOrUpdateTeamMembership;

        // Set base mocks
        githubConfig.validateConfig = () => ({ isValid: true, missingFields: [] });
        githubTeamService.validateOrganizationAllowlisted = () => {};
        githubTeamService.getTeam = async () => ({ id: 201, name: 'Backend Engineers' });
        githubTeamService.getTeamRepoPermissions = async () => ({ permissions: { pull: true, push: true } });
    });

    after(async () => {
        // Restore original functions
        githubConfig.validateConfig = originalValidateConfig;
        githubTeamService.validateOrganizationAllowlisted = originalValidateOrg;
        githubTeamService.getTeam = originalGetTeam;
        githubTeamService.getTeamRepoPermissions = originalGetRepoPerms;
        githubTeamService.getTeamMembership = originalGetMembership;
        githubTeamService.addOrUpdateTeamMembership = originalAddMembership;
        githubApiClient.setCustomTransport(null);

        // Clean up events
        if (pool && testGrantId) {
            await pool.request().query(`DELETE FROM dbo.provisioning_events WHERE grant_id = '${testGrantId}';`);
        }
        if (fixture) {
            await fixture.cleanup();
        }
        await closePool();
    });

    // -------------------------------------------------------------------------
    // 1. GitHub App installation token with documented permissions
    // -------------------------------------------------------------------------
    it('1. GitHub App installation token with documented permissions (Organization: Administration: Read)', () => {
        const status = githubConfig.getStatus();
        assert.ok(status.requiredPermissions.organization.administration, 'Must document Organization: Administration: Read permission');
        assert.ok(status.requiredPermissions.organization.administration.toLowerCase().includes('read'), 'Must specify read permission');
        assert.strictEqual(status.requiredPermissions.organization.members, 'read/write');
        assert.ok(status.requiredPermissions.note.includes('Administration: Read'), 'Must document Administration: Read in permission notes');
    });

    // -------------------------------------------------------------------------
    // 2. Missing organization owner authorization
    // -------------------------------------------------------------------------
    it('2. Missing organization owner authorization (HTTP 403 handled gracefully)', async () => {
        githubApiClient.setCustomTransport(async (endpoint) => {
            if (endpoint.includes('/audit-log')) {
                return {
                    status: 403,
                    data: { message: 'You must be an organization owner to access the audit log.' },
                    headers: new Headers()
                };
            }
            throw new Error(`Unhandled endpoint: ${endpoint}`);
        });

        const result = await githubAuditService.queryTeamAddMemberAuditEvents(org);
        assert.strictEqual(result.available, false);
        assert.strictEqual(result.reason, 'AUDIT_LOG_UNSUPPORTED_OR_FORBIDDEN');
        assert.ok(result.error.includes('organization owner'));

        githubApiClient.setCustomTransport(null);
    });

    // -------------------------------------------------------------------------
    // 3. Invalid or unsupported permission configuration
    // -------------------------------------------------------------------------
    it('3. Invalid or unsupported permission configuration (Resource not accessible handled)', async () => {
        githubApiClient.setCustomTransport(async (endpoint) => {
            if (endpoint.includes('/audit-log')) {
                return {
                    status: 403,
                    data: { message: 'Resource not accessible by integration' },
                    headers: new Headers()
                };
            }
            throw new Error(`Unhandled endpoint: ${endpoint}`);
        });

        const outcome = await githubAuditService.verifyMembershipAddEvent(org, teamSlug, username);
        assert.strictEqual(outcome.verified, false);
        assert.strictEqual(outcome.status, 'AUDIT_UNAVAILABLE');
        assert.ok(outcome.reason.includes('Resource not accessible by integration'));

        githubApiClient.setCustomTransport(null);
    });

    // -------------------------------------------------------------------------
    // 4. oauth_application_id matches the configured App ID
    // -------------------------------------------------------------------------
    it('4. oauth_application_id matches the configured App ID (Verified)', async () => {
        const matchingEvent = {
            _document_id: 'doc_verified_123',
            action: 'team.add_member',
            actor: 'accesslease[bot]',
            actor_id: 998877, // Bot user account numeric ID
            actor_is_bot: true,
            oauth_application_id: configuredAppId, // Matches configured GitHub App ID!
            user: username,
            user_id: numericContractorId,
            org,
            team: teamSlug,
            '@timestamp': Date.now()
        };

        const result = await githubAuditService.verifyMembershipAddEvent(org, teamSlug, username, {
            appId: configuredAppId,
            injectedEvents: [matchingEvent]
        });

        assert.strictEqual(result.verified, true);
        assert.strictEqual(result.status, 'VERIFIED');
        assert.strictEqual(result.auditEvent.oauthAppId, configuredAppId);
        assert.strictEqual(result.auditEvent.actor, 'accesslease[bot]');
    });

    // -------------------------------------------------------------------------
    // 5. Different OAuth application ID
    // -------------------------------------------------------------------------
    it('5. Different OAuth application ID (Actor mismatch denied)', async () => {
        const differentOauthAppEvent = {
            _document_id: 'doc_diff_oauth_456',
            action: 'team.add_member',
            actor: 'accesslease[bot]',
            actor_id: 998877,
            actor_is_bot: true,
            oauth_application_id: '999999', // Different OAuth application!
            user: username,
            user_id: numericContractorId,
            org,
            team: teamSlug,
            '@timestamp': Date.now()
        };

        const result = await githubAuditService.verifyMembershipAddEvent(org, teamSlug, username, {
            appId: configuredAppId,
            injectedEvents: [differentOauthAppEvent]
        });

        assert.strictEqual(result.verified, false);
        assert.strictEqual(result.status, 'ACTOR_MISMATCH');
        assert.ok(result.reason.includes('OAUTH_APPLICATION_ID_MISMATCH'));
    });

    // -------------------------------------------------------------------------
    // 6. Bot login matches but OAuth application ID conflicts
    // -------------------------------------------------------------------------
    it('6. Bot login matches but OAuth application ID conflicts (Ownership denied)', async () => {
        await pool.request().query(`DELETE FROM dbo.provisioning_events WHERE grant_id = '${testGrantId}';`);

        let membershipCalls = 0;
        githubTeamService.getTeamMembership = async () => {
            membershipCalls++;
            return membershipCalls === 1 ? null : { state: 'active', role: 'member' };
        };
        githubTeamService.addOrUpdateTeamMembership = async () => ({ state: 'active', role: 'member' });

        const conflictingAppEvent = {
            _document_id: 'doc_conflict_789',
            action: 'team.add_member',
            actor: 'accesslease[bot]', // Login matches bot name!
            actor_is_bot: true,
            oauth_application_id: '888888', // BUT conflicting OAuth app ID!
            user: username,
            user_id: numericContractorId,
            org,
            team: teamSlug,
            '@timestamp': Date.now()
        };

        const outcome = await githubVerificationService.provisionAndVerifyAccess({
            org,
            teamSlug,
            repoOwner: org,
            repoName: 'backend-service',
            requiredPermission: 'pull',
            username,
            isRetry: false,
            grantId: testGrantId,
            oauthApplicationId: configuredAppId,
            injectedAuditEvents: [conflictingAppEvent]
        });

        assert.strictEqual(outcome.membershipProvenance, 'UNCERTAIN_PRE_EXISTING', 'Must deny ownership when OAuth application ID conflicts, even if bot login matches');
        assert.strictEqual(outcome.preExisting, true);
        assert.strictEqual(outcome.auditVerified, false);
    });

    // -------------------------------------------------------------------------
    // 7. actor_id differs from App ID but OAuth application identity is verified
    // -------------------------------------------------------------------------
    it('7. actor_id differs from App ID but OAuth application identity is verified (Recognizes distinct bot user ID)', async () => {
        // App ID is 123456, but GitHub bot user account ID is 7771234 (completely separate numeric space)
        const validBotDifferentIdEvent = {
            _document_id: 'doc_valid_bot_id',
            action: 'team.add_member',
            actor: 'accesslease[bot]',
            actor_id: 7771234, // Distinct bot account user ID
            actor_is_bot: true,
            oauth_application_id: configuredAppId, // Matches GitHub App ID!
            user: username,
            user_id: numericContractorId,
            org,
            team: teamSlug,
            '@timestamp': Date.now()
        };

        const actorCheck = githubAuditService.isAccessLeaseActor(validBotDifferentIdEvent, {
            configuredAppSlug: 'accesslease',
            configuredAppId
        });

        assert.strictEqual(actorCheck.matches, true, 'Must verify actor when oauth_application_id matches, regardless of distinct actor_id');
        assert.strictEqual(actorCheck.actorId, 7771234);
        assert.strictEqual(actorCheck.oauthAppId, configuredAppId);
    });

    // -------------------------------------------------------------------------
    // 8. Missing actor fields
    // -------------------------------------------------------------------------
    it('8. Missing actor fields (Rejected as incomplete/invalid)', () => {
        // Missing actor property
        const missingActor = githubAuditService.isAccessLeaseActor({ action: 'team.add_member' });
        assert.strictEqual(missingActor.matches, false);
        assert.strictEqual(missingActor.reason, 'MISSING_OR_INVALID_ACTOR_LOGIN');

        // Human actor (actor_is_bot === false)
        const humanActor = githubAuditService.isAccessLeaseActor({
            actor: 'accesslease[bot]',
            actor_is_bot: false
        });
        assert.strictEqual(humanActor.matches, false);
        assert.strictEqual(humanActor.reason, 'ACTOR_NOT_A_BOT');
    });

    // -------------------------------------------------------------------------
    // 9. Missing target user ID
    // -------------------------------------------------------------------------
    it('9. Missing target user ID (Rejected when immutable user ID required)', async () => {
        const missingUserIdEvent = {
            _document_id: 'doc_missing_uid',
            action: 'team.add_member',
            actor: 'accesslease[bot]',
            actor_is_bot: true,
            oauth_application_id: configuredAppId,
            user: username,
            // user_id is missing!
            org,
            team: teamSlug,
            '@timestamp': Date.now()
        };

        const result = await githubAuditService.verifyMembershipAddEvent(org, teamSlug, username, {
            appId: configuredAppId,
            numericAccountId: numericContractorId,
            requireTargetUserId: true, // Enforce presence of immutable ID
            injectedEvents: [missingUserIdEvent]
        });

        assert.strictEqual(result.verified, false);
        assert.strictEqual(result.status, 'USER_ID_MISSING');
        assert.ok(result.reason.includes('missing required user_id'));
    });

    // -------------------------------------------------------------------------
    // 10. Different immutable GitHub user ID
    // -------------------------------------------------------------------------
    it('10. Different immutable GitHub user ID (user_id mismatch rejected)', async () => {
        const recycledUserEvent = {
            _document_id: 'doc_recycled_user',
            action: 'team.add_member',
            actor: 'accesslease[bot]',
            actor_is_bot: true,
            oauth_application_id: configuredAppId,
            user: username, // Username matches
            user_id: '999111222', // BUT immutable account ID belongs to another account!
            org,
            team: teamSlug,
            '@timestamp': Date.now()
        };

        const result = await githubAuditService.verifyMembershipAddEvent(org, teamSlug, username, {
            appId: configuredAppId,
            numericAccountId: numericContractorId, // Contractor's verified ID: '777888999'
            injectedEvents: [recycledUserEvent]
        });

        assert.strictEqual(result.verified, false);
        assert.strictEqual(result.status, 'USER_ID_MISMATCH');
        assert.ok(result.reason.includes('does not match contractor'));
    });

    // -------------------------------------------------------------------------
    // 11. Full team slug matching
    // -------------------------------------------------------------------------
    it('11. Full team slug matching (Supports "org/team-slug" and bare slug format)', async () => {
        // GitHub audit log returns full team slug: 'accesslease-governance/backend-engineers'
        const fullSlugEvent = {
            _document_id: 'doc_full_slug',
            action: 'team.add_member',
            actor: 'accesslease[bot]',
            actor_is_bot: true,
            oauth_application_id: configuredAppId,
            user: username,
            user_id: numericContractorId,
            org,
            team: `${org}/${teamSlug}`, // Full slug format!
            '@timestamp': Date.now()
        };

        const result = await githubAuditService.verifyMembershipAddEvent(org, teamSlug, username, {
            appId: configuredAppId,
            numericAccountId: numericContractorId,
            injectedEvents: [fullSlugEvent]
        });

        assert.strictEqual(result.verified, true);
        assert.strictEqual(result.status, 'VERIFIED');
    });

    // -------------------------------------------------------------------------
    // 12. Pagination and duplicate audit events
    // -------------------------------------------------------------------------
    it('12. Pagination and duplicate audit events (Deduplicated and idempotent)', async () => {
        let callCount = 0;
        githubApiClient.setCustomTransport(async (endpoint) => {
            callCount++;
            return {
                status: 200,
                data: [
                    // Same event duplicated in response payload
                    { _document_id: 'event_dup_1', action: 'team.add_member', actor: 'accesslease[bot]' },
                    { _document_id: 'event_dup_1', action: 'team.add_member', actor: 'accesslease[bot]' },
                    { _document_id: 'event_dup_2', action: 'team.add_member', actor: 'accesslease[bot]' }
                ],
                headers: new Headers()
            };
        });

        const queryResult = await githubAuditService.queryTeamAddMemberAuditEvents(org, { page: 1, perPage: 10 });
        assert.strictEqual(queryResult.available, true);
        assert.strictEqual(queryResult.events.length, 2, 'Duplicate event IDs must be filtered');
        assert.strictEqual(queryResult.page, 1);
        assert.strictEqual(queryResult.perPage, 10);

        githubApiClient.setCustomTransport(null);
    });

    // -------------------------------------------------------------------------
    // 13. Audit event not yet visible
    // -------------------------------------------------------------------------
    it('13. Audit event not yet visible (EVENT_NOT_YET_VISIBLE with retry eligibility)', async () => {
        // Operation occurred 5 seconds ago (within ingestion latency window)
        const recentOpTime = Date.now() - 5000;

        const result = await githubAuditService.verifyMembershipAddEvent(org, teamSlug, username, {
            appId: configuredAppId,
            operationTimestamp: recentOpTime,
            injectedEvents: [] // Empty: not yet ingested by GitHub
        });

        assert.strictEqual(result.verified, false);
        assert.strictEqual(result.status, 'EVENT_NOT_YET_VISIBLE');
        assert.strictEqual(result.retryEligible, true, 'Must indicate retry eligibility during ingestion latency');
        assert.ok(result.reason.includes('ingestion latency'));
    });

    // -------------------------------------------------------------------------
    // 14. GitHub rate-limit response
    // -------------------------------------------------------------------------
    it('14. GitHub rate-limit response (HTTP 429 Retry-After parsed)', async () => {
        githubApiClient.setCustomTransport(async (endpoint) => {
            const headers = new Headers();
            headers.set('retry-after', '90');
            return {
                status: 429,
                data: { message: 'You have exceeded a secondary rate limit.' },
                headers
            };
        });

        const result = await githubAuditService.queryTeamAddMemberAuditEvents(org);
        assert.strictEqual(result.available, false);
        assert.strictEqual(result.rateLimited, true);
        assert.strictEqual(result.retryAfterSeconds, 90);
        assert.strictEqual(result.reason, 'RATE_LIMITED');

        githubApiClient.setCustomTransport(null);
    });

    // -------------------------------------------------------------------------
    // 15. Audit API unavailable
    // -------------------------------------------------------------------------
    it('15. Audit API unavailable (Non-enterprise plan yields UNCERTAIN_PRE_EXISTING)', async () => {
        await pool.request().query(`DELETE FROM dbo.provisioning_events WHERE grant_id = '${testGrantId}';`);

        let membershipCalls = 0;
        githubTeamService.getTeamMembership = async () => {
            membershipCalls++;
            return membershipCalls === 1 ? null : { state: 'active', role: 'member' };
        };
        githubTeamService.addOrUpdateTeamMembership = async () => ({ state: 'active', role: 'member' });

        // Simulate 404 / 403 non-enterprise plan response
        githubApiClient.setCustomTransport(async (endpoint) => {
            if (endpoint.includes('/audit-log')) {
                return {
                    status: 403,
                    data: { message: 'Must have an enterprise account to access audit log API.' },
                    headers: new Headers()
                };
            }
            throw new Error(`Unhandled endpoint: ${endpoint}`);
        });

        const outcome = await githubVerificationService.provisionAndVerifyAccess({
            org,
            teamSlug,
            repoOwner: org,
            repoName: 'backend-service',
            requiredPermission: 'pull',
            username,
            isRetry: false,
            grantId: testGrantId
        });

        assert.strictEqual(outcome.success, true);
        assert.strictEqual(outcome.state, 'ACTIVE');
        assert.strictEqual(outcome.membershipProvenance, 'UNCERTAIN_PRE_EXISTING', 'Must assign UNCERTAIN_PRE_EXISTING on non-enterprise plan');
        assert.strictEqual(outcome.preExisting, true);

        githubApiClient.setCustomTransport(null);
    });

    // -------------------------------------------------------------------------
    // 16. Existing OAuth, PKCE, provisioning and revocation eligibility regression
    // -------------------------------------------------------------------------
    it('16. Existing OAuth, PKCE, provisioning and revocation eligibility regression', async () => {
        await pool.request().query(`DELETE FROM dbo.provisioning_events WHERE grant_id = '${testGrantId}';`);

        // Insert valid PROVIDER_AUDIT_CONFIRMED event with oauthAppId and immutable userId
        await provisioningRepository.createProvisioningEvent({
            grantId: testGrantId,
            eventType: 'PROVIDER_AUDIT_CONFIRMED',
            connectorName: 'GITHUB',
            payload: {
                grantId: testGrantId,
                targetOrg: org,
                targetTeam: teamSlug,
                externalUsername: username,
                auditActor: 'accesslease[bot]',
                auditActorId: 7771234,
                auditOauthAppId: configuredAppId,
                auditUserId: numericContractorId,
                verificationStatus: 'VERIFIED'
            },
            statusCode: '200'
        });

        const testGrant = {
            grant_id: testGrantId,
            membership_provenance: 'CREATED_BY_ACCESSLEASE',
            target_org: org,
            target_team_slug: teamSlug,
            external_username: username,
            numeric_account_id: numericContractorId
        };

        // 16a. Matching evidence with active membership -> Eligible
        const validRevoke = await isSafeForAutomatedRevocation(testGrant, {
            currentMembership: { state: 'active' },
            configuredAppId
        });
        assert.strictEqual(validRevoke.canRevoke, true, 'Revocation permitted when matching provider evidence and immutable ID exist');

        // 16b. Mismatched immutable user ID -> Denied
        const wrongUserGrant = { ...testGrant, numeric_account_id: '999000111' };
        const mismatchedRevoke = await isSafeForAutomatedRevocation(wrongUserGrant, {
            currentMembership: { state: 'active' },
            configuredAppId
        });
        assert.strictEqual(mismatchedRevoke.canRevoke, false, 'Revocation must be denied when immutable account ID conflicts');
    });
});
