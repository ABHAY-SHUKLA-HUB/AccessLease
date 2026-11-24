/**
 * AccessLease — Integration Tests: Cross-Connector State Machine, Canonical Identity & Recovery (PROMPT 07.4)
 *
 * Verifies:
 * 1. Strict Coordination State Machine & Mutual Exclusion:
 *    - IDLE -> PROVISIONING -> IDLE
 *    - IDLE -> REVOCATION -> IDLE
 * 2. All 9 Race Interleavings (A through I):
 *    - Interleaving A: Provisioning runs while Revocation is IDLE
 *    - Interleaving B: Revocation runs while Provisioning is IDLE
 *    - Interleaving C: Provisioning arrives while Revocation is in Phase 1 (coordination held)
 *    - Interleaving D: Provisioning arrives while Revocation is in Phase 2 (DELETE in flight)
 *    - Interleaving E: Revocation arrives while Provisioning is calling GitHub PUT
 *    - Interleaving F: Revocation completes DELETE; concurrent active grant detected in Phase 3; access restored & verified
 *    - Interleaving G: Revocation completes DELETE; concurrent active grant detected; post-GET verification fails; durable retry work created
 *    - Interleaving H: Provisioning and Revocation arrive simultaneously for same canonical membership
 *    - Interleaving I: Stale/crashed worker coordination lease reclaims safely after expiration
 * 3. Canonical Identity DB Resolution & Fallback to Manual Review:
 *    - Resolves numeric account ID from dbo.user_external_identities and persists to dbo.access_grants
 *    - Routes to MANUAL_REVIEW_REQUIRED with category CANONICAL_IDENTITY_UNRESOLVED when unresolvable
 * 4. Stale/Expired Worker Coordination Lease Fencing on Renewal & Release
 */

const { describe, it, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const sql = require('mssql');

const { getPool, closePool } = require('../../src/config/database');
const {
    revocationRepository,
    grantRepository,
    auditRepository,
    requestRepository,
    provisioningRepository
} = require('../../src/repositories');
const revocationWorker = require('../../src/services/revocationWorker');
const provisioningWorker = require('../../src/services/provisioningWorker');
const { githubTeamService, githubConfig, githubVerificationService } = require('../../src/connectors/github');
const { ConflictError } = require('../../src/utils/errors');

describe('Prompt 07.4: Cross-Connector Coordination State Machine, Canonical Identity & Recovery Integration', () => {
    let pool;
    let testResourceId;
    let testEntitlementId;
    let testUserId = '27F3224F-8C5A-456E-8295-68D9919CDEED'; // Seeded contractor

    const cleanupEngagementIds = [];
    const cleanupRequestIds = [];
    const cleanupGrantIds = [];
    const cleanupJobIds = [];
    const cleanupCoordinationKeys = [];
    const cleanupIdentityUserIds = [];

    let originalGetTeam;
    let originalGetMembership;
    let originalRemoveMembership;
    let originalAddMembership;
    let originalValidateOrg;
    let originalValidateConfig;
    let originalProvisionAndVerify;

    before(async () => {
        pool = await getPool();

        const resQuery = await pool.request().query(`
            SELECT TOP 1 r.resource_id, e.entitlement_id
            FROM dbo.resources r
            INNER JOIN dbo.entitlements e ON r.resource_id = e.resource_id;
        `);
        assert.ok(resQuery.recordset.length > 0, 'Seed resource and entitlement must exist');
        testResourceId = resQuery.recordset[0].resource_id;
        testEntitlementId = resQuery.recordset[0].entitlement_id;

        originalGetTeam = githubTeamService.getTeam;
        originalGetMembership = githubTeamService.getTeamMembership;
        originalRemoveMembership = githubTeamService.removeTeamMembership;
        originalAddMembership = githubTeamService.addOrUpdateTeamMembership;
        originalValidateOrg = githubTeamService.validateOrganizationAllowlisted;
        originalValidateConfig = githubConfig.validateConfig;
        originalProvisionAndVerify = githubVerificationService.provisionAndVerifyAccess;

        githubTeamService.validateOrganizationAllowlisted = () => {};
        githubConfig.validateConfig = () => ({ isValid: true, missingFields: [] });
    });

    beforeEach(() => {
        githubTeamService.getTeam = async (org, team) => ({ id: 99999, slug: team, name: team });
        githubTeamService.getTeamMembership = async () => ({ state: 'active', role: 'member' });
        githubTeamService.removeTeamMembership = async () => ({ success: true, removed: true, status: 204 });
        githubTeamService.addOrUpdateTeamMembership = async () => ({ state: 'active', role: 'member' });
        githubVerificationService.provisionAndVerifyAccess = async () => ({
            state: 'ACTIVE',
            membershipProvenance: 'CREATED_BY_ACCESSLEASE',
            preExisting: false,
            verifiedAt: new Date().toISOString(),
            metadata: { statusCode: 200 }
        });
    });

    after(async () => {
        githubTeamService.getTeam = originalGetTeam;
        githubTeamService.getTeamMembership = originalGetMembership;
        githubTeamService.removeTeamMembership = originalRemoveMembership;
        githubTeamService.addOrUpdateTeamMembership = originalAddMembership;
        githubTeamService.validateOrganizationAllowlisted = originalValidateOrg;
        githubConfig.validateConfig = originalValidateConfig;
        githubVerificationService.provisionAndVerifyAccess = originalProvisionAndVerify;

        if (pool) {
            for (const key of cleanupCoordinationKeys) {
                try {
                    await pool.request().query(`DELETE FROM dbo.membership_coordination WHERE coordination_key = '${key}';`);
                } catch {}
            }
            for (const jid of cleanupJobIds) {
                try {
                    await pool.request().query(`
                        DELETE FROM dbo.provisioning_events WHERE job_id = '${jid}';
                        DELETE FROM dbo.provisioning_jobs WHERE job_id = '${jid}';
                    `);
                } catch {}
            }
            for (const gid of cleanupGrantIds) {
                try {
                    await pool.request().query(`
                        DELETE FROM dbo.provisioning_events WHERE grant_id = '${gid}';
                        DELETE FROM dbo.audit_events WHERE entity_id = '${gid}';
                        DELETE FROM dbo.revocation_jobs WHERE grant_id = '${gid}';
                        DELETE FROM dbo.access_grants WHERE grant_id = '${gid}';
                    `);
                } catch {}
            }
            for (const rid of cleanupRequestIds) {
                try {
                    await pool.request().query(`
                        DELETE FROM dbo.audit_events WHERE entity_id = '${rid}';
                        DELETE FROM dbo.access_requests WHERE request_id = '${rid}';
                    `);
                } catch {}
            }
            for (const eid of cleanupEngagementIds) {
                try {
                    await pool.request().query(`
                        DELETE FROM dbo.audit_events WHERE entity_id = '${eid}';
                        DELETE FROM dbo.contractor_engagements WHERE engagement_id = '${eid}';
                    `);
                } catch {}
            }
            for (const uid of cleanupIdentityUserIds) {
                try {
                    await pool.request().query(`
                        DELETE FROM dbo.user_external_identities WHERE user_id = '${uid}' AND provider = 'GITHUB';
                        DELETE FROM dbo.users WHERE user_id = '${uid}';
                    `);
                } catch {}
            }
            await closePool();
        }
    });

    // Helper: Create Contractor Engagement
    async function createEngagement() {
        const engId = crypto.randomUUID();
        cleanupEngagementIds.push(engId);
        const ref = `ENG-P074-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        await pool.request()
            .input('eid', engId)
            .input('ref', ref)
            .query(`
                INSERT INTO dbo.contractor_engagements (
                    engagement_id, contractor_user_id, sponsor_user_id,
                    vendor_name, contract_reference, status, start_date, end_date
                ) VALUES (
                    @eid, '${testUserId}', '00F82335-7866-440A-B633-D9DFFF51CF80',
                    'Test Vendor', @ref, 'ACTIVE',
                    CAST(DATEADD(DAY, -30, SYSUTCDATETIME()) AS DATE),
                    CAST(DATEADD(DAY, 30, SYSUTCDATETIME()) AS DATE)
                );
            `);
        return { engagement_id: engId };
    }

    // Helper: Create Access Request
    async function createAccessRequest(engagementId) {
        const requestId = crypto.randomUUID();
        cleanupRequestIds.push(requestId);
        const reqNum = `REQ-P074-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;
        await pool.request()
            .input('requestId', requestId)
            .input('reqNum', reqNum)
            .input('engagementId', engagementId)
            .query(`
                INSERT INTO dbo.access_requests (
                    request_id, request_number, contractor_engagement_id, requested_by_user_id,
                    resource_id, entitlement_id, requested_start_date, requested_end_date,
                    business_justification, status
                ) VALUES (
                    @requestId, @reqNum, @engagementId, '${testUserId}',
                    '${testResourceId}', '${testEntitlementId}',
                    TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'),
                    DATEADD(DAY, 30, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')),
                    'Prompt 07.4 test request', 'APPROVED'
                );
            `);
        return requestId;
    }

    // Helper: Create Access Grant
    async function createGrant(engagementId, options = {}) {
        const gid = crypto.randomUUID();
        cleanupGrantIds.push(gid);
        const reqId = options.requestId || await createAccessRequest(engagementId);
        const grantNum = `GNT-P074-${Math.floor(Math.random() * 900000 + 100000)}`;
        const status = options.status || 'ACTIVE';
        const targetOrg = options.targetOrg || 'accesslease-governance';
        const targetTeamSlug = options.targetTeamSlug || `team-p074-${Math.floor(Math.random() * 900000 + 100000)}`;
        const externalUsername = options.externalUsername || `user-p074-${Math.floor(Math.random() * 900000 + 100000)}`;
        const numericAccountId = options.numericAccountId !== undefined
            ? options.numericAccountId
            : String(Math.floor(Math.random() * 900000000 + 100000000));
        const provenance = options.provenance || 'CREATED_BY_ACCESSLEASE';
        const expiresAtExpr = options.expiresAtExpr || "DATEADD(MINUTE, -10, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))";

        await pool.request()
            .input('gid', gid)
            .input('gnum', grantNum)
            .input('reqId', reqId)
            .input('eid', engagementId)
            .input('status', status)
            .input('targetOrg', targetOrg)
            .input('targetTeamSlug', targetTeamSlug)
            .input('externalUsername', externalUsername)
            .input('numericAccountId', numericAccountId)
            .input('provenance', provenance)
            .query(`
                INSERT INTO dbo.access_grants (
                    grant_id, grant_number, request_id, contractor_engagement_id,
                    resource_id, entitlement_id, status, target_org, target_team_slug,
                    external_username, numeric_account_id, membership_provenance,
                    granted_at, expires_at
                ) VALUES (
                    @gid, @gnum, @reqId, @eid,
                    '${testResourceId}', '${testEntitlementId}', @status, @targetOrg, @targetTeamSlug,
                    @externalUsername, @numericAccountId, @provenance,
                    DATEADD(DAY, -1, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')),
                    ${expiresAtExpr}
                );
            `);

        return {
            grant_id: gid,
            target_org: targetOrg,
            target_team_slug: targetTeamSlug,
            external_username: externalUsername,
            numeric_account_id: numericAccountId,
            status,
            request_id: reqId,
            contractor_engagement_id: engagementId
        };
    }

    // Helper: Create Provider Audit Event
    async function createProviderAuditEvent(grantId, options = {}) {
        const eventId = crypto.randomUUID();
        const g = await grantRepository.findGrantById(grantId);
        const payload = {
            verificationStatus: 'VERIFIED',
            grantId,
            targetOrg: options.targetOrg || g?.target_org || 'accesslease-governance',
            targetTeam: options.targetTeam || g?.target_team_slug || 'team-test',
            externalUsername: options.externalUsername || g?.external_username || 'user-test',
            auditUserId: options.numericAccountId || g?.numeric_account_id || '888999000',
            auditOauthAppId: options.appId || '123456'
        };
        await pool.request()
            .input('eventId', eventId)
            .input('grantId', grantId)
            .input('payload', JSON.stringify(payload))
            .query(`
                INSERT INTO dbo.provisioning_events (
                    event_id, grant_id, event_type, connector_name,
                    payload, status_code, executed_at
                ) VALUES (
                    @eventId, @grantId, 'PROVIDER_AUDIT_CONFIRMED', 'GITHUB',
                    @payload, '200', SYSUTCDATETIME()
                );
            `);
    }

    // =========================================================================
    // Interleaving A: Provisioning runs while Revocation is IDLE
    // =========================================================================
    it('Interleaving A: Provisioning runs while Revocation is IDLE (IDLE -> PROVISIONING -> IDLE)', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `interleave-a-${rand}`;
        const accountId = String(900000000 + rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        // Verify initial state is IDLE or absent
        const initialCoord = await revocationRepository.acquireMembershipCoordination(
            org, team, accountId, 'PROVISIONING', crypto.randomUUID(), 'worker-prov-A', 60
        );
        assert.strictEqual(initialCoord.acquired, true);
        assert.strictEqual(initialCoord.active_operation, 'PROVISIONING');

        // Worker releases coordination back to IDLE
        const released = await revocationRepository.releaseMembershipCoordination(
            org, team, accountId, 'worker-prov-A'
        );
        assert.strictEqual(released, true);

        // Verify state is IDLE
        const check = await pool.request().query(
            `SELECT active_operation, worker_id FROM dbo.membership_coordination WHERE coordination_key = '${key}'`
        );
        assert.strictEqual(check.recordset[0].active_operation, 'IDLE');
        assert.strictEqual(check.recordset[0].worker_id, null);
    });

    // =========================================================================
    // Interleaving B: Revocation runs while Provisioning is IDLE
    // =========================================================================
    it('Interleaving B: Revocation runs while Provisioning is IDLE (IDLE -> REVOCATION -> IDLE)', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `interleave-b-${rand}`;
        const user = `user-b-${rand}`;
        const accountId = String(900000000 + rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id, {
            targetOrg: org,
            targetTeamSlug: team,
            externalUsername: user,
            numericAccountId: accountId
        });
        await createProviderAuditEvent(grant.grant_id);

        let removeCalled = false;
        githubTeamService.removeTeamMembership = async () => {
            removeCalled = true;
            return { success: true, removed: true, status: 204 };
        };
        githubTeamService.getTeamMembership = async () => {
            return removeCalled ? null : { state: 'active', role: 'member' };
        };

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        const outcome = await revocationWorker.executeRevocationJob(job, { workerId: 'worker-rev-B' });
        assert.strictEqual(outcome.success, true);

        // Verify coordination returned cleanly to IDLE
        const check = await pool.request().query(
            `SELECT active_operation, worker_id FROM dbo.membership_coordination WHERE coordination_key = '${key}'`
        );
        assert.strictEqual(check.recordset[0].active_operation, 'IDLE');
        assert.strictEqual(check.recordset[0].worker_id, null);

        // Verify grant marked REVOKED
        const g = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(g.status, 'REVOKED');
    });

    // =========================================================================
    // Interleaving C: Provisioning arrives while Revocation is in Phase 1
    // =========================================================================
    it('Interleaving C: Provisioning blocked when Revocation holds coordination in Phase 1', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `interleave-c-${rand}`;
        const accountId = String(900000000 + rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        // Revocation worker acquires coordination
        const revJobId = crypto.randomUUID();
        const coord = await revocationRepository.acquireMembershipCoordination(
            org, team, accountId, 'REVOCATION', revJobId, 'worker-rev-C', 60
        );
        assert.strictEqual(coord.acquired, true);

        // Provisioning worker attempts acquisition on same canonical account ID
        const provCoord = await revocationRepository.acquireMembershipCoordination(
            org, team, accountId, 'PROVISIONING', crypto.randomUUID(), 'worker-prov-C', 60
        );
        assert.strictEqual(provCoord.acquired, false, 'Provisioning must be blocked while Revocation holds coordination');
        assert.strictEqual(provCoord.currentOperation, 'REVOCATION');
        assert.strictEqual(provCoord.currentWorkerId, 'worker-rev-C');

        // Cleanup
        await revocationRepository.releaseMembershipCoordination(org, team, accountId, 'worker-rev-C');
    });

    // =========================================================================
    // Interleaving D: Provisioning arrives while Revocation is in Phase 2 (DELETE in flight)
    // =========================================================================
    it('Interleaving D: Provisioning cannot acquire coordination during Revocation Phase 2 DELETE', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `interleave-d-${rand}`;
        const accountId = String(900000000 + rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        // Revocation worker holds coordination throughout Phase 2
        const revJobId = crypto.randomUUID();
        await revocationRepository.acquireMembershipCoordination(
            org, team, accountId, 'REVOCATION', revJobId, 'worker-rev-D', 60
        );

        // Provisioning wait-loop should fail to acquire before timeout
        const provCoord = await revocationRepository.acquireMembershipCoordinationWithWait(
            org, team, accountId, 'PROVISIONING', crypto.randomUUID(), 'worker-prov-D', 60, 150, 30
        );
        assert.strictEqual(provCoord.acquired, false);
        assert.strictEqual(provCoord.currentOperation, 'REVOCATION');

        // Release coordination
        await revocationRepository.releaseMembershipCoordination(org, team, accountId, 'worker-rev-D');
    });

    // =========================================================================
    // Interleaving E: Revocation arrives while Provisioning is calling GitHub PUT
    // =========================================================================
    it('Interleaving E: Revocation blocked when Provisioning holds coordination', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `interleave-e-${rand}`;
        const accountId = String(900000000 + rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        // Provisioning acquires coordination
        const provJobId = crypto.randomUUID();
        await revocationRepository.acquireMembershipCoordination(
            org, team, accountId, 'PROVISIONING', provJobId, 'worker-prov-E', 60
        );

        // Revocation worker attempts acquisition
        const revCoord = await revocationRepository.acquireMembershipCoordination(
            org, team, accountId, 'REVOCATION', crypto.randomUUID(), 'worker-rev-E', 60
        );
        assert.strictEqual(revCoord.acquired, false, 'Revocation must be blocked while Provisioning holds coordination');
        assert.strictEqual(revCoord.currentOperation, 'PROVISIONING');
        assert.strictEqual(revCoord.currentWorkerId, 'worker-prov-E');

        // Release coordination
        await revocationRepository.releaseMembershipCoordination(org, team, accountId, 'worker-prov-E');
    });

    // =========================================================================
    // Interleaving F: Revocation Phase 3 Restoration & Provider Verification
    // =========================================================================
    it('Interleaving F: Phase 3 detects concurrent active grant, restores membership, and confirms via GET', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `interleave-f-${rand}`;
        const user = `user-f-${rand}`;
        const accountId = String(900000000 + rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        const eng1 = await createEngagement();
        const eng2 = await createEngagement();

        // Expiring grant1
        const grant1 = await createGrant(eng1.engagement_id, {
            targetOrg: org,
            targetTeamSlug: team,
            externalUsername: user,
            numericAccountId: accountId
        });
        await createProviderAuditEvent(grant1.grant_id);

        const job1 = await revocationRepository.createRevocationJob({
            grantId: grant1.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        let restorationPutCalled = false;
        let restorationGetCalled = false;

        githubTeamService.addOrUpdateTeamMembership = async (o, t, u, role) => {
            restorationPutCalled = true;
            return { state: 'active', role };
        };

        let removeCallCount = 0;
        githubTeamService.removeTeamMembership = async () => {
            removeCallCount++;
            // During DELETE, a new grant2 for same membership becomes active!
            await createGrant(eng2.engagement_id, {
                targetOrg: org,
                targetTeamSlug: team,
                externalUsername: user,
                numericAccountId: accountId,
                status: 'ACTIVE',
                expiresAtExpr: "DATEADD(DAY, 14, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))"
            });
            return { success: true, removed: true, status: 204 };
        };

        githubTeamService.getTeamMembership = async () => {
            if (restorationPutCalled) {
                restorationGetCalled = true;
                return { state: 'active', role: 'member' };
            }
            return removeCallCount > 0 ? null : { state: 'active', role: 'member' };
        };

        const res = await revocationWorker.executeRevocationJob(job1, { workerId: 'worker-restore-F' });

        assert.strictEqual(res.success, true);
        assert.strictEqual(res.restoredForConcurrentGrant, true);
        assert.strictEqual(restorationPutCalled, true, 'PUT must be executed to restore access');
        assert.strictEqual(restorationGetCalled, true, 'GET must verify restored membership');

        // Grant 1 marked REVOKED with CONCURRENT_GRANT_RESTORED
        const g1 = await grantRepository.findGrantById(grant1.grant_id);
        assert.strictEqual(g1.status, 'REVOKED');
        assert.strictEqual(g1.revocation_reason, 'CONCURRENT_GRANT_RESTORED');

        // Audit events RESTORATION_ATTEMPTED and RESTORATION_CONFIRMED recorded
        const auditEvents = await auditRepository.listAuditEvents({ entityId: grant1.grant_id });
        const actions = auditEvents.map(e => e.event_action);
        assert.ok(actions.includes('RESTORATION_ATTEMPTED'));
        assert.ok(actions.includes('RESTORATION_CONFIRMED'));
        assert.ok(actions.includes('COORDINATION_RELEASED'));
    });

    // =========================================================================
    // Interleaving G: Restoration PUT or verification GET fails; durable retry work created
    // =========================================================================
    it('Interleaving G: Phase 3 restoration GET failure routes to retry backoff and never reports success', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `interleave-g-${rand}`;
        const user = `user-g-${rand}`;
        const accountId = String(900000000 + rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        const eng1 = await createEngagement();
        const eng2 = await createEngagement();

        const grant1 = await createGrant(eng1.engagement_id, {
            targetOrg: org,
            targetTeamSlug: team,
            externalUsername: user,
            numericAccountId: accountId
        });
        await createProviderAuditEvent(grant1.grant_id);

        const job1 = await revocationRepository.createRevocationJob({
            grantId: grant1.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        let removeCallCount = 0;
        githubTeamService.removeTeamMembership = async () => {
            removeCallCount++;
            await createGrant(eng2.engagement_id, {
                targetOrg: org,
                targetTeamSlug: team,
                externalUsername: user,
                numericAccountId: accountId,
                status: 'ACTIVE',
                expiresAtExpr: "DATEADD(DAY, 14, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))"
            });
            return { success: true, removed: true, status: 204 };
        };

        // Restoration PUT succeeds...
        githubTeamService.addOrUpdateTeamMembership = async () => ({ state: 'active', role: 'member' });

        // ...but independent verification GET returns null (fails to confirm active membership!)
        githubTeamService.getTeamMembership = async () => {
            return removeCallCount > 0 ? null : { state: 'active', role: 'member' };
        };

        const res = await revocationWorker.executeRevocationJob(job1, { workerId: 'worker-restore-fail-G' });

        assert.strictEqual(res.success, false, 'Engine must NEVER report success when restoration GET fails');
        assert.strictEqual(res.category, 'POST_VERIFICATION_FAILED');

        // Grant 1 must NOT be marked REVOKED
        const g1 = await grantRepository.findGrantById(grant1.grant_id);
        assert.notStrictEqual(g1.status, 'REVOKED');

        // Job must be failed with retry backoff (FAILED_RETRY)
        const jobRecord = await revocationRepository.findRevocationJobById(job1.job_id);
        assert.strictEqual(jobRecord.status, 'FAILED_RETRY');
        assert.strictEqual(jobRecord.last_error_category, 'POST_VERIFICATION_FAILED');

        // Audit event RESTORATION_FAILED recorded
        const auditEvents = await auditRepository.listAuditEvents({ entityId: grant1.grant_id });
        const actions = auditEvents.map(e => e.event_action);
        assert.ok(actions.includes('RESTORATION_ATTEMPTED'));
        assert.ok(actions.includes('RESTORATION_FAILED'));
    });

    // =========================================================================
    // Interleaving H: Simultaneous Provisioning & Revocation arrival
    // =========================================================================
    it('Interleaving H: Simultaneous acquisition attempts serialize safely with zero double-claims', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `interleave-h-${rand}`;
        const accountId = String(900000000 + rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        const [coord1, coord2] = await Promise.all([
            revocationRepository.acquireMembershipCoordination(
                org, team, accountId, 'PROVISIONING', crypto.randomUUID(), 'worker-sim-prov', 60
            ),
            revocationRepository.acquireMembershipCoordination(
                org, team, accountId, 'REVOCATION', crypto.randomUUID(), 'worker-sim-rev', 60
            )
        ]);

        // Exactly one must succeed, the other must be blocked
        const successes = [coord1, coord2].filter(c => c.acquired);
        const failures = [coord1, coord2].filter(c => !c.acquired);

        assert.strictEqual(successes.length, 1, 'Exactly one operation can acquire coordination');
        assert.strictEqual(failures.length, 1, 'The competing operation must be blocked');

        // Cleanup
        const winner = successes[0];
        await revocationRepository.releaseMembershipCoordination(
            org, team, accountId, winner.worker_id
        );
    });

    // =========================================================================
    // Interleaving I: Expired Coordination Lease Reclaim
    // =========================================================================
    it('Interleaving I: Expired coordination lease reclaims safely with wasReclaimed = true', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `interleave-i-${rand}`;
        const accountId = String(900000000 + rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        // Simulate crashed worker with expired lease
        await pool.request()
            .input('key', key)
            .input('org', org)
            .input('team', team)
            .input('accountId', accountId)
            .query(`
                INSERT INTO dbo.membership_coordination (
                    coordination_key, target_org, target_team_slug, account_identifier,
                    active_operation, operation_job_id, worker_id,
                    lease_expires_at, created_at, updated_at
                ) VALUES (
                    @key, @org, @team, @accountId,
                    'REVOCATION', NEWID(), 'worker-crashed-old',
                    DATEADD(MINUTE, -10, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')),
                    SYSUTCDATETIME(), SYSUTCDATETIME()
                );
            `);

        // New worker arrives to reclaim
        const newJobId = crypto.randomUUID();
        const coord = await revocationRepository.acquireMembershipCoordination(
            org, team, accountId, 'PROVISIONING', newJobId, 'worker-reclaim-new', 60
        );

        assert.strictEqual(coord.acquired, true);
        assert.strictEqual(coord.wasReclaimed, true, 'Expired lease must be detected as reclaimed');
        assert.strictEqual(coord.worker_id, 'worker-reclaim-new');
        assert.strictEqual(coord.active_operation, 'PROVISIONING');

        // Cleanup
        await revocationRepository.releaseMembershipCoordination(org, team, accountId, 'worker-reclaim-new');
    });

    // =========================================================================
    // Canonical Identity Resolution from DB
    // =========================================================================
    it('Canonical Identity: Resolves numeric account ID from user_external_identities and persists to grant', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `canonical-resolve-${rand}`;
        const user = `user-canon-${rand}`;
        const expectedAccountId = String(550000000 + rand);

        const dedicatedUserId = crypto.randomUUID();
        cleanupIdentityUserIds.push(dedicatedUserId);

        await pool.request().query(`
            INSERT INTO dbo.users (user_id, entra_object_id, email, first_name, last_name, display_name, user_type, is_active)
            VALUES ('${dedicatedUserId}', 'oid-canon-${rand}', 'canon-${rand}@test.com', 'Canon', 'User', 'Canon User', 'CONTRACTOR', 1);

            INSERT INTO dbo.user_external_identities (identity_id, user_id, provider, external_username, external_account_id, verification_status, verified_at, created_at, updated_at)
            VALUES (NEWID(), '${dedicatedUserId}', 'GITHUB', '${user}', '${expectedAccountId}', 'VERIFIED', SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME());
        `);

        const engId = crypto.randomUUID();
        cleanupEngagementIds.push(engId);
        await pool.request()
            .input('eid', engId)
            .input('uid', dedicatedUserId)
            .input('ref', `ENG-CANON-${rand}`)
            .query(`
                INSERT INTO dbo.contractor_engagements (
                    engagement_id, contractor_user_id, sponsor_user_id,
                    vendor_name, contract_reference, status, start_date, end_date
                ) VALUES (
                    @eid, @uid, '00F82335-7866-440A-B633-D9DFFF51CF80',
                    'Canon Vendor', @ref, 'ACTIVE',
                    CAST(DATEADD(DAY, -30, SYSUTCDATETIME()) AS DATE),
                    CAST(DATEADD(DAY, 30, SYSUTCDATETIME()) AS DATE)
                );
            `);

        // Grant created with numeric_account_id = null!
        const grant = await createGrant(engId, {
            targetOrg: org,
            targetTeamSlug: team,
            externalUsername: user,
            numericAccountId: null
        });

        // Call resolveCanonicalAccountId
        const resolved = await revocationRepository.resolveCanonicalAccountId(grant);
        assert.strictEqual(resolved, expectedAccountId, 'Should resolve numeric account ID from user_external_identities');

        // Verify it was persisted back to dbo.access_grants
        const updatedGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(updatedGrant.numeric_account_id, expectedAccountId, 'Should persist resolved account ID to grant table');
    });

    // =========================================================================
    // Unresolvable Canonical Identity Routes to Manual Review
    // =========================================================================
    it('Canonical Identity: Unresolvable identity routes to MANUAL_REVIEW_REQUIRED (CANONICAL_IDENTITY_UNRESOLVED)', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `canonical-unresolved-${rand}`;
        const unknownUser = `unknown-ghost-${rand}`;

        // Create an unlinked contractor user
        const ghostUserId = crypto.randomUUID();
        const engId = crypto.randomUUID();
        cleanupEngagementIds.push(engId);

        await pool.request().query(`
            INSERT INTO dbo.users (user_id, entra_object_id, email, first_name, last_name, display_name, user_type, is_active)
            VALUES ('${ghostUserId}', 'oid-${rand}', 'ghost-${rand}@test.com', 'Ghost', 'User', 'Ghost User', 'CONTRACTOR', 1);

            INSERT INTO dbo.contractor_engagements (
                engagement_id, contractor_user_id, sponsor_user_id,
                vendor_name, contract_reference, status, start_date, end_date
            ) VALUES (
                '${engId}', '${ghostUserId}', '00F82335-7866-440A-B633-D9DFFF51CF80',
                'Ghost Vendor', 'REF-GHOST', 'ACTIVE',
                CAST(DATEADD(DAY, -30, SYSUTCDATETIME()) AS DATE),
                CAST(DATEADD(DAY, 30, SYSUTCDATETIME()) AS DATE)
            );
        `);

        const grant = await createGrant(engId, {
            targetOrg: org,
            targetTeamSlug: team,
            externalUsername: unknownUser,
            numericAccountId: null
        });

        // Ensure no external identity exists for ghost user
        await pool.request().query(`DELETE FROM dbo.user_external_identities WHERE user_id = '${ghostUserId}';`);

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        const outcome = await revocationWorker.executeRevocationJob(job, { workerId: 'worker-canon-fail' });

        assert.strictEqual(outcome.success, false);
        assert.strictEqual(outcome.manualReview, true);
        assert.strictEqual(outcome.category, 'CANONICAL_IDENTITY_UNRESOLVED');

        // Grant routed to MANUAL_REVIEW_REQUIRED
        const g = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(g.status, 'MANUAL_REVIEW_REQUIRED');

        // Cleanup ghost user and engagement
        await pool.request().query(`
            DELETE FROM dbo.provisioning_events WHERE grant_id = '${grant.grant_id}';
            DELETE FROM dbo.audit_events WHERE entity_id = '${grant.grant_id}' OR entity_id = '${engId}' OR entity_id = '${grant.request_id}';
            DELETE FROM dbo.revocation_jobs WHERE grant_id = '${grant.grant_id}';
            DELETE FROM dbo.access_grants WHERE grant_id = '${grant.grant_id}';
            DELETE FROM dbo.access_requests WHERE request_id = '${grant.request_id}';
            DELETE FROM dbo.contractor_engagements WHERE engagement_id = '${engId}';
            DELETE FROM dbo.users WHERE user_id = '${ghostUserId}';
        `);
    });

    // =========================================================================
    // Stale/Expired Worker Coordination Fencing
    // =========================================================================
    it('Coordination Fencing: renewMembershipCoordination and releaseMembershipCoordination reject stale/expired workers', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `coord-fence-${rand}`;
        const accountId = String(900000000 + rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        // Legitimate worker claims coordination
        await revocationRepository.acquireMembershipCoordination(
            org, team, accountId, 'REVOCATION', crypto.randomUUID(), 'worker-legit', 60
        );

        // Imposter worker attempts renewal
        const imposterRenewal = await revocationRepository.renewMembershipCoordination(
            org, team, accountId, 'worker-imposter', 60
        );
        assert.strictEqual(imposterRenewal, null, 'Imposter worker cannot renew coordination lease');

        // Imposter worker attempts release
        const imposterRelease = await revocationRepository.releaseMembershipCoordination(
            org, team, accountId, 'worker-imposter'
        );
        assert.strictEqual(imposterRelease, false, 'Imposter worker cannot release coordination lease');

        // Legitimate worker renews successfully
        const legitRenewal = await revocationRepository.renewMembershipCoordination(
            org, team, accountId, 'worker-legit', 60
        );
        assert.ok(legitRenewal, 'Legitimate worker must be able to renew coordination lease');

        // Legitimate worker releases successfully
        const legitRelease = await revocationRepository.releaseMembershipCoordination(
            org, team, accountId, 'worker-legit'
        );
        assert.strictEqual(legitRelease, true, 'Legitimate worker must be able to release coordination lease');
    });

    // =========================================================================
    // Prompt 07.4.1: Exact Critical Concurrency Verification Scenarios (1 to 7)
    // =========================================================================
    describe('Prompt 07.4.1: Exact Critical Concurrency Verification Scenarios (1 to 7)', () => {

        // Scenario 1: Provisioning starts immediately before Phase 3 supporting-grant check
        it('1. Provisioning starts immediately before Phase 3 supporting-grant check', async () => {
            const rand = Math.floor(Math.random() * 900000 + 100000);
            const org = 'accesslease-governance';
            const team = `scen1-team-${rand}`;
            const user = `user-scen1-${rand}`;
            const accountId = String(910000000 + rand);

            const key = revocationRepository.getMembershipLockKey(org, team, accountId);
            cleanupCoordinationKeys.push(key);

            const eng1 = await createEngagement();
            const eng2 = await createEngagement();

            const grant1 = await createGrant(eng1.engagement_id, {
                targetOrg: org,
                targetTeamSlug: team,
                externalUsername: user,
                numericAccountId: accountId
            });
            await createProviderAuditEvent(grant1.grant_id);

            const job1 = await revocationRepository.createRevocationJob({
                grantId: grant1.grant_id,
                triggerSource: 'SCHEDULED_EXPIRATION'
            });

            let restorationPutCalled = false;
            let restorationGetCalled = false;
            githubTeamService.addOrUpdateTeamMembership = async (o, t, u, role) => {
                restorationPutCalled = true;
                return { state: 'active', role };
            };

            let deleteCallCount = 0;
            let grant2 = null;
            githubTeamService.removeTeamMembership = async () => {
                deleteCallCount++;
                // Concurrently, immediately before Phase 3 supporting-grant check, grant2 becomes ACTIVE
                grant2 = await createGrant(eng2.engagement_id, {
                    targetOrg: org,
                    targetTeamSlug: team,
                    externalUsername: user,
                    numericAccountId: accountId,
                    status: 'ACTIVE',
                    expiresAtExpr: "DATEADD(DAY, 14, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))"
                });
                return { success: true, removed: true, status: 204 };
            };

            githubTeamService.getTeamMembership = async () => {
                if (restorationPutCalled) {
                    restorationGetCalled = true;
                    return { state: 'active', role: 'member' };
                }
                return deleteCallCount > 0 ? null : { state: 'active', role: 'member' };
            };

            const outcome = await revocationWorker.executeRevocationJob(job1, { workerId: 'worker-scen-1' });

            assert.strictEqual(outcome.success, true);
            assert.strictEqual(outcome.restoredForConcurrentGrant, true, 'Must detect grant2 provisioned before Phase 3 check');
            assert.strictEqual(restorationPutCalled, true, 'Must execute restoration PUT');
            assert.strictEqual(restorationGetCalled, true, 'Must confirm restored state via provider GET');

            const g1 = await grantRepository.findGrantById(grant1.grant_id);
            assert.strictEqual(g1.status, 'REVOKED');
            assert.strictEqual(g1.revocation_reason, 'CONCURRENT_GRANT_RESTORED');

            const g2 = await grantRepository.findGrantById(grant2.grant_id);
            assert.strictEqual(g2.status, 'ACTIVE', 'Grant 2 must remain ACTIVE');
        });

        // Scenario 2: Provisioning starts immediately after the supporting-grant check
        it('2. Provisioning starts immediately after the supporting-grant check', async () => {
            const rand = Math.floor(Math.random() * 900000 + 100000);
            const org = 'accesslease-governance';
            const team = `scen2-team-${rand}`;
            const user = `user-scen2-${rand}`;
            const accountId = String(920000000 + rand);

            const key = revocationRepository.getMembershipLockKey(org, team, accountId);
            cleanupCoordinationKeys.push(key);

            const eng = await createEngagement();
            const grant = await createGrant(eng.engagement_id, {
                targetOrg: org,
                targetTeamSlug: team,
                externalUsername: user,
                numericAccountId: accountId
            });
            await createProviderAuditEvent(grant.grant_id);

            const job = await revocationRepository.createRevocationJob({
                grantId: grant.grant_id,
                triggerSource: 'SCHEDULED_EXPIRATION'
            });

            let removeDone = false;
            let provisioningBlocked = false;
            githubTeamService.removeTeamMembership = async () => {
                removeDone = true;
                return { success: true, removed: true, status: 204 };
            };
            githubTeamService.getTeamMembership = async () => {
                return removeDone ? null : { state: 'active', role: 'member' };
            };

            // Revocation runs. While Revocation holds coordination in Phase 3,
            // Provisioning attempts to acquire coordination immediately after check begins.
            // We verify mutual exclusion: Provisioning CANNOT acquire coordination while Revocation is in Phase 3.
            const originalComplete = revocationRepository.completeRevocationJob;
            try {
                // Hook completeRevocationJob to simulate Provisioning arriving immediately before finalization commits
                revocationRepository.completeRevocationJob = async (...args) => {
                    // Provisioning attempts acquisition for the same canonical account ID!
                    const provAttempt = await revocationRepository.acquireMembershipCoordination(
                        org, team, accountId, 'PROVISIONING', crypto.randomUUID(), 'worker-prov-scen2', 60
                    );
                    if (!provAttempt.acquired && provAttempt.currentOperation === 'REVOCATION') {
                        provisioningBlocked = true;
                    }
                    return originalComplete.apply(revocationRepository, args);
                };

                const outcome = await revocationWorker.executeRevocationJob(job, { workerId: 'worker-scen-2' });
                assert.strictEqual(outcome.success, true);
                assert.strictEqual(provisioningBlocked, true, 'Provisioning must be blocked by coordination lease while Revocation finalizes');

                // After Revocation completes, coordination is IDLE, so Provisioning can cleanly acquire
                const provAfter = await revocationRepository.acquireMembershipCoordination(
                    org, team, accountId, 'PROVISIONING', crypto.randomUUID(), 'worker-prov-scen2', 60
                );
                assert.strictEqual(provAfter.acquired, true, 'Provisioning cleanly acquires once Revocation finishes');
                await revocationRepository.releaseMembershipCoordination(org, team, accountId, 'worker-prov-scen2');

                // Grant is verified as REVOKED
                const g = await grantRepository.findGrantById(grant.grant_id);
                assert.strictEqual(g.status, 'REVOKED');
            } finally {
                revocationRepository.completeRevocationJob = originalComplete;
            }
        });

        // Scenario 3: Coordination lease expires during DELETE and another worker reclaims it
        it('3. Coordination lease expires during DELETE and another worker reclaims it', async () => {
            const rand = Math.floor(Math.random() * 900000 + 100000);
            const org = 'accesslease-governance';
            const team = `scen3-team-${rand}`;
            const accountId = String(930000000 + rand);

            const key = revocationRepository.getMembershipLockKey(org, team, accountId);
            cleanupCoordinationKeys.push(key);

            // Worker 1 acquires coordination
            const job1Id = crypto.randomUUID();
            const coord1 = await revocationRepository.acquireMembershipCoordination(
                org, team, accountId, 'REVOCATION', job1Id, 'worker-scen3-old', 60
            );
            assert.strictEqual(coord1.acquired, true);

            // Simulate lease expiration during DELETE: advance lease_expires_at into the past
            await pool.request()
                .input('key', key)
                .query(`
                    UPDATE dbo.membership_coordination
                    SET lease_expires_at = DATEADD(SECOND, -15, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                    WHERE coordination_key = @key;
                `);

            // Worker 2 arrives and reclaims the expired coordination lease
            const job2Id = crypto.randomUUID();
            const coord2 = await revocationRepository.acquireMembershipCoordination(
                org, team, accountId, 'REVOCATION', job2Id, 'worker-scen3-new', 60
            );

            assert.strictEqual(coord2.acquired, true, 'Worker 2 must successfully acquire the expired coordination lease');
            assert.strictEqual(coord2.wasReclaimed, true, 'Worker 2 acquisition must be flagged as wasReclaimed');
            assert.strictEqual(coord2.worker_id, 'worker-scen3-new');
            assert.strictEqual(coord2.prev_worker_id, 'worker-scen3-old');

            // Cleanup
            await revocationRepository.releaseMembershipCoordination(org, team, accountId, 'worker-scen3-new');
        });

        // Scenario 4: Old worker returns after the new worker acquires coordination
        it('4. Old worker returns after the new worker acquires coordination', async () => {
            const rand = Math.floor(Math.random() * 900000 + 100000);
            const org = 'accesslease-governance';
            const team = `scen4-team-${rand}`;
            const accountId = String(940000000 + rand);

            const key = revocationRepository.getMembershipLockKey(org, team, accountId);
            cleanupCoordinationKeys.push(key);

            // Worker 1 claims coordination
            await revocationRepository.acquireMembershipCoordination(
                org, team, accountId, 'REVOCATION', crypto.randomUUID(), 'worker-scen4-old', 60
            );

            // Worker 1's lease expires and Worker 2 reclaims it
            await pool.request()
                .input('key', key)
                .query(`
                    UPDATE dbo.membership_coordination
                    SET lease_expires_at = DATEADD(SECOND, -10, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                    WHERE coordination_key = @key;
                `);

            await revocationRepository.acquireMembershipCoordination(
                org, team, accountId, 'REVOCATION', crypto.randomUUID(), 'worker-scen4-new', 60
            );

            // Old Worker 1 returns and re-verifies ownership before mutating or finalizing:
            const oldWorkerCoordActive = await revocationRepository.verifyMembershipCoordinationActive(
                org, team, accountId, 'worker-scen4-old', 'REVOCATION'
            );
            assert.strictEqual(oldWorkerCoordActive, false, 'Old worker must fail coordination verification');

            // Old Worker 1 attempts to release coordination: mutates 0 rows
            const oldWorkerRelease = await revocationRepository.releaseMembershipCoordination(
                org, team, accountId, 'worker-scen4-old'
            );
            assert.strictEqual(oldWorkerRelease, false, 'Old worker cannot release new worker lease');

            // Old Worker 1 attempts to renew: returns null
            const oldWorkerRenew = await revocationRepository.renewMembershipCoordination(
                org, team, accountId, 'worker-scen4-old', 60
            );
            assert.strictEqual(oldWorkerRenew, null, 'Old worker cannot renew new worker lease');

            // Active coordination owner in database remains Worker 2!
            const coordRecord = await pool.request()
                .input('key', key)
                .query(`SELECT worker_id, active_operation FROM dbo.membership_coordination WHERE coordination_key = @key;`);
            assert.strictEqual(coordRecord.recordset[0].worker_id, 'worker-scen4-new');

            // Cleanup
            await revocationRepository.releaseMembershipCoordination(org, team, accountId, 'worker-scen4-new');
        });

        // Scenario 5: Worker crashes after GitHub DELETE but before database reconciliation
        it('5. Worker crashes after GitHub DELETE but before database reconciliation', async () => {
            const rand = Math.floor(Math.random() * 900000 + 100000);
            const org = 'accesslease-governance';
            const team = `scen5-team-${rand}`;
            const user = `user-scen5-${rand}`;
            const accountId = String(950000000 + rand);

            const key = revocationRepository.getMembershipLockKey(org, team, accountId);
            cleanupCoordinationKeys.push(key);

            const eng = await createEngagement();
            const grant = await createGrant(eng.engagement_id, {
                targetOrg: org,
                targetTeamSlug: team,
                externalUsername: user,
                numericAccountId: accountId
            });
            await createProviderAuditEvent(grant.grant_id);

            const job = await revocationRepository.createRevocationJob({
                grantId: grant.grant_id,
                triggerSource: 'SCHEDULED_EXPIRATION'
            });

            // Simulate Worker 1 claiming job and coordination, performing DELETE, then crashing before Phase 3!
            await revocationRepository.claimRevocationJobById(job.job_id, 'worker-scen5-crashed', 60);
            await revocationRepository.acquireMembershipCoordination(
                org, team, accountId, 'REVOCATION', job.job_id, 'worker-scen5-crashed', 60
            );
            await grantRepository.updateGrantStatus(grant.grant_id, 'REVOKE_PENDING');

            // Provider DELETE succeeded: membership is now absent at GitHub
            githubTeamService.getTeamMembership = async () => null;

            // Worker 1 crashes: leases expire
            await pool.request()
                .input('jobId', job.job_id)
                .input('key', key)
                .query(`
                    UPDATE dbo.revocation_jobs
                    SET lease_expires_at = DATEADD(SECOND, -30, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                    WHERE job_id = @jobId;

                    UPDATE dbo.membership_coordination
                    SET lease_expires_at = DATEADD(SECOND, -30, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                    WHERE coordination_key = @key;
                `);

            // Worker 2 arrives to recover
            const recoveryOutcome = await revocationWorker.executeRevocationJob(job, { workerId: 'worker-scen5-recovery' });

            assert.strictEqual(recoveryOutcome.success, true);
            assert.strictEqual(recoveryOutcome.alreadyAbsent, true, 'Worker 2 must detect membership is already absent at provider');

            // Grant is finalized to REVOKED as ALREADY_ABSENT_AT_PROVIDER
            const g = await grantRepository.findGrantById(grant.grant_id);
            assert.strictEqual(g.status, 'REVOKED');
            assert.strictEqual(g.revocation_reason, 'ALREADY_ABSENT_AT_PROVIDER');

            // Job is completed
            const updatedJob = await revocationRepository.findRevocationJobById(job.job_id);
            assert.strictEqual(updatedJob.status, 'REVOKED');
            assert.strictEqual(updatedJob.lease_owner, null);
        });

        // Scenario 6: Restoration PUT fails
        it('6. Restoration PUT fails', async () => {
            const rand = Math.floor(Math.random() * 900000 + 100000);
            const org = 'accesslease-governance';
            const team = `scen6-team-${rand}`;
            const user = `user-scen6-${rand}`;
            const accountId = String(960000000 + rand);

            const key = revocationRepository.getMembershipLockKey(org, team, accountId);
            cleanupCoordinationKeys.push(key);

            const eng1 = await createEngagement();
            const eng2 = await createEngagement();

            const grant1 = await createGrant(eng1.engagement_id, {
                targetOrg: org,
                targetTeamSlug: team,
                externalUsername: user,
                numericAccountId: accountId
            });
            await createProviderAuditEvent(grant1.grant_id);

            const job1 = await revocationRepository.createRevocationJob({
                grantId: grant1.grant_id,
                triggerSource: 'SCHEDULED_EXPIRATION'
            });

            let removeCount = 0;
            githubTeamService.removeTeamMembership = async () => {
                removeCount++;
                // Create concurrent active grant2
                await createGrant(eng2.engagement_id, {
                    targetOrg: org,
                    targetTeamSlug: team,
                    externalUsername: user,
                    numericAccountId: accountId,
                    status: 'ACTIVE',
                    expiresAtExpr: "DATEADD(DAY, 14, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))"
                });
                return { success: true, removed: true, status: 204 };
            };

            // Restoration PUT throws an error!
            githubTeamService.addOrUpdateTeamMembership = async () => {
                const err = new Error('GitHub API 500: Server error during team membership PUT');
                err.statusCode = 500;
                throw err;
            };

            githubTeamService.getTeamMembership = async () => {
                return removeCount > 0 ? null : { state: 'active', role: 'member' };
            };

            const outcome = await revocationWorker.executeRevocationJob(job1, { workerId: 'worker-scen-6' });

            assert.strictEqual(outcome.success, false, 'Must fail when restoration PUT throws');
            assert.strictEqual(outcome.category, 'POST_VERIFICATION_FAILED');

            // Grant 1 must NOT be marked REVOKED and NOT ACTIVE (remains REVOKE_PENDING)
            const g1 = await grantRepository.findGrantById(grant1.grant_id);
            assert.strictEqual(g1.status, 'REVOKE_PENDING', 'Grant 1 must remain in pending state');

            // Job must be failed with retry backoff
            const jobRec = await revocationRepository.findRevocationJobById(job1.job_id);
            assert.strictEqual(jobRec.status, 'FAILED_RETRY');
            assert.strictEqual(jobRec.last_error_category, 'POST_VERIFICATION_FAILED');

            // Audit event RESTORATION_FAILED is recorded
            const events = await auditRepository.listAuditEvents({ entityId: grant1.grant_id });
            const actions = events.map(e => e.event_action);
            assert.ok(actions.includes('RESTORATION_ATTEMPTED'));
            assert.ok(actions.includes('RESTORATION_FAILED'));
        });

        // Scenario 7: Restoration PUT succeeds but verification GET fails
        it('7. Restoration PUT succeeds but verification GET fails', async () => {
            const rand = Math.floor(Math.random() * 900000 + 100000);
            const org = 'accesslease-governance';
            const team = `scen7-team-${rand}`;
            const user = `user-scen7-${rand}`;
            const accountId = String(970000000 + rand);

            const key = revocationRepository.getMembershipLockKey(org, team, accountId);
            cleanupCoordinationKeys.push(key);

            const eng1 = await createEngagement();
            const eng2 = await createEngagement();

            const grant1 = await createGrant(eng1.engagement_id, {
                targetOrg: org,
                targetTeamSlug: team,
                externalUsername: user,
                numericAccountId: accountId
            });
            await createProviderAuditEvent(grant1.grant_id);

            const job1 = await revocationRepository.createRevocationJob({
                grantId: grant1.grant_id,
                triggerSource: 'SCHEDULED_EXPIRATION'
            });

            let removeCount = 0;
            githubTeamService.removeTeamMembership = async () => {
                removeCount++;
                // Create concurrent active grant2
                await createGrant(eng2.engagement_id, {
                    targetOrg: org,
                    targetTeamSlug: team,
                    externalUsername: user,
                    numericAccountId: accountId,
                    status: 'ACTIVE',
                    expiresAtExpr: "DATEADD(DAY, 14, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))"
                });
                return { success: true, removed: true, status: 204 };
            };

            // Restoration PUT succeeds!
            githubTeamService.addOrUpdateTeamMembership = async () => ({ state: 'active', role: 'member' });

            // BUT verification GET fails (returns null - user not found!)
            githubTeamService.getTeamMembership = async () => {
                return removeCount > 0 ? null : { state: 'active', role: 'member' };
            };

            const outcome = await revocationWorker.executeRevocationJob(job1, { workerId: 'worker-scen-7' });

            assert.strictEqual(outcome.success, false, 'Must never infer success when verification GET fails');
            assert.strictEqual(outcome.category, 'POST_VERIFICATION_FAILED');

            // Grant 1 must NOT be marked REVOKED or ACTIVE
            const g1 = await grantRepository.findGrantById(grant1.grant_id);
            assert.strictEqual(g1.status, 'REVOKE_PENDING', 'Grant 1 must remain in pending state');

            // Job must be failed with retry backoff
            const jobRec = await revocationRepository.findRevocationJobById(job1.job_id);
            assert.strictEqual(jobRec.status, 'FAILED_RETRY');
            assert.strictEqual(jobRec.last_error_category, 'POST_VERIFICATION_FAILED');

            // Audit event RESTORATION_FAILED is recorded
            const events = await auditRepository.listAuditEvents({ entityId: grant1.grant_id });
            const actions = events.map(e => e.event_action);
            assert.ok(actions.includes('RESTORATION_ATTEMPTED'));
            assert.ok(actions.includes('RESTORATION_FAILED'));
        });
    });
});
