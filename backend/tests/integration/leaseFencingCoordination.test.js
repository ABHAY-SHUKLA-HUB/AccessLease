/**
 * AccessLease — Integration Tests: Final Lease Fencing & Cross-Connector Coordination (PROMPT 07.3)
 *
 * Verifies:
 * 1. Strict SQL Server UTC lease fencing: completeRevocationJob, failRevocationJob, routeToManualReview reject expired leases even if lease_owner matches.
 * 2. Reclaimed lease fencing: former worker is completely blocked after lease is reassigned to another worker.
 * 3. Cross-connector coordination: acquireMembershipCoordination blocks conflicting operations across engines.
 * 4. Phase 3 convergence: concurrent grant creation during revocation triggers automatic membership restoration for active access.
 * 5. Crash recovery: worker crash between GitHub DELETE and DB reconciliation is recovered safely as ALREADY_ABSENT_AT_PROVIDER.
 * 6. Manual review evidence: CONFIRMED_REVOKED records MANUAL_ATTESTATION; DISMISSED never marks grant REVOKED.
 */

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { getPool, closePool } = require('../../src/config/database');
const {
    revocationRepository,
    grantRepository,
    auditRepository,
    provisioningRepository
} = require('../../src/repositories');
const revocationWorker = require('../../src/services/revocationWorker');
const revocationService = require('../../src/services/revocationService');
const { githubTeamService, githubConfig } = require('../../src/connectors/github');

describe('Prompt 07.3: Final Lease Fencing & Cross-Connector Coordination Integration', () => {
    let pool;
    let adminUser;
    let testResourceId;
    let testEntitlementId;

    let originalGetTeam;
    let originalGetMembership;
    let originalRemoveMembership;
    let originalAddMembership;
    let originalValidateOrg;
    let originalValidateConfig;

    const cleanupEngagementIds = [];
    const cleanupGrantIds = [];
    const cleanupRequestIds = [];
    const cleanupCoordinationKeys = [];

    before(async () => {
        pool = await getPool();

        // 1. Fetch seed users
        const usersRes = await pool.request().query(`
            SELECT u.user_id, u.email, u.display_name, r.role_code
            FROM dbo.users u
            LEFT JOIN dbo.user_roles ur ON u.user_id = ur.user_id
            LEFT JOIN dbo.roles r ON ur.role_id = r.role_id;
        `);
        const rows = usersRes.recordset;
        const adminRow = rows.find(u => u.role_code === 'SYSTEM_ADMIN');
        adminUser = {
            user_id: adminRow ? adminRow.user_id : '65DC0F17-2FDD-F111-B04D-B81EA4E649CE',
            email: adminRow ? adminRow.email : 'admin@accesslease.io',
            roles: ['SYSTEM_ADMIN']
        };

        // 2. Fetch test resource & entitlement
        const resQuery = await pool.request().query(`
            SELECT TOP 1 r.resource_id, e.entitlement_id
            FROM dbo.resources r
            INNER JOIN dbo.entitlements e ON r.resource_id = e.resource_id;
        `);
        assert.ok(resQuery.recordset.length > 0, 'Seed resource and entitlement must exist');
        testResourceId = resQuery.recordset[0].resource_id;
        testEntitlementId = resQuery.recordset[0].entitlement_id;

        // Save original methods
        originalGetTeam = githubTeamService.getTeam;
        originalGetMembership = githubTeamService.getTeamMembership;
        originalRemoveMembership = githubTeamService.removeTeamMembership;
        originalAddMembership = githubTeamService.addOrUpdateTeamMembership;
        originalValidateOrg = githubTeamService.validateOrganizationAllowlisted;
        originalValidateConfig = githubConfig.validateConfig;

        githubTeamService.validateOrganizationAllowlisted = () => {};
        githubConfig.validateConfig = () => ({ isValid: true, missingFields: [] });
    });

    beforeEach(() => {
        githubTeamService.getTeam = async (org, team) => ({ id: 99999, slug: team, name: team });
        githubTeamService.getTeamMembership = async () => ({ state: 'active', role: 'member' });
        githubTeamService.removeTeamMembership = async () => ({ success: true, removed: true, status: 204 });
        githubTeamService.addOrUpdateTeamMembership = async () => ({ state: 'active', role: 'member' });
        githubTeamService.validateOrganizationAllowlisted = () => {};
        githubConfig.validateConfig = () => ({ isValid: true, missingFields: [] });
    });

    after(async () => {
        githubTeamService.getTeam = originalGetTeam;
        githubTeamService.getTeamMembership = originalGetMembership;
        githubTeamService.removeTeamMembership = originalRemoveMembership;
        githubTeamService.addOrUpdateTeamMembership = originalAddMembership;
        githubTeamService.validateOrganizationAllowlisted = originalValidateOrg;
        githubConfig.validateConfig = originalValidateConfig;

        if (pool) {
            for (const key of cleanupCoordinationKeys) {
                try {
                    await pool.request().query(`DELETE FROM dbo.membership_coordination WHERE coordination_key = '${key}';`);
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
                    await pool.request().query(`DELETE FROM dbo.access_requests WHERE request_id = '${rid}';`);
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
            await closePool();
        }
    });

    async function createEngagement(status = 'ACTIVE') {
        const engId = crypto.randomUUID();
        cleanupEngagementIds.push(engId);
        const ref = `ENG-FENCE-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        await pool.request()
            .input('eid', engId)
            .input('ref', ref)
            .input('status', status)
            .query(`
                INSERT INTO dbo.contractor_engagements (
                    engagement_id, contractor_user_id, sponsor_user_id,
                    vendor_name, contract_reference, status, start_date, end_date
                ) VALUES (
                    @eid, '27F3224F-8C5A-456E-8295-68D9919CDEED', '00F82335-7866-440A-B633-D9DFFF51CF80',
                    'Lease Corp', @ref, @status,
                    CAST(DATEADD(DAY, -30, SYSUTCDATETIME()) AS DATE),
                    CAST(DATEADD(DAY, 30, SYSUTCDATETIME()) AS DATE)
                );
            `);
        return { engagement_id: engId };
    }

    async function createAccessRequest(engagementId) {
        const requestId = crypto.randomUUID();
        cleanupRequestIds.push(requestId);
        const reqNum = `REQ-FENCE-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;
        await pool.request()
            .input('requestId', requestId)
            .input('reqNum', reqNum)
            .input('engagementId', engagementId)
            .input('userId', '27F3224F-8C5A-456E-8295-68D9919CDEED')
            .input('resId', testResourceId)
            .input('entId', testEntitlementId)
            .query(`
                INSERT INTO dbo.access_requests (
                    request_id, request_number, contractor_engagement_id, requested_by_user_id,
                    resource_id, entitlement_id, requested_start_date, requested_end_date,
                    business_justification, status
                ) VALUES (
                    @requestId, @reqNum, @engagementId, @userId,
                    @resId, @entId, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'), DATEADD(DAY, 30, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')),
                    'Fencing test request', 'APPROVED'
                );
            `);
        return requestId;
    }

    async function createGrant(engagementId, options = {}) {
        const gid = crypto.randomUUID();
        cleanupGrantIds.push(gid);
        const reqId = options.requestId || await createAccessRequest(engagementId);
        const grantNum = `GNT-FENCE-${Math.floor(Math.random() * 900000 + 100000)}`;
        const status = options.status || 'ACTIVE';
        const targetOrg = options.targetOrg || 'accesslease-governance';
        const targetTeamSlug = options.targetTeamSlug || `team-fence-${Math.floor(Math.random() * 900000 + 100000)}`;
        const externalUsername = options.externalUsername || `user-fence-${Math.floor(Math.random() * 900000 + 100000)}`;
        const numericAccountId = options.numericAccountId || String(Math.floor(Math.random() * 900000000 + 100000000));
        const provenance = options.provenance || 'CREATED_BY_ACCESSLEASE';
        const expiresAtExpr = options.expiresAtExpr || "DATEADD(MINUTE, -10, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))";

        await pool.request()
            .input('gid', gid)
            .input('gnum', grantNum)
            .input('reqId', reqId)
            .input('eid', engagementId)
            .input('rid', testResourceId)
            .input('entid', testEntitlementId)
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
                    @rid, @entid, @status, @targetOrg, @targetTeamSlug,
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
            membership_provenance: provenance
        };
    }

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
                    event_id, grant_id, event_type, connector_name, status_code, payload, executed_at
                ) VALUES (
                    @eventId, @grantId, 'PROVIDER_AUDIT_CONFIRMED', 'GITHUB', '200', @payload, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                );
            `);
    }

    // =========================================================================
    // Test 1: Strict Expired-Lease Fencing for completeRevocationJob
    // =========================================================================
    it('1. Strict lease expiration fencing: completeRevocationJob rejects expired lease even with valid lease_owner', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        const workerId = 'worker-fence-complete';

        // Claim job
        const claimed = await revocationRepository.claimRevocationJobById(job.job_id, workerId, 60);
        assert.ok(claimed, 'Job must be successfully claimed');
        assert.strictEqual(claimed.status, 'PROCESSING');
        assert.strictEqual(claimed.lease_owner, workerId);

        // Force lease to expire in database (10 seconds ago UTC)
        await pool.request()
            .input('jobId', job.job_id)
            .query(`
                UPDATE dbo.revocation_jobs
                SET lease_expires_at = DATEADD(SECOND, -10, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                WHERE job_id = @jobId;
            `);

        // Worker attempts to complete job with expired lease
        const completionResult = await revocationRepository.completeRevocationJob(job.job_id, workerId, {
            connectorResponse: { removed: true }
        });

        // Fencing must reject completion and return null (0 rows affected)
        assert.strictEqual(completionResult, null, 'Expired lease completion must return null');

        // Verify database state: status remains PROCESSING, grant is NOT marked REVOKED
        const dbJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(dbJob.status, 'PROCESSING', 'Job status must remain PROCESSING when completion is rejected');
        assert.strictEqual(dbJob.confirmed_at, null, 'confirmed_at must remain null');

        const dbGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.notStrictEqual(dbGrant.status, 'REVOKED', 'Grant must NOT be marked REVOKED by expired worker');
    });

    // =========================================================================
    // Test 2: Strict Expired-Lease Fencing for failRevocationJob and routeToManualReview
    // =========================================================================
    it('2. Strict lease expiration fencing: failRevocationJob and routeToManualReview reject expired lease', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        const workerId = 'worker-fence-fail';

        // Claim job
        await revocationRepository.claimRevocationJobById(job.job_id, workerId, 60);

        // Force lease to expire in database
        await pool.request()
            .input('jobId', job.job_id)
            .query(`
                UPDATE dbo.revocation_jobs
                SET lease_expires_at = DATEADD(SECOND, -15, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                WHERE job_id = @jobId;
            `);

        // Worker attempts to fail job with expired lease
        const failResult = await revocationRepository.failRevocationJob(
            job.job_id,
            workerId,
            'NETWORK_TIMEOUT',
            'Connection timed out',
            true,
            30
        );
        assert.strictEqual(failResult, null, 'Expired lease failRevocationJob must return null');

        // Worker attempts to route job to manual review with expired lease
        const routeResult = await revocationRepository.routeToManualReview(
            job.job_id,
            workerId,
            'Policy ambiguity reason'
        );
        assert.strictEqual(routeResult, null, 'Expired lease routeToManualReview must return null');

        // Status remains PROCESSING in database
        const dbJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(dbJob.status, 'PROCESSING');
    });

    // =========================================================================
    // Test 3: Reclaimed Lease Fencing
    // =========================================================================
    it('3. Reclaimed lease fencing: former worker is completely blocked after lease is reassigned to another worker', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        const workerA = 'worker-reclaim-A';
        const workerB = 'worker-reclaim-B';

        // Worker A claims job
        await revocationRepository.claimRevocationJobById(job.job_id, workerA, 60);

        // Worker A lease expires
        await pool.request()
            .input('jobId', job.job_id)
            .query(`
                UPDATE dbo.revocation_jobs
                SET lease_expires_at = DATEADD(SECOND, -5, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
                WHERE job_id = @jobId;
            `);

        // Worker B reclaims the job
        const claimedB = await revocationRepository.claimRevocationJobById(job.job_id, workerB, 60);
        assert.ok(claimedB, 'Worker B must successfully reclaim expired job');
        assert.strictEqual(claimedB.lease_owner, workerB);

        // Worker A attempts to complete the job
        const staleCompletion = await revocationRepository.completeRevocationJob(job.job_id, workerA, {
            connectorResponse: { stale: true }
        });
        assert.strictEqual(staleCompletion, null, 'Stale worker A completion must be rejected');

        // Worker B completes the job
        const validCompletion = await revocationRepository.completeRevocationJob(job.job_id, workerB, {
            connectorResponse: { valid: true }
        });
        assert.ok(validCompletion, 'Active lease owner worker B completion must succeed');
        assert.strictEqual(validCompletion.status, 'REVOKED');
    });

    // =========================================================================
    // Test 4: Cross-Connector Coordination Protocol
    // =========================================================================
    it('4. Cross-connector coordination: acquireMembershipCoordination blocks conflicting operations across engines', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `coord-team-${rand}`;
        const accountId = String(rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        const dummyJobId1 = crypto.randomUUID();
        const dummyJobId2 = crypto.randomUUID();

        // 1. Worker 1 acquires coordination for REVOCATION
        const coord1 = await revocationRepository.acquireMembershipCoordination(
            org, team, accountId, 'REVOCATION', dummyJobId1, 'worker-coord-1', 60
        );
        assert.strictEqual(coord1.acquired, true);
        assert.strictEqual(coord1.active_operation, 'REVOCATION');
        assert.strictEqual(coord1.worker_id, 'worker-coord-1');

        // 2. Worker 2 attempts PROVISIONING on same membership while REVOCATION is active
        const coord2 = await revocationRepository.acquireMembershipCoordination(
            org, team, accountId, 'PROVISIONING', dummyJobId2, 'worker-coord-2', 60
        );
        assert.strictEqual(coord2.acquired, false, 'Conflicting PROVISIONING must be blocked by active REVOCATION');
        assert.strictEqual(coord2.currentOperation, 'REVOCATION');
        assert.strictEqual(coord2.currentWorkerId, 'worker-coord-1');

        // 3. Worker 1 releases coordination back to IDLE
        await revocationRepository.releaseMembershipCoordination(
            org, team, accountId, 'worker-coord-1'
        );

        const afterRelease = await revocationRepository.getMembershipCoordination(org, team, accountId);
        assert.strictEqual(afterRelease.active_operation, 'IDLE');
        assert.strictEqual(afterRelease.worker_id, null);

        // 4. Now Worker 2 acquires coordination for PROVISIONING
        const coord3 = await revocationRepository.acquireMembershipCoordination(
            org, team, accountId, 'PROVISIONING', dummyJobId2, 'worker-coord-2', 60
        );
        assert.strictEqual(coord3.acquired, true);
        assert.strictEqual(coord3.active_operation, 'PROVISIONING');

        // Cleanup
        await revocationRepository.releaseMembershipCoordination(
            org, team, accountId, 'worker-coord-2'
        );
    });

    // =========================================================================
    // Test 5: Phase 3 Convergence: Concurrent Active Grant Restores Membership
    // =========================================================================
    it('5. Phase 3 convergence: new grant approved during Phase 2 DELETE triggers restoration in Phase 3', async () => {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const org = 'accesslease-governance';
        const team = `converge-team-${rand}`;
        const user = `user-converge-${rand}`;
        const accountId = String(rand);

        const key = revocationRepository.getMembershipLockKey(org, team, accountId);
        cleanupCoordinationKeys.push(key);

        const eng1 = await createEngagement();
        const eng2 = await createEngagement();

        // Expired grant1 that will be revoked
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

        let restoredMembershipCalled = false;
        githubTeamService.addOrUpdateTeamMembership = async (o, t, u, role) => {
            restoredMembershipCalled = true;
            return { state: 'active', role };
        };

        // When removeTeamMembership is called during Phase 2, concurrently simulate a newly approved active grant2!
        let removeCount = 0;
        githubTeamService.removeTeamMembership = async () => {
            removeCount++;
            // Concurrently create an active non-expired grant2 for same membership!
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

        // Membership returns active initially, absent after delete, active again once restored
        githubTeamService.getTeamMembership = async () => {
            if (restoredMembershipCalled) return { state: 'active', role: 'member' };
            return removeCount > 0 ? null : { state: 'active', role: 'member' };
        };

        // Execute revocation job for grant1
        const res = await revocationWorker.executeRevocationJob(job1, { workerId: 'worker-converge-test' });

        assert.strictEqual(res.success, true);
        assert.strictEqual(res.restoredForConcurrentGrant, true, 'Revocation must detect concurrent active grant and trigger restoration');
        assert.strictEqual(restoredMembershipCalled, true, 'GitHub addOrUpdateTeamMembership must be called to restore access for active grant');

        // Grant 1 is marked REVOKED
        const g1 = await grantRepository.findGrantById(grant1.grant_id);
        assert.strictEqual(g1.status, 'REVOKED');
        assert.strictEqual(g1.revocation_reason, 'CONCURRENT_GRANT_RESTORED');

        // Audit event CONCURRENT_GRANT_RESTORED_DURING_REVOCATION is recorded
        const auditEvents = await pool.request()
            .input('grantId', grant1.grant_id)
            .query(`
                SELECT event_action FROM dbo.audit_events
                WHERE entity_id = @grantId AND event_action = 'CONCURRENT_GRANT_RESTORED_DURING_REVOCATION';
            `);
        assert.strictEqual(auditEvents.recordset.length, 1);
    });

    // =========================================================================
    // Test 6: Crash Recovery Between GitHub DELETE and DB Reconciliation
    // =========================================================================
    it('6. Worker crash between GitHub DELETE and DB reconciliation recovered safely by next worker', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        await createProviderAuditEvent(grant.grant_id);

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Simulate crash: GitHub DELETE succeeded at provider, so membership is ALREADY absent
        githubTeamService.getTeamMembership = async () => null; // 404 absent

        let removeCalled = false;
        githubTeamService.removeTeamMembership = async () => {
            removeCalled = true;
            return { success: true, removed: true, status: 204 };
        };

        // Next worker executes the job
        const res = await revocationWorker.executeRevocationJob(job, { workerId: 'worker-crash-recovery' });

        assert.strictEqual(res.success, true);
        assert.strictEqual(res.alreadyAbsent, true, 'Job must identify membership already absent from previous crashed run');
        assert.strictEqual(removeCalled, false, 'Should not attempt DELETE when membership is already absent');

        const g = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(g.status, 'REVOKED');
        assert.strictEqual(g.revocation_reason, 'ALREADY_ABSENT_AT_PROVIDER');

        const dbJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(dbJob.status, 'REVOKED');
    });

    // =========================================================================
    // Test 7: Manual Review Resolution Evidence
    // =========================================================================
    it('7. Manual review resolution: CONFIRMED_REVOKED records MANUAL_ATTESTATION with evidence; DISMISSED does not mark grant REVOKED', async () => {
        const eng = await createEngagement();
        const grant1 = await createGrant(eng.engagement_id, { status: 'MANUAL_REVIEW_REQUIRED' });
        const grant2 = await createGrant(eng.engagement_id, { status: 'MANUAL_REVIEW_REQUIRED' });

        const job1 = await revocationRepository.createRevocationJob({
            grantId: grant1.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION',
            status: 'MANUAL_REVIEW_REQUIRED'
        });
        const job2 = await revocationRepository.createRevocationJob({
            grantId: grant2.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION',
            status: 'MANUAL_REVIEW_REQUIRED'
        });

        // 1. Resolve job1 as CONFIRMED_REVOKED with full evidence structure
        const resolution1 = await revocationService.resolveManualReview(
            job1.job_id,
            adminUser,
            'CONFIRMED_REVOKED',
            {
                justification: 'Independently confirmed member removal in GitHub organization audit log export',
                confirmationSource: 'GITHUB_ORGANIZATION_AUDIT_LOG',
                evidenceReference: 'AUDIT_LOG_EXPORT_BATCH_44219'
            }
        );

        assert.strictEqual(resolution1.status, 'REVOKED');

        const dbJob1 = await revocationRepository.findRevocationJobById(job1.job_id);
        assert.strictEqual(dbJob1.status, 'REVOKED');
        assert.ok(dbJob1.connector_response, 'connector_response must be populated with attestation');
        const parsedAttestation = typeof dbJob1.connector_response === 'string'
            ? JSON.parse(dbJob1.connector_response)
            : dbJob1.connector_response;
        assert.strictEqual(parsedAttestation.confirmationType, 'MANUAL_ATTESTATION');
        assert.strictEqual(parsedAttestation.confirmationSource, 'GITHUB_ORGANIZATION_AUDIT_LOG');
        assert.strictEqual(parsedAttestation.evidenceReference, 'AUDIT_LOG_EXPORT_BATCH_44219');
        assert.strictEqual(parsedAttestation.confirmedByUserId, adminUser.user_id);

        const updatedGrant1 = await grantRepository.findGrantById(grant1.grant_id);
        assert.strictEqual(updatedGrant1.status, 'REVOKED');
        assert.ok(updatedGrant1.revocation_reason.includes('Manually confirmed (MANUAL_ATTESTATION)'));

        // 2. Resolve job2 as DISMISSED
        const resolution2 = await revocationService.resolveManualReview(
            job2.job_id,
            adminUser,
            'DISMISSED',
            'Dismissed manual review exception without revoking access'
        );

        assert.strictEqual(resolution2.status, 'PERMANENT_FAILURE');

        // Grant 2 must NOT be marked REVOKED
        const updatedGrant2 = await grantRepository.findGrantById(grant2.grant_id);
        assert.strictEqual(updatedGrant2.status, 'MANUAL_REVIEW_REQUIRED', 'DISMISSED decision must NEVER mark grant as REVOKED');
    });
});
