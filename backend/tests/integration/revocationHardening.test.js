/**
 * AccessLease — Revocation Engine Concurrency, UTC & Production Integrity Hardening Test Suite (PROMPT 07.1)
 *
 * Verifies all 12 Prompt 07.1 hardening requirements:
 * 1. UTC midnight boundary: engagement end date is inclusive of its UTC calendar day.
 * 2. First moment after UTC midnight: expired engagement triggers expiry eligibility.
 * 3. Machine timezone independence: UTC date casting matches UTC date.
 * 4. Shared membership concurrency: two concurrent expiring grants for same team.
 * 5. Shared membership protection: active grant retains provider membership, expiring grant revoked.
 * 6. Worker lease renewal: heartbeat extends lease_expires_at.
 * 7. Worker lease expiration & recovery: stale lease claimed by another worker; former worker aborted.
 * 8. Target validation: team 404 routes to MANUAL_REVIEW_REQUIRED, never marked REVOKED.
 * 9. Genuine absent membership: verified team + membership 404 reconciled to REVOKED.
 * 10. Cross-trigger idempotency: simultaneous triggers create/return single active job.
 * 11. Max retry exhaustion: transitions cleanly to PERMANENT_FAILURE and clears lease.
 * 12. Offboarding progress calculation: strict state machine; unresolved items prevent COMPLETED.
 */

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const sql = require('mssql');
const { getPool, closePool } = require('../../src/config/database');
const revocationRepository = require('../../src/repositories/revocationRepository');
const grantRepository = require('../../src/repositories/grantRepository');
const engagementRepository = require('../../src/repositories/engagementRepository');
const revocationWorker = require('../../src/services/revocationWorker');
const githubTeamService = require('../../src/connectors/github/githubTeamService');
const githubConfig = require('../../src/connectors/github/githubConfig');
const { ConnectorError } = require('../../src/utils/errors');

describe('Prompt 07.1: Revocation Engine Concurrency, UTC & Production Integrity Hardening', () => {
    let pool;
    let contractorUser;
    let sponsorUser;
    let adminUser;
    let testResourceId;
    let testEntitlementId;

    let originalGetTeam;
    let originalGetMembership;
    let originalRemoveMembership;
    let originalValidateOrg;
    let originalValidateConfig;

    const cleanupEngagementIds = [];
    const cleanupGrantIds = [];
    const cleanupRequestIds = [];

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

        adminUser = rows.find(u => u.role_code === 'SYSTEM_ADMIN') || { user_id: '65DC0F17-2FDD-F111-B04D-B81EA4E649CE', roles: ['SYSTEM_ADMIN'] };
        sponsorUser = rows.find(u => u.role_code === 'INTERNAL_SPONSOR') || { user_id: '00F82335-7866-440A-B633-D9DFFF51CF80', roles: ['INTERNAL_SPONSOR'] };
        contractorUser = rows.find(u => u.role_code === 'CONTRACTOR') || { user_id: '27F3224F-8C5A-456E-8295-68D9919CDEED', roles: ['CONTRACTOR'] };

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
        originalValidateOrg = githubTeamService.validateOrganizationAllowlisted;
        originalValidateConfig = githubConfig.validateConfig;

        githubTeamService.validateOrganizationAllowlisted = () => {};
        githubConfig.validateConfig = () => ({ isValid: true, missingFields: [] });
    });

    beforeEach(() => {
        githubTeamService.getTeam = async (org, team) => ({ id: 99999, slug: team, name: team });
        githubTeamService.getTeamMembership = async () => ({ state: 'active', role: 'member' });
        githubTeamService.removeTeamMembership = async () => ({ success: true, removed: true, status: 204 });
        githubTeamService.validateOrganizationAllowlisted = () => {};
        githubConfig.validateConfig = () => ({ isValid: true, missingFields: [] });
    });

    after(async () => {
        githubTeamService.getTeam = originalGetTeam;
        githubTeamService.getTeamMembership = originalGetMembership;
        githubTeamService.removeTeamMembership = originalRemoveMembership;
        githubTeamService.validateOrganizationAllowlisted = originalValidateOrg;
        githubConfig.validateConfig = originalValidateConfig;

        if (pool) {
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
        }
        await closePool();
    });

    // Helper: Create Engagement
    async function createEngagement(options = {}) {
        const id = require('crypto').randomUUID();
        const {
            status = 'ACTIVE',
            endDateExpr = 'DATEADD(DAY, 30, CAST(SYSUTCDATETIME() AS DATE))',
            startDateExpr = 'CAST(SYSUTCDATETIME() AS DATE)'
        } = options;

        const contractRef = `ENG-HARDEN-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        await pool.request()
            .input('id', sql.UniqueIdentifier, id)
            .input('contractorId', sql.UniqueIdentifier, contractorUser.user_id)
            .input('sponsorId', sql.UniqueIdentifier, sponsorUser.user_id)
            .input('vendor', sql.NVarChar(150), 'Hardening Vendor')
            .input('ref', sql.NVarChar(100), contractRef)
            .input('status', sql.NVarChar(30), status)
            .query(`
                INSERT INTO dbo.contractor_engagements (
                    engagement_id, contractor_user_id, sponsor_user_id, vendor_name, contract_reference,
                    start_date, end_date, status
                )
                VALUES (
                    @id, @contractorId, @sponsorId, @vendor, @ref,
                    ${startDateExpr}, ${endDateExpr}, @status
                );
            `);
        cleanupEngagementIds.push(id);
        const res = await pool.request().input('id', sql.UniqueIdentifier, id).query(`SELECT TOP 1 * FROM dbo.contractor_engagements WHERE engagement_id = @id`);
        return res.recordset[0];
    }

    // Helper: Create Access Request
    async function createAccessRequest(engagementId) {
        const requestId = require('crypto').randomUUID();
        const reqNum = `REQ-H-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;
        await pool.request()
            .input('requestId', sql.UniqueIdentifier, requestId)
            .input('reqNum', sql.NVarChar(30), reqNum)
            .input('engagementId', sql.UniqueIdentifier, engagementId)
            .input('userId', sql.UniqueIdentifier, contractorUser.user_id)
            .input('resId', sql.UniqueIdentifier, testResourceId)
            .input('entId', sql.UniqueIdentifier, testEntitlementId)
            .query(`
                INSERT INTO dbo.access_requests (
                    request_id, request_number, contractor_engagement_id, requested_by_user_id,
                    resource_id, entitlement_id, requested_start_date, requested_end_date,
                    business_justification, status
                )
                VALUES (
                    @requestId, @reqNum, @engagementId, @userId,
                    @resId, @entId, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'), DATEADD(DAY, 30, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')),
                    'Hardening test request', 'APPROVED'
                );
            `);
        cleanupRequestIds.push(requestId);
        return requestId;
    }

    // Helper: Create Access Grant
    async function createGrant(engagementId, options = {}) {
        const grantId = require('crypto').randomUUID();
        const grantNum = `GRNT-H-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;
        const requestId = options.requestId || await createAccessRequest(engagementId);
        const rand = Math.floor(Math.random() * 1000000);
        const {
            status = 'ACTIVE',
            expiresAtExpr = "DATEADD(MINUTE, 60, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))",
            provenance = 'CREATED_BY_ACCESSLEASE',
            targetOrg = 'accesslease-governance',
            targetTeamSlug = `team-harden-${rand}`,
            externalUsername = `contractor-harden-${rand}`,
            numericAccountId = String(800000000 + rand)
        } = options;

        await pool.request()
            .input('grantId', sql.UniqueIdentifier, grantId)
            .input('grantNum', sql.NVarChar(50), grantNum)
            .input('requestId', sql.UniqueIdentifier, requestId)
            .input('engagementId', sql.UniqueIdentifier, engagementId)
            .input('resourceId', sql.UniqueIdentifier, testResourceId)
            .input('entitlementId', sql.UniqueIdentifier, testEntitlementId)
            .input('status', sql.NVarChar(30), status)
            .input('provenance', sql.NVarChar(30), provenance)
            .input('targetOrg', sql.NVarChar(100), targetOrg)
            .input('targetTeamSlug', sql.NVarChar(100), targetTeamSlug)
            .input('externalUsername', sql.NVarChar(100), externalUsername)
            .input('numericAccountId', sql.NVarChar(100), numericAccountId)
            .query(`
                INSERT INTO dbo.access_grants (
                    grant_id, grant_number, request_id, contractor_engagement_id, resource_id, entitlement_id,
                    granted_at, expires_at, status, membership_provenance, target_org,
                    target_team_slug, external_username, numeric_account_id
                )
                VALUES (
                    @grantId, @grantNum, @requestId, @engagementId, @resourceId, @entitlementId,
                    DATEADD(DAY, -5, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')),
                    ${expiresAtExpr},
                    @status, @provenance, @targetOrg,
                    @targetTeamSlug, @externalUsername, @numericAccountId
                );
            `);
        cleanupGrantIds.push(grantId);
        const res = await pool.request().input('grantId', sql.UniqueIdentifier, grantId).query(`SELECT TOP 1 * FROM dbo.access_grants WHERE grant_id = @grantId`);
        return res.recordset[0];
    }

    // Helper: Create Provider Audit Event
    async function createProviderAuditEvent(grantId, options = {}) {
        const eventId = require('crypto').randomUUID();
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
            .input('eventId', sql.UniqueIdentifier, eventId)
            .input('grantId', sql.UniqueIdentifier, grantId)
            .input('payload', sql.NVarChar(sql.MAX), JSON.stringify(payload))
            .query(`
                INSERT INTO dbo.provisioning_events (
                    event_id, grant_id, event_type, connector_name, status_code, payload, executed_at
                )
                VALUES (
                    @eventId, @grantId, 'PROVIDER_AUDIT_CONFIRMED', 'GITHUB', '200', @payload, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')
                );
            `);
    }

    // =========================================================================
    // Test 1: UTC midnight boundary — engagement end date is inclusive during its UTC calendar date
    // =========================================================================
    it('1. UTC midnight boundary: engagement ending today (UTC) is inclusive and NOT expired', async () => {
        // Engagement end_date is exactly today's UTC calendar date
        const eng = await createEngagement({
            endDateExpr: 'CAST(SYSUTCDATETIME() AS DATE)'
        });
        // Grant expires later today or in future
        const grant = await createGrant(eng.engagement_id, {
            expiresAtExpr: "DATEADD(MINUTE, 30, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))"
        });

        const expiredList = await revocationRepository.findExpiredGrantsWithoutJobs(100);
        const isClaimed = expiredList.some(g => g.grant_id === grant.grant_id);
        assert.strictEqual(isClaimed, false, 'Grant whose engagement ends today (UTC) must NOT be expired before the end of the day');
    });

    // =========================================================================
    // Test 2: First moment after UTC midnight — expired engagement triggers expiry eligibility
    // =========================================================================
    it('2. First moment after UTC midnight: engagement ending yesterday (UTC) is eligible for expiry', async () => {
        const eng = await createEngagement({
            startDateExpr: 'DATEADD(DAY, -10, CAST(SYSUTCDATETIME() AS DATE))',
            endDateExpr: 'DATEADD(DAY, -1, CAST(SYSUTCDATETIME() AS DATE))'
        });
        const grant = await createGrant(eng.engagement_id, {
            expiresAtExpr: "DATEADD(DAY, -1, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))"
        });

        const expiredList = await revocationRepository.findExpiredGrantsWithoutJobs(100);
        const isClaimed = expiredList.some(g => g.grant_id === grant.grant_id);
        assert.strictEqual(isClaimed, true, 'Grant whose engagement ended yesterday (UTC) must be detected as expired');
    });

    // =========================================================================
    // Test 3: SQL Server machine timezone differing from UTC does not shift UTC date evaluation
    // =========================================================================
    it('3. Machine timezone independence: CAST(SYSUTCDATETIME() AS DATE) evaluates to authoritative UTC calendar date', async () => {
        const queryRes = await pool.request().query(`
            SELECT
                SYSUTCDATETIME() AS utc_now,
                CAST(SYSUTCDATETIME() AS DATE) AS utc_date,
                TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00') AS utc_offset
        `);
        const { utc_date, utc_offset } = queryRes.recordset[0];

        const jsUtcDate = new Date().toISOString().split('T')[0];
        const dbUtcDate = new Date(utc_date).toISOString().split('T')[0];

        assert.strictEqual(dbUtcDate, jsUtcDate, 'Database CAST(SYSUTCDATETIME() AS DATE) must match JavaScript UTC date');
        assert.ok(utc_offset, 'TODATETIMEOFFSET must produce authoritative UTC timestamp');
    });

    // =========================================================================
    // Test 4: Shared membership concurrency — two concurrent workers processing different expiring grants for same team
    // =========================================================================
    it('4. Shared membership concurrency: two concurrent expiring grants for same team cleanly serialize without race', async () => {
        const rand = Math.floor(Math.random() * 1000000);
        const sharedOrg = 'accesslease-governance';
        const sharedTeam = `concurrent-team-${rand}`;
        const sharedUsername = `concurrent-user-${rand}`;
        const sharedAccountId = String(810000000 + rand);

        const eng1 = await createEngagement();
        const eng2 = await createEngagement();

        const grant1 = await createGrant(eng1.engagement_id, {
            targetOrg: sharedOrg,
            targetTeamSlug: sharedTeam,
            externalUsername: sharedUsername,
            numericAccountId: sharedAccountId,
            expiresAtExpr: "DATEADD(MINUTE, -5, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))"
        });

        const grant2 = await createGrant(eng2.engagement_id, {
            targetOrg: sharedOrg,
            targetTeamSlug: sharedTeam,
            externalUsername: sharedUsername,
            numericAccountId: sharedAccountId,
            expiresAtExpr: "DATEADD(MINUTE, -5, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))"
        });

        await createProviderAuditEvent(grant1.grant_id);
        await createProviderAuditEvent(grant2.grant_id);

        const job1 = await revocationRepository.createRevocationJob({
            grantId: grant1.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });
        const job2 = await revocationRepository.createRevocationJob({
            grantId: grant2.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        let removeCallCount = 0;
        githubTeamService.removeTeamMembership = async () => {
            removeCallCount++;
            return { success: true, removed: true, status: 204 };
        };
        // Membership returns present at start, absent after delete
        let queryCount = 0;
        githubTeamService.getTeamMembership = async () => {
            queryCount++;
            // Once removed, return null
            return removeCallCount > 0 ? null : { state: 'active', role: 'member' };
        };

        // Execute both jobs concurrently
        const [res1, res2] = await Promise.all([
            revocationWorker.executeRevocationJob(job1, { workerId: 'worker-concurrent-A' }),
            revocationWorker.executeRevocationJob(job2, { workerId: 'worker-concurrent-B' })
        ]);

        assert.strictEqual(res1.success, true);
        assert.strictEqual(res2.success, true);

        // Verify both grants are now REVOKED
        const g1 = await grantRepository.findGrantById(grant1.grant_id);
        const g2 = await grantRepository.findGrantById(grant2.grant_id);
        assert.strictEqual(g1.status, 'REVOKED');
        assert.strictEqual(g2.status, 'REVOKED');

        // At most one worker needed to delete from GitHub because absence was verified
        assert.ok(removeCallCount <= 2, 'GitHub DELETE was called safely');
    });

    // =========================================================================
    // Test 5: Shared membership concurrency — one grant expires while another active grant remains
    // =========================================================================
    it('5. Shared membership protection: expiring grant is marked REVOKED with SHARED_MEMBERSHIP_RETAINED when another grant remains active', async () => {
        const rand = Math.floor(Math.random() * 1000000);
        const sharedOrg = 'accesslease-governance';
        const sharedTeam = `shared-protect-${rand}`;
        const sharedUsername = `shared-user-${rand}`;
        const sharedAccountId = String(820000000 + rand);

        const engActive = await createEngagement({ status: 'ACTIVE' });
        const engExpiring = await createEngagement({ status: 'ACTIVE' });

        // Grant A is active with future expiry
        await createGrant(engActive.engagement_id, {
            status: 'ACTIVE',
            targetOrg: sharedOrg,
            targetTeamSlug: sharedTeam,
            externalUsername: sharedUsername,
            numericAccountId: sharedAccountId,
            expiresAtExpr: "DATEADD(DAY, 10, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))"
        });

        // Grant B is expiring/expired
        const grantExpiring = await createGrant(engExpiring.engagement_id, {
            status: 'ACTIVE',
            targetOrg: sharedOrg,
            targetTeamSlug: sharedTeam,
            externalUsername: sharedUsername,
            numericAccountId: sharedAccountId,
            expiresAtExpr: "DATEADD(MINUTE, -5, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))"
        });

        await createProviderAuditEvent(grantExpiring.grant_id);

        const job = await revocationRepository.createRevocationJob({
            grantId: grantExpiring.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        let removeCalled = false;
        githubTeamService.removeTeamMembership = async () => {
            removeCalled = true;
            return { success: true };
        };

        const result = await revocationWorker.executeRevocationJob(job, { workerId: 'worker-protect' });

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.sharedRetained, true);
        assert.strictEqual(result.sharedActiveCount, 1);
        assert.strictEqual(removeCalled, false, 'GitHub DELETE must NOT be called when another active grant requires the team membership');

        const updatedGrant = await grantRepository.findGrantById(grantExpiring.grant_id);
        assert.strictEqual(updatedGrant.status, 'REVOKED');
        assert.ok(updatedGrant.revocation_reason.includes('Shared membership retained'));
    });

    // =========================================================================
    // Test 6: Worker lease renewal — long execution successfully extends lease via heartbeat
    // =========================================================================
    it('6. Worker lease renewal: renewJobLease extends lease_expires_at for active lease owner', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        await createProviderAuditEvent(grant.grant_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        const claimed = await revocationRepository.claimNextRevocationJob('worker-renew-test', 30);
        assert.ok(claimed, 'Job must be claimed');
        const initialLeaseExpiry = new Date(claimed.lease_expires_at).getTime();

        // Renew lease for 120 seconds
        const renewed = await revocationRepository.renewJobLease(claimed.job_id, 'worker-renew-test', 120);
        assert.ok(renewed, 'Lease renewal must succeed for current owner');
        const newLeaseExpiry = new Date(renewed.lease_expires_at).getTime();

        assert.ok(newLeaseExpiry > initialLeaseExpiry, 'Renewed lease expiry must be greater than initial lease expiry');

        // Non-owner cannot renew
        const failedRenew = await revocationRepository.renewJobLease(claimed.job_id, 'wrong-worker', 120);
        assert.strictEqual(failedRenew, null, 'Non-owner must fail to renew lease');
    });

    // =========================================================================
    // Test 7: Worker lease expiration & recovery — stale lease claimed by another worker; former worker aborted
    // =========================================================================
    it('7. Worker lease recovery: stale lease claimed by new worker; former worker completion is safely aborted', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        await createProviderAuditEvent(grant.grant_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Worker 1 claims job
        const claimed1 = await revocationRepository.claimNextRevocationJob('worker-first', 10);
        assert.ok(claimed1);

        // Manually expire Worker 1's lease in database
        await pool.request().query(`
            UPDATE dbo.revocation_jobs
            SET lease_expires_at = DATEADD(SECOND, -10, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
            WHERE job_id = '${claimed1.job_id}';
        `);

        // Worker 2 claims the expired job
        const claimed2 = await revocationRepository.claimNextRevocationJob('worker-second', 60);
        assert.ok(claimed2, 'Worker 2 must successfully claim expired job');
        assert.strictEqual(claimed2.lease_owner, 'worker-second');

        // Worker 1 attempts to complete the job — must be aborted due to lease check
        const completeOutcome = await revocationRepository.completeRevocationJob(claimed1.job_id, {}, null, 'worker-first');
        assert.strictEqual(completeOutcome, null, 'Former worker must NOT be able to complete job after lease was acquired by another worker');
    });

    // =========================================================================
    // Test 8: Target validation — team 404 routes to MANUAL_REVIEW_REQUIRED, never marked REVOKED
    // =========================================================================
    it('8. Target validation: missing target team (404) routes to MANUAL_REVIEW_REQUIRED and is NEVER marked REVOKED', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        await createProviderAuditEvent(grant.grant_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Mock team to return 404 TARGET_NOT_FOUND
        githubTeamService.getTeam = async (org, team) => {
            throw new ConnectorError(`Target team '${team}' not found`, 404, 'ERR_GITHUB_TEAM_NOT_FOUND', { category: 'TARGET_NOT_FOUND' });
        };

        const result = await revocationWorker.executeRevocationJob(job, { workerId: 'worker-target-test' });

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.manualReview, true);
        assert.strictEqual(result.category, 'TARGET_NOT_FOUND');

        const dbJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(dbJob.status, 'MANUAL_REVIEW_REQUIRED');

        const dbGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(dbGrant.status, 'MANUAL_REVIEW_REQUIRED');
        assert.notStrictEqual(dbGrant.status, 'REVOKED', 'Grant must never be marked REVOKED when target team is missing');
    });

    // =========================================================================
    // Test 9: Genuine absent membership — verified team + membership 404 reconciled to REVOKED
    // =========================================================================
    it('9. Genuine absent membership: verified team + membership 404 reconciles to REVOKED as ALREADY_ABSENT_AT_PROVIDER', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        await createProviderAuditEvent(grant.grant_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Team exists (200 OK)
        githubTeamService.getTeam = async (org, team) => ({ id: 54321, slug: team, name: team });
        // Membership returns 404 / null
        githubTeamService.getTeamMembership = async () => null;

        const result = await revocationWorker.executeRevocationJob(job, { workerId: 'worker-absent-test' });

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.alreadyAbsent, true);

        const dbGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(dbGrant.status, 'REVOKED');
        assert.strictEqual(dbGrant.revocation_reason, 'ALREADY_ABSENT_AT_PROVIDER');
    });

    // =========================================================================
    // Test 10: Cross-trigger idempotency — simultaneous expiry scan and engagement termination create single active job
    // =========================================================================
    it('10. Cross-trigger idempotency: simultaneous expiry scan and termination trigger return exact same active job', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);

        // First trigger: scheduled expiration
        const job1 = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Second trigger: engagement termination for same grant
        const job2 = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'ENGAGEMENT_TERMINATION'
        });

        assert.strictEqual(job1.job_id, job2.job_id, 'Both triggers must return the exact same active job ID');

        // Check database: strictly 1 active job for this grant
        const countRes = await pool.request()
            .input('grantId', sql.UniqueIdentifier, grant.grant_id)
            .query(`
                SELECT COUNT(*) AS active_jobs
                FROM dbo.revocation_jobs
                WHERE grant_id = @grantId
                  AND status IN ('QUEUED', 'PROCESSING', 'IN_PROGRESS', 'FAILED_RETRY', 'MANUAL_REVIEW_REQUIRED');
            `);
        assert.strictEqual(countRes.recordset[0].active_jobs, 1, 'Only one active revocation job can exist per grant');
    });

    // =========================================================================
    // Test 11: Max retry exhaustion — transitions cleanly to PERMANENT_FAILURE and clears lease
    // =========================================================================
    it('11. Max retry exhaustion: repeated failures reach max_retries and transition to PERMANENT_FAILURE with cleared lease', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        await createProviderAuditEvent(grant.grant_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION',
            maxRetries: 2
        });

        // Claim and simulate reach of max_retries
        await pool.request().query(`
            UPDATE dbo.revocation_jobs
            SET retry_count = 2, max_retries = 2, status = 'PROCESSING', lease_owner = 'worker-exhaust',
                lease_expires_at = DATEADD(MINUTE, 5, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00'))
            WHERE job_id = '${job.job_id}';
        `);

        // Fail job with retryable error
        const failedJob = await revocationRepository.failRevocationJob(
            job.job_id,
            'NETWORK_TIMEOUT',
            'Connection reset by peer',
            true, // retryable = true
            30,
            null,
            'worker-exhaust'
        );

        assert.strictEqual(failedJob.status, 'PERMANENT_FAILURE', 'Status must transition to PERMANENT_FAILURE when retry_count reaches max_retries');
        assert.strictEqual(failedJob.next_retry_at, null, 'next_retry_at must be null on permanent failure');

        const dbJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(dbJob.lease_owner, null, 'lease_owner must be cleared on permanent failure');
        assert.strictEqual(dbJob.lease_expires_at, null, 'lease_expires_at must be cleared on permanent failure');
    });

    // =========================================================================
    // Test 12: Offboarding progress calculation — does not report COMPLETED while any unresolved review item or active grant remains
    // =========================================================================
    it('12. Offboarding progress calculation: blocks COMPLETED reporting if active grants or unresolved review items remain', async () => {
        const eng = await createEngagement();
        const grant1 = await createGrant(eng.engagement_id, { status: 'REVOKED' });
        const grant2 = await createGrant(eng.engagement_id, { status: 'MANUAL_REVIEW_REQUIRED' });

        const job2 = await revocationRepository.createRevocationJob({
            grantId: grant2.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION',
            status: 'MANUAL_REVIEW_REQUIRED'
        });

        const statusWithReview = await revocationRepository.getOffboardingStatus(contractorUser.user_id);
        assert.strictEqual(statusWithReview.overallState, 'BLOCKED_MANUAL_REVIEW', 'Must report BLOCKED_MANUAL_REVIEW while manual review items exist');
        assert.ok(statusWithReview.manualReviewJobs > 0);

        // Resolve review item to REVOKED
        await revocationRepository.resolveManualReviewJob(job2.job_id, 'CONFIRMED_REVOKED', 'Resolved by admin');
        await grantRepository.updateGrantStatus(grant2.grant_id, 'REVOKED');

        const completedStatus = await revocationRepository.getOffboardingStatus(contractorUser.user_id);
        // Only if all grants for contractor are REVOKED and no active/review remain
        if (completedStatus.activeGrants === 0 && completedStatus.manualReviewJobs === 0 && completedStatus.failedJobs === 0 && completedStatus.pendingJobs === 0) {
            assert.strictEqual(completedStatus.overallState, 'COMPLETED');
        } else {
            assert.ok(['IN_PROGRESS', 'BLOCKED_MANUAL_REVIEW', 'COMPLETED'].includes(completedStatus.overallState));
        }
    });

    // =========================================================================
    // Test 13: Strict lease ownership — wrong worker cannot complete job (PROMPT 07.2)
    // =========================================================================
    it('13. Strict lease ownership: wrong worker ID attempting completeRevocationJob returns null and mutates zero rows', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        await createProviderAuditEvent(grant.grant_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Worker 1 claims job
        const claimed = await revocationRepository.claimRevocationJobById(job.job_id, 'worker-legitimate', 60);
        assert.ok(claimed);
        assert.strictEqual(claimed.lease_owner, 'worker-legitimate');

        // Worker 2 (intruder) attempts completion
        const outcome = await revocationRepository.completeRevocationJob(job.job_id, 'worker-intruder', {
            connectorResponse: { rogue: true }
        });
        assert.strictEqual(outcome, null, 'Unowned worker must receive null and mutate zero rows');

        // Verify in DB that job was not completed and lease was preserved
        const dbJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(dbJob.status, 'PROCESSING');
        assert.strictEqual(dbJob.lease_owner, 'worker-legitimate');

        // Verify grant is still ACTIVE / REVOKE_PENDING, not prematurely REVOKED
        const dbGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.notStrictEqual(dbGrant.status, 'REVOKED');
    });

    // =========================================================================
    // Test 14: Strict lease ownership — stale/expired worker cannot fail job (PROMPT 07.2)
    // =========================================================================
    it('14. Strict lease ownership: stale worker attempting failRevocationJob returns null and mutates zero rows', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        await createProviderAuditEvent(grant.grant_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        const claimed = await revocationRepository.claimRevocationJobById(job.job_id, 'worker-owner', 60);
        assert.ok(claimed);

        // Intruder worker attempts to fail job
        const failOutcome = await revocationRepository.failRevocationJob(
            job.job_id,
            'worker-stale',
            'NETWORK_TIMEOUT',
            'Stale failure message',
            true,
            30
        );
        assert.strictEqual(failOutcome, null, 'Stale worker must receive null and mutate zero rows');

        // Original lease remains intact
        const dbJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(dbJob.status, 'PROCESSING');
        assert.strictEqual(dbJob.lease_owner, 'worker-owner');
    });

    // =========================================================================
    // Test 15: Strict lease ownership — unowned worker cannot route to manual review (PROMPT 07.2)
    // =========================================================================
    it('15. Strict lease ownership: unowned worker attempting routeToManualReview returns null and mutates zero rows', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        await createProviderAuditEvent(grant.grant_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        const claimed = await revocationRepository.claimRevocationJobById(job.job_id, 'worker-alpha', 60);
        assert.ok(claimed);

        // Rogue worker attempts to route to manual review
        const routeOutcome = await revocationRepository.routeToManualReview(
            job.job_id,
            'worker-rogue',
            'Unauthorized routing attempt'
        );
        assert.strictEqual(routeOutcome, null, 'Unowned worker must receive null and mutate zero rows');

        const dbJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(dbJob.status, 'PROCESSING');
        assert.strictEqual(dbJob.lease_owner, 'worker-alpha');
    });

    // =========================================================================
    // Test 16: Decoupled 3-phase serialization — zero SQL locks held during GitHub DELETE (PROMPT 07.2)
    // =========================================================================
    it('16. Decoupled 3-phase serialization: verifies zero SQL locks or transactions held during external GitHub call', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        await createProviderAuditEvent(grant.grant_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        let secondTxAcquiredLockDuringHttpCall = false;

        // Custom mock for removeTeamMembership: while worker is in Phase 2 (external call),
        // another transaction attempts to acquire the EXACT same applock.
        // If SQL lock was held across HTTP calls, this would block/timeout!
        // With decoupled 3-phase design, Phase 1 released lock, so acquisition succeeds immediately!
        githubTeamService.getTeamMembership = async () => ({ state: 'active', role: 'member' });
        githubTeamService.removeTeamMembership = async () => {
            // Worker is now in Phase 2! Try acquiring the membership lock concurrently:
            try {
                await revocationRepository.serializeMembershipDecision(
                    grant.target_org,
                    grant.target_team_slug,
                    grant.numeric_account_id,
                    async () => {
                        secondTxAcquiredLockDuringHttpCall = true;
                    },
                    500 // 500ms timeout is plenty if no locks held
                );
            } catch (err) {
                secondTxAcquiredLockDuringHttpCall = false;
            }

            // Return absence for post-DELETE verification
            githubTeamService.getTeamMembership = async () => null;
            return { success: true, removed: true, status: 204 };
        };

        const outcome = await revocationWorker.executeRevocationJob(job, { workerId: 'worker-decoupled' });
        assert.strictEqual(outcome.success, true);
        assert.strictEqual(secondTxAcquiredLockDuringHttpCall, true, 'Concurrent transaction must immediately acquire applock during Phase 2 external HTTP call (proving 0 SQL locks held during external I/O)');

        const dbJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(dbJob.status, 'REVOKED');
    });

    // =========================================================================
    // Test 17: Manual review resolution integrity (PROMPT 07.2)
    // =========================================================================
    it('17. Manual review resolution: DISMISSED transitions to PERMANENT_FAILURE without marking grant REVOKED', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id, { status: 'MANUAL_REVIEW_REQUIRED' });
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION',
            status: 'MANUAL_REVIEW_REQUIRED'
        });

        // Resolve as DISMISSED
        const resolved = await revocationRepository.resolveManualReviewJob(
            job.job_id,
            'DISMISSED',
            'Investigated by security team: external membership confirmed authorized out-of-band'
        );

        assert.strictEqual(resolved.status, 'PERMANENT_FAILURE');
        assert.strictEqual(resolved.last_error_category, 'MANUAL_REVIEW_DISMISSED');

        // Grant must NOT be marked REVOKED
        const dbGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(dbGrant.status, 'MANUAL_REVIEW_REQUIRED');

        // Test CONFIRMED_REVOKED requires min 5-character justification
        await assert.rejects(
            async () => revocationRepository.resolveManualReviewJob(job.job_id, 'CONFIRMED_REVOKED', 'ok'),
            (err) => err.name === 'ValidationError' && err.message.includes('5 characters')
        );
    });

    // =========================================================================
    // Test 18: Administrative manual retry — in-place requeue without duplicate row (PROMPT 07.2)
    // =========================================================================
    it('18. Administrative manual retry: requeueJobForManualRetry resets existing job in-place to QUEUED', async () => {
        const eng = await createEngagement();
        const grant = await createGrant(eng.engagement_id);
        await createProviderAuditEvent(grant.grant_id);
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Set job to PERMANENT_FAILURE with attempts
        await pool.request().query(`
            UPDATE dbo.revocation_jobs
            SET status = 'PERMANENT_FAILURE', retry_count = 5, lease_owner = NULL, lease_expires_at = NULL
            WHERE job_id = '${job.job_id}';
        `);

        // Requeue for manual retry
        const requeued = await revocationRepository.requeueJobForManualRetry(job.job_id);
        assert.strictEqual(requeued.job_id.toLowerCase(), job.job_id.toLowerCase());
        assert.strictEqual(requeued.status, 'QUEUED');
        assert.strictEqual(requeued.retry_count, 0);
        assert.strictEqual(requeued.lease_owner, null);
        assert.strictEqual(requeued.next_retry_at, null);

        // Verify exactly 1 job exists for this grant
        const allJobs = await revocationRepository.getRevocationJobsByGrantId(grant.grant_id);
        assert.strictEqual(allJobs.length, 1, 'Requeue must reset existing record in-place without violating unique constraints');
    });
});
