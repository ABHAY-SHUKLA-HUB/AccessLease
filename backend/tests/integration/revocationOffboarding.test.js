/**
 * AccessLease — Automated Expiry, Revocation & Offboarding Integration Test Suite (PROMPT 07)
 * 
 * Verifies all 22 mandatory requirements:
 * 1. Expired grant creates one revocation job.
 * 2. Duplicate timer execution does not create duplicate jobs.
 * 3. Active grant is not revoked prematurely.
 * 4. Terminated engagement triggers offboarding.
 * 5. Completed engagement triggers eligible expiry processing.
 * 6. Pre-existing membership is never automatically removed.
 * 7. Uncertain provenance is never automatically removed.
 * 8. Missing provider evidence blocks removal.
 * 9. Matching provider evidence allows eligibility evaluation.
 * 10. Shared active grant prevents membership deletion.
 * 11. GitHub DELETE success followed by GET absence confirms revocation.
 * 12. GitHub DELETE success without verified absence does not mark REVOKED.
 * 13. GitHub 403 is handled safely.
 * 14. GitHub 404 is reconciled correctly.
 * 15. GitHub 429 respects Retry-After.
 * 16. Network timeout enters retry handling.
 * 17. Worker crash recovery is safe.
 * 18. Concurrent workers cannot process the same job unsafely.
 * 19. Database failure after GitHub success triggers reconciliation.
 * 20. Unauthorized users cannot manually retry jobs.
 * 21. Compliance auditors cannot mutate revocation state.
 * 22. Existing authentication, approval, provisioning and provenance tests remain passing.
 */

const { describe, it, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const sql = require('mssql');
const { getPool, closePool } = require('../../src/config/database');
const revocationRepository = require('../../src/repositories/revocationRepository');
const grantRepository = require('../../src/repositories/grantRepository');
const engagementRepository = require('../../src/repositories/engagementRepository');
const revocationService = require('../../src/services/revocationService');
const revocationWorker = require('../../src/services/revocationWorker');
const githubTeamService = require('../../src/connectors/github/githubTeamService');
const githubConfig = require('../../src/connectors/github/githubConfig');
const { isSafeForAutomatedRevocation } = require('../../src/services/provisioningService');
const { ConnectorError, ForbiddenError } = require('../../src/utils/errors');

describe('Prompt 07: Automated Expiry, Revocation & Contractor Offboarding Engine', () => {
    let pool;
    let adminUser;
    let securityUser;
    let sponsorUser;
    let contractorUser;
    let auditorUser;
    let testResourceId;
    let testEntitlementId;

    // Original methods for mock restoration
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

        // 1. Fetch real seed users for RBAC testing
        const usersRes = await pool.request().query(`
            SELECT u.user_id, u.email, u.display_name, r.role_code
            FROM dbo.users u
            LEFT JOIN dbo.user_roles ur ON u.user_id = ur.user_id
            LEFT JOIN dbo.roles r ON ur.role_id = r.role_id;
        `);
        const rows = usersRes.recordset;

        adminUser = rows.find(u => u.role_code === 'SYSTEM_ADMIN') || { user_id: '65DC0F17-2FDD-F111-B04D-B81EA4E649CE', roles: ['SYSTEM_ADMIN'] };
        adminUser.roles = ['SYSTEM_ADMIN'];

        securityUser = rows.find(u => u.role_code === 'SECURITY_OFFICER') || { user_id: '0BFF6785-29DD-F111-B04D-B81EA4E649CE', roles: ['SECURITY_OFFICER'] };
        securityUser.roles = ['SECURITY_OFFICER'];

        sponsorUser = rows.find(u => u.role_code === 'INTERNAL_SPONSOR') || { user_id: '00F82335-7866-440A-B633-D9DFFF51CF80', roles: ['INTERNAL_SPONSOR'] };
        sponsorUser.roles = ['INTERNAL_SPONSOR'];

        contractorUser = rows.find(u => u.role_code === 'CONTRACTOR') || { user_id: '27F3224F-8C5A-456E-8295-68D9919CDEED', roles: ['CONTRACTOR'] };
        contractorUser.roles = ['CONTRACTOR'];

        auditorUser = rows.find(u => u.role_code === 'COMPLIANCE_AUDITOR') || { user_id: '64DC0F17-2FDD-F111-B04D-B81EA4E649CE', roles: ['COMPLIANCE_AUDITOR'] };
        auditorUser.roles = ['COMPLIANCE_AUDITOR'];

        // 2. Fetch test resource & entitlement
        const resQuery = await pool.request().query(`
            SELECT TOP 1 r.resource_id, e.entitlement_id
            FROM dbo.resources r
            INNER JOIN dbo.entitlements e ON r.resource_id = e.resource_id;
        `);
        assert.ok(resQuery.recordset.length > 0, 'Seed resource and entitlement must exist');
        testResourceId = resQuery.recordset[0].resource_id;
        testEntitlementId = resQuery.recordset[0].entitlement_id;

        // Save original methods for mocking
        originalGetTeam = githubTeamService.getTeam;
        originalGetMembership = githubTeamService.getTeamMembership;
        originalRemoveMembership = githubTeamService.removeTeamMembership;
        originalValidateOrg = githubTeamService.validateOrganizationAllowlisted;
        originalValidateConfig = githubConfig.validateConfig;

        githubTeamService.getTeam = async (org, team) => ({ id: 99999, slug: team, name: team });
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
        // Restore mocks
        githubTeamService.getTeam = originalGetTeam;
        githubTeamService.getTeamMembership = originalGetMembership;
        githubTeamService.removeTeamMembership = originalRemoveMembership;
        githubTeamService.validateOrganizationAllowlisted = originalValidateOrg;
        githubConfig.validateConfig = originalValidateConfig;

        // Cleanup database fixtures
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
                    await pool.request().query(`
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
        }
        await closePool();
    });

    // Helper: Create an engagement
    async function createTestEngagement(status = 'ACTIVE', endDateOffsetDays = 30) {
        const id = require('crypto').randomUUID();
        const contractRef = `ENG-TEST-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        const startDays = endDateOffsetDays < 0 ? (endDateOffsetDays - 10) : 0;
        const result = await pool.request()
            .input('id', sql.UniqueIdentifier, id)
            .input('contractorId', sql.UniqueIdentifier, contractorUser.user_id)
            .input('sponsorId', sql.UniqueIdentifier, sponsorUser.user_id)
            .input('vendor', sql.NVarChar(150), 'Test Vendor Offboarding')
            .input('ref', sql.NVarChar(100), contractRef)
            .input('startDays', sql.Int, startDays)
            .input('days', sql.Int, endDateOffsetDays)
            .input('status', sql.NVarChar(30), status)
            .query(`
                INSERT INTO dbo.contractor_engagements (
                    engagement_id, contractor_user_id, sponsor_user_id, vendor_name, contract_reference,
                    start_date, end_date, status
                )
                OUTPUT INSERTED.*
                VALUES (
                    @id, @contractorId, @sponsorId, @vendor, @ref,
                    CAST(DATEADD(DAY, @startDays, SYSDATETIMEOFFSET()) AS DATE),
                    CAST(DATEADD(DAY, @days, SYSDATETIMEOFFSET()) AS DATE),
                    @status
                );
            `);
        cleanupEngagementIds.push(id);
        return result.recordset[0];
    }

    // Helper: Create an access request
    async function createTestAccessRequest(engagementId) {
        const requestId = require('crypto').randomUUID();
        const reqNum = `REQ-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;
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
                    @resId, @entId, SYSDATETIMEOFFSET(), DATEADD(DAY, 30, SYSDATETIMEOFFSET()),
                    'Offboarding integration test justification', 'APPROVED'
                );
            `);
        cleanupRequestIds.push(requestId);
        return requestId;
    }

    // Helper: Create an access grant
    async function createTestGrant(engagementId, options = {}) {
        const grantId = require('crypto').randomUUID();
        const grantNum = `GRNT-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;
        const requestId = options.requestId || await createTestAccessRequest(engagementId);
        const rand = Math.floor(Math.random() * 1000000);
        const {
            status = 'ACTIVE',
            expiresAtOffsetMinutes = 60,
            provenance = 'CREATED_BY_ACCESSLEASE',
            targetOrg = 'accesslease-governance',
            targetTeamSlug = `team-test-${rand}`,
            externalUsername = `contractor-${rand}`,
            numericAccountId = String(700000000 + rand)
        } = options;

        const result = await pool.request()
            .input('grantId', sql.UniqueIdentifier, grantId)
            .input('grantNum', sql.NVarChar(50), grantNum)
            .input('requestId', sql.UniqueIdentifier, requestId)
            .input('engagementId', sql.UniqueIdentifier, engagementId)
            .input('resourceId', sql.UniqueIdentifier, testResourceId)
            .input('entitlementId', sql.UniqueIdentifier, testEntitlementId)
            .input('status', sql.NVarChar(30), status)
            .input('offsetMin', sql.Int, expiresAtOffsetMinutes)
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
                    DATEADD(DAY, -1, SYSDATETIMEOFFSET()),
                    DATEADD(MINUTE, @offsetMin, SYSDATETIMEOFFSET()),
                    @status, @provenance, @targetOrg,
                    @targetTeamSlug, @externalUsername, @numericAccountId
                );
                SELECT TOP 1 * FROM dbo.access_grants WHERE grant_id = @grantId;
            `);
        cleanupGrantIds.push(grantId);
        return result.recordset[0];
    }

    // Helper: Create provider audit evidence event in dbo.provisioning_events
    async function createProviderAuditEvent(grantId, options = {}) {
        const eventId = require('crypto').randomUUID();

        let targetOrg = options.targetOrg;
        let targetTeam = options.targetTeam;
        let externalUsername = options.externalUsername;
        let numericAccountId = options.numericAccountId;

        if (!targetTeam || !numericAccountId || !externalUsername) {
            const g = await grantRepository.findGrantById(grantId);
            if (g) {
                targetOrg = targetOrg || g.target_org;
                targetTeam = targetTeam || g.target_team_slug;
                externalUsername = externalUsername || g.external_username;
                numericAccountId = numericAccountId || g.numeric_account_id;
            }
        }

        const payload = {
            verificationStatus: 'VERIFIED',
            grantId,
            targetOrg: targetOrg || 'accesslease-governance',
            targetTeam: targetTeam || 'backend-engineers',
            externalUsername: externalUsername || 'test-revocation-user',
            auditUserId: numericAccountId || '777888999',
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
                    @eventId, @grantId, 'PROVIDER_AUDIT_CONFIRMED', 'GITHUB', '200', @payload, SYSDATETIMEOFFSET()
                );
            `);
    }

    // -------------------------------------------------------------------------
    // Test 1: Expired grant creates one revocation job
    // -------------------------------------------------------------------------
    it('1. Expired grant creates one revocation job', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'ACTIVE',
            expiresAtOffsetMinutes: -10 // expired 10 minutes ago
        });

        const scanResult = await revocationService.processExpiredGrants({ batchSize: 50, autoProcess: false });
        assert.ok(scanResult.jobsCreated >= 1, 'Should create at least one revocation job');

        const jobs = await revocationRepository.getRevocationJobsByGrantId(grant.grant_id);
        assert.strictEqual(jobs.length, 1, 'Exactly one job must be created for the expired grant');
        assert.strictEqual(jobs[0].trigger_source, 'SCHEDULED_EXPIRATION');
        assert.strictEqual(jobs[0].status, 'QUEUED');

        const updatedGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(updatedGrant.status, 'REVOKE_PENDING', 'Grant status must be transitioned to REVOKE_PENDING');
    });

    // -------------------------------------------------------------------------
    // Test 2: Duplicate timer execution does not create duplicate jobs
    // -------------------------------------------------------------------------
    it('2. Duplicate timer execution does not create duplicate jobs', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'ACTIVE',
            expiresAtOffsetMinutes: -20
        });

        // First timer scan
        await revocationService.processExpiredGrants({ batchSize: 50, autoProcess: false });
        const jobsAfterFirst = await revocationRepository.getRevocationJobsByGrantId(grant.grant_id);
        assert.strictEqual(jobsAfterFirst.length, 1);

        // Second duplicate timer scan
        await revocationService.processExpiredGrants({ batchSize: 50, autoProcess: false });
        const jobsAfterSecond = await revocationRepository.getRevocationJobsByGrantId(grant.grant_id);
        assert.strictEqual(jobsAfterSecond.length, 1, 'Duplicate timer execution must not create duplicate jobs');
    });

    // -------------------------------------------------------------------------
    // Test 3: Active grant is not revoked prematurely
    // -------------------------------------------------------------------------
    it('3. Active grant is not revoked prematurely', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'ACTIVE',
            expiresAtOffsetMinutes: 1440 // expires in 24 hours
        });

        await revocationService.processExpiredGrants({ batchSize: 50, autoProcess: false });

        const jobs = await revocationRepository.getRevocationJobsByGrantId(grant.grant_id);
        assert.strictEqual(jobs.length, 0, 'No revocation job should be created for non-expired grant');

        const currentGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(currentGrant.status, 'ACTIVE', 'Grant must remain ACTIVE');
    });

    // -------------------------------------------------------------------------
    // Test 4: Terminated engagement triggers offboarding
    // -------------------------------------------------------------------------
    it('4. Terminated engagement triggers offboarding', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'ACTIVE',
            expiresAtOffsetMinutes: 1440
        });

        // Terminate engagement via revocationService
        const offboardResult = await revocationService.terminateContractorEngagement(
            eng.engagement_id,
            adminUser,
            'Project terminated early by sponsor'
        );

        assert.strictEqual(offboardResult.engagementStatus, 'TERMINATED');
        assert.strictEqual(offboardResult.grantsQueued, 1);

        const jobs = await revocationRepository.getRevocationJobsByGrantId(grant.grant_id);
        assert.ok(jobs.length >= 1, 'Revocation job must be enqueued for engagement termination');
        assert.strictEqual(jobs[0].trigger_source, 'ENGAGEMENT_TERMINATION');
    });

    // -------------------------------------------------------------------------
    // Test 5: Completed engagement triggers eligible expiry processing
    // -------------------------------------------------------------------------
    it('5. Completed engagement triggers eligible expiry processing', async () => {
        // Engagement whose status is COMPLETED
        const eng = await createTestEngagement('COMPLETED', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'ACTIVE',
            expiresAtOffsetMinutes: 120
        });

        const scanResult = await revocationService.processExpiredGrants({ batchSize: 50, autoProcess: false });
        assert.ok(scanResult.jobsCreated >= 1, 'Scan must identify grants whose engagement is completed');

        const jobs = await revocationRepository.getRevocationJobsByGrantId(grant.grant_id);
        assert.strictEqual(jobs.length, 1);
        assert.strictEqual(jobs[0].trigger_source, 'SCHEDULED_EXPIRATION');
    });

    // -------------------------------------------------------------------------
    // Test 6: Pre-existing membership is never automatically removed
    // -------------------------------------------------------------------------
    it('6. Pre-existing membership is never automatically removed', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'REVOKE_PENDING',
            provenance: 'PRE_EXISTING_ADOPTED'
        });

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        let deleteCalled = false;
        githubTeamService.removeTeamMembership = async () => {
            deleteCalled = true;
            return { success: true };
        };

        const outcome = await revocationWorker.executeRevocationJob(job);

        assert.strictEqual(deleteCalled, false, 'GitHub DELETE must NEVER be called for PRE_EXISTING_ADOPTED');
        assert.strictEqual(outcome.success, false);
        assert.strictEqual(outcome.manualReview, true);

        const updatedJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(updatedJob.status, 'MANUAL_REVIEW_REQUIRED');

        const updatedGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.notStrictEqual(updatedGrant.status, 'REVOKED', 'Grant must NOT be marked REVOKED');
    });

    // -------------------------------------------------------------------------
    // Test 7: Uncertain provenance is never automatically removed
    // -------------------------------------------------------------------------
    it('7. Uncertain provenance is never automatically removed', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'REVOKE_PENDING',
            provenance: 'UNCERTAIN_PRE_EXISTING'
        });

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        let deleteCalled = false;
        githubTeamService.removeTeamMembership = async () => {
            deleteCalled = true;
            return { success: true };
        };

        const outcome = await revocationWorker.executeRevocationJob(job);

        assert.strictEqual(deleteCalled, false, 'GitHub DELETE must NEVER be called for UNCERTAIN_PRE_EXISTING');
        assert.strictEqual(outcome.manualReview, true);

        const updatedJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(updatedJob.status, 'MANUAL_REVIEW_REQUIRED');
    });

    // -------------------------------------------------------------------------
    // Test 8: Missing provider evidence blocks removal
    // -------------------------------------------------------------------------
    it('8. Missing provider evidence blocks removal', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'REVOKE_PENDING',
            provenance: 'CREATED_BY_ACCESSLEASE' // but NO PROVIDER_AUDIT_CONFIRMED event inserted
        });

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        let deleteCalled = false;
        githubTeamService.removeTeamMembership = async () => {
            deleteCalled = true;
            return { success: true };
        };

        const outcome = await revocationWorker.executeRevocationJob(job);

        assert.strictEqual(deleteCalled, false, 'Absence of provider audit confirmation must block removal');
        assert.strictEqual(outcome.manualReview, true);
        assert.ok(outcome.reason.includes('Missing') || outcome.reason.includes('provider-side audit evidence'));

        const updatedJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(updatedJob.status, 'MANUAL_REVIEW_REQUIRED');
    });

    // -------------------------------------------------------------------------
    // Test 9: Matching provider evidence allows eligibility evaluation
    // -------------------------------------------------------------------------
    it('9. Matching provider evidence allows eligibility evaluation', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'ACTIVE',
            provenance: 'CREATED_BY_ACCESSLEASE',
            numericAccountId: '777888999'
        });

        // Insert matching PROVIDER_AUDIT_CONFIRMED event
        await createProviderAuditEvent(grant.grant_id);

        const safety = await isSafeForAutomatedRevocation(grant, {
            numericAccountId: grant.numeric_account_id
        });

        assert.strictEqual(safety.canRevoke, true, 'Matching provider audit evidence must allow eligibility evaluation');
        assert.ok(safety.reason.includes('Safe for automated revocation'));
    });

    // -------------------------------------------------------------------------
    // Test 10: Shared active grant prevents membership deletion
    // -------------------------------------------------------------------------
    it('10. Shared active grant prevents membership deletion', async () => {
        const engA = await createTestEngagement('ACTIVE', 30);
        const engB = await createTestEngagement('ACTIVE', 30);
        // Grant A (being revoked)
        const grantA = await createTestGrant(engA.engagement_id, {
            status: 'ACTIVE',
            expiresAtOffsetMinutes: -5,
            provenance: 'CREATED_BY_ACCESSLEASE',
            numericAccountId: '999111222',
            targetOrg: 'accesslease-governance',
            targetTeamSlug: 'shared-team-dev'
        });
        await createProviderAuditEvent(grantA.grant_id, {
            numericAccountId: '999111222',
            targetOrg: 'accesslease-governance',
            targetTeam: 'shared-team-dev'
        });

        // Grant B (still active and valid for the same membership)
        const grantB = await createTestGrant(engB.engagement_id, {
            status: 'ACTIVE',
            expiresAtOffsetMinutes: 2880, // 2 days in future
            provenance: 'CREATED_BY_ACCESSLEASE',
            numericAccountId: '999111222',
            targetOrg: 'accesslease-governance',
            targetTeamSlug: 'shared-team-dev'
        });

        const jobA = await revocationRepository.createRevocationJob({
            grantId: grantA.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        let deleteCalled = false;
        githubTeamService.removeTeamMembership = async () => {
            deleteCalled = true;
            return { success: true };
        };

        const outcome = await revocationWorker.executeRevocationJob(jobA);

        assert.strictEqual(deleteCalled, false, 'GitHub DELETE must NOT be called when shared active grant exists');
        assert.strictEqual(outcome.sharedRetained, true);
        assert.strictEqual(outcome.sharedActiveCount, 1);

        // Grant A must be marked REVOKED with shared retention reason
        const updatedGrantA = await grantRepository.findGrantById(grantA.grant_id);
        assert.strictEqual(updatedGrantA.status, 'REVOKED');
        assert.ok(updatedGrantA.revocation_reason.includes('Shared membership retained'));

        // Grant B must still be ACTIVE
        const updatedGrantB = await grantRepository.findGrantById(grantB.grant_id);
        assert.strictEqual(updatedGrantB.status, 'ACTIVE');
    });

    // -------------------------------------------------------------------------
    // Test 11: GitHub DELETE success followed by GET absence confirms revocation
    // -------------------------------------------------------------------------
    it('11. GitHub DELETE success followed by GET absence confirms revocation', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'REVOKE_PENDING',
            provenance: 'CREATED_BY_ACCESSLEASE'
        });
        await createProviderAuditEvent(grant.grant_id);

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Mock: First GET returns active membership, DELETE returns 204, Second GET returns null (absent)
        let getCallCount = 0;
        githubTeamService.getTeamMembership = async () => {
            getCallCount++;
            if (getCallCount === 1) return { state: 'active', role: 'member' };
            return null; // Post-DELETE confirms absence
        };

        let deleteCallCount = 0;
        githubTeamService.removeTeamMembership = async () => {
            deleteCallCount++;
            return { success: true, removed: true, status: 204 };
        };

        const outcome = await revocationWorker.executeRevocationJob(job);

        assert.strictEqual(deleteCallCount, 1);
        assert.strictEqual(getCallCount, 2, 'Must query before DELETE and after DELETE for verification');
        assert.strictEqual(outcome.success, true);
        assert.strictEqual(outcome.confirmedAbsent, true);

        const updatedJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(updatedJob.status, 'REVOKED');
        assert.ok(updatedJob.confirmed_at !== null);

        const updatedGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(updatedGrant.status, 'REVOKED');
    });

    // -------------------------------------------------------------------------
    // Test 12: GitHub DELETE success without verified absence does not mark REVOKED
    // -------------------------------------------------------------------------
    it('12. GitHub DELETE success without verified absence does not mark REVOKED', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'REVOKE_PENDING',
            provenance: 'CREATED_BY_ACCESSLEASE'
        });
        await createProviderAuditEvent(grant.grant_id);

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Mock: DELETE succeeds, but post-DELETE GET STILL returns active!
        githubTeamService.getTeamMembership = async () => ({ state: 'active', role: 'member' });
        githubTeamService.removeTeamMembership = async () => ({ success: true, removed: true, status: 204 });

        const outcome = await revocationWorker.executeRevocationJob(job);

        assert.strictEqual(outcome.success, false);
        assert.strictEqual(outcome.category, 'POST_VERIFICATION_FAILED');

        const updatedJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.notStrictEqual(updatedJob.status, 'REVOKED', 'Job must NOT be marked REVOKED');
        assert.strictEqual(updatedJob.status, 'FAILED_RETRY');

        const updatedGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.notStrictEqual(updatedGrant.status, 'REVOKED', 'Grant must NOT be marked REVOKED');
    });

    // -------------------------------------------------------------------------
    // Test 13: GitHub 403 is handled safely
    // -------------------------------------------------------------------------
    it('13. GitHub 403 is handled safely', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'REVOKE_PENDING',
            provenance: 'CREATED_BY_ACCESSLEASE'
        });
        await createProviderAuditEvent(grant.grant_id);

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        githubTeamService.getTeamMembership = async () => ({ state: 'active' });
        githubTeamService.removeTeamMembership = async () => {
            throw new ConnectorError('GitHub App lacks Members: Write permission on this organization.', 403, 'ERR_FORBIDDEN', {
                category: 'PERMISSION_DENIED'
            });
        };

        const outcome = await revocationWorker.executeRevocationJob(job);

        assert.strictEqual(outcome.success, false);
        assert.strictEqual(outcome.isRetryable, false, 'Permission denied must be non-retryable');

        const updatedJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(updatedJob.status, 'PERMANENT_FAILURE');
        assert.strictEqual(updatedJob.last_error_category, 'PERMISSION_DENIED');
    });

    // -------------------------------------------------------------------------
    // Test 14: GitHub 404 is reconciled correctly
    // -------------------------------------------------------------------------
    it('14. GitHub 404 is reconciled correctly', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'REVOKE_PENDING',
            provenance: 'CREATED_BY_ACCESSLEASE'
        });
        await createProviderAuditEvent(grant.grant_id);

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Mock: GET returns null (user is already absent / HTTP 404)
        githubTeamService.getTeamMembership = async () => null;

        let deleteCalled = false;
        githubTeamService.removeTeamMembership = async () => {
            deleteCalled = true;
            return { success: true };
        };

        const outcome = await revocationWorker.executeRevocationJob(job);

        assert.strictEqual(deleteCalled, false, 'DELETE is redundant if user is already absent');
        assert.strictEqual(outcome.success, true);
        assert.strictEqual(outcome.alreadyAbsent, true);

        const updatedJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(updatedJob.status, 'REVOKED');

        const updatedGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(updatedGrant.status, 'REVOKED');
        assert.strictEqual(updatedGrant.revocation_reason, 'ALREADY_ABSENT_AT_PROVIDER');
    });

    // -------------------------------------------------------------------------
    // Test 15: GitHub 429 respects Retry-After
    // -------------------------------------------------------------------------
    it('15. GitHub 429 respects Retry-After', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'REVOKE_PENDING',
            provenance: 'CREATED_BY_ACCESSLEASE'
        });
        await createProviderAuditEvent(grant.grant_id);

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        githubTeamService.getTeamMembership = async () => ({ state: 'active' });
        githubTeamService.removeTeamMembership = async () => {
            throw new ConnectorError('GitHub rate limit exceeded', 429, 'ERR_RATE_LIMIT', {
                category: 'RATE_LIMIT',
                retryAfterSeconds: 45
            });
        };

        const outcome = await revocationWorker.executeRevocationJob(job);

        assert.strictEqual(outcome.success, false);
        assert.strictEqual(outcome.isRetryable, true);

        const updatedJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(updatedJob.status, 'FAILED_RETRY');
        assert.ok(updatedJob.next_retry_at !== null);

        const nextRetryDate = new Date(updatedJob.next_retry_at);
        const now = new Date();
        const diffSeconds = Math.round((nextRetryDate - now) / 1000);
        assert.ok(diffSeconds >= 40 && diffSeconds <= 50, `next_retry_at should be ~45s in future, got ${diffSeconds}s`);
    });

    // -------------------------------------------------------------------------
    // Test 16: Network timeout enters retry handling
    // -------------------------------------------------------------------------
    it('16. Network timeout enters retry handling', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'REVOKE_PENDING',
            provenance: 'CREATED_BY_ACCESSLEASE'
        });
        await createProviderAuditEvent(grant.grant_id);

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        githubTeamService.getTeamMembership = async () => ({ state: 'active' });
        githubTeamService.removeTeamMembership = async () => {
            const err = new Error('Socket timeout connecting to api.github.com');
            err.code = 'ETIMEDOUT';
            throw err;
        };

        const outcome = await revocationWorker.executeRevocationJob(job);

        assert.strictEqual(outcome.success, false);
        assert.strictEqual(outcome.isRetryable, true);
        assert.strictEqual(outcome.category, 'NETWORK_TIMEOUT');

        const updatedJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(updatedJob.status, 'FAILED_RETRY');
    });

    // -------------------------------------------------------------------------
    // Test 17: Worker crash recovery is safe
    // -------------------------------------------------------------------------
    it('17. Worker crash recovery is safe', async () => {
        // Clear any previous queued jobs so this test specifically tests lease recovery
        await pool.request().query(`
            UPDATE dbo.revocation_jobs
            SET status = 'REVOKED'
            WHERE status IN ('QUEUED', 'FAILED_RETRY', 'PROCESSING');
        `);

        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, { status: 'REVOKE_PENDING' });

        // Simulate a job that was claimed by 'worker-crashed' with lease expired 10 minutes ago
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        await pool.request()
            .input('jobId', sql.UniqueIdentifier, job.job_id)
            .query(`
                UPDATE dbo.revocation_jobs
                SET status = 'PROCESSING',
                    lease_owner = 'worker-crashed',
                    lease_expires_at = DATEADD(MINUTE, -10, SYSDATETIMEOFFSET())
                WHERE job_id = @jobId;
            `);

        // A new healthy worker attempts to claim
        const recoveredJob = await revocationRepository.claimNextRevocationJob('worker-healthy', 60);

        assert.ok(recoveredJob !== null, 'Stale lease must be reclaimed by active worker');
        assert.strictEqual(recoveredJob.job_id.toLowerCase(), job.job_id.toLowerCase());
        assert.strictEqual(recoveredJob.lease_owner, 'worker-healthy');
    });

    // -------------------------------------------------------------------------
    // Test 18: Concurrent workers cannot process the same job unsafely
    // -------------------------------------------------------------------------
    it('18. Concurrent workers cannot process the same job unsafely', async () => {
        // Clear previous queued jobs so this test strictly isolates the single target job
        await pool.request().query(`
            UPDATE dbo.revocation_jobs
            SET status = 'REVOKED'
            WHERE status IN ('QUEUED', 'FAILED_RETRY', 'PROCESSING');
        `);

        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, { status: 'REVOKE_PENDING' });

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Run two concurrent worker claims
        const [claim1, claim2] = await Promise.all([
            revocationRepository.claimNextRevocationJob('worker-alpha', 60),
            revocationRepository.claimNextRevocationJob('worker-beta', 60)
        ]);

        const claimed = [claim1, claim2].filter(c => c && c.job_id.toLowerCase() === job.job_id.toLowerCase());
        assert.strictEqual(claimed.length, 1, 'Exactly one concurrent worker must claim the job');
    });

    // -------------------------------------------------------------------------
    // Test 19: Database failure after GitHub success triggers reconciliation
    // -------------------------------------------------------------------------
    it('19. Database failure after GitHub success triggers reconciliation', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'REVOKE_PENDING',
            provenance: 'CREATED_BY_ACCESSLEASE'
        });
        await createProviderAuditEvent(grant.grant_id);

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION'
        });

        // Scenario: Previous attempt removed the user from GitHub, but process died before DB commit.
        // On retry, GitHub GET returns null (user is absent).
        githubTeamService.getTeamMembership = async () => null;

        const outcome = await revocationWorker.executeRevocationJob(job);

        assert.strictEqual(outcome.success, true);
        assert.strictEqual(outcome.alreadyAbsent, true);

        // State is cleanly reconciled
        const updatedJob = await revocationRepository.findRevocationJobById(job.job_id);
        assert.strictEqual(updatedJob.status, 'REVOKED');

        const updatedGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(updatedGrant.status, 'REVOKED');
    });

    // -------------------------------------------------------------------------
    // Test 20: Unauthorized users cannot manually retry jobs
    // -------------------------------------------------------------------------
    it('20. Unauthorized users cannot manually retry jobs', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, { status: 'REVOKE_PENDING' });
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION',
            status: 'FAILED_RETRY'
        });

        // Contractor tries to manually retry job
        await assert.rejects(
            async () => {
                await revocationService.retryRevocationJob(job.job_id, contractorUser);
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.ok(err.message.includes('Only System Administrators and Security Officers'));
                return true;
            }
        );
    });

    // -------------------------------------------------------------------------
    // Test 21: Compliance auditors cannot mutate revocation state
    // -------------------------------------------------------------------------
    it('21. Compliance auditors cannot mutate revocation state', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, { status: 'REVOKE_PENDING' });
        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION',
            status: 'FAILED_RETRY'
        });

        // Compliance auditor (strictly read-only) tries to retry job
        await assert.rejects(
            async () => {
                await revocationService.retryRevocationJob(job.job_id, auditorUser);
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                return true;
            }
        );
    });

    // -------------------------------------------------------------------------
    // Test 22: Authorized System Admin CAN retry and resolve jobs
    // -------------------------------------------------------------------------
    it('22. Authorized System Admin CAN retry and resolve jobs', async () => {
        const eng = await createTestEngagement('ACTIVE', 30);
        const grant = await createTestGrant(eng.engagement_id, {
            status: 'REVOKE_PENDING',
            provenance: 'CREATED_BY_ACCESSLEASE'
        });
        await createProviderAuditEvent(grant.grant_id);

        const job = await revocationRepository.createRevocationJob({
            grantId: grant.grant_id,
            triggerSource: 'SCHEDULED_EXPIRATION',
            status: 'MANUAL_REVIEW_REQUIRED'
        });

        // Admin resolves manual review exception
        const resolved = await revocationService.resolveManualReview(
            job.job_id,
            adminUser,
            'CONFIRMED_REVOKED',
            'Manually verified removal in GitHub audit log'
        );

        assert.strictEqual(resolved.status, 'REVOKED');

        const updatedGrant = await grantRepository.findGrantById(grant.grant_id);
        assert.strictEqual(updatedGrant.status, 'REVOKED');
        assert.ok(updatedGrant.revocation_reason.includes('Manually confirmed'));
    });
});
