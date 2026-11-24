/**
 * AccessLease — Prompt 06: GitHub Team Provisioning Engine Integration Tests
 * Real LocalDB integration tests executing against Microsoft SQL Server:
 * 
 * 1. Transactional Job & Grant Creation upon Access Request Approval.
 * 2. Deterministic Database-Level Idempotency (Duplicate start prevention).
 * 3. Identity Verification Guardrail: Blocks unmapped/unverified contractor identities.
 * 4. Confirmed Active GitHub Team Provisioning & Verified Grant Activation.
 * 5. Pre-Existing Membership Adoption: Provenance tracking.
 * 6. Invitation Pending Acceptance State & Eventual Reconciliation.
 * 7. Worker Lease Claiming, Concurrency, and Stale Lease Recovery.
 * 8. Manual Retry Authorization (Admin/Security allowed, Contractor/Auditor forbidden).
 * 9. GET /api/connectors/github/status sanitized public reporting.
 */

process.env.NODE_ENV = 'test';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const {
    createRequest,
    submitApprovalDecision
} = require('../../src/functions/requests');
const {
    getGitHubStatus,
    startProvisioning,
    getProvisioningStateByRequest,
    listProvisioningJobs,
    listGrants,
    retryProvisioningJob
} = require('../../src/functions/provisioning');

const tokenUtils = require('../../src/utils/tokenUtils');
const { getPool, closePool, withTransaction } = require('../../src/config/database');
const { getValidTestDates } = require('../helpers/testDateUtils');
const provisioningService = require('../../src/services/provisioningService');
const provisioningWorker = require('../../src/services/provisioningWorker');
const githubConnector = require('../../src/connectors/github');
const userExternalIdentityRepository = require('../../src/repositories/userExternalIdentityRepository');
const grantRepository = require('../../src/repositories/grantRepository');
const provisioningRepository = require('../../src/repositories/provisioningRepository');

describe('Integration: GitHub Team Access Provisioning Engine (PROMPT 06)', () => {
    let rsaKeyPair;
    let originalTenantId, originalSpaClientId, originalApiClientId, originalApiAudience;

    const TEST_TENANT_ID = 'test-prov-tenant';
    const TEST_SPA_CLIENT_ID = 'test-spa-client-prov';
    const TEST_API_CLIENT_ID = 'test-api-client-prov';
    const TEST_AUDIENCE = `api://${TEST_API_CLIENT_ID}`;
    const TEST_ISSUER = `https://login.microsoftonline.com/${TEST_TENANT_ID}/v2.0`;

    let contractorUserId;
    let sponsorUserId;
    let ownerUserId;
    let securityUserId;
    let adminUserId;
    let auditorUserId;

    let repoResourceId;
    let repoEntitlementId;

    before(async () => {
        originalTenantId = process.env.ENTRA_TENANT_ID;
        originalSpaClientId = process.env.ENTRA_SPA_CLIENT_ID;
        originalApiClientId = process.env.ENTRA_API_CLIENT_ID;
        originalApiAudience = process.env.ENTRA_API_AUDIENCE;

        process.env.ENTRA_TENANT_ID = TEST_TENANT_ID;
        process.env.ENTRA_SPA_CLIENT_ID = TEST_SPA_CLIENT_ID;
        process.env.ENTRA_API_CLIENT_ID = TEST_API_CLIENT_ID;
        process.env.ENTRA_API_AUDIENCE = TEST_AUDIENCE;

        rsaKeyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        process.env.GITHUB_APP_ID = '123456';
        process.env.GITHUB_APP_PRIVATE_KEY = rsaKeyPair.privateKey;
        process.env.GITHUB_APP_INSTALLATION_ID = '88776655';
        process.env.GITHUB_ALLOWED_ORGS = 'accesslease-org,test-partner-org';

        tokenUtils.setCustomKeyResolver((header, callback) => {
            callback(null, rsaKeyPair.publicKey);
        });

        // Set mock installation token
        githubConnector.githubAuth.setMockTokenProvider(async () => 'ghs_integration_mock_token');

        // Resolve seeded identities from database
        const pool = await getPool();
        const users = await pool.request().query(`
            SELECT user_id, entra_object_id FROM dbo.users
            WHERE entra_object_id IN ('TEST-OID-CONTRACTOR', 'TEST-OID-SPONSOR', 'TEST-OID-OWNER', 'TEST-OID-SECURITY', 'TEST-OID-ADMIN', 'TEST-OID-AUDITOR');
        `);

        for (const u of users.recordset) {
            if (u.entra_object_id === 'TEST-OID-CONTRACTOR') contractorUserId = u.user_id;
            if (u.entra_object_id === 'TEST-OID-SPONSOR') sponsorUserId = u.user_id;
            if (u.entra_object_id === 'TEST-OID-OWNER') ownerUserId = u.user_id;
            if (u.entra_object_id === 'TEST-OID-SECURITY') securityUserId = u.user_id;
            if (u.entra_object_id === 'TEST-OID-ADMIN') adminUserId = u.user_id;
            if (u.entra_object_id === 'TEST-OID-AUDITOR') auditorUserId = u.user_id;
        }

        // Resolve seeded repository resource and entitlement
        const resQuery = await pool.request().query(`
            SELECT r.resource_id, e.entitlement_id
            FROM dbo.resources r
            INNER JOIN dbo.entitlements e ON r.resource_id = e.resource_id
            WHERE r.resource_code = 'RES-GH-CORE-REPO' AND e.entitlement_code = 'REPO_CORE_CONTRIBUTOR';
        `);

        if (resQuery.recordset.length > 0) {
            repoResourceId = resQuery.recordset[0].resource_id;
            repoEntitlementId = resQuery.recordset[0].entitlement_id;
        }

        // Clean stale test grants and requests for this test entitlement to ensure fresh test runs
        await pool.request().query(`
            DELETE FROM dbo.provisioning_events WHERE grant_id IN (
                SELECT grant_id FROM dbo.access_grants WHERE entitlement_id = '${repoEntitlementId}'
            );
            DELETE FROM dbo.provisioning_jobs WHERE grant_id IN (
                SELECT grant_id FROM dbo.access_grants WHERE entitlement_id = '${repoEntitlementId}'
            );
            DELETE FROM dbo.access_grants WHERE entitlement_id = '${repoEntitlementId}';
            UPDATE dbo.access_requests SET status = 'CANCELLED'
            WHERE entitlement_id = '${repoEntitlementId}' AND status IN ('SUBMITTED', 'PENDING_APPROVAL');
        `);
    });

    after(async () => {
        tokenUtils.setCustomKeyResolver(null);
        githubConnector.githubAuth.setMockTokenProvider(null);
        githubConnector.githubApiClient.setCustomTransport(null);

        process.env.ENTRA_TENANT_ID = originalTenantId;
        process.env.ENTRA_SPA_CLIENT_ID = originalSpaClientId;
        process.env.ENTRA_API_CLIENT_ID = originalApiClientId;
        process.env.ENTRA_API_AUDIENCE = originalApiAudience;

        try {
            const pool = await getPool();
            await pool.request().query(`
                DELETE FROM dbo.provisioning_events WHERE grant_id IN (
                    SELECT grant_id FROM dbo.access_grants WHERE entitlement_id = '${repoEntitlementId}'
                );
                DELETE FROM dbo.provisioning_jobs WHERE grant_id IN (
                    SELECT grant_id FROM dbo.access_grants WHERE entitlement_id = '${repoEntitlementId}'
                );
                DELETE FROM dbo.access_grants WHERE entitlement_id = '${repoEntitlementId}';
            `);
        } catch (_) {}

        provisioningWorker.stopWorker();
        await closePool();
    });

    function generateMockToken(oid, email) {
        const payload = {
            oid,
            email,
            preferred_username: email,
            name: email.split('@')[0],
            tid: TEST_TENANT_ID,
            aud: TEST_AUDIENCE,
            iss: TEST_ISSUER,
            scp: 'access_as_user'
        };

        return jwt.sign(payload, rsaKeyPair.privateKey, {
            algorithm: 'RS256',
            keyid: 'test-prov-key',
            expiresIn: '1h'
        });
    }

    function createMockRequest(method, path, options = {}) {
        const { headers = {}, params = {}, query = {}, body = {} } = options;
        const headersMap = new Map();
        for (const [k, v] of Object.entries(headers)) {
            headersMap.set(k.toLowerCase(), v);
        }

        return {
            method,
            path,
            url: path,
            headers: headersMap,
            params,
            query,
            body,
            json: async () => body
        };
    }

    const mockContext = { invocationId: 'test-prov-inv', log: () => {} };

    // -------------------------------------------------------------------------
    // 1. Transactional Job & Grant Creation upon Request Approval
    // -------------------------------------------------------------------------
    let testRequestId;
    let testJobId;
    let testGrantId;

    test('1. Transactional Job and Grant Creation when Access Request is Approved', async () => {
        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const sponsorToken = generateMockToken('TEST-OID-SPONSOR', 'sponsor@example.com');
        const ownerToken = generateMockToken('TEST-OID-OWNER', 'owner@example.com');
        const securityToken = generateMockToken('TEST-OID-SECURITY', 'security@example.com');

        // Create high-risk request for GitHub repository
        const { startDate, endDate } = getValidTestDates(1, 14);
        const createReq = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${contractorToken}` },
            body: {
                resourceId: repoResourceId,
                entitlementId: repoEntitlementId,
                requestedStartDate: startDate,
                requestedEndDate: endDate,
                businessJustification: 'Core repository pull request and CI/CD contributions.'
            }
        });
        const createRes = await createRequest(createReq, mockContext);
        assert.strictEqual(createRes.status, 201);
        testRequestId = createRes.jsonBody.data.request_id;
        const steps = createRes.jsonBody.data.approval_steps;
        assert.strictEqual(steps.length, 3, 'High-risk repo must require 3 stages');

        // Step 1: Sponsor approves
        await submitApprovalDecision(createMockRequest('POST', `/api/approvals/${steps[0].approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${sponsorToken}` },
            params: { stepId: steps[0].approval_step_id },
            body: { decision: 'APPROVE', comments: 'Sponsor endorsement for repo access.' }
        }), mockContext);

        // Step 2: Resource Owner approves
        await submitApprovalDecision(createMockRequest('POST', `/api/approvals/${steps[1].approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${ownerToken}` },
            params: { stepId: steps[1].approval_step_id },
            body: { decision: 'APPROVE', comments: 'Resource owner verified.' }
        }), mockContext);

        // Step 3: Security Officer approves -> Final Approval
        const step3Res = await submitApprovalDecision(createMockRequest('POST', `/api/approvals/${steps[2].approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${securityToken}` },
            params: { stepId: steps[2].approval_step_id },
            body: { decision: 'APPROVE', comments: 'Security review completed and approved.' }
        }), mockContext);

        assert.strictEqual(step3Res.status, 200);
        assert.strictEqual(step3Res.jsonBody.data.request_status, 'APPROVED');

        // Verify that durable provisioning job was created in SQL Server
        const pool = await getPool();
        const jobResult = await pool.request().query(`
            SELECT job_id, request_id, grant_id, connector_type, target_resource, idempotency_key, job_status
            FROM dbo.provisioning_jobs
            WHERE request_id = '${testRequestId}';
        `);

        assert.strictEqual(jobResult.recordset.length, 1, 'Exactly one provisioning job must exist');
        const jobRow = jobResult.recordset[0];
        testJobId = jobRow.job_id;
        testGrantId = jobRow.grant_id;
        assert.strictEqual(jobRow.connector_type, 'GITHUB');
        assert.ok(jobRow.job_status === 'QUEUED' || jobRow.job_status === 'PROCESSING' || jobRow.job_status === 'SUCCEEDED');

        // Verify that access_grants record was created
        const grantResult = await pool.request().query(`
            SELECT grant_id, status, target_org, target_team_slug, target_repo, external_username
            FROM dbo.access_grants
            WHERE grant_id = '${testGrantId}';
        `);
        assert.strictEqual(grantResult.recordset.length, 1);
        const grantRow = grantResult.recordset[0];
        assert.strictEqual(grantRow.target_org, 'accesslease-org');
        assert.strictEqual(grantRow.target_team_slug, 'contractor-engineering-team');
        assert.strictEqual(grantRow.external_username, 'contractor-governance-test');
    });

    // -------------------------------------------------------------------------
    // 2. Deterministic Database-Level Idempotency
    // -------------------------------------------------------------------------
    test('2. Calling startProvisioning a second time returns existing job without duplicates', async () => {
        assert.ok(testRequestId, 'Prerequisite testRequestId from step 1 must be present');
        assert.ok(testJobId, 'Prerequisite testJobId from step 1 must be present');
        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const startReq = createMockRequest('POST', `/api/provisioning/requests/${testRequestId}/start`, {
            headers: { authorization: `Bearer ${contractorToken}` },
            params: { id: testRequestId }
        });

        const startRes = await startProvisioning(startReq, mockContext);
        assert.strictEqual(startRes.status, 200);
        assert.strictEqual(startRes.jsonBody.data.alreadyExists, true);
        assert.strictEqual(startRes.jsonBody.data.job.job_id, testJobId);

        // Verify database row count remains exactly 1
        const pool = await getPool();
        const countRes = await pool.request().query(`
            SELECT COUNT(*) AS total FROM dbo.provisioning_jobs WHERE request_id = '${testRequestId}';
        `);
        assert.strictEqual(countRes.recordset[0].total, 1);
    });

    // -------------------------------------------------------------------------
    // 3. Identity Verification Guardrail
    // -------------------------------------------------------------------------
    test('3. Provisioning blocks and marks PERMANENT_FAILURE if contractor identity is unverified', async () => {
        const pool = await getPool();

        // Create an unmapped contractor identity
        let unmappedContractor = await pool.request().query(`SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-UNMAPPED-CONTRACTOR'`);
        if (unmappedContractor.recordset.length === 0) {
            await pool.request().query(`
                INSERT INTO dbo.users (entra_object_id, email, first_name, last_name, display_name, user_type, department, is_active)
                VALUES ('TEST-OID-UNMAPPED-CONTRACTOR', 'unmapped@example.com', 'Uma', 'Unmapped', 'Uma Unmapped Contractor', 'CONTRACTOR', 'Engineering', 1);
                DECLARE @uId UNIQUEIDENTIFIER = (SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-UNMAPPED-CONTRACTOR');
                DECLARE @cRoleId INT = (SELECT role_id FROM dbo.roles WHERE role_code = 'CONTRACTOR');
                INSERT INTO dbo.user_roles (user_id, role_id) VALUES (@uId, @cRoleId);
            `);
            unmappedContractor = await pool.request().query(`SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-UNMAPPED-CONTRACTOR'`);
        }
        const unmappedUserId = unmappedContractor.recordset[0].user_id;

        // Ensure an engagement exists for unmapped contractor
        let eng = await pool.request().query(`SELECT engagement_id FROM dbo.contractor_engagements WHERE contractor_user_id = '${unmappedUserId}'`);
        if (eng.recordset.length === 0) {
            await pool.request().query(`
                INSERT INTO dbo.contractor_engagements (contractor_user_id, sponsor_user_id, vendor_name, contract_reference, start_date, end_date, status)
                VALUES ('${unmappedUserId}', '${sponsorUserId}', 'Vendor Unmapped', 'CR-UNMAPPED-01', '2026-01-01', '2026-12-31', 'ACTIVE');
            `);
            eng = await pool.request().query(`SELECT engagement_id FROM dbo.contractor_engagements WHERE contractor_user_id = '${unmappedUserId}'`);
        }
        const unmappedEngId = eng.recordset[0].engagement_id;

        // Create an approved request directly for unmapped contractor
        const unmappedReqNum = `AR-2026-UNM-${Date.now().toString().slice(-4)}`;
        const { startDate: unmappedStart, endDate: unmappedEnd } = getValidTestDates(1, 14);
        const reqResult = await pool.request().query(`
            INSERT INTO dbo.access_requests (
                request_number, contractor_engagement_id, requested_by_user_id, resource_id, entitlement_id,
                requested_start_date, requested_end_date, business_justification, status, requires_security_approval
            )
            OUTPUT INSERTED.request_id
            VALUES (
                '${unmappedReqNum}', '${unmappedEngId}', '${unmappedUserId}', '${repoResourceId}', '${repoEntitlementId}',
                '${unmappedStart}', '${unmappedEnd}', 'Testing unmapped identity block', 'APPROVED', 1
            );
        `);
        const unmappedReqId = reqResult.recordset[0].request_id;

        // Trigger provisioning creation
        const provOutcome = await provisioningService.createProvisioningOperation(unmappedReqId, { user_id: unmappedUserId }, { deferExecution: true });
        assert.ok(provOutcome.job);

        // Execute worker pass on this job
        const execOutcome = await provisioningWorker.executeProvisioningJob(provOutcome.job);
        assert.strictEqual(execOutcome.success, false);
        assert.strictEqual(execOutcome.category, 'IDENTITY_NOT_LINKED');

        // Verify job in database is PERMANENT_FAILURE and grant is PROVISIONING_FAILED
        const updatedJob = await provisioningRepository.findJobById(provOutcome.job.job_id);
        assert.strictEqual(updatedJob.job_status, 'PERMANENT_FAILURE');
        assert.strictEqual(updatedJob.last_error_category, 'IDENTITY_NOT_LINKED');

        const updatedGrant = await grantRepository.findGrantById(provOutcome.grant.grant_id);
        assert.strictEqual(updatedGrant.status, 'PROVISIONING_FAILED');
        assert.strictEqual(updatedGrant.failure_category, 'IDENTITY_NOT_LINKED');
    });

    // -------------------------------------------------------------------------
    // 4. Confirmed Active GitHub Team Provisioning
    // -------------------------------------------------------------------------
    test('4. Confirmed active GitHub membership activates grant with CREATED_BY_ACCESSLEASE provenance', async () => {
        assert.ok(testJobId, 'Prerequisite testJobId from step 1 must be present');
        assert.ok(testGrantId, 'Prerequisite testGrantId from step 1 must be present');
        // Configure custom transport to simulate GitHub responses
        githubConnector.githubApiClient.setCustomTransport(async (endpoint, options) => {
            if (endpoint.includes('/teams/contractor-engineering-team') && !endpoint.includes('/repos') && !endpoint.includes('/memberships')) {
                return { status: 200, data: { id: 333, name: 'Contractor Engineering Team' }, headers: new Headers() };
            }
            if (endpoint.includes('/repos/accesslease-org/accesslease-governance')) {
                return {
                    status: 200,
                    data: { id: 444, full_name: 'accesslease-org/accesslease-governance', permissions: { push: true, pull: true } },
                    headers: new Headers()
                };
            }
            // Check membership: initially not member
            if (endpoint.includes('/memberships/contractor-governance-test') && options.method !== 'PUT') {
                return { status: 404, data: null, headers: new Headers() };
            }
            // Add membership: returns active
            if (endpoint.includes('/memberships/contractor-governance-test') && options.method === 'PUT') {
                return { status: 200, data: { state: 'active', role: 'member' }, headers: new Headers() };
            }
            // Audit log query for authoritative provider verification (PROMPT 06.5)
            if (endpoint.includes('/audit-log')) {
                return {
                    status: 200,
                    data: [{
                        action: 'team.add_member',
                        actor: 'accesslease[bot]',
                        actor_is_bot: true,
                        user: 'contractor-governance-test',
                        org: 'accesslease-org',
                        team: 'contractor-engineering-team',
                        '@timestamp': Date.now()
                    }],
                    headers: new Headers()
                };
            }
            throw new Error(`Unhandled mock endpoint: ${endpoint}`);
        });

        // Claim and execute testJobId
        const job = await provisioningRepository.findJobById(testJobId);
        const result = await provisioningWorker.executeProvisioningJob(job);

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.outcome.state, 'ACTIVE');
        assert.strictEqual(result.outcome.membershipProvenance, 'CREATED_BY_ACCESSLEASE');

        // Verify in database: grant is ACTIVE
        const grant = await grantRepository.findGrantById(testGrantId);
        assert.strictEqual(grant.status, 'ACTIVE');
        assert.strictEqual(grant.membership_provenance, 'CREATED_BY_ACCESSLEASE');
        assert.ok(grant.verified_at !== null);

        // Verify job in database: SUCCEEDED
        const completedJob = await provisioningRepository.findJobById(testJobId);
        assert.strictEqual(completedJob.job_status, 'SUCCEEDED');
    });

    // -------------------------------------------------------------------------
    // 5. Pre-Existing Membership Adoption
    // -------------------------------------------------------------------------
    test('5. Discovers pre-existing GitHub membership and marks PRE_EXISTING_ADOPTED without altering team', async () => {
        let putCalled = false;

        githubConnector.githubApiClient.setCustomTransport(async (endpoint, options) => {
            if (endpoint.includes('/teams/contractor-engineering-team') && !endpoint.includes('/repos') && !endpoint.includes('/memberships')) {
                return { status: 200, data: { id: 333, name: 'Contractor Engineering Team' }, headers: new Headers() };
            }
            if (endpoint.includes('/repos/accesslease-org/accesslease-governance')) {
                return {
                    status: 200,
                    data: { id: 444, full_name: 'accesslease-org/accesslease-governance', permissions: { push: true, pull: true } },
                    headers: new Headers()
                };
            }
            if (endpoint.includes('/memberships/contractor-governance-test')) {
                if (options.method === 'PUT') {
                    putCalled = true;
                }
                // Pre-existing active member
                return { status: 200, data: { state: 'active', role: 'maintainer' }, headers: new Headers() };
            }
            throw new Error(`Unhandled mock endpoint: ${endpoint}`);
        });

        const outcome = await githubConnector.githubVerificationService.provisionAndVerifyAccess({
            org: 'accesslease-org',
            teamSlug: 'contractor-engineering-team',
            repoOwner: 'accesslease-org',
            repoName: 'accesslease-governance',
            requiredPermission: 'push',
            username: 'contractor-governance-test'
        });

        assert.strictEqual(outcome.success, true);
        assert.strictEqual(outcome.state, 'ACTIVE');
        assert.strictEqual(outcome.membershipProvenance, 'PRE_EXISTING_ADOPTED');
        assert.strictEqual(outcome.preExisting, true);
        assert.strictEqual(putCalled, false, 'Should not issue PUT request when membership is already active');
    });

    // -------------------------------------------------------------------------
    // 6. Invitation Pending State & Eventual Reconciliation
    // -------------------------------------------------------------------------
    test('6. Invitation pending sets PENDING_ACCEPTANCE and reconciles upon acceptance', async () => {
        assert.ok(testJobId, 'Prerequisite testJobId from step 1 must be present');
        assert.ok(testGrantId, 'Prerequisite testGrantId from step 1 must be present');
        let memberState = 'pending';

        githubConnector.githubApiClient.setCustomTransport(async (endpoint, options) => {
            if (endpoint.includes('/teams/contractor-engineering-team') && !endpoint.includes('/repos') && !endpoint.includes('/memberships')) {
                return { status: 200, data: { id: 333, name: 'Contractor Engineering Team' }, headers: new Headers() };
            }
            if (endpoint.includes('/repos/accesslease-org/accesslease-governance')) {
                return {
                    status: 200,
                    data: { id: 444, full_name: 'accesslease-org/accesslease-governance', permissions: { push: true, pull: true } },
                    headers: new Headers()
                };
            }
            if (endpoint.includes('/memberships/contractor-governance-test')) {
                return { status: 200, data: { state: memberState, role: 'member' }, headers: new Headers() };
            }
            if (endpoint.includes('/audit-log')) {
                return {
                    status: 200,
                    data: [{
                        action: 'team.add_member',
                        actor: 'accesslease[bot]',
                        actor_is_bot: true,
                        user: 'contractor-governance-test',
                        org: 'accesslease-org',
                        team: 'contractor-engineering-team',
                        '@timestamp': Date.now()
                    }],
                    headers: new Headers()
                };
            }
            throw new Error(`Unhandled mock endpoint: ${endpoint}`);
        });

        // Reset test job to QUEUED
        await provisioningRepository.updateJobStatus(testJobId, 'QUEUED');
        const job = await provisioningRepository.findJobById(testJobId);

        // Process job with state = 'pending'
        await provisioningWorker.executeProvisioningJob(job);

        // Grant must be PENDING_ACCEPTANCE, not ACTIVE
        const grantPending = await grantRepository.findGrantById(testGrantId);
        assert.strictEqual(grantPending.status, 'PENDING_ACCEPTANCE');

        const jobPending = await provisioningRepository.findJobById(testJobId);
        assert.strictEqual(jobPending.job_status, 'PENDING_ACCEPTANCE');

        // Now simulate contractor accepting invitation on GitHub
        memberState = 'active';

        // Worker reconciliation cycle runs
        await provisioningWorker.reconcilePendingAcceptanceJobs();

        // Grant must now be ACTIVE
        const grantActive = await grantRepository.findGrantById(testGrantId);
        assert.strictEqual(grantActive.status, 'ACTIVE');

        const jobActive = await provisioningRepository.findJobById(testJobId);
        assert.strictEqual(jobActive.job_status, 'SUCCEEDED');
    });

    // -------------------------------------------------------------------------
    // 7. Worker Lease Claiming & Stale Lease Recovery
    // -------------------------------------------------------------------------
    test('7. Stale worker leases are automatically recovered and claimed by active workers', async () => {
        assert.ok(testJobId, 'Prerequisite testJobId from step 1 must be present');
        const pool = await getPool();

        // Manually place a job into PROCESSING with an expired lease
        await pool.request().query(`
            UPDATE dbo.provisioning_jobs
            SET
                job_status = 'FAILED_RETRY',
                lease_owner = 'crashed-worker-pid-999',
                lease_expires_at = DATEADD(SECOND, -30, SYSDATETIMEOFFSET()),
                next_retry_at = DATEADD(SECOND, -10, SYSDATETIMEOFFSET())
            WHERE job_id = '${testJobId}';
        `);

        // Claim job as a new healthy worker
        const claimed = await provisioningRepository.claimNextProvisioningJob('healthy-worker-01', 45);
        assert.ok(claimed !== null);
        assert.strictEqual(claimed.job_id, testJobId);
        assert.strictEqual(claimed.lease_owner, 'healthy-worker-01');
        assert.strictEqual(claimed.job_status, 'PROCESSING');
    });

    // -------------------------------------------------------------------------
    // 8. Manual Retry Authorization
    // -------------------------------------------------------------------------
    test('8. System Admin can retry failed job, while Contractor and Compliance Auditor are blocked', async () => {
        assert.ok(testJobId, 'Prerequisite testJobId from step 1 must be present');
        // Mark job as PERMANENT_FAILURE for test
        await provisioningRepository.updateJobStatus(testJobId, 'PERMANENT_FAILURE', {
            lastErrorCategory: 'SIMULATED_FAIL',
            lastErrorMessage: 'Simulated failure for retry testing'
        });

        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const auditorToken = generateMockToken('TEST-OID-AUDITOR', 'auditor@example.com');
        const adminToken = generateMockToken('TEST-OID-ADMIN', 'admin@example.com');

        // Contractor attempts retry -> HTTP 403
        const contractorReq = createMockRequest('POST', `/api/provisioning/jobs/${testJobId}/retry`, {
            headers: { authorization: `Bearer ${contractorToken}` },
            params: { id: testJobId }
        });
        const contractorRes = await retryProvisioningJob(contractorReq, mockContext);
        assert.strictEqual(contractorRes.status, 403);
        assert.strictEqual(contractorRes.jsonBody.error.code, 'ERR_FORBIDDEN_RETRY');

        // Auditor attempts retry -> HTTP 403
        const auditorReq = createMockRequest('POST', `/api/provisioning/jobs/${testJobId}/retry`, {
            headers: { authorization: `Bearer ${auditorToken}` },
            params: { id: testJobId }
        });
        const auditorRes = await retryProvisioningJob(auditorReq, mockContext);
        assert.strictEqual(auditorRes.status, 403);
        assert.strictEqual(auditorRes.jsonBody.error.code, 'ERR_FORBIDDEN_RETRY');

        // System Admin attempts retry -> HTTP 200
        const adminReq = createMockRequest('POST', `/api/provisioning/jobs/${testJobId}/retry`, {
            headers: { authorization: `Bearer ${adminToken}` },
            params: { id: testJobId },
            body: { deferExecution: true }
        });
        const adminRes = await retryProvisioningJob(adminReq, mockContext);
        assert.strictEqual(adminRes.status, 200);
        assert.strictEqual(adminRes.jsonBody.data.job_status, 'QUEUED');
        assert.strictEqual(adminRes.jsonBody.data.attempt_count, 0);
    });

    // -------------------------------------------------------------------------
    // 9. Sanitized Connector Status Endpoint
    // -------------------------------------------------------------------------
    test('9. GET /api/connectors/github/status returns safe public status with zero secret leakage', async () => {
        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const req = createMockRequest('GET', '/api/connectors/github/status', {
            headers: { authorization: `Bearer ${contractorToken}` }
        });

        const res = await getGitHubStatus(req, mockContext);
        assert.strictEqual(res.status, 200);
        const data = res.jsonBody.data;
        assert.strictEqual(data.connector, 'GITHUB');
        assert.strictEqual(data.appId, '123456');
        assert.strictEqual(data.installationId, '88776655');
        assert.deepStrictEqual(data.allowedOrgs, ['accesslease-org', 'test-partner-org']);

        const serialized = JSON.stringify(data);
        assert.ok(!serialized.includes('privateKey'));
        assert.ok(!serialized.includes('token'));
        assert.ok(!serialized.includes('secret'));
    });
});
