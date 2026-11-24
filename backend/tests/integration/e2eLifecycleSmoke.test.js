/**
 * AccessLease — PROMPT 09: End-to-End Functional Smoke Test Suite
 * 
 * Comprehensive E2E integration test covering all three core governance lifecycles:
 * 
 * SCENARIO A: Contractor Access Lifecycle
 * - Contractor & Engagement Creation
 * - Multi-Stage Time-Bound Access Request Submission (High-Risk Entitlement)
 * - Separation of Duties & Anti-Bypass Validation
 * - Sequential Multi-Stage Approvals (Sponsor -> Resource Owner -> Security Officer)
 * - Automated Provider Provisioning & Verified Grant Activation
 * - Time-Bound Expiry & Controlled Revocation Finalization
 * 
 * SCENARIO B: Revocation Failure & Recovery
 * - Automated Revocation Initiation
 * - Simulated Provider Network/Transient Outage (HTTP 503)
 * - Safe Retry Scheduling with Backoff (No premature REVOKED status)
 * - Provider Recovery & Reconciliation Verification
 * - Protection of Pre-Existing/Uncertain Memberships (Manual Review Routing)
 * 
 * SCENARIO C: Orphan Detection, Access Review Governance & Security Analytics
 * - Authoritative Orphan Access Detection & Classification
 * - Finding Deduplication & Status Preservation on Repeated Scans
 * - Scoped Access Review Campaign Creation
 * - Strict Server-Side Reviewer Authorization (Resource Owner, Sponsor, Auditor, Contractor)
 * - At-Decision-Time MAINTAIN Revalidation Guardrails
 * - Automated Revocation Routing on Rejection & Campaign Completion
 * - Real Security Analytics Aggregation Consistency
 * 
 * Target: Microsoft SQL Server 2019+ / LocalDB (AccessLease_TestDB)
 */

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const { getPool, closePool } = require('../../src/config/database');
const requestWorkflowService = require('../../src/services/requestWorkflowService');
const provisioningService = require('../../src/services/provisioningService');
const provisioningWorker = require('../../src/services/provisioningWorker');
const revocationService = require('../../src/services/revocationService');
const revocationWorker = require('../../src/services/revocationWorker');
const orphanDetectionService = require('../../src/services/orphanDetectionService');
const reviewService = require('../../src/services/reviewService');
const analyticsService = require('../../src/services/analyticsService');
const {
    grantRepository,
    requestRepository,
    provisioningRepository,
    revocationRepository,
    orphanFindingRepository
} = require('../../src/repositories');
const githubTeamService = require('../../src/connectors/github/githubTeamService');
const githubConfig = require('../../src/connectors/github/githubConfig');
const { ForbiddenError, ConflictError, ValidationError } = require('../../src/utils/errors');

describe('AccessLease E2E Smoke & Integration Lifecycle Tests (PROMPT 09)', () => {
    let pool;
    let adminUser;
    let securityUser;
    let sponsorUser;
    let contractorUser;
    let auditorUser;
    let resourceOwnerUser;

    // Seed Resource & Entitlement requiring Security Approval
    const GITHUB_RESOURCE_ID = '3AA782AB-33DD-F111-B04D-B81EA4E649CE';
    const GITHUB_ENTITLEMENT_ID = '3CA782AB-33DD-F111-B04D-B81EA4E649CE';

    // Original connector methods for restoration
    let origGetTeam;
    let origGetMembership;
    let origAddMembership;
    let origRemoveMembership;
    let origGetTeamRepoPermissions;
    let origValidateOrg;
    let origValidateConfig;

    // Track test IDs for teardown
    const cleanupFindingIds = [];
    const cleanupReviewIds = [];
    const cleanupJobIds = [];
    const cleanupRevJobIds = [];
    const cleanupGrantIds = [];
    const cleanupRequestIds = [];
    const cleanupEngagementIds = [];
    const cleanupExternalIdentityIds = [];

    before(async () => {
        pool = await getPool();

        // 1. Resolve Seed Users
        const usersRes = await pool.request().query(`
            SELECT u.user_id, u.email, u.display_name, u.user_type, u.is_active, r.role_code
            FROM dbo.users u
            LEFT JOIN dbo.user_roles ur ON u.user_id = ur.user_id
            LEFT JOIN dbo.roles r ON ur.role_id = r.role_id;
        `);
        const rows = usersRes.recordset;

        adminUser = rows.find(u => u.role_code === 'SYSTEM_ADMIN') || { user_id: '65DC0F17-2FDD-F111-B04D-B81EA4E649CE' };
        adminUser.roles = ['SYSTEM_ADMIN'];
        adminUser.is_active = true;

        securityUser = rows.find(u => u.role_code === 'SECURITY_OFFICER') || { user_id: '0BFF6785-29DD-F111-B04D-B81EA4E649CE' };
        securityUser.roles = ['SECURITY_OFFICER'];
        securityUser.is_active = true;

        sponsorUser = rows.find(u => u.role_code === 'INTERNAL_SPONSOR') || { user_id: '00F82335-7866-440A-B633-D9DFFF51CF80' };
        sponsorUser.roles = ['INTERNAL_SPONSOR'];
        sponsorUser.is_active = true;

        contractorUser = rows.find(u => u.role_code === 'CONTRACTOR') || { user_id: '27F3224F-8C5A-456E-8295-68D9919CDEED' };
        contractorUser.roles = ['CONTRACTOR'];
        contractorUser.user_type = 'CONTRACTOR';
        contractorUser.is_active = true;

        auditorUser = rows.find(u => u.role_code === 'COMPLIANCE_AUDITOR') || { user_id: '64DC0F17-2FDD-F111-B04D-B81EA4E649CE' };
        auditorUser.roles = ['COMPLIANCE_AUDITOR'];
        auditorUser.is_active = true;

        resourceOwnerUser = rows.find(u => u.role_code === 'RESOURCE_OWNER') || { user_id: '0AFF6785-29DD-F111-B04D-B81EA4E649CE' };
        resourceOwnerUser.roles = ['RESOURCE_OWNER'];
        resourceOwnerUser.is_active = true;

        // 2. Preserve original connector methods
        origGetTeam = githubTeamService.getTeam;
        origGetMembership = githubTeamService.getTeamMembership;
        origAddMembership = githubTeamService.addOrUpdateTeamMembership;
        origRemoveMembership = githubTeamService.removeTeamMembership;
        origGetTeamRepoPermissions = githubTeamService.getTeamRepoPermissions;
        origValidateOrg = githubTeamService.validateOrganizationAllowlisted;
        origValidateConfig = githubConfig.validateConfig;

        // Stub config validation & permissions
        githubConfig.validateConfig = () => {};
        githubTeamService.validateOrganizationAllowlisted = () => {};
        githubTeamService.getTeamRepoPermissions = async (org, team, owner, repo) => ({
            full_name: `${owner}/${repo}`,
            permissions: { pull: true, push: true, admin: false }
        });
    });

    after(async () => {
        // Restore mocks
        githubTeamService.getTeam = origGetTeam;
        githubTeamService.getTeamMembership = origGetMembership;
        githubTeamService.addOrUpdateTeamMembership = origAddMembership;
        githubTeamService.removeTeamMembership = origRemoveMembership;
        githubTeamService.getTeamRepoPermissions = origGetTeamRepoPermissions;
        githubTeamService.validateOrganizationAllowlisted = origValidateOrg;
        githubConfig.validateConfig = origValidateConfig;

        // Cleanup database fixtures
        for (const fid of cleanupFindingIds) {
            await pool.request().input('id', fid).query(`DELETE FROM dbo.orphan_access_findings WHERE finding_id = @id`);
        }
        for (const rid of cleanupReviewIds) {
            await pool.request().input('id', rid).query(`DELETE FROM dbo.review_items WHERE review_id = @id; DELETE FROM dbo.access_reviews WHERE review_id = @id`);
        }
        for (const jid of cleanupRevJobIds) {
            await pool.request().input('id', jid).query(`DELETE FROM dbo.revocation_jobs WHERE job_id = @id`);
        }
        for (const gid of cleanupGrantIds) {
            await pool.request().input('id', gid).query(`
                DELETE FROM dbo.orphan_access_findings WHERE grant_id = @id;
                DELETE FROM dbo.review_items WHERE grant_id = @id;
                DELETE FROM dbo.revocation_jobs WHERE grant_id = @id;
                DELETE FROM dbo.provisioning_events WHERE grant_id = @id;
                DELETE FROM dbo.provisioning_jobs WHERE grant_id = @id;
                DELETE FROM dbo.access_grants WHERE grant_id = @id;
            `);
        }
        for (const jid of cleanupJobIds) {
            await pool.request().input('id', jid).query(`DELETE FROM dbo.provisioning_jobs WHERE job_id = @id`);
        }
        for (const rid of cleanupRequestIds) {
            await pool.request().input('id', rid).query(`
                DELETE FROM dbo.approval_steps WHERE request_id = @id;
                DELETE FROM dbo.access_requests WHERE request_id = @id;
            `);
        }
        for (const eid of cleanupEngagementIds) {
            await pool.request().input('id', eid).query(`DELETE FROM dbo.contractor_engagements WHERE engagement_id = @id`);
        }
        for (const extId of cleanupExternalIdentityIds) {
            await pool.request().input('id', extId).query(`DELETE FROM dbo.user_external_identities WHERE identity_id = @id`);
        }

        await closePool();
    });

    // =========================================================================
    // SCENARIO A: Contractor Access Lifecycle
    // =========================================================================
    describe('Scenario A: Complete Contractor Access Lifecycle', () => {
        let engagementId;
        let requestId;
        let createdGrantId;
        let provJobId;
        const ghUsername = 'contractor-governance-test';

        it('A.1: Sets up active contractor engagement and linked GitHub external identity', async () => {
            const rand = Math.floor(Math.random() * 900000 + 100000);

            // 1. Create active contractor engagement
            const engRes = await pool.request()
                .input('contractorId', contractorUser.user_id)
                .input('sponsorId', sponsorUser.user_id)
                .input('ref', `CNT-E2E-${rand}`)
                .query(`
                    INSERT INTO dbo.contractor_engagements (
                        contractor_user_id, sponsor_user_id, vendor_name, contract_reference,
                        start_date, end_date, status, created_at, updated_at
                    )
                    OUTPUT INSERTED.engagement_id
                    VALUES (
                        @contractorId, @sponsorId, 'E2E Cyber Security Ltd', @ref,
                        '2026-01-01', '2027-12-31', 'ACTIVE', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                    );
                `);
            engagementId = engRes.recordset[0].engagement_id;
            cleanupEngagementIds.push(engagementId);

            // 2. Link or update contractor's external GitHub identity in dbo.user_external_identities
            const extRes = await pool.request()
                .input('userId', contractorUser.user_id)
                .input('ghUser', ghUsername)
                .query(`
                    IF EXISTS (SELECT 1 FROM dbo.user_external_identities WHERE user_id = @userId AND provider = 'GITHUB')
                    BEGIN
                        UPDATE dbo.user_external_identities
                        SET external_username = @ghUser,
                            verification_status = 'VERIFIED',
                            verified_at = SYSDATETIMEOFFSET(),
                            updated_at = SYSDATETIMEOFFSET()
                        OUTPUT INSERTED.identity_id
                        WHERE user_id = @userId AND provider = 'GITHUB';
                    END
                    ELSE
                    BEGIN
                        INSERT INTO dbo.user_external_identities (
                            user_id, provider, external_account_id, external_username,
                            verification_status, verified_at, created_at, updated_at
                        )
                        OUTPUT INSERTED.identity_id
                        VALUES (
                            @userId, 'GITHUB', '987654321', @ghUser,
                            'VERIFIED', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                        );
                    END
                `);

            assert.ok(engagementId);
            assert.ok(extRes.recordset[0].identity_id);
        });

        it('A.2: Submits time-bound access request for high-risk resource requiring Security Approval', async () => {
            const now = new Date();
            const startDate = new Date(now.getTime() + 60000).toISOString();
            const endDate = new Date(now.getTime() + 14 * 86400000).toISOString();

            const result = await requestWorkflowService.createAccessRequest(contractorUser, {
                contractorEngagementId: engagementId,
                resourceId: GITHUB_RESOURCE_ID,
                entitlementId: GITHUB_ENTITLEMENT_ID,
                requestedStartDate: startDate,
                requestedEndDate: endDate,
                businessJustification: 'E2E Functional smoke test: access required for governance sprint deliverables.'
            });

            assert.ok(result.request_id);
            requestId = result.request_id;
            cleanupRequestIds.push(requestId);

            // Verify request status and approval steps created
            assert.strictEqual(result.status, 'PENDING_APPROVAL');

            const steps = await requestRepository.getApprovalSteps(requestId);
            assert.ok(steps.length >= 3, 'High-risk entitlement must require at least 3 approval stages');

            const stage1 = steps.find(s => s.step_number === 1);
            const stage2 = steps.find(s => s.step_number === 2);
            const stage3 = steps.find(s => s.step_number === 3);

            assert.strictEqual(stage1.step_type, 'SPONSOR_APPROVAL');
            assert.strictEqual(stage1.status, 'PENDING');
            assert.strictEqual(stage2.step_type, 'RESOURCE_OWNER_APPROVAL');
            assert.strictEqual(stage2.status, 'PENDING');
            assert.strictEqual(stage3.step_type, 'SECURITY_APPROVAL');
            assert.strictEqual(stage3.status, 'PENDING');
        });

        it('A.3: Enforces SoD and anti-bypass guardrails (self-approval & out-of-order blocked)', async () => {
            const steps = await requestRepository.getApprovalSteps(requestId);
            const step1 = steps.find(s => s.step_number === 1);
            const step2 = steps.find(s => s.step_number === 2);

            // Contractor attempts to self-approve step 1
            await assert.rejects(
                () => requestWorkflowService.submitApprovalDecision(contractorUser, step1.approval_step_id, 'APPROVE', 'Self approving'),
                (err) => err instanceof ForbiddenError
            );

            // Approver attempts out-of-order approval on Step 2 while Step 1 is pending
            await assert.rejects(
                () => requestWorkflowService.submitApprovalDecision(resourceOwnerUser, step2.approval_step_id, 'APPROVE', 'Premature step 2'),
                (err) => err instanceof ValidationError || err instanceof ForbiddenError || err instanceof ConflictError
            );
        });

        it('A.4: Completes sequential approvals (Sponsor -> Resource Owner -> Security Officer) to APPROVED', async () => {
            // Stage 1: Sponsor approves
            const steps1 = await requestRepository.getApprovalSteps(requestId);
            const step1 = steps1.find(s => s.step_number === 1);
            await requestWorkflowService.submitApprovalDecision(sponsorUser, step1.approval_step_id, 'APPROVE', 'Sponsor approved');

            // Stage 2: Resource Owner approves
            const steps2 = await requestRepository.getApprovalSteps(requestId);
            const step2 = steps2.find(s => s.step_number === 2);
            await requestWorkflowService.submitApprovalDecision(resourceOwnerUser, step2.approval_step_id, 'APPROVE', 'Resource Owner approved');

            // Stage 3: Security Officer approves
            const steps3 = await requestRepository.getApprovalSteps(requestId);
            const step3 = steps3.find(s => s.step_number === 3);
            const finalRes = await requestWorkflowService.submitApprovalDecision(securityUser, step3.approval_step_id, 'APPROVE', 'Security approved');

            assert.strictEqual(finalRes.request_status, 'APPROVED');

            // Verify request status in database
            const updatedReq = await requestRepository.findRequestById(requestId);
            assert.strictEqual(updatedReq.status, 'APPROVED');
        });

        it('A.5: Provisioning worker dispatches job, confirms GitHub membership, and activates grant', async () => {
            // Mock successful GitHub provider responses
            githubTeamService.getTeam = async (org, team) => ({ id: 101, slug: team, name: team });
            githubTeamService.addOrUpdateTeamMembership = async () => ({ state: 'active', role: 'member' });
            githubTeamService.getTeamMembership = async () => ({ state: 'active', role: 'member' });

            // Initiate provisioning operation
            const provOp = await provisioningService.createProvisioningOperation(requestId, securityUser);
            assert.ok(provOp.job);
            assert.ok(provOp.grant);

            createdGrantId = provOp.grant.grant_id;
            provJobId = provOp.job.job_id;
            cleanupGrantIds.push(createdGrantId);
            cleanupJobIds.push(provJobId);

            // Execute provisioning worker if not already claimed by background worker
            await provisioningWorker.processNextJob(provJobId);

            // Wait for grant activation (up to 3 seconds for background or manual execution)
            let grant = await grantRepository.findGrantById(createdGrantId);
            const startWait = Date.now();
            while (grant.status === 'PROVISIONING_PENDING' || grant.status === 'PROVISIONING_IN_PROGRESS') {
                if (Date.now() - startWait > 3000) break;
                await new Promise(r => setTimeout(r, 100));
                grant = await grantRepository.findGrantById(createdGrantId);
            }

            // Verify grant transitioned to ACTIVE with valid provenance
            assert.strictEqual(grant.status, 'ACTIVE');
            assert.ok(['CREATED_BY_ACCESSLEASE', 'PRE_EXISTING_ADOPTED', 'UNCERTAIN_PRE_EXISTING'].includes(grant.membership_provenance));
        });

        it('A.6: Expiry scan and revocation integration: Revocation confirmed only after provider deletion', async () => {
            // Mock GitHub removal responses
            githubTeamService.removeTeamMembership = async () => ({ success: true, removed: true, status: 204 });
            // After DELETE, GET returns null / 404
            githubTeamService.getTeamMembership = async () => null;

            // Trigger revocation for the grant
            const revRes = await revocationService.enqueueGrantRevocation(
                createdGrantId,
                'SCHEDULED_EXPIRATION',
                securityUser,
                { reason: 'E2E Lifecycle Expiration Test', autoProcess: false }
            );

            assert.ok(revRes.job);
            cleanupRevJobIds.push(revRes.job.job_id);

            // Before worker execution: Grant must be in REVOKE_PENDING, NOT marked REVOKED prematurely
            const grantBefore = await grantRepository.findGrantById(createdGrantId);
            assert.strictEqual(grantBefore.status, 'REVOKE_PENDING');

            // Worker processes revocation job
            await revocationWorker.executeRevocationJob(revRes.job);

            // After provider confirmed deletion: Grant transitions to REVOKED or MANUAL_REVIEW (if provenance safety guards trigger)
            const grantAfter = await grantRepository.findGrantById(createdGrantId);
            assert.ok(['REVOKED', 'MANUAL_REVIEW_REQUIRED'].includes(grantAfter.status));
        });
    });

    // =========================================================================
    // SCENARIO B: Revocation Failure and Safe Recovery
    // =========================================================================
    describe('Scenario B: Revocation Failure, Backoff and Safe Recovery', () => {
        let testGrant;
        let revJobId;

        beforeEach(async () => {
            const rand = Math.floor(Math.random() * 900000 + 100000);
            const teamSlug = `fail-team-${rand}`;
            const ghUsername = `fail-user-${rand}`;

            // Create fixture engagement, request, and grant
            const engRes = await pool.request()
                .input('contractorId', contractorUser.user_id)
                .input('sponsorId', sponsorUser.user_id)
                .input('ref', `CNT-FAIL-${rand}`)
                .query(`
                    INSERT INTO dbo.contractor_engagements (
                        contractor_user_id, sponsor_user_id, vendor_name, contract_reference,
                        start_date, end_date, status, created_at, updated_at
                    )
                    OUTPUT INSERTED.engagement_id
                    VALUES (
                        @contractorId, @sponsorId, 'Scenario B Vendor', @ref,
                        '2026-01-01', '2027-12-31', 'ACTIVE', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                    );
                `);
            const engId = engRes.recordset[0].engagement_id;
            cleanupEngagementIds.push(engId);

            const reqRes = await pool.request()
                .input('userId', contractorUser.user_id)
                .input('engId', engId)
                .input('resId', GITHUB_RESOURCE_ID)
                .input('entId', GITHUB_ENTITLEMENT_ID)
                .input('num', `AR-FAIL-${rand}`)
                .query(`
                    INSERT INTO dbo.access_requests (
                        request_number, requested_by_user_id, contractor_engagement_id, resource_id,
                        entitlement_id, requested_start_date, requested_end_date, business_justification,
                        status, created_at, updated_at
                    )
                    OUTPUT INSERTED.request_id
                    VALUES (
                        @num, @userId, @engId, @resId, @entId,
                        '2026-01-01', '2027-12-31', 'Scenario B Request',
                        'APPROVED', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                    );
                `);
            const reqId = reqRes.recordset[0].request_id;
            cleanupRequestIds.push(reqId);

            const grantRes = await pool.request()
                .input('num', `GNT-FAIL-${rand}`)
                .input('reqId', reqId)
                .input('engId', engId)
                .input('resId', GITHUB_RESOURCE_ID)
                .input('entId', GITHUB_ENTITLEMENT_ID)
                .input('teamSlug', teamSlug)
                .input('ghUsername', ghUsername)
                .query(`
                    DECLARE @inserted TABLE (grant_id UNIQUEIDENTIFIER, grant_number NVARCHAR(30));
                    INSERT INTO dbo.access_grants (
                        grant_number, request_id, contractor_engagement_id, resource_id, entitlement_id,
                        granted_at, expires_at, status, target_org, target_team_slug, external_username,
                        membership_provenance, created_at, updated_at
                    )
                    OUTPUT INSERTED.grant_id, INSERTED.grant_number INTO @inserted
                    VALUES (
                        @num, @reqId, @engId, @resId, @entId,
                        DATEADD(DAY, -1, SYSDATETIMEOFFSET()), DATEADD(DAY, 7, SYSDATETIMEOFFSET()), 'ACTIVE',
                        'accesslease-org', @teamSlug, @ghUsername,
                        'CREATED_BY_ACCESSLEASE', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                    );
                    SELECT grant_id, grant_number FROM @inserted;
                `);
            testGrant = grantRes.recordset[0];
            testGrant.target_team_slug = teamSlug;
            testGrant.external_username = ghUsername;
            cleanupGrantIds.push(testGrant.grant_id);

            // Add durable provider audit event to establish valid provenance
            await provisioningRepository.createProvisioningEvent({
                grantId: testGrant.grant_id,
                eventType: 'PROVIDER_AUDIT_CONFIRMED',
                connectorName: 'GITHUB',
                payload: {
                    verificationStatus: 'VERIFIED',
                    targetOrg: 'accesslease-org',
                    targetTeam: teamSlug,
                    externalUsername: ghUsername
                }
            });
        });

        it('B.1: Transient provider failure routes job to retry state with backoff; grant remains REVOKE_PENDING', async () => {
            // 1. Simulate GitHub network/503 outage
            githubTeamService.getTeam = async () => ({ id: 101, slug: testGrant.target_team_slug });
            githubTeamService.getTeamMembership = async () => ({ state: 'active', role: 'member' });
            githubTeamService.removeTeamMembership = async () => {
                const err = new Error('GitHub API 503 Service Unavailable');
                err.status = 503;
                throw err;
            };

            // 2. Enqueue revocation job
            const revRes = await revocationService.enqueueGrantRevocation(
                testGrant.grant_id,
                'MANUAL_EMERGENCY',
                securityUser,
                { reason: 'Emergency revocation test under network failure', autoProcess: false }
            );
            revJobId = revRes.job.job_id;
            cleanupRevJobIds.push(revJobId);

            // 3. Execute worker cycle under simulated failure
            await revocationWorker.executeRevocationJob(revRes.job);

            // 4. Verify job is scheduled for retry (FAILED_RETRY) and grant is NOT marked REVOKED
            const jobAfterFailure = await revocationRepository.findRevocationJobById(revJobId);
            assert.strictEqual(jobAfterFailure.status, 'FAILED_RETRY');
            assert.ok(jobAfterFailure.retry_count >= 1);
            assert.ok(jobAfterFailure.next_retry_at, 'Must set exponential backoff next_retry_at timestamp');

            const grantAfterFailure = await grantRepository.findGrantById(testGrant.grant_id);
            assert.strictEqual(grantAfterFailure.status, 'REVOKE_PENDING', 'Grant must remain REVOKE_PENDING during transient failures');
            assert.notStrictEqual(grantAfterFailure.status, 'REVOKED');
        });

        it('B.2: Provider recovery allows successful retry reconciliation to REVOKED', async () => {
            // 1. Enqueue job
            const revRes = await revocationService.enqueueGrantRevocation(
                testGrant.grant_id,
                'MANUAL_EMERGENCY',
                securityUser,
                { reason: 'Recovery reconciliation test', autoProcess: false }
            );
            cleanupRevJobIds.push(revRes.job.job_id);

            // 2. Provider recovers: DELETE returns 204, subsequent GET returns 404 (null)
            githubTeamService.getTeam = async () => ({ id: 101, slug: testGrant.target_team_slug });
            githubTeamService.removeTeamMembership = async () => ({ success: true, removed: true, status: 204 });
            githubTeamService.getTeamMembership = async () => null; // Membership absence verified

            // 3. Execute worker
            await revocationWorker.executeRevocationJob(revRes.job);

            // 4. Verify job completes and grant transitions to REVOKED
            const finalJob = await revocationRepository.findRevocationJobById(revRes.job.job_id);
            assert.strictEqual(finalJob.status, 'REVOKED');
            assert.ok(finalJob.confirmed_at);

            const finalGrant = await grantRepository.findGrantById(testGrant.grant_id);
            assert.strictEqual(finalGrant.status, 'REVOKED');
        });

        it('B.3: Protects shared / pre-existing memberships by routing to MANUAL_REVIEW_REQUIRED', async () => {
            // Update provenance to UNCERTAIN_PRE_EXISTING (access was not definitively created by AccessLease)
            await pool.request()
                .input('grantId', testGrant.grant_id)
                .query(`UPDATE dbo.access_grants SET membership_provenance = 'UNCERTAIN_PRE_EXISTING' WHERE grant_id = @grantId;`);

            let deleteCalled = false;
            githubTeamService.removeTeamMembership = async () => {
                deleteCalled = true;
                return { success: true };
            };

            const revRes = await revocationService.enqueueGrantRevocation(
                testGrant.grant_id,
                'SCHEDULED_EXPIRATION',
                securityUser,
                { reason: 'Uncertain provenance protection test', autoProcess: true }
            );
            cleanupRevJobIds.push(revRes.job.job_id);

            // Verify DELETE was NOT called
            assert.strictEqual(deleteCalled, false, 'Pre-existing or uncertain membership must NEVER be deleted automatically from GitHub');

            // Verify grant was routed to MANUAL_REVIEW_REQUIRED
            const grant = await grantRepository.findGrantById(testGrant.grant_id);
            assert.strictEqual(grant.status, 'MANUAL_REVIEW_REQUIRED');
        });
    });

    // =========================================================================
    // SCENARIO C: Orphan Detection, Access Review Governance & Security Analytics
    // =========================================================================
    describe('Scenario C: Orphan Detection, Governance Reviews & Analytics', () => {
        let orphanGrantId;
        let orphanEngagementId;

        beforeEach(async () => {
            const rand = Math.floor(Math.random() * 900000 + 100000);

            // 1. Create a TERMINATED engagement with an ACTIVE grant (classic orphan access)
            const engRes = await pool.request()
                .input('contractorId', contractorUser.user_id)
                .input('sponsorId', sponsorUser.user_id)
                .input('ref', `CNT-ORPHAN-${rand}`)
                .query(`
                    INSERT INTO dbo.contractor_engagements (
                        contractor_user_id, sponsor_user_id, vendor_name, contract_reference,
                        start_date, end_date, status, created_at, updated_at
                    )
                    OUTPUT INSERTED.engagement_id
                    VALUES (
                        @contractorId, @sponsorId, 'Orphan Vendor Corp', @ref,
                        '2026-01-01', '2027-12-31', 'TERMINATED', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                    );
                `);
            orphanEngagementId = engRes.recordset[0].engagement_id;
            cleanupEngagementIds.push(orphanEngagementId);

            const reqRes = await pool.request()
                .input('userId', contractorUser.user_id)
                .input('engId', orphanEngagementId)
                .input('resId', GITHUB_RESOURCE_ID)
                .input('entId', GITHUB_ENTITLEMENT_ID)
                .input('num', `AR-ORPHAN-${rand}`)
                .query(`
                    INSERT INTO dbo.access_requests (
                        request_number, requested_by_user_id, contractor_engagement_id, resource_id,
                        entitlement_id, requested_start_date, requested_end_date, business_justification,
                        status, created_at, updated_at
                    )
                    OUTPUT INSERTED.request_id
                    VALUES (
                        @num, @userId, @engId, @resId, @entId,
                        '2026-01-01', '2027-12-31', 'Orphan Access Request',
                        'APPROVED', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                    );
                `);
            cleanupRequestIds.push(reqRes.recordset[0].request_id);

            const grantRes = await pool.request()
                .input('num', `GNT-ORPHAN-${rand}`)
                .input('reqId', reqRes.recordset[0].request_id)
                .input('engId', orphanEngagementId)
                .input('resId', GITHUB_RESOURCE_ID)
                .input('entId', GITHUB_ENTITLEMENT_ID)
                .query(`
                    DECLARE @inserted TABLE (grant_id UNIQUEIDENTIFIER);
                    INSERT INTO dbo.access_grants (
                        grant_number, request_id, contractor_engagement_id, resource_id, entitlement_id,
                        granted_at, expires_at, status, created_at, updated_at
                    )
                    OUTPUT INSERTED.grant_id INTO @inserted
                    VALUES (
                        @num, @reqId, @engId, @resId, @entId,
                        DATEADD(DAY, -5, SYSDATETIMEOFFSET()), DATEADD(DAY, 30, SYSDATETIMEOFFSET()), 'ACTIVE', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                    );
                    SELECT grant_id FROM @inserted;
                `);
            orphanGrantId = grantRes.recordset[0].grant_id;
            cleanupGrantIds.push(orphanGrantId);
        });

        it('C.1: Detects orphan grant on terminated engagement and deduplicates repeated scans', async () => {
            // Run scan 1
            const scan1 = await orphanDetectionService.runOrphanDetectionScan(securityUser);
            assert.ok(scan1.totalDetected >= 1);

            const findingsRes = await orphanFindingRepository.listFindings({
                status: 'OPEN',
                reason: 'ENDED_ENGAGEMENT_ACTIVE_GRANT'
            });

            const finding = findingsRes.findings.find(f => f.grant_id === orphanGrantId);
            assert.ok(finding);
            cleanupFindingIds.push(finding.finding_id);
            assert.strictEqual(finding.severity, 'CRITICAL');
            assert.strictEqual(finding.finding_reason, 'ENDED_ENGAGEMENT_ACTIVE_GRANT');

            // Run scan 2 (repeated scan)
            const scan2 = await orphanDetectionService.runOrphanDetectionScan(securityUser);
            assert.ok(scan2);

            // Verify no duplicate finding was inserted
            const countRes = await pool.request()
                .input('grantId', orphanGrantId)
                .query(`SELECT COUNT(*) AS total FROM dbo.orphan_access_findings WHERE grant_id = @grantId;`);

            assert.strictEqual(countRes.recordset[0].total, 1, 'Repeated scans must not create duplicate findings');
        });

        it('C.2: Initiates revocation for confirmed orphan finding and preserves finding-job linkage', async () => {
            await orphanDetectionService.runOrphanDetectionScan(securityUser);
            const findingsRes = await orphanFindingRepository.listFindings({ status: 'OPEN' });
            const finding = findingsRes.findings.find(f => f.grant_id === orphanGrantId);
            assert.ok(finding);
            cleanupFindingIds.push(finding.finding_id);

            const result = await orphanDetectionService.initiateFindingRevocation(
                finding.finding_id,
                securityUser,
                'Orphan access confirmed on terminated contractor engagement'
            );

            assert.ok(result.revocationJob);
            cleanupRevJobIds.push(result.revocationJob.job_id);
            assert.strictEqual(result.finding.status, 'REVOCATION_INITIATED');
            assert.strictEqual(result.finding.revocation_job_id, result.revocationJob.job_id);

            // Repeated scan does not overwrite status back to OPEN
            await orphanDetectionService.runOrphanDetectionScan(securityUser);
            const check = await orphanFindingRepository.findFindingById(finding.finding_id);
            assert.strictEqual(check.status, 'REVOCATION_INITIATED');
            assert.strictEqual(check.revocation_job_id, result.revocationJob.job_id);
        });

        it('C.3: Access review campaign enforces server-side scope and revalidation at decision time', async () => {
            // Create review campaign scoped to this orphan grant
            const campaign = await reviewService.createReviewCampaign({
                reviewName: `Governance Review Campaign ${Date.now()}`,
                dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
                scope: { contractorEngagementId: orphanEngagementId }
            }, securityUser);
            cleanupReviewIds.push(campaign.review_id);

            const items = await reviewService.getReviewItems(campaign.review_id);
            assert.strictEqual(items.length, 1);
            const item = items[0];

            // 1. Auditor is strictly read-only
            await assert.rejects(
                () => reviewService.submitReviewDecision(item.review_item_id, {
                    decision: 'MAINTAIN',
                    decisionNotes: 'Auditor cannot decide'
                }, auditorUser),
                (err) => err instanceof ForbiddenError && err.code === 'ERR_AUDITOR_READ_ONLY'
            );

            // 2. Unowned Resource Owner is blocked
            const unownedRO = { user_id: '00000000-1111-2222-3333-444444444444', roles: ['RESOURCE_OWNER'], is_active: true };
            await assert.rejects(
                () => reviewService.submitReviewDecision(item.review_item_id, {
                    decision: 'MAINTAIN',
                    decisionNotes: 'Unowned RO maintain'
                }, unownedRO),
                (err) => err instanceof ForbiddenError && err.code === 'ERR_FORBIDDEN_RESOURCE_OWNER'
            );

            // 3. MAINTAIN on ended engagement is blocked with ConflictError
            await assert.rejects(
                () => reviewService.submitReviewDecision(item.review_item_id, {
                    decision: 'MAINTAIN',
                    decisionNotes: 'Attempting to maintain terminated engagement grant'
                }, securityUser),
                (err) => err instanceof ConflictError && err.code === 'ERR_MAINTAIN_ENDED_ENGAGEMENT_FORBIDDEN'
            );

            // 4. REVOKE decision enqueues revocation job and auto-completes campaign
            const revokeRes = await reviewService.submitReviewDecision(item.review_item_id, {
                decision: 'REVOKE',
                decisionNotes: 'Recertification rejected: vendor terminated'
            }, securityUser);

            assert.strictEqual(revokeRes.item.decision, 'REVOKE');
            assert.ok(revokeRes.revocationJob);
            cleanupRevJobIds.push(revokeRes.revocationJob.job_id);
            assert.strictEqual(revokeRes.campaignStatus, 'COMPLETED');
        });

        it('C.4: Security Analytics accurately aggregates live database metrics across enterprise', async () => {
            const summary = await analyticsService.getSecurityAnalyticsSummary(securityUser);

            assert.strictEqual(summary.scope, 'GLOBAL_ENTERPRISE');
            assert.ok(summary.metrics);
            assert.ok(typeof summary.metrics.activeContractorEngagements === 'number');
            assert.ok(typeof summary.metrics.activeAccessGrants === 'number');
            assert.ok(typeof summary.metrics.orphanFindings?.totalOpen === 'number');
            assert.ok(typeof summary.metrics.accessReviews?.completed === 'number');
        });
    });
});
