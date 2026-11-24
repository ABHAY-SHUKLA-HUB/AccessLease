/**
 * AccessLease — Worker Integrity, Crash Recovery & GitHub Identity Linking Test Suite
 * (PROMPT 06.2 Hardening Verification against LocalDB)
 */

process.env.NODE_ENV = 'test';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const { getPool, closePool, withTransaction } = require('../../src/config/database');
const provisioningRepository = require('../../src/repositories/provisioningRepository');
const grantRepository = require('../../src/repositories/grantRepository');
const userExternalIdentityRepository = require('../../src/repositories/userExternalIdentityRepository');
const auditRepository = require('../../src/repositories/auditRepository');
const oauthStateRepository = require('../../src/repositories/oauthStateRepository');
const githubOAuthService = require('../../src/connectors/github/githubOAuthService');
const githubVerificationService = require('../../src/connectors/github/githubVerificationService');
const { isSafeForAutomatedRevocation } = require('../../src/services/provisioningService');
const { initiateGitHubLinkHandler, callbackGitHubLinkHandler, unlinkGitHubHandler, manualVerifyIdentityHandler } = require('../../src/functions/contractors');
const { createIsolatedGrantFixture } = require('../helpers/testFixtureUtils');

describe('Hardening: Worker Integrity, Crash Recovery & Identity Linking (PROMPT 06.2)', () => {
    let pool;
    let testRequestId;
    let testContractorId;
    let testIsolatedContractorId;
    let testAdminId;
    let testSponsorId;

    before(async () => {
        pool = await getPool();

        // Resolve seeded test users
        const contractorUser = await pool.request()
            .input('oid', 'TEST-OID-CONTRACTOR')
            .query("SELECT user_id FROM dbo.users WHERE entra_object_id = @oid;");
        testContractorId = contractorUser.recordset[0].user_id;

        const adminUser = await pool.request()
            .input('oid', 'TEST-OID-ADMIN')
            .query("SELECT user_id FROM dbo.users WHERE entra_object_id = @oid;");
        testAdminId = adminUser.recordset[0].user_id;

        const sponsorUser = await pool.request()
            .input('oid', 'TEST-OID-SPONSOR')
            .query("SELECT user_id FROM dbo.users WHERE entra_object_id = @oid;");
        testSponsorId = sponsorUser.recordset[0].user_id;

        // Create an isolated contractor user for identity linking tests to prevent mutating seeded users
        await pool.request().query(`
            IF NOT EXISTS (SELECT 1 FROM dbo.users WHERE entra_object_id = 'TEST-HARDENING-CONTRACTOR-OID')
            BEGIN
                INSERT INTO dbo.users (entra_object_id, first_name, last_name, display_name, email, user_type, is_active)
                VALUES ('TEST-HARDENING-CONTRACTOR-OID', 'Hardening', 'Contractor', 'Hardening Contractor', 'hardening@example.com', 'CONTRACTOR', 1);
            END;
        `);
        const userRes = await pool.request().query("SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-HARDENING-CONTRACTOR-OID';");
        testIsolatedContractorId = userRes.recordset[0].user_id;

        // Resolve a valid request_id for testing foreign keys
        const reqResult = await pool.request()
            .query("SELECT TOP 1 request_id FROM dbo.access_requests WHERE status IN ('APPROVED', 'PENDING_APPROVAL');");
        testRequestId = reqResult.recordset[0].request_id;
    });

    after(async () => {
        // Clean up test identities and jobs created during this suite
        if (pool) {
            await pool.request().query(`
                DELETE FROM dbo.provisioning_jobs WHERE idempotency_key LIKE 'TEST-HARDENING-%';
                DELETE FROM dbo.audit_events WHERE entity_id IN (SELECT identity_id FROM dbo.user_external_identities WHERE user_id = '${testIsolatedContractorId}');
                DELETE FROM dbo.user_external_identities WHERE user_id = '${testIsolatedContractorId}' OR external_username LIKE 'test-hardening-%';
                DELETE FROM dbo.users WHERE entra_object_id = 'TEST-HARDENING-CONTRACTOR-OID';
            `);
        }
        await closePool();
    });

    // -------------------------------------------------------------------------
    // 1. Database and Worker Column & Status Reconciliation
    // -------------------------------------------------------------------------
    it('1. Reconciles canonical column names and aliases (job_status/status, lease_expires_at/locked_until)', async () => {
        const idempotencyKey = `TEST-HARDENING-RECON-${Date.now()}`;
        const job = await provisioningRepository.createProvisioningJob({
            requestId: testRequestId,
            connectorType: 'GITHUB',
            targetResource: 'AccessLease-Test-Org/team-a',
            idempotencyKey,
            jobStatus: 'QUEUED',
            maxAttempts: 3
        });

        // Canonical names exist
        assert.strictEqual(job.job_status, 'QUEUED');
        assert.ok('lease_expires_at' in job);
        assert.ok('lease_owner' in job);

        // Aliases exist without duplicate DB columns
        assert.strictEqual(job.status, 'QUEUED');
        assert.strictEqual(job.locked_until, job.lease_expires_at);
        assert.strictEqual(job.locked_by, job.lease_owner);

        // Cleanup
        await pool.request().query(`DELETE FROM dbo.provisioning_jobs WHERE job_id = '${job.job_id}';`);
    });

    // -------------------------------------------------------------------------
    // 2. Crash Recovery & Expired Lease Reclaiming
    // -------------------------------------------------------------------------
    it('2. Crash Recovery: Automatically reclaims a job stuck in PROCESSING when worker lease expires', async () => {
        const idempotencyKey = `TEST-HARDENING-CRASH-${Date.now()}`;
        
        // Insert a simulated job abandoned by a crashed worker 2 minutes ago
        const insertRes = await pool.request()
            .input('requestId', testRequestId)
            .input('idempotencyKey', idempotencyKey)
            .query(`
                INSERT INTO dbo.provisioning_jobs (
                    request_id,
                    connector_type,
                    target_resource,
                    idempotency_key,
                    job_status,
                    attempt_count,
                    max_attempts,
                    lease_owner,
                    lease_expires_at,
                    created_at,
                    updated_at
                )
                OUTPUT INSERTED.job_id
                VALUES (
                    @requestId,
                    'GITHUB',
                    'AccessLease-Test-Org/crashed-team',
                    @idempotencyKey,
                    'PROCESSING',
                    1,
                    5,
                    'crashed-worker-pid-9999',
                    DATEADD(MINUTE, -2, SYSDATETIMEOFFSET()),
                    SYSDATETIMEOFFSET(),
                    SYSDATETIMEOFFSET()
                );
            `);

        const abandonedJobId = insertRes.recordset[0].job_id;

        // Next healthy worker cycle attempts to claim next job
        const claimed = await provisioningRepository.claimNextProvisioningJob('healthy-worker-active-01', 60);

        assert.ok(claimed, 'Expected crashed job to be reclaimed');
        assert.strictEqual(claimed.job_id, abandonedJobId);
        assert.strictEqual(claimed.lease_owner, 'healthy-worker-active-01');
        assert.strictEqual(claimed.job_status, 'PROCESSING');
        assert.strictEqual(claimed.attempt_count, 2, 'Attempt count must increment on crash recovery');

        // Cleanup
        await pool.request().query(`DELETE FROM dbo.provisioning_jobs WHERE job_id = '${abandonedJobId}';`);
    });

    // -------------------------------------------------------------------------
    // 3. Max Attempts Enforcement
    // -------------------------------------------------------------------------
    it('3. Max Attempts Enforcement: Does not claim jobs that have exhausted max_attempts', async () => {
        const idempotencyKey = `TEST-HARDENING-MAXATT-${Date.now()}`;
        
        const insertRes = await pool.request()
            .input('requestId', testRequestId)
            .input('idempotencyKey', idempotencyKey)
            .query(`
                INSERT INTO dbo.provisioning_jobs (
                    request_id,
                    connector_type,
                    target_resource,
                    idempotency_key,
                    job_status,
                    attempt_count,
                    max_attempts,
                    lease_owner,
                    lease_expires_at,
                    created_at,
                    updated_at
                )
                OUTPUT INSERTED.job_id
                VALUES (
                    @requestId,
                    'GITHUB',
                    'AccessLease-Test-Org/dead-letter-team',
                    @idempotencyKey,
                    'FAILED_RETRY',
                    5,
                    5,
                    NULL,
                    NULL,
                    SYSDATETIMEOFFSET(),
                    SYSDATETIMEOFFSET()
                );
            `);

        const deadLetterJobId = insertRes.recordset[0].job_id;

        // Worker claim should ignore this job because attempt_count >= max_attempts
        const claimed = await provisioningRepository.claimNextProvisioningJob('worker-max-test', 60);
        
        if (claimed) {
            assert.notStrictEqual(claimed.job_id, deadLetterJobId, 'Job exceeding max attempts must never be claimed');
            // Clean up claimed job if it was a different one
            await pool.request().query(`UPDATE dbo.provisioning_jobs SET lease_owner = NULL, job_status = 'QUEUED' WHERE job_id = '${claimed.job_id}';`);
        }

        // Cleanup
        await pool.request().query(`DELETE FROM dbo.provisioning_jobs WHERE job_id = '${deadLetterJobId}';`);
    });

    // -------------------------------------------------------------------------
    // 4. Status Filter Mapping (FAILED -> FAILED_RETRY + PERMANENT_FAILURE)
    // -------------------------------------------------------------------------
    it('4. listProvisioningJobs: Maps status=FAILED to both FAILED_RETRY and PERMANENT_FAILURE', async () => {
        const key1 = `TEST-HARDENING-F1-${Date.now()}`;
        const key2 = `TEST-HARDENING-F2-${Date.now()}`;

        await pool.request().query(`
            INSERT INTO dbo.provisioning_jobs (request_id, connector_type, target_resource, idempotency_key, job_status)
            VALUES 
                ('${testRequestId}', 'GITHUB', 'org/t1', '${key1}', 'FAILED_RETRY'),
                ('${testRequestId}', 'GITHUB', 'org/t2', '${key2}', 'PERMANENT_FAILURE');
        `);

        const failedJobs = await provisioningRepository.listProvisioningJobs({ status: 'FAILED' });
        const found1 = failedJobs.find(j => j.idempotency_key === key1);
        const found2 = failedJobs.find(j => j.idempotency_key === key2);

        assert.ok(found1, 'Expected FAILED_RETRY job to be matched by status=FAILED');
        assert.ok(found2, 'Expected PERMANENT_FAILURE job to be matched by status=FAILED');

        // Cleanup
        await pool.request().query(`DELETE FROM dbo.provisioning_jobs WHERE idempotency_key IN ('${key1}', '${key2}');`);
    });

    // -------------------------------------------------------------------------
    // 5. Safe Membership Provenance Recovery & Offboarding Protection (PROMPT 06.4)
    // -------------------------------------------------------------------------
    it('5. Safe Provenance Recovery: Only matching confirmed mutation proves ownership; rejects pre-flight inference', async () => {
        // Test githubVerificationService logic directly
        const org = 'accesslease-governance';
        const teamSlug = 'backend-engineers';
        const username = 'test-contractor-gh';

        // Mock GitHub team service in verification
        const originalValidateConfig = require('../../src/connectors/github/githubConfig').validateConfig;
        const originalValidateOrg = require('../../src/connectors/github/githubTeamService').validateOrganizationAllowlisted;
        const originalGetTeam = require('../../src/connectors/github/githubTeamService').getTeam;
        const originalGetRepoPerms = require('../../src/connectors/github/githubTeamService').getTeamRepoPermissions;
        const originalGetMembership = require('../../src/connectors/github/githubTeamService').getTeamMembership;

        require('../../src/connectors/github/githubConfig').validateConfig = () => ({ isValid: true, missingFields: [] });
        require('../../src/connectors/github/githubTeamService').validateOrganizationAllowlisted = () => {};
        require('../../src/connectors/github/githubTeamService').getTeam = async () => ({ id: 101, name: 'Backend Engineers' });
        require('../../src/connectors/github/githubTeamService').getTeamRepoPermissions = async () => ({ permissions: { pull: true, push: true } });
        require('../../src/connectors/github/githubTeamService').getTeamMembership = async () => ({ state: 'active', role: 'member' });

        try {
            // Case A: Fresh discovery without retry -> PRE_EXISTING_ADOPTED (never claims AccessLease created it)
            const freshOutcome = await githubVerificationService.provisionAndVerifyAccess({
                org,
                teamSlug,
                repoOwner: org,
                repoName: 'backend-service',
                requiredPermission: 'pull',
                username,
                isRetry: false
            });

            assert.strictEqual(freshOutcome.membershipProvenance, 'PRE_EXISTING_ADOPTED');
            assert.strictEqual(freshOutcome.preExisting, true);

            // Case B: Retry WITHOUT confirmed mutation event -> UNCERTAIN_PRE_EXISTING (safe fallback)
            const uncertainRetryOutcome = await githubVerificationService.provisionAndVerifyAccess({
                org,
                teamSlug,
                repoOwner: org,
                repoName: 'backend-service',
                requiredPermission: 'pull',
                username,
                isRetry: true,
                confirmedMutationEvent: null
            });

            assert.strictEqual(uncertainRetryOutcome.membershipProvenance, 'UNCERTAIN_PRE_EXISTING');
            assert.strictEqual(uncertainRetryOutcome.preExisting, true);
            assert.strictEqual(uncertainRetryOutcome.state, 'ACTIVE');

            // Case C: Retry WITH matching provider audit event -> CREATED_BY_ACCESSLEASE confirmed!
            const matchingConfirmedEvent = {
                event_type: 'PROVIDER_AUDIT_CONFIRMED',
                payload: {
                    targetOrg: org,
                    targetTeam: teamSlug,
                    externalUsername: username,
                    verificationStatus: 'VERIFIED'
                }
            };

            const confirmedRetryOutcome = await githubVerificationService.provisionAndVerifyAccess({
                org,
                teamSlug,
                repoOwner: org,
                repoName: 'backend-service',
                requiredPermission: 'pull',
                username,
                isRetry: true,
                providerAuditEvent: matchingConfirmedEvent
            });

            assert.strictEqual(confirmedRetryOutcome.membershipProvenance, 'CREATED_BY_ACCESSLEASE');
            assert.strictEqual(confirmedRetryOutcome.preExisting, false);
            assert.strictEqual(confirmedRetryOutcome.state, 'ACTIVE');

            // Case D: Retry with confirmed event for a DIFFERENT team (Target Mismatch) -> UNCERTAIN_PRE_EXISTING
            const mismatchedEvent = {
                event_type: 'PROVIDER_AUDIT_CONFIRMED',
                payload: {
                    targetOrg: org,
                    targetTeam: 'other-unrelated-team',
                    externalUsername: username,
                    verificationStatus: 'VERIFIED'
                }
            };

            const mismatchedOutcome = await githubVerificationService.provisionAndVerifyAccess({
                org,
                teamSlug,
                repoOwner: org,
                repoName: 'backend-service',
                requiredPermission: 'pull',
                username,
                isRetry: true,
                providerAuditEvent: mismatchedEvent
            });

            assert.strictEqual(mismatchedOutcome.membershipProvenance, 'UNCERTAIN_PRE_EXISTING');
            assert.strictEqual(mismatchedOutcome.preExisting, true);

            // Case E: Automated Revocation Safeguard Checks
            const safePreExisting = await isSafeForAutomatedRevocation({ membership_provenance: 'PRE_EXISTING_ADOPTED' });
            assert.strictEqual(safePreExisting.canRevoke, false, 'Pre-existing membership must never be automatically revoked');

            const safeUncertain = await isSafeForAutomatedRevocation({ membership_provenance: 'UNCERTAIN_PRE_EXISTING' });
            assert.strictEqual(safeUncertain.canRevoke, false, 'Uncertain provenance membership must never be automatically revoked');

            const safeNoEvidence = await isSafeForAutomatedRevocation({
                membership_provenance: 'CREATED_BY_ACCESSLEASE',
                target_org: org,
                target_team_slug: teamSlug,
                external_username: username
            });
            assert.strictEqual(safeNoEvidence.canRevoke, false, 'Revocation must be denied when mutation confirmation evidence is missing');

            const safeWithEvidence = await isSafeForAutomatedRevocation(
                {
                    membership_provenance: 'CREATED_BY_ACCESSLEASE',
                    target_org: org,
                    target_team_slug: teamSlug,
                    external_username: username
                },
                { auditEvent: matchingConfirmedEvent }
            );
            assert.strictEqual(safeWithEvidence.canRevoke, true, 'Verified CREATED_BY_ACCESSLEASE with matching provider audit evidence is safe for automated revocation');
        } finally {
            require('../../src/connectors/github/githubConfig').validateConfig = originalValidateConfig;
            require('../../src/connectors/github/githubTeamService').validateOrganizationAllowlisted = originalValidateOrg;
            require('../../src/connectors/github/githubTeamService').getTeam = originalGetTeam;
            require('../../src/connectors/github/githubTeamService').getTeamRepoPermissions = originalGetRepoPerms;
            require('../../src/connectors/github/githubTeamService').getTeamMembership = originalGetMembership;
        }
    });

    // -------------------------------------------------------------------------
    // 6. GitHub OAuth State Cryptographic Tamper & Expiration Resistance
    // -------------------------------------------------------------------------
    it('6. OAuth State: Rejects tampered signatures, expired states, and mismatched user bindings', () => {
        const state = githubOAuthService.generateOAuthState(testIsolatedContractorId);
        assert.ok(state && state.includes('.'), 'State must be in payload.signature format');

        // Valid verification passes
        const verified = githubOAuthService.verifyOAuthState(state, testIsolatedContractorId);
        assert.strictEqual(verified.u, testIsolatedContractorId);

        // Tampered signature is rejected
        const tamperedSig = state.slice(0, -3) + 'XYZ';
        assert.throws(() => {
            githubOAuthService.verifyOAuthState(tamperedSig, testIsolatedContractorId);
        }, err => err.code === 'ERR_INVALID_OAUTH_STATE');

        // Tampered payload is rejected
        const [payload, sig] = state.split('.');
        const tamperedPayload = payload.slice(1) + 'A';
        assert.throws(() => {
            githubOAuthService.verifyOAuthState(`${tamperedPayload}.${sig}`, testIsolatedContractorId);
        }, err => err.code === 'ERR_INVALID_OAUTH_STATE');

        // Mismatched user is rejected
        assert.throws(() => {
            githubOAuthService.verifyOAuthState(state, testAdminId);
        }, err => err.code === 'ERR_OAUTH_USER_MISMATCH');
    });

    // -------------------------------------------------------------------------
    // 7. GitHub Account Linking Uniqueness & ID Collision Prevention
    // -------------------------------------------------------------------------
    it('7. Account Uniqueness: Prevents linking a GitHub account already bound to another user', async () => {
        const ghUsername = `test-hardening-user-${Date.now()}`;
        const ghNumericId = `999${Math.floor(1000 + Math.random() * 9000)}`;

        // User A links the account
        await userExternalIdentityRepository.upsertExternalIdentity({
            userId: testIsolatedContractorId,
            provider: 'GITHUB',
            externalAccountId: ghNumericId,
            externalUsername: ghUsername,
            verificationStatus: 'VERIFIED',
            verifiedByUserId: testIsolatedContractorId
        });

        // User B (Admin or another contractor) attempts to link the exact same username
        const mockUserB = { user_id: testAdminId, roles: ['SYSTEM_ADMIN'] };
        const state = githubOAuthService.generateOAuthState(testAdminId);
        const statePayload = githubOAuthService.verifyOAuthState(state, testAdminId);
        await oauthStateRepository.saveOAuthState({
            stateNonce: statePayload.n,
            userId: testAdminId,
            codeVerifier: 'mock-code-verifier',
            expiresAt: new Date(Date.now() + 600000)
        });

        // Mock token exchange and fetch profile
        const originalExchange = githubOAuthService.exchangeCodeForToken;
        const originalFetch = githubOAuthService.fetchAuthenticatedGitHubUser;

        githubOAuthService.exchangeCodeForToken = async () => 'mock-ephemeral-access-token';
        githubOAuthService.fetchAuthenticatedGitHubUser = async () => ({
            id: Number(ghNumericId),
            login: ghUsername
        });

        try {
            await assert.rejects(async () => {
                await githubOAuthService.linkContractorGitHubAccount({
                    user: mockUserB,
                    code: 'valid-test-code',
                    state
                });
            }, err => err.code === 'ERR_GITHUB_ACCOUNT_ALREADY_BOUND');
        } finally {
            githubOAuthService.exchangeCodeForToken = originalExchange;
            githubOAuthService.fetchAuthenticatedGitHubUser = originalFetch;
            await pool.request().query(`DELETE FROM dbo.oauth_states WHERE state_nonce = '${statePayload.n}';`);
        }

        // Cleanup
        await pool.request().query(`DELETE FROM dbo.user_external_identities WHERE external_username = '${ghUsername}';`);
    });

    // -------------------------------------------------------------------------
    // 8. Contractor Self-Service Unlink & Audit Trail
    // -------------------------------------------------------------------------
    it('8. Contractor Unlink: Contractor can unlink own account, transitions to REVOKED with audit log', async () => {
        const ghUsername = `test-hardening-unlink-${Date.now()}`;
        const ghNumericId = `888${Math.floor(1000 + Math.random() * 9000)}`;

        const identity = await userExternalIdentityRepository.upsertExternalIdentity({
            userId: testIsolatedContractorId,
            provider: 'GITHUB',
            externalAccountId: ghNumericId,
            externalUsername: ghUsername,
            verificationStatus: 'VERIFIED',
            verifiedByUserId: testIsolatedContractorId
        });

        // Contractor unlinks account
        const mockContractor = { user_id: testIsolatedContractorId, roles: ['CONTRACTOR'] };
        const result = await githubOAuthService.unlinkContractorGitHubAccount({
            user: mockContractor
        });

        assert.strictEqual(result.verification_status, 'REVOKED');

        // Verify status in DB
        const updated = await userExternalIdentityRepository.findIdentityByUserAndProvider(testIsolatedContractorId, 'GITHUB');
        assert.strictEqual(updated.verification_status, 'REVOKED');

        // Verify audit event
        const auditLog = await pool.request()
            .input('entityId', identity.identity_id)
            .query("SELECT TOP 1 * FROM dbo.audit_events WHERE entity_id = @entityId AND event_action = 'GITHUB_ACCOUNT_UNLINKED';");
        assert.ok(auditLog.recordset.length > 0, 'Expected GITHUB_ACCOUNT_UNLINKED audit event');

        // Cleanup
        await pool.request().query(`
            DELETE FROM dbo.audit_events WHERE entity_id = '${identity.identity_id}';
            DELETE FROM dbo.user_external_identities WHERE identity_id = '${identity.identity_id}';
        `);
    });

    // -------------------------------------------------------------------------
    // 9. Administrative Verification Exception Guard
    // -------------------------------------------------------------------------
    it('9. Manual Verification Exception: Enforces admin role and mandatory justification cap (>=10 chars)', async () => {
        const ghUsername = `test-hardening-manual-${Date.now()}`;
        const mockContractor = { user_id: testIsolatedContractorId, roles: ['CONTRACTOR'] };
        const mockAdmin = { user_id: testAdminId, roles: ['SYSTEM_ADMIN'] };

        // Non-admin attempt rejected
        await assert.rejects(async () => {
            await githubOAuthService.manualVerifyContractorIdentity({
                actorUser: mockContractor,
                targetUserId: testIsolatedContractorId,
                externalUsername: ghUsername,
                justification: 'Valid business justification here'
            });
        }, err => err.code === 'ERR_FORBIDDEN_MANUAL_VERIFY');

        // Admin attempt with insufficient justification rejected (< 10 chars)
        await assert.rejects(async () => {
            await githubOAuthService.manualVerifyContractorIdentity({
                actorUser: mockAdmin,
                targetUserId: testIsolatedContractorId,
                externalUsername: ghUsername,
                justification: 'Too short'
            });
        }, err => err.code === 'ERR_JUSTIFICATION_REQUIRED');

        // Admin attempt with valid justification succeeds and records exception audit log
        const success = await githubOAuthService.manualVerifyContractorIdentity({
            actorUser: mockAdmin,
            targetUserId: testIsolatedContractorId,
            externalUsername: ghUsername,
            justification: 'Approved off-band verification by security lead after passport inspection.'
        });

        assert.strictEqual(success.verification_status, 'VERIFIED');
        assert.strictEqual(success.verification_method, 'ADMINISTRATIVE_EXCEPTION');

        // Verify audit event
        const auditLog = await pool.request()
            .input('entityId', success.identity_id)
            .query("SELECT TOP 1 * FROM dbo.audit_events WHERE entity_id = @entityId AND event_action = 'IDENTITY_MANUAL_VERIFICATION_EXCEPTION';");
        assert.ok(auditLog.recordset.length > 0, 'Expected IDENTITY_MANUAL_VERIFICATION_EXCEPTION audit event');

        // Cleanup
        await pool.request().query(`
            DELETE FROM dbo.audit_events WHERE entity_id = '${success.identity_id}';
            DELETE FROM dbo.user_external_identities WHERE identity_id = '${success.identity_id}';
        `);
    });

    // -------------------------------------------------------------------------
    // 10. Atomic OAuth State One-Time Consumption & Replay Prevention (PROMPT 06.3)
    // -------------------------------------------------------------------------
    it('10. OAuth Replay Protection: Atomically consumes state exactly once and rejects replayed requests', async () => {
        const ghUsername = `test-hardening-replay-${Date.now()}`;
        const ghNumericId = `777${Math.floor(1000 + Math.random() * 9000)}`;
        const mockContractor = { user_id: testIsolatedContractorId, roles: ['CONTRACTOR'] };

        // Generate state & PKCE
        const state = githubOAuthService.generateOAuthState(testIsolatedContractorId);
        const statePayload = githubOAuthService.verifyOAuthState(state, testIsolatedContractorId);
        await oauthStateRepository.saveOAuthState({
            stateNonce: statePayload.n,
            userId: testIsolatedContractorId,
            codeVerifier: 'mock-pkce-verifier-test',
            expiresAt: new Date(Date.now() + 600000)
        });

        // Mock token exchange and fetch profile
        const originalExchange = githubOAuthService.exchangeCodeForToken;
        const originalFetch = githubOAuthService.fetchAuthenticatedGitHubUser;

        githubOAuthService.exchangeCodeForToken = async (code, redirectUri, codeVerifier) => {
            assert.strictEqual(codeVerifier, 'mock-pkce-verifier-test', 'Must pass PKCE code_verifier to token endpoint');
            return 'mock-ephemeral-access-token';
        };
        githubOAuthService.fetchAuthenticatedGitHubUser = async () => ({
            id: Number(ghNumericId),
            login: ghUsername
        });

        try {
            // First callback attempt: Must succeed
            const linked = await githubOAuthService.linkContractorGitHubAccount({
                user: mockContractor,
                code: 'first-auth-code',
                state
            });
            assert.strictEqual(linked.external_username, ghUsername);
            assert.strictEqual(linked.verification_status, 'VERIFIED');

            // Second callback attempt with identical state: Must throw ERR_OAUTH_STATE_REPLAY
            await assert.rejects(async () => {
                await githubOAuthService.linkContractorGitHubAccount({
                    user: mockContractor,
                    code: 'replayed-auth-code',
                    state
                });
            }, err => {
                assert.strictEqual(err.code, 'ERR_OAUTH_STATE_REPLAY');
                return true;
            });
        } finally {
            githubOAuthService.exchangeCodeForToken = originalExchange;
            githubOAuthService.fetchAuthenticatedGitHubUser = originalFetch;
            await pool.request().query(`
                DELETE FROM dbo.user_external_identities WHERE external_username = '${ghUsername}';
                DELETE FROM dbo.oauth_states WHERE state_nonce = '${statePayload.n}';
            `);
        }
    });

    // -------------------------------------------------------------------------
    // 11. PKCE Code Challenge Generation and Verifier Persistence (PROMPT 06.3)
    // -------------------------------------------------------------------------
    it('11. PKCE Support: Generates S256 code_challenge and securely persists code_verifier', async () => {
        // Ensure GITHUB_OAUTH_CLIENT_ID is set in env for this test
        const originalClientId = process.env.GITHUB_OAUTH_CLIENT_ID;
        process.env.GITHUB_OAUTH_CLIENT_ID = 'test-mock-client-id';

        try {
            const mockContractor = { user_id: testIsolatedContractorId, roles: ['CONTRACTOR'] };
            const authResult = await githubOAuthService.getAuthorizationUrl(mockContractor);

            assert.ok(authResult.authorization_url, 'Must generate authorization URL');
            assert.ok(authResult.state, 'Must generate signed state');

            const url = new URL(authResult.authorization_url);
            const codeChallenge = url.searchParams.get('code_challenge');
            const codeChallengeMethod = url.searchParams.get('code_challenge_method');

            assert.strictEqual(codeChallengeMethod, 'S256', 'Must require S256 PKCE code challenge method');
            assert.ok(codeChallenge && codeChallenge.length > 20, 'Must include non-empty code_challenge');

            // Verify code_verifier was saved in dbo.oauth_states
            const statePayload = githubOAuthService.verifyOAuthState(authResult.state, testIsolatedContractorId);
            const savedState = await pool.request()
                .input('nonce', statePayload.n)
                .query("SELECT TOP 1 * FROM dbo.oauth_states WHERE state_nonce = @nonce;");

            assert.strictEqual(savedState.recordset.length, 1, 'Expected oauth_states row in database');
            const row = savedState.recordset[0];
            assert.strictEqual(row.is_consumed, false);
            assert.ok(row.code_verifier, 'Must store code_verifier in database');

            // Verify cryptographic derivation: SHA-256(code_verifier) === code_challenge
            const expectedChallenge = githubOAuthService.generateCodeChallenge(row.code_verifier);
            assert.strictEqual(expectedChallenge, codeChallenge);

            // Cleanup
            await pool.request().query(`DELETE FROM dbo.oauth_states WHERE state_nonce = '${statePayload.n}';`);
        } finally {
            if (originalClientId) {
                process.env.GITHUB_OAUTH_CLIENT_ID = originalClientId;
            } else {
                delete process.env.GITHUB_OAUTH_CLIENT_ID;
            }
        }
    });

    // -------------------------------------------------------------------------
    // 12. LocalDB Durable Provenance Recovery & Mutation Confirmation (PROMPT 06.4)
    // -------------------------------------------------------------------------
    it('12. Provenance Recovery: LocalDB enforces PROVIDER_AUDIT_CONFIRMED proof and guards revocation', async () => {
        const org = 'accesslease-governance';
        const teamSlug = 'backend-engineers';
        const username = 'test-contractor-provenance';

        // Resolve or create a grant in AccessLease_TestDB
        let fixture = null;
        let testGrantId;
        const grantRes = await pool.request().query(`
            SELECT TOP 1 ag.grant_id, ag.request_id 
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

        const mockAuditEvents = [{
            action: 'team.add_member',
            actor: 'accesslease[bot]',
            actor_is_bot: true,
            user: username,
            org,
            team: teamSlug,
            '@timestamp': Date.now()
        }];

        // Mock GitHub team service in verification
        const originalValidateConfig = require('../../src/connectors/github/githubConfig').validateConfig;
        const originalValidateOrg = require('../../src/connectors/github/githubTeamService').validateOrganizationAllowlisted;
        const originalGetTeam = require('../../src/connectors/github/githubTeamService').getTeam;
        const originalGetRepoPerms = require('../../src/connectors/github/githubTeamService').getTeamRepoPermissions;
        const originalGetMembership = require('../../src/connectors/github/githubTeamService').getTeamMembership;
        const originalAddMembership = require('../../src/connectors/github/githubTeamService').addOrUpdateTeamMembership;

        require('../../src/connectors/github/githubConfig').validateConfig = () => ({ isValid: true, missingFields: [] });
        require('../../src/connectors/github/githubTeamService').validateOrganizationAllowlisted = () => {};
        require('../../src/connectors/github/githubTeamService').getTeam = async () => ({ id: 101, name: 'Backend Engineers' });
        require('../../src/connectors/github/githubTeamService').getTeamRepoPermissions = async () => ({ permissions: { pull: true, push: true } });

        try {
            // Clean any existing events for testGrantId
            await pool.request().query(`DELETE FROM dbo.provisioning_events WHERE grant_id = '${testGrantId}';`);

            // -----------------------------------------------------------------
            // Scenario 1: Initial mutation: PUT succeeds and commits PROVIDER_AUDIT_CONFIRMED
            // -----------------------------------------------------------------
            let membershipCalls = 0;
            require('../../src/connectors/github/githubTeamService').getTeamMembership = async () => {
                membershipCalls++;
                // First pre-flight check: absent. Second post-check: active.
                return membershipCalls === 1 ? null : { state: 'active', role: 'member' };
            };
            require('../../src/connectors/github/githubTeamService').addOrUpdateTeamMembership = async () => ({ state: 'active', role: 'member' });

            const initialOutcome = await githubVerificationService.provisionAndVerifyAccess({
                org,
                teamSlug,
                repoOwner: org,
                repoName: 'backend-service',
                requiredPermission: 'pull',
                username,
                isRetry: false,
                grantId: testGrantId,
                injectedAuditEvents: mockAuditEvents
            });

            assert.strictEqual(initialOutcome.membershipProvenance, 'CREATED_BY_ACCESSLEASE');
            assert.strictEqual(initialOutcome.preExisting, false);
            assert.strictEqual(initialOutcome.state, 'ACTIVE');

            // Verify row in LocalDB dbo.provisioning_events
            const eventCheck = await pool.request()
                .input('grantId', testGrantId)
                .query("SELECT * FROM dbo.provisioning_events WHERE grant_id = @grantId AND event_type = 'PROVIDER_AUDIT_CONFIRMED';");
            assert.strictEqual(eventCheck.recordset.length, 1, 'Must persist exactly one provider audit confirmation event');
            const eventRow = eventCheck.recordset[0];
            const parsedPayload = JSON.parse(eventRow.payload);
            assert.strictEqual(parsedPayload.targetOrg, org);
            assert.strictEqual(parsedPayload.targetTeam, teamSlug);
            assert.strictEqual(parsedPayload.externalUsername, username);
            assert.strictEqual(parsedPayload.verificationStatus, 'VERIFIED');

            // -----------------------------------------------------------------
            // Scenario 2: Duplicate worker execution: Idempotency (no duplicate confirmation events)
            // -----------------------------------------------------------------
            membershipCalls = 0;
            await githubVerificationService.provisionAndVerifyAccess({
                org,
                teamSlug,
                repoOwner: org,
                repoName: 'backend-service',
                requiredPermission: 'pull',
                username,
                isRetry: false,
                grantId: testGrantId,
                injectedAuditEvents: mockAuditEvents
            });

            const dupCheck = await pool.request()
                .input('grantId', testGrantId)
                .query("SELECT COUNT(*) AS total FROM dbo.provisioning_events WHERE grant_id = @grantId AND event_type = 'PROVIDER_AUDIT_CONFIRMED';");
            assert.strictEqual(dupCheck.recordset[0].total, 1, 'Duplicate execution must NOT insert duplicate provider audit confirmation events');

            // -----------------------------------------------------------------
            // Scenario 3: Worker crash recovery after confirmation event is committed
            // -----------------------------------------------------------------
            require('../../src/connectors/github/githubTeamService').getTeamMembership = async () => ({ state: 'active', role: 'member' });
            const recoveredOutcome = await githubVerificationService.provisionAndVerifyAccess({
                org,
                teamSlug,
                repoOwner: org,
                repoName: 'backend-service',
                requiredPermission: 'pull',
                username,
                isRetry: true,
                grantId: testGrantId
            });
            assert.strictEqual(recoveredOutcome.membershipProvenance, 'CREATED_BY_ACCESSLEASE', 'Must recover CREATED_BY_ACCESSLEASE from provider audit event');
            assert.strictEqual(recoveredOutcome.preExisting, false);

            // -----------------------------------------------------------------
            // Scenario 4: Crash between PUT and audit confirmation (no audit event in DB)
            // -----------------------------------------------------------------
            await pool.request().query(`DELETE FROM dbo.provisioning_events WHERE grant_id = '${testGrantId}';`);
            const crashWindowOutcome = await githubVerificationService.provisionAndVerifyAccess({
                org,
                teamSlug,
                repoOwner: org,
                repoName: 'backend-service',
                requiredPermission: 'pull',
                username,
                isRetry: true,
                grantId: testGrantId
            });
            assert.strictEqual(crashWindowOutcome.membershipProvenance, 'UNCERTAIN_PRE_EXISTING', 'Must assign UNCERTAIN_PRE_EXISTING when audit confirmation event is missing');
            assert.strictEqual(crashWindowOutcome.preExisting, true);

            // -----------------------------------------------------------------
            // Scenario 5: External maintainer added user between pre-flight and PUT
            // -----------------------------------------------------------------
            // Pre-flight discovers active membership on initial run
            const preflightMaintainerOutcome = await githubVerificationService.provisionAndVerifyAccess({
                org,
                teamSlug,
                repoOwner: org,
                repoName: 'backend-service',
                requiredPermission: 'pull',
                username,
                isRetry: false,
                grantId: testGrantId
            });
            assert.strictEqual(preflightMaintainerOutcome.membershipProvenance, 'PRE_EXISTING_ADOPTED', 'Must assign PRE_EXISTING_ADOPTED, not AccessLease-owned');

            // -----------------------------------------------------------------
            // Scenario 6: Confirmation event belongs to another team (Target Mismatch)
            // -----------------------------------------------------------------
            await provisioningRepository.createProvisioningEvent({
                grantId: testGrantId,
                eventType: 'PROVIDER_AUDIT_CONFIRMED',
                connectorName: 'GITHUB',
                payload: {
                    grantId: testGrantId,
                    targetOrg: org,
                    targetTeam: 'different-engineering-team', // Different team!
                    externalUsername: username,
                    verificationStatus: 'VERIFIED'
                },
                statusCode: '200'
            });

            const mismatchedOutcome = await githubVerificationService.provisionAndVerifyAccess({
                org,
                teamSlug, // 'backend-engineers'
                repoOwner: org,
                repoName: 'backend-service',
                requiredPermission: 'pull',
                username,
                isRetry: true,
                grantId: testGrantId
            });
            assert.strictEqual(mismatchedOutcome.membershipProvenance, 'UNCERTAIN_PRE_EXISTING', 'Target mismatch must reject ownership inference');

            // -----------------------------------------------------------------
            // Scenario 7: LocalDB Revocation Safeguard Verification
            // -----------------------------------------------------------------
            // 7a. Mismatched confirmation in DB -> Denied
            const testGrantObj = {
                grant_id: testGrantId,
                membership_provenance: 'CREATED_BY_ACCESSLEASE',
                target_org: org,
                target_team_slug: teamSlug,
                external_username: username
            };
            const mismatchRevokeCheck = await isSafeForAutomatedRevocation(testGrantObj);
            assert.strictEqual(mismatchRevokeCheck.canRevoke, false, 'Revocation denied when DB confirmation event target does not match');

            // 7b. Correct confirmation in DB -> Approved
            await pool.request().query(`DELETE FROM dbo.provisioning_events WHERE grant_id = '${testGrantId}';`);
            await provisioningRepository.createProvisioningEvent({
                grantId: testGrantId,
                eventType: 'PROVIDER_AUDIT_CONFIRMED',
                connectorName: 'GITHUB',
                payload: {
                    grantId: testGrantId,
                    targetOrg: org,
                    targetTeam: teamSlug,
                    externalUsername: username,
                    verificationStatus: 'VERIFIED'
                },
                statusCode: '200'
            });
            const validRevokeCheck = await isSafeForAutomatedRevocation(testGrantObj);
            assert.strictEqual(validRevokeCheck.canRevoke, true, 'Revocation permitted when matching DB provider audit event exists');

        } finally {
            require('../../src/connectors/github/githubConfig').validateConfig = originalValidateConfig;
            require('../../src/connectors/github/githubTeamService').validateOrganizationAllowlisted = originalValidateOrg;
            require('../../src/connectors/github/githubTeamService').getTeam = originalGetTeam;
            require('../../src/connectors/github/githubTeamService').getTeamRepoPermissions = originalGetRepoPerms;
            require('../../src/connectors/github/githubTeamService').getTeamMembership = originalGetMembership;
            require('../../src/connectors/github/githubTeamService').addOrUpdateTeamMembership = originalAddMembership;
            if (testGrantId) {
                await pool.request().query(`DELETE FROM dbo.provisioning_events WHERE grant_id = '${testGrantId}';`);
            }
            if (fixture) {
                await fixture.cleanup();
            }
        }
    });
});
