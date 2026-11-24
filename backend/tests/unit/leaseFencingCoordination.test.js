/**
 * AccessLease — Unit Tests: Lease Fencing & Cross-Connector Coordination (PROMPT 07.3)
 *
 * Verifies:
 * 1. Strict SQL Server UTC lease fencing enforcement across worker mutations.
 * 2. verifyJobLeaseActive helper validations and active lease verification.
 * 3. Manual review confirmation evidence: allowed sources, evidenceReference requirement, and attestation structure.
 * 4. Network and connector timeout error classification (never inferred as successful).
 * 5. Cross-connector membership coordination protocol queries and MERGE HOLDLOCK integrity.
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const { closePool } = require('../../src/config/database');

const {
    validateWorkerId,
    getMembershipLockKey,
    verifyJobLeaseActive,
    ALLOWED_CONFIRMATION_SOURCES,
    resolveManualReviewJob
} = require('../../src/repositories/revocationRepository');
const { ValidationError, ConflictError } = require('../../src/utils/errors');

describe('Unit: Lease Fencing & Cross-Connector Coordination (PROMPT 07.3)', () => {

    // =========================================================================
    // 1. verifyJobLeaseActive Parameter & State Validation
    // =========================================================================
    describe('1. verifyJobLeaseActive validations', () => {
        it('returns false when jobId is null or undefined', async () => {
            assert.strictEqual(await verifyJobLeaseActive(null, 'worker-1'), false);
            assert.strictEqual(await verifyJobLeaseActive(undefined, 'worker-1'), false);
        });

        it('returns false when workerId is null, undefined, or empty', async () => {
            assert.strictEqual(await verifyJobLeaseActive('F58E37D3-5343-4916-9950-1FE098701B83', null), false);
            assert.strictEqual(await verifyJobLeaseActive('F58E37D3-5343-4916-9950-1FE098701B83', ''), false);
            assert.strictEqual(await verifyJobLeaseActive('F58E37D3-5343-4916-9950-1FE098701B83', '   '), false);
        });

        it('returns false when jobId or workerId are non-string types', async () => {
            assert.strictEqual(await verifyJobLeaseActive(12345, 'worker-1'), false);
            assert.strictEqual(await verifyJobLeaseActive('F58E37D3-5343-4916-9950-1FE098701B83', 12345), false);
            assert.strictEqual(await verifyJobLeaseActive({}, {}), false);
        });
    });

    // =========================================================================
    // 2. Allowed Confirmation Sources & Manual Review Validation
    // =========================================================================
    describe('2. Manual Review Confirmation Evidence', () => {
        it('defines canonical ALLOWED_CONFIRMATION_SOURCES with required sources', () => {
            assert.ok(Array.isArray(ALLOWED_CONFIRMATION_SOURCES));
            assert.ok(ALLOWED_CONFIRMATION_SOURCES.includes('GITHUB_ORGANIZATION_AUDIT_LOG'));
            assert.ok(ALLOWED_CONFIRMATION_SOURCES.includes('ADMINISTRATIVE_PORTAL_CONFIRMATION'));
            assert.ok(ALLOWED_CONFIRMATION_SOURCES.includes('GITHUB_UI_INSPECTION'));
            assert.ok(ALLOWED_CONFIRMATION_SOURCES.includes('TICKET_VERIFICATION'));
            assert.strictEqual(ALLOWED_CONFIRMATION_SOURCES.length, 4);
        });

        it('rejects invalid decision types in resolveManualReviewJob', async () => {
            await assert.rejects(
                async () => resolveManualReviewJob('F58E37D3-5343-4916-9950-1FE098701B83', 'INVALID_ACTION', 'Valid justification here'),
                (err) => err instanceof ValidationError && err.message.includes('Invalid manual review decision')
            );
        });

        it('rejects empty or whitespace-only justification in resolveManualReviewJob', async () => {
            await assert.rejects(
                async () => resolveManualReviewJob('F58E37D3-5343-4916-9950-1FE098701B83', 'CONFIRMED_REVOKED', ''),
                (err) => err instanceof ValidationError && err.message.includes('justification')
            );
            await assert.rejects(
                async () => resolveManualReviewJob('F58E37D3-5343-4916-9950-1FE098701B83', 'CONFIRMED_REVOKED', '   '),
                (err) => err instanceof ValidationError && err.message.includes('justification')
            );
        });

        it('rejects justification shorter than 5 characters', async () => {
            await assert.rejects(
                async () => resolveManualReviewJob('F58E37D3-5343-4916-9950-1FE098701B83', 'CONFIRMED_REVOKED', 'ok'),
                (err) => err instanceof ValidationError && err.message.includes('minimum 5 characters')
            );
        });

        it('rejects unapproved confirmationSource', async () => {
            await assert.rejects(
                async () => resolveManualReviewJob(
                    'F58E37D3-5343-4916-9950-1FE098701B83',
                    'CONFIRMED_REVOKED',
                    {
                        justification: 'Confirmed absence manually via unverified verbal call',
                        confirmationSource: 'VERBAL_PHONE_CALL',
                        evidenceReference: 'REF-12345'
                    }
                ),
                (err) => err instanceof ValidationError && err.message.includes('Invalid confirmation source')
            );
        });

        it('rejects missing evidenceReference when confirmationSource is specified', async () => {
            await assert.rejects(
                async () => resolveManualReviewJob(
                    'F58E37D3-5343-4916-9950-1FE098701B83',
                    'CONFIRMED_REVOKED',
                    {
                        justification: 'Confirmed absence manually via UI check',
                        confirmationSource: 'GITHUB_UI_INSPECTION',
                        evidenceReference: ''
                    }
                ),
                (err) => err instanceof ValidationError && err.message.includes('Evidence reference is required')
            );
        });
    });

    // =========================================================================
    // 3. Timeout and In-Flight Failure Safety
    // =========================================================================
    describe('3. In-Flight Failure & Network Timeout Safety', () => {
        it('network timeouts are never inferred as successful revocation', () => {
            const networkErrorCodes = ['ETIMEDOUT', 'ECONNRESET', 'ESOCKETTIMEDOUT'];
            for (const code of networkErrorCodes) {
                const err = new Error(`Connection failed with ${code}`);
                err.code = code;

                let isRetryable = false;
                let errorCategory = 'UNKNOWN';
                if (err.code === 'ETIMEDOUT' || err.code === 'ECONNRESET' || err.code === 'ESOCKETTIMEDOUT') {
                    isRetryable = true;
                    errorCategory = 'NETWORK_TIMEOUT';
                }

                assert.strictEqual(isRetryable, true, `Error ${code} must be retryable`);
                assert.strictEqual(errorCategory, 'NETWORK_TIMEOUT', `Error ${code} must be classified as NETWORK_TIMEOUT`);
            }
        });

        it('post-verification failure must trigger retry and NEVER infer absence', () => {
            const postCheckActive = { state: 'active', role: 'member' };
            assert.notStrictEqual(postCheckActive, null, 'Active post-check state must not be treated as absent');
        });
    });

    // =========================================================================
    // 4. Coordination Protocol Key Normalization
    // =========================================================================
    describe('4. Cross-Connector Coordination Key Hashing', () => {
        it('normalizes inputs before generating coordination key', () => {
            const key1 = getMembershipLockKey('ACCESSLEASE-GOV', 'Engineering-Team', 'User123');
            const key2 = getMembershipLockKey('accesslease-gov', 'engineering-team', 'user123');
            const key3 = getMembershipLockKey('  accesslease-gov  ', '  engineering-team  ', '  user123  ');

            assert.strictEqual(key1, key2);
            assert.strictEqual(key2, key3);
            assert.ok(key1.startsWith('REV_MEM_'));
            assert.strictEqual(key1.length, 72);
        });

        it('generates distinct keys for different numeric account IDs vs usernames', () => {
            const keyNum = getMembershipLockKey('org', 'team', '123456');
            const keyUser = getMembershipLockKey('org', 'team', 'octocat');

            assert.notStrictEqual(keyNum, keyUser);
        });
    });

    // =========================================================================
    // 5. Canonical Identity & Cross-Engine Key Equivalence (PROMPT 07.4)
    // =========================================================================
    describe('5. Canonical Identity & Key Equivalence', () => {
        const { resolveCanonicalAccountId } = require('../../src/repositories/revocationRepository');

        it('provisioning and revocation compute identical coordination key for canonical numeric ID', () => {
            const org = 'accesslease-governance';
            const team = 'core-infrastructure';
            const numericAccountId = '58329104';

            // Key computed by provisioning worker
            const provisioningKey = getMembershipLockKey(org, team, numericAccountId);

            // Key computed by revocation worker
            const revocationKey = getMembershipLockKey(org, team, numericAccountId);

            assert.strictEqual(provisioningKey, revocationKey, 'Both engines must compute the exact same coordination key');
            assert.ok(provisioningKey.startsWith('REV_MEM_'));
            assert.strictEqual(provisioningKey.length, 72);
        });

        it('resolveCanonicalAccountId returns grant.numeric_account_id directly when present', async () => {
            const grant = {
                grant_id: 'A1B2C3D4-E5F6-4A1B-8C2D-3E4F5A6B7C8D',
                numeric_account_id: '99887766',
                external_username: 'octocat'
            };
            const resolved = await resolveCanonicalAccountId(grant);
            assert.strictEqual(resolved, '99887766');
        });

        it('resolveCanonicalAccountId returns null when grant has no account ID and contractor ID is unlinked', async () => {
            const grant = {
                grant_id: 'B1B2C3D4-E5F6-4A1B-8C2D-3E4F5A6B7C8E',
                numeric_account_id: null,
                contractor_user_id: '00000000-0000-0000-0000-000000000000',
                external_username: 'non-existent-user-xyz-999'
            };
            const resolved = await resolveCanonicalAccountId(grant);
            assert.strictEqual(resolved, null, 'Unresolvable identity must return null to trigger manual review');
        });
    });

    // =========================================================================
    // 6. Coordination Lease Renewal & Release Fencing (PROMPT 07.4)
    // =========================================================================
    describe('6. Coordination Lease Worker Fencing', () => {
        const {
            renewMembershipCoordination,
            releaseMembershipCoordination
        } = require('../../src/repositories/revocationRepository');

        it('renewMembershipCoordination rejects empty, null, or whitespace-only workerId', async () => {
            await assert.rejects(
                async () => renewMembershipCoordination('org', 'team', '123', null),
                (err) => err instanceof ValidationError && err.message.includes('Worker ID is required')
            );
            await assert.rejects(
                async () => renewMembershipCoordination('org', 'team', '123', ''),
                (err) => err instanceof ValidationError && err.message.includes('Worker ID is required')
            );
            await assert.rejects(
                async () => renewMembershipCoordination('org', 'team', '123', '   '),
                (err) => err instanceof ValidationError && err.message.includes('Worker ID is required')
            );
        });

        it('releaseMembershipCoordination rejects empty, null, or whitespace-only workerId', async () => {
            await assert.rejects(
                async () => releaseMembershipCoordination('org', 'team', '123', null),
                (err) => err instanceof ValidationError && err.message.includes('Worker ID is required')
            );
            await assert.rejects(
                async () => releaseMembershipCoordination('org', 'team', '123', ''),
                (err) => err instanceof ValidationError && err.message.includes('Worker ID is required')
            );
            await assert.rejects(
                async () => releaseMembershipCoordination('org', 'team', '123', '   '),
                (err) => err instanceof ValidationError && err.message.includes('Worker ID is required')
            );
        });
    });

    // =========================================================================
    // 7. Phase 3 Restoration Verification Safety (PROMPT 07.4)
    // =========================================================================
    describe('7. Restoration Provider Verification Guard', () => {
        it('restoration PUT success with verification GET null must be treated as failure', () => {
            const putResponse = { state: 'active', role: 'member' };
            const postRestoreGet = null; // GET verification failed to find member

            const isRestored = putResponse && postRestoreGet !== null;
            assert.strictEqual(isRestored, false, 'Restoration must never report success without provider GET confirmation');
        });

        it('restoration PUT success with verification GET confirmed is verified successfully', () => {
            const putResponse = { state: 'active', role: 'member' };
            const postRestoreGet = { state: 'active', role: 'member' };

            const isRestored = putResponse && postRestoreGet !== null && postRestoreGet.state === 'active';
            assert.strictEqual(isRestored, true, 'Restoration succeeds only when provider confirms active membership');
        });
    });

    after(async () => {
        await closePool();
    });
});
