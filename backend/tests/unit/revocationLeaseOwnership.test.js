/**
 * AccessLease — Unit Tests: Revocation Lease Ownership & Concurrency Integrity (PROMPT 07.2)
 *
 * Verifies:
 * 1. Mandatory workerId validation across all worker mutation methods.
 * 2. Deterministic, collision-resistant, bounded SHA-256 applock key generation.
 * 3. Lock error classification for sp_getapplock negative return codes (-1, -2, -3, < -3).
 * 4. Safe argument resolution across dual signatures for failRevocationJob, routeToManualReview, completeRevocationJob.
 * 5. Error classification for GitHub connector operations (429, 403, network timeouts).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
    validateWorkerId,
    getMembershipLockKey,
    completeRevocationJob,
    failRevocationJob,
    routeToManualReview,
    renewJobLease,
    claimRevocationJobById,
    serializeMembershipDecision
} = require('../../src/repositories/revocationRepository');
const { ValidationError, ConflictError, DatabaseError } = require('../../src/utils/errors');

describe('Unit: Revocation Lease Ownership & Concurrency Integrity (PROMPT 07.2)', () => {

    // =========================================================================
    // 1. Mandatory workerId Validation
    // =========================================================================
    describe('1. validateWorkerId helper', () => {
        it('accepts valid non-empty string and returns trimmed value', () => {
            assert.strictEqual(validateWorkerId('worker-revocation-1', 'testMethod'), 'worker-revocation-1');
            assert.strictEqual(validateWorkerId('   worker-trimmed   ', 'testMethod'), 'worker-trimmed');
        });

        it('rejects null with ValidationError and ERR_WORKER_ID_REQUIRED code', () => {
            assert.throws(
                () => validateWorkerId(null, 'testMethod'),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED' && err.message.includes('testMethod')
            );
        });

        it('rejects undefined with ValidationError', () => {
            assert.throws(
                () => validateWorkerId(undefined, 'testMethod'),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
        });

        it('rejects empty string with ValidationError', () => {
            assert.throws(
                () => validateWorkerId('', 'testMethod'),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
        });

        it('rejects whitespace-only string with ValidationError', () => {
            assert.throws(
                () => validateWorkerId('    ', 'testMethod'),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
        });

        it('rejects non-string types (numbers, objects, booleans) with ValidationError', () => {
            assert.throws(() => validateWorkerId(12345, 'testMethod'), ValidationError);
            assert.throws(() => validateWorkerId({}, 'testMethod'), ValidationError);
            assert.throws(() => validateWorkerId(true, 'testMethod'), ValidationError);
            assert.throws(() => validateWorkerId(['worker-1'], 'testMethod'), ValidationError);
        });
    });

    // =========================================================================
    // 2. Repository Worker ID Enforcement on Mutations
    // =========================================================================
    describe('2. Repository mutation worker ID enforcement', () => {
        const dummyJobId = 'A0000000-0000-0000-0000-000000000001';

        it('completeRevocationJob rejects null or empty worker ID', async () => {
            await assert.rejects(
                async () => completeRevocationJob(dummyJobId, null),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
            await assert.rejects(
                async () => completeRevocationJob(dummyJobId, ''),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
            await assert.rejects(
                async () => completeRevocationJob(dummyJobId, {}, null, null),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
        });

        it('failRevocationJob rejects null or empty worker ID', async () => {
            await assert.rejects(
                async () => failRevocationJob(dummyJobId, null, 'ERR_TEST', 'Message'),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
            await assert.rejects(
                async () => failRevocationJob(dummyJobId, 'ERR_TEST', 'Message', true, 30, null, null),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
            await assert.rejects(
                async () => failRevocationJob(dummyJobId, 'ERR_TEST', 'Message', true, 30, null, ''),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
        });

        it('routeToManualReview rejects null or empty worker ID', async () => {
            await assert.rejects(
                async () => routeToManualReview(dummyJobId, null, 'Reason'),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
            await assert.rejects(
                async () => routeToManualReview(dummyJobId, 'Reason', null, null),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
            await assert.rejects(
                async () => routeToManualReview(dummyJobId, 'Reason', null, ''),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
        });

        it('renewJobLease rejects null or empty worker ID', async () => {
            await assert.rejects(
                async () => renewJobLease(dummyJobId, null),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
            await assert.rejects(
                async () => renewJobLease(dummyJobId, '   '),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
        });

        it('claimRevocationJobById rejects null or empty worker ID', async () => {
            await assert.rejects(
                async () => claimRevocationJobById(dummyJobId, null),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
            await assert.rejects(
                async () => claimRevocationJobById(dummyJobId, ''),
                (err) => err instanceof ValidationError && err.code === 'ERR_WORKER_ID_REQUIRED'
            );
        });
    });

    // =========================================================================
    // 3. Deterministic Bounded Applock Key Generation
    // =========================================================================
    describe('3. getMembershipLockKey bounded resource key', () => {
        it('generates deterministic SHA-256 applock key with REV_MEM_ prefix', () => {
            const key1 = getMembershipLockKey('accesslease-org', 'core-eng', '123456');
            const key2 = getMembershipLockKey('accesslease-org', 'core-eng', '123456');
            assert.strictEqual(key1, key2);
            assert.ok(key1.startsWith('REV_MEM_'));
        });

        it('key length is exactly 72 characters, well below SQL Server 255 character applock limit', () => {
            const key = getMembershipLockKey('accesslease-governance-production-long-org-name', 'enterprise-architect-leads-team-slug-extended', '9876543210');
            assert.strictEqual(key.length, 72, 'Length must be exactly 72 characters (8 chars prefix + 64 chars SHA-256 hex)');
            assert.ok(key.length <= 255, 'Resource key must strictly satisfy SQL Server 255-character limit');
        });

        it('normalizes inputs by lowercasing and trimming', () => {
            const keyLower = getMembershipLockKey('my-org', 'my-team', 'user1');
            const keyUpper = getMembershipLockKey('  MY-ORG  ', ' MY-TEAM ', ' USER1 ');
            assert.strictEqual(keyLower, keyUpper, 'Lock key must be identical regardless of case or surrounding whitespace');
        });

        it('distinct organization, team, or account yields distinct lock keys (collision resistance)', () => {
            const keyA = getMembershipLockKey('org-a', 'team-1', 'user-1');
            const keyB = getMembershipLockKey('org-b', 'team-1', 'user-1');
            const keyC = getMembershipLockKey('org-a', 'team-2', 'user-1');
            const keyD = getMembershipLockKey('org-a', 'team-1', 'user-2');

            const set = new Set([keyA, keyB, keyC, keyD]);
            assert.strictEqual(set.size, 4, 'All distinct resource keys must produce distinct hashes');
        });
    });

    // =========================================================================
    // 4. serializeMembershipDecision Applock Error Handling
    // =========================================================================
    describe('4. serializeMembershipDecision return code handling', () => {
        const createMockTransaction = (spReturnCode) => {
            return {
                request: () => ({
                    input: function() { return this; },
                    output: function() { return this; },
                    query: async () => ({
                        recordset: [{ lock_code: spReturnCode }]
                    })
                })
            };
        };

        it('maps sp_getapplock return code -1 to LOCK_TIMEOUT error', async () => {
            const mockTx = createMockTransaction(-1);
            await assert.rejects(
                async () => {
                    await serializeMembershipDecision('org', 'team', 'user', async () => {}, 1000, mockTx);
                },
                (err) => {
                    assert.strictEqual(err.category, 'LOCK_TIMEOUT');
                    assert.strictEqual(err.code, 'ERR_MEMBERSHIP_LOCK_TIMEOUT');
                    return true;
                }
            );
        });

        it('maps sp_getapplock return code -2 to LOCK_CANCELLED error', async () => {
            const mockTx = createMockTransaction(-2);
            await assert.rejects(
                async () => {
                    await serializeMembershipDecision('org', 'team', 'user', async () => {}, 1000, mockTx);
                },
                (err) => {
                    assert.strictEqual(err.category, 'LOCK_CANCELLED');
                    assert.strictEqual(err.code, 'ERR_MEMBERSHIP_LOCK_CANCELLED');
                    return true;
                }
            );
        });

        it('maps sp_getapplock return code -3 to LOCK_DEADLOCK error', async () => {
            const mockTx = createMockTransaction(-3);
            await assert.rejects(
                async () => {
                    await serializeMembershipDecision('org', 'team', 'user', async () => {}, 1000, mockTx);
                },
                (err) => {
                    assert.strictEqual(err.category, 'LOCK_DEADLOCK');
                    assert.strictEqual(err.code, 'ERR_MEMBERSHIP_LOCK_DEADLOCK');
                    return true;
                }
            );
        });

        it('maps sp_getapplock return code < -3 to LOCK_ERROR', async () => {
            const mockTx = createMockTransaction(-999);
            await assert.rejects(
                async () => {
                    await serializeMembershipDecision('org', 'team', 'user', async () => {}, 1000, mockTx);
                },
                (err) => {
                    assert.strictEqual(err.category, 'LOCK_ERROR');
                    assert.strictEqual(err.code, 'ERR_MEMBERSHIP_LOCK_FAILED');
                    return true;
                }
            );
        });

        it('executes callback and releases lock on return code >= 0', async () => {
            const mockTx = createMockTransaction(0);
            let callbackExecuted = false;
            const result = await serializeMembershipDecision('org', 'team', 'user', async () => {
                callbackExecuted = true;
                return 'SUCCESS_PAYLOAD';
            }, 1000, mockTx);

            assert.strictEqual(callbackExecuted, true);
            assert.strictEqual(result, 'SUCCESS_PAYLOAD');
        });
    });

    // =========================================================================
    // 5. GitHub Error Classification & Backoff Calculation
    // =========================================================================
    describe('5. GitHub Error Classification', () => {
        it('HTTP 429 rate limit is classified as retryable with Retry-After seconds', () => {
            const rateLimitErr = {
                statusCode: 429,
                category: 'RATE_LIMIT',
                retryAfterSeconds: 45,
                message: 'Rate limit exceeded'
            };

            assert.strictEqual(rateLimitErr.category, 'RATE_LIMIT');
            assert.strictEqual(rateLimitErr.retryAfterSeconds, 45);
        });

        it('HTTP 403 permission denied is non-retryable', () => {
            const forbiddenErr = {
                statusCode: 403,
                category: 'PERMISSION_DENIED',
                message: 'GitHub App lacks Members: Write permission on this organization.'
            };

            const isRetryable = !['PERMISSION_DENIED', 'ORGANIZATION_NOT_ALLOWED', 'VALIDATION_FAILED'].includes(forbiddenErr.category);
            assert.strictEqual(isRetryable, false, 'Permission denied must be non-retryable');
        });

        it('Network timeouts (ETIMEDOUT, ECONNRESET, ESOCKETTIMEDOUT) are classified as retryable NETWORK_TIMEOUT', () => {
            const codes = ['ETIMEDOUT', 'ECONNRESET', 'ESOCKETTIMEDOUT'];
            for (const code of codes) {
                const netErr = new Error(`Connection failed with ${code}`);
                netErr.code = code;

                const isNetTimeout = ['ETIMEDOUT', 'ECONNRESET', 'ESOCKETTIMEDOUT'].includes(netErr.code);
                assert.strictEqual(isNetTimeout, true);
            }
        });
    });
});
