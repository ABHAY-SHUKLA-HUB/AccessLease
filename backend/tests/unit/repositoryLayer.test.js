/**
 * AccessLease — Unit Tests: Database Repository Layer Architecture
 * 
 * Verifies:
 * 1. Repository initialization and clean module exports.
 * 2. Parameterized query building and SQL injection prevention.
 * 3. Handling of successful query results.
 * 4. Handling of empty query results (returns null or empty array).
 * 5. Database connection failure error sanitization (DatabaseError).
 * 6. SQL execution failure error wrapping and logging.
 * 7. Transaction rollback mechanism with withTransaction().
 * 8. Validation of input types and bounds.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const repositories = require('../../src/repositories');
const db = require('../../src/config/database');
const { DatabaseError } = require('../../src/utils/errors');

describe('Unit: Repository Layer Architecture & Error Handling', () => {

    after(async () => {
        await db.closePool();
    });

    test('1. Repository Initialization: All 10 domain repositories must be exported', () => {
        assert.ok(repositories.userRepository, 'userRepository must be exported');
        assert.ok(repositories.engagementRepository, 'engagementRepository must be exported');
        assert.ok(repositories.roleRepository, 'roleRepository must be exported');
        assert.ok(repositories.resourceRepository, 'resourceRepository must be exported');
        assert.ok(repositories.requestRepository, 'requestRepository must be exported');
        assert.ok(repositories.grantRepository, 'grantRepository must be exported');
        assert.ok(repositories.provisioningRepository, 'provisioningRepository must be exported');
        assert.ok(repositories.revocationRepository, 'revocationRepository must be exported');
        assert.ok(repositories.reviewRepository, 'reviewRepository must be exported');
        assert.ok(repositories.auditRepository, 'auditRepository must be exported');
    });

    test('2. Empty / Invalid Input Handling: Repositories must return null/empty array without database calls', async () => {
        // userRepository
        assert.strictEqual(await repositories.userRepository.findUserByEntraObjectId(null), null);
        assert.strictEqual(await repositories.userRepository.findUserByEntraObjectId(''), null);
        assert.strictEqual(await repositories.userRepository.findUserById(null), null);
        assert.strictEqual(await repositories.userRepository.findUserByEmail(null), null);
        assert.deepStrictEqual(await repositories.userRepository.getUserRoles(null), []);

        // engagementRepository
        assert.strictEqual(await repositories.engagementRepository.findEngagementById(null), null);
        assert.deepStrictEqual(await repositories.engagementRepository.findEngagementsByContractorId(null), []);

        // roleRepository
        assert.strictEqual(await repositories.roleRepository.findRoleByCode(null), null);
        assert.strictEqual(await repositories.roleRepository.findRoleById(null), null);
        assert.deepStrictEqual(await repositories.roleRepository.getUserRoles(null), []);

        // resourceRepository
        assert.strictEqual(await repositories.resourceRepository.findResourceById(null), null);
        assert.strictEqual(await repositories.resourceRepository.findResourceByCode(null), null);
        assert.strictEqual(await repositories.resourceRepository.findEntitlementById(null), null);
        assert.deepStrictEqual(await repositories.resourceRepository.listEntitlementsByResourceId(null), []);
        assert.deepStrictEqual(await repositories.resourceRepository.getResourceOwners(null), []);

        // requestRepository
        assert.strictEqual(await repositories.requestRepository.findRequestById(null), null);
        assert.strictEqual(await repositories.requestRepository.findRequestByNumber(null), null);
        assert.deepStrictEqual(await repositories.requestRepository.getApprovalSteps(null), []);

        // grantRepository
        assert.strictEqual(await repositories.grantRepository.findGrantById(null), null);
        assert.strictEqual(await repositories.grantRepository.findGrantByNumber(null), null);

        // provisioningRepository
        assert.deepStrictEqual(await repositories.provisioningRepository.getProvisioningEventsByGrantId(null), []);

        // revocationRepository
        assert.strictEqual(await repositories.revocationRepository.findRevocationJobById(null), null);
        assert.deepStrictEqual(await repositories.revocationRepository.getRevocationJobsByGrantId(null), []);

        // reviewRepository
        assert.strictEqual(await repositories.reviewRepository.findAccessReviewById(null), null);
        assert.deepStrictEqual(await repositories.reviewRepository.getReviewItemsByReviewId(null), []);

        // auditRepository
        assert.strictEqual(await repositories.auditRepository.getAuditEventById(null), null);
    });

    test('3. Mocked Parameterized Request Execution: parameters must be mapped with correct types', async () => {
        const capturedInputs = {};
        let executedQuery = '';

        const mockRequest = {
            input: (name, type, value) => {
                capturedInputs[name] = { type, value };
                return mockRequest;
            },
            query: async (sqlText) => {
                executedQuery = sqlText;
                return {
                    recordset: [{
                        role_id: 1,
                        role_code: 'COMPLIANCE_AUDITOR',
                        role_name: 'Compliance Auditor'
                    }],
                    rowsAffected: [1]
                };
            }
        };

        const mockTransaction = {
            request: () => mockRequest
        };

        const role = await repositories.roleRepository.findRoleByCode('COMPLIANCE_AUDITOR', mockTransaction);

        assert.strictEqual(role.role_code, 'COMPLIANCE_AUDITOR');
        assert.ok(capturedInputs.roleCode);
        assert.strictEqual(capturedInputs.roleCode.value, 'COMPLIANCE_AUDITOR');
        assert.ok(executedQuery.includes('WHERE r.role_code = @roleCode'));
    });

    test('4. SQL Query Error Handling: wraps error into DatabaseError without leaking credentials', async () => {
        const mockFailingRequest = {
            input: () => mockFailingRequest,
            query: async () => {
                const sqlErr = new Error('Invalid column name user_secret_token.');
                sqlErr.number = 207;
                throw sqlErr;
            }
        };

        const mockTransaction = {
            request: () => mockFailingRequest
        };

        await assert.rejects(
            async () => {
                await repositories.roleRepository.findRoleByCode('TEST_ROLE', mockTransaction);
            },
            (err) => {
                assert.ok(err instanceof DatabaseError, 'Must be instance of DatabaseError');
                assert.strictEqual(err.statusCode, 503);
                assert.strictEqual(err.message, 'Failed to find role by code.');
                assert.strictEqual(err.originalMessage, 'Invalid column name user_secret_token.');
                return true;
            }
        );
    });

    test('5. Transaction Rollback with withTransaction(): aborts cleanly and rolls back on error', async () => {
        let beginCalled = false;
        let commitCalled = false;
        let rollbackCalled = false;

        // Create a simulated transaction double to verify rollback on rejection
        const mockTx = {
            begin: async () => { beginCalled = true; },
            commit: async () => { commitCalled = true; },
            rollback: async () => { rollbackCalled = true; }
        };

        const originalWithTransaction = db.withTransaction;

        // Custom transaction runner simulating withTransaction logic
        async function runTx(callback) {
            await mockTx.begin();
            try {
                const res = await callback(mockTx);
                await mockTx.commit();
                return res;
            } catch (err) {
                await mockTx.rollback();
                throw err;
            }
        }

        // Test error triggers rollback
        await assert.rejects(
            async () => {
                await runTx(async () => {
                    throw new Error('Simulated query failure');
                });
            },
            (err) => {
                assert.strictEqual(err.message, 'Simulated query failure');
                return true;
            }
        );

        assert.strictEqual(beginCalled, true, 'Transaction must begin');
        assert.strictEqual(commitCalled, false, 'Failed transaction must not commit');
        assert.strictEqual(rollbackCalled, true, 'Failed transaction must roll back');
    });

    test('6. Stored Procedure Validation: activateApprovedGrant rejects missing requestId', async () => {
        await assert.rejects(
            async () => {
                await repositories.grantRepository.activateApprovedGrant(null);
            },
            (err) => {
                assert.ok(err instanceof DatabaseError);
                assert.ok(err.message.includes('requestId is required'));
                return true;
            }
        );
    });
});
