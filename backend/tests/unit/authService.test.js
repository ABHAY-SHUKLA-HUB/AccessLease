/**
 * AccessLease — Unit Tests: Authentication Service & Identity Mapping (authService.js)
 * 
 * Verifies:
 * 1. Mapping verified Entra Object ID (oid) to existing application user in dbo.users.
 * 2. Rejection of unknown Entra identities (ERR_USER_NOT_REGISTERED).
 * 3. Rejection of deactivated users (is_active = false) with ForbiddenError (ERR_USER_INACTIVE).
 * 4. User role resolution.
 * 5. Verification that returned profile leaks zero secrets, hashes, or credentials.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const tokenUtils = require('../../src/utils/tokenUtils');
const authService = require('../../src/services/authService');
const userRepository = require('../../src/repositories/userRepository');
const { UnauthorizedError, ForbiddenError } = require('../../src/utils/errors');

describe('Unit: Authentication Service & Identity Mapping (authService)', () => {
    let rsaKeyPair;
    let originalFindUserByEntraObjectId;
    let originalGetUserRoles;
    let envBackup = {};

    const TEST_TENANT_ID = 'test-tenant-1111-2222-3333';
    const TEST_CLIENT_ID = 'test-client-aaaa-bbbb-cccc';
    const TEST_AUDIENCE = `api://${TEST_CLIENT_ID}`;
    const TEST_ISSUER = `https://login.microsoftonline.com/${TEST_TENANT_ID}/v2.0`;

    before(() => {
        rsaKeyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        tokenUtils.setCustomKeyResolver((header, callback) => {
            callback(null, rsaKeyPair.publicKey);
        });

        // Backup environment and enforce test identity boundaries
        envBackup = {
            ENTRA_TENANT_ID: process.env.ENTRA_TENANT_ID,
            ENTRA_API_CLIENT_ID: process.env.ENTRA_API_CLIENT_ID,
            ENTRA_API_AUDIENCE: process.env.ENTRA_API_AUDIENCE,
            ENTRA_ISSUER: process.env.ENTRA_ISSUER
        };
        process.env.ENTRA_TENANT_ID = TEST_TENANT_ID;
        process.env.ENTRA_API_CLIENT_ID = TEST_CLIENT_ID;
        process.env.ENTRA_API_AUDIENCE = TEST_AUDIENCE;
        process.env.ENTRA_ISSUER = TEST_ISSUER;

        // Backup repository methods for isolated unit testing
        originalFindUserByEntraObjectId = userRepository.findUserByEntraObjectId;
        originalGetUserRoles = userRepository.getUserRoles;
    });

    after(() => {
        tokenUtils.setCustomKeyResolver(null);
        userRepository.findUserByEntraObjectId = originalFindUserByEntraObjectId;
        userRepository.getUserRoles = originalGetUserRoles;

        // Restore environment
        for (const [key, val] of Object.entries(envBackup)) {
            if (val !== undefined) process.env[key] = val;
            else delete process.env[key];
        }
    });

    function createTokenForOid(oid) {
        return jwt.sign(
            {
                oid,
                sub: `sub-${oid}`,
                email: 'test.identity@accesslease.corp',
                name: 'Identity Tester',
                tid: TEST_TENANT_ID
            },
            rsaKeyPair.privateKey,
            {
                algorithm: 'RS256',
                audience: TEST_AUDIENCE,
                issuer: TEST_ISSUER,
                expiresIn: '1h'
            }
        );
    }

    test('1. Identity Mapping: should resolve valid Entra OID to internal user profile', async () => {
        const mockOid = 'entra-oid-governance-123';
        const mockDbUser = {
            user_id: '11111111-2222-3333-4444-555555555555',
            entra_object_id: mockOid,
            email: 'governance.officer@accesslease.corp',
            first_name: 'Genevieve',
            last_name: 'Governance',
            display_name: 'Genevieve Governance',
            user_type: 'INTERNAL_EMPLOYEE',
            department: 'Identity Security',
            is_active: true
        };

        const mockRoles = [
            { role_id: 2, role_code: 'SECURITY_OFFICER', role_name: 'Security Officer' }
        ];

        userRepository.findUserByEntraObjectId = async (oid) => {
            return oid === mockOid ? mockDbUser : null;
        };

        userRepository.getUserRoles = async (userId) => {
            return userId === mockDbUser.user_id ? mockRoles : [];
        };

        const token = createTokenForOid(mockOid);
        const profile = await authService.authenticateToken(token, {
            audience: TEST_AUDIENCE,
            issuer: TEST_ISSUER
        });

        assert.strictEqual(profile.user_id, mockDbUser.user_id);
        assert.strictEqual(profile.entra_object_id, mockOid);
        assert.strictEqual(profile.email, mockDbUser.email);
        assert.strictEqual(profile.display_name, mockDbUser.display_name);
        assert.strictEqual(profile.user_type, 'INTERNAL_EMPLOYEE');
        assert.strictEqual(profile.is_active, true);
        assert.strictEqual(profile.roles.length, 1);
        assert.strictEqual(profile.roles[0].role_code, 'SECURITY_OFFICER');
    });

    test('2. Unknown User Rejection: should reject Entra identity not registered in dbo.users', async () => {
        const unknownOid = 'unknown-entra-oid-999';

        userRepository.findUserByEntraObjectId = async () => null;

        const token = createTokenForOid(unknownOid);

        await assert.rejects(
            async () => {
                await authService.authenticateToken(token, {
                    audience: TEST_AUDIENCE,
                    issuer: TEST_ISSUER
                });
            },
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_USER_NOT_REGISTERED');
                return true;
            }
        );
    });

    test('3. Deactivated User Rejection: should reject deactivated account with ForbiddenError (ERR_USER_INACTIVE)', async () => {
        const deactivatedOid = 'deactivated-oid-777';
        const mockInactiveUser = {
            user_id: '99999999-8888-7777-6666-555555555555',
            entra_object_id: deactivatedOid,
            email: 'terminated.contractor@vendor.corp',
            first_name: 'Terminated',
            last_name: 'Contractor',
            display_name: 'Terminated Contractor',
            user_type: 'CONTRACTOR',
            department: 'Vendor Engineering',
            is_active: false
        };

        userRepository.findUserByEntraObjectId = async () => mockInactiveUser;
        userRepository.getUserRoles = async () => [];

        const token = createTokenForOid(deactivatedOid);

        await assert.rejects(
            async () => {
                await authService.authenticateToken(token, {
                    audience: TEST_AUDIENCE,
                    issuer: TEST_ISSUER
                });
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_USER_INACTIVE');
                return true;
            }
        );
    });

    test('4. Zero Secret Leakage: verified profile must not contain internal secrets or database connection data', async () => {
        const testOid = 'audit-oid-555';
        userRepository.findUserByEntraObjectId = async () => ({
            user_id: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
            entra_object_id: testOid,
            email: 'audit@accesslease.corp',
            first_name: 'Auditor',
            last_name: 'User',
            display_name: 'Auditor User',
            user_type: 'INTERNAL_EMPLOYEE',
            department: 'Compliance',
            is_active: true
        });
        userRepository.getUserRoles = async () => [];

        const token = createTokenForOid(testOid);
        const profile = await authService.authenticateToken(token, {
            audience: TEST_AUDIENCE,
            issuer: TEST_ISSUER
        });

        const serialized = JSON.stringify(profile).toLowerCase();
        assert.strictEqual(serialized.includes('password'), false);
        assert.strictEqual(serialized.includes('client_secret'), false);
        assert.strictEqual(serialized.includes('connectionstring'), false);
        assert.strictEqual(serialized.includes('privatekey'), false);
        assert.strictEqual(serialized.includes('token_secret'), false);
    });

    test('5. Tenant Mismatch Pre-Database Rejection: tenant mismatch must NEVER query the database repository', async () => {
        let dbQueryCalls = 0;
        userRepository.findUserByEntraObjectId = async () => {
            dbQueryCalls++;
            return { user_id: 'fake', entra_object_id: 'fake' };
        };

        // Create token with foreign unauthorized tenant
        const foreignTenantToken = jwt.sign(
            {
                oid: 'entra-user-with-wrong-tenant',
                sub: 'sub-wrong-tenant',
                tid: 'unauthorized-foreign-tenant-9999'
            },
            rsaKeyPair.privateKey,
            {
                algorithm: 'RS256',
                audience: TEST_AUDIENCE,
                issuer: TEST_ISSUER,
                expiresIn: '1h'
            }
        );

        await assert.rejects(
            async () => {
                await authService.authenticateToken(foreignTenantToken, {
                    tenantId: TEST_TENANT_ID,
                    audience: TEST_AUDIENCE,
                    issuer: TEST_ISSUER
                });
            },
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_INVALID_TENANT_ID');
                return true;
            }
        );

        // Crucial security invariant: Database repository was NEVER queried
        assert.strictEqual(
            dbQueryCalls,
            0,
            'Security violation: Database repository must never be reached when tenant ID is mismatched'
        );
    });
});
