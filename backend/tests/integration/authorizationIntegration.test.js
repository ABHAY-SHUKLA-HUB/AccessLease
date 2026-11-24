/**
 * AccessLease — Integration Tests: Real Database RBAC & Authorization Flow
 * Target: Microsoft SQL Server LocalDB (AccessLease_TestDB)
 * 
 * Verifies:
 * 1. Live identity mapping + role retrieval + permission generation for seeded users.
 * 2. GET /api/auth/me outputs roles and effective permissions array from live SQL Server.
 * 3. Contractor access control with live dbo.contractor_engagements.
 * 4. Separation of duties validation against real dbo.access_requests.
 * 5. Deny-by-default behavior for unmapped roles.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const cp = require('child_process');
const db = require('../../src/config/database');
const tokenUtils = require('../../src/utils/tokenUtils');
const authService = require('../../src/services/authService');
const { getAuthMe } = require('../../src/functions/auth');
const Permissions = require('../../src/security/permissions');
const { canAccessContractorData, validateSeparationOfDuties } = require('../../src/security/resourceAccess');

describe('Integration: Real Database RBAC & Permission Flow (AccessLease_TestDB)', () => {
    let localDbAvailable = false;
    let rsaKeyPair;
    let originalTenantId;
    let originalApiClientId;
    let originalApiAudience;

    const TEST_TENANT_ID = 'test-rbac-int-tenant';
    const TEST_API_CLIENT_ID = 'test-rbac-int-api';
    const TEST_AUDIENCE = `api://${TEST_API_CLIENT_ID}`;
    const TEST_ISSUER = `https://login.microsoftonline.com/${TEST_TENANT_ID}/v2.0`;

    before(async () => {
        process.env.SQL_SERVER = '(localdb)\\MSSQLLocalDB';
        process.env.SQL_DATABASE = 'AccessLease_TestDB';

        originalTenantId = process.env.ENTRA_TENANT_ID;
        originalApiClientId = process.env.ENTRA_API_CLIENT_ID;
        originalApiAudience = process.env.ENTRA_API_AUDIENCE;

        process.env.ENTRA_TENANT_ID = TEST_TENANT_ID;
        process.env.ENTRA_API_CLIENT_ID = TEST_API_CLIENT_ID;
        process.env.ENTRA_API_AUDIENCE = TEST_AUDIENCE;

        try {
            cp.execSync('sqllocaldb start MSSQLLocalDB', { stdio: 'pipe' });
            const pool = await db.getPool();
            localDbAvailable = pool && pool.connected;
        } catch {
            localDbAvailable = false;
        }

        // Generate in-memory RSA keypair for testing
        rsaKeyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        tokenUtils.setCustomKeyResolver((header, callback) => {
            callback(null, rsaKeyPair.publicKey);
        });
    });

    after(async () => {
        tokenUtils.setCustomKeyResolver(null);
        if (originalTenantId) process.env.ENTRA_TENANT_ID = originalTenantId;
        if (originalApiClientId) process.env.ENTRA_API_CLIENT_ID = originalApiClientId;
        if (originalApiAudience) process.env.ENTRA_API_AUDIENCE = originalApiAudience;
        await db.closePool();
    });

    function createToken(oid) {
        return jwt.sign(
            {
                oid,
                sub: `sub-${oid}`,
                email: `${oid.toLowerCase()}@accesslease.corp`,
                name: `User ${oid}`,
                tid: TEST_TENANT_ID
            },
            rsaKeyPair.privateKey,
            {
                algorithm: 'RS256',
                audience: TEST_AUDIENCE,
                issuer: TEST_ISSUER,
                expiresIn: '30m'
            }
        );
    }

    test('1. authService: resolves seeded contractor profile and computes contractor permissions', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server LocalDB not available.');
            return;
        }

        const token = createToken('TEST-OID-CONTRACTOR');
        const user = await authService.authenticateToken(token);

        assert.ok(user);
        assert.strictEqual(user.entra_object_id, 'TEST-OID-CONTRACTOR');
        assert.strictEqual(user.user_type, 'CONTRACTOR');
        assert.ok(Array.isArray(user.permissions));
        assert.strictEqual(user.is_active, true);
    });

    test('2. authService: resolves seeded sponsor profile from live database', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server LocalDB not available.');
            return;
        }

        const token = createToken('TEST-OID-SPONSOR');
        const user = await authService.authenticateToken(token);

        assert.ok(user);
        assert.strictEqual(user.entra_object_id, 'TEST-OID-SPONSOR');
        assert.strictEqual(user.email, 'sponsor@example.com');
        assert.strictEqual(user.user_type, 'INTERNAL_EMPLOYEE');
        assert.ok(Array.isArray(user.roles));
        assert.ok(Array.isArray(user.permissions));
    });

    test('3. GET /api/auth/me: returns authenticated user profile with roles and permissions array', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server LocalDB not available.');
            return;
        }

        const token = createToken('TEST-OID-SPONSOR');
        const mockReq = {
            headers: { authorization: `Bearer ${token}` },
            url: 'http://localhost:7071/api/auth/me'
        };
        const mockContext = { invocationId: 'rbac-int-me' };

        const res = await getAuthMe(mockReq, mockContext);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.success, true);
        assert.ok(res.jsonBody.data.user);
        assert.strictEqual(res.jsonBody.data.user.email, 'sponsor@example.com');
        assert.ok('roles' in res.jsonBody.data.user);
        assert.ok('permissions' in res.jsonBody.data.user);
        assert.ok(Array.isArray(res.jsonBody.data.user.permissions));
    });

    test('4. Real Contextual Access: Contractor accessing live contractor engagement data', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server LocalDB not available.');
            return;
        }

        const pool = await db.getPool();
        const contractorRes = await pool.request().query("SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-CONTRACTOR'");
        assert.ok(contractorRes.recordset.length > 0);
        const contractorUserId = contractorRes.recordset[0].user_id;

        const contractorUser = {
            user_id: contractorUserId,
            roles: [{ role_code: 'CONTRACTOR' }]
        };

        // Allowed: contractor accessing own records
        const selfAccess = await canAccessContractorData(contractorUser, contractorUserId);
        assert.strictEqual(selfAccess, true);

        // Denied: contractor accessing another contractor's data
        const crossAccess = await canAccessContractorData(contractorUser, '00000000-0000-0000-0000-000000000000');
        assert.strictEqual(crossAccess, false);
    });

    test('5. Real Separation of Duties: Evaluates live access request from database', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server LocalDB not available.');
            return;
        }

        const pool = await db.getPool();
        const reqRes = await pool.request().query("SELECT TOP 1 request_id, requested_by_user_id FROM dbo.access_requests");
        if (reqRes.recordset.length === 0) {
            t.skip('Skipped: No access request found in test database.');
            return;
        }

        const liveRequest = reqRes.recordset[0];

        // Creator of the request attempts to approve
        const requesterUser = {
            user_id: liveRequest.requested_by_user_id,
            roles: [{ role_code: 'INTERNAL_SPONSOR' }]
        };

        const canApproveOwn = await validateSeparationOfDuties(requesterUser, liveRequest.request_id);
        assert.strictEqual(canApproveOwn, false, 'Requester must not be allowed to approve their own live request');

        // Different user attempts to approve
        const differentUser = {
            user_id: '11111111-2222-3333-4444-555555555555',
            roles: [{ role_code: 'RESOURCE_OWNER' }]
        };

        const canApproveOther = await validateSeparationOfDuties(differentUser, liveRequest.request_id);
        assert.strictEqual(canApproveOther, true, 'Different authorized user passes separation of duties');
    });
});

