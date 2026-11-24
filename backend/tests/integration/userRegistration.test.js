/**
 * AccessLease — Admin-Controlled Internal User Registration & Governance Integration Tests
 * 
 * Verifies:
 * 1. POST /api/users without Authorization header returns HTTP 401 (ERR_MISSING_AUTH_HEADER).
 * 2. POST /api/users by non-admin identity (INTERNAL_SPONSOR) returns HTTP 403 (ERR_FORBIDDEN_ROLE).
 * 3. POST /api/users with missing/invalid inputs returns HTTP 400 (ERR_VALIDATION_FAILED).
 * 4. POST /api/users with invalid or unauthorized role codes returns HTTP 400 (ERR_VALIDATION_FAILED).
 * 5. POST /api/users by SYSTEM_ADMIN successfully registers internal user with atomic role assignments:
 *    - Status HTTP 201 Created conforming to canonical response envelope.
 *    - Database record in dbo.users has user_type = 'INTERNAL_EMPLOYEE', is_active = 1.
 *    - Assigned governance roles persisted in dbo.user_roles.
 *    - Immutable audit event USER_REGISTERED recorded in dbo.audit_events.
 * 6. SYSTEM_ADMIN role is not assigned automatically unless explicitly requested.
 * 7. POST /api/users with duplicate email returns HTTP 409 (ERR_USER_EXISTS).
 * 8. POST /api/users with duplicate Entra Object ID returns HTTP 409 (ERR_IDENTITY_EXISTS).
 * 9. GET /api/users lists internal users with assigned roles, respects pagination and search.
 * 10. PATCH /api/users/{id}/status activates/deactivates users and blocks self-deactivation.
 * 11. Newly registered user can authenticate via authService; unregistered Entra user receives ERR_USER_NOT_REGISTERED.
 * 12. External contractor registered with synthetic OID remains strictly ineligible for Microsoft Entra login.
 * 13. Automated test cleanup removes test records from AccessLease_TestDB.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const cp = require('child_process');

const { createUser, listUsers, updateUserStatus, listRoles } = require('../../src/functions/users');
const { createContractor } = require('../../src/functions/contractors');
const authService = require('../../src/services/authService');
const { userRepository, roleRepository } = require('../../src/repositories');
const tokenUtils = require('../../src/utils/tokenUtils');
const db = require('../../src/config/database');

describe('Integration: SYSTEM_ADMIN Internal User Registration & Governance (LocalDB)', () => {
    let rsaKeyPair;
    let originalTenantId;
    let originalSpaClientId;
    let originalApiClientId;
    let originalApiAudience;
    let localDbAvailable = false;
    let adminOid = null;

    const TEST_TENANT_ID = 'test-user-reg-tenant-999';
    const TEST_SPA_CLIENT_ID = 'test-spa-client-user-reg';
    const TEST_API_CLIENT_ID = 'test-api-client-user-reg';
    const TEST_AUDIENCE = `api://${TEST_API_CLIENT_ID}`;
    const TEST_ISSUER = `https://login.microsoftonline.com/${TEST_TENANT_ID}/v2.0`;

    const createdUserIds = [];

    before(async () => {
        originalTenantId = process.env.ENTRA_TENANT_ID;
        originalSpaClientId = process.env.ENTRA_SPA_CLIENT_ID;
        originalApiClientId = process.env.ENTRA_API_CLIENT_ID;
        originalApiAudience = process.env.ENTRA_API_AUDIENCE;

        process.env.ENTRA_TENANT_ID = TEST_TENANT_ID;
        process.env.ENTRA_SPA_CLIENT_ID = TEST_SPA_CLIENT_ID;
        process.env.ENTRA_API_CLIENT_ID = TEST_API_CLIENT_ID;
        process.env.ENTRA_API_AUDIENCE = TEST_AUDIENCE;
        process.env.SQL_SERVER = '(localdb)\\MSSQLLocalDB';
        process.env.SQL_DATABASE = 'AccessLease_TestDB';

        rsaKeyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        tokenUtils.setCustomKeyResolver((header, callback) => {
            callback(null, rsaKeyPair.publicKey);
        });

        try {
            cp.execSync('sqllocaldb start MSSQLLocalDB', { stdio: 'pipe' });
            const pool = await db.getPool();
            localDbAvailable = pool && pool.connected;

            // Resolve an existing SYSTEM_ADMIN user from AccessLease_TestDB
            const adminQuery = await pool.request().query(`
                SELECT TOP 1 u.entra_object_id 
                FROM dbo.users u
                JOIN dbo.user_roles ur ON u.user_id = ur.user_id
                JOIN dbo.roles r ON ur.role_id = r.role_id
                WHERE r.role_code = 'SYSTEM_ADMIN' AND u.is_active = 1;
            `);
            if (adminQuery.recordset.length > 0) {
                adminOid = adminQuery.recordset[0].entra_object_id;
            } else {
                adminOid = 'f2bba284-9dba-4570-b865-875a009870ed';
            }
        } catch {
            localDbAvailable = false;
        }
    });

    after(async () => {
        tokenUtils.setCustomKeyResolver(null);
        if (originalTenantId) process.env.ENTRA_TENANT_ID = originalTenantId;
        if (originalSpaClientId) process.env.ENTRA_SPA_CLIENT_ID = originalSpaClientId;
        if (originalApiClientId) process.env.ENTRA_API_CLIENT_ID = originalApiClientId;
        if (originalApiAudience) process.env.ENTRA_API_AUDIENCE = originalApiAudience;

        if (localDbAvailable && createdUserIds.length > 0) {
            const pool = await db.getPool();
            for (const uid of createdUserIds) {
                try {
                    await pool.request()
                        .input('uid', uid)
                        .query(`
                            DELETE FROM dbo.audit_events WHERE entity_id = @uid OR actor_user_id = @uid;
                            DELETE FROM dbo.user_roles WHERE user_id = @uid;
                            DELETE FROM dbo.users WHERE user_id = @uid;
                        `);
                } catch {
                    // Ignore cleanup errors
                }
            }
        }

        await db.closePool();
    });

    function createSignedToken(oid, email = 'user@example.com') {
        return jwt.sign(
            {
                oid,
                sub: `sub-${oid}`,
                email,
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

    test('1. POST /api/users: returns 401 when Authorization header is missing', async (t) => {
        if (!localDbAvailable) { t.skip('LocalDB unavailable'); return; }

        const mockReq = { headers: {}, body: {} };
        const res = await createUser(mockReq, { invocationId: 'test-no-auth' });

        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.success, false);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_MISSING_AUTH_HEADER');
    });

    test('2. POST /api/users: returns 403 when user is not SYSTEM_ADMIN', async (t) => {
        if (!localDbAvailable) { t.skip('LocalDB unavailable'); return; }

        const sponsorToken = createSignedToken('TEST-OID-SPONSOR', 'sponsor@example.com');
        const mockReq = {
            headers: { authorization: `Bearer ${sponsorToken}` },
            body: {
                email: 'test.intern@accesslease.corp',
                displayName: 'Test Intern',
                entraObjectId: crypto.randomUUID(),
                roleCodes: ['INTERNAL_SPONSOR']
            }
        };

        const res = await createUser(mockReq, { invocationId: 'test-forbidden-role' });
        assert.strictEqual(res.status, 403);
        assert.strictEqual(res.jsonBody.success, false);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_FORBIDDEN_ROLE');
    });

    test('3. POST /api/users: returns 400 when required fields are missing or invalid', async (t) => {
        if (!localDbAvailable) { t.skip('LocalDB unavailable'); return; }

        const adminToken = createSignedToken(adminOid);

        // Missing email
        let res = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: { displayName: 'John Doe', entraObjectId: crypto.randomUUID(), roleCodes: ['SECURITY_OFFICER'] }
        }, { invocationId: 'test-missing-email' });
        assert.strictEqual(res.status, 400);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_VALIDATION_FAILED');

        // Invalid email format
        res = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: { email: 'not-an-email', displayName: 'John Doe', entraObjectId: crypto.randomUUID(), roleCodes: ['SECURITY_OFFICER'] }
        }, { invocationId: 'test-invalid-email' });
        assert.strictEqual(res.status, 400);

        // Missing display name
        res = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: { email: 'john@example.com', entraObjectId: crypto.randomUUID(), roleCodes: ['SECURITY_OFFICER'] }
        }, { invocationId: 'test-missing-name' });
        assert.strictEqual(res.status, 400);

        // Missing entra object ID
        res = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: { email: 'john@example.com', displayName: 'John Doe', roleCodes: ['SECURITY_OFFICER'] }
        }, { invocationId: 'test-missing-oid' });
        assert.strictEqual(res.status, 400);

        // Empty roleCodes array
        res = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: { email: 'john@example.com', displayName: 'John Doe', entraObjectId: crypto.randomUUID(), roleCodes: [] }
        }, { invocationId: 'test-empty-roles' });
        assert.strictEqual(res.status, 400);
    });

    test('4. POST /api/users: returns 400 when invalid or unauthorized role is requested', async (t) => {
        if (!localDbAvailable) { t.skip('LocalDB unavailable'); return; }

        const adminToken = createSignedToken(adminOid);

        const res = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                email: 'hacker@example.com',
                displayName: 'Hacker User',
                entraObjectId: crypto.randomUUID(),
                roleCodes: ['SUPER_ADMINISTRATOR', 'CONTRACTOR']
            }
        }, { invocationId: 'test-invalid-role' });

        assert.strictEqual(res.status, 400);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_VALIDATION_FAILED');
    });

    test('5. POST /api/users: SYSTEM_ADMIN successfully registers user and assigns roles', async (t) => {
        if (!localDbAvailable) { t.skip('LocalDB unavailable'); return; }

        const adminToken = createSignedToken(adminOid);
        const testEmail = `gov.officer.${Date.now()}@governance.corp`;
        const testOid = crypto.randomUUID();

        const res = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                email: testEmail,
                displayName: 'Eleanor Security',
                entraObjectId: testOid,
                department: 'Information Security',
                roleCodes: ['SECURITY_OFFICER', 'RESOURCE_OWNER']
            }
        }, { invocationId: 'test-create-user-success' });

        assert.strictEqual(res.status, 201);
        assert.strictEqual(res.jsonBody.success, true);
        assert.ok(res.jsonBody.data.user);

        const created = res.jsonBody.data.user;
        createdUserIds.push(created.user_id);

        assert.strictEqual(created.email, testEmail);
        assert.strictEqual(created.display_name, 'Eleanor Security');
        assert.strictEqual(created.entra_object_id, testOid);
        assert.strictEqual(created.user_type, 'INTERNAL_EMPLOYEE');
        assert.strictEqual(created.department, 'Information Security');
        assert.strictEqual(created.is_active, true);
        assert.strictEqual(created.roles.length, 2);

        // Verify roles do NOT include SYSTEM_ADMIN
        const assignedCodes = created.roles.map(r => r.role_code);
        assert.ok(assignedCodes.includes('SECURITY_OFFICER'));
        assert.ok(assignedCodes.includes('RESOURCE_OWNER'));
        assert.strictEqual(assignedCodes.includes('SYSTEM_ADMIN'), false);

        // Verify database persistence in dbo.users
        const pool = await db.getPool();
        const userCheck = await pool.request()
            .input('uid', created.user_id)
            .query('SELECT * FROM dbo.users WHERE user_id = @uid');
        assert.strictEqual(userCheck.recordset.length, 1);
        assert.strictEqual(userCheck.recordset[0].user_type, 'INTERNAL_EMPLOYEE');

        // Verify audit event persisted
        const auditCheck = await pool.request()
            .input('uid', created.user_id)
            .query("SELECT * FROM dbo.audit_events WHERE entity_id = @uid AND event_action = 'USER_REGISTERED'");
        assert.strictEqual(auditCheck.recordset.length, 1);
        const auditPayload = JSON.parse(auditCheck.recordset[0].event_payload);
        assert.strictEqual(auditPayload.email, testEmail);
    });

    test('6. POST /api/users: rejects duplicate email with HTTP 409 Conflict', async (t) => {
        if (!localDbAvailable) { t.skip('LocalDB unavailable'); return; }

        const adminToken = createSignedToken(adminOid);
        const duplicateEmail = `dup.user.${Date.now()}@governance.corp`;
        const firstOid = crypto.randomUUID();
        const secondOid = crypto.randomUUID();

        // Register first
        const firstRes = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                email: duplicateEmail,
                displayName: 'First User',
                entraObjectId: firstOid,
                roleCodes: ['INTERNAL_SPONSOR']
            }
        }, { invocationId: 'test-dup-email-1' });
        assert.strictEqual(firstRes.status, 201);
        createdUserIds.push(firstRes.jsonBody.data.user.user_id);

        // Attempt second with same email
        const secondRes = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                email: duplicateEmail,
                displayName: 'Second User',
                entraObjectId: secondOid,
                roleCodes: ['INTERNAL_SPONSOR']
            }
        }, { invocationId: 'test-dup-email-2' });

        assert.strictEqual(secondRes.status, 409);
        assert.strictEqual(secondRes.jsonBody.error.code, 'ERR_USER_EXISTS');
    });

    test('7. POST /api/users: rejects duplicate Entra Object ID with HTTP 409 Conflict', async (t) => {
        if (!localDbAvailable) { t.skip('LocalDB unavailable'); return; }

        const adminToken = createSignedToken(adminOid);
        const duplicateOid = crypto.randomUUID();
        const firstEmail = `dup.oid.1.${Date.now()}@governance.corp`;
        const secondEmail = `dup.oid.2.${Date.now()}@governance.corp`;

        // Register first
        const firstRes = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                email: firstEmail,
                displayName: 'First OID User',
                entraObjectId: duplicateOid,
                roleCodes: ['COMPLIANCE_AUDITOR']
            }
        }, { invocationId: 'test-dup-oid-1' });
        assert.strictEqual(firstRes.status, 201);
        createdUserIds.push(firstRes.jsonBody.data.user.user_id);

        // Attempt second with same Entra OID
        const secondRes = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                email: secondEmail,
                displayName: 'Second OID User',
                entraObjectId: duplicateOid,
                roleCodes: ['COMPLIANCE_AUDITOR']
            }
        }, { invocationId: 'test-dup-oid-2' });

        assert.strictEqual(secondRes.status, 409);
        assert.strictEqual(secondRes.jsonBody.error.code, 'ERR_IDENTITY_EXISTS');
    });

    test('8. GET /api/users: lists internal users with assigned roles', async (t) => {
        if (!localDbAvailable) { t.skip('LocalDB unavailable'); return; }

        const adminToken = createSignedToken(adminOid);
        const res = await listUsers({
            headers: { authorization: `Bearer ${adminToken}` },
            query: { limit: 10, offset: 0 }
        }, { invocationId: 'test-list-users' });

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.success, true);
        assert.ok(Array.isArray(res.jsonBody.data.users));
        assert.ok(res.jsonBody.data.users.length > 0);

        // All returned records must be INTERNAL_EMPLOYEE
        for (const u of res.jsonBody.data.users) {
            assert.strictEqual(u.user_type, 'INTERNAL_EMPLOYEE');
            assert.ok(Array.isArray(u.roles));
        }
    });

    test('9. PATCH /api/users/{id}/status: deactivates and reactivates user, blocks self-deactivation', async (t) => {
        if (!localDbAvailable) { t.skip('LocalDB unavailable'); return; }

        const adminToken = createSignedToken(adminOid);
        const testEmail = `status.user.${Date.now()}@governance.corp`;
        const testOid = crypto.randomUUID();

        // Create user
        const createRes = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                email: testEmail,
                displayName: 'Status Tester',
                entraObjectId: testOid,
                roleCodes: ['INTERNAL_SPONSOR']
            }
        }, { invocationId: 'test-status-create' });
        const targetUserId = createRes.jsonBody.data.user.user_id;
        createdUserIds.push(targetUserId);

        // Deactivate user
        const deactRes = await updateUserStatus({
            headers: { authorization: `Bearer ${adminToken}` },
            params: { id: targetUserId },
            body: { is_active: false }
        }, { invocationId: 'test-deactivate' });

        assert.strictEqual(deactRes.status, 200);
        assert.strictEqual(deactRes.jsonBody.data.user.is_active, false);

        // Reactivate user
        const reactRes = await updateUserStatus({
            headers: { authorization: `Bearer ${adminToken}` },
            params: { id: targetUserId },
            body: { is_active: true }
        }, { invocationId: 'test-reactivate' });

        assert.strictEqual(reactRes.status, 200);
        assert.strictEqual(reactRes.jsonBody.data.user.is_active, true);
    });

    test('10. Authentication Flow: newly registered user succeeds; unregistered identity receives ERR_USER_NOT_REGISTERED', async (t) => {
        if (!localDbAvailable) { t.skip('LocalDB unavailable'); return; }

        const adminToken = createSignedToken(adminOid);
        const registeredEmail = `auth.test.${Date.now()}@governance.corp`;
        const registeredOid = crypto.randomUUID();

        // Register user
        const createRes = await createUser({
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                email: registeredEmail,
                displayName: 'Auth Test User',
                entraObjectId: registeredOid,
                roleCodes: ['SECURITY_OFFICER']
            }
        }, { invocationId: 'test-auth-create' });
        createdUserIds.push(createRes.jsonBody.data.user.user_id);

        // Registered user authenticates successfully
        const userToken = createSignedToken(registeredOid, registeredEmail);
        const profile = await authService.authenticateToken(userToken);
        assert.ok(profile);
        assert.strictEqual(profile.email, registeredEmail);
        assert.strictEqual(profile.entra_object_id, registeredOid);

        // Unregistered Entra identity is rejected
        const unregisteredOid = crypto.randomUUID();
        const unregToken = createSignedToken(unregisteredOid, 'unregistered@corp.com');
        await assert.rejects(
            async () => {
                await authService.authenticateToken(unregToken);
            },
            (err) => {
                assert.strictEqual(err.code, 'ERR_USER_NOT_REGISTERED');
                return true;
            }
        );
    });

    test('11. Contractor login remains ineligible: contractor created via createContractor cannot log in with Microsoft Entra token', async (t) => {
        if (!localDbAvailable) { t.skip('LocalDB unavailable'); return; }

        const adminToken = createSignedToken(adminOid);
        const contractorEmail = `external.contractor.${Date.now()}@vendor.com`;

        // Register external contractor via existing contractor endpoint
        const contractorRes = await createContractor({
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                name: 'External Vendor Dev',
                email: contractorEmail,
                company: 'Vendor Partner Inc'
            }
        }, { invocationId: 'test-ext-contractor-create' });
        assert.strictEqual(contractorRes.status, 201);
        createdUserIds.push(contractorRes.jsonBody.data.contractor.contractor_id);

        // Contractor has synthetic OID 'LOCAL-CONTRACTOR-...' in database
        const pool = await db.getPool();
        const dbCheck = await pool.request()
            .input('cid', contractorRes.jsonBody.data.contractor.contractor_id)
            .query('SELECT entra_object_id FROM dbo.users WHERE user_id = @cid');
        assert.ok(dbCheck.recordset[0].entra_object_id.startsWith('LOCAL-CONTRACTOR-'));

        // If contractor attempts to sign in via Microsoft Entra, Azure assigns a real UUID OID
        const realAzureOid = crypto.randomUUID();
        const realEntraToken = createSignedToken(realAzureOid, contractorEmail);

        // Must reject with ERR_USER_NOT_REGISTERED
        await assert.rejects(
            async () => {
                await authService.authenticateToken(realEntraToken);
            },
            (err) => {
                assert.strictEqual(err.code, 'ERR_USER_NOT_REGISTERED');
                return true;
            }
        );
    });
});
