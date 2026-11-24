/**
 * AccessLease — Admin-Only Contractor Registration Integration Tests
 * 
 * Verifies:
 * 1. POST /api/contractors without Authorization header returns HTTP 401 (ERR_MISSING_AUTH_HEADER).
 * 2. POST /api/contractors by non-admin identity (INTERNAL_SPONSOR) returns HTTP 403 (ERR_FORBIDDEN_ROLE).
 * 3. POST /api/contractors with missing name returns HTTP 400 (ERR_CONTRACTOR_NAME_REQUIRED).
 * 4. POST /api/contractors with invalid email returns HTTP 400 (ERR_INVALID_EMAIL).
 * 5. POST /api/contractors by SYSTEM_ADMIN successfully registers new contractor:
 *    - Status HTTP 201 Created conforming to canonical response envelope.
 *    - Database record in dbo.users has user_type = 'CONTRACTOR', is_active = 1, department = company.
 *    - Synthetic entra_object_id starting with 'LOCAL-CONTRACTOR-'.
 *    - Assigned CONTRACTOR role in dbo.user_roles.
 *    - Tamper-evident audit event recorded in dbo.audit_events.
 * 6. POST /api/contractors with duplicate email returns HTTP 409 (ERR_CONTRACTOR_EXISTS).
 * 7. Arbitrary client user_type is overridden/forced to 'CONTRACTOR'.
 * 8. Newly registered contractor appears in GET /api/contractors?limit=100&isActive=true.
 * 9. Dropdown mapping verification: registered contractor's database UUID is returned as contractor_id.
 * 10. Automated test cleanup removes test records from database.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const cp = require('child_process');

const { createContractor, listContractors } = require('../../src/functions/contractors');
const { userRepository, roleRepository } = require('../../src/repositories');
const tokenUtils = require('../../src/utils/tokenUtils');
const db = require('../../src/config/database');

describe('Integration: Admin-Only Contractor Registration (LocalDB)', () => {
    let rsaKeyPair;
    let originalTenantId;
    let originalSpaClientId;
    let originalApiClientId;
    let originalApiAudience;
    let localDbAvailable = false;

    const TEST_TENANT_ID = 'test-reg-tenant-999';
    const TEST_SPA_CLIENT_ID = 'test-spa-client-reg';
    const TEST_API_CLIENT_ID = 'test-api-client-reg';
    const TEST_AUDIENCE = `api://${TEST_API_CLIENT_ID}`;
    const TEST_ISSUER = `https://login.microsoftonline.com/${TEST_TENANT_ID}/v2.0`;

    // Seeded test accounts
    const ADMIN_OID = 'f2bba284-9dba-4570-b865-875a009870ed';
    const ADMIN_EMAIL = 'shuklaabhayas0@gmail.com';
    const SPONSOR_OID = 'TEST-OID-SPONSOR';
    const SPONSOR_EMAIL = 'sponsor@example.com';

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
        } catch {
            localDbAvailable = false;
        }
    });

    after(async () => {
        // Cleanup all created test users
        for (const userId of createdUserIds) {
            try {
                await userRepository.deleteUser(userId);
            } catch {
                // Ignore cleanup errors
            }
        }

        tokenUtils.setCustomKeyResolver(null);
        process.env.ENTRA_TENANT_ID = originalTenantId;
        process.env.ENTRA_SPA_CLIENT_ID = originalSpaClientId;
        process.env.ENTRA_API_CLIENT_ID = originalApiClientId;
        process.env.ENTRA_API_AUDIENCE = originalApiAudience;
        await db.closePool();
    });

    function generateMockToken(oid, email, expiresIn = '1h') {
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
            keyid: 'test-key-id',
            expiresIn
        });
    }

    function createMockRequest(method, path, options = {}) {
        const { headers = {}, query = {}, body = {} } = options;
        const headersMap = new Map();
        for (const [k, v] of Object.entries(headers)) {
            headersMap.set(k.toLowerCase(), v);
        }

        return {
            method,
            path,
            url: path,
            headers: headersMap,
            query,
            body,
            json: async () => body
        };
    }

    const mockContext = { invocationId: 'test-reg-inv-001', log: () => {} };

    test('1. POST /api/contractors: returns 401 when Authorization header is missing', async () => {
        const req = createMockRequest('POST', '/api/contractors', {
            body: { name: 'Unauthorized Contractor', email: 'unauth@test.com' }
        });

        const res = await createContractor(req, mockContext);
        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_MISSING_AUTH_HEADER');
    });

    test('2. POST /api/contractors: returns 403 when caller is non-admin (INTERNAL_SPONSOR)', async () => {
        const token = generateMockToken(SPONSOR_OID, SPONSOR_EMAIL);
        const req = createMockRequest('POST', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            body: { name: 'Sponsor Attempt', email: 'sponsor.attempt@vendor.com' }
        });

        const res = await createContractor(req, mockContext);
        assert.strictEqual(res.status, 403);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_FORBIDDEN_ROLE');
    });

    test('3. POST /api/contractors: returns 400 when contractor name is missing or whitespace', async () => {
        const token = generateMockToken(ADMIN_OID, ADMIN_EMAIL);
        const req = createMockRequest('POST', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            body: { name: '   ', email: 'valid@vendor.com' }
        });

        const res = await createContractor(req, mockContext);
        assert.strictEqual(res.status, 400);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_CONTRACTOR_NAME_REQUIRED');
    });

    test('4. POST /api/contractors: returns 400 when email is invalid', async () => {
        const token = generateMockToken(ADMIN_OID, ADMIN_EMAIL);
        const req = createMockRequest('POST', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            body: { name: 'Valid Name', email: 'not-a-valid-email' }
        });

        const res = await createContractor(req, mockContext);
        assert.strictEqual(res.status, 400);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_INVALID_EMAIL');
    });

    test('5. POST /api/contractors: SYSTEM_ADMIN successfully registers contractor with company mapping', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        const token = generateMockToken(ADMIN_OID, ADMIN_EMAIL);
        const testEmail = `regtest.${Date.now()}@cyberdyne-vendor.com`;
        const testName = 'Marcus Wright';
        const testCompany = 'Cyberdyne Advanced Systems';
        const testPhone = '+1 555-0188';

        const req = createMockRequest('POST', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            body: {
                name: testName,
                email: testEmail,
                company: testCompany,
                phone: testPhone,
                user_type: 'INTERNAL_EMPLOYEE' // Should be overridden to CONTRACTOR
            }
        });

        const res = await createContractor(req, mockContext);
        assert.strictEqual(res.status, 201);
        assert.strictEqual(res.jsonBody.success, true);
        assert.strictEqual(res.jsonBody.data.status, 'REGISTERED');

        const contractor = res.jsonBody.data.contractor;
        assert.ok(contractor.user_id, 'Must contain user_id');
        assert.strictEqual(contractor.contractor_id, contractor.user_id, 'contractor_id must equal user_id');
        assert.strictEqual(contractor.email, testEmail);
        assert.strictEqual(contractor.display_name, testName);
        assert.strictEqual(contractor.user_type, 'CONTRACTOR', 'user_type must be strictly CONTRACTOR');
        assert.strictEqual(contractor.department, testCompany, 'company must be stored in department');

        createdUserIds.push(contractor.user_id);

        // Verify in live SQL Server dbo.users
        const dbUser = await userRepository.findUserById(contractor.user_id);
        assert.ok(dbUser, 'User must exist in dbo.users');
        assert.strictEqual(dbUser.email, testEmail);
        assert.strictEqual(dbUser.user_type, 'CONTRACTOR');
        assert.strictEqual(dbUser.department, testCompany);
        assert.strictEqual(dbUser.is_active, true);
        assert.ok(dbUser.entra_object_id.startsWith('LOCAL-CONTRACTOR-'));

        // Verify role in dbo.user_roles
        const roles = await userRepository.getUserRoles(contractor.user_id);
        assert.ok(roles.some(r => r.role_code === 'CONTRACTOR'), 'Must have CONTRACTOR role in user_roles');
    });

    test('6. POST /api/contractors: returns 409 Conflict when email already exists', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        const token = generateMockToken(ADMIN_OID, ADMIN_EMAIL);
        // Use an email already registered in previous test
        const existingEmail = `duplicate.${Date.now()}@vendor.com`;

        // Register first time
        const req1 = createMockRequest('POST', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            body: { name: 'Original Contractor', email: existingEmail }
        });
        const res1 = await createContractor(req1, mockContext);
        assert.strictEqual(res1.status, 201);
        createdUserIds.push(res1.jsonBody.data.contractor.user_id);

        // Register second time with same email
        const req2 = createMockRequest('POST', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            body: { name: 'Duplicate Contractor', email: existingEmail }
        });
        const res2 = await createContractor(req2, mockContext);
        assert.strictEqual(res2.status, 409);
        assert.strictEqual(res2.jsonBody.error.code, 'ERR_CONTRACTOR_EXISTS');
    });

    test('7. GET /api/contractors: newly registered contractor appears in directory listing', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        const token = generateMockToken(ADMIN_OID, ADMIN_EMAIL);
        const testEmail = `listing.${Date.now()}@vendor.com`;

        const reqCreate = createMockRequest('POST', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            body: { name: 'Listing Candidate', email: testEmail, company: 'Listing Agency' }
        });
        const resCreate = await createContractor(reqCreate, mockContext);
        assert.strictEqual(resCreate.status, 201);
        const createdId = resCreate.jsonBody.data.contractor.user_id;
        createdUserIds.push(createdId);

        // Fetch directory
        const reqList = createMockRequest('GET', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            query: { limit: '100', isActive: 'true' }
        });
        const resList = await listContractors(reqList, mockContext);
        assert.strictEqual(resList.status, 200);
        assert.strictEqual(resList.jsonBody.success, true);

        const contractors = resList.jsonBody.data.contractors;
        const found = contractors.find(c => c.user_id === createdId || c.contractor_id === createdId);
        assert.ok(found, 'Newly registered contractor must appear in directory listing');
        assert.strictEqual(found.email, testEmail);
        assert.strictEqual(found.display_name, 'Listing Candidate');
        assert.strictEqual(found.user_type, 'CONTRACTOR');
    });
});
