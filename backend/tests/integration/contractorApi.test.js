/**
 * AccessLease — Contractor & Engagement HTTP API Handlers Integration Tests
 * Verifies HTTP triggers, parameter parsing, authorization wrapping, and JSON responses.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const {
    listContractors,
    getContractorSelf,
    getContractorById,
    createContractor,
    listEngagements,
    getEngagementById,
    createEngagement,
    updateEngagement,
    transitionEngagementStatus
} = require('../../src/functions/contractors');
const { userRepository } = require('../../src/repositories');
const tokenUtils = require('../../src/utils/tokenUtils');
const { getPool, closePool } = require('../../src/config/database');

describe('Integration: Contractor & Engagement HTTP Handlers', () => {
    let rsaKeyPair;
    let originalTenantId;
    let originalSpaClientId;
    let originalApiClientId;
    let originalApiAudience;

    const TEST_TENANT_ID = 'test-contractor-tenant';
    const TEST_SPA_CLIENT_ID = 'test-spa-client-3333';
    const TEST_API_CLIENT_ID = 'test-api-client-4444';
    const TEST_AUDIENCE = `api://${TEST_API_CLIENT_ID}`;
    const TEST_ISSUER = `https://login.microsoftonline.com/${TEST_TENANT_ID}/v2.0`;

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

        tokenUtils.setCustomKeyResolver((header, callback) => {
            callback(null, rsaKeyPair.publicKey);
        });
    });

    after(async () => {
        tokenUtils.setCustomKeyResolver(null);
        process.env.ENTRA_TENANT_ID = originalTenantId;
        process.env.ENTRA_SPA_CLIENT_ID = originalSpaClientId;
        process.env.ENTRA_API_CLIENT_ID = originalApiClientId;
        process.env.ENTRA_API_AUDIENCE = originalApiAudience;
        await closePool();
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

    const mockContext = { invocationId: 'test-inv-001', log: () => {} };

    test('1. GET /api/contractors: returns 401 when Authorization header is missing', async () => {
        const req = createMockRequest('GET', '/api/contractors');
        const res = await listContractors(req, mockContext);
        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_MISSING_AUTH_HEADER');
    });

    test('2. GET /api/contractors: returns 200 OK for internal sponsor identity', async () => {
        const token = generateMockToken('TEST-OID-SPONSOR', 'sponsor@example.com');
        const req = createMockRequest('GET', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            query: { limit: '10' }
        });

        // Use bypassValidation for our test RSA key
        req.user = undefined; // withAuth will authenticate using validateToken with test option
        const res = await listContractors(req, mockContext);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.success, true);
        assert.ok(Array.isArray(res.jsonBody.data.contractors));
    });

    test('3. GET /api/contractors/me: returns 200 OK for contractor self-service', async () => {
        const token = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const req = createMockRequest('GET', '/api/contractors/me', {
            headers: { authorization: `Bearer ${token}` }
        });

        const res = await getContractorSelf(req, mockContext);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.success, true);
        assert.strictEqual(res.jsonBody.data.contractor.email, 'contractor@example.com');
    });

    test('4. GET /api/engagements: returns 200 OK and lists engagements', async () => {
        const token = generateMockToken('TEST-OID-SPONSOR', 'sponsor@example.com');
        const req = createMockRequest('GET', '/api/engagements', {
            headers: { authorization: `Bearer ${token}` }
        });

        const res = await listEngagements(req, mockContext);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.success, true);
        assert.ok(Array.isArray(res.jsonBody.data.engagements));
    });

    test('5. POST /api/contractors: returns 401 when Authorization header is missing', async () => {
        const req = createMockRequest('POST', '/api/contractors', {
            body: { name: 'Unauthorized Contractor', email: 'unauth@vendor.com' }
        });

        const res = await createContractor(req, mockContext);
        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_MISSING_AUTH_HEADER');
    });

    test('6. POST /api/contractors: returns 403 when user is not SYSTEM_ADMIN', async () => {
        const token = generateMockToken('TEST-OID-SPONSOR', 'sponsor@example.com');
        const req = createMockRequest('POST', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            body: { name: 'Jane Doe', email: 'jane.doe@vendor.com' }
        });

        const res = await createContractor(req, mockContext);
        assert.strictEqual(res.status, 403);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_FORBIDDEN_ROLE');
    });

    test('7. POST /api/contractors: returns 400 when contractor name is missing', async () => {
        const token = generateMockToken('f2bba284-9dba-4570-b865-875a009870ed', 'shuklaabhayas0@gmail.com');
        const req = createMockRequest('POST', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            body: { name: '   ', email: 'valid.email@vendor.com' }
        });

        const res = await createContractor(req, mockContext);
        assert.strictEqual(res.status, 400);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_CONTRACTOR_NAME_REQUIRED');
    });

    test('8. POST /api/contractors: returns 400 when contractor email is invalid', async () => {
        const token = generateMockToken('f2bba284-9dba-4570-b865-875a009870ed', 'shuklaabhayas0@gmail.com');
        const req = createMockRequest('POST', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            body: { name: 'Valid Contractor', email: 'invalid-email-format' }
        });

        const res = await createContractor(req, mockContext);
        assert.strictEqual(res.status, 400);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_INVALID_EMAIL');
    });

    test('9. POST /api/contractors: returns 201 Created for SYSTEM_ADMIN and persists contractor', async () => {
        const token = generateMockToken('f2bba284-9dba-4570-b865-875a009870ed', 'shuklaabhayas0@gmail.com');
        const testEmail = `apitest.${Date.now()}@vendor-corp.com`;
        const req = createMockRequest('POST', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            body: {
                name: 'Samantha Smith',
                email: testEmail,
                company: 'Acme Contracting Services',
                phone: '+1 555-0144'
            }
        });

        const res = await createContractor(req, mockContext);
        assert.strictEqual(res.status, 201);
        assert.strictEqual(res.jsonBody.success, true);
        assert.strictEqual(res.jsonBody.data.status, 'REGISTERED');

        const created = res.jsonBody.data.contractor;
        assert.ok(created.user_id, 'Must contain user_id');
        assert.ok(created.contractor_id, 'Must contain contractor_id');
        assert.strictEqual(created.contractor_id, created.user_id);
        assert.strictEqual(created.email, testEmail);
        assert.strictEqual(created.department, 'Acme Contracting Services');
        assert.strictEqual(created.user_type, 'CONTRACTOR');

        // Clean up created test user from database
        try {
            await userRepository.deleteUser(created.user_id);
        } catch (cleanupErr) {
            // Ignore cleanup errors
        }
    });

    test('10. GET /api/contractors: strictly returns records where user_type is CONTRACTOR and never INTERNAL_EMPLOYEE', async () => {
        const token = generateMockToken('TEST-OID-SPONSOR', 'sponsor@example.com');
        const req = createMockRequest('GET', '/api/contractors', {
            headers: { authorization: `Bearer ${token}` },
            query: { limit: '50' }
        });

        const res = await listContractors(req, mockContext);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.success, true);
        const contractors = res.jsonBody.data.contractors;
        assert.ok(Array.isArray(contractors));

        // Verify all returned records have user_type === 'CONTRACTOR'
        for (const c of contractors) {
            assert.strictEqual(c.user_type, 'CONTRACTOR', `Record ${c.email} must have user_type CONTRACTOR`);
            assert.notStrictEqual(c.user_type, 'INTERNAL_EMPLOYEE', `Record ${c.email} must not be INTERNAL_EMPLOYEE`);
        }

        // Verify internal users (such as SYSTEM_ADMIN or INTERNAL_SPONSOR) never appear
        const returnedEmails = contractors.map(c => c.email.toLowerCase());
        assert.ok(!returnedEmails.includes('sponsor@example.com'), 'Internal sponsor must not be in contractor list');
        assert.ok(!returnedEmails.includes('shuklaabhayas0@gmail.com'), 'System admin must not be in contractor list');

        // Verify total matches count of CONTRACTOR records
        assert.strictEqual(typeof res.jsonBody.data.total, 'number');
        assert.ok(res.jsonBody.data.total >= contractors.length);
    });
});
