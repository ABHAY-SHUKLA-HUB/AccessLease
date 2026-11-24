/**
 * AccessLease — Integration Tests: Authentication API & End-to-End Identity Mapping
 * 
 * Verifies live HTTP trigger behavior against Microsoft SQL Server LocalDB:
 * 1. GET /api/auth/config returns safe public bootstrap config without leaking secrets.
 * 2. GET /api/auth/me returns 401 when Authorization header is omitted.
 * 3. GET /api/auth/me returns 401 when token has expired.
 * 4. GET /api/auth/me returns 401 when Entra OID is not registered in dbo.users.
 * 5. GET /api/auth/me returns 200 OK and live database user record for registered Entra OID.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const { getAuthMe, getAuthConfigHandler } = require('../../src/functions/auth');
const tokenUtils = require('../../src/utils/tokenUtils');
const { getPool, closePool } = require('../../src/config/database');

describe('Integration: Authentication Endpoints & Real Database Identity Mapping', () => {
    let rsaKeyPair;
    let originalTenantId;
    let originalClientId;
    let originalSpaClientId;
    let originalApiClientId;
    let originalApiAudience;
    let originalApiScope;
    let originalIssuer;

    const TEST_TENANT_ID = 'test-integration-tenant';
    const TEST_SPA_CLIENT_ID = 'test-spa-client-integration-1111';
    const TEST_API_CLIENT_ID = 'test-api-client-integration-2222';
    const TEST_AUDIENCE = `api://${TEST_API_CLIENT_ID}`;
    const TEST_ISSUER = `https://login.microsoftonline.com/${TEST_TENANT_ID}/v2.0`;

    before(async () => {
        // Set environment variables for tenant matching
        originalTenantId = process.env.ENTRA_TENANT_ID;
        originalClientId = process.env.ENTRA_CLIENT_ID;
        originalSpaClientId = process.env.ENTRA_SPA_CLIENT_ID;
        originalApiClientId = process.env.ENTRA_API_CLIENT_ID;
        originalApiAudience = process.env.ENTRA_API_AUDIENCE;
        originalApiScope = process.env.ENTRA_API_SCOPE;
        originalIssuer = process.env.ENTRA_ISSUER;

        process.env.ENTRA_TENANT_ID = TEST_TENANT_ID;
        process.env.ENTRA_SPA_CLIENT_ID = TEST_SPA_CLIENT_ID;
        process.env.ENTRA_API_CLIENT_ID = TEST_API_CLIENT_ID;
        process.env.ENTRA_API_AUDIENCE = TEST_AUDIENCE;
        process.env.ENTRA_API_SCOPE = `${TEST_AUDIENCE}/access_as_user`;
        process.env.ENTRA_ISSUER = TEST_ISSUER;

        // Verify database connectivity
        const pool = await getPool();
        assert.ok(pool.connected, 'Database pool must be connected for integration test');

        // Generate in-memory RSA keypair for integration test tokens
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
        process.env.ENTRA_CLIENT_ID = originalClientId;
        process.env.ENTRA_SPA_CLIENT_ID = originalSpaClientId;
        process.env.ENTRA_API_CLIENT_ID = originalApiClientId;
        process.env.ENTRA_API_AUDIENCE = originalApiAudience;
        process.env.ENTRA_API_SCOPE = originalApiScope;
        process.env.ENTRA_ISSUER = originalIssuer;
        await closePool();
    });

    function createSignedToken(oid, overrides = {}, signOverrides = {}) {
        const payload = {
            oid,
            sub: `sub-${oid}`,
            email: `${oid.toLowerCase()}@accesslease.corp`,
            name: `Test User ${oid}`,
            tid: TEST_TENANT_ID,
            ...overrides
        };

        return jwt.sign(payload, rsaKeyPair.privateKey, {
            algorithm: 'RS256',
            audience: TEST_AUDIENCE,
            issuer: TEST_ISSUER,
            expiresIn: '30m',
            ...signOverrides
        });
    }

    test('1. GET /api/auth/config: should return 200 OK with safe public parameters and zero secrets', async () => {
        const mockReq = { headers: {} };
        const mockContext = { invocationId: 'int-cfg-1' };

        const res = await getAuthConfigHandler(mockReq, mockContext);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.success, true);
        assert.ok('configured' in res.jsonBody.data);
        assert.strictEqual(res.headers['X-Content-Type-Options'], 'nosniff');
        assert.strictEqual(res.jsonBody.data.clientId, TEST_SPA_CLIENT_ID);
        assert.strictEqual(res.jsonBody.data.apiScope, `${TEST_AUDIENCE}/access_as_user`);

        // Verify zero secret leakage
        const serialized = JSON.stringify(res.jsonBody).toLowerCase();
        assert.strictEqual(serialized.includes('secret'), false);
        assert.strictEqual(serialized.includes('password'), false);
    });

    test('2. GET /api/auth/me: should return HTTP 401 when Authorization header is missing', async () => {
        const mockReq = { headers: {}, url: 'http://localhost:7071/api/auth/me' };
        const mockContext = { invocationId: 'int-me-noauth' };

        const res = await getAuthMe(mockReq, mockContext);

        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.success, false);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_MISSING_AUTH_HEADER');
    });

    test('3. GET /api/auth/me: should return HTTP 401 when token has expired', async () => {
        const expiredToken = createSignedToken('TEST-OID-SPONSOR', {}, { expiresIn: '-5m' });
        const mockReq = {
            headers: {
                authorization: `Bearer ${expiredToken}`
            },
            url: 'http://localhost:7071/api/auth/me'
        };
        const mockContext = { invocationId: 'int-me-expired' };

        const res = await getAuthMe(mockReq, mockContext);

        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.success, false);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_TOKEN_EXPIRED');
    });

    test('4. GET /api/auth/me: should return HTTP 401 when token is valid but OID is unmapped in dbo.users', async () => {
        const unmappedOid = 'UNMAPPED-OID-99999999-AAAA-BBBB';
        const validToken = createSignedToken(unmappedOid);
        const mockReq = {
            headers: {
                authorization: `Bearer ${validToken}`
            },
            url: 'http://localhost:7071/api/auth/me'
        };
        const mockContext = { invocationId: 'int-me-unmapped' };

        const res = await getAuthMe(mockReq, mockContext);

        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.success, false);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_USER_NOT_REGISTERED');
    });

    test('5. GET /api/auth/me: should return HTTP 200 OK and live database record for seeded user (TEST-OID-SPONSOR)', async () => {
        // 'TEST-OID-SPONSOR' was seeded into dbo.users during Step 01
        const liveOid = 'TEST-OID-SPONSOR';
        const validToken = createSignedToken(liveOid);
        const mockReq = {
            headers: {
                authorization: `Bearer ${validToken}`
            },
            url: 'http://localhost:7071/api/auth/me'
        };
        const mockContext = { invocationId: 'int-me-live' };

        const res = await getAuthMe(mockReq, mockContext);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.success, true);
        assert.strictEqual(res.jsonBody.data.user.entra_object_id, 'TEST-OID-SPONSOR');
        assert.strictEqual(res.jsonBody.data.user.email, 'sponsor@example.com');
        assert.strictEqual(res.jsonBody.data.user.display_name, 'Sarah Sponsor');
        assert.strictEqual(res.jsonBody.data.user.user_type, 'INTERNAL_EMPLOYEE');
        assert.strictEqual(res.jsonBody.data.user.is_active, true);
        assert.strictEqual(res.jsonBody.data.session.authenticated, true);
        assert.strictEqual(res.jsonBody.data.session.auth_provider, 'Microsoft Entra ID');
    });

    test('6. GET /api/auth/me: should return HTTP 200 OK and live contractor record for seeded contractor (TEST-OID-CONTRACTOR)', async () => {
        // 'TEST-OID-CONTRACTOR' was seeded into dbo.users during Step 01
        const liveContractorOid = 'TEST-OID-CONTRACTOR';
        const validToken = createSignedToken(liveContractorOid);
        const mockReq = {
            headers: {
                authorization: `Bearer ${validToken}`
            },
            url: 'http://localhost:7071/api/auth/me'
        };
        const mockContext = { invocationId: 'int-me-contractor' };

        const res = await getAuthMe(mockReq, mockContext);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.success, true);
        assert.strictEqual(res.jsonBody.data.user.entra_object_id, 'TEST-OID-CONTRACTOR');
        assert.strictEqual(res.jsonBody.data.user.email, 'contractor@example.com');
        assert.strictEqual(res.jsonBody.data.user.display_name, 'Carlos Contractor');
        assert.strictEqual(res.jsonBody.data.user.user_type, 'CONTRACTOR');
        assert.strictEqual(res.jsonBody.data.user.is_active, true);
    });

    test('7. GET /api/auth/me: should return HTTP 401 ERR_INVALID_TENANT_ID when token tid does not match configured tenant', async () => {
        const wrongTenantToken = createSignedToken('TEST-OID-SPONSOR', { tid: 'completely-different-foreign-tenant' });
        const mockReq = {
            headers: { authorization: `Bearer ${wrongTenantToken}` },
            url: 'http://localhost:7071/api/auth/me'
        };
        const mockContext = { invocationId: 'int-me-wrong-tenant' };

        const res = await getAuthMe(mockReq, mockContext);

        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.success, false);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_INVALID_TENANT_ID');
    });

    test('8. GET /api/auth/me: should return HTTP 401 ERR_MISSING_TENANT_ID when token lacks tid claim', async () => {
        const noTenantToken = createSignedToken('TEST-OID-SPONSOR', { tid: undefined });
        const mockReq = {
            headers: { authorization: `Bearer ${noTenantToken}` },
            url: 'http://localhost:7071/api/auth/me'
        };
        const mockContext = { invocationId: 'int-me-no-tenant' };

        const res = await getAuthMe(mockReq, mockContext);

        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.success, false);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_MISSING_TENANT_ID');
    });

    test('9. GET /api/auth/me: should return HTTP 401 ERR_INVALID_ISSUER when token issuer does not match tenant STS', async () => {
        const wrongIssuerToken = createSignedToken('TEST-OID-SPONSOR', {}, { issuer: 'https://sts.windows.net/wrong-tenant-id/' });
        const mockReq = {
            headers: { authorization: `Bearer ${wrongIssuerToken}` },
            url: 'http://localhost:7071/api/auth/me'
        };
        const mockContext = { invocationId: 'int-me-wrong-issuer' };

        const res = await getAuthMe(mockReq, mockContext);

        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.success, false);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_INVALID_ISSUER');
    });

    test('10. GET /api/auth/me: should return HTTP 401 ERR_INVALID_SIGNATURE when token signed by untrusted key', async () => {
        const foreignKeyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const untrustedToken = jwt.sign(
            {
                oid: 'TEST-OID-SPONSOR',
                sub: 'TEST-OID-SPONSOR',
                tid: TEST_TENANT_ID
            },
            foreignKeyPair.privateKey,
            {
                algorithm: 'RS256',
                audience: TEST_AUDIENCE,
                issuer: TEST_ISSUER,
                expiresIn: '30m'
            }
        );

        const mockReq = {
            headers: { authorization: `Bearer ${untrustedToken}` },
            url: 'http://localhost:7071/api/auth/me'
        };
        const mockContext = { invocationId: 'int-me-untrusted-key' };

        const res = await getAuthMe(mockReq, mockContext);

        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.success, false);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_INVALID_SIGNATURE');
    });

    test('11. GET /api/auth/me: should return HTTP 401 ERR_INVALID_AUDIENCE when token is issued for SPA Client ID', async () => {
        // SPA token or ID token has audience of ENTRA_SPA_CLIENT_ID, not the Web API
        const spaToken = createSignedToken('TEST-OID-SPONSOR', {}, { audience: TEST_SPA_CLIENT_ID });

        const mockReq = {
            headers: { authorization: `Bearer ${spaToken}` },
            url: 'http://localhost:7071/api/auth/me'
        };
        const mockContext = { invocationId: 'int-me-spa-token' };

        const res = await getAuthMe(mockReq, mockContext);

        assert.strictEqual(res.status, 401);
        assert.strictEqual(res.jsonBody.success, false);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_INVALID_AUDIENCE');
    });
});

