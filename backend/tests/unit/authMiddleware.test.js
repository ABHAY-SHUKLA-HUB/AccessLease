/**
 * AccessLease — Unit Tests: Authentication Middleware (authMiddleware.js)
 * 
 * Verifies:
 * 1. Extraction of Bearer token from Map and object header structures.
 * 2. Rejection of missing Authorization headers with HTTP 401 (ERR_MISSING_AUTH_HEADER).
 * 3. Rejection of non-Bearer schemes (e.g. Basic, Token) with HTTP 401 (ERR_INVALID_AUTH_HEADER).
 * 4. Rejection of empty Bearer tokens.
 * 5. withAuth wrapper execution and attachment of request.authenticatedUser.
 * 6. Attachment of security headers (nosniff, DENY) on unauthorized responses.
 * 7. Regression: Real @azure/functions v4 HttpRequest instance compatibility and dedicated authenticatedUser attachment.
 * 8. Regression: GET /api/auth/me execution with real HttpRequest instance without null user crashes.
 * 9. Regression: GET /api/contractors execution with real HttpRequest reaching RBAC authorization.
 * 10. Regression: Backward compatibility for plain mock objects using request.user.
 */

const { test, describe, afterEach } = require('node:test');
const assert = require('node:assert');
const { HttpRequest } = require('@azure/functions');
const authMiddleware = require('../../src/middleware/authMiddleware');
const authService = require('../../src/services/authService');
const { getAuthMe } = require('../../src/functions/auth');
const { listContractors } = require('../../src/functions/contractors');
const contractorService = require('../../src/services/contractorService');
const { UnauthorizedError } = require('../../src/utils/errors');

describe('Unit: Authentication Middleware (authMiddleware)', () => {
    test('1. extractBearerToken: should extract raw token from standard Bearer header', () => {
        const mockReq = {
            headers: {
                authorization: 'Bearer valid.jwt.payload'
            }
        };
        const token = authMiddleware.extractBearerToken(mockReq);
        assert.strictEqual(token, 'valid.jwt.payload');
    });

    test('2. extractBearerToken: should extract from Azure Functions v4 Map headers', () => {
        const headersMap = new Map();
        headersMap.set('authorization', 'Bearer map.header.token');

        const mockReq = {
            headers: headersMap
        };
        const token = authMiddleware.extractBearerToken(mockReq);
        assert.strictEqual(token, 'map.header.token');
    });

    test('3. Missing Authorization header: should throw UnauthorizedError with ERR_MISSING_AUTH_HEADER', () => {
        const mockReq = {
            headers: {}
        };

        assert.throws(
            () => authMiddleware.extractBearerToken(mockReq),
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_MISSING_AUTH_HEADER');
                return true;
            }
        );
    });

    test('4. Non-Bearer scheme rejection: should throw ERR_INVALID_AUTH_HEADER for Basic scheme', () => {
        const mockReq = {
            headers: {
                authorization: 'Basic dXNlcjpwYXNzd29yZA=='
            }
        };

        assert.throws(
            () => authMiddleware.extractBearerToken(mockReq),
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_INVALID_AUTH_HEADER');
                return true;
            }
        );
    });

    test('5. Empty Bearer token rejection: should throw ERR_INVALID_AUTH_HEADER for standalone "Bearer"', () => {
        const mockReq = {
            headers: {
                authorization: 'Bearer   '
            }
        };

        assert.throws(
            () => authMiddleware.extractBearerToken(mockReq),
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_INVALID_AUTH_HEADER');
                return true;
            }
        );
    });

    test('6. withAuth wrapper: should intercept unauthenticated request and return HTTP 401 with standard envelope', async () => {
        const mockHandler = async () => ({ status: 200, jsonBody: { success: true } });
        const wrapped = authMiddleware.withAuth(mockHandler);

        const mockReq = {
            headers: {},
            url: 'http://localhost:7071/api/auth/me'
        };
        const mockContext = { invocationId: 'test-inv-123' };

        const response = await wrapped(mockReq, mockContext);

        assert.strictEqual(response.status, 401);
        assert.strictEqual(response.headers['Content-Type'], 'application/json; charset=utf-8');
        assert.strictEqual(response.headers['X-Content-Type-Options'], 'nosniff');
        assert.strictEqual(response.headers['X-Frame-Options'], 'DENY');
        assert.strictEqual(response.jsonBody.success, false);
        assert.strictEqual(response.jsonBody.error.code, 'ERR_MISSING_AUTH_HEADER');
        assert.strictEqual(response.jsonBody.meta.correlation_id, 'test-inv-123');
    });

    test('7. Real @azure/functions HttpRequest: authenticateRequest assigns request.authenticatedUser and leaves native read-only request.user intact', async () => {
        const mockUser = {
            user_id: 'USER-REAL-001',
            email: 'realuser@accesslease.corp',
            first_name: 'Real',
            last_name: 'Tester',
            display_name: 'Real Tester',
            user_type: 'INTERNAL_EMPLOYEE',
            department: 'Engineering',
            is_active: true,
            roles: [{ role_code: 'INTERNAL_SPONSOR', role_name: 'Internal Sponsor' }],
            permissions: ['READ_CONTRACTORS', 'MANAGE_ENGAGEMENTS']
        };

        const originalAuthenticateToken = authService.authenticateToken;
        authService.authenticateToken = async () => mockUser;

        try {
            const realReq = new HttpRequest({
                method: 'GET',
                url: 'http://localhost:7071/api/test',
                headers: { authorization: 'Bearer mock.jwt.token' }
            });
            const context = { invocationId: 'test-real-001' };

            const resolvedUser = await authMiddleware.authenticateRequest(realReq, context);

            // Verifies profile assignment to dedicated non-reserved property
            assert.strictEqual(resolvedUser.user_id, 'USER-REAL-001');
            assert.strictEqual(realReq.authenticatedUser.user_id, 'USER-REAL-001');
            assert.strictEqual(context.authenticatedUser.user_id, 'USER-REAL-001');

            // Verifies Azure Functions native read-only request.user property was not shadowed/mutated
            assert.strictEqual(realReq.user, null);
        } finally {
            authService.authenticateToken = originalAuthenticateToken;
        }
    });

    test('8. Real @azure/functions HttpRequest: /api/auth/me returns HTTP 200 and resolved profile via request.authenticatedUser', async () => {
        const mockUser = {
            user_id: 'USER-REAL-002',
            entra_object_id: 'ENTRA-OID-REAL-002',
            email: 'sponsor@accesslease.corp',
            first_name: 'Sponsor',
            last_name: 'User',
            display_name: 'Sponsor User',
            user_type: 'INTERNAL_EMPLOYEE',
            department: 'Security',
            is_active: true,
            roles: [{ role_code: 'INTERNAL_SPONSOR', role_name: 'Internal Sponsor' }],
            permissions: ['READ_CONTRACTORS']
        };

        const originalAuthenticateToken = authService.authenticateToken;
        authService.authenticateToken = async () => mockUser;

        try {
            const realReq = new HttpRequest({
                method: 'GET',
                url: 'http://localhost:7071/api/auth/me',
                headers: { authorization: 'Bearer mock.jwt.token' }
            });
            const context = { invocationId: 'test-auth-me-002' };

            const response = await getAuthMe(realReq, context);

            assert.strictEqual(response.status, 200);
            assert.strictEqual(response.jsonBody.success, true);
            assert.strictEqual(response.jsonBody.data.user.user_id, 'USER-REAL-002');
            assert.strictEqual(response.jsonBody.data.user.email, 'sponsor@accesslease.corp');
            assert.strictEqual(response.jsonBody.data.session.authenticated, true);
            assert.strictEqual(realReq.authenticatedUser.user_id, 'USER-REAL-002');
            assert.strictEqual(realReq.user, null);
        } finally {
            authService.authenticateToken = originalAuthenticateToken;
        }
    });

    test('9. Real @azure/functions HttpRequest: /api/contractors passes authenticatedUser to authorization checks without failing with null user', async () => {
        const originalAuthenticateToken = authService.authenticateToken;
        const originalListContractors = contractorService.listContractors;

        try {
            // Case 9A: Contractor identity receives RBAC forbidden check (ERR_FORBIDDEN_CONTRACTOR_DIRECTORY), proving user reached logic
            authService.authenticateToken = async () => ({
                user_id: 'CONTRACTOR-USER-001',
                email: 'contractor@external.com',
                user_type: 'CONTRACTOR',
                roles: [{ role_code: 'CONTRACTOR', role_name: 'External Contractor' }]
            });

            const realReqA = new HttpRequest({
                method: 'GET',
                url: 'http://localhost:7071/api/contractors',
                headers: { authorization: 'Bearer mock.jwt.token' }
            });
            const contextA = { invocationId: 'test-contractor-rbac-001' };

            const responseA = await listContractors(realReqA, contextA);

            // Must NOT fail with ERR_UNAUTHORIZED (403 when user is null), but with ERR_FORBIDDEN_CONTRACTOR_DIRECTORY
            assert.strictEqual(responseA.status, 403);
            assert.strictEqual(responseA.jsonBody.error.code, 'ERR_FORBIDDEN_CONTRACTOR_DIRECTORY');

            // Case 9B: Authorized Internal Sponsor receives HTTP 200 with list data
            authService.authenticateToken = async () => ({
                user_id: 'SPONSOR-USER-001',
                email: 'sponsor@accesslease.corp',
                user_type: 'INTERNAL_EMPLOYEE',
                roles: [{ role_code: 'INTERNAL_SPONSOR', role_name: 'Internal Sponsor' }]
            });

            contractorService.listContractors = async (user) => ({
                actingUserId: user.user_id,
                contractors: [],
                total: 0
            });

            const realReqB = new HttpRequest({
                method: 'GET',
                url: 'http://localhost:7071/api/contractors',
                headers: { authorization: 'Bearer mock.jwt.token' }
            });
            const contextB = { invocationId: 'test-contractor-sponsor-002' };

            const responseB = await listContractors(realReqB, contextB);

            assert.strictEqual(responseB.status, 200);
            assert.strictEqual(responseB.jsonBody.success, true);
            assert.strictEqual(responseB.jsonBody.data.actingUserId, 'SPONSOR-USER-001');
        } finally {
            authService.authenticateToken = originalAuthenticateToken;
            contractorService.listContractors = originalListContractors;
        }
    });

    test('10. Backward compatibility: supports legacy plain mock objects with pre-attached request.user', async () => {
        const legacyMockReq = {
            user: {
                user_id: 'USER-LEGACY-999',
                email: 'legacy@accesslease.corp',
                roles: [{ role_code: 'SYSTEM_ADMIN' }]
            },
            headers: {}
        };
        const context = {};

        const resolvedUser = await authMiddleware.authenticateRequest(legacyMockReq, context);

        assert.strictEqual(resolvedUser.user_id, 'USER-LEGACY-999');
        assert.strictEqual(legacyMockReq.authenticatedUser.user_id, 'USER-LEGACY-999');
        assert.strictEqual(context.authenticatedUser.user_id, 'USER-LEGACY-999');
    });

    test('11. Chained middleware reuse: reuses existing request.authenticatedUser without re-authenticating', async () => {
        let authServiceCalled = false;
        const originalAuthenticateToken = authService.authenticateToken;
        authService.authenticateToken = async () => {
            authServiceCalled = true;
            return { user_id: 'SHOULD-NOT-BE-CALLED' };
        };

        try {
            const req = {
                authenticatedUser: {
                    user_id: 'USER-CACHED-001',
                    email: 'cached@accesslease.corp',
                    roles: []
                },
                headers: { authorization: 'Bearer ignored.token' }
            };
            const context = {};

            const resolvedUser = await authMiddleware.authenticateRequest(req, context);

            assert.strictEqual(authServiceCalled, false);
            assert.strictEqual(resolvedUser.user_id, 'USER-CACHED-001');
            assert.strictEqual(context.authenticatedUser.user_id, 'USER-CACHED-001');
        } finally {
            authService.authenticateToken = originalAuthenticateToken;
        }
    });
});

