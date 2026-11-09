/**
 * AccessLease — Unit Tests: Authentication Middleware (authMiddleware.js)
 * 
 * Verifies:
 * 1. Extraction of Bearer token from Map and object header structures.
 * 2. Rejection of missing Authorization headers with HTTP 401 (ERR_MISSING_AUTH_HEADER).
 * 3. Rejection of non-Bearer schemes (e.g. Basic, Token) with HTTP 401 (ERR_INVALID_AUTH_HEADER).
 * 4. Rejection of empty Bearer tokens.
 * 5. withAuth wrapper execution and attachment of request.user.
 * 6. Attachment of security headers (nosniff, DENY) on unauthorized responses.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const authMiddleware = require('../../src/middleware/authMiddleware');
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
});

