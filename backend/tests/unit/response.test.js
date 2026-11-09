/**
 * AccessLease — Unit Tests: Response Formatting & Error Consistency
 * Tests:
 * - Success envelope structure
 * - Error envelope structure and consistency
 * - HTTP response generation with mandatory security headers
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { createSuccessBody, createErrorBody, toHttpResponse } = require('../../src/utils/response');

describe('Unit: Response Formatting', () => {
    test('createSuccessBody should format standard canonical success envelope', () => {
        const payload = { test_key: 'value_123' };
        const response = createSuccessBody(payload, { correlation_id: 'test-corr-id-001' });

        assert.strictEqual(response.success, true);
        assert.deepStrictEqual(response.data, payload);
        assert.strictEqual(response.meta.correlation_id, 'test-corr-id-001');
        assert.ok(response.meta.timestamp);
    });

    test('createErrorBody should format standard canonical error envelope', () => {
        const errorResponse = createErrorBody(
            'ERR_SAMPLE_CODE',
            'Sample error message',
            [{ field: 'user_id', issue: 'Invalid UUID' }],
            { correlation_id: 'test-corr-id-002' }
        );

        assert.strictEqual(errorResponse.success, false);
        assert.strictEqual(errorResponse.error.code, 'ERR_SAMPLE_CODE');
        assert.strictEqual(errorResponse.error.message, 'Sample error message');
        assert.strictEqual(errorResponse.error.details.length, 1);
        assert.strictEqual(errorResponse.meta.correlation_id, 'test-corr-id-002');
        assert.ok(errorResponse.meta.timestamp);
    });

    test('toHttpResponse should include mandatory HTTP security headers', () => {
        const body = createSuccessBody({ ok: true });
        const httpResponse = toHttpResponse(200, body);

        assert.strictEqual(httpResponse.status, 200);
        assert.strictEqual(httpResponse.headers['Content-Type'], 'application/json; charset=utf-8');
        assert.strictEqual(httpResponse.headers['X-Content-Type-Options'], 'nosniff');
        assert.strictEqual(httpResponse.headers['X-Frame-Options'], 'DENY');
        assert.deepStrictEqual(httpResponse.jsonBody, body);
    });
});
