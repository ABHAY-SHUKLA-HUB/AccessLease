/**
 * AccessLease — Unit Tests: Environment Configuration & Secret Sanitization
 * Tests:
 * - Environment loading and defaults
 * - Missing environment variables validation
 * - Secret exposure prevention in public summaries
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const env = require('../../src/config/environment');

describe('Unit: Environment Configuration', () => {
    test('should have default NODE_ENV set to development or test', () => {
        assert.ok(['development', 'test', 'production'].includes(env.NODE_ENV));
    });

    test('should correctly validate database configuration presence', () => {
        const validation = env.validateDatabaseConfig();
        assert.strictEqual(typeof validation.isValid, 'boolean');
        assert.ok(Array.isArray(validation.missingFields));
    });

    test('should prevent secret exposure in getPublicEnvironmentSummary()', () => {
        const summary = env.getPublicEnvironmentSummary();

        // Must include safe keys
        assert.strictEqual(summary.status, 'online');
        assert.ok(summary.version);
        assert.ok(summary.environment);
        assert.ok(summary.timestamp);
        assert.strictEqual(typeof summary.database_configured, 'boolean');

        // MUST NOT contain sensitive keywords or raw credential properties
        const serialized = JSON.stringify(summary).toLowerCase();
        assert.strictEqual(serialized.includes('password'), false, 'Public summary must not leak password');
        assert.strictEqual(serialized.includes('secret'), false, 'Public summary must not leak secret');
        assert.strictEqual(serialized.includes('token'), false, 'Public summary must not leak token');
        assert.strictEqual(serialized.includes('connectionstring'), false, 'Public summary must not leak connection string');
        assert.strictEqual(serialized.includes('.database.windows.net'), false, 'Public summary must not leak raw hostname');
    });

    test('should provide valid integer defaults for timeouts and pool limits', () => {
        assert.ok(env.SQL_PORT > 0);
        assert.ok(env.SQL_CONNECTION_TIMEOUT >= 1000);
        assert.ok(env.SQL_REQUEST_TIMEOUT >= 1000);
        assert.ok(env.SQL_POOL_MAX >= 1);
        assert.ok(env.SQL_POOL_MIN >= 0);
    });
});
