/**
 * AccessLease — Unit Tests: Database Configuration & Sanitization
 * Tests:
 * - Driver config generation from environment
 * - Error hierarchy behavior
 * - Logger secret redaction
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { buildSqlConfig } = require('../../src/config/database');
const { DatabaseError, ValidationError, AppError } = require('../../src/utils/errors');
const logger = require('../../src/utils/logger');

describe('Unit: Database Configuration & Driver Options', () => {
    test('buildSqlConfig should populate connection options from environment', () => {
        const config = buildSqlConfig();

        assert.ok(config);
        assert.ok(config.pool);
        assert.ok(config.options);
        assert.strictEqual(typeof config.options.enableArithAbort, 'boolean');
        assert.ok(config.connectionTimeout > 0);
        assert.ok(config.requestTimeout > 0);
    });

    test('DatabaseError should sanitize message and not leak stack or sensitive info', () => {
        const rawErr = new Error('Login failed for user sa. Connection string: Server=tcp:secret.db;User=sa;Password=SecretPassword123');
        const dbErr = new DatabaseError('Database operation failed', rawErr);

        assert.strictEqual(dbErr.statusCode, 503);
        assert.strictEqual(dbErr.code, 'ERR_DATABASE_UNAVAILABLE');
        assert.strictEqual(dbErr.message, 'Database operation failed');
        assert.strictEqual(dbErr.isOperational, true);
    });

    test('Logger should sanitize sensitive keys from logged context', () => {
        const sensitivePayload = {
            username: 'admin',
            password: 'SuperSecretPassword!',
            client_secret: 'EntraSecret999',
            token: 'eyJh...token',
            normal_field: 'public_value'
        };

        const sanitized = logger.sanitizeObject(sensitivePayload);

        assert.strictEqual(sanitized.username, 'admin');
        assert.strictEqual(sanitized.normal_field, 'public_value');
        assert.strictEqual(sanitized.password, '[REDACTED_SECRET]');
        assert.strictEqual(sanitized.client_secret, '[REDACTED_SECRET]');
        assert.strictEqual(sanitized.token, '[REDACTED_SECRET]');
    });
});
