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
        assert.strictEqual(config.pool.idleTimeoutMillis, 30000, 'Pool must configure 30s idle connection reclamation timeout');
    });

    test('buildSqlConfig should configure Windows LocalDB named-pipe mode', () => {
        const origServer = process.env.SQL_SERVER;
        const origMode = process.env.SQL_AUTH_MODE;
        try {
            process.env.SQL_SERVER = '(localdb)\\MSSQLLocalDB';
            process.env.SQL_AUTH_MODE = 'localdb';

            const config = buildSqlConfig();
            assert.strictEqual(config.options.encrypt, false);
            assert.strictEqual(config.options.trustServerCertificate, true);
            assert.strictEqual(config.user, undefined);
            assert.strictEqual(config.password, undefined);
        } finally {
            if (origServer !== undefined) process.env.SQL_SERVER = origServer; else delete process.env.SQL_SERVER;
            if (origMode !== undefined) process.env.SQL_AUTH_MODE = origMode; else delete process.env.SQL_AUTH_MODE;
        }
    });

    test('buildSqlConfig should configure standard SQL credentials when mode is sql-password', () => {
        const origServer = process.env.SQL_SERVER;
        const origMode = process.env.SQL_AUTH_MODE;
        const origUser = process.env.SQL_USER;
        const origPass = process.env.SQL_PASSWORD;
        try {
            process.env.SQL_SERVER = '127.0.0.1';
            process.env.SQL_AUTH_MODE = 'sql-password';
            process.env.SQL_USER = 'test_sql_user';
            process.env.SQL_PASSWORD = 'test_sql_password_123';

            const config = buildSqlConfig();
            assert.strictEqual(config.server, '127.0.0.1');
            assert.strictEqual(config.user, 'test_sql_user');
            assert.strictEqual(config.password, 'test_sql_password_123');
            assert.strictEqual(config.authentication, undefined);
        } finally {
            if (origServer !== undefined) process.env.SQL_SERVER = origServer; else delete process.env.SQL_SERVER;
            if (origMode !== undefined) process.env.SQL_AUTH_MODE = origMode; else delete process.env.SQL_AUTH_MODE;
            if (origUser !== undefined) process.env.SQL_USER = origUser; else delete process.env.SQL_USER;
            if (origPass !== undefined) process.env.SQL_PASSWORD = origPass; else delete process.env.SQL_PASSWORD;
        }
    });

    test('buildSqlConfig should configure Azure Managed Identity mode with zero credentials and dynamic token acquisition', () => {
        const origServer = process.env.SQL_SERVER;
        const origMode = process.env.SQL_AUTH_MODE;
        const origUser = process.env.SQL_USER;
        const origPass = process.env.SQL_PASSWORD;
        try {
            process.env.SQL_SERVER = 'sql-accesslease-dev-2m8f3u2k.database.windows.net';
            process.env.SQL_AUTH_MODE = 'azure-identity';
            delete process.env.SQL_USER;
            delete process.env.SQL_PASSWORD;

            const config = buildSqlConfig();
            assert.strictEqual(config.server, 'sql-accesslease-dev-2m8f3u2k.database.windows.net');
            assert.strictEqual(config.user, undefined, 'Must NOT contain user');
            assert.strictEqual(config.password, undefined, 'Must NOT contain password');
            assert.strictEqual(config.options.encrypt, true, 'Azure SQL requires encrypted connection');
            assert.ok(config.authentication, 'Tedious authentication block must be present');
            assert.strictEqual(config.authentication.type, 'azure-active-directory-default');
            assert.deepStrictEqual(config.authentication.options, {}, 'System-Assigned identity uses empty options');
        } finally {
            if (origServer !== undefined) process.env.SQL_SERVER = origServer; else delete process.env.SQL_SERVER;
            if (origMode !== undefined) process.env.SQL_AUTH_MODE = origMode; else delete process.env.SQL_AUTH_MODE;
            if (origUser !== undefined) process.env.SQL_USER = origUser; else delete process.env.SQL_USER;
            if (origPass !== undefined) process.env.SQL_PASSWORD = origPass; else delete process.env.SQL_PASSWORD;
        }
    });

    test('buildSqlConfig should strictly omit SQL credentials in azure-identity mode even if SQL_USER and SQL_PASSWORD exist', () => {
        const origServer = process.env.SQL_SERVER;
        const origMode = process.env.SQL_AUTH_MODE;
        const origUser = process.env.SQL_USER;
        const origPass = process.env.SQL_PASSWORD;
        try {
            process.env.SQL_SERVER = 'sql-accesslease-dev.database.windows.net';
            process.env.SQL_AUTH_MODE = 'azure-identity';
            process.env.SQL_USER = 'sqladmin_should_be_ignored';
            process.env.SQL_PASSWORD = 'admin_password_should_be_ignored';

            const config = buildSqlConfig();
            assert.strictEqual(config.user, undefined, 'Must strictly delete user in azure-identity mode');
            assert.strictEqual(config.password, undefined, 'Must strictly delete password in azure-identity mode');
            assert.strictEqual(config.authentication.type, 'azure-active-directory-default');
        } finally {
            if (origServer !== undefined) process.env.SQL_SERVER = origServer; else delete process.env.SQL_SERVER;
            if (origMode !== undefined) process.env.SQL_AUTH_MODE = origMode; else delete process.env.SQL_AUTH_MODE;
            if (origUser !== undefined) process.env.SQL_USER = origUser; else delete process.env.SQL_USER;
            if (origPass !== undefined) process.env.SQL_PASSWORD = origPass; else delete process.env.SQL_PASSWORD;
        }
    });

    test('buildSqlConfig should throw DatabaseError when unsupported SQL_AUTH_MODE is configured', () => {
        const origMode = process.env.SQL_AUTH_MODE;
        try {
            process.env.SQL_AUTH_MODE = 'kerberos-invalid-mode';
            assert.throws(() => {
                buildSqlConfig();
            }, /Unsupported SQL authentication mode/);
        } finally {
            if (origMode !== undefined) process.env.SQL_AUTH_MODE = origMode; else delete process.env.SQL_AUTH_MODE;
        }
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

