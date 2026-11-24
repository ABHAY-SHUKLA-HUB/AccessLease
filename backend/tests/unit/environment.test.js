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

    test('validateDatabaseConfig should succeed for localdb without SQL credentials', () => {
        const origServer = process.env.SQL_SERVER;
        const origDb = process.env.SQL_DATABASE;
        const origMode = process.env.SQL_AUTH_MODE;
        const origUser = process.env.SQL_USER;
        const origPass = process.env.SQL_PASSWORD;
        try {
            process.env.SQL_SERVER = '(localdb)\\MSSQLLocalDB';
            process.env.SQL_DATABASE = 'AccessLease_TestDB';
            process.env.SQL_AUTH_MODE = 'localdb';
            delete process.env.SQL_USER;
            delete process.env.SQL_PASSWORD;

            const validation = env.validateDatabaseConfig();
            assert.strictEqual(validation.isValid, true);
            assert.deepStrictEqual(validation.missingFields, []);
        } finally {
            if (origServer !== undefined) process.env.SQL_SERVER = origServer; else delete process.env.SQL_SERVER;
            if (origDb !== undefined) process.env.SQL_DATABASE = origDb; else delete process.env.SQL_DATABASE;
            if (origMode !== undefined) process.env.SQL_AUTH_MODE = origMode; else delete process.env.SQL_AUTH_MODE;
            if (origUser !== undefined) process.env.SQL_USER = origUser; else delete process.env.SQL_USER;
            if (origPass !== undefined) process.env.SQL_PASSWORD = origPass; else delete process.env.SQL_PASSWORD;
        }
    });

    test('validateDatabaseConfig should require SQL credentials when mode is sql-password', () => {
        const origServer = process.env.SQL_SERVER;
        const origDb = process.env.SQL_DATABASE;
        const origMode = process.env.SQL_AUTH_MODE;
        const origUser = process.env.SQL_USER;
        const origPass = process.env.SQL_PASSWORD;
        try {
            process.env.SQL_SERVER = '127.0.0.1';
            process.env.SQL_DATABASE = 'accesslease-db';
            process.env.SQL_AUTH_MODE = 'sql-password';
            delete process.env.SQL_USER;
            delete process.env.SQL_PASSWORD;

            const validation = env.validateDatabaseConfig();
            assert.strictEqual(validation.isValid, false);
            assert.ok(validation.missingFields.some(f => f.includes('Database Credentials')));
        } finally {
            if (origServer !== undefined) process.env.SQL_SERVER = origServer; else delete process.env.SQL_SERVER;
            if (origDb !== undefined) process.env.SQL_DATABASE = origDb; else delete process.env.SQL_DATABASE;
            if (origMode !== undefined) process.env.SQL_AUTH_MODE = origMode; else delete process.env.SQL_AUTH_MODE;
            if (origUser !== undefined) process.env.SQL_USER = origUser; else delete process.env.SQL_USER;
            if (origPass !== undefined) process.env.SQL_PASSWORD = origPass; else delete process.env.SQL_PASSWORD;
        }
    });

    test('validateDatabaseConfig should succeed for azure-identity without SQL credentials', () => {
        const origServer = process.env.SQL_SERVER;
        const origDb = process.env.SQL_DATABASE;
        const origMode = process.env.SQL_AUTH_MODE;
        const origUser = process.env.SQL_USER;
        const origPass = process.env.SQL_PASSWORD;
        try {
            process.env.SQL_SERVER = 'sql-accesslease-dev-2m8f3u2k.database.windows.net';
            process.env.SQL_DATABASE = 'accesslease-db';
            process.env.SQL_AUTH_MODE = 'azure-identity';
            delete process.env.SQL_USER;
            delete process.env.SQL_PASSWORD;

            const validation = env.validateDatabaseConfig();
            assert.strictEqual(validation.isValid, true);
            assert.deepStrictEqual(validation.missingFields, []);
        } finally {
            if (origServer !== undefined) process.env.SQL_SERVER = origServer; else delete process.env.SQL_SERVER;
            if (origDb !== undefined) process.env.SQL_DATABASE = origDb; else delete process.env.SQL_DATABASE;
            if (origMode !== undefined) process.env.SQL_AUTH_MODE = origMode; else delete process.env.SQL_AUTH_MODE;
            if (origUser !== undefined) process.env.SQL_USER = origUser; else delete process.env.SQL_USER;
            if (origPass !== undefined) process.env.SQL_PASSWORD = origPass; else delete process.env.SQL_PASSWORD;
        }
    });

    test('validateDatabaseConfig should reject unsupported SQL_AUTH_MODE', () => {
        const origServer = process.env.SQL_SERVER;
        const origDb = process.env.SQL_DATABASE;
        const origMode = process.env.SQL_AUTH_MODE;
        try {
            process.env.SQL_SERVER = '127.0.0.1';
            process.env.SQL_DATABASE = 'testdb';
            process.env.SQL_AUTH_MODE = 'kerberos';

            const validation = env.validateDatabaseConfig();
            assert.strictEqual(validation.isValid, false);
            assert.ok(validation.missingFields.some(f => f.includes('Unsupported SQL authentication mode')));
        } finally {
            if (origServer !== undefined) process.env.SQL_SERVER = origServer; else delete process.env.SQL_SERVER;
            if (origDb !== undefined) process.env.SQL_DATABASE = origDb; else delete process.env.SQL_DATABASE;
            if (origMode !== undefined) process.env.SQL_AUTH_MODE = origMode; else delete process.env.SQL_AUTH_MODE;
        }
    });

    test('should prevent secret exposure in getPublicEnvironmentSummary()', () => {
        const summary = env.getPublicEnvironmentSummary();

        // Must include safe keys
        assert.strictEqual(summary.status, 'online');
        assert.ok(summary.version);
        assert.ok(summary.environment);
        assert.ok(summary.timestamp);
        assert.strictEqual(typeof summary.database_configured, 'boolean');
        assert.ok(summary.sql_auth_mode, 'Must expose safe auth mode indicator');

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

    test('should return ENTRA_SPA_CLIENT_ID as clientId in getPublicAuthConfig()', () => {
        const originalSpa = process.env.ENTRA_SPA_CLIENT_ID;
        const originalApi = process.env.ENTRA_API_CLIENT_ID;
        const originalTenant = process.env.ENTRA_TENANT_ID;
        const originalAudience = process.env.ENTRA_API_AUDIENCE;
        const originalScope = process.env.ENTRA_API_SCOPE;

        try {
            delete process.env.ENTRA_API_AUDIENCE;
            delete process.env.ENTRA_API_SCOPE;
            process.env.ENTRA_TENANT_ID = 'test-tenant-uuid';
            process.env.ENTRA_SPA_CLIENT_ID = 'spa-client-uuid-1111';
            process.env.ENTRA_API_CLIENT_ID = 'api-client-uuid-2222';

            const config = env.getPublicAuthConfig();
            assert.strictEqual(config.configured, true);
            assert.strictEqual(config.clientId, 'spa-client-uuid-1111', 'MSAL clientId must receive the SPA client ID');
            assert.strictEqual(config.tenantId, 'test-tenant-uuid');
            assert.strictEqual(config.apiAudience, 'api://api-client-uuid-2222');
            assert.strictEqual(config.apiScope, 'api://api-client-uuid-2222/access_as_user');
        } finally {
            if (originalSpa !== undefined) process.env.ENTRA_SPA_CLIENT_ID = originalSpa; else delete process.env.ENTRA_SPA_CLIENT_ID;
            if (originalApi !== undefined) process.env.ENTRA_API_CLIENT_ID = originalApi; else delete process.env.ENTRA_API_CLIENT_ID;
            if (originalTenant !== undefined) process.env.ENTRA_TENANT_ID = originalTenant; else delete process.env.ENTRA_TENANT_ID;
            if (originalAudience !== undefined) process.env.ENTRA_API_AUDIENCE = originalAudience; else delete process.env.ENTRA_API_AUDIENCE;
            if (originalScope !== undefined) process.env.ENTRA_API_SCOPE = originalScope; else delete process.env.ENTRA_API_SCOPE;
        }
    });

    test('should correctly compute default ENTRA_API_AUDIENCE and ENTRA_API_SCOPE from API registration', () => {
        const originalApi = process.env.ENTRA_API_CLIENT_ID;
        const originalAudience = process.env.ENTRA_API_AUDIENCE;
        const originalScope = process.env.ENTRA_API_SCOPE;

        try {
            delete process.env.ENTRA_API_AUDIENCE;
            delete process.env.ENTRA_API_SCOPE;
            process.env.ENTRA_API_CLIENT_ID = 'custom-api-client-id';

            assert.strictEqual(env.ENTRA_API_AUDIENCE, 'api://custom-api-client-id');
            assert.strictEqual(env.ENTRA_API_SCOPE, 'api://custom-api-client-id/access_as_user');
        } finally {
            if (originalApi) process.env.ENTRA_API_CLIENT_ID = originalApi; else delete process.env.ENTRA_API_CLIENT_ID;
            if (originalAudience) process.env.ENTRA_API_AUDIENCE = originalAudience; else delete process.env.ENTRA_API_AUDIENCE;
            if (originalScope) process.env.ENTRA_API_SCOPE = originalScope; else delete process.env.ENTRA_API_SCOPE;
        }
    });

    test('should report missing fields in validateEntraConfig() when SPA or API client IDs are omitted', () => {
        const originalSpa = process.env.ENTRA_SPA_CLIENT_ID;
        const originalApi = process.env.ENTRA_API_CLIENT_ID;
        const originalLegacy = process.env.ENTRA_CLIENT_ID;
        const originalAudience = process.env.ENTRA_API_AUDIENCE;
        const originalTenant = process.env.ENTRA_TENANT_ID;

        try {
            process.env.ENTRA_TENANT_ID = 'valid-tenant-id';
            delete process.env.ENTRA_SPA_CLIENT_ID;
            delete process.env.ENTRA_API_CLIENT_ID;
            delete process.env.ENTRA_CLIENT_ID;
            delete process.env.ENTRA_API_AUDIENCE;

            const validation = env.validateEntraConfig();
            assert.strictEqual(validation.isValid, false);
            assert.ok(validation.missingFields.some(f => f.includes('ENTRA_SPA_CLIENT_ID')));
            assert.ok(validation.missingFields.some(f => f.includes('ENTRA_API_CLIENT_ID')));
        } finally {
            if (originalSpa) process.env.ENTRA_SPA_CLIENT_ID = originalSpa;
            if (originalApi) process.env.ENTRA_API_CLIENT_ID = originalApi;
            if (originalLegacy) process.env.ENTRA_CLIENT_ID = originalLegacy;
            if (originalAudience) process.env.ENTRA_API_AUDIENCE = originalAudience;
            if (originalTenant) process.env.ENTRA_TENANT_ID = originalTenant;
        }
    });

    test('should reject identical SPA and API client IDs when NODE_ENV is production', () => {
        const originalEnv = process.env.NODE_ENV;
        const originalSpa = process.env.ENTRA_SPA_CLIENT_ID;
        const originalApi = process.env.ENTRA_API_CLIENT_ID;
        const originalTenant = process.env.ENTRA_TENANT_ID;

        try {
            process.env.NODE_ENV = 'production';
            process.env.ENTRA_TENANT_ID = 'valid-tenant-id';
            process.env.ENTRA_SPA_CLIENT_ID = 'same-client-guid-0001';
            process.env.ENTRA_API_CLIENT_ID = 'same-client-guid-0001';

            const validation = env.validateEntraConfig();
            assert.strictEqual(validation.isValid, false);
            assert.ok(validation.missingFields.some(f => f.includes('Separate SPA and Backend API App Registrations required')));
        } finally {
            process.env.NODE_ENV = originalEnv;
            if (originalSpa) process.env.ENTRA_SPA_CLIENT_ID = originalSpa; else delete process.env.ENTRA_SPA_CLIENT_ID;
            if (originalApi) process.env.ENTRA_API_CLIENT_ID = originalApi; else delete process.env.ENTRA_API_CLIENT_ID;
            if (originalTenant) process.env.ENTRA_TENANT_ID = originalTenant; else delete process.env.ENTRA_TENANT_ID;
        }
    });
});

