/**
 * AccessLease — Unit Tests: Health Endpoint Handlers
 * Tests:
 * - Application health endpoint response
 * - Database health endpoint behavior when database is unconfigured or unavailable
 * - Secret exposure prevention
 */

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { getApplicationHealth, getDatabaseHealth } = require('../../src/functions/health');

describe('Unit: Health API Handlers', () => {
    let savedEnv;

    beforeEach(() => {
        savedEnv = { ...process.env };
    });

    afterEach(() => {
        process.env = savedEnv;
    });

    test('getApplicationHealth should return 200 OK with safe application status', async () => {
        const mockRequest = {
            headers: new Map([['x-correlation-id', 'test-health-corr-001']])
        };

        const response = await getApplicationHealth(mockRequest, {});

        assert.strictEqual(response.status, 200);
        assert.ok(response.jsonBody.success);
        assert.strictEqual(response.jsonBody.data.application, 'AccessLease');
        assert.strictEqual(response.jsonBody.data.status, 'UP');
        assert.ok(response.jsonBody.data.environment);
        assert.ok(response.jsonBody.data.version);
        assert.strictEqual(response.jsonBody.meta.correlation_id, 'test-health-corr-001');

        // Zero secret verification
        const serialized = JSON.stringify(response.jsonBody).toLowerCase();
        assert.strictEqual(serialized.includes('password'), false);
        assert.strictEqual(serialized.includes('secret'), false);
    });

    test('getDatabaseHealth should return 503 Service Unavailable when configuration is completely missing', async () => {
        // Clear all SQL environment variables
        delete process.env.SQL_SERVER;
        delete process.env.AZURE_SQL_SERVER;
        delete process.env.SQL_DATABASE;
        delete process.env.AZURE_SQL_DATABASE;
        delete process.env.SQL_USER;
        delete process.env.AZURE_SQL_USER;
        delete process.env.SQL_PASSWORD;
        delete process.env.AZURE_SQL_PASSWORD;

        const mockRequest = {
            headers: new Map([['x-correlation-id', 'test-db-unconfigured-001']])
        };

        const response = await getDatabaseHealth(mockRequest, {});

        assert.strictEqual(response.status, 503);
        assert.strictEqual(response.jsonBody.success, false);
        assert.strictEqual(response.jsonBody.error.code, 'ERR_DATABASE_NOT_CONFIGURED');
        assert.strictEqual(response.jsonBody.meta.correlation_id, 'test-db-unconfigured-001');

        // Verify zero secrets leaked in response
        const serialized = JSON.stringify(response.jsonBody).toLowerCase();
        assert.strictEqual(serialized.includes('password'), false);
        assert.strictEqual(serialized.includes('secret'), false);
        assert.strictEqual(serialized.includes('connectionstring'), false);
    });
});
