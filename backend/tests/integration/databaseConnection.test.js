/**
 * AccessLease — Integration Tests: Real Microsoft SQL Server Connectivity
 * Target: (localdb)\MSSQLLocalDB / Azure SQL Database
 * 
 * Rules:
 * - Real live database connection check (NOT mocked).
 * - Queries sys.tables and SELECT 1.
 * - Confirms clean pool shutdown.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const cp = require('child_process');
const db = require('../../src/config/database');
const env = require('../../src/config/environment');

describe('Integration: Real Microsoft SQL Server Connectivity', () => {
    let localDbAvailable = false;

    before(() => {
        // Configure test database target
        process.env.SQL_SERVER = '(localdb)\\MSSQLLocalDB';
        process.env.SQL_DATABASE = 'AccessLease_TestDB';

        // Check if LocalDB or SQL Server is reachable in this environment
        try {
            cp.execSync('sqllocaldb start MSSQLLocalDB', { stdio: 'pipe' });
            localDbAvailable = true;
        } catch {
            localDbAvailable = false;
        }
    });

    after(async () => {
        await db.closePool();
    });

    test('should connect to real Microsoft SQL Server and execute lightweight health query', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server / LocalDB instance is not detected in current execution environment.');
            return;
        }

        const result = await db.checkConnection();

        assert.strictEqual(result.is_healthy, true, 'Live database must return is_healthy === true');
        assert.ok(result.server_time, 'Live database must return real server timestamp');
        console.log(`[Integration Test] Real SQL Server Connection Verified. Server Time: ${result.server_time}`);
    });

    test('should query the 15 core governance tables from live sys.tables', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server instance not available.');
            return;
        }

        const result = await db.query(`
            SELECT name 
            FROM sys.tables 
            WHERE name IN (
                'users', 'contractor_engagements', 'roles', 'user_roles',
                'resources', 'entitlements', 'resource_owners', 'access_requests',
                'approval_steps', 'access_grants', 'provisioning_events',
                'revocation_jobs', 'access_reviews', 'review_items', 'audit_events'
            )
        `);

        assert.ok(result.recordset);
        assert.strictEqual(
            result.recordset.length,
            15,
            `Expected exactly 15 core governance tables in database, found ${result.recordset.length}`
        );
        console.log(`[Integration Test] Verified all 15 core tables exist on live database.`);
    });
});
