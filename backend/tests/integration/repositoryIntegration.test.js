/**
 * AccessLease — Integration Tests: Real Database Repository Operations
 * Target: Microsoft SQL Server LocalDB (AccessLease_TestDB)
 * 
 * Verifies live repository operations against actual database:
 * 1. userRepository: retrieves seeded users and handles non-existent IDs.
 * 2. roleRepository: retrieves the 6 seeded enterprise roles and finds role by code.
 * 3. resourceRepository: retrieves resources, entitlements, and resource owners.
 * 4. engagementRepository: lists active contractor engagements.
 * 5. grantRepository: retrieves seeded grant and queries v_AccessExposureQueue.
 * 6. auditRepository: writes and reads real audit trail records.
 * 7. Transaction atomicity: verifies rollback prevents dirty writes.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const cp = require('child_process');
const db = require('../../src/config/database');
const repositories = require('../../src/repositories');

describe('Integration: Real Database Repository Operations (AccessLease_TestDB)', () => {
    let localDbAvailable = false;

    before(async () => {
        process.env.SQL_SERVER = '(localdb)\\MSSQLLocalDB';
        process.env.SQL_DATABASE = 'AccessLease_TestDB';

        try {
            cp.execSync('sqllocaldb start MSSQLLocalDB', { stdio: 'pipe' });
            const pool = await db.getPool();
            localDbAvailable = pool && pool.connected;
        } catch {
            localDbAvailable = false;
        }
    });

    after(async () => {
        await db.closePool();
    });

    test('1. userRepository: finds seeded sponsor user by Entra Object ID', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server / LocalDB is not available.');
            return;
        }

        const user = await repositories.userRepository.findUserByEntraObjectId('TEST-OID-SPONSOR');

        assert.ok(user, 'Seeded sponsor user must exist in dbo.users');
        assert.strictEqual(user.entra_object_id, 'TEST-OID-SPONSOR');
        assert.strictEqual(user.email, 'sponsor@example.com');
        assert.strictEqual(user.user_type, 'INTERNAL_EMPLOYEE');
        assert.strictEqual(user.is_active, true);
    });

    test('2. userRepository: returns null when user does not exist', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server / LocalDB is not available.');
            return;
        }

        const nonExistent = await repositories.userRepository.findUserByEntraObjectId('NON-EXISTENT-OID-0000');
        assert.strictEqual(nonExistent, null);
    });

    test('3. roleRepository: retrieves all 6 seeded roles from dbo.roles', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server / LocalDB is not available.');
            return;
        }

        const roles = await repositories.roleRepository.listRoles();

        assert.ok(Array.isArray(roles));
        assert.strictEqual(roles.length, 6, `Expected exactly 6 seeded roles, found ${roles.length}`);

        const roleCodes = roles.map(r => r.role_code);
        assert.ok(roleCodes.includes('RESOURCE_OWNER'));
        assert.ok(roleCodes.includes('SECURITY_OFFICER'));
        assert.ok(roleCodes.includes('COMPLIANCE_AUDITOR'));
    });

    test('4. roleRepository: finds role by role_code', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server / LocalDB is not available.');
            return;
        }

        const role = await repositories.roleRepository.findRoleByCode('RESOURCE_OWNER');

        assert.ok(role);
        assert.strictEqual(role.role_code, 'RESOURCE_OWNER');
        assert.strictEqual(role.role_name, 'Resource Owner');
    });

    test('5. resourceRepository: lists resources and retrieves entitlements', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server / LocalDB is not available.');
            return;
        }

        const resources = await repositories.resourceRepository.listResources();
        assert.ok(resources.length >= 1, 'At least 1 resource should exist');

        const firstResource = resources[0];
        assert.ok(firstResource.resource_id);
        assert.ok(firstResource.resource_code);

        const entitlements = await repositories.resourceRepository.listEntitlementsByResourceId(firstResource.resource_id);
        assert.ok(Array.isArray(entitlements));
        assert.ok(entitlements.length >= 1, 'Resource should have associated entitlements');
    });

    test('6. engagementRepository: lists engagements and joins contractor/sponsor names', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server / LocalDB is not available.');
            return;
        }

        const engagements = await repositories.engagementRepository.listEngagements();
        assert.ok(Array.isArray(engagements));
        assert.ok(engagements.length >= 1, 'At least 1 contractor engagement should exist');

        const eng = engagements[0];
        assert.ok(eng.engagement_id);
        assert.ok(eng.contractor_name);
        assert.ok(eng.sponsor_name);
        assert.ok(eng.vendor_name);
    });

    test('7. grantRepository: queries active exposure queue from v_AccessExposureQueue', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server / LocalDB is not available.');
            return;
        }

        const queue = await repositories.grantRepository.getAccessExposureQueue();
        assert.ok(Array.isArray(queue));
        assert.ok(queue.length >= 1, 'v_AccessExposureQueue should return at least 1 record');

        const item = queue[0];
        assert.ok(item.grant_id);
        assert.ok(item.grant_number);
        assert.ok(item.exposure_category);
        assert.ok(item.exposure_severity);
    });

    test('8. auditRepository: records and retrieves audit event', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server / LocalDB is not available.');
            return;
        }

        const auditEvent = await repositories.auditRepository.createAuditEvent({
            eventCategory: 'SECURITY_POLICY',
            eventAction: 'INTEGRATION_TEST_EVENT',
            entityType: 'TEST_SUITE',
            entityId: 'REPO-INT-TEST-001',
            actorType: 'SYSTEM_TIMER',
            eventPayload: { testRun: true, timestamp: new Date().toISOString() },
            ipAddress: '127.0.0.1'
        });

        assert.ok(auditEvent.event_id);
        assert.strictEqual(auditEvent.event_category, 'SECURITY_POLICY');
        assert.strictEqual(auditEvent.event_action, 'INTEGRATION_TEST_EVENT');

        const retrieved = await repositories.auditRepository.getAuditEventById(auditEvent.event_id);
        assert.ok(retrieved);
        assert.strictEqual(retrieved.entity_id, 'REPO-INT-TEST-001');
    });

    test('9. Transaction Atomicity: withTransaction() rollback prevents dirty writes on error', async (t) => {
        if (!localDbAvailable) {
            t.skip('Skipped: Real SQL Server / LocalDB is not available.');
            return;
        }

        const testRoleCode = `TMP_ROLE_${Date.now()}`;

        // Attempt transaction that inserts and then throws
        await assert.rejects(
            async () => {
                await db.withTransaction(async (tx) => {
                    await tx.request()
                        .input('roleCode', testRoleCode)
                        .input('roleName', 'Temporary Rollback Role')
                        .query(`
                            INSERT INTO dbo.roles (role_code, role_name, description)
                            VALUES (@roleCode, @roleName, 'Should be rolled back');
                        `);

                    // Force an error to trigger rollback
                    throw new Error('Simulated failure triggering rollback');
                });
            },
            (err) => {
                assert.strictEqual(err.message, 'Simulated failure triggering rollback');
                return true;
            }
        );

        // Verify the temporary role was NOT persisted in dbo.roles
        const checkRole = await repositories.roleRepository.findRoleByCode(testRoleCode);
        assert.strictEqual(checkRole, null, 'Rolled-back record must NOT exist in database');
    });
});
