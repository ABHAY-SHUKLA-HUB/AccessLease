const { describe, test, before, after } = require('node:test');
const assert = require('node:assert');

const { getPool, closePool } = require('../../src/config/database');
const catalogService = require('../../src/services/catalogService');
const { ConflictError, ValidationError, ForbiddenError } = require('../../src/utils/errors');

describe('Integration: Real Database Resource Catalogue Lifecycle (AccessLease_TestDB)', () => {
    let pool;
    let seededAdminUser;
    let seededSponsorUser;
    let createdResourceId;
    let createdEntitlementId;
    const testResCode = `RES-TEST-${Date.now().toString().slice(-6)}`;

    before(async () => {
        pool = await getPool();

        // Retrieve seeded users
        const adminRes = await pool.request().query(`
            SELECT TOP 1 u.user_id, u.display_name, u.email
            FROM dbo.users u
            INNER JOIN dbo.user_roles ur ON u.user_id = ur.user_id
            INNER JOIN dbo.roles r ON ur.role_id = r.role_id
            WHERE r.role_code = 'SYSTEM_ADMIN' AND u.is_active = 1;
        `);
        if (adminRes.recordset.length > 0) {
            seededAdminUser = {
                user_id: adminRes.recordset[0].user_id,
                display_name: adminRes.recordset[0].display_name,
                email: adminRes.recordset[0].email,
                roles: [{ role_code: 'SYSTEM_ADMIN' }]
            };
        }

        const sponsorRes = await pool.request().query(`
            SELECT TOP 1 u.user_id, u.display_name, u.email
            FROM dbo.users u
            INNER JOIN dbo.user_roles ur ON u.user_id = ur.user_id
            INNER JOIN dbo.roles r ON ur.role_id = r.role_id
            WHERE r.role_code = 'INTERNAL_SPONSOR' AND u.is_active = 1;
        `);
        if (sponsorRes.recordset.length > 0) {
            seededSponsorUser = {
                user_id: sponsorRes.recordset[0].user_id,
                display_name: sponsorRes.recordset[0].display_name,
                email: sponsorRes.recordset[0].email,
                roles: [{ role_code: 'INTERNAL_SPONSOR' }]
            };
        }
    });

    after(async () => {
        // Clean up created test entities if any
        if (createdEntitlementId) {
            await pool.request()
                .input('id', createdEntitlementId)
                .query(`DELETE FROM dbo.entitlements WHERE entitlement_id = @id`);
        }
        if (createdResourceId) {
            await pool.request()
                .input('id', createdResourceId)
                .query(`DELETE FROM dbo.resource_owners WHERE resource_id = @id`);
            await pool.request()
                .input('id', createdResourceId)
                .query(`DELETE FROM dbo.entitlements WHERE resource_id = @id`);
            await pool.request()
                .input('id', createdResourceId)
                .query(`DELETE FROM dbo.resources WHERE resource_id = @id`);
        }
        await closePool();
    });

    test('1. listResources: returns active seeded resources with owner and entitlement metrics', async () => {
        assert.ok(seededAdminUser, 'Seeded admin user must exist');
        const resources = await catalogService.listResources({ isActive: true }, seededAdminUser);

        assert.ok(Array.isArray(resources));
        assert.ok(resources.length >= 2, 'Should contain at least 2 seeded resources');

        const kube = resources.find(r => r.resource_code === 'RES-PROD-KUBE');
        assert.ok(kube, 'RES-PROD-KUBE must be present');
        assert.strictEqual(kube.risk_level, 'CRITICAL');
        assert.strictEqual(kube.environment, 'PRODUCTION');
        assert.ok(parseInt(kube.total_entitlements_count, 10) >= 1);
    });

    test('2. createResource: registers new resource with primary owner mapping and audit logging', async () => {
        const result = await catalogService.createResource({
            resourceCode: testResCode,
            resourceName: 'Integration Test Microservice',
            resourceType: 'INTERNAL_APP',
            environment: 'STAGING',
            riskLevel: 'HIGH',
            maxLeaseDurationDays: 45,
            requiresSecurityApproval: true,
            primaryOwnerUserId: seededAdminUser.user_id,
            description: 'Automated integration testing workload'
        }, seededAdminUser);

        assert.ok(result.resource_id);
        createdResourceId = result.resource_id;

        assert.strictEqual(result.resource_code, testResCode);
        assert.strictEqual(result.environment, 'STAGING');
        assert.strictEqual(result.risk_level, 'HIGH');
        assert.strictEqual(result.max_lease_duration_days, 45);

        // Verify in database
        const dbRes = await pool.request()
            .input('id', createdResourceId)
            .query(`SELECT * FROM dbo.resources WHERE resource_id = @id`);
        assert.strictEqual(dbRes.recordset.length, 1);
        assert.strictEqual(dbRes.recordset[0].resource_code, testResCode);

        // Verify primary owner in database
        const ownerRes = await pool.request()
            .input('id', createdResourceId)
            .query(`SELECT * FROM dbo.resource_owners WHERE resource_id = @id AND ownership_type = 'PRIMARY'`);
        assert.strictEqual(ownerRes.recordset.length, 1);
        assert.strictEqual(ownerRes.recordset[0].owner_user_id.toLowerCase(), seededAdminUser.user_id.toLowerCase());
    });

    test('3. createResource: enforces unique constraint on resource_code', async () => {
        await assert.rejects(
            async () => {
                await catalogService.createResource({
                    resourceCode: testResCode,
                    resourceName: 'Duplicate Attempt',
                    resourceType: 'DATABASE'
                }, seededAdminUser);
            },
            (err) => err instanceof ConflictError && err.message.includes('already exists')
        );
    });

    test('4. createEntitlement: creates entitlement mapped to resource', async () => {
        const ent = await catalogService.createEntitlement(createdResourceId, {
            entitlementCode: 'TEST_READ_ONLY',
            entitlementName: 'Test Read Only Access',
            sensitivityLevel: 'MEDIUM',
            description: 'Can query test workload diagnostics'
        }, seededAdminUser);

        assert.ok(ent.entitlement_id);
        createdEntitlementId = ent.entitlement_id;
        assert.strictEqual(ent.entitlement_code, 'TEST_READ_ONLY');
        assert.strictEqual(ent.sensitivity_level, 'MEDIUM');

        // Verify in database
        const dbEnt = await pool.request()
            .input('id', createdEntitlementId)
            .query(`SELECT * FROM dbo.entitlements WHERE entitlement_id = @id`);
        assert.strictEqual(dbEnt.recordset.length, 1);
        assert.strictEqual(dbEnt.recordset[0].resource_id.toLowerCase(), createdResourceId.toLowerCase());
    });

    test('5. createEntitlement: rejects duplicate entitlement code under same resource', async () => {
        await assert.rejects(
            async () => {
                await catalogService.createEntitlement(createdResourceId, {
                    entitlementCode: 'TEST_READ_ONLY',
                    entitlementName: 'Duplicate Code'
                }, seededAdminUser);
            },
            (err) => err instanceof ConflictError && err.message.includes('already exists')
        );
    });

    test('6. getResourceById: retrieves complete resource details with owners and entitlements', async () => {
        const res = await catalogService.getResourceById(createdResourceId, seededAdminUser);

        assert.strictEqual(res.resource_id.toLowerCase(), createdResourceId.toLowerCase());
        assert.strictEqual(res.resource_code, testResCode);
        assert.strictEqual(res.environment, 'STAGING');
        assert.ok(res.primary_owner);
        assert.strictEqual(res.primary_owner.owner_user_id.toLowerCase(), seededAdminUser.user_id.toLowerCase());
        assert.ok(Array.isArray(res.entitlements));
        assert.strictEqual(res.entitlements.length, 1);
        assert.strictEqual(res.entitlements[0].entitlement_code, 'TEST_READ_ONLY');
    });

    test('7. setEntitlementStatus: deactivates entitlement and filters it from standard list', async () => {
        await catalogService.setEntitlementStatus(createdEntitlementId, false, seededAdminUser);

        // List with active filter
        const activeEnts = await catalogService.listEntitlements(createdResourceId, { isActive: true }, seededSponsorUser);
        assert.strictEqual(activeEnts.length, 0, 'Deactivated entitlement must not be returned in active list');

        // List all (admin)
        const allEnts = await catalogService.listEntitlements(createdResourceId, { isActive: 'all' }, seededAdminUser);
        assert.strictEqual(allEnts.length, 1);
        assert.strictEqual(allEnts[0].is_active, false);
    });

    test('8. Audit trail: verifies audit events were recorded in dbo.audit_events', async () => {
        const auditRes = await pool.request()
            .input('resId', createdResourceId)
            .query(`
                SELECT event_action, entity_type
                FROM dbo.audit_events
                WHERE entity_id = @resId OR entity_id = @resId
                ORDER BY created_at DESC;
            `);

        assert.ok(auditRes.recordset.length >= 1, 'Audit records must be created for resource');
        const actions = auditRes.recordset.map(r => r.event_action);
        assert.ok(actions.includes('RESOURCE_CREATED'), 'Must record RESOURCE_CREATED event');
    });
});
