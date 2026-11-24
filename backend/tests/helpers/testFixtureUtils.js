/**
 * AccessLease — Shared Test Fixture Utilities
 * Safely creates and cleans up isolated test fixtures in AccessLease_TestDB.
 * Enforces strict safety check against executing on non-test databases.
 */

const crypto = require('node:crypto');

/**
 * Creates an isolated access request and grant fixture in AccessLease_TestDB.
 * @param {object} pool mssql ConnectionPool
 * @param {object} [overrides={}]
 * @returns {Promise<{ requestId: string, grantId: string, cleanup: Function }>}
 */
async function createIsolatedGrantFixture(pool, overrides = {}) {
    const dbNameRes = await pool.request().query('SELECT DB_NAME() AS dbName');
    const dbName = dbNameRes.recordset[0]?.dbName;
    if (!dbName || !dbName.toLowerCase().includes('test')) {
        throw new Error(`Safety violation: Test fixtures must only be created in AccessLease_TestDB, current db: '${dbName}'`);
    }

    // Resolve test contractor identity
    const userRes = await pool.request().query(`
        SELECT TOP 1 u.user_id FROM dbo.users u WHERE u.entra_object_id = 'TEST-OID-CONTRACTOR';
    `);
    const contractorUserId = userRes.recordset[0]?.user_id;
    if (!contractorUserId) {
        throw new Error('Required seeded user TEST-OID-CONTRACTOR not found in AccessLease_TestDB');
    }

    // Resolve active engagement
    const engRes = await pool.request().query(`
        SELECT TOP 1 ce.engagement_id FROM dbo.contractor_engagements ce 
        WHERE ce.status = 'ACTIVE' ORDER BY ce.created_at ASC;
    `);
    const engagementId = engRes.recordset[0]?.engagement_id;
    if (!engagementId) {
        throw new Error('Required active contractor engagement not found in AccessLease_TestDB');
    }

    // Resolve resource and entitlement
    const resRes = await pool.request().query(`
        SELECT TOP 1 r.resource_id, e.entitlement_id 
        FROM dbo.resources r
        JOIN dbo.entitlements e ON r.resource_id = e.resource_id
        WHERE r.resource_code IN ('RES-GH-CORE-REPO', 'RES-PROD-KUBE');
    `);
    const resourceId = resRes.recordset[0]?.resource_id;
    const entitlementId = resRes.recordset[0]?.entitlement_id;
    if (!resourceId || !entitlementId) {
        throw new Error('Required test resource or entitlement not found in AccessLease_TestDB');
    }

    const fixtureRequestId = crypto.randomUUID();
    const fixtureGrantId = crypto.randomUUID();
    const suffix = `${Date.now().toString().slice(-6)}-${Math.floor(Math.random() * 10000)}`;
    const fixtureGrantNumber = `GNT-FIX-${suffix}`;
    const fixtureReqNumber = `AR-FIX-${suffix}`;

    const org = overrides.targetOrg || 'accesslease-governance';
    const teamSlug = overrides.targetTeamSlug || 'backend-engineers';
    const username = overrides.externalUsername || 'test-contractor-provenance';
    const status = overrides.status || 'ACTIVE';

    await pool.request().query(`
        INSERT INTO dbo.access_requests (
            request_id, request_number, contractor_engagement_id, requested_by_user_id,
            resource_id, entitlement_id, requested_start_date, requested_end_date,
            business_justification, status, requires_security_approval, created_at, updated_at
        ) VALUES (
            '${fixtureRequestId}', '${fixtureReqNumber}', '${engagementId}', '${contractorUserId}',
            '${resourceId}', '${entitlementId}', '2026-11-01', '2026-12-31',
            'Self-contained integration test fixture', 'APPROVED', 1, SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
        );

        INSERT INTO dbo.access_grants (
            grant_id, grant_number, request_id, contractor_engagement_id,
            resource_id, entitlement_id, granted_at, expires_at, status,
            connector_type, target_org, target_team_slug, external_username,
            membership_provenance, created_at, updated_at
        ) VALUES (
            '${fixtureGrantId}', '${fixtureGrantNumber}', '${fixtureRequestId}', '${engagementId}',
            '${resourceId}', '${entitlementId}', SYSDATETIMEOFFSET(), DATEADD(DAY, 30, SYSDATETIMEOFFSET()), '${status}',
            'GITHUB', '${org}', '${teamSlug}', '${username}',
            'CREATED_BY_ACCESSLEASE', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
        );
    `);

    return {
        requestId: fixtureRequestId,
        grantId: fixtureGrantId,
        cleanup: async () => {
            try {
                await pool.request().query(`
                    DELETE FROM dbo.provisioning_events WHERE grant_id = '${fixtureGrantId}';
                    DELETE FROM dbo.provisioning_jobs WHERE grant_id = '${fixtureGrantId}';
                    DELETE FROM dbo.access_grants WHERE grant_id = '${fixtureGrantId}';
                    DELETE FROM dbo.access_requests WHERE request_id = '${fixtureRequestId}';
                `);
            } catch (err) {
                // Silently swallow cleanup error
            }
        }
    };
}

module.exports = {
    createIsolatedGrantFixture
};
