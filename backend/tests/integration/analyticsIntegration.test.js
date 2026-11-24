/**
 * AccessLease — Security Analytics Integration Tests (PROMPT 08)
 * Real database-driven integration tests running against Microsoft SQL Server LocalDB.
 * 
 * Verifies:
 * 1. Accuracy of aggregate governance metrics against authoritative database tables.
 * 2. Zero duplicate counting from table relationships.
 * 3. Strict RBAC data scoping:
 *    - Governance users (Admin/Security/Auditor) receive enterprise-wide totals (GLOBAL_ENTERPRISE).
 *    - Internal Sponsors receive totals scoped to their sponsored engagements (SPONSORED_SCOPE).
 *    - Contractors receive totals scoped to their personal identity (CONTRACTOR_SCOPE).
 * 4. API envelope formatting and structure.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const { getPool, closePool } = require('../../src/config/database');
const analyticsService = require('../../src/services/analyticsService');
const { getAnalyticsSummary } = require('../../src/functions/analytics');

describe('Prompt 08: Security Analytics & Metrics Integration Tests (LocalDB)', () => {
    let pool;
    let adminUser;
    let securityUser;
    let sponsorUser;
    let contractorUser;
    let auditorUser;

    before(async () => {
        pool = await getPool();

        // Fetch seed users
        const usersRes = await pool.request().query(`
            SELECT u.user_id, u.email, u.display_name, r.role_code
            FROM dbo.users u
            LEFT JOIN dbo.user_roles ur ON u.user_id = ur.user_id
            LEFT JOIN dbo.roles r ON ur.role_id = r.role_id;
        `);
        const rows = usersRes.recordset;

        adminUser = rows.find(u => u.role_code === 'SYSTEM_ADMIN') || { user_id: '65DC0F17-2FDD-F111-B04D-B81EA4E649CE' };
        adminUser.roles = ['SYSTEM_ADMIN'];

        securityUser = rows.find(u => u.role_code === 'SECURITY_OFFICER') || { user_id: '0BFF6785-29DD-F111-B04D-B81EA4E649CE' };
        securityUser.roles = ['SECURITY_OFFICER'];

        sponsorUser = rows.find(u => u.role_code === 'INTERNAL_SPONSOR') || { user_id: '00F82335-7866-440A-B633-D9DFFF51CF80' };
        sponsorUser.roles = ['INTERNAL_SPONSOR'];

        contractorUser = rows.find(u => u.role_code === 'CONTRACTOR') || { user_id: '27F3224F-8C5A-456E-8295-68D9919CDEED' };
        contractorUser.roles = ['CONTRACTOR'];

        auditorUser = rows.find(u => u.role_code === 'COMPLIANCE_AUDITOR') || { user_id: '64DC0F17-2FDD-F111-B04D-B81EA4E649CE' };
        auditorUser.roles = ['COMPLIANCE_AUDITOR'];
    });

    after(async () => {
        await closePool();
    });

    it('1. Computes accurate enterprise metrics matching live database queries for governance roles', async () => {
        const summary = await analyticsService.getSecurityAnalyticsSummary(adminUser);

        assert.strictEqual(summary.scope, 'GLOBAL_ENTERPRISE');
        assert.ok(summary.metrics);

        // Verify active engagements count matches raw SQL
        const rawEngs = await pool.request().query(`
            SELECT COUNT(*) AS cnt FROM dbo.contractor_engagements WHERE status = 'ACTIVE' AND end_date >= CAST(SYSUTCDATETIME() AS DATE);
        `);
        assert.strictEqual(summary.metrics.activeContractorEngagements, rawEngs.recordset[0].cnt);

        // Verify active grants count matches raw SQL
        const rawGrants = await pool.request().query(`
            SELECT COUNT(*) AS cnt FROM dbo.access_grants WHERE status = 'ACTIVE';
        `);
        assert.strictEqual(summary.metrics.activeAccessGrants, rawGrants.recordset[0].cnt);

        // Verify open orphan findings matches raw SQL
        const rawFindings = await pool.request().query(`
            SELECT COUNT(*) AS cnt FROM dbo.orphan_access_findings WHERE status = 'OPEN';
        `);
        assert.strictEqual(summary.metrics.orphanFindings.totalOpen, rawFindings.recordset[0].cnt);
    });

    it('2. Compliance Auditor receives GLOBAL_ENTERPRISE oversight metrics', async () => {
        const summary = await analyticsService.getSecurityAnalyticsSummary(auditorUser);
        assert.strictEqual(summary.scope, 'GLOBAL_ENTERPRISE');
        assert.ok(typeof summary.metrics.activeContractorEngagements === 'number');
        assert.ok(typeof summary.metrics.orphanFindings.totalOpen === 'number');
    });

    it('3. Scopes metrics to SPONSORED_SCOPE for Internal Business Sponsors', async () => {
        const summary = await analyticsService.getSecurityAnalyticsSummary(sponsorUser);
        assert.strictEqual(summary.scope, 'SPONSORED_SCOPE');

        const rawSponsoredEngs = await pool.request()
            .input('uid', sponsorUser.user_id)
            .query(`
                SELECT COUNT(*) AS cnt FROM dbo.contractor_engagements
                WHERE status = 'ACTIVE' AND end_date >= CAST(SYSUTCDATETIME() AS DATE) AND sponsor_user_id = @uid;
            `);
        assert.strictEqual(summary.metrics.activeContractorEngagements, rawSponsoredEngs.recordset[0].cnt);
    });

    it('4. Scopes metrics to CONTRACTOR_SCOPE for external contractors', async () => {
        const summary = await analyticsService.getSecurityAnalyticsSummary(contractorUser);
        assert.strictEqual(summary.scope, 'CONTRACTOR_SCOPE');

        const rawContractorEngs = await pool.request()
            .input('uid', contractorUser.user_id)
            .query(`
                SELECT COUNT(*) AS cnt FROM dbo.contractor_engagements
                WHERE status = 'ACTIVE' AND end_date >= CAST(SYSUTCDATETIME() AS DATE) AND contractor_user_id = @uid;
            `);
        assert.strictEqual(summary.metrics.activeContractorEngagements, rawContractorEngs.recordset[0].cnt);
        assert.strictEqual(summary.metrics.pendingApprovals, 0, 'Contractors cannot hold pending approvals');
    });

    it('5. API handler GET /api/analytics/summary returns canonical success envelope', async () => {
        const mockReq = {
            user: securityUser,
            headers: new Map(),
            query: {}
        };
        const mockContext = { invocationId: 'inv-analytics-1' };

        const response = await getAnalyticsSummary(mockReq, mockContext);
        assert.strictEqual(response.status, 200);

        const body = typeof response.jsonBody === 'object' ? response.jsonBody : JSON.parse(response.body);
        assert.strictEqual(body.success, true);
        assert.ok(body.data.metrics);
        assert.ok(body.meta.correlation_id);
    });
});

