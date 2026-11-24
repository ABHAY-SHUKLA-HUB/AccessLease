/**
 * AccessLease — Orphan & Stale Access Detection Integration Tests (PROMPT 08)
 * Real database-driven integration tests running against Microsoft SQL Server LocalDB.
 * 
 * Verifies:
 * 1. Ended or terminated engagement with active grant is detected as ENDED_ENGAGEMENT_ACTIVE_GRANT (CRITICAL).
 * 2. Expired engagement with active grant is detected as EXPIRED_ENGAGEMENT_ACTIVE_GRANT (CRITICAL).
 * 3. Expired active grant (expires_at in UTC) is detected as EXPIRED_GRANT_ACTIVE_STATUS (CRITICAL).
 * 4. Repeated scans prevent duplicate open findings (MERGE upsert refreshes last_detected_at).
 * 5. Pagination and filtering by status, severity, and reason work accurately.
 * 6. Authorized Security Officer / System Admin initiates revocation for confirmed finding:
 *    enqueues revocation job (ORPHAN_DETECTION), transitions grant to REVOKE_PENDING,
 *    and updates finding to REVOCATION_INITIATED with revocation_job_id.
 * 7. Finding resolution (RESOLVED / FALSE_POSITIVE) with required notes.
 * 8. Compliance Auditor read-only restrictions: blocked from triggering scan or initiating revocation.
 */

const { describe, it, before, after, afterEach } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { getPool, closePool } = require('../../src/config/database');
const orphanDetectionService = require('../../src/services/orphanDetectionService');
const { orphanFindingRepository } = require('../../src/repositories');
const { ForbiddenError, ValidationError, ConflictError } = require('../../src/utils/errors');

describe('Prompt 08: Orphan & Stale Access Detection Integration Tests (LocalDB)', () => {
    let pool;
    let adminUser;
    let securityUser;
    let sponsorUser;
    let contractorUser;
    let auditorUser;
    let testResourceId;
    let testEntitlementId;

    const cleanupFindingIds = [];
    const cleanupGrantIds = [];
    const cleanupEngagementIds = [];
    const cleanupRequestIds = [];
    const cleanupJobIds = [];

    before(async () => {
        pool = await getPool();

        // 1. Fetch seed users
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

        // 2. Fetch catalog resource and entitlement
        const resQuery = await pool.request().query(`
            SELECT TOP 1 r.resource_id, e.entitlement_id
            FROM dbo.resources r
            INNER JOIN dbo.entitlements e ON r.resource_id = e.resource_id;
        `);
        testResourceId = resQuery.recordset[0].resource_id;
        testEntitlementId = resQuery.recordset[0].entitlement_id;
    });

    after(async () => {
        // Cleanup all created records
        if (cleanupFindingIds.length > 0) {
            for (const fid of cleanupFindingIds) {
                await pool.request().input('id', fid).query(`DELETE FROM dbo.orphan_access_findings WHERE finding_id = @id`);
            }
        }
        if (cleanupJobIds.length > 0) {
            for (const jid of cleanupJobIds) {
                await pool.request().input('id', jid).query(`DELETE FROM dbo.revocation_jobs WHERE job_id = @id`);
            }
        }
        if (cleanupGrantIds.length > 0) {
            for (const gid of cleanupGrantIds) {
                await pool.request().input('id', gid).query(`DELETE FROM dbo.orphan_access_findings WHERE grant_id = @id`);
                await pool.request().input('id', gid).query(`DELETE FROM dbo.revocation_jobs WHERE grant_id = @id`);
                await pool.request().input('id', gid).query(`DELETE FROM dbo.access_grants WHERE grant_id = @id`);
            }
        }
        if (cleanupRequestIds.length > 0) {
            for (const rid of cleanupRequestIds) {
                await pool.request().input('id', rid).query(`DELETE FROM dbo.access_requests WHERE request_id = @id`);
            }
        }
        if (cleanupEngagementIds.length > 0) {
            for (const eid of cleanupEngagementIds) {
                await pool.request().input('id', eid).query(`DELETE FROM dbo.contractor_engagements WHERE engagement_id = @id`);
            }
        }
        await closePool();
    });

    // Helper to create test engagement, request, and grant
    async function createTestGrantFixture(overrides = {}) {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const engagementStatus = overrides.engagementStatus || 'ACTIVE';
        const engagementEndDate = overrides.engagementEndDate || '2026-12-31';
        const grantStatus = overrides.grantStatus || 'ACTIVE';
        const grantExpiresAt = overrides.grantExpiresAt || '2026-12-31T23:59:59Z';

        // 1. Create Engagement
        const engRes = await pool.request()
            .input('contractorUserId', contractorUser.user_id)
            .input('sponsorUserId', sponsorUser.user_id)
            .input('status', engagementStatus)
            .input('contractRef', `CNT-ORPHAN-${rand}`)
            .input('endDate', engagementEndDate)
            .query(`
                INSERT INTO dbo.contractor_engagements (
                    contractor_user_id, sponsor_user_id, vendor_name, contract_reference,
                    start_date, end_date, status, created_at, updated_at
                )
                OUTPUT INSERTED.engagement_id
                VALUES (
                    @contractorUserId, @sponsorUserId, 'Acme Security Labs', @contractRef,
                    '2026-01-01', @endDate, @status, SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                );
            `);
        const engagementId = engRes.recordset[0].engagement_id;
        cleanupEngagementIds.push(engagementId);

        // 2. Create Access Request
        const reqRes = await pool.request()
            .input('requestedByUserId', sponsorUser.user_id)
            .input('contractorEngagementId', engagementId)
            .input('resourceId', testResourceId)
            .input('entitlementId', testEntitlementId)
            .input('reqNum', `AR-ORPHAN-${rand}`)
            .query(`
                INSERT INTO dbo.access_requests (
                    request_number, requested_by_user_id, contractor_engagement_id, resource_id,
                    entitlement_id, requested_start_date, requested_end_date, business_justification,
                    status, created_at, updated_at
                )
                OUTPUT INSERTED.request_id
                VALUES (
                    @reqNum, @requestedByUserId, @contractorEngagementId, @resourceId,
                    @entitlementId, '2026-01-01', '2026-12-31', 'Orphan test justification',
                    'APPROVED', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                );
            `);
        const requestId = reqRes.recordset[0].request_id;
        cleanupRequestIds.push(requestId);

        // 3. Create Access Grant
        const grantRes = await pool.request()
            .input('grantNum', `GNT-ORPHAN-${rand}`)
            .input('requestId', requestId)
            .input('engagementId', engagementId)
            .input('resourceId', testResourceId)
            .input('entitlementId', testEntitlementId)
            .input('status', grantStatus)
            .input('expiresAt', grantExpiresAt)
            .query(`
                DECLARE @inserted TABLE (grant_id UNIQUEIDENTIFIER, grant_number NVARCHAR(30));

                INSERT INTO dbo.access_grants (
                    grant_number, request_id, contractor_engagement_id, resource_id, entitlement_id,
                    granted_at, expires_at, status, created_at, updated_at
                )
                OUTPUT INSERTED.grant_id, INSERTED.grant_number INTO @inserted
                VALUES (
                    @grantNum, @requestId, @engagementId, @resourceId, @entitlementId,
                    '2026-01-01T00:00:00Z', @expiresAt, @status, SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                );

                SELECT grant_id, grant_number FROM @inserted;
            `);
        const grant = grantRes.recordset[0];
        cleanupGrantIds.push(grant.grant_id);

        return { engagementId, requestId, grantId: grant.grant_id, grantNumber: grant.grant_number };
    }

    it('1. Detects active grant on TERMINATED engagement as ENDED_ENGAGEMENT_ACTIVE_GRANT (CRITICAL)', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'TERMINATED',
            grantStatus: 'ACTIVE'
        });

        // Run detection scan
        const scanRes = await orphanDetectionService.runOrphanDetectionScan(securityUser);
        assert.ok(scanRes.totalDetected >= 1, 'Scan must detect at least 1 orphan candidate');

        // Verify finding in database
        const findings = await orphanFindingRepository.listFindings({
            status: 'OPEN',
            reason: 'ENDED_ENGAGEMENT_ACTIVE_GRANT'
        });

        const finding = findings.findings.find(f => f.grant_id === fixture.grantId);
        assert.ok(finding, 'Must record finding for terminated engagement with active grant');
        assert.strictEqual(finding.severity, 'CRITICAL');
        assert.strictEqual(finding.finding_reason, 'ENDED_ENGAGEMENT_ACTIVE_GRANT');
        assert.strictEqual(finding.status, 'OPEN');
        cleanupFindingIds.push(finding.finding_id);
    });

    it('2. Detects active grant on EXPIRED engagement as EXPIRED_ENGAGEMENT_ACTIVE_GRANT (CRITICAL)', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'ACTIVE',
            engagementEndDate: '2026-01-15', // Past date
            grantStatus: 'ACTIVE',
            grantExpiresAt: '2026-01-15T23:59:59Z'
        });

        const scanRes = await orphanDetectionService.runOrphanDetectionScan(securityUser);
        assert.ok(scanRes.totalDetected >= 1);

        const findings = await orphanFindingRepository.listFindings({
            status: 'OPEN',
            reason: 'EXPIRED_ENGAGEMENT_ACTIVE_GRANT'
        });

        const finding = findings.findings.find(f => f.grant_id === fixture.grantId);
        assert.ok(finding, 'Must record finding for expired engagement with active grant');
        assert.strictEqual(finding.severity, 'CRITICAL');
        cleanupFindingIds.push(finding.finding_id);
    });

    it('3. Detects grant past expires_at remaining ACTIVE as EXPIRED_GRANT_ACTIVE_STATUS (CRITICAL)', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'ACTIVE',
            engagementEndDate: '2026-12-31',
            grantStatus: 'ACTIVE',
            grantExpiresAt: '2026-02-01T00:00:00Z' // Past timestamp
        });

        const scanRes = await orphanDetectionService.runOrphanDetectionScan(securityUser);
        assert.ok(scanRes.totalDetected >= 1);

        const findings = await orphanFindingRepository.listFindings({
            status: 'OPEN',
            reason: 'EXPIRED_GRANT_ACTIVE_STATUS'
        });

        const finding = findings.findings.find(f => f.grant_id === fixture.grantId);
        assert.ok(finding, 'Must record finding for expired grant remaining active');
        assert.strictEqual(finding.severity, 'CRITICAL');
        cleanupFindingIds.push(finding.finding_id);
    });

    it('4. Repeated scans prevent duplicate findings (upsert refreshes last_detected_at)', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'TERMINATED',
            grantStatus: 'ACTIVE'
        });

        // Scan 1
        const scan1 = await orphanDetectionService.runOrphanDetectionScan(adminUser);
        const countBeforeRes = await pool.request()
            .input('grantId', fixture.grantId)
            .query(`SELECT COUNT(*) AS cnt, MAX(finding_id) AS fid, MAX(last_detected_at) AS last_dt FROM dbo.orphan_access_findings WHERE grant_id = @grantId;`);
        assert.strictEqual(countBeforeRes.recordset[0].cnt, 1, 'Initial scan must create exactly 1 finding');
        const findingId = countBeforeRes.recordset[0].fid;
        const initialLastDetected = countBeforeRes.recordset[0].last_dt;
        cleanupFindingIds.push(findingId);

        // Scan 2 (repeated scan)
        const scan2 = await orphanDetectionService.runOrphanDetectionScan(adminUser);

        // Verify zero duplicate rows created
        const countAfterRes = await pool.request()
            .input('grantId', fixture.grantId)
            .query(`SELECT COUNT(*) AS cnt, MAX(last_detected_at) AS last_dt FROM dbo.orphan_access_findings WHERE grant_id = @grantId;`);
        assert.strictEqual(countAfterRes.recordset[0].cnt, 1, 'Repeated scan must NOT create duplicate finding');
        assert.ok(countAfterRes.recordset[0].last_dt >= initialLastDetected, 'last_detected_at must be refreshed');
    });

    it('5. Filters findings by severity, reason, and status accurately', async () => {
        const list = await orphanDetectionService.getFindings({
            status: 'OPEN',
            severity: 'CRITICAL',
            limit: 10
        });

        assert.ok(Array.isArray(list.findings));
        for (const item of list.findings) {
            assert.strictEqual(item.status, 'OPEN');
            assert.strictEqual(item.severity, 'CRITICAL');
        }
    });

    it('6. Initiates revocation workflow for confirmed orphan finding (enqueues job & updates finding)', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'TERMINATED',
            grantStatus: 'ACTIVE'
        });

        // Detect
        await orphanDetectionService.runOrphanDetectionScan(securityUser);
        const findings = await orphanFindingRepository.listFindings({ status: 'OPEN' });
        const finding = findings.findings.find(f => f.grant_id === fixture.grantId);
        assert.ok(finding);
        cleanupFindingIds.push(finding.finding_id);

        // Security Officer initiates revocation
        const result = await orphanDetectionService.initiateFindingRevocation(
            finding.finding_id,
            securityUser,
            'Confirmed orphan access on terminated vendor engagement'
        );

        assert.ok(result.revocationJob);
        assert.strictEqual(result.revocationJob.grant_id, fixture.grantId);
        cleanupJobIds.push(result.revocationJob.job_id);

        // Verify finding status transitioned to REVOCATION_INITIATED
        assert.strictEqual(result.finding.status, 'REVOCATION_INITIATED');
        assert.strictEqual(result.finding.revocation_job_id, result.revocationJob.job_id);

        // Verify grant status transitioned through revocation pipeline in database (REVOKE_PENDING or MANUAL_REVIEW_REQUIRED)
        const grantCheck = await pool.request()
            .input('grantId', fixture.grantId)
            .query(`SELECT status FROM dbo.access_grants WHERE grant_id = @grantId;`);
        assert.ok(['REVOKE_PENDING', 'MANUAL_REVIEW_REQUIRED', 'REVOKED'].includes(grantCheck.recordset[0].status),
            `Grant status must transition into revocation pipeline, got: ${grantCheck.recordset[0].status}`);
    });

    it('7. Resolves finding with notes without revoking', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'TERMINATED',
            grantStatus: 'ACTIVE'
        });

        await orphanDetectionService.runOrphanDetectionScan(securityUser);
        const findings = await orphanFindingRepository.listFindings({ status: 'OPEN' });
        const finding = findings.findings.find(f => f.grant_id === fixture.grantId);
        assert.ok(finding);
        cleanupFindingIds.push(finding.finding_id);

        const resolved = await orphanDetectionService.resolveFinding(
            finding.finding_id,
            securityUser,
            'FALSE_POSITIVE',
            'Verified renewal paperwork pending signature in external system'
        );

        assert.strictEqual(resolved.status, 'FALSE_POSITIVE');
        assert.strictEqual(resolved.resolved_by_user_id, securityUser.user_id);
        assert.strictEqual(resolved.resolution_notes, 'Verified renewal paperwork pending signature in external system');
    });

    it('8. Compliance Auditor is strictly read-only and blocked from triggering scans', async () => {
        const { triggerOrphanScan } = require('../../src/functions/orphanAccess');

        const mockReq = {
            user: auditorUser,
            headers: new Map(),
            query: {}
        };
        const mockContext = { invocationId: 'inv-aud-1' };

        const response = await triggerOrphanScan(mockReq, mockContext);
        assert.strictEqual(response.status, 403);
        const body = typeof response.jsonBody === 'object' ? response.jsonBody : JSON.parse(response.body);
        assert.strictEqual(body.error.code, 'ERR_AUDITOR_READ_ONLY');
    });

    it('9. Deduplication preserves REVOCATION_INITIATED status and revocation_job_id on repeated scans', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'TERMINATED',
            grantStatus: 'ACTIVE'
        });

        // 1. Initial scan detects finding
        await orphanDetectionService.runOrphanDetectionScan(adminUser);
        const findings = await orphanFindingRepository.listFindings({ status: 'OPEN' });
        const finding = findings.findings.find(f => f.grant_id === fixture.grantId);
        assert.ok(finding);
        cleanupFindingIds.push(finding.finding_id);

        // 2. Transition finding to REVOCATION_INITIATED with revocation job
        const revResult = await orphanDetectionService.initiateFindingRevocation(
            finding.finding_id,
            securityUser,
            'Initiating revocation for deduplication test'
        );
        cleanupJobIds.push(revResult.revocationJob.job_id);
        assert.strictEqual(revResult.finding.status, 'REVOCATION_INITIATED');

        // 3. Run repeated scan while finding is in REVOCATION_INITIATED
        const repeatedScan = await orphanDetectionService.runOrphanDetectionScan(adminUser);

        // 4. Verify no duplicate finding was inserted and existing finding status & revocation_job_id remain intact
        const allFindingsRes = await pool.request()
            .input('grantId', fixture.grantId)
            .query(`
                SELECT finding_id, status, revocation_job_id, last_detected_at
                FROM dbo.orphan_access_findings
                WHERE grant_id = @grantId;
            `);

        assert.strictEqual(allFindingsRes.recordset.length, 1, 'Must NOT create duplicate finding row for REVOCATION_INITIATED finding');
        const refreshedFinding = allFindingsRes.recordset[0];
        assert.strictEqual(refreshedFinding.status, 'REVOCATION_INITIATED', 'Must preserve REVOCATION_INITIATED status');
        assert.strictEqual(refreshedFinding.revocation_job_id, revResult.revocationJob.job_id, 'Must preserve revocation_job_id');
    });

    it('10. Deduplication does NOT reopen RESOLVED or FALSE_POSITIVE findings automatically', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'TERMINATED',
            grantStatus: 'ACTIVE'
        });

        // 1. Detect and resolve as FALSE_POSITIVE
        await orphanDetectionService.runOrphanDetectionScan(adminUser);
        const findings = await orphanFindingRepository.listFindings({ status: 'OPEN' });
        const finding = findings.findings.find(f => f.grant_id === fixture.grantId);
        assert.ok(finding);
        cleanupFindingIds.push(finding.finding_id);

        await orphanDetectionService.resolveFinding(
            finding.finding_id,
            securityUser,
            'FALSE_POSITIVE',
            'Business approved special exception through next quarter'
        );

        // 2. Run repeated automated scan
        await orphanDetectionService.runOrphanDetectionScan(adminUser);

        // 3. Verify finding was NOT reopened to OPEN and no duplicate was inserted
        const findingsRes = await pool.request()
            .input('grantId', fixture.grantId)
            .query(`
                SELECT finding_id, status
                FROM dbo.orphan_access_findings
                WHERE grant_id = @grantId;
            `);

        assert.strictEqual(findingsRes.recordset.length, 1, 'Must NOT create duplicate row for resolved finding');
        assert.strictEqual(findingsRes.recordset[0].status, 'FALSE_POSITIVE', 'Routine scan must NOT reopen FALSE_POSITIVE finding');
    });

    it('11. Safely serializes concurrent scan executions without duplicate inserts or deadlocks', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'TERMINATED',
            grantStatus: 'ACTIVE'
        });

        // Trigger two scans concurrently against the same newly created fixture
        const [scanA, scanB] = await Promise.all([
            orphanDetectionService.runOrphanDetectionScan(adminUser),
            orphanDetectionService.runOrphanDetectionScan(securityUser)
        ]);

        assert.ok(scanA.scannedAt);
        assert.ok(scanB.scannedAt);

        // Verify exactly one finding exists for this grant
        const countRes = await pool.request()
            .input('grantId', fixture.grantId)
            .query(`
                SELECT COUNT(*) AS total_count, MAX(finding_id) AS fid
                FROM dbo.orphan_access_findings
                WHERE grant_id = @grantId;
            `);

        assert.strictEqual(countRes.recordset[0].total_count, 1, 'Concurrent scans must safely produce exactly 1 finding');
        cleanupFindingIds.push(countRes.recordset[0].fid);
    });

    it('12. Blocks ordinary resolution when an automated revocation job is actively pending or processing', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'TERMINATED',
            grantStatus: 'ACTIVE'
        });

        await orphanDetectionService.runOrphanDetectionScan(adminUser);
        const findings = await orphanFindingRepository.listFindings({ status: 'OPEN' });
        const finding = findings.findings.find(f => f.grant_id === fixture.grantId);
        assert.ok(finding);
        cleanupFindingIds.push(finding.finding_id);

        // Create an active pending revocation job directly in QUEUED/PROCESSING status
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const jobRes = await pool.request()
            .input('grantId', fixture.grantId)
            .input('workerId', `worker-${rand}`)
            .query(`
                INSERT INTO dbo.revocation_jobs (
                    grant_id, connector_name, trigger_source, status,
                    lease_owner, lease_expires_at, created_at, updated_at
                )
                OUTPUT INSERTED.job_id
                VALUES (
                    @grantId, 'GITHUB', 'ORPHAN_DETECTION', 'PROCESSING',
                    @workerId, DATEADD(MINUTE, 5, SYSDATETIMEOFFSET()), SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                );
            `);
        const jobId = jobRes.recordset[0].job_id;
        cleanupJobIds.push(jobId);

        // Link revocation job to finding
        await pool.request()
            .input('findingId', finding.finding_id)
            .input('jobId', jobId)
            .query(`UPDATE dbo.orphan_access_findings SET revocation_job_id = @jobId WHERE finding_id = @findingId;`);

        // Attempting ordinary resolution while job is PROCESSING must be blocked
        await assert.rejects(
            () => orphanDetectionService.resolveFinding(
                finding.finding_id,
                securityUser,
                'FALSE_POSITIVE',
                'Attempting to resolve while revocation is actively processing'
            ),
            (err) => err instanceof ConflictError && err.code === 'ERR_PENDING_REVOCATION_ACTIVE'
        );
    });

    it('13. Permits resolution when explicit administrative override is authorized and audits override', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'TERMINATED',
            grantStatus: 'ACTIVE'
        });

        await orphanDetectionService.runOrphanDetectionScan(adminUser);
        const findings = await orphanFindingRepository.listFindings({ status: 'OPEN' });
        const finding = findings.findings.find(f => f.grant_id === fixture.grantId);
        assert.ok(finding);
        cleanupFindingIds.push(finding.finding_id);

        // Create an active revocation job in QUEUED status
        const jobRes = await pool.request()
            .input('grantId', fixture.grantId)
            .query(`
                INSERT INTO dbo.revocation_jobs (
                    grant_id, connector_name, trigger_source, status,
                    created_at, updated_at
                )
                OUTPUT INSERTED.job_id
                VALUES (
                    @grantId, 'GITHUB', 'ORPHAN_DETECTION', 'QUEUED',
                    SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                );
            `);
        const jobId = jobRes.recordset[0].job_id;
        cleanupJobIds.push(jobId);

        await pool.request()
            .input('findingId', finding.finding_id)
            .input('jobId', jobId)
            .query(`UPDATE dbo.orphan_access_findings SET revocation_job_id = @jobId WHERE finding_id = @findingId;`);

        // Resolve with explicit administrative override
        const resolved = await orphanDetectionService.resolveFinding(
            finding.finding_id,
            adminUser,
            'FALSE_POSITIVE',
            'Administrative emergency halt on automated revocation for audit compliance',
            { allowOverride: true }
        );

        assert.strictEqual(resolved.status, 'FALSE_POSITIVE');

        // Verify audit event captured isAdministrativeOverride: true
        const auditRes = await pool.request()
            .input('findingId', finding.finding_id)
            .query(`
                SELECT TOP 1 event_payload
                FROM dbo.audit_events
                WHERE entity_id = @findingId AND event_action = 'ORPHAN_FINDING_RESOLVED'
                ORDER BY created_at DESC;
            `);

        assert.ok(auditRes.recordset.length > 0);
        const payload = JSON.parse(auditRes.recordset[0].event_payload);
        assert.strictEqual(payload.isAdministrativeOverride, true);
    });

    it('14. Contradiction protection: Cannot mark finding RESOLVED while grant remains ACTIVE without remediation', async () => {
        const fixture = await createTestGrantFixture({
            engagementStatus: 'TERMINATED',
            grantStatus: 'ACTIVE' // Grant is still active
        });

        await orphanDetectionService.runOrphanDetectionScan(adminUser);
        const findings = await orphanFindingRepository.listFindings({ status: 'OPEN' });
        const finding = findings.findings.find(f => f.grant_id === fixture.grantId);
        assert.ok(finding);
        cleanupFindingIds.push(finding.finding_id);

        // Attempting to mark as RESOLVED while grant is still ACTIVE (without override or revocation) must fail
        await assert.rejects(
            () => orphanDetectionService.resolveFinding(
                finding.finding_id,
                securityUser,
                'RESOLVED',
                'Trying to mark resolved without revoking active grant'
            ),
            (err) => err instanceof ConflictError && err.code === 'ERR_FINDING_STATUS_CONTRADICTION'
        );
    });
});
