/**
 * AccessLease — Access Review & Recertification Integration Tests (PROMPT 08)
 * Real database-driven integration tests running against Microsoft SQL Server LocalDB.
 * 
 * Verifies:
 * 1. Review campaign creation automatically populates review items for candidate grants.
 * 2. Contractor self-review is strictly blocked (Separation of Duties).
 * 3. Compliance Auditor is strictly read-only and blocked from submitting decisions.
 * 4. Authorized reviewer decides MAINTAIN: Decision recorded with notes; grant remains ACTIVE.
 * 5. Authorized reviewer decides REVOKE: Enqueues revocation job (REVIEW_REJECTION), transitions grant to REVOKE_PENDING.
 * 6. Never marks grant REVOKED before provider deprovisioning confirmation.
 * 7. When all items are decided, campaign status automatically transitions to COMPLETED.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const { getPool, closePool } = require('../../src/config/database');
const reviewService = require('../../src/services/reviewService');
const { reviewRepository } = require('../../src/repositories');
const { ForbiddenError, ValidationError, ConflictError } = require('../../src/utils/errors');

describe('Prompt 08: Access Review & Recertification Integration Tests (LocalDB)', () => {
    let pool;
    let adminUser;
    let securityUser;
    let sponsorUser;
    let contractorUser;
    let auditorUser;
    let resourceOwnerUser;
    let testResourceId;
    let testEntitlementId;

    const cleanupReviewIds = [];
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

        resourceOwnerUser = rows.find(u => u.role_code === 'RESOURCE_OWNER') || { user_id: '0AFF6785-29DD-F111-B04D-B81EA4E649CE' };
        resourceOwnerUser.roles = ['RESOURCE_OWNER'];

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
        // Cleanup review items and reviews
        if (cleanupReviewIds.length > 0) {
            for (const rid of cleanupReviewIds) {
                await pool.request().input('id', rid).query(`DELETE FROM dbo.review_items WHERE review_id = @id`);
                await pool.request().input('id', rid).query(`DELETE FROM dbo.access_reviews WHERE review_id = @id`);
            }
        }
        if (cleanupJobIds.length > 0) {
            for (const jid of cleanupJobIds) {
                await pool.request().input('id', jid).query(`DELETE FROM dbo.revocation_jobs WHERE job_id = @id`);
            }
        }
        if (cleanupGrantIds.length > 0) {
            for (const gid of cleanupGrantIds) {
                await pool.request().input('id', gid).query(`DELETE FROM dbo.review_items WHERE grant_id = @id`);
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

    // Helper to create active test grant with optional overrides
    async function createActiveGrant(overrides = {}) {
        const rand = Math.floor(Math.random() * 900000 + 100000);
        const engagementStatus = overrides.engagementStatus || 'ACTIVE';
        const engagementEndDate = overrides.engagementEndDate || '2027-12-31';
        const grantStatus = overrides.grantStatus || 'ACTIVE';
        const grantExpiresAt = overrides.grantExpiresAt || null;
        const grantResourceId = overrides.resourceId || testResourceId;
        const grantSponsorId = overrides.sponsorUserId || sponsorUser.user_id;
        const grantContractorId = overrides.contractorUserId || contractorUser.user_id;

        const engRes = await pool.request()
            .input('contractorUserId', grantContractorId)
            .input('sponsorUserId', grantSponsorId)
            .input('status', engagementStatus)
            .input('endDate', engagementEndDate)
            .input('contractRef', `CNT-REV-${rand}`)
            .query(`
                INSERT INTO dbo.contractor_engagements (
                    contractor_user_id, sponsor_user_id, vendor_name, contract_reference,
                    start_date, end_date, status, created_at, updated_at
                )
                OUTPUT INSERTED.engagement_id
                VALUES (
                    @contractorUserId, @sponsorUserId, 'Global Security Consulting', @contractRef,
                    '2026-01-01', @endDate, @status, SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                );
            `);
        const engagementId = engRes.recordset[0].engagement_id;
        cleanupEngagementIds.push(engagementId);

        const reqRes = await pool.request()
            .input('requestedByUserId', grantSponsorId)
            .input('contractorEngagementId', engagementId)
            .input('resourceId', grantResourceId)
            .input('entitlementId', testEntitlementId)
            .input('reqNum', `AR-REV-${rand}`)
            .query(`
                INSERT INTO dbo.access_requests (
                    request_number, requested_by_user_id, contractor_engagement_id, resource_id,
                    entitlement_id, requested_start_date, requested_end_date, business_justification,
                    status, created_at, updated_at
                )
                OUTPUT INSERTED.request_id
                VALUES (
                    @reqNum, @requestedByUserId, @contractorEngagementId, @resourceId,
                    @entitlementId, '2026-01-01', '2027-12-31', 'Review test grant',
                    'APPROVED', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
                );
            `);
        const requestId = reqRes.recordset[0].request_id;
        cleanupRequestIds.push(requestId);

        const grantReq = pool.request()
            .input('grantNum', `GNT-REV-${rand}`)
            .input('requestId', requestId)
            .input('engagementId', engagementId)
            .input('resourceId', grantResourceId)
            .input('entitlementId', testEntitlementId)
            .input('status', grantStatus);

        let expiresExpr = 'DATEADD(DAY, 14, SYSDATETIMEOFFSET())';
        if (grantExpiresAt) {
            grantReq.input('expiresAt', grantExpiresAt);
            expiresExpr = '@expiresAt';
        }

        const grantRes = await grantReq.query(`
            DECLARE @inserted TABLE (grant_id UNIQUEIDENTIFIER, grant_number NVARCHAR(30));

            INSERT INTO dbo.access_grants (
                grant_number, request_id, contractor_engagement_id, resource_id, entitlement_id,
                granted_at, expires_at, status, created_at, updated_at
            )
            OUTPUT INSERTED.grant_id, INSERTED.grant_number INTO @inserted
            VALUES (
                @grantNum, @requestId, @engagementId, @resourceId, @entitlementId,
                SYSDATETIMEOFFSET(), ${expiresExpr}, @status, SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
            );

            SELECT grant_id, grant_number FROM @inserted;
        `);
        const grant = grantRes.recordset[0];
        cleanupGrantIds.push(grant.grant_id);

        return { engagementId, requestId, grantId: grant.grant_id, grantNumber: grant.grant_number, resourceId: grantResourceId };
    }

    it('1. Creates access review campaign and automatically populates items for active grants in scope', async () => {
        const fixture = await createActiveGrant();

        const campaign = await reviewService.createReviewCampaign({
            reviewName: `Q4 2026 Recertification Campaign ${Date.now()}`,
            description: 'Automated periodic review of active contractor entitlements',
            campaignType: 'PERIODIC_RECERTIFICATION',
            startDate: new Date().toISOString(),
            dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
            scope: { resourceId: testResourceId }
        }, securityUser);

        assert.ok(campaign.review_id);
        cleanupReviewIds.push(campaign.review_id);
        assert.ok(campaign.total_items >= 1, 'Must populate review items for matching active grants');

        const items = await reviewService.getReviewItems(campaign.review_id);
        const item = items.find(i => i.grant_id === fixture.grantId);
        assert.ok(item, 'Candidate grant must exist in campaign review items');
        assert.strictEqual(item.decision, 'PENDING');
    });

    it('2. Enforces Separation of Duties: Contractor is strictly blocked from reviewing own access', async () => {
        const fixture = await createActiveGrant();

        const campaign = await reviewService.createReviewCampaign({
            reviewName: `SoD Test Campaign ${Date.now()}`,
            dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
            scope: { resourceId: testResourceId }
        }, securityUser);
        cleanupReviewIds.push(campaign.review_id);

        const items = await reviewService.getReviewItems(campaign.review_id);
        const targetItem = items.find(i => i.grant_id === fixture.grantId);
        assert.ok(targetItem);

        // Contractor attempts to submit a decision on their own access
        await assert.rejects(
            () => reviewService.submitReviewDecision(targetItem.review_item_id, {
                decision: 'MAINTAIN',
                decisionNotes: 'I need to keep this access'
            }, contractorUser),
            (err) => err instanceof ForbiddenError && err.code === 'ERR_SELF_REVIEW_FORBIDDEN'
        );
    });

    it('3. Compliance Auditor is strictly read-only and blocked from submitting decisions', async () => {
        const fixture = await createActiveGrant();

        const campaign = await reviewService.createReviewCampaign({
            reviewName: `Auditor Guardrail Campaign ${Date.now()}`,
            dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
            scope: { resourceId: testResourceId }
        }, securityUser);
        cleanupReviewIds.push(campaign.review_id);

        const items = await reviewService.getReviewItems(campaign.review_id);
        const targetItem = items.find(i => i.grant_id === fixture.grantId);
        assert.ok(targetItem);

        await assert.rejects(
            () => reviewService.submitReviewDecision(targetItem.review_item_id, {
                decision: 'MAINTAIN',
                decisionNotes: 'Auditor recertifying'
            }, auditorUser),
            (err) => err instanceof ForbiddenError && err.code === 'ERR_AUDITOR_READ_ONLY'
        );
    });

    it('4. Authorized reviewer decides MAINTAIN: Decision recorded with notes; grant remains ACTIVE', async () => {
        const fixture = await createActiveGrant();

        const campaign = await reviewService.createReviewCampaign({
            reviewName: `Maintain Test Campaign ${Date.now()}`,
            dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
            scope: { resourceId: testResourceId }
        }, securityUser);
        cleanupReviewIds.push(campaign.review_id);

        const items = await reviewService.getReviewItems(campaign.review_id);
        const targetItem = items.find(i => i.grant_id === fixture.grantId);
        assert.ok(targetItem);

        const res = await reviewService.submitReviewDecision(targetItem.review_item_id, {
            decision: 'MAINTAIN',
            decisionNotes: 'Contractor ongoing engagement verified for Q4 sprint deliverables'
        }, securityUser);

        assert.strictEqual(res.item.decision, 'MAINTAIN');
        assert.strictEqual(res.item.decision_notes, 'Contractor ongoing engagement verified for Q4 sprint deliverables');

        // Grant must remain ACTIVE in database
        const grantCheck = await pool.request()
            .input('grantId', fixture.grantId)
            .query(`SELECT status FROM dbo.access_grants WHERE grant_id = @grantId;`);
        assert.strictEqual(grantCheck.recordset[0].status, 'ACTIVE');
    });

    it('5. Authorized reviewer decides REVOKE: Enqueues revocation job and transitions grant to REVOKE_PENDING', async () => {
        const fixture = await createActiveGrant();

        const campaign = await reviewService.createReviewCampaign({
            reviewName: `Revoke Test Campaign ${Date.now()}`,
            dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
            scope: { resourceId: testResourceId }
        }, securityUser);
        cleanupReviewIds.push(campaign.review_id);

        const items = await reviewService.getReviewItems(campaign.review_id);
        const targetItem = items.find(i => i.grant_id === fixture.grantId);
        assert.ok(targetItem);

        const res = await reviewService.submitReviewDecision(targetItem.review_item_id, {
            decision: 'REVOKE',
            decisionNotes: 'Access entitlement no longer required for current work scope'
        }, securityUser);

        assert.strictEqual(res.item.decision, 'REVOKE');
        assert.ok(res.revocationJob);
        assert.strictEqual(res.revocationJob.grant_id, fixture.grantId);
        assert.strictEqual(res.revocationJob.trigger_source, 'REVIEW_REJECTION');
        cleanupJobIds.push(res.revocationJob.job_id);

        // Grant transitions into revocation pipeline (REVOKE_PENDING or MANUAL_REVIEW_REQUIRED) - NEVER prematurely marked REVOKED
        const grantCheck = await pool.request()
            .input('grantId', fixture.grantId)
            .query(`SELECT status FROM dbo.access_grants WHERE grant_id = @grantId;`);
        assert.ok(['REVOKE_PENDING', 'MANUAL_REVIEW_REQUIRED'].includes(grantCheck.recordset[0].status),
            `Grant must enter revocation pipeline without being marked REVOKED prematurely, got: ${grantCheck.recordset[0].status}`);
        assert.notStrictEqual(grantCheck.recordset[0].status, 'REVOKED', 'Grant must never be marked REVOKED before provider deprovisioning');
    });

    it('6. Automatically completes campaign when all items are decided', async () => {
        const fixture = await createActiveGrant();

        // Create campaign scoped to this single grant's engagement
        const campaign = await reviewService.createReviewCampaign({
            reviewName: `Auto Complete Campaign ${Date.now()}`,
            dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
            scope: { contractorEngagementId: fixture.engagementId }
        }, securityUser);
        cleanupReviewIds.push(campaign.review_id);

        const items = await reviewService.getReviewItems(campaign.review_id);
        assert.strictEqual(items.length, 1, 'Scoped campaign must have exactly 1 item');

        // Decide the item
        const res = await reviewService.submitReviewDecision(items[0].review_item_id, {
            decision: 'MAINTAIN',
            decisionNotes: 'Completed single-item review'
        }, securityUser);

        assert.strictEqual(res.remainingPending, 0);
        assert.strictEqual(res.campaignStatus, 'COMPLETED');

        // Verify status in database
        const campaignCheck = await reviewRepository.findAccessReviewById(campaign.review_id);
        assert.strictEqual(campaignCheck.status, 'COMPLETED');
    });

    it('7. Resource Owner scope: Cannot review grants for resources they do not own', async () => {
        const fixture = await createActiveGrant();

        const campaign = await reviewService.createReviewCampaign({
            reviewName: `RO Scope Test ${Date.now()}`,
            dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
            scope: { contractorEngagementId: fixture.engagementId }
        }, securityUser);
        cleanupReviewIds.push(campaign.review_id);

        const items = await reviewService.getReviewItems(campaign.review_id);
        assert.strictEqual(items.length, 1);

        // Simulated resource owner who does NOT own this resource
        const unownedResourceOwner = {
            user_id: '11111111-2222-3333-4444-555555555555',
            roles: ['RESOURCE_OWNER'],
            display_name: 'Unowned Resource Owner'
        };

        await assert.rejects(
            () => reviewService.submitReviewDecision(items[0].review_item_id, {
                decision: 'MAINTAIN',
                decisionNotes: 'Attempting to maintain unowned resource'
            }, unownedResourceOwner),
            (err) => err instanceof ForbiddenError && err.code === 'ERR_FORBIDDEN_RESOURCE_OWNER'
        );
    });

    it('8. Internal Sponsor scope: Cannot review grants for contractors they do not sponsor', async () => {
        const fixture = await createActiveGrant();

        const campaign = await reviewService.createReviewCampaign({
            reviewName: `Sponsor Scope Test ${Date.now()}`,
            dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
            scope: { contractorEngagementId: fixture.engagementId }
        }, securityUser);
        cleanupReviewIds.push(campaign.review_id);

        const items = await reviewService.getReviewItems(campaign.review_id);
        assert.strictEqual(items.length, 1);

        // Different internal sponsor who is NOT the sponsor for this contractor engagement
        const otherSponsor = {
            user_id: '99999999-8888-7777-6666-555555555555',
            roles: ['INTERNAL_SPONSOR'],
            display_name: 'Other Unrelated Sponsor'
        };

        await assert.rejects(
            () => reviewService.submitReviewDecision(items[0].review_item_id, {
                decision: 'MAINTAIN',
                decisionNotes: 'Attempting to maintain unsponsored contractor'
            }, otherSponsor),
            (err) => err instanceof ForbiddenError && err.code === 'ERR_FORBIDDEN_SPONSOR_SCOPE'
        );
    });

    it('9. MAINTAIN rejected when grant has already expired (revalidation at decision time)', async () => {
        const fixture = await createActiveGrant();

        // Expire the grant in database (ensuring granted_at < expires_at for CK_access_grants_dates)
        await pool.request()
            .input('grantId', fixture.grantId)
            .query(`
                UPDATE dbo.access_grants
                SET granted_at = DATEADD(DAY, -10, SYSDATETIMEOFFSET()),
                    expires_at = DATEADD(DAY, -1, SYSDATETIMEOFFSET())
                WHERE grant_id = @grantId;
            `);

        const campaign = await reviewService.createReviewCampaign({
            reviewName: `Expired Grant Revalidation ${Date.now()}`,
            dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
            scope: { contractorEngagementId: fixture.engagementId }
        }, securityUser);
        cleanupReviewIds.push(campaign.review_id);

        const items = await reviewService.getReviewItems(campaign.review_id);
        assert.strictEqual(items.length, 1);

        // Attempting to MAINTAIN must throw ConflictError with ERR_MAINTAIN_EXPIRED_ACCESS_FORBIDDEN
        await assert.rejects(
            () => reviewService.submitReviewDecision(items[0].review_item_id, {
                decision: 'MAINTAIN',
                decisionNotes: 'Attempting to maintain expired grant'
            }, securityUser),
            (err) => err instanceof ConflictError && err.code === 'ERR_MAINTAIN_EXPIRED_ACCESS_FORBIDDEN'
        );

        // Verify database state is untouched (decision remains PENDING)
        const itemInDb = await reviewRepository.findReviewItemById(items[0].review_item_id);
        assert.strictEqual(itemInDb.decision, 'PENDING');
    });

    it('10. MAINTAIN rejected when contractor engagement has ended or terminated', async () => {
        const fixture = await createActiveGrant();

        const campaign = await reviewService.createReviewCampaign({
            reviewName: `Ended Engagement Revalidation ${Date.now()}`,
            dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
            scope: { contractorEngagementId: fixture.engagementId }
        }, securityUser);
        cleanupReviewIds.push(campaign.review_id);

        const items = await reviewService.getReviewItems(campaign.review_id);
        assert.strictEqual(items.length, 1);

        // Terminate engagement in database
        await pool.request()
            .input('engagementId', fixture.engagementId)
            .query(`UPDATE dbo.contractor_engagements SET status = 'TERMINATED' WHERE engagement_id = @engagementId;`);

        // Attempting to MAINTAIN must throw ConflictError with ERR_MAINTAIN_ENDED_ENGAGEMENT_FORBIDDEN
        await assert.rejects(
            () => reviewService.submitReviewDecision(items[0].review_item_id, {
                decision: 'MAINTAIN',
                decisionNotes: 'Attempting to maintain terminated engagement grant'
            }, securityUser),
            (err) => err instanceof ConflictError && err.code === 'ERR_MAINTAIN_ENDED_ENGAGEMENT_FORBIDDEN'
        );

        // Verify database state is untouched
        const itemInDb = await reviewRepository.findReviewItemById(items[0].review_item_id);
        assert.strictEqual(itemInDb.decision, 'PENDING');
    });

    it('11. getReviewItems enforces server-side scope filtering for Resource Owners and Sponsors', async () => {
        const fixture = await createActiveGrant();

        const campaign = await reviewService.createReviewCampaign({
            reviewName: `Scope Retrieval Test ${Date.now()}`,
            dueDate: new Date(Date.now() + 14 * 86400000).toISOString(),
            scope: { contractorEngagementId: fixture.engagementId }
        }, securityUser);
        cleanupReviewIds.push(campaign.review_id);

        // Privileged user (Security Officer) sees the item
        const adminItems = await reviewService.getReviewItems(campaign.review_id, securityUser);
        assert.strictEqual(adminItems.length, 1);

        // Unrelated Resource Owner sees 0 items (does not own testResourceId)
        const unrelatedOwner = {
            user_id: '11111111-2222-3333-4444-555555555555',
            roles: ['RESOURCE_OWNER']
        };
        const roItems = await reviewService.getReviewItems(campaign.review_id, unrelatedOwner);
        assert.strictEqual(roItems.length, 0, 'Resource Owner must not see items for unowned resources');

        // Legitimate Resource Owner sees the item
        const legitRoItems = await reviewService.getReviewItems(campaign.review_id, resourceOwnerUser);
        assert.ok(legitRoItems.length >= 1, 'Legitimate Resource Owner must see items for owned resources');

        // Unrelated Sponsor sees 0 items (does not sponsor fixture's contractor)
        const unrelatedSponsor = {
            user_id: '99999999-8888-7777-6666-555555555555',
            roles: ['INTERNAL_SPONSOR']
        };
        const sponsorItems = await reviewService.getReviewItems(campaign.review_id, unrelatedSponsor);
        assert.strictEqual(sponsorItems.length, 0, 'Sponsor must not see items for unsponsored contractors');
    });
});
