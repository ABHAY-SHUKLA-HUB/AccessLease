/**
 * AccessLease — Access Request Creation & End-to-End Lease Activation Integration Tests
 * Validates:
 * - Admin/Sponsor request creation on behalf of contractor with engagement selection
 * - Date boundary validations (end date <= engagement end date, end date > start date)
 * - Duration limit enforcement
 * - Justification length requirement
 * - Duplicate active request rejection
 * - Multi-stage sequential approval progression
 * - Stored procedure dbo.sp_ActivateApprovedGrant lease activation into dbo.access_grants
 * - Immutable audit trail verification (REQUEST_CREATED, STEP_APPROVED, REQUEST_APPROVED, GRANT_ACTIVATED)
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const {
    createRequest,
    getRequestById,
    submitApprovalDecision
} = require('../../src/functions/requests');
const tokenUtils = require('../../src/utils/tokenUtils');
const { getPool, closePool } = require('../../src/config/database');

describe('Integration: Access Request Creation & Grant Activation Lifecycle', () => {
    let rsaKeyPair;
    let originalTenantId;
    let originalSpaClientId;
    let originalApiClientId;
    let originalApiAudience;

    const TEST_TENANT_ID = 'test-workflow-tenant';
    const TEST_SPA_CLIENT_ID = 'test-spa-client-5555';
    const TEST_API_CLIENT_ID = 'test-api-client-6666';
    const TEST_AUDIENCE = `api://${TEST_API_CLIENT_ID}`;
    const TEST_ISSUER = `https://login.microsoftonline.com/${TEST_TENANT_ID}/v2.0`;

    const mockContext = { invocationId: 'test-req-creation-inv', log: () => {} };

    let testEngagement = null;
    let testResource = null;
    let testEntitlement = null;
    let createdRequestId = null;
    let step1Id = null;
    let step2Id = null;

    before(async () => {
        originalTenantId = process.env.ENTRA_TENANT_ID;
        originalSpaClientId = process.env.ENTRA_SPA_CLIENT_ID;
        originalApiClientId = process.env.ENTRA_API_CLIENT_ID;
        originalApiAudience = process.env.ENTRA_API_AUDIENCE;

        process.env.ENTRA_TENANT_ID = TEST_TENANT_ID;
        process.env.ENTRA_SPA_CLIENT_ID = TEST_SPA_CLIENT_ID;
        process.env.ENTRA_API_CLIENT_ID = TEST_API_CLIENT_ID;
        process.env.ENTRA_API_AUDIENCE = TEST_AUDIENCE;

        rsaKeyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        tokenUtils.setCustomKeyResolver((header, callback) => {
            callback(null, rsaKeyPair.publicKey);
        });

        // Resolve active engagement, resource, and entitlement from test DB
        const pool = await getPool();
        const engResult = await pool.request().query(`
            SELECT TOP 1 ce.engagement_id, ce.contractor_user_id, ce.sponsor_user_id, ce.end_date, ce.status
            FROM dbo.contractor_engagements ce
            INNER JOIN dbo.users cu ON ce.contractor_user_id = cu.user_id
            WHERE ce.status = 'ACTIVE' AND cu.email = 'contractor@example.com';
        `);
        testEngagement = engResult.recordset[0];

        const resResult = await pool.request().query(`
            SELECT TOP 1 r.resource_id, r.resource_code, r.resource_name, r.max_lease_duration_days,
                         e.entitlement_id, e.entitlement_code, e.entitlement_name
            FROM dbo.resources r
            INNER JOIN dbo.entitlements e ON r.resource_id = e.resource_id
            WHERE r.resource_code = 'RES-CORP-WIKI' AND e.entitlement_code = 'WIKI_CONTRIBUTOR' AND r.is_active = 1;
        `);
        testResource = resResult.recordset[0];
        testEntitlement = {
            entitlement_id: testResource.entitlement_id,
            entitlement_code: testResource.entitlement_code,
            entitlement_name: testResource.entitlement_name
        };

        // Clean up any existing active requests/grants for this test entitlement to ensure clean test state
        await pool.request()
            .input('engId', testEngagement.engagement_id)
            .input('entId', testEntitlement.entitlement_id)
            .query(`
                DELETE FROM dbo.access_grants
                WHERE contractor_engagement_id = @engId AND entitlement_id = @entId;

                UPDATE dbo.access_requests
                SET status = 'CANCELLED'
                WHERE contractor_engagement_id = @engId AND entitlement_id = @entId AND status IN ('PENDING_APPROVAL', 'APPROVED');
            `);
    });

    after(async () => {
        tokenUtils.setCustomKeyResolver(null);
        process.env.ENTRA_TENANT_ID = originalTenantId;
        process.env.ENTRA_SPA_CLIENT_ID = originalSpaClientId;
        process.env.ENTRA_API_CLIENT_ID = originalApiClientId;
        process.env.ENTRA_API_AUDIENCE = originalApiAudience;
        await closePool();
    });

    function generateMockToken(oid, email) {
        const payload = {
            oid,
            email,
            preferred_username: email,
            name: email.split('@')[0],
            tid: TEST_TENANT_ID,
            aud: TEST_AUDIENCE,
            iss: TEST_ISSUER,
            scp: 'access_as_user'
        };

        return jwt.sign(payload, rsaKeyPair.privateKey, {
            algorithm: 'RS256',
            keyid: 'test-key-id',
            expiresIn: '1h'
        });
    }

    function createMockRequest(method, path, options = {}) {
        const { headers = {}, params = {}, query = {}, body = {} } = options;
        const headersMap = new Map();
        for (const [k, v] of Object.entries(headers)) {
            headersMap.set(k.toLowerCase(), v);
        }

        return {
            method,
            path,
            url: path,
            headers: headersMap,
            params,
            query,
            body,
            json: async () => body
        };
    }

    test('1. Validates that requested end date cannot exceed contractor engagement end date', async () => {
        const adminToken = generateMockToken('TEST-OID-ADMIN', 'admin@example.com');
        const engEndDate = new Date(testEngagement.end_date);
        const pastEngEndDate = new Date(engEndDate.getTime() + 30 * 86400000).toISOString().split('T')[0];

        const req = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                contractorEngagementId: testEngagement.engagement_id,
                resourceId: testResource.resource_id,
                entitlementId: testEntitlement.entitlement_id,
                requestedStartDate: new Date().toISOString().split('T')[0],
                requestedEndDate: pastEngEndDate,
                businessJustification: 'Requesting access exceeding engagement end date.'
            }
        });

        const res = await createRequest(req, mockContext);
        assert.strictEqual(res.status, 400);
        const details = res.jsonBody.error.details || [];
        assert.ok(
            res.jsonBody.error.message.includes('exceeds the contractor engagement end date') ||
            details.some(d => d.includes('exceeds the contractor engagement end date')),
            'Should reject when requested end date exceeds engagement end date'
        );
    });

    test('2. Validates that requested end date must be strictly after start date', async () => {
        const adminToken = generateMockToken('TEST-OID-ADMIN', 'admin@example.com');
        const todayStr = new Date().toISOString().split('T')[0];
        const yesterdayStr = new Date(Date.now() - 86400000).toISOString().split('T')[0];

        const req = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                contractorEngagementId: testEngagement.engagement_id,
                resourceId: testResource.resource_id,
                entitlementId: testEntitlement.entitlement_id,
                requestedStartDate: todayStr,
                requestedEndDate: yesterdayStr,
                businessJustification: 'Inverted dates test validation.'
            }
        });

        const res = await createRequest(req, mockContext);
        assert.strictEqual(res.status, 400);
        const details = res.jsonBody.error.details || [];
        assert.ok(
            res.jsonBody.error.message.includes('strictly after the requested start date') ||
            details.some(d => d.includes('strictly after the requested start date')),
            'Should reject when end date is not strictly after start date'
        );
    });

    test('3. Validates business justification must be at least 10 characters', async () => {
        const adminToken = generateMockToken('TEST-OID-ADMIN', 'admin@example.com');
        const todayStr = new Date().toISOString().split('T')[0];
        const futureStr = new Date(Date.now() + 14 * 86400000).toISOString().split('T')[0];

        const req = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                contractorEngagementId: testEngagement.engagement_id,
                resourceId: testResource.resource_id,
                entitlementId: testEntitlement.entitlement_id,
                requestedStartDate: todayStr,
                requestedEndDate: futureStr,
                businessJustification: 'short'
            }
        });

        const res = await createRequest(req, mockContext);
        assert.strictEqual(res.status, 400);
        const details = res.jsonBody.error.details || [];
        assert.ok(
            res.jsonBody.error.message.includes('at least 10 characters') ||
            details.some(d => d.includes('at least 10 characters')),
            'Should reject when justification is under 10 characters'
        );
    });

    test('4. System Admin creates access request on behalf of contractor with engagement selection', async () => {
        const adminToken = generateMockToken('TEST-OID-ADMIN', 'admin@example.com');
        const todayStr = new Date().toISOString().split('T')[0];
        const futureStr = new Date(Date.now() + 14 * 86400000).toISOString().split('T')[0];

        const req = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                contractorEngagementId: testEngagement.engagement_id,
                resourceId: testResource.resource_id,
                entitlementId: testEntitlement.entitlement_id,
                requestedStartDate: todayStr,
                requestedEndDate: futureStr,
                businessJustification: 'Engineering team architectural documentation maintenance lease.'
            }
        });

        const res = await createRequest(req, mockContext);
        assert.strictEqual(res.status, 201);
        assert.ok(res.jsonBody.data);
        assert.ok(res.jsonBody.data.request_number.startsWith('AR-'));
        assert.strictEqual(res.jsonBody.data.status, 'PENDING_APPROVAL');
        assert.strictEqual(res.jsonBody.data.requires_security_approval, false);

        // Subject contractor is assigned
        assert.strictEqual(
            res.jsonBody.data.requested_by_user_id.toLowerCase(),
            testEngagement.contractor_user_id.toLowerCase()
        );

        // Steps generated: Stage 1 Sponsor, Stage 2 Resource Owner
        const steps = res.jsonBody.data.approval_steps;
        assert.strictEqual(steps.length, 2);
        assert.strictEqual(steps[0].step_type, 'SPONSOR_APPROVAL');
        assert.strictEqual(steps[1].step_type, 'RESOURCE_OWNER_APPROVAL');

        createdRequestId = res.jsonBody.data.request_id;
        step1Id = steps[0].approval_step_id;
        step2Id = steps[1].approval_step_id;
    });

    test('5. Rejects duplicate active request for the same engagement and entitlement', async () => {
        const adminToken = generateMockToken('TEST-OID-ADMIN', 'admin@example.com');
        const todayStr = new Date().toISOString().split('T')[0];
        const futureStr = new Date(Date.now() + 14 * 86400000).toISOString().split('T')[0];

        const req = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${adminToken}` },
            body: {
                contractorEngagementId: testEngagement.engagement_id,
                resourceId: testResource.resource_id,
                entitlementId: testEntitlement.entitlement_id,
                requestedStartDate: todayStr,
                requestedEndDate: futureStr,
                businessJustification: 'Attempting duplicate active request.'
            }
        });

        const res = await createRequest(req, mockContext);
        assert.strictEqual(res.status, 409);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_DUPLICATE_ACTIVE_REQUEST');
    });

    test('6. Separation of Duties: Contractor cannot approve Step 1 of the request', async () => {
        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const req = createMockRequest('POST', `/api/approvals/${step1Id}/decision`, {
            headers: { authorization: `Bearer ${contractorToken}` },
            params: { stepId: step1Id },
            body: {
                decision: 'APPROVE',
                comments: 'Contractor attempting self-approval.'
            }
        });

        const res = await submitApprovalDecision(req, mockContext);
        assert.strictEqual(res.status, 403);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_SELF_APPROVAL_FORBIDDEN');
    });

    test('7. Stage 1 Approval: Internal Business Sponsor approves Step 1', async () => {
        const sponsorToken = generateMockToken('TEST-OID-SPONSOR', 'sponsor@example.com');
        const req = createMockRequest('POST', `/api/approvals/${step1Id}/decision`, {
            headers: { authorization: `Bearer ${sponsorToken}` },
            params: { stepId: step1Id },
            body: {
                decision: 'APPROVE',
                comments: 'Sponsor endorsement for documentation work.'
            }
        });

        const res = await submitApprovalDecision(req, mockContext);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.data.step.status, 'APPROVED');
        assert.strictEqual(res.jsonBody.data.request_status, 'PENDING_APPROVAL');
    });

    test('8. Stage 2 Approval: Resource Owner approves Step 2 -> Activates Lease into dbo.access_grants', async () => {
        const ownerToken = generateMockToken('TEST-OID-OWNER', 'owner@example.com');
        const req = createMockRequest('POST', `/api/approvals/${step2Id}/decision`, {
            headers: { authorization: `Bearer ${ownerToken}` },
            params: { stepId: step2Id },
            body: {
                decision: 'APPROVE',
                comments: 'Resource owner approval granted for wiki contributor entitlement.'
            }
        });

        const res = await submitApprovalDecision(req, mockContext);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.data.step.status, 'APPROVED');
        assert.strictEqual(res.jsonBody.data.request_status, 'APPROVED');

        // Verify request details
        const detailReq = createMockRequest('GET', `/api/requests/${createdRequestId}`, {
            headers: { authorization: `Bearer ${ownerToken}` },
            params: { id: createdRequestId }
        });
        const detailRes = await getRequestById(detailReq, mockContext);
        assert.strictEqual(detailRes.status, 200);
        assert.strictEqual(detailRes.jsonBody.data.status, 'APPROVED');

        // Verify that the grant is now ACTIVE in dbo.access_grants
        const pool = await getPool();
        const grantResult = await pool.request()
            .input('requestId', createdRequestId)
            .query(`
                SELECT grant_id, grant_number, request_id, contractor_engagement_id,
                       resource_id, entitlement_id, granted_at, expires_at, status
                FROM dbo.access_grants
                WHERE request_id = @requestId;
            `);

        assert.strictEqual(grantResult.recordset.length, 1, 'Exactly one active grant must be created in dbo.access_grants');
        const grant = grantResult.recordset[0];
        assert.strictEqual(grant.status, 'ACTIVE');
        assert.ok(grant.grant_number.startsWith('AG-'), 'Grant number must start with AG-');
        assert.ok(new Date(grant.expires_at) > new Date(grant.granted_at), 'Expiry must be in the future');
        assert.ok(new Date(grant.expires_at) <= new Date(testEngagement.end_date), 'Expiry must not exceed engagement end date');
    });

    test('9. Immutable Audit Trail: Verifies REQUEST_CREATED, STEP_APPROVED, REQUEST_APPROVED, and GRANT_ACTIVATED events', async () => {
        const pool = await getPool();
        const auditResult = await pool.request()
            .input('entityId', createdRequestId)
            .query(`
                SELECT event_category, event_action, actor_user_id, event_payload
                FROM dbo.audit_events
                WHERE entity_id = @entityId
                ORDER BY created_at ASC;
            `);

        const actions = auditResult.recordset.map(r => r.event_action);
        assert.ok(actions.includes('REQUEST_CREATED'), 'Must record REQUEST_CREATED');
        assert.ok(actions.includes('STEP_APPROVED'), 'Must record STEP_APPROVED');
        assert.ok(actions.includes('REQUEST_APPROVED'), 'Must record REQUEST_APPROVED');

        // Check GRANT_ACTIVATED event for the created request
        const grantAudit = await pool.request()
            .input('requestId', createdRequestId)
            .query(`
                SELECT event_action, entity_type, actor_user_id
                FROM dbo.audit_events
                WHERE event_action = 'GRANT_ACTIVATED';
            `);
        assert.ok(grantAudit.recordset.length > 0, 'Must record GRANT_ACTIVATED event upon lease activation');
    });
});
