/**
 * AccessLease — Access Request & Multi-Stage Approval Integration Tests
 * Validates real database workflow: catalog queries, request creation, SoD, out-of-order rejection,
 * sequential approval progression across 3 stages, audit events, and request cancellation.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const {
    listCatalogResources,
    listResourceEntitlements,
    createRequest,
    listRequests,
    getRequestById,
    cancelRequest,
    listPendingApprovals,
    submitApprovalDecision
} = require('../../src/functions/requests');
const tokenUtils = require('../../src/utils/tokenUtils');
const { getPool, closePool } = require('../../src/config/database');

describe('Integration: Multi-Stage Access Request & Approval Workflow', () => {
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

    const mockContext = { invocationId: 'test-workflow-inv', log: () => {} };

    let kubeResourceId = null;
    let clusterAdminEntitlementId = null;
    let wikiResourceId = null;
    let wikiContributorEntitlementId = null;
    let created3StageRequest = null;
    let step1 = null;
    let step2 = null;
    let step3 = null;

    test('1. GET /api/catalog/resources: contractor can list active resources', async () => {
        const token = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const req = createMockRequest('GET', '/api/catalog/resources', {
            headers: { authorization: `Bearer ${token}` }
        });

        const res = await listCatalogResources(req, mockContext);
        assert.strictEqual(res.status, 200);
        assert.ok(Array.isArray(res.jsonBody.data));
        assert.ok(res.jsonBody.data.length >= 2);

        const kube = res.jsonBody.data.find(r => r.resource_code === 'RES-PROD-KUBE');
        const wiki = res.jsonBody.data.find(r => r.resource_code === 'RES-CORP-WIKI');

        assert.ok(kube, 'RES-PROD-KUBE must exist in catalogue');
        assert.ok(wiki, 'RES-CORP-WIKI must exist in catalogue');

        kubeResourceId = kube.resource_id;
        wikiResourceId = wiki.resource_id;
    });

    test('2. GET /api/catalog/resources/:id/entitlements: returns entitlements for resource', async () => {
        const token = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const req = createMockRequest('GET', `/api/catalog/resources/${kubeResourceId}/entitlements`, {
            headers: { authorization: `Bearer ${token}` },
            params: { id: kubeResourceId }
        });

        const res = await listResourceEntitlements(req, mockContext);
        assert.strictEqual(res.status, 200);
        assert.ok(Array.isArray(res.jsonBody.data));

        const admin = res.jsonBody.data.find(e => e.entitlement_code === 'CLUSTER_ADMIN');
        assert.ok(admin, 'CLUSTER_ADMIN entitlement must exist');
        clusterAdminEntitlementId = admin.entitlement_id;

        // Also fetch wiki contributor
        const wikiReq = createMockRequest('GET', `/api/catalog/resources/${wikiResourceId}/entitlements`, {
            headers: { authorization: `Bearer ${token}` },
            params: { id: wikiResourceId }
        });
        const wikiRes = await listResourceEntitlements(wikiReq, mockContext);
        assert.strictEqual(wikiRes.status, 200);
        const contrib = wikiRes.jsonBody.data.find(e => e.entitlement_code === 'WIKI_CONTRIBUTOR');
        assert.ok(contrib, 'WIKI_CONTRIBUTOR entitlement must exist');
        wikiContributorEntitlementId = contrib.entitlement_id;
    });

    test('3. POST /api/requests: contractor submits high-risk access request routing to 3 stages', async () => {
        const token = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const req = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${token}` },
            body: {
                resourceId: kubeResourceId,
                entitlementId: clusterAdminEntitlementId,
                requestedStartDate: new Date().toISOString().split('T')[0],
                requestedEndDate: new Date(Date.now() + 20 * 86400000).toISOString().split('T')[0],
                businessJustification: 'Infrastructure upgrade and emergency container patch deployment.'
            }
        });

        const res = await createRequest(req, mockContext);
        assert.strictEqual(res.status, 201);
        assert.ok(res.jsonBody.data);
        assert.strictEqual(res.jsonBody.data.status, 'PENDING_APPROVAL');
        assert.strictEqual(res.jsonBody.data.requires_security_approval, true);

        const steps = res.jsonBody.data.approval_steps;
        assert.strictEqual(steps.length, 3, 'Must have exactly 3 approval stages');
        assert.strictEqual(steps[0].step_type, 'SPONSOR_APPROVAL');
        assert.strictEqual(steps[0].step_number, 1);
        assert.strictEqual(steps[1].step_type, 'RESOURCE_OWNER_APPROVAL');
        assert.strictEqual(steps[1].step_number, 2);
        assert.strictEqual(steps[2].step_type, 'SECURITY_APPROVAL');
        assert.strictEqual(steps[2].step_number, 3);

        created3StageRequest = res.jsonBody.data;
        step1 = steps[0];
        step2 = steps[1];
        step3 = steps[2];
    });

    test('4. Separation of Duties: Contractor cannot approve their own Step 1', async () => {
        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const req = createMockRequest('POST', `/api/approvals/${step1.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${contractorToken}` },
            params: { stepId: step1.approval_step_id },
            body: {
                decision: 'APPROVE',
                comments: 'Self approving access request.'
            }
        });

        const res = await submitApprovalDecision(req, mockContext);
        assert.strictEqual(res.status, 403);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_SELF_APPROVAL_FORBIDDEN');
    });

    test('5. Sequential Order Enforcement: Resource Owner cannot approve Step 2 before Step 1', async () => {
        const ownerToken = generateMockToken('TEST-OID-OWNER', 'owner@example.com');
        const req = createMockRequest('POST', `/api/approvals/${step2.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${ownerToken}` },
            params: { stepId: step2.approval_step_id },
            body: {
                decision: 'APPROVE',
                comments: 'Pre-approving before sponsor.'
            }
        });

        const res = await submitApprovalDecision(req, mockContext);
        assert.strictEqual(res.status, 400);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_OUT_OF_ORDER_APPROVAL');
    });

    test('6. Unauthorized Approver Rejection: Security Officer cannot approve Sponsor step', async () => {
        const secToken = generateMockToken('TEST-OID-SECURITY', 'security@example.com');
        const req = createMockRequest('POST', `/api/approvals/${step1.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${secToken}` },
            params: { stepId: step1.approval_step_id },
            body: {
                decision: 'APPROVE',
                comments: 'Security officer stepping in for sponsor.'
            }
        });

        const res = await submitApprovalDecision(req, mockContext);
        assert.strictEqual(res.status, 403);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_UNAUTHORIZED_APPROVER');
    });

    test('7. Stage 1 Approval: Sponsor approves Step 1', async () => {
        const sponsorToken = generateMockToken('TEST-OID-SPONSOR', 'sponsor@example.com');
        const req = createMockRequest('POST', `/api/approvals/${step1.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${sponsorToken}` },
            params: { stepId: step1.approval_step_id },
            body: {
                decision: 'APPROVE',
                comments: 'Verified business scope for container patching maintenance window.'
            }
        });

        const res = await submitApprovalDecision(req, mockContext);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.data.step.status, 'APPROVED');
        assert.strictEqual(res.jsonBody.data.request_status, 'PENDING_APPROVAL');
    });

    test('8. Stage 2 Approval: Resource Owner approves Step 2', async () => {
        const ownerToken = generateMockToken('TEST-OID-OWNER', 'owner@example.com');
        const req = createMockRequest('POST', `/api/approvals/${step2.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${ownerToken}` },
            params: { stepId: step2.approval_step_id },
            body: {
                decision: 'APPROVE',
                comments: 'Cluster access granted for node maintenance under least-privilege boundary.'
            }
        });

        const res = await submitApprovalDecision(req, mockContext);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.data.step.status, 'APPROVED');
        assert.strictEqual(res.jsonBody.data.request_status, 'PENDING_APPROVAL');
    });

    test('9. Stage 3 Approval: Security Officer approves Step 3 -> Request transitions to APPROVED', async () => {
        const secToken = generateMockToken('TEST-OID-SECURITY', 'security@example.com');
        const req = createMockRequest('POST', `/api/approvals/${step3.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${secToken}` },
            params: { stepId: step3.approval_step_id },
            body: {
                decision: 'APPROVE',
                comments: 'Security review completed. Zero open CVEs for target version; access endorsed.'
            }
        });

        const res = await submitApprovalDecision(req, mockContext);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.data.step.status, 'APPROVED');
        assert.strictEqual(res.jsonBody.data.request_status, 'APPROVED');

        // Verify request details reflects final APPROVED state and all 3 steps approved
        const detailReq = createMockRequest('GET', `/api/requests/${created3StageRequest.request_id}`, {
            headers: { authorization: `Bearer ${secToken}` },
            params: { id: created3StageRequest.request_id }
        });
        const detailRes = await getRequestById(detailReq, mockContext);
        assert.strictEqual(detailRes.status, 200);
        assert.strictEqual(detailRes.jsonBody.data.status, 'APPROVED');
        assert.strictEqual(detailRes.jsonBody.data.approval_steps.every(s => s.status === 'APPROVED'), true);
    });

    test('10. Audit Events: Verifies complete audit trail in dbo.audit_events', async () => {
        const pool = await getPool();
        const auditResult = await pool.request()
            .input('entityId', created3StageRequest.request_id)
            .query(`
                SELECT event_action, actor_user_id, created_at, event_payload
                FROM dbo.audit_events
                WHERE entity_id = @entityId
                ORDER BY created_at ASC;
            `);

        const actions = auditResult.recordset.map(r => r.event_action);
        assert.ok(actions.includes('REQUEST_CREATED'), 'Must log REQUEST_CREATED');
        assert.ok(actions.includes('SOD_VIOLATION_BLOCKED'), 'Must log SOD_VIOLATION_BLOCKED');
        assert.ok(actions.includes('STEP_APPROVED'), 'Must log STEP_APPROVED');
        assert.ok(actions.includes('REQUEST_APPROVED'), 'Must log REQUEST_APPROVED');
    });

    test('11. Request Cancellation: Requester can cancel pending request and skip remaining steps', async () => {
        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        
        // 1. Create a request for wiki
        const todayStr = new Date().toISOString().split('T')[0];
        const futureDateStr = new Date(Date.now() + 20 * 86400000).toISOString().split('T')[0];
        const createReq = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${contractorToken}` },
            body: {
                resourceId: wikiResourceId,
                entitlementId: wikiContributorEntitlementId,
                requestedStartDate: todayStr,
                requestedEndDate: futureDateStr,
                businessJustification: 'Documentation update task scheduled for November.'
            }
        });
        const createRes = await createRequest(createReq, mockContext);
        assert.strictEqual(createRes.status, 201);
        const cancelReqId = createRes.jsonBody.data.request_id;

        // 2. Requester cancels it
        const cancelReq = createMockRequest('POST', `/api/requests/${cancelReqId}/cancel`, {
            headers: { authorization: `Bearer ${contractorToken}` },
            params: { id: cancelReqId },
            body: { reason: 'Scope changed, documentation update no longer required.' }
        });
        const cancelRes = await cancelRequest(cancelReq, mockContext);
        assert.strictEqual(cancelRes.status, 200);
        assert.strictEqual(cancelRes.jsonBody.data.status, 'CANCELLED');

        // 3. Verify step resolution rejected on cancelled request
        const sponsorToken = generateMockToken('TEST-OID-SPONSOR', 'sponsor@example.com');
        const firstStep = createRes.jsonBody.data.approval_steps[0];
        const stepReq = createMockRequest('POST', `/api/approvals/${firstStep.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${sponsorToken}` },
            params: { stepId: firstStep.approval_step_id },
            body: { decision: 'APPROVE', comments: 'Attempting to approve cancelled request' }
        });
        const stepRes = await submitApprovalDecision(stepReq, mockContext);
        assert.strictEqual(stepRes.status, 400);
        assert.strictEqual(stepRes.jsonBody.error.code, 'ERR_REQUEST_NOT_PENDING');
    });
});
