/**
 * AccessLease — Prompt 05.1: Approval Workflow Security & Integrity Audit Tests
 * Real LocalDB integration tests verifying:
 * 1. Separation of Duties (Self-approval, Dual-stage signoff, Admin bypass prevention)
 * 2. Authorization & Data Isolation (IDOR, role scoping, read-only auditor)
 * 3. Concurrency & Idempotency (Duplicate submissions, terminal state rejections)
 * 4. Policy & Date Boundaries (Date-only semantics, lease caps, engagement bounds)
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
const requestWorkflowService = require('../../src/services/requestWorkflowService');
const tokenUtils = require('../../src/utils/tokenUtils');
const { getPool, closePool } = require('../../src/config/database');
const { getValidTestDates } = require('../helpers/testDateUtils');

describe('Security Audit: Approval Workflow Integrity & Access Isolation (PROMPT 05.1)', () => {
    let rsaKeyPair;
    let originalTenantId;
    let originalSpaClientId;
    let originalApiClientId;
    let originalApiAudience;
    const createdRequestIds = [];

    const TEST_TENANT_ID = 'test-audit-tenant';
    const TEST_SPA_CLIENT_ID = 'test-spa-client-audit';
    const TEST_API_CLIENT_ID = 'test-api-client-audit';
    const TEST_AUDIENCE = `api://${TEST_API_CLIENT_ID}`;
    const TEST_ISSUER = `https://login.microsoftonline.com/${TEST_TENANT_ID}/v2.0`;

    let contractorUserId;
    let sponsorUserId;
    let ownerUserId;
    let securityUserId;
    let auditorUserId;
    let adminUserId;

    let kubeResourceId;
    let wikiResourceId;
    let clusterAuditEnt1;
    let clusterAuditEnt2;
    let wikiAuditEnt1;
    let wikiAuditEnt2;

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

        // Resolve seeded identities from database
        const pool = await getPool();
        const users = await pool.request().query(`
            SELECT user_id, entra_object_id, email FROM dbo.users
            WHERE entra_object_id IN ('TEST-OID-CONTRACTOR', 'TEST-OID-SPONSOR', 'TEST-OID-OWNER', 'TEST-OID-SECURITY');
        `);

        for (const u of users.recordset) {
            if (u.entra_object_id === 'TEST-OID-CONTRACTOR') contractorUserId = u.user_id;
            if (u.entra_object_id === 'TEST-OID-SPONSOR') sponsorUserId = u.user_id;
            if (u.entra_object_id === 'TEST-OID-OWNER') ownerUserId = u.user_id;
            if (u.entra_object_id === 'TEST-OID-SECURITY') securityUserId = u.user_id;
        }

        // Ensure an Auditor identity exists
        let auditor = await pool.request().query(`SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-AUDITOR'`);
        if (auditor.recordset.length === 0) {
            await pool.request().query(`
                INSERT INTO dbo.users (entra_object_id, email, first_name, last_name, display_name, user_type, department, is_active)
                VALUES ('TEST-OID-AUDITOR', 'auditor@example.com', 'Alice', 'Auditor', 'Alice Compliance Auditor', 'INTERNAL_EMPLOYEE', 'Internal Audit', 1);
                DECLARE @auditUserId UNIQUEIDENTIFIER = (SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-AUDITOR');
                DECLARE @auditRoleId INT = (SELECT role_id FROM dbo.roles WHERE role_code = 'COMPLIANCE_AUDITOR');
                INSERT INTO dbo.user_roles (user_id, role_id) VALUES (@auditUserId, @auditRoleId);
            `);
            auditor = await pool.request().query(`SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-AUDITOR'`);
        }
        auditorUserId = auditor.recordset[0].user_id;

        // Ensure an Admin identity exists
        let admin = await pool.request().query(`SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-ADMIN'`);
        if (admin.recordset.length === 0) {
            await pool.request().query(`
                INSERT INTO dbo.users (entra_object_id, email, first_name, last_name, display_name, user_type, department, is_active)
                VALUES ('TEST-OID-ADMIN', 'admin@example.com', 'Adam', 'Admin', 'Adam System Admin', 'INTERNAL_EMPLOYEE', 'IT Security Operations', 1);
                DECLARE @admUserId UNIQUEIDENTIFIER = (SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-ADMIN');
                DECLARE @admRoleId INT = (SELECT role_id FROM dbo.roles WHERE role_code = 'SYSTEM_ADMIN');
                INSERT INTO dbo.user_roles (user_id, role_id) VALUES (@admUserId, @admRoleId);
            `);
            admin = await pool.request().query(`SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-ADMIN'`);
        }
        adminUserId = admin.recordset[0].user_id;

        // Resolve resources
        const resQuery = await pool.request().query(`SELECT resource_id, resource_code FROM dbo.resources WHERE resource_code IN ('RES-PROD-KUBE', 'RES-CORP-WIKI')`);
        for (const r of resQuery.recordset) {
            if (r.resource_code === 'RES-PROD-KUBE') kubeResourceId = r.resource_id;
            if (r.resource_code === 'RES-CORP-WIKI') wikiResourceId = r.resource_id;
        }

        // Ensure distinct audit test entitlements exist on target resources
        await pool.request().query(`
            IF NOT EXISTS (SELECT 1 FROM dbo.entitlements WHERE entitlement_code = 'CLUSTER_AUDIT_TEST_1')
            BEGIN
                INSERT INTO dbo.entitlements (resource_id, entitlement_code, entitlement_name, description, sensitivity_level, is_active)
                VALUES ('${kubeResourceId}', 'CLUSTER_AUDIT_TEST_1', 'Cluster Audit Test 1', 'Dedicated audit test entitlement 1', 'CRITICAL', 1);
            END;

            IF NOT EXISTS (SELECT 1 FROM dbo.entitlements WHERE entitlement_code = 'CLUSTER_AUDIT_TEST_2')
            BEGIN
                INSERT INTO dbo.entitlements (resource_id, entitlement_code, entitlement_name, description, sensitivity_level, is_active)
                VALUES ('${kubeResourceId}', 'CLUSTER_AUDIT_TEST_2', 'Cluster Audit Test 2', 'Dedicated audit test entitlement 2', 'CRITICAL', 1);
            END;

            IF NOT EXISTS (SELECT 1 FROM dbo.entitlements WHERE entitlement_code = 'WIKI_AUDIT_TEST_1')
            BEGIN
                INSERT INTO dbo.entitlements (resource_id, entitlement_code, entitlement_name, description, sensitivity_level, is_active)
                VALUES ('${wikiResourceId}', 'WIKI_AUDIT_TEST_1', 'Wiki Audit Test 1', 'Dedicated audit test entitlement 1', 'LOW', 1);
            END;

            IF NOT EXISTS (SELECT 1 FROM dbo.entitlements WHERE entitlement_code = 'WIKI_AUDIT_TEST_2')
            BEGIN
                INSERT INTO dbo.entitlements (resource_id, entitlement_code, entitlement_name, description, sensitivity_level, is_active)
                VALUES ('${wikiResourceId}', 'WIKI_AUDIT_TEST_2', 'Wiki Audit Test 2', 'Dedicated audit test entitlement 2', 'LOW', 1);
            END;
        `);

        const auditEntQuery = await pool.request().query(`
            SELECT entitlement_id, entitlement_code FROM dbo.entitlements WHERE entitlement_code IN (
                'CLUSTER_AUDIT_TEST_1', 'CLUSTER_AUDIT_TEST_2', 'WIKI_AUDIT_TEST_1', 'WIKI_AUDIT_TEST_2'
            )
        `);
        for (const e of auditEntQuery.recordset) {
            if (e.entitlement_code === 'CLUSTER_AUDIT_TEST_1') clusterAuditEnt1 = e.entitlement_id;
            if (e.entitlement_code === 'CLUSTER_AUDIT_TEST_2') clusterAuditEnt2 = e.entitlement_id;
            if (e.entitlement_code === 'WIKI_AUDIT_TEST_1') wikiAuditEnt1 = e.entitlement_id;
            if (e.entitlement_code === 'WIKI_AUDIT_TEST_2') wikiAuditEnt2 = e.entitlement_id;
        }

        // Clean any stale pending requests for audit entitlements in test database
        await pool.request().query(`
            UPDATE dbo.access_requests SET status = 'CANCELLED'
            WHERE status = 'PENDING_APPROVAL' AND entitlement_id IN ('${clusterAuditEnt1}', '${clusterAuditEnt2}', '${wikiAuditEnt1}', '${wikiAuditEnt2}');
        `);
    });

    after(async () => {
        tokenUtils.setCustomKeyResolver(null);
        process.env.ENTRA_TENANT_ID = originalTenantId;
        process.env.ENTRA_SPA_CLIENT_ID = originalSpaClientId;
        process.env.ENTRA_API_CLIENT_ID = originalApiClientId;
        process.env.ENTRA_API_AUDIENCE = originalApiAudience;

        if (createdRequestIds.length > 0) {
            try {
                const pool = await getPool();
                for (const reqId of createdRequestIds) {
                    await pool.request().query(`
                        DELETE FROM dbo.approval_steps WHERE request_id = '${reqId}';
                        DELETE FROM dbo.access_requests WHERE request_id = '${reqId}';
                    `);
                }
            } catch (_) {}
        }
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

    const mockContext = { invocationId: 'test-audit-inv', log: () => {} };

    // -------------------------------------------------------------------------
    // 1. Separation of Duties: Dual-Stage Approval & Privilege Escalation
    // -------------------------------------------------------------------------
    test('1. SoD: Dual-Stage Approval Violation is blocked when same user attempts Step 2', async () => {
        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const sponsorToken = generateMockToken('TEST-OID-SPONSOR', 'sponsor@example.com');

        // Create a 3-stage request
        const { startDate, endDate } = getValidTestDates(1, 14);
        const createReq = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${contractorToken}` },
            body: {
                resourceId: kubeResourceId,
                entitlementId: clusterAuditEnt1,
                requestedStartDate: startDate,
                requestedEndDate: endDate,
                businessJustification: 'Security audit test: verifying dual-stage signoff blocking.'
            }
        });
        const createRes = await createRequest(createReq, mockContext);
        assert.strictEqual(createRes.status, 201);
        if (createRes.jsonBody?.data?.request_id) createdRequestIds.push(createRes.jsonBody.data.request_id);
        const reqData = createRes.jsonBody.data;
        const step1 = reqData.approval_steps[0];
        const step2 = reqData.approval_steps[1];

        // Sponsor approves Step 1
        const step1Req = createMockRequest('POST', `/api/approvals/${step1.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${sponsorToken}` },
            params: { stepId: step1.approval_step_id },
            body: { decision: 'APPROVE', comments: 'Sponsor endorsement for step 1.' }
        });
        const step1Res = await submitApprovalDecision(step1Req, mockContext);
        assert.strictEqual(step1Res.status, 200);

        // Now Sponsor attempts to also approve Step 2 (Resource Owner step)
        const step2Req = createMockRequest('POST', `/api/approvals/${step2.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${sponsorToken}` },
            params: { stepId: step2.approval_step_id },
            body: { decision: 'APPROVE', comments: 'Attempting to satisfy second stage with same approver.' }
        });
        const step2Res = await submitApprovalDecision(step2Req, mockContext);
        assert.strictEqual(step2Res.status, 403);
        assert.strictEqual(step2Res.jsonBody.error.code, 'ERR_DUAL_APPROVAL_FORBIDDEN');
    });

    test('2. SoD: System Admin cannot approve Step 3 without SECURITY_OFFICER role', async () => {
        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const sponsorToken = generateMockToken('TEST-OID-SPONSOR', 'sponsor@example.com');
        const ownerToken = generateMockToken('TEST-OID-OWNER', 'owner@example.com');
        const adminToken = generateMockToken('TEST-OID-ADMIN', 'admin@example.com');

        // Create new high-risk request on dedicated audit entitlement 2
        const { startDate, endDate } = getValidTestDates(1, 14);
        const createReq = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${contractorToken}` },
            body: {
                resourceId: kubeResourceId,
                entitlementId: clusterAuditEnt2,
                requestedStartDate: startDate,
                requestedEndDate: endDate,
                businessJustification: 'Security audit test: admin security bypass block.'
            }
        });
        const createRes = await createRequest(createReq, mockContext);
        assert.strictEqual(createRes.status, 201);
        if (createRes.jsonBody?.data?.request_id) createdRequestIds.push(createRes.jsonBody.data.request_id);
        const reqData = createRes.jsonBody.data;
        const step1 = reqData.approval_steps[0];
        const step2 = reqData.approval_steps[1];
        const step3 = reqData.approval_steps[2];

        // Sponsor approves Step 1
        await submitApprovalDecision(createMockRequest('POST', `/api/approvals/${step1.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${sponsorToken}` },
            params: { stepId: step1.approval_step_id },
            body: { decision: 'APPROVE', comments: 'Step 1 sponsor approved.' }
        }), mockContext);

        // Owner approves Step 2
        await submitApprovalDecision(createMockRequest('POST', `/api/approvals/${step2.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${ownerToken}` },
            params: { stepId: step2.approval_step_id },
            body: { decision: 'APPROVE', comments: 'Step 2 owner approved.' }
        }), mockContext);

        // System Admin (without SECURITY_OFFICER role) attempts to approve Step 3
        const step3Req = createMockRequest('POST', `/api/approvals/${step3.approval_step_id}/decision`, {
            headers: { authorization: `Bearer ${adminToken}` },
            params: { stepId: step3.approval_step_id },
            body: { decision: 'APPROVE', comments: 'Admin attempting security officer signoff override.' }
        });
        const step3Res = await submitApprovalDecision(step3Req, mockContext);
        assert.strictEqual(step3Res.status, 403);
        assert.strictEqual(step3Res.jsonBody.error.code, 'ERR_FORBIDDEN_ROLE');
    });

    test('3. SoD: Compliance Auditor is strictly read-only and cannot approve steps', async () => {
        const auditorToken = generateMockToken('TEST-OID-AUDITOR', 'auditor@example.com');
        const req = createMockRequest('POST', `/api/approvals/00000000-0000-0000-0000-000000000000/decision`, {
            headers: { authorization: `Bearer ${auditorToken}` },
            params: { stepId: '00000000-0000-0000-0000-000000000000' },
            body: { decision: 'APPROVE', comments: 'Auditor attempting decision.' }
        });

        const res = await submitApprovalDecision(req, mockContext);
        assert.strictEqual(res.status, 403);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_AUDITOR_READ_ONLY');
    });

    // -------------------------------------------------------------------------
    // 2. Authorization & Data Isolation (IDOR Checks)
    // -------------------------------------------------------------------------
    test('4. IDOR: Unrelated Sponsor cannot inspect requests outside their scope', async () => {
        // Create an unrelated sponsor identity
        const pool = await getPool();
        let otherSponsor = await pool.request().query(`SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-OTHER-SPONSOR'`);
        if (otherSponsor.recordset.length === 0) {
            await pool.request().query(`
                INSERT INTO dbo.users (entra_object_id, email, first_name, last_name, display_name, user_type, department, is_active)
                VALUES ('TEST-OID-OTHER-SPONSOR', 'othersponsor@example.com', 'Oscar', 'Other', 'Oscar Other Sponsor', 'INTERNAL_EMPLOYEE', 'Finance Platform', 1);
                DECLARE @otherSpId UNIQUEIDENTIFIER = (SELECT user_id FROM dbo.users WHERE entra_object_id = 'TEST-OID-OTHER-SPONSOR');
                DECLARE @spRoleId INT = (SELECT role_id FROM dbo.roles WHERE role_code = 'INTERNAL_SPONSOR');
                INSERT INTO dbo.user_roles (user_id, role_id) VALUES (@otherSpId, @spRoleId);
            `);
        }

        const otherSponsorToken = generateMockToken('TEST-OID-OTHER-SPONSOR', 'othersponsor@example.com');

        // Fetch any existing request created by contractor
        const reqResult = await pool.request().query(`
            SELECT TOP 1 request_id FROM dbo.access_requests WHERE requested_by_user_id = '${contractorUserId}';
        `);
        const targetReqId = reqResult.recordset[0].request_id;

        const inspectReq = createMockRequest('GET', `/api/requests/${targetReqId}`, {
            headers: { authorization: `Bearer ${otherSponsorToken}` },
            params: { id: targetReqId }
        });

        const inspectRes = await getRequestById(inspectReq, mockContext);
        assert.strictEqual(inspectRes.status, 403);
        assert.strictEqual(inspectRes.jsonBody.error.code, 'ERR_FORBIDDEN_REQUEST_ACCESS');
    });

    test('5. Data Isolation: listRequests scopes results strictly to user role and ownership', async () => {
        const otherSponsorToken = generateMockToken('TEST-OID-OTHER-SPONSOR', 'othersponsor@example.com');
        const listReq = createMockRequest('GET', '/api/requests', {
            headers: { authorization: `Bearer ${otherSponsorToken}` }
        });

        const listRes = await listRequests(listReq, mockContext);
        assert.strictEqual(listRes.status, 200);
        // Oscar Other Sponsor does not sponsor contractor and owns no resources -> must see 0 requests
        assert.strictEqual(listRes.jsonBody.data.length, 0);

        // System Admin should see all requests
        const adminToken = generateMockToken('TEST-OID-ADMIN', 'admin@example.com');
        const adminReq = createMockRequest('GET', '/api/requests', {
            headers: { authorization: `Bearer ${adminToken}` }
        });
        const adminRes = await listRequests(adminReq, mockContext);
        assert.strictEqual(adminRes.status, 200);
        assert.ok(adminRes.jsonBody.data.length > 0);
    });

    // -------------------------------------------------------------------------
    // 3. Concurrency & Idempotency
    // -------------------------------------------------------------------------
    test('6. Concurrency: Duplicate request for active entitlement rejected with 409', async () => {
        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');

        // Create first active request
        const { startDate, endDate } = getValidTestDates(1, 14);
        const firstReq = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${contractorToken}` },
            body: {
                resourceId: wikiResourceId,
                entitlementId: wikiAuditEnt1,
                requestedStartDate: startDate,
                requestedEndDate: endDate,
                businessJustification: 'Active entitlement documentation task.'
            }
        });
        const firstRes = await createRequest(firstReq, mockContext);
        assert.strictEqual(firstRes.status, 201);
        if (firstRes.jsonBody?.data?.request_id) createdRequestIds.push(firstRes.jsonBody.data.request_id);

        // Immediate duplicate request submission for same active entitlement
        const dupReq = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${contractorToken}` },
            body: {
                resourceId: wikiResourceId,
                entitlementId: wikiAuditEnt1,
                requestedStartDate: startDate,
                requestedEndDate: endDate,
                businessJustification: 'Simultaneous duplicate request attempt.'
            }
        });
        const dupRes = await createRequest(dupReq, mockContext);
        assert.strictEqual(dupRes.status, 409);
        assert.strictEqual(dupRes.jsonBody.error.code, 'ERR_DUPLICATE_ACTIVE_REQUEST');
    });

    test('7. Lifecycle: Cannot decide step on a cancelled request', async () => {
        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');
        const sponsorToken = generateMockToken('TEST-OID-SPONSOR', 'sponsor@example.com');

        // Create a request with wikiAuditEnt2
        const { startDate, endDate } = getValidTestDates(1, 14);
        const createReq = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${contractorToken}` },
            body: {
                resourceId: wikiResourceId,
                entitlementId: wikiAuditEnt2,
                requestedStartDate: startDate,
                requestedEndDate: endDate,
                businessJustification: 'Lifecycle test request to cancel.'
            }
        });
        const createRes = await createRequest(createReq, mockContext);
        assert.strictEqual(createRes.status, 201);
        const reqData = createRes.jsonBody.data;
        const cancelReqId = reqData.request_id;
        createdRequestIds.push(cancelReqId);
        const stepId = reqData.approval_steps[0].approval_step_id;

        // Cancel
        const cancelReq = createMockRequest('POST', `/api/requests/${cancelReqId}/cancel`, {
            headers: { authorization: `Bearer ${contractorToken}` },
            params: { id: cancelReqId },
            body: { reason: 'No longer needed' }
        });
        const cancelRes = await cancelRequest(cancelReq, mockContext);
        assert.strictEqual(cancelRes.status, 200);

        // Attempt decision on cancelled step
        const decReq = createMockRequest('POST', `/api/approvals/${stepId}/decision`, {
            headers: { authorization: `Bearer ${sponsorToken}` },
            params: { stepId },
            body: { decision: 'APPROVE', comments: 'Attempting decision on cancelled request' }
        });
        const decRes = await submitApprovalDecision(decReq, mockContext);
        assert.strictEqual(decRes.status, 400);
        assert.strictEqual(decRes.jsonBody.error.code, 'ERR_REQUEST_NOT_PENDING');
    });

    test('8. Date-Only Semantics: End date identical to start date is rejected', async () => {
        const contractorToken = generateMockToken('TEST-OID-CONTRACTOR', 'contractor@example.com');

        const { startDate } = getValidTestDates(1, 14);
        const sameDateReq = createMockRequest('POST', '/api/requests', {
            headers: { authorization: `Bearer ${contractorToken}` },
            body: {
                resourceId: wikiResourceId,
                entitlementId: wikiAuditEnt2,
                requestedStartDate: startDate,
                requestedEndDate: startDate, // Same day
                businessJustification: 'Attempting zero duration same day access.'
            }
        });
        const res = await createRequest(sameDateReq, mockContext);
        assert.strictEqual(res.status, 400);
        assert.ok(res.jsonBody.error.message.includes('strictly after the requested start date') || res.jsonBody.error.details.some(d => d.includes('strictly after')));
    });
});
