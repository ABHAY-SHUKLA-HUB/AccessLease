/**
 * AccessLease — Unit Tests: Audit & Compliance Trail
 * Validates immutable audit event retrieval, search/filtering, stats aggregation, and role authorization.
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert');
const { closePool } = require('../../src/config/database');
const auditRepository = require('../../src/repositories/auditRepository');
const {
    listAuditEvents,
    getAuditEventById,
    getAuditStats
} = require('../../src/functions/audit');

describe('Unit: Audit & Compliance Trail Subsystem', () => {
    after(async () => {
        await closePool();
    });
    describe('1. Repository Layer', () => {
        it('exports listAuditEvents, getAuditCount, getAuditStats, getAuditEventById, createAuditEvent', () => {
            assert.strictEqual(typeof auditRepository.listAuditEvents, 'function');
            assert.strictEqual(typeof auditRepository.getAuditCount, 'function');
            assert.strictEqual(typeof auditRepository.getAuditStats, 'function');
            assert.strictEqual(typeof auditRepository.getAuditEventById, 'function');
            assert.strictEqual(typeof auditRepository.createAuditEvent, 'function');
        });
    });

    describe('2. HTTP Handler Authorization Guardrails', () => {
        it('rejects unauthenticated request with HTTP 401', async () => {
            const req = {
                headers: {},
                query: new Map(),
                params: {}
            };
            const res = await listAuditEvents(req, { invocationId: 'test-inv-1' });
            assert.strictEqual(res.status, 401);
            const body = res.jsonBody;
            assert.strictEqual(body.success, false);
            assert.strictEqual(body.error.code, 'ERR_MISSING_AUTH_HEADER');
        });

        it('rejects contractor user with HTTP 403 ERR_FORBIDDEN_ROLE', async () => {
            const req = {
                headers: { authorization: 'Bearer mock-token' },
                user: {
                    user_id: 'contractor-uuid-1',
                    display_name: 'Carlos Contractor',
                    roles: ['CONTRACTOR']
                },
                query: new Map(),
                params: {}
            };
            const res = await listAuditEvents(req, { invocationId: 'test-inv-2' });
            assert.strictEqual(res.status, 403);
            const body = res.jsonBody;
            assert.strictEqual(body.success, false);
            assert.strictEqual(body.error.code, 'ERR_FORBIDDEN_ROLE');
        });

        it('rejects contractor for audit stats with HTTP 403', async () => {
            const req = {
                headers: { authorization: 'Bearer mock-token' },
                user: {
                    user_id: 'contractor-uuid-1',
                    roles: ['CONTRACTOR']
                },
                query: new Map(),
                params: {}
            };
            const res = await getAuditStats(req, { invocationId: 'test-inv-3' });
            assert.strictEqual(res.status, 403);
            const body = res.jsonBody;
            assert.strictEqual(body.success, false);
            assert.strictEqual(body.error.code, 'ERR_FORBIDDEN_ROLE');
        });

        it('rejects contractor for single audit event with HTTP 403', async () => {
            const req = {
                headers: { authorization: 'Bearer mock-token' },
                user: {
                    user_id: 'contractor-uuid-1',
                    roles: ['CONTRACTOR']
                },
                query: new Map(),
                params: { id: '1' }
            };
            const res = await getAuditEventById(req, { invocationId: 'test-inv-4' });
            assert.strictEqual(res.status, 403);
            const body = res.jsonBody;
            assert.strictEqual(body.success, false);
            assert.strictEqual(body.error.code, 'ERR_FORBIDDEN_ROLE');
        });
    });

    describe('3. Single Event Retrieval Validation', () => {
        it('returns HTTP 404 if event does not exist', async () => {
            const req = {
                headers: { authorization: 'Bearer mock-token' },
                user: {
                    user_id: 'auditor-uuid-1',
                    roles: ['COMPLIANCE_AUDITOR']
                },
                query: new Map(),
                params: { id: '999999999' }
            };
            const res = await getAuditEventById(req, { invocationId: 'test-inv-5' });
            assert.strictEqual(res.status, 404);
            const body = res.jsonBody;
            assert.strictEqual(body.success, false);
            assert.strictEqual(body.error.code, 'ERR_NOT_FOUND');
        });
    });
});
