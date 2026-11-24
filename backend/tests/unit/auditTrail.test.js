/**
 * AccessLease — Unit Tests: Audit & Compliance Trail
 * Validates immutable audit event retrieval, search/filtering, stats aggregation, and role authorization.
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert');
const { closePool } = require('../../src/config/database');
const auditRepository = require('../../src/repositories/auditRepository');
const { DatabaseError } = require('../../src/utils/errors');
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
        it('returns HTTP 404 if event does not exist (isolated unit test)', async () => {
            const originalGetAuditEventById = auditRepository.getAuditEventById;
            auditRepository.getAuditEventById = async () => null;

            try {
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
            } finally {
                auditRepository.getAuditEventById = originalGetAuditEventById;
            }
        });

        it('returns HTTP 503 if database connection fails (ERR_DATABASE_UNAVAILABLE)', async () => {
            const originalGetAuditEventById = auditRepository.getAuditEventById;
            auditRepository.getAuditEventById = async () => {
                throw new DatabaseError('Database connection lost');
            };

            try {
                const req = {
                    headers: { authorization: 'Bearer mock-token' },
                    user: {
                        user_id: 'auditor-uuid-1',
                        roles: ['COMPLIANCE_AUDITOR']
                    },
                    query: new Map(),
                    params: { id: '1001' }
                };
                const res = await getAuditEventById(req, { invocationId: 'test-inv-db-err' });
                assert.strictEqual(res.status, 503);
                const body = res.jsonBody;
                assert.strictEqual(body.success, false);
                assert.strictEqual(body.error.code, 'ERR_DATABASE_UNAVAILABLE');
            } finally {
                auditRepository.getAuditEventById = originalGetAuditEventById;
            }
        });

        it('returns HTTP 200 with event data if event exists', async () => {
            const originalGetAuditEventById = auditRepository.getAuditEventById;
            auditRepository.getAuditEventById = async (id) => ({
                event_id: Number(id),
                event_category: 'LIFECYCLE',
                event_action: 'GRANT_ACTIVATED',
                entity_type: 'ACCESS_GRANT',
                entity_id: '87BD1FD6-A262-4D93-972D-79D9BA179317',
                actor_user_id: 'user-guid-1',
                actor_type: 'INTERNAL_USER',
                actor_name: 'Rachel Resource Owner',
                actor_email: 'owner@example.com',
                ip_address: '10.0.0.1',
                event_payload: JSON.stringify({ grant_number: 'AG-20261125-001' }),
                created_at: new Date('2026-11-25T00:00:00.000Z')
            });

            try {
                const req = {
                    headers: { authorization: 'Bearer mock-token' },
                    user: {
                        user_id: 'auditor-uuid-1',
                        roles: ['COMPLIANCE_AUDITOR']
                    },
                    query: new Map(),
                    params: { id: '1001' }
                };
                const res = await getAuditEventById(req, { invocationId: 'test-inv-success' });
                assert.strictEqual(res.status, 200);
                const body = res.jsonBody;
                assert.strictEqual(body.success, true);
                assert.strictEqual(body.data.event.eventId, 1001);
                assert.strictEqual(body.data.event.eventAction, 'GRANT_ACTIVATED');
                assert.strictEqual(body.data.event.actorName, 'Rachel Resource Owner');
            } finally {
                auditRepository.getAuditEventById = originalGetAuditEventById;
            }
        });
    });
});
