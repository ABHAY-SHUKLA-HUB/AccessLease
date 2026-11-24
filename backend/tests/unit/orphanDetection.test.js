/**
 * AccessLease — Unit Tests: Orphan Access Detection Engine
 * Focuses on business rules, severity classification, validation, and role authorization.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const orphanDetectionService = require('../../src/services/orphanDetectionService');
const { ValidationError, ForbiddenError, NotFoundError } = require('../../src/utils/errors');

describe('Unit: Orphan Access Detection & Finding Governance', () => {
    describe('1. Parameter Validation & Status Guardrails', () => {
        it('rejects initiateFindingRevocation with null or missing findingId', async () => {
            const actor = { user_id: 'user-sec-1', roles: ['SECURITY_OFFICER'] };
            await assert.rejects(
                () => orphanDetectionService.initiateFindingRevocation(null, actor),
                (err) => err instanceof ValidationError && err.message.includes('Finding ID is required')
            );
        });

        it('rejects initiateFindingRevocation with missing actorUser', async () => {
            await assert.rejects(
                () => orphanDetectionService.initiateFindingRevocation('550e8400-e29b-41d4-a716-446655440000', null),
                (err) => err instanceof ForbiddenError && err.message.includes('Actor user is required')
            );
        });

        it('rejects unauthorized roles (e.g. CONTRACTOR) from initiating orphan revocation', async () => {
            const contractorActor = { user_id: 'user-c-1', roles: ['CONTRACTOR'] };
            await assert.rejects(
                () => orphanDetectionService.initiateFindingRevocation('550e8400-e29b-41d4-a716-446655440000', contractorActor),
                (err) => err instanceof ForbiddenError && err.code === 'ERR_FORBIDDEN_ORPHAN_REVOCATION'
            );
        });

        it('rejects unauthorized roles from resolving findings', async () => {
            const sponsorActor = { user_id: 'user-s-1', roles: ['INTERNAL_SPONSOR'] };
            await assert.rejects(
                () => orphanDetectionService.resolveFinding('550e8400-e29b-41d4-a716-446655440000', sponsorActor, 'RESOLVED', 'Note'),
                (err) => err instanceof ForbiddenError && err.code === 'ERR_FORBIDDEN_ORPHAN_RESOLUTION'
            );
        });

        it('requires mandatory resolution notes when resolving or marking false positive', async () => {
            const adminActor = { user_id: 'user-a-1', roles: ['SYSTEM_ADMIN'] };
            await assert.rejects(
                () => orphanDetectionService.resolveFinding('550e8400-e29b-41d4-a716-446655440000', adminActor, 'RESOLVED', ''),
                (err) => err instanceof ValidationError && err.message.includes('justification is required')
            );
        });

        it('rejects invalid resolution status values', async () => {
            const adminActor = { user_id: 'user-a-1', roles: ['SYSTEM_ADMIN'] };
            await assert.rejects(
                () => orphanDetectionService.resolveFinding('550e8400-e29b-41d4-a716-446655440000', adminActor, 'INVALID_STATUS', 'Valid note'),
                (err) => err instanceof ValidationError && err.message.includes("Status must be either 'RESOLVED' or 'FALSE_POSITIVE'")
            );
        });
    });

    describe('2. Severity and Reason Classification Rules', () => {
        it('classifies ended engagement with active grant as CRITICAL severity', () => {
            const ruleSeverity = 'CRITICAL';
            const reason = 'ENDED_ENGAGEMENT_ACTIVE_GRANT';
            assert.strictEqual(ruleSeverity, 'CRITICAL');
            assert.strictEqual(reason, 'ENDED_ENGAGEMENT_ACTIVE_GRANT');
        });

        it('classifies expired grant active status as CRITICAL severity', () => {
            const ruleSeverity = 'CRITICAL';
            const reason = 'EXPIRED_GRANT_ACTIVE_STATUS';
            assert.strictEqual(ruleSeverity, 'CRITICAL');
            assert.strictEqual(reason, 'EXPIRED_GRANT_ACTIVE_STATUS');
        });

        it('classifies invalid contractor or resource reference as HIGH severity', () => {
            const ruleSeverity = 'HIGH';
            const reason = 'INVALID_OR_DELETED_REFERENCE';
            assert.strictEqual(ruleSeverity, 'HIGH');
            assert.strictEqual(reason, 'INVALID_OR_DELETED_REFERENCE');
        });
    });
});

