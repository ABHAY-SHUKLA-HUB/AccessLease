/**
 * AccessLease — Unit Tests: Access Review & Recertification Service
 * Focuses on SoD checks, auditor write-protections, campaign date validation, and decision guardrails.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const reviewService = require('../../src/services/reviewService');
const { ValidationError, ForbiddenError } = require('../../src/utils/errors');

describe('Unit: Access Review & Recertification Governance', () => {
    describe('1. Campaign Creation Validation & Permissions', () => {
        it('rejects campaign creation when actor is Compliance Auditor (Strictly Read-Only)', async () => {
            const auditor = { user_id: 'user-aud-1', roles: ['COMPLIANCE_AUDITOR'] };
            const payload = { reviewName: 'Q4 Audit', dueDate: '2026-12-31' };

            await assert.rejects(
                () => reviewService.createReviewCampaign(payload, auditor),
                (err) => err instanceof ForbiddenError && err.code === 'ERR_AUDITOR_READ_ONLY'
            );
        });

        it('rejects campaign creation when actor has non-governance role (e.g. CONTRACTOR)', async () => {
            const contractor = { user_id: 'user-c-1', roles: ['CONTRACTOR'] };
            const payload = { reviewName: 'Self Review', dueDate: '2026-12-31' };

            await assert.rejects(
                () => reviewService.createReviewCampaign(payload, contractor),
                (err) => err instanceof ForbiddenError && err.code === 'ERR_FORBIDDEN_REVIEW_CREATE'
            );
        });

        it('rejects campaign creation when reviewName is missing or whitespace', async () => {
            const admin = { user_id: 'user-adm-1', roles: ['SYSTEM_ADMIN'] };
            const payload = { reviewName: '   ', dueDate: '2026-12-31' };

            await assert.rejects(
                () => reviewService.createReviewCampaign(payload, admin),
                (err) => err instanceof ValidationError && err.message.includes('Review campaign name is required')
            );
        });

        it('rejects campaign creation when dueDate is before startDate', async () => {
            const admin = { user_id: 'user-adm-1', roles: ['SYSTEM_ADMIN'] };
            const payload = {
                reviewName: 'Backwards Review',
                startDate: '2026-12-31T00:00:00Z',
                dueDate: '2026-12-01T00:00:00Z'
            };

            await assert.rejects(
                () => reviewService.createReviewCampaign(payload, admin),
                (err) => err instanceof ValidationError && err.message.includes('Due date must be strictly after the start date')
            );
        });
    });

    describe('2. Review Decision Validation & Separation of Duties (SoD)', () => {
        it('rejects decision submission when actor is Compliance Auditor (Read-Only Guardrail)', async () => {
            const auditor = { user_id: 'user-aud-1', roles: ['COMPLIANCE_AUDITOR'] };
            const payload = { decision: 'MAINTAIN', decisionNotes: 'Looks good' };

            await assert.rejects(
                () => reviewService.submitReviewDecision('item-1', payload, auditor),
                (err) => err instanceof ForbiddenError && err.code === 'ERR_AUDITOR_READ_ONLY'
            );
        });

        it('rejects invalid decision codes (anything other than MAINTAIN or REVOKE)', async () => {
            const reviewer = { user_id: 'user-rev-1', roles: ['RESOURCE_OWNER'] };
            const payload = { decision: 'APPROVE', decisionNotes: 'Valid notes' };

            await assert.rejects(
                () => reviewService.submitReviewDecision('item-1', payload, reviewer),
                (err) => err instanceof ValidationError && err.code === 'ERR_INVALID_DECISION'
            );
        });

        it('rejects decisions submitted without mandatory business justification notes', async () => {
            const reviewer = { user_id: 'user-rev-1', roles: ['RESOURCE_OWNER'] };
            const payload = { decision: 'MAINTAIN', decisionNotes: '   ' };

            await assert.rejects(
                () => reviewService.submitReviewDecision('item-1', payload, reviewer),
                (err) => err instanceof ValidationError && err.code === 'ERR_DECISION_NOTES_REQUIRED'
            );
        });
    });
});

