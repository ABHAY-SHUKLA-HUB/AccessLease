/**
 * AccessLease — Access Request & Policy Engine Unit Tests
 * Tests policy evaluation, separation of duties, date boundaries, duration caps, and stage routing.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const policyEngine = require('../../src/services/policyEngine');
const requestWorkflowService = require('../../src/services/requestWorkflowService');
const {
    ValidationError,
    NotFoundError,
    ForbiddenError,
    ConflictError
} = require('../../src/utils/errors');

describe('Unit: Access Request Policy Engine & Workflow Rules', () => {
    const baseEngagement = {
        engagement_id: '11111111-1111-1111-1111-111111111111',
        contractor_user_id: '22222222-2222-2222-2222-222222222222',
        sponsor_user_id: '33333333-3333-3333-3333-333333333333',
        status: 'ACTIVE',
        start_date: new Date('2026-01-01T00:00:00Z'),
        end_date: new Date('2027-12-31T23:59:59Z')
    };

    const lowRiskResource = {
        resource_id: '44444444-4444-4444-4444-444444444444',
        resource_code: 'RES-CORP-WIKI',
        risk_level: 'LOW',
        requires_security_approval: false,
        max_lease_duration_days: 90,
        is_active: true
    };

    const highRiskResource = {
        resource_id: '55555555-5555-5555-5555-555555555555',
        resource_code: 'RES-PROD-KUBE',
        risk_level: 'CRITICAL',
        requires_security_approval: true,
        max_lease_duration_days: 30,
        is_active: true
    };

    const readEntitlement = {
        entitlement_id: '66666666-6666-6666-6666-666666666666',
        resource_id: '44444444-4444-4444-4444-444444444444',
        entitlement_code: 'WIKI_CONTRIBUTOR',
        sensitivity_level: 'LOW',
        is_active: true
    };

    const adminEntitlement = {
        entitlement_id: '77777777-7777-7777-7777-777777777777',
        resource_id: '55555555-5555-5555-5555-555555555555',
        entitlement_code: 'CLUSTER_ADMIN',
        sensitivity_level: 'CRITICAL',
        is_active: true
    };

    // -------------------------------------------------------------------------
    // 1. Policy Engine: Date & Duration Validation
    // -------------------------------------------------------------------------
    test('1. Validates standard low-risk access request within limits', () => {
        const result = policyEngine.evaluatePolicy({
            resource: lowRiskResource,
            entitlement: readEntitlement,
            engagement: baseEngagement,
            requestedStartDate: '2027-01-01',
            requestedEndDate: '2027-01-30',
            justification: 'Requires contributor access to update engineering system architecture guides.'
        });

        assert.strictEqual(result.isPermitted, true);
        assert.strictEqual(result.durationDays, 29);
        assert.strictEqual(result.requiresSecurityApproval, false);
        assert.strictEqual(result.evaluatedRiskLevel, 'LOW');
        assert.strictEqual(result.stages.length, 2);
    });

    test('2. Rejects request when end date is before start date', () => {
        assert.throws(
            () => {
                policyEngine.evaluatePolicy({
                    resource: lowRiskResource,
                    entitlement: readEntitlement,
                    engagement: baseEngagement,
                    requestedStartDate: '2027-02-15',
                    requestedEndDate: '2027-02-10',
                    justification: 'Valid length justification for testing invalid date inversion.'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.details.some(d => d.includes('strictly after the requested start date')));
                return true;
            }
        );
    });

    test('3. Rejects request when start date is in the past', () => {
        assert.throws(
            () => {
                policyEngine.evaluatePolicy({
                    resource: lowRiskResource,
                    entitlement: readEntitlement,
                    engagement: baseEngagement,
                    requestedStartDate: '2020-01-01',
                    requestedEndDate: '2020-01-15',
                    justification: 'Testing retroactive access request validation reject.'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.details.some(d => d.includes('cannot be in the past')));
                return true;
            }
        );
    });

    test('4. Rejects request exceeding max resource lease duration cap', () => {
        assert.throws(
            () => {
                policyEngine.evaluatePolicy({
                    resource: highRiskResource, // max 30 days
                    entitlement: adminEntitlement,
                    engagement: baseEngagement,
                    requestedStartDate: '2027-01-01',
                    requestedEndDate: '2027-02-15', // 46 days
                    justification: 'Need access across multiple months for production maintenance.'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.details.some(d => d.includes('exceeds maximum allowable lease')));
                return true;
            }
        );
    });

    test('5. Rejects request when access dates fall outside engagement period', () => {
        assert.throws(
            () => {
                policyEngine.evaluatePolicy({
                    resource: lowRiskResource,
                    entitlement: readEntitlement,
                    engagement: {
                        ...baseEngagement,
                        end_date: new Date('2027-03-31T23:59:59Z')
                    },
                    requestedStartDate: '2027-04-01',
                    requestedEndDate: '2027-04-20',
                    justification: 'Attempting access past engagement contract conclusion date.'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.details.some(d => d.includes('exceeds the contractor engagement end date')));
                return true;
            }
        );
    });

    test('6. Rejects insufficient business justification', () => {
        assert.throws(
            () => {
                policyEngine.evaluatePolicy({
                    resource: lowRiskResource,
                    entitlement: readEntitlement,
                    engagement: baseEngagement,
                    requestedStartDate: '2027-01-01',
                    requestedEndDate: '2027-01-10',
                    justification: 'too short'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.details.some(d => d.includes('at least 10 characters')));
                return true;
            }
        );
    });

    // -------------------------------------------------------------------------
    // 2. Risk Escalation & Security Approval Routing
    // -------------------------------------------------------------------------
    test('7. Critical risk resource triggers mandatory Security Officer approval', () => {
        const adminEntitlementForKube = {
            ...adminEntitlement,
            resource_id: highRiskResource.resource_id
        };

        const result = policyEngine.evaluatePolicy({
            resource: highRiskResource,
            entitlement: adminEntitlementForKube,
            engagement: baseEngagement,
            requestedStartDate: '2027-01-01',
            requestedEndDate: '2027-01-20',
            justification: 'Critical Kubernetes infrastructure monitoring maintenance.'
        });

        assert.strictEqual(result.requiresSecurityApproval, true);
        assert.strictEqual(result.evaluatedRiskLevel, 'CRITICAL');
        assert.ok(result.reasons.some(r => r.includes('requires Security Officer approval')));
        assert.strictEqual(result.stages.length, 3);
    });

    test('8. Critical sensitivity entitlement triggers mandatory Security Officer approval on low-risk resource', () => {
        const adminEntitlementForWiki = {
            ...adminEntitlement,
            resource_id: lowRiskResource.resource_id
        };

        const result = policyEngine.evaluatePolicy({
            resource: lowRiskResource,
            entitlement: adminEntitlementForWiki, // CRITICAL
            engagement: baseEngagement,
            requestedStartDate: '2027-01-01',
            requestedEndDate: '2027-01-20',
            justification: 'Elevated administrative privileges on documentation portal.'
        });

        assert.strictEqual(result.requiresSecurityApproval, true);
        assert.strictEqual(result.evaluatedRiskLevel, 'CRITICAL');
        assert.ok(result.reasons.some(r => r.includes('requires Security Officer approval')));
        assert.strictEqual(result.stages.length, 3);
    });

    test('9. Resource with explicit requires_security_approval flag triggers Security stage', () => {
        const flaggedResource = {
            ...lowRiskResource,
            risk_level: 'MEDIUM',
            requires_security_approval: true
        };

        const result = policyEngine.evaluatePolicy({
            resource: flaggedResource,
            entitlement: readEntitlement,
            engagement: baseEngagement,
            requestedStartDate: '2027-01-01',
            requestedEndDate: '2027-01-20',
            justification: 'Regular task on resource configured for security sign-off.'
        });

        assert.strictEqual(result.requiresSecurityApproval, true);
        assert.ok(result.reasons.some(r => r.includes('explicitly requires Security Officer approval')));
        assert.strictEqual(result.stages.length, 3);
    });

    // -------------------------------------------------------------------------
    // 3. Workflow Role Restrictions
    // -------------------------------------------------------------------------
    test('10. Non-contractor user cannot submit contractor access requests', async () => {
        const sponsorUser = {
            user_id: '33333333-3333-3333-3333-333333333333',
            user_type: 'INTERNAL_EMPLOYEE',
            is_active: true,
            roles: [{ role_code: 'INTERNAL_SPONSOR' }]
        };

        await assert.rejects(
            async () => {
                await requestWorkflowService.createAccessRequest(sponsorUser, {
                    resourceId: lowRiskResource.resource_id,
                    entitlementId: readEntitlement.entitlement_id
                });
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_FORBIDDEN_NOT_CONTRACTOR');
                return true;
            }
        );
    });

    test('11. Deactivated contractor cannot submit requests', async () => {
        const deactivatedContractor = {
            user_id: '22222222-2222-2222-2222-222222222222',
            user_type: 'CONTRACTOR',
            is_active: false,
            roles: [{ role_code: 'CONTRACTOR' }]
        };

        await assert.rejects(
            async () => {
                await requestWorkflowService.createAccessRequest(deactivatedContractor, {
                    resourceId: lowRiskResource.resource_id,
                    entitlementId: readEntitlement.entitlement_id
                });
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_USER_INACTIVE');
                return true;
            }
        );
    });

    test('12. Rejection decision requires a valid justification of at least 5 characters', async () => {
        const approverUser = {
            user_id: '33333333-3333-3333-3333-333333333333',
            user_type: 'INTERNAL_EMPLOYEE',
            is_active: true,
            roles: [{ role_code: 'INTERNAL_SPONSOR' }]
        };

        await assert.rejects(
            async () => {
                await requestWorkflowService.submitApprovalDecision(
                    approverUser,
                    'step-uuid-1234',
                    'REJECT',
                    'no' // too short
                );
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.message.includes('at least 5 characters'));
                return true;
            }
        );
    });

    test('13. Invalid decision value is rejected', async () => {
        const approverUser = {
            user_id: '33333333-3333-3333-3333-333333333333',
            user_type: 'INTERNAL_EMPLOYEE',
            is_active: true,
            roles: [{ role_code: 'INTERNAL_SPONSOR' }]
        };

        await assert.rejects(
            async () => {
                await requestWorkflowService.submitApprovalDecision(
                    approverUser,
                    'step-uuid-1234',
                    'MAYBE'
                );
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.message.includes("must be either 'APPROVE' or 'REJECT'"));
                return true;
            }
        );
    });
});
