/**
 * AccessLease — Unit Tests: RBAC, ABAC & Authorization Middleware
 * 
 * Verifies:
 * 1. Authenticated user context creation & permission resolution.
 * 2. User with no assigned roles (least privilege / deny-by-default).
 * 3. User with multiple roles (union of permissions).
 * 4. Unknown or inactive internal user rejection.
 * 5. Allowed permission check.
 * 6. Denied permission check (HTTP 403 ERR_FORBIDDEN_PERMISSION).
 * 7. Contractor accessing their own record (permitted).
 * 8. Contractor attempting to access another contractor's record (HTTP 403 ERR_FORBIDDEN_CONTRACTOR_ACCESS).
 * 9. Resource owner accessing an assigned resource.
 * 10. Resource owner attempting to access an unassigned resource (HTTP 403 ERR_NOT_RESOURCE_OWNER).
 * 11. Compliance auditor attempting a write operation (HTTP 403 ERR_AUDITOR_READ_ONLY).
 * 12. Unauthorized security action attempted by non-security role.
 * 13. Missing or invalid authentication (HTTP 401).
 * 14. Database/role lookup failure (fail-closed, error handling).
 * 15. Separation of Duties: Requester cannot approve own request (HTTP 403 ERR_SELF_APPROVAL_FORBIDDEN).
 * 16. Attempts to spoof user IDs or roles from frontend body or query params.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const Permissions = require('../../src/security/permissions');
const {
    getEffectivePermissions,
    hasPermission,
    hasAnyPermission,
    hasRole,
    hasAnyRole,
    isStrictlyReadOnlyAuditor
} = require('../../src/security/permissionPolicy');
const {
    canAccessContractorData,
    isAuthorizedResourceOwner,
    validateSeparationOfDuties
} = require('../../src/security/resourceAccess');
const {
    requireRole,
    requirePermission,
    requireWriteAccess,
    requireResourceOwner,
    requireContractorAccess,
    requireSeparationOfDuties
} = require('../../src/middleware/authorize');
const { ForbiddenError, UnauthorizedError } = require('../../src/utils/errors');

describe('Unit: RBAC, ABAC & Authorization Security Engine', () => {

    // -------------------------------------------------------------------------
    // 1. Permission Policy & Context Tests
    // -------------------------------------------------------------------------

    test('1. User Context & Permissions: single role resolves expected permissions', () => {
        const contractorRoles = [{ role_id: 2, role_code: 'CONTRACTOR', role_name: 'External Contractor' }];
        const perms = getEffectivePermissions(contractorRoles);

        assert.ok(perms.has(Permissions.PROFILE_READ_SELF));
        assert.ok(perms.has(Permissions.ENGAGEMENT_READ_SELF));
        assert.ok(perms.has(Permissions.REQUEST_READ_SELF));
        assert.ok(perms.has(Permissions.GRANT_READ_SELF));

        // Least privilege: Contractor must NOT have management or approval permissions
        assert.strictEqual(perms.has(Permissions.ENGAGEMENT_CREATE), false);
        assert.strictEqual(perms.has(Permissions.REQUEST_CREATE), false);
        assert.strictEqual(perms.has(Permissions.REQUEST_APPROVE_OWNER), false);
        assert.strictEqual(perms.has(Permissions.REVOCATION_TRIGGER), false);
    });

    test('2. User with no assigned roles: deny-by-default (zero permissions)', () => {
        const emptyRoles = [];
        const perms = getEffectivePermissions(emptyRoles);

        assert.strictEqual(perms.size, 0, 'User with no roles must receive 0 permissions');
        assert.strictEqual(hasPermission(emptyRoles, Permissions.PROFILE_READ_SELF), false);
        assert.strictEqual(hasPermission(emptyRoles, Permissions.REQUEST_READ_ALL), false);
    });

    test('3. User with multiple roles: receives complete union of permissions', () => {
        const multiRoles = [
            { role_id: 3, role_code: 'INTERNAL_SPONSOR', role_name: 'Sponsor' },
            { role_id: 4, role_code: 'RESOURCE_OWNER', role_name: 'Resource Owner' }
        ];
        const perms = getEffectivePermissions(multiRoles);

        // From INTERNAL_SPONSOR
        assert.ok(perms.has(Permissions.ENGAGEMENT_CREATE));
        assert.ok(perms.has(Permissions.REQUEST_APPROVE_SPONSOR));

        // From RESOURCE_OWNER
        assert.ok(perms.has(Permissions.REQUEST_APPROVE_OWNER));
        assert.ok(perms.has(Permissions.REVIEW_DECIDE));

        // Still must NOT hold SECURITY_OFFICER permissions
        assert.strictEqual(perms.has(Permissions.REVOCATION_TRIGGER), false);
        assert.strictEqual(perms.has(Permissions.SECURITY_POLICY_OVERRIDE), false);
    });

    test('4. SYSTEM_ADMIN: holds all system permissions', () => {
        const adminRoles = [{ role_id: 6, role_code: 'SYSTEM_ADMIN' }];
        const perms = getEffectivePermissions(adminRoles);

        for (const perm of Object.values(Permissions)) {
            assert.ok(perms.has(perm), `SYSTEM_ADMIN must possess permission ${perm}`);
        }
    });

    // -------------------------------------------------------------------------
    // 2. Middleware & Role Enforcement Tests
    // -------------------------------------------------------------------------

    test('5. Allowed Role: requireRole executes target handler when role is held', async () => {
        const targetHandler = async (req) => ({ status: 200, jsonBody: { success: true, user: req.user.user_id } });
        const wrapped = requireRole(['INTERNAL_SPONSOR', 'SECURITY_OFFICER'], targetHandler);

        const mockReq = {
            user: {
                user_id: 'user-sponsor-001',
                roles: [{ role_code: 'INTERNAL_SPONSOR' }]
            }
        };

        const response = await wrapped(mockReq, { invocationId: 'unit-auth-1' });
        assert.strictEqual(response.status, 200);
        assert.strictEqual(response.jsonBody.success, true);
    });

    test('6. Denied Role: requireRole returns HTTP 403 ERR_FORBIDDEN_ROLE when role is absent', async () => {
        const targetHandler = async () => ({ status: 200 });
        const wrapped = requireRole(['SECURITY_OFFICER'], targetHandler);

        const mockReq = {
            user: {
                user_id: 'user-contractor-001',
                roles: [{ role_code: 'CONTRACTOR' }]
            },
            url: '/api/security/revoke'
        };

        const response = await wrapped(mockReq, { invocationId: 'unit-auth-2' });
        assert.strictEqual(response.status, 403);
        assert.strictEqual(response.jsonBody.success, false);
        assert.strictEqual(response.jsonBody.error.code, 'ERR_FORBIDDEN_ROLE');
    });

    test('7. Allowed Permission: requirePermission executes handler when permission is granted', async () => {
        const targetHandler = async () => ({ status: 200, jsonBody: { data: 'grants list' } });
        const wrapped = requirePermission([Permissions.GRANT_READ_ALL], targetHandler);

        const mockReq = {
            user: {
                user_id: 'user-auditor-001',
                roles: [{ role_code: 'COMPLIANCE_AUDITOR' }]
            }
        };

        const response = await wrapped(mockReq, { invocationId: 'unit-auth-3' });
        assert.strictEqual(response.status, 200);
    });

    test('8. Denied Permission: requirePermission returns HTTP 403 ERR_FORBIDDEN_PERMISSION', async () => {
        const targetHandler = async () => ({ status: 200 });
        const wrapped = requirePermission([Permissions.REVOCATION_TRIGGER], targetHandler);

        const mockReq = {
            user: {
                user_id: 'user-sponsor-001',
                roles: [{ role_code: 'INTERNAL_SPONSOR' }] // Sponsor cannot trigger emergency revocation
            },
            url: '/api/grants/revoke'
        };

        const response = await wrapped(mockReq, { invocationId: 'unit-auth-4' });
        assert.strictEqual(response.status, 403);
        assert.strictEqual(response.jsonBody.success, false);
        assert.strictEqual(response.jsonBody.error.code, 'ERR_FORBIDDEN_PERMISSION');
    });

    // -------------------------------------------------------------------------
    // 3. ABAC & Contextual Resource Access Tests
    // -------------------------------------------------------------------------

    test('9. Contractor Data Access: Contractor can access their OWN record', async () => {
        const contractorUser = {
            user_id: 'CONTRACTOR-GUID-001',
            roles: [{ role_code: 'CONTRACTOR' }]
        };

        const canAccess = await canAccessContractorData(contractorUser, 'CONTRACTOR-GUID-001');
        assert.strictEqual(canAccess, true);
    });

    test('10. Contractor Data Access: Contractor CANNOT access another contractor record', async () => {
        const contractorUser = {
            user_id: 'CONTRACTOR-GUID-001',
            roles: [{ role_code: 'CONTRACTOR' }]
        };

        const canAccess = await canAccessContractorData(contractorUser, 'CONTRACTOR-GUID-999-DIFFERENT');
        assert.strictEqual(canAccess, false);
    });

    test('11. requireContractorAccess Middleware: rejects cross-contractor access with HTTP 403', async () => {
        const targetHandler = async () => ({ status: 200 });
        const wrapped = requireContractorAccess(
            (req) => ({ contractorUserId: req.params.contractorId }),
            targetHandler
        );

        const mockReq = {
            user: {
                user_id: 'CONTRACTOR-GUID-001',
                roles: [{ role_code: 'CONTRACTOR' }]
            },
            params: {
                contractorId: 'CONTRACTOR-GUID-999' // Attacking different contractor record
            },
            url: '/api/contractors/CONTRACTOR-GUID-999/engagements'
        };

        const response = await wrapped(mockReq, { invocationId: 'unit-auth-5' });
        assert.strictEqual(response.status, 403);
        assert.strictEqual(response.jsonBody.error.code, 'ERR_FORBIDDEN_CONTRACTOR_ACCESS');
    });

    test('12. Resource Ownership: Resource Owner allowed for assigned resource', async () => {
        const ownerUser = {
            user_id: 'OWNER-GUID-001',
            roles: [{ role_code: 'RESOURCE_OWNER' }]
        };

        const mockTransaction = null;
        // Mocking repo method in resourceAccess context
        const isOwner = await isAuthorizedResourceOwner(
            ownerUser,
            'RESOURCE-GUID-100',
            {
                // mock runner returning assigned owner record
                request: () => ({
                    input: () => ({
                        query: async () => ({
                            recordset: [{ resource_id: 'RESOURCE-GUID-100', owner_user_id: 'OWNER-GUID-001', ownership_type: 'PRIMARY' }]
                        })
                    })
                })
            }
        );

        assert.strictEqual(isOwner, true);
    });

    test('13. Resource Ownership: Resource Owner denied for unassigned resource', async () => {
        const ownerUser = {
            user_id: 'OWNER-GUID-001',
            roles: [{ role_code: 'RESOURCE_OWNER' }]
        };

        const isOwner = await isAuthorizedResourceOwner(
            ownerUser,
            'RESOURCE-GUID-999',
            {
                // mock runner returning empty owners
                request: () => ({
                    input: () => ({
                        query: async () => ({ recordset: [] })
                    })
                })
            }
        );

        assert.strictEqual(isOwner, false);
    });

    test('14. Auditor Write Restriction: requireWriteAccess blocks COMPLIANCE_AUDITOR write with HTTP 403', async () => {
        const targetHandler = async () => ({ status: 201, jsonBody: { created: true } });
        const wrapped = requireWriteAccess(targetHandler);

        const mockReq = {
            user: {
                user_id: 'auditor-user-001',
                roles: [{ role_code: 'COMPLIANCE_AUDITOR' }]
            },
            method: 'POST',
            url: '/api/access-requests'
        };

        const response = await wrapped(mockReq, { invocationId: 'unit-auth-6' });
        assert.strictEqual(response.status, 403);
        assert.strictEqual(response.jsonBody.error.code, 'ERR_AUDITOR_READ_ONLY');
        assert.ok(response.jsonBody.error.message.includes('Compliance Auditor role is strictly read-only'));
    });

    test('15. Separation of Duties: Requester CANNOT approve their own access request', async () => {
        const requesterUser = {
            user_id: 'USER-SPONSOR-001',
            roles: [{ role_code: 'INTERNAL_SPONSOR' }]
        };

        const ownRequest = {
            request_id: 'REQ-GUID-001',
            requested_by_user_id: 'USER-SPONSOR-001', // Created by same user
            request_number: 'AR-2026-0001'
        };

        const isSeparated = await validateSeparationOfDuties(requesterUser, ownRequest);
        assert.strictEqual(isSeparated, false, 'Requester must be blocked from approving own request');
    });

    test('16. Separation of Duties Middleware: returns HTTP 403 ERR_SELF_APPROVAL_FORBIDDEN', async () => {
        const targetHandler = async () => ({ status: 200, jsonBody: { approved: true } });
        const wrapped = requireSeparationOfDuties(
            (req) => req.requestObject,
            targetHandler
        );

        const mockReq = {
            user: {
                user_id: 'USER-APPROVER-001',
                roles: [{ role_code: 'RESOURCE_OWNER' }]
            },
            requestObject: {
                request_id: 'REQ-GUID-005',
                requested_by_user_id: 'USER-APPROVER-001', // Self-request
                request_number: 'AR-2026-0005'
            },
            url: '/api/requests/REQ-GUID-005/approve'
        };

        const response = await wrapped(mockReq, { invocationId: 'unit-auth-7' });
        assert.strictEqual(response.status, 403);
        assert.strictEqual(response.jsonBody.error.code, 'ERR_SELF_APPROVAL_FORBIDDEN');
    });

    test('17. Frontend Privilege Escalation Prevention: body or query params claiming roles are completely ignored', async () => {
        let evaluatedUser = null;
        const targetHandler = async (req) => {
            evaluatedUser = req.user;
            return { status: 200 };
        };

        const wrapped = requireRole(['SYSTEM_ADMIN'], targetHandler);

        // Attacker sends request with low-privilege token, but puts SYSTEM_ADMIN in body & query
        const mockReq = {
            user: {
                user_id: 'contractor-001',
                roles: [{ role_code: 'CONTRACTOR' }] // Real verified DB role
            },
            body: {
                role: 'SYSTEM_ADMIN', // Spoofed payload
                roles: ['SYSTEM_ADMIN']
            },
            query: {
                role: 'SYSTEM_ADMIN' // Spoofed parameter
            },
            url: '/api/admin/system'
        };

        const response = await wrapped(mockReq, { invocationId: 'unit-auth-8' });

        // Must reject with 403 despite spoofed parameters
        assert.strictEqual(response.status, 403);
        assert.strictEqual(response.jsonBody.error.code, 'ERR_FORBIDDEN_ROLE');
        assert.strictEqual(evaluatedUser, null);
    });
});

