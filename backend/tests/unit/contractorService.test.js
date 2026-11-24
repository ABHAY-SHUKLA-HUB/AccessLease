/**
 * AccessLease — Contractor & Engagement Business Service Unit Tests
 * Tests state transition rules, date validation, role checks, and error handling.
 */

const { test, describe, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const contractorService = require('../../src/services/contractorService');
const { userRepository, engagementRepository, roleRepository, auditRepository } = require('../../src/repositories');
const {
    ValidationError,
    NotFoundError,
    ForbiddenError,
    ConflictError
} = require('../../src/utils/errors');

describe('Unit: Contractor & Engagement Management Service', () => {
    const adminUser = {
        user_id: '11111111-1111-1111-1111-111111111111',
        email: 'admin@accesslease.corp',
        is_active: true,
        roles: [{ role_code: 'SYSTEM_ADMIN' }]
    };

    const sponsorUser = {
        user_id: '22222222-2222-2222-2222-222222222222',
        email: 'sponsor@accesslease.corp',
        is_active: true,
        roles: [{ role_code: 'INTERNAL_SPONSOR' }]
    };

    const contractorUser = {
        user_id: '33333333-3333-3333-3333-333333333333',
        email: 'contractor@vendor.com',
        is_active: true,
        roles: [{ role_code: 'CONTRACTOR' }]
    };

    const auditorUser = {
        user_id: '44444444-4444-4444-4444-444444444444',
        email: 'auditor@accesslease.corp',
        is_active: true,
        roles: [{ role_code: 'COMPLIANCE_AUDITOR' }]
    };

    const deactivatedUser = {
        user_id: '55555555-5555-5555-5555-555555555555',
        email: 'disabled@accesslease.corp',
        is_active: false,
        roles: [{ role_code: 'INTERNAL_SPONSOR' }]
    };

    // 1. Authorization & Role Restrictions
    test('1. Contractors cannot access contractor directory', async () => {
        await assert.rejects(
            async () => {
                await contractorService.listContractors(contractorUser);
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_FORBIDDEN_CONTRACTOR_DIRECTORY');
                return true;
            }
        );
    });

    test('2. Contractor cannot access another contractor record by ID (IDOR prevention)', async () => {
        await assert.rejects(
            async () => {
                await contractorService.getContractorById(contractorUser, '99999999-9999-9999-9999-999999999999');
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_FORBIDDEN_CONTRACTOR_ACCESS');
                return true;
            }
        );
    });

    test('3. Unauthorized roles cannot create an engagement', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createEngagement(contractorUser, {
                    contractorUserId: contractorUser.user_id,
                    vendorName: 'Acme',
                    contractReference: 'SOW-001',
                    startDate: '2026-01-01',
                    endDate: '2026-12-31'
                });
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_FORBIDDEN_ENGAGEMENT_CREATE');
                return true;
            }
        );
    });

    test('4. Read-only Compliance Auditor cannot create or manage engagements', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createEngagement(auditorUser, {
                    contractorUserId: contractorUser.user_id,
                    vendorName: 'Acme',
                    contractReference: 'SOW-001',
                    startDate: '2026-01-01',
                    endDate: '2026-12-31'
                });
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                return true;
            }
        );
    });

    test('5. Disabled internal user cannot perform management operations', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createEngagement(deactivatedUser, {
                    contractorUserId: contractorUser.user_id,
                    vendorName: 'Acme',
                    contractReference: 'SOW-001',
                    startDate: '2026-01-01',
                    endDate: '2026-12-31'
                });
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_USER_INACTIVE');
                return true;
            }
        );
    });

    // 2. Date and Field Validations
    test('6. Rejects missing required engagement fields with validation details', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createEngagement(adminUser, {});
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.details.length >= 3);
                return true;
            }
        );
    });

    test('7. Rejects invalid date format and inverted date ranges (endDate < startDate)', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createEngagement(adminUser, {
                    contractorUserId: contractorUser.user_id,
                    vendorName: 'Vendor X',
                    contractReference: 'REF-001',
                    startDate: '2026-12-31',
                    endDate: '2026-01-01'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.details.some(d => d.includes('End date must be on or after start date')));
                return true;
            }
        );
    });

    test('8. Rejects ACTIVE engagement when endDate is already in the past', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createEngagement(adminUser, {
                    contractorUserId: contractorUser.user_id,
                    vendorName: 'Vendor X',
                    contractReference: 'REF-001',
                    startDate: '2020-01-01',
                    endDate: '2020-06-30',
                    status: 'ACTIVE'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.details.some(d => d.includes('Cannot mark engagement ACTIVE when the end date is already in the past')));
                return true;
            }
        );
    });

    // 3. Contractor ID Mapping & Eligibility Validations
    test('9. Rejects invalid contractor GUID format with clean ValidationError', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createEngagement(adminUser, {
                    contractorUserId: 'invalid-non-guid-12345',
                    vendorName: 'Vendor Valid',
                    contractReference: 'REF-UUID-TEST',
                    startDate: '2026-11-20',
                    endDate: '2027-05-30',
                    status: 'ACTIVE'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.details.some(d => d.includes('valid UUID format')));
                return true;
            }
        );
    });

    test('10. Accepts contractorId alias and validates UUID format', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createEngagement(adminUser, {
                    contractorId: 'invalid-alias-guid',
                    vendorName: 'Vendor Valid',
                    contractReference: 'REF-ALIAS-TEST',
                    startDate: '2026-11-20',
                    endDate: '2027-05-30',
                    status: 'ACTIVE'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.ok(err.details.some(d => d.includes('valid UUID format')));
                return true;
            }
        );
    });

    test('11. Rejects non-existent contractor ID with ValidationError', async () => {
        const origFindUserById = userRepository.findUserById;
        try {
            userRepository.findUserById = async (id) => {
                if (id === '99999999-0000-0000-0000-000000000000') return null;
                return origFindUserById(id);
            };

            await assert.rejects(
                async () => {
                    await contractorService.createEngagement(adminUser, {
                        contractorUserId: '99999999-0000-0000-0000-000000000000',
                        vendorName: 'Vendor Valid',
                        contractReference: 'REF-NOT-FOUND-TEST',
                        startDate: '2026-11-20',
                        endDate: '2027-05-30',
                        status: 'ACTIVE'
                    });
                },
                (err) => {
                    assert.ok(err instanceof ValidationError);
                    assert.ok(err.message.includes('Contractor not found or user is not classified as a CONTRACTOR'));
                    return true;
                }
            );
        } finally {
            userRepository.findUserById = origFindUserById;
        }
    });

    test('12. Rejects contractor ID when user is not classified as CONTRACTOR', async () => {
        const origFindUserById = userRepository.findUserById;
        try {
            userRepository.findUserById = async (id) => {
                if (id === '88888888-8888-8888-8888-888888888888') {
                    return {
                        user_id: '88888888-8888-8888-8888-888888888888',
                        user_type: 'INTERNAL_EMPLOYEE',
                        display_name: 'Employee Test',
                        is_active: true
                    };
                }
                return origFindUserById(id);
            };

            await assert.rejects(
                async () => {
                    await contractorService.createEngagement(adminUser, {
                        contractorUserId: '88888888-8888-8888-8888-888888888888',
                        vendorName: 'Vendor Valid',
                        contractReference: 'REF-EMPLOYEE-TEST',
                        startDate: '2026-11-20',
                        endDate: '2027-05-30',
                        status: 'ACTIVE'
                    });
                },
                (err) => {
                    assert.ok(err instanceof ValidationError);
                    assert.ok(err.message.includes('Contractor not found or user is not classified as a CONTRACTOR'));
                    return true;
                }
            );
        } finally {
            userRepository.findUserById = origFindUserById;
        }
    });

    test('13. Rejects inactive contractor record with ValidationError', async () => {
        const origFindUserById = userRepository.findUserById;
        try {
            userRepository.findUserById = async (id) => {
                if (id === '77777777-7777-7777-7777-777777777777') {
                    return {
                        user_id: '77777777-7777-7777-7777-777777777777',
                        user_type: 'CONTRACTOR',
                        display_name: 'Deactivated Contractor',
                        is_active: false
                    };
                }
                return origFindUserById(id);
            };

            await assert.rejects(
                async () => {
                    await contractorService.createEngagement(adminUser, {
                        contractorUserId: '77777777-7777-7777-7777-777777777777',
                        vendorName: 'Vendor Valid',
                        contractReference: 'REF-INACTIVE-TEST',
                        startDate: '2026-11-20',
                        endDate: '2027-05-30',
                        status: 'ACTIVE'
                    });
                },
                (err) => {
                    assert.ok(err instanceof ValidationError);
                    assert.ok(err.message.includes('Contractor record is currently deactivated'));
                    return true;
                }
            );
        } finally {
            userRepository.findUserById = origFindUserById;
        }
    });

    test('14. getContractorById includes contractor_id mapped to primary key alongside user_id', async () => {
        const origFindUserById = userRepository.findUserById;
        const origFindEngagements = engagementRepository.findEngagementsByContractorId;
        try {
            userRepository.findUserById = async (id) => ({
                user_id: id,
                email: 'contractor@vendor.com',
                first_name: 'John',
                last_name: 'Doe',
                display_name: 'John Doe',
                user_type: 'CONTRACTOR',
                department: 'External',
                is_active: true,
                created_at: new Date()
            });
            engagementRepository.findEngagementsByContractorId = async () => [];

            const res = await contractorService.getContractorById(adminUser, contractorUser.user_id);
            assert.ok(res.contractor);
            assert.strictEqual(res.contractor.user_id, contractorUser.user_id);
            assert.strictEqual(res.contractor.contractor_id, contractorUser.user_id);
        } finally {
            userRepository.findUserById = origFindUserById;
            engagementRepository.findEngagementsByContractorId = origFindEngagements;
        }
    });

    // 15. createContractor: Authorization & Validation Tests
    test('15. createContractor: rejects registration when actor lacks SYSTEM_ADMIN role', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createContractor(sponsorUser, {
                    name: 'Test Contractor',
                    email: 'contractor.test@example.com'
                });
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_FORBIDDEN_ROLE');
                return true;
            }
        );

        await assert.rejects(
            async () => {
                await contractorService.createContractor(contractorUser, {
                    name: 'Test Contractor',
                    email: 'contractor.test@example.com'
                });
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_FORBIDDEN_ROLE');
                return true;
            }
        );
    });

    test('16. createContractor: rejects missing or whitespace name with ValidationError', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createContractor(adminUser, {
                    name: '',
                    email: 'contractor.test@example.com'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.strictEqual(err.code, 'ERR_CONTRACTOR_NAME_REQUIRED');
                return true;
            }
        );

        await assert.rejects(
            async () => {
                await contractorService.createContractor(adminUser, {
                    name: '   ',
                    email: 'contractor.test@example.com'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.strictEqual(err.code, 'ERR_CONTRACTOR_NAME_REQUIRED');
                return true;
            }
        );
    });

    test('17. createContractor: rejects name with less than 2 characters with ValidationError', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createContractor(adminUser, {
                    name: 'A',
                    email: 'contractor.test@example.com'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                return true;
            }
        );
    });

    test('18. createContractor: rejects invalid email with ValidationError', async () => {
        await assert.rejects(
            async () => {
                await contractorService.createContractor(adminUser, {
                    name: 'Jane Doe',
                    email: 'not-an-email'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.strictEqual(err.code, 'ERR_INVALID_EMAIL');
                return true;
            }
        );

        await assert.rejects(
            async () => {
                await contractorService.createContractor(adminUser, {
                    name: 'Jane Doe',
                    email: 'missing@domain'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.strictEqual(err.code, 'ERR_INVALID_EMAIL');
                return true;
            }
        );
    });

    test('19. createContractor: rejects email exceeding 256 characters with ValidationError', async () => {
        const longEmail = 'a'.repeat(250) + '@example.com';
        await assert.rejects(
            async () => {
                await contractorService.createContractor(adminUser, {
                    name: 'Jane Doe',
                    email: longEmail
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.strictEqual(err.code, 'ERR_INVALID_EMAIL');
                return true;
            }
        );
    });

    test('20. createContractor: rejects duplicate email with ConflictError', async () => {
        const origFindUserByEmail = userRepository.findUserByEmail;
        try {
            userRepository.findUserByEmail = async (email) => ({
                user_id: '99999999-9999-9999-9999-999999999999',
                email: email,
                user_type: 'CONTRACTOR'
            });

            await assert.rejects(
                async () => {
                    await contractorService.createContractor(adminUser, {
                        name: 'Jane Doe',
                        email: 'existing@contractor.com'
                    });
                },
                (err) => {
                    assert.ok(err instanceof ConflictError);
                    assert.strictEqual(err.code, 'ERR_CONTRACTOR_EXISTS');
                    return true;
                }
            );
        } finally {
            userRepository.findUserByEmail = origFindUserByEmail;
        }
    });

    test('21. createContractor: successfully creates contractor, enforces user_type CONTRACTOR and assigns role', async () => {
        const origFindUserByEmail = userRepository.findUserByEmail;
        const origCreateUser = userRepository.createUser;
        const origFindRoleByCode = roleRepository.findRoleByCode;
        const origAssignRole = roleRepository.assignRoleToUser;
        const origCreateAudit = auditRepository.createAuditEvent;
        const db = require('../../src/config/database');
        const origWithTransaction = db.withTransaction;

        try {
            let createdUserParams = null;
            let assignedRoleParams = null;
            let auditRecorded = null;

            userRepository.findUserByEmail = async () => null;
            db.withTransaction = async (cb) => cb({});

            userRepository.createUser = async (userData, tx) => {
                createdUserParams = userData;
                return {
                    user_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                    entra_object_id: userData.entraObjectId,
                    email: userData.email,
                    first_name: userData.firstName,
                    last_name: userData.lastName,
                    display_name: userData.displayName || `${userData.firstName} ${userData.lastName}`.trim(),
                    user_type: userData.userType,
                    department: userData.department,
                    is_active: userData.isActive,
                    created_at: new Date()
                };
            };

            roleRepository.findRoleByCode = async (code) => ({
                role_id: 'rrrrrrrr-rrrr-rrrr-rrrr-rrrrrrrrrrrr',
                role_code: code
            });

            roleRepository.assignRoleToUser = async (userId, roleId, tx) => {
                assignedRoleParams = { userId, roleId };
                return true;
            };

            auditRepository.createAuditEvent = async (event, tx) => {
                auditRecorded = event;
                return true;
            };

            const result = await contractorService.createContractor(adminUser, {
                name: 'Alice Wonder',
                email: '  Alice.Wonder@PartnerCorp.com  ',
                company: 'Wonderland Logistics',
                user_type: 'INTERNAL_EMPLOYEE' // Should be overridden to CONTRACTOR
            });

            assert.strictEqual(result.status, 'REGISTERED');
            assert.strictEqual(result.contractor.user_type, 'CONTRACTOR');
            assert.strictEqual(result.contractor.department, 'Wonderland Logistics');
            assert.strictEqual(result.contractor.contractor_id, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
            assert.strictEqual(createdUserParams.email, 'alice.wonder@partnercorp.com');
            assert.strictEqual(createdUserParams.userType, 'CONTRACTOR');
            assert.strictEqual(createdUserParams.department, 'Wonderland Logistics');
            assert.ok(createdUserParams.entraObjectId.startsWith('LOCAL-CONTRACTOR-'));
            assert.strictEqual(assignedRoleParams.userId, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
            assert.strictEqual(auditRecorded.eventAction, 'CONTRACTOR_REGISTERED');
        } finally {
            userRepository.findUserByEmail = origFindUserByEmail;
            userRepository.createUser = origCreateUser;
            roleRepository.findRoleByCode = origFindRoleByCode;
            roleRepository.assignRoleToUser = origAssignRole;
            auditRepository.createAuditEvent = origCreateAudit;
            db.withTransaction = origWithTransaction;
        }
    });

    test('22. listContractors: strictly filters and returns only records where user_type is CONTRACTOR, excluding INTERNAL_EMPLOYEE records', async () => {
        const origListContractors = userRepository.listContractors;
        const origCountContractors = userRepository.countContractors;
        try {
            userRepository.listContractors = async () => [
                {
                    user_id: '11111111-0000-0000-0000-000000000001',
                    display_name: 'Real Contractor',
                    email: 'contractor@vendor.com',
                    user_type: 'CONTRACTOR',
                    is_active: true
                },
                {
                    user_id: '22222222-0000-0000-0000-000000000002',
                    display_name: 'System Admin Internal',
                    email: 'admin@corp.internal',
                    user_type: 'INTERNAL_EMPLOYEE',
                    is_active: true
                },
                {
                    user_id: '33333333-0000-0000-0000-000000000003',
                    display_name: 'Internal Sponsor User',
                    email: 'sponsor@corp.internal',
                    user_type: 'INTERNAL_EMPLOYEE',
                    is_active: true
                }
            ];
            userRepository.countContractors = async () => 1;

            const result = await contractorService.listContractors(adminUser);
            assert.strictEqual(result.contractors.length, 1, 'Must strictly exclude INTERNAL_EMPLOYEE records');
            assert.strictEqual(result.contractors[0].user_type, 'CONTRACTOR');
            assert.strictEqual(result.contractors[0].display_name, 'Real Contractor');
            assert.strictEqual(result.total, 1, 'Total count must reflect eligible contractors');
        } finally {
            userRepository.listContractors = origListContractors;
            userRepository.countContractors = origCountContractors;
        }
    });

    test('23. listContractors: uses countContractors to ensure total count and pagination reflect eligible CONTRACTOR records', async () => {
        const origListContractors = userRepository.listContractors;
        const origCountContractors = userRepository.countContractors;
        let countFilterReceived = null;
        try {
            userRepository.listContractors = async () => [];
            userRepository.countContractors = async (f) => {
                countFilterReceived = f;
                return 42;
            };

            const result = await contractorService.listContractors(sponsorUser, {
                search: 'Acme',
                isActive: 'true',
                limit: '25',
                offset: '50'
            });

            assert.strictEqual(result.total, 42);
            assert.strictEqual(result.limit, 25);
            assert.strictEqual(result.offset, 50);
            assert.strictEqual(countFilterReceived.search, 'Acme');
            assert.strictEqual(countFilterReceived.isActive, true);
        } finally {
            userRepository.listContractors = origListContractors;
            userRepository.countContractors = origCountContractors;
        }
    });

    after(async () => {
        const db = require('../../src/config/database');
        await db.closePool();
    });
});

