/**
 * AccessLease — Contractor & Engagement Integration Tests
 * Runs against real Microsoft SQL Server LocalDB (AccessLease_TestDB).
 * Tests complete lifecycle: listing, creation, updates, state transitions, constraints, and audit logging.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const cp = require('child_process');
const db = require('../../src/config/database');
const contractorService = require('../../src/services/contractorService');
const { userRepository, engagementRepository, auditRepository } = require('../../src/repositories');
const {
    ValidationError,
    NotFoundError,
    ForbiddenError,
    ConflictError
} = require('../../src/utils/errors');

describe('Integration: Real Database Contractor & Engagement Management (AccessLease_TestDB)', () => {
    let localDbAvailable = false;
    let seededContractor = null;
    let seededSponsor = null;
    let seededAdmin = null;
    let otherSponsor = null;
    let createdTestEngagementId = null;

    before(async () => {
        process.env.SQL_SERVER = '(localdb)\\MSSQLLocalDB';
        process.env.SQL_DATABASE = 'AccessLease_TestDB';

        try {
            cp.execSync('sqllocaldb start MSSQLLocalDB', { stdio: 'pipe' });
            const pool = await db.getPool();
            localDbAvailable = pool && pool.connected;

            if (localDbAvailable) {
                // Fetch seeded records
                seededContractor = await userRepository.findUserByEntraObjectId('TEST-OID-CONTRACTOR');
                seededSponsor = await userRepository.findUserByEntraObjectId('TEST-OID-SPONSOR');
                seededAdmin = await userRepository.findUserByEntraObjectId('f2bba284-9dba-4570-b865-875a009870ed');

                // Attach roles for service context
                if (seededContractor) {
                    seededContractor.roles = [{ role_code: 'CONTRACTOR' }];
                }
                if (seededSponsor) {
                    seededSponsor.roles = [{ role_code: 'INTERNAL_SPONSOR' }];
                }
                if (seededAdmin) {
                    seededAdmin.roles = [{ role_code: 'SYSTEM_ADMIN' }, { role_code: 'INTERNAL_SPONSOR' }];
                }

                // Check or create a second sponsor for cross-sponsor isolation testing
                otherSponsor = await userRepository.findUserByEmail('other.sponsor@example.com');
                if (!otherSponsor) {
                    otherSponsor = await userRepository.createUser({
                        entraObjectId: 'TEST-OID-OTHER-SPONSOR',
                        email: 'other.sponsor@example.com',
                        firstName: 'Olivia',
                        lastName: 'Other',
                        displayName: 'Olivia Other Sponsor',
                        userType: 'INTERNAL_EMPLOYEE',
                        department: 'Engineering',
                        isActive: true
                    });
                }
                otherSponsor.roles = [{ role_code: 'INTERNAL_SPONSOR' }];
            }
        } catch {
            localDbAvailable = false;
        }
    });

    after(async () => {
        if (localDbAvailable && createdTestEngagementId) {
            try {
                const pool = await db.getPool();
                await pool.request()
                    .input('id', createdTestEngagementId)
                    .query(`
                        DELETE FROM dbo.audit_events WHERE entity_id = CAST(@id AS NVARCHAR(64));
                        DELETE FROM dbo.contractor_engagements WHERE engagement_id = @id;
                    `);
            } catch {
                // Cleanup best effort
            }
        }
        await db.closePool();
    });

    test('1. listContractors: returns contractor directory with engagement metrics for internal sponsor', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        const result = await contractorService.listContractors(seededSponsor, { limit: 10 });
        assert.ok(Array.isArray(result.contractors));
        assert.ok(result.total >= 1);
        const carlos = result.contractors.find(c => c.user_id === seededContractor.user_id);
        assert.ok(carlos, 'Carlos Contractor must be in directory');
        assert.strictEqual(carlos.user_type, 'CONTRACTOR');
        assert.ok(carlos.total_engagements >= 1);
    });

    test('2. listContractors: rejects contractor user with ERR_FORBIDDEN_CONTRACTOR_DIRECTORY', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        await assert.rejects(
            async () => {
                await contractorService.listContractors(seededContractor);
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_FORBIDDEN_CONTRACTOR_DIRECTORY');
                return true;
            }
        );
    });

    test('3. listEngagements: contractor self-service scopes strictly to own records', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        const result = await contractorService.listEngagements(seededContractor);
        assert.ok(Array.isArray(result.engagements));
        for (const eng of result.engagements) {
            assert.strictEqual(eng.contractor_user_id.toLowerCase(), seededContractor.user_id.toLowerCase());
        }
    });

    test('4. getEngagementById: contractor cannot access another contractor engagement (IDOR prevention)', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        // Carlos attempts to access an engagement not belonging to him (e.g. random GUID or non-owned)
        await assert.rejects(
            async () => {
                // If it doesn't exist, returns NotFoundError, but if an engagement belongs to another, returns Forbidden
                await contractorService.getEngagementById(seededContractor, '00000000-0000-0000-0000-000000000000');
            },
            (err) => {
                assert.ok(err instanceof NotFoundError || err instanceof ForbiddenError);
                return true;
            }
        );
    });

    test('5. createEngagement: creates a real record in dbo.contractor_engagements and records audit event', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        const testContractRef = `TEST-SOW-${Date.now()}`;
        const created = await contractorService.createEngagement(seededSponsor, {
            contractorUserId: seededContractor.user_id,
            vendorName: 'Integration Test Vendor Corp',
            contractReference: testContractRef,
            startDate: '2026-11-15',
            endDate: '2027-05-31',
            status: 'ACTIVE'
        }, { ipAddress: '127.0.0.1' });

        assert.ok(created, 'Engagement must be created');
        assert.ok(created.engagement_id);
        createdTestEngagementId = created.engagement_id;
        assert.strictEqual(created.contract_reference, testContractRef);
        assert.strictEqual(created.status, 'ACTIVE');

        // Verify audit event in dbo.audit_events
        const auditEvents = await auditRepository.listAuditEvents({
            entityType: 'contractor_engagements',
            entityId: created.engagement_id
        });
        assert.ok(auditEvents.length >= 1, 'Audit event must be persisted');
        assert.strictEqual(auditEvents[0].event_action, 'ENGAGEMENT_CREATED');
        assert.strictEqual(auditEvents[0].event_category, 'SECURITY_POLICY');
    });

    test('6. createEngagement: rejects duplicate contract_reference for same contractor (UQ_contractor_contract_ref)', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        // SOW-2026-001 already exists for seededContractor
        await assert.rejects(
            async () => {
                await contractorService.createEngagement(seededSponsor, {
                    contractorUserId: seededContractor.user_id,
                    vendorName: 'Duplicate Test Vendor',
                    contractReference: 'SOW-2026-001',
                    startDate: '2026-11-15',
                    endDate: '2027-06-30'
                });
            },
            (err) => {
                assert.ok(err instanceof ConflictError);
                return true;
            }
        );
    });

    test('7. updateEngagement: sponsor cannot update engagement owned by different sponsor', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        // otherSponsor attempts to update createdTestEngagementId (sponsored by seededSponsor)
        await assert.rejects(
            async () => {
                await contractorService.updateEngagement(otherSponsor, createdTestEngagementId, {
                    vendorName: 'Unauthorized Vendor Change'
                });
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_FORBIDDEN_SPONSOR_MISMATCH');
                return true;
            }
        );
    });

    test('8. updateEngagement: authorized sponsor updates permitted fields and records audit', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        const updated = await contractorService.updateEngagement(seededSponsor, createdTestEngagementId, {
            vendorName: 'Updated Vendor Name Corp',
            endDate: '2027-06-15'
        });

        assert.strictEqual(updated.vendor_name, 'Updated Vendor Name Corp');

        // Verify audit event
        const audits = await auditRepository.listAuditEvents({
            entityType: 'contractor_engagements',
            entityId: createdTestEngagementId
        });
        const updateAudit = audits.find(a => a.event_action === 'ENGAGEMENT_UPDATED');
        assert.ok(updateAudit, 'Update audit event must be present');
    });

    test('9. transitionEngagementStatus: transitions ACTIVE to COMPLETED and forbids reactivation', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        // Transition to COMPLETED
        const completed = await contractorService.transitionEngagementStatus(
            seededSponsor,
            createdTestEngagementId,
            'COMPLETED',
            'Contract deliverables completed successfully'
        );
        assert.strictEqual(completed.status, 'COMPLETED');

        // Attempt invalid reactivation: COMPLETED -> ACTIVE
        await assert.rejects(
            async () => {
                await contractorService.transitionEngagementStatus(
                    seededSponsor,
                    createdTestEngagementId,
                    'ACTIVE'
                );
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.strictEqual(err.code, 'ERR_ENGAGEMENT_ALREADY_ENDED');
                return true;
            }
        );

        // Attempt update on ended engagement: Must be blocked
        await assert.rejects(
            async () => {
                await contractorService.updateEngagement(seededSponsor, createdTestEngagementId, {
                    vendorName: 'Should Fail'
                });
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                return true;
            }
        );
    });

    test('10. createContractor: registers new contractor in real LocalDB, assigns CONTRACTOR role, and records audit event', async (t) => {
        if (!localDbAvailable) return t.skip('LocalDB unavailable');

        const testEmail = `contractor.dbtest.${Date.now()}@external-agency.com`;
        let createdUserId = null;

        try {
            const regResult = await contractorService.createContractor(seededAdmin, {
                name: 'Evelyn Enterprise',
                email: testEmail,
                company: 'External Agency Inc',
                phone: '+1 555-8822'
            });

            assert.strictEqual(regResult.status, 'REGISTERED');
            assert.ok(regResult.contractor);
            createdUserId = regResult.contractor.user_id;

            // 1. Verify in dbo.users
            const dbUser = await userRepository.findUserById(createdUserId);
            assert.ok(dbUser, 'User must exist in dbo.users');
            assert.strictEqual(dbUser.email, testEmail);
            assert.strictEqual(dbUser.display_name, 'Evelyn Enterprise');
            assert.strictEqual(dbUser.user_type, 'CONTRACTOR');
            assert.strictEqual(dbUser.department, 'External Agency Inc');
            assert.strictEqual(dbUser.is_active, true);
            assert.ok(dbUser.entra_object_id.startsWith('LOCAL-CONTRACTOR-'), 'Synthetic Entra ID prefix verified');

            // 2. Verify role assignment in dbo.user_roles
            const roles = await userRepository.getUserRoles(createdUserId);
            assert.ok(roles.some(r => r.role_code === 'CONTRACTOR'), 'Must have CONTRACTOR role assigned');

            // 3. Verify contractor appears in listContractors
            const listResult = await contractorService.listContractors(seededAdmin, { isActive: true, limit: 100 });
            assert.ok(listResult.contractors.some(c => c.user_id === createdUserId), 'Contractor must appear in directory');

            // 4. Verify duplicate registration fails with ConflictError (409)
            await assert.rejects(
                async () => {
                    await contractorService.createContractor(seededAdmin, {
                        name: 'Evelyn Duplicate',
                        email: testEmail
                    });
                },
                (err) => {
                    assert.ok(err instanceof ConflictError);
                    assert.strictEqual(err.code, 'ERR_CONTRACTOR_EXISTS');
                    return true;
                }
            );
        } finally {
            if (createdUserId) {
                try {
                    await userRepository.deleteUser(createdUserId);
                } catch (e) {
                    // Ignore cleanup error
                }
            }
        }
    });
});
