const { describe, test, beforeEach } = require('node:test');
const assert = require('node:assert');

const catalogService = require('../../src/services/catalogService');
const { resourceRepository, userRepository, auditRepository } = require('../../src/repositories');
const {
    ValidationError,
    NotFoundError,
    ForbiddenError,
    ConflictError
} = require('../../src/utils/errors');

describe('Unit: CatalogService (catalogService.js)', () => {
    const adminUser = {
        user_id: 'USER-ADMIN-001',
        display_name: 'Admin User',
        roles: [{ role_code: 'SYSTEM_ADMIN' }]
    };

    const ownerUser = {
        user_id: 'USER-OWNER-001',
        display_name: 'Owner User',
        roles: [{ role_code: 'RESOURCE_OWNER' }]
    };

    const contractorUser = {
        user_id: 'USER-CONT-001',
        display_name: 'Contractor User',
        roles: [{ role_code: 'CONTRACTOR' }]
    };

    beforeEach(() => {
        // Reset repository mocks
        resourceRepository.findResourceByCode = async () => null;
        resourceRepository.findResourceById = async () => null;
        resourceRepository.createResource = async (data) => ({
            resource_id: 'RES-NEW-1',
            resource_code: data.resourceCode,
            resource_name: data.resourceName,
            resource_type: data.resourceType,
            risk_level: data.riskLevel,
            requires_security_approval: data.requiresSecurityApproval,
            max_lease_duration_days: data.maxLeaseDurationDays,
            is_active: data.isActive,
            description: data.description
        });
        resourceRepository.updateResource = async (id, data) => ({ resource_id: id, ...data });
        resourceRepository.setResourceStatus = async (id, isActive) => ({ resource_id: id, is_active: isActive });
        resourceRepository.setPrimaryResourceOwner = async (resId, userId) => ({ resource_id: resId, owner_user_id: userId, ownership_type: 'PRIMARY' });
        resourceRepository.assignResourceOwner = async (resId, userId, type) => ({ resource_id: resId, owner_user_id: userId, ownership_type: type });
        resourceRepository.removeResourceOwner = async () => true;
        resourceRepository.isUserResourceOwner = async () => false;
        resourceRepository.listResourcesDetailed = async () => [];
        resourceRepository.listEntitlementsByResourceId = async () => [];
        resourceRepository.findEntitlementById = async () => null;
        resourceRepository.findEntitlementByCode = async () => null;
        resourceRepository.createEntitlement = async (data) => ({ entitlement_id: 'ENT-NEW-1', ...data });
        resourceRepository.updateEntitlement = async (id, data) => ({ entitlement_id: id, ...data });
        resourceRepository.setEntitlementStatus = async (id, isActive) => ({ entitlement_id: id, is_active: isActive });
        userRepository.findUserById = async () => ({ user_id: 'USER-OWNER-001', is_active: true });
        auditRepository.createAuditEvent = async () => ({});
    });

    // -------------------------------------------------------------------------
    // 1. Resource Creation Validation & Authorization
    // -------------------------------------------------------------------------
    test('1. createResource rejects non-SYSTEM_ADMIN actors with ForbiddenError', async () => {
        await assert.rejects(
            async () => {
                await catalogService.createResource({
                    resourceCode: 'RES-TEST-01',
                    resourceName: 'Test Resource',
                    resourceType: 'DATABASE'
                }, contractorUser);
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_FORBIDDEN_CATALOG_ADMIN');
                return true;
            }
        );
    });

    test('2. createResource rejects invalid or missing resourceCode', async () => {
        // Missing code
        await assert.rejects(
            async () => {
                await catalogService.createResource({
                    resourceName: 'Test Resource',
                    resourceType: 'DATABASE'
                }, adminUser);
            },
            (err) => err instanceof ValidationError && err.message.includes('Resource Code')
        );

        // Invalid characters (spaces, special chars)
        await assert.rejects(
            async () => {
                await catalogService.createResource({
                    resourceCode: 'RES INVALID $#@',
                    resourceName: 'Test Resource',
                    resourceType: 'DATABASE'
                }, adminUser);
            },
            (err) => err instanceof ValidationError && err.message.includes('uppercase alphanumeric')
        );
    });

    test('3. createResource rejects invalid resourceType', async () => {
        await assert.rejects(
            async () => {
                await catalogService.createResource({
                    resourceCode: 'RES-VALID-01',
                    resourceName: 'Valid Name',
                    resourceType: 'INVALID_TYPE'
                }, adminUser);
            },
            (err) => err instanceof ValidationError && err.message.includes('Invalid Resource Type')
        );
    });

    test('4. createResource rejects duplicate resourceCode with ConflictError', async () => {
        resourceRepository.findResourceByCode = async (code) => ({
            resource_id: 'RES-EXISTING-1',
            resource_code: code
        });

        await assert.rejects(
            async () => {
                await catalogService.createResource({
                    resourceCode: 'RES-EXISTING-1',
                    resourceName: 'Duplicate Test',
                    resourceType: 'DATABASE'
                }, adminUser);
            },
            (err) => err instanceof ConflictError && err.message.includes('already exists')
        );
    });

    test('5. createResource successfully registers resource, tags environment, and records audit event', async () => {
        let auditCaptured = null;
        auditRepository.createAuditEvent = async (event) => { auditCaptured = event; };

        let primaryOwnerAssigned = null;
        resourceRepository.setPrimaryResourceOwner = async (resId, userId) => {
            primaryOwnerAssigned = { resId, userId };
            return { resource_id: resId, owner_user_id: userId, ownership_type: 'PRIMARY' };
        };

        const res = await catalogService.createResource({
            resourceCode: 'RES-KUBE-PROD',
            resourceName: 'Production Kubernetes Workload',
            resourceType: 'CLOUD_SUBSCRIPTION',
            environment: 'PRODUCTION',
            riskLevel: 'CRITICAL',
            maxLeaseDurationDays: 30,
            primaryOwnerUserId: 'USER-OWNER-001',
            description: 'Core production cluster for API services.'
        }, adminUser);

        assert.strictEqual(res.resource_code, 'RES-KUBE-PROD');
        assert.strictEqual(res.environment, 'PRODUCTION');
        assert.strictEqual(res.risk_level, 'CRITICAL');
        assert.strictEqual(res.requires_security_approval, true, 'CRITICAL risk must enforce requiresSecurityApproval');
        assert.ok(primaryOwnerAssigned);
        assert.strictEqual(primaryOwnerAssigned.userId, 'USER-OWNER-001');

        assert.ok(auditCaptured);
        assert.strictEqual(auditCaptured.eventCategory, 'SECURITY_POLICY');
        assert.strictEqual(auditCaptured.eventAction, 'RESOURCE_CREATED');
    });

    // -------------------------------------------------------------------------
    // 2. Resource Update & Authorization
    // -------------------------------------------------------------------------
    test('6. updateResource rejects unauthorized users who do not own the resource', async () => {
        resourceRepository.findResourceById = async () => ({
            resource_id: 'RES-01',
            resource_code: 'RES-01',
            resource_name: 'Existing Resource'
        });
        resourceRepository.isUserResourceOwner = async () => false;

        await assert.rejects(
            async () => {
                await catalogService.updateResource('RES-01', { resourceName: 'Hacked Name' }, contractorUser);
            },
            (err) => err instanceof ForbiddenError && err.code === 'ERR_FORBIDDEN_RESOURCE_MANAGE'
        );
    });

    test('7. updateResource allows verified RESOURCE_OWNER to update resource details', async () => {
        resourceRepository.findResourceById = async () => ({
            resource_id: 'RES-01',
            resource_code: 'RES-01',
            resource_name: 'Existing Resource',
            risk_level: 'MEDIUM',
            description: '[STAGING] Old description'
        });
        resourceRepository.isUserResourceOwner = async () => true;

        const updated = await catalogService.updateResource('RES-01', {
            resourceName: 'Updated Resource Name',
            description: 'New runbook link and guidelines',
            environment: 'PRODUCTION'
        }, ownerUser);

        assert.strictEqual(updated.resourceName, 'Updated Resource Name');
        assert.strictEqual(updated.environment, 'PRODUCTION');
    });

    test('8. setResourceStatus rejects non-SYSTEM_ADMIN actors and updates active status for admin', async () => {
        resourceRepository.findResourceById = async () => ({
            resource_id: 'RES-01',
            is_active: true
        });

        // Non-admin rejected
        await assert.rejects(
            async () => {
                await catalogService.setResourceStatus('RES-01', false, ownerUser);
            },
            (err) => err instanceof ForbiddenError && err.code === 'ERR_FORBIDDEN_STATUS_CHANGE'
        );

        // Admin succeeds
        const deactivated = await catalogService.setResourceStatus('RES-01', false, adminUser);
        assert.strictEqual(deactivated.is_active, false);
    });

    // -------------------------------------------------------------------------
    // 3. Entitlement Management & Resource Mapping
    // -------------------------------------------------------------------------
    test('9. createEntitlement rejects duplicate entitlement code under same resource', async () => {
        resourceRepository.findResourceById = async () => ({
            resource_id: 'RES-01',
            is_active: true
        });
        resourceRepository.findEntitlementByCode = async () => ({
            entitlement_id: 'ENT-EXISTING',
            entitlement_code: 'READ_ONLY'
        });

        await assert.rejects(
            async () => {
                await catalogService.createEntitlement('RES-01', {
                    entitlementCode: 'READ_ONLY',
                    entitlementName: 'Read Only Access'
                }, adminUser);
            },
            (err) => err instanceof ConflictError && err.message.includes('already exists')
        );
    });

    test('10. createEntitlement successfully maps entitlement to resource and records audit event', async () => {
        resourceRepository.findResourceById = async () => ({
            resource_id: 'RES-01',
            is_active: true
        });

        let auditCaptured = null;
        auditRepository.createAuditEvent = async (event) => { auditCaptured = event; };

        const ent = await catalogService.createEntitlement('RES-01', {
            entitlementCode: 'KUBE_ADMIN',
            entitlementName: 'Kubernetes Cluster Admin',
            sensitivityLevel: 'CRITICAL',
            description: 'Full cluster administration privileges'
        }, adminUser);

        assert.strictEqual(ent.resourceId, 'RES-01');
        assert.strictEqual(ent.entitlementCode, 'KUBE_ADMIN');
        assert.strictEqual(ent.sensitivityLevel, 'CRITICAL');
        assert.ok(auditCaptured);
        assert.strictEqual(auditCaptured.eventAction, 'ENTITLEMENT_CREATED');
    });

    test('11. setEntitlementStatus toggles active state for authorized resource manager', async () => {
        resourceRepository.findEntitlementById = async () => ({
            entitlement_id: 'ENT-01',
            resource_id: 'RES-01',
            is_active: true
        });
        resourceRepository.isUserResourceOwner = async () => true;

        const res = await catalogService.setEntitlementStatus('ENT-01', false, ownerUser);
        assert.strictEqual(res.is_active, false);
    });

    // -------------------------------------------------------------------------
    // 4. Resource Owner Mapping
    // -------------------------------------------------------------------------
    test('12. assignResourceOwner enforces active user existence and SYSTEM_ADMIN role', async () => {
        resourceRepository.findResourceById = async () => ({
            resource_id: 'RES-01',
            is_active: true
        });
        userRepository.findUserById = async () => null; // Not found

        await assert.rejects(
            async () => {
                await catalogService.assignResourceOwner('RES-01', {
                    ownerUserId: 'USER-UNKNOWN-99',
                    ownershipType: 'DELEGATE'
                }, adminUser);
            },
            (err) => err instanceof ValidationError && err.message.includes('active registered user')
        );
    });
});
