/**
 * AccessLease — Enterprise Resource & Entitlement Catalogue Service
 * Business logic, role authorization, governance constraints, and audit logging.
 */

const { resourceRepository, userRepository, auditRepository } = require('../repositories');
const {
    ValidationError,
    NotFoundError,
    ForbiddenError,
    ConflictError
} = require('../utils/errors');
const logger = require('../utils/logger');

const VALID_RESOURCE_TYPES = ['SAAS', 'CLOUD_SUBSCRIPTION', 'DATABASE', 'REPOSITORY', 'NETWORK_VPN', 'INTERNAL_APP'];
const VALID_RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const VALID_SENSITIVITY_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const VALID_ENVIRONMENTS = ['PRODUCTION', 'STAGING', 'DEVELOPMENT', 'CORPORATE'];

/**
 * Extracts environment and clean description from resource.
 * Supports [ENV] tag prefix in description while maintaining schema compatibility.
 */
function parseEnvironment(resource) {
    if (!resource) return resource;
    let env = 'PRODUCTION';
    let cleanDesc = resource.description || '';

    if (resource.description && resource.description.startsWith('[')) {
        const match = resource.description.match(/^\[(PRODUCTION|STAGING|DEVELOPMENT|CORPORATE|PROD|STAGE|DEV|CORP)\]\s*(.*)/i);
        if (match) {
            const rawEnv = match[1].toUpperCase();
            if (rawEnv === 'PROD') env = 'PRODUCTION';
            else if (rawEnv === 'STAGE') env = 'STAGING';
            else if (rawEnv === 'DEV') env = 'DEVELOPMENT';
            else if (rawEnv === 'CORP') env = 'CORPORATE';
            else env = rawEnv;
            cleanDesc = match[2];
        }
    } else if (resource.resource_code) {
        if (/PROD/i.test(resource.resource_code)) env = 'PRODUCTION';
        else if (/STAGE|STG/i.test(resource.resource_code)) env = 'STAGING';
        else if (/DEV/i.test(resource.resource_code)) env = 'DEVELOPMENT';
        else if (/CORP/i.test(resource.resource_code)) env = 'CORPORATE';
    }

    return {
        ...resource,
        environment: env,
        clean_description: cleanDesc
    };
}

/**
 * Formats description with environment tag.
 */
function formatDescriptionWithEnv(description, environment) {
    const rawDesc = (description || '').replace(/^\[(PRODUCTION|STAGING|DEVELOPMENT|CORPORATE|PROD|STAGE|DEV|CORP)\]\s*/i, '').trim();
    if (!environment) return rawDesc || null;
    const cleanEnv = environment.trim().toUpperCase();
    return `[${cleanEnv}] ${rawDesc}`.trim();
}

/**
 * Validates whether the actor has an administrative governance role.
 */
function isSystemAdmin(user) {
    if (!user || !user.roles) return false;
    return user.roles.some(r => (r.role_code || r) === 'SYSTEM_ADMIN');
}

/**
 * Validates whether the actor has the resource owner role or is an owner of the resource.
 */
async function canManageResource(user, resourceId) {
    if (isSystemAdmin(user)) return true;
    if (!user || !user.user_id || !resourceId) return false;

    // Check if user has RESOURCE_OWNER role and actually owns this specific resource
    const hasRole = user.roles && user.roles.some(r => (r.role_code || r) === 'RESOURCE_OWNER');
    if (!hasRole) return false;

    return await resourceRepository.isUserResourceOwner(user.user_id, resourceId);
}

class CatalogService {
    /**
     * Lists catalogue resources with owners and entitlement metrics.
     * @param {object} filter
     * @param {object} actorUser
     */
    async listResources(filter = {}, actorUser = null) {
        if (!actorUser) {
            throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
        }

        const isAdmin = isSystemAdmin(actorUser);
        let isActive = filter.isActive;
        if (isActive === undefined || isActive === null) {
            // Non-admins only see active resources by default unless explicitly querying
            isActive = isAdmin ? undefined : true;
        } else if (typeof isActive === 'string') {
            if (isActive.toLowerCase() === 'all') isActive = undefined;
            else isActive = isActive === 'true' || isActive === '1';
        }

        const queryFilter = {
            search: filter.search,
            resourceType: filter.resourceType,
            riskLevel: filter.riskLevel,
            isActive: isActive,
            limit: filter.limit || 100,
            offset: filter.offset || 0
        };

        const records = await resourceRepository.listResourcesDetailed(queryFilter);
        return records.map(parseEnvironment);
    }

    /**
     * Retrieves full details for a resource including all owners and active/inactive entitlements.
     * @param {string} resourceId
     * @param {object} actorUser
     */
    async getResourceById(resourceId, actorUser) {
        if (!actorUser) {
            throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
        }
        if (!resourceId) {
            throw new ValidationError('Resource ID is required.');
        }

        const resource = await resourceRepository.findResourceById(resourceId);
        if (!resource) {
            throw new NotFoundError('Resource');
        }

        const [owners, entitlements] = await Promise.all([
            resourceRepository.getResourceOwners(resourceId),
            resourceRepository.listEntitlementsByResourceId(resourceId)
        ]);

        const primaryOwner = owners.find(o => o.ownership_type === 'PRIMARY') || null;

        return {
            ...parseEnvironment(resource),
            primary_owner: primaryOwner,
            owners,
            entitlements
        };
    }

    /**
     * Registers a new resource in the catalogue with validation, owner assignment, and audit event.
     * Requires SYSTEM_ADMIN role.
     * @param {object} data
     * @param {object} actorUser
     */
    async createResource(data, actorUser) {
        if (!isSystemAdmin(actorUser)) {
            throw new ForbiddenError('Only System Administrators can register new resources in the catalogue.', 'ERR_FORBIDDEN_CATALOG_ADMIN');
        }

        const {
            resourceCode,
            resourceName,
            resourceType,
            environment = 'PRODUCTION',
            description = '',
            riskLevel = 'MEDIUM',
            maxLeaseDurationDays = 90,
            requiresSecurityApproval = false,
            primaryOwnerUserId = null
        } = data;

        // 1. Validation
        if (!resourceCode || typeof resourceCode !== 'string' || resourceCode.trim().length < 3) {
            throw new ValidationError('Resource Code must be at least 3 characters.');
        }
        const cleanCode = resourceCode.trim().toUpperCase();
        if (!/^[A-Z0-9_-]+$/.test(cleanCode)) {
            throw new ValidationError('Resource Code must contain only uppercase alphanumeric characters, dashes, and underscores.');
        }

        if (!resourceName || typeof resourceName !== 'string' || resourceName.trim().length < 3) {
            throw new ValidationError('Resource Name must be at least 3 characters.');
        }

        if (!resourceType || !VALID_RESOURCE_TYPES.includes(resourceType)) {
            throw new ValidationError(`Invalid Resource Type. Must be one of: ${VALID_RESOURCE_TYPES.join(', ')}.`);
        }

        if (environment && !VALID_ENVIRONMENTS.includes(environment.toUpperCase())) {
            throw new ValidationError(`Invalid Environment. Must be one of: ${VALID_ENVIRONMENTS.join(', ')}.`);
        }

        if (!riskLevel || !VALID_RISK_LEVELS.includes(riskLevel.toUpperCase())) {
            throw new ValidationError(`Invalid Risk Level. Must be one of: ${VALID_RISK_LEVELS.join(', ')}.`);
        }

        const parsedDuration = parseInt(maxLeaseDurationDays, 10);
        if (isNaN(parsedDuration) || parsedDuration < 1 || parsedDuration > 365) {
            throw new ValidationError('Maximum lease duration must be an integer between 1 and 365 days.');
        }

        // 2. Uniqueness check
        const existing = await resourceRepository.findResourceByCode(cleanCode);
        if (existing) {
            throw new ConflictError(`Resource with code '${cleanCode}' already exists in the catalogue.`);
        }

        // 3. Primary Owner validation (if specified)
        if (primaryOwnerUserId) {
            const ownerUser = await userRepository.findUserById(primaryOwnerUserId);
            if (!ownerUser || !ownerUser.is_active) {
                throw new ValidationError('Selected primary owner must be an active registered user.');
            }
        }

        // 4. Persistence
        const finalDescription = formatDescriptionWithEnv(description, environment);
        const createdResource = await resourceRepository.createResource({
            resourceCode: cleanCode,
            resourceName: resourceName.trim(),
            resourceType,
            description: finalDescription,
            riskLevel: riskLevel.toUpperCase(),
            requiresSecurityApproval: Boolean(requiresSecurityApproval || riskLevel.toUpperCase() === 'CRITICAL'),
            maxLeaseDurationDays: parsedDuration,
            isActive: true
        });

        // 5. Assign Primary Owner if provided
        let primaryOwner = null;
        if (primaryOwnerUserId) {
            primaryOwner = await resourceRepository.setPrimaryResourceOwner(createdResource.resource_id, primaryOwnerUserId);
        }

        // 6. Record Audit Event
        await auditRepository.createAuditEvent({
            eventCategory: 'SECURITY_POLICY',
            eventAction: 'RESOURCE_CREATED',
            entityType: 'RESOURCE',
            entityId: createdResource.resource_id,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                resourceId: createdResource.resource_id,
                resourceCode: cleanCode,
                resourceName: createdResource.resource_name,
                resourceType: createdResource.resource_type,
                riskLevel: createdResource.risk_level,
                primaryOwnerUserId: primaryOwnerUserId || null
            }
        });

        logger.info('Resource successfully registered in catalogue', {
            resourceId: createdResource.resource_id,
            resourceCode: cleanCode,
            actorUserId: actorUser.user_id
        });

        return {
            ...parseEnvironment(createdResource),
            primary_owner: primaryOwner
        };
    }

    /**
     * Updates an existing resource in the catalogue.
     * Allowed for SYSTEM_ADMIN or designated RESOURCE_OWNER.
     * @param {string} resourceId
     * @param {object} data
     * @param {object} actorUser
     */
    async updateResource(resourceId, data, actorUser) {
        if (!resourceId) throw new ValidationError('Resource ID is required.');

        const canManage = await canManageResource(actorUser, resourceId);
        if (!canManage) {
            throw new ForbiddenError('You do not have permission to modify this resource.', 'ERR_FORBIDDEN_RESOURCE_MANAGE');
        }

        const existing = await resourceRepository.findResourceById(resourceId);
        if (!existing) {
            throw new NotFoundError('Resource');
        }

        const updates = {};

        if (data.resourceName !== undefined) {
            if (typeof data.resourceName !== 'string' || data.resourceName.trim().length < 3) {
                throw new ValidationError('Resource Name must be at least 3 characters.');
            }
            updates.resourceName = data.resourceName.trim();
        }

        if (data.resourceType !== undefined) {
            if (!VALID_RESOURCE_TYPES.includes(data.resourceType)) {
                throw new ValidationError(`Invalid Resource Type. Must be one of: ${VALID_RESOURCE_TYPES.join(', ')}.`);
            }
            updates.resourceType = data.resourceType;
        }

        if (data.environment !== undefined || data.description !== undefined) {
            const currentParsed = parseEnvironment(existing);
            const env = data.environment || currentParsed.environment;
            const desc = data.description !== undefined ? data.description : currentParsed.clean_description;
            updates.description = formatDescriptionWithEnv(desc, env);
        }

        if (data.riskLevel !== undefined) {
            const cleanRisk = data.riskLevel.toUpperCase();
            if (!VALID_RISK_LEVELS.includes(cleanRisk)) {
                throw new ValidationError(`Invalid Risk Level. Must be one of: ${VALID_RISK_LEVELS.join(', ')}.`);
            }
            updates.riskLevel = cleanRisk;
        }

        if (data.maxLeaseDurationDays !== undefined) {
            const parsedDuration = parseInt(data.maxLeaseDurationDays, 10);
            if (isNaN(parsedDuration) || parsedDuration < 1 || parsedDuration > 365) {
                throw new ValidationError('Maximum lease duration must be an integer between 1 and 365 days.');
            }
            updates.maxLeaseDurationDays = parsedDuration;
        }

        if (data.requiresSecurityApproval !== undefined) {
            updates.requiresSecurityApproval = Boolean(data.requiresSecurityApproval);
        }

        if (data.isActive !== undefined) {
            // Only SYSTEM_ADMIN can toggle active/inactive status
            if (!isSystemAdmin(actorUser)) {
                throw new ForbiddenError('Only System Administrators can change resource activation status.', 'ERR_FORBIDDEN_STATUS_CHANGE');
            }
            updates.isActive = Boolean(data.isActive);
        }

        // Apply primary owner update if provided (Admin only)
        let primaryOwner = null;
        if (data.primaryOwnerUserId !== undefined && isSystemAdmin(actorUser)) {
            if (data.primaryOwnerUserId) {
                const ownerUser = await userRepository.findUserById(data.primaryOwnerUserId);
                if (!ownerUser || !ownerUser.is_active) {
                    throw new ValidationError('Selected primary owner must be an active registered user.');
                }
            }
            primaryOwner = await resourceRepository.setPrimaryResourceOwner(resourceId, data.primaryOwnerUserId || null);
        }

        const updated = await resourceRepository.updateResource(resourceId, updates);

        await auditRepository.createAuditEvent({
            eventCategory: 'SECURITY_POLICY',
            eventAction: 'RESOURCE_UPDATED',
            entityType: 'RESOURCE',
            entityId: resourceId,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                resourceId,
                updatedFields: Object.keys(updates)
            }
        });

        return {
            ...parseEnvironment(updated),
            primary_owner: primaryOwner
        };
    }

    /**
     * Deactivates or activates a resource in the catalogue.
     * Requires SYSTEM_ADMIN role.
     * @param {string} resourceId
     * @param {boolean} isActive
     * @param {object} actorUser
     */
    async setResourceStatus(resourceId, isActive, actorUser) {
        if (!isSystemAdmin(actorUser)) {
            throw new ForbiddenError('Only System Administrators can change resource activation status.', 'ERR_FORBIDDEN_STATUS_CHANGE');
        }
        if (!resourceId) throw new ValidationError('Resource ID is required.');

        const existing = await resourceRepository.findResourceById(resourceId);
        if (!existing) throw new NotFoundError('Resource');

        const updated = await resourceRepository.setResourceStatus(resourceId, Boolean(isActive));

        await auditRepository.createAuditEvent({
            eventCategory: 'SECURITY_POLICY',
            eventAction: isActive ? 'RESOURCE_ACTIVATED' : 'RESOURCE_DEACTIVATED',
            entityType: 'RESOURCE',
            entityId: resourceId,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                resourceId,
                previousStatus: existing.is_active,
                newStatus: Boolean(isActive)
            }
        });

        return parseEnvironment(updated);
    }

    /**
     * Lists entitlements belonging to a resource.
     * @param {string} resourceId
     * @param {object} filter
     * @param {object} actorUser
     */
    async listEntitlements(resourceId, filter = {}, actorUser = null) {
        if (!actorUser) {
            throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
        }
        if (!resourceId) throw new ValidationError('Resource ID is required.');

        const resource = await resourceRepository.findResourceById(resourceId);
        if (!resource) throw new NotFoundError('Resource');

        const entitlements = await resourceRepository.listEntitlementsByResourceId(resourceId);

        let filtered = entitlements;
        if (filter.isActive !== undefined && filter.isActive !== null && filter.isActive !== 'all') {
            const activeBool = filter.isActive === true || filter.isActive === 'true';
            filtered = filtered.filter(e => e.is_active === activeBool);
        } else if (!isSystemAdmin(actorUser)) {
            // Contractors & sponsors view active entitlements only
            filtered = filtered.filter(e => e.is_active);
        }

        return filtered;
    }

    /**
     * Adds an entitlement under a resource.
     * Requires SYSTEM_ADMIN or designated RESOURCE_OWNER.
     * @param {string} resourceId
     * @param {object} data
     * @param {object} actorUser
     */
    async createEntitlement(resourceId, data, actorUser) {
        if (!resourceId) throw new ValidationError('Resource ID is required.');

        const canManage = await canManageResource(actorUser, resourceId);
        if (!canManage) {
            throw new ForbiddenError('You do not have permission to create entitlements for this resource.', 'ERR_FORBIDDEN_RESOURCE_MANAGE');
        }

        const resource = await resourceRepository.findResourceById(resourceId);
        if (!resource) throw new NotFoundError('Resource');

        const {
            entitlementCode,
            entitlementName,
            description = '',
            sensitivityLevel = 'MEDIUM',
            isActive = true
        } = data;

        if (!entitlementCode || typeof entitlementCode !== 'string' || entitlementCode.trim().length < 2) {
            throw new ValidationError('Entitlement Code must be at least 2 characters.');
        }
        const cleanCode = entitlementCode.trim().toUpperCase();
        if (!/^[A-Z0-9_-]+$/.test(cleanCode)) {
            throw new ValidationError('Entitlement Code must contain only uppercase alphanumeric characters, dashes, and underscores.');
        }

        if (!entitlementName || typeof entitlementName !== 'string' || entitlementName.trim().length < 2) {
            throw new ValidationError('Entitlement Name must be at least 2 characters.');
        }

        const cleanSensitivity = (sensitivityLevel || 'MEDIUM').toUpperCase();
        if (!VALID_SENSITIVITY_LEVELS.includes(cleanSensitivity)) {
            throw new ValidationError(`Invalid Sensitivity Level. Must be one of: ${VALID_SENSITIVITY_LEVELS.join(', ')}.`);
        }

        // Uniqueness under resource
        const existingEnt = await resourceRepository.findEntitlementByCode(resourceId, cleanCode);
        if (existingEnt) {
            throw new ConflictError(`Entitlement with code '${cleanCode}' already exists for this resource.`);
        }

        const created = await resourceRepository.createEntitlement({
            resourceId,
            entitlementCode: cleanCode,
            entitlementName: entitlementName.trim(),
            description: description ? description.trim() : null,
            sensitivityLevel: cleanSensitivity,
            isActive: Boolean(isActive)
        });

        await auditRepository.createAuditEvent({
            eventCategory: 'SECURITY_POLICY',
            eventAction: 'ENTITLEMENT_CREATED',
            entityType: 'ENTITLEMENT',
            entityId: created.entitlement_id,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                entitlementId: created.entitlement_id,
                resourceId,
                entitlementCode: cleanCode,
                entitlementName: created.entitlement_name,
                sensitivityLevel: created.sensitivity_level
            }
        });

        return created;
    }

    /**
     * Updates an entitlement.
     * Requires SYSTEM_ADMIN or owner of the parent resource.
     * @param {string} entitlementId
     * @param {object} data
     * @param {object} actorUser
     */
    async updateEntitlement(entitlementId, data, actorUser) {
        if (!entitlementId) throw new ValidationError('Entitlement ID is required.');

        const entitlement = await resourceRepository.findEntitlementById(entitlementId);
        if (!entitlement) throw new NotFoundError('Entitlement');

        const canManage = await canManageResource(actorUser, entitlement.resource_id);
        if (!canManage) {
            throw new ForbiddenError('You do not have permission to modify entitlements for this resource.', 'ERR_FORBIDDEN_RESOURCE_MANAGE');
        }

        const updates = {};

        if (data.entitlementName !== undefined) {
            if (typeof data.entitlementName !== 'string' || data.entitlementName.trim().length < 2) {
                throw new ValidationError('Entitlement Name must be at least 2 characters.');
            }
            updates.entitlementName = data.entitlementName.trim();
        }

        if (data.description !== undefined) {
            updates.description = data.description ? data.description.trim() : null;
        }

        if (data.sensitivityLevel !== undefined) {
            const cleanSensitivity = data.sensitivityLevel.toUpperCase();
            if (!VALID_SENSITIVITY_LEVELS.includes(cleanSensitivity)) {
                throw new ValidationError(`Invalid Sensitivity Level. Must be one of: ${VALID_SENSITIVITY_LEVELS.join(', ')}.`);
            }
            updates.sensitivityLevel = cleanSensitivity;
        }

        if (data.isActive !== undefined) {
            updates.isActive = Boolean(data.isActive);
        }

        const updated = await resourceRepository.updateEntitlement(entitlementId, updates);

        await auditRepository.createAuditEvent({
            eventCategory: 'SECURITY_POLICY',
            eventAction: 'ENTITLEMENT_UPDATED',
            entityType: 'ENTITLEMENT',
            entityId: entitlementId,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                entitlementId,
                resourceId: entitlement.resource_id,
                updatedFields: Object.keys(updates)
            }
        });

        return updated;
    }

    /**
     * Activates or deactivates an entitlement.
     * Requires SYSTEM_ADMIN or owner of the parent resource.
     * @param {string} entitlementId
     * @param {boolean} isActive
     * @param {object} actorUser
     */
    async setEntitlementStatus(entitlementId, isActive, actorUser) {
        if (!entitlementId) throw new ValidationError('Entitlement ID is required.');

        const entitlement = await resourceRepository.findEntitlementById(entitlementId);
        if (!entitlement) throw new NotFoundError('Entitlement');

        const canManage = await canManageResource(actorUser, entitlement.resource_id);
        if (!canManage) {
            throw new ForbiddenError('You do not have permission to change entitlement status for this resource.', 'ERR_FORBIDDEN_RESOURCE_MANAGE');
        }

        const updated = await resourceRepository.setEntitlementStatus(entitlementId, Boolean(isActive));

        await auditRepository.createAuditEvent({
            eventCategory: 'SECURITY_POLICY',
            eventAction: isActive ? 'ENTITLEMENT_ACTIVATED' : 'ENTITLEMENT_DEACTIVATED',
            entityType: 'ENTITLEMENT',
            entityId: entitlementId,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                entitlementId,
                resourceId: entitlement.resource_id,
                previousStatus: entitlement.is_active,
                newStatus: Boolean(isActive)
            }
        });

        return updated;
    }

    /**
     * Assigns a secondary or delegate owner to a resource.
     * Requires SYSTEM_ADMIN role.
     * @param {string} resourceId
     * @param {object} ownerData { ownerUserId, ownershipType }
     * @param {object} actorUser
     */
    async assignResourceOwner(resourceId, ownerData, actorUser) {
        if (!isSystemAdmin(actorUser)) {
            throw new ForbiddenError('Only System Administrators can assign resource owners.', 'ERR_FORBIDDEN_CATALOG_ADMIN');
        }
        if (!resourceId) throw new ValidationError('Resource ID is required.');

        const resource = await resourceRepository.findResourceById(resourceId);
        if (!resource) throw new NotFoundError('Resource');

        const { ownerUserId, ownershipType = 'DELEGATE' } = ownerData;
        if (!ownerUserId) throw new ValidationError('Owner User ID is required.');

        const user = await userRepository.findUserById(ownerUserId);
        if (!user || !user.is_active) {
            throw new ValidationError('Designated owner must be an active registered user.');
        }

        const validTypes = ['PRIMARY', 'DELEGATE', 'TECHNICAL_CONTACT'];
        const cleanType = (ownershipType || 'DELEGATE').toUpperCase();
        if (!validTypes.includes(cleanType)) {
            throw new ValidationError(`Invalid ownership type. Must be one of: ${validTypes.join(', ')}.`);
        }

        if (cleanType === 'PRIMARY') {
            const assigned = await resourceRepository.setPrimaryResourceOwner(resourceId, ownerUserId);
            return assigned;
        }

        const assigned = await resourceRepository.assignResourceOwner(resourceId, ownerUserId, cleanType);

        await auditRepository.createAuditEvent({
            eventCategory: 'SECURITY_POLICY',
            eventAction: 'RESOURCE_OWNER_ASSIGNED',
            entityType: 'RESOURCE',
            entityId: resourceId,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                resourceId,
                ownerUserId,
                ownershipType: cleanType
            }
        });

        return assigned;
    }

    /**
     * Removes an owner from a resource.
     * Requires SYSTEM_ADMIN role.
     * @param {string} resourceId
     * @param {string} ownerUserId
     * @param {object} actorUser
     */
    async removeResourceOwner(resourceId, ownerUserId, actorUser) {
        if (!isSystemAdmin(actorUser)) {
            throw new ForbiddenError('Only System Administrators can remove resource owners.', 'ERR_FORBIDDEN_CATALOG_ADMIN');
        }
        if (!resourceId) throw new ValidationError('Resource ID is required.');
        if (!ownerUserId) throw new ValidationError('Owner User ID is required.');

        const removed = await resourceRepository.removeResourceOwner(resourceId, ownerUserId);
        if (!removed) {
            throw new NotFoundError('Resource Owner assignment');
        }

        await auditRepository.createAuditEvent({
            eventCategory: 'SECURITY_POLICY',
            eventAction: 'RESOURCE_OWNER_REMOVED',
            entityType: 'RESOURCE',
            entityId: resourceId,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                resourceId,
                ownerUserId
            }
        });

        return { success: true };
    }
}

module.exports = new CatalogService();
