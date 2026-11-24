/**
 * AccessLease — Internal User Governance & Registration Service
 * Orchestrates administrative user onboarding, role assignments, and account status management.
 */

const db = require('../config/database');
const userRepository = require('../repositories/userRepository');
const roleRepository = require('../repositories/roleRepository');
const auditRepository = require('../repositories/auditRepository');
const { hasRole } = require('../security/permissionPolicy');
const { ValidationError, ConflictError, ForbiddenError, NotFoundError } = require('../utils/errors');
const logger = require('../utils/logger');

const VALID_GOVERNANCE_ROLES = [
    'SYSTEM_ADMIN',
    'SECURITY_OFFICER',
    'INTERNAL_SPONSOR',
    'RESOURCE_OWNER',
    'COMPLIANCE_AUDITOR'
];

/**
 * Registers an internal application user with assigned governance roles.
 * Atomic transaction guarantees user and role assignments are committed together.
 * 
 * @param {object} userData
 * @param {object} actorUser Authenticated SYSTEM_ADMIN profile
 * @returns {Promise<object>} Created user with roles
 */
async function registerUser(userData, actorUser) {
    // 1. Authorization: strictly SYSTEM_ADMIN
    if (!actorUser || !hasRole(actorUser.roles, 'SYSTEM_ADMIN')) {
        throw new ForbiddenError(
            'Access denied: Action requires one of the following roles: SYSTEM_ADMIN.',
            'ERR_FORBIDDEN_ROLE'
        );
    }

    if (!userData || typeof userData !== 'object') {
        throw new ValidationError('User registration data must be provided.', [], 'ERR_VALIDATION_FAILED');
    }

    // 2. Validate email
    if (!userData.email || typeof userData.email !== 'string') {
        throw new ValidationError('Email address is required.', [{ field: 'email', message: 'Email address is required.' }], 'ERR_VALIDATION_FAILED');
    }
    const email = userData.email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email) || email.length > 256) {
        throw new ValidationError('A valid corporate email address is required (max 256 characters).', [{ field: 'email', message: 'Invalid email format.' }], 'ERR_VALIDATION_FAILED');
    }

    // 3. Validate display name
    const rawName = userData.displayName || userData.display_name;
    if (!rawName || typeof rawName !== 'string' || !rawName.trim()) {
        throw new ValidationError('Full display name is required.', [{ field: 'display_name', message: 'Name is required.' }], 'ERR_VALIDATION_FAILED');
    }
    const displayName = rawName.trim();
    if (displayName.length < 2 || displayName.length > 128) {
        throw new ValidationError('Display name must be between 2 and 128 characters.', [{ field: 'display_name', message: 'Name length invalid.' }], 'ERR_VALIDATION_FAILED');
    }

    // 4. Validate Microsoft Entra Object ID
    const rawOid = userData.entraObjectId || userData.entra_object_id;
    if (!rawOid || typeof rawOid !== 'string' || !rawOid.trim()) {
        throw new ValidationError('Microsoft Entra Object ID (oid) is required.', [{ field: 'entra_object_id', message: 'Entra Object ID is required.' }], 'ERR_VALIDATION_FAILED');
    }
    const entraObjectId = rawOid.trim();
    if (entraObjectId.length < 3 || entraObjectId.length > 64 || entraObjectId.toUpperCase().startsWith('LOCAL-CONTRACTOR-')) {
        throw new ValidationError('Invalid Microsoft Entra Object ID format.', [{ field: 'entra_object_id', message: 'Invalid Entra Object ID format.' }], 'ERR_VALIDATION_FAILED');
    }

    // 5. Department (optional)
    const rawDept = userData.department;
    const department = (typeof rawDept === 'string' && rawDept.trim()) ? rawDept.trim().substring(0, 100) : null;

    // 6. Assigned governance roles
    const rawRoles = userData.roleCodes || userData.roles || userData.role_codes;
    if (!Array.isArray(rawRoles) || rawRoles.length === 0) {
        throw new ValidationError('At least one governance role must be assigned.', [{ field: 'roles', message: 'Roles array cannot be empty.' }], 'ERR_VALIDATION_FAILED');
    }
    const roleCodes = rawRoles.map(r => typeof r === 'string' ? r.trim().toUpperCase() : (r && r.role_code ? r.role_code.trim().toUpperCase() : ''));
    for (const code of roleCodes) {
        if (!VALID_GOVERNANCE_ROLES.includes(code)) {
            throw new ValidationError(
                `Invalid role '${code}'. Allowed governance roles: ${VALID_GOVERNANCE_ROLES.join(', ')}.`,
                [{ field: 'roles', message: `Unrecognized or unauthorized role code '${code}'.` }],
                'ERR_VALIDATION_FAILED'
            );
        }
    }
    const uniqueRoleCodes = Array.from(new Set(roleCodes));

    // Parse first and last names for dbo.users schema
    const nameParts = displayName.split(/\s+/);
    let firstName, lastName;
    if (nameParts.length === 1) {
        firstName = nameParts[0];
        lastName = 'Employee';
    } else {
        lastName = nameParts.pop();
        firstName = nameParts.join(' ');
    }
    firstName = firstName.substring(0, 64);
    lastName = lastName.substring(0, 64);

    // 7. Pre-check uniqueness before transaction
    const existingEmail = await userRepository.findUserByEmail(email);
    if (existingEmail) {
        throw new ConflictError(`A user with email '${email}' is already registered.`, 'ERR_USER_EXISTS');
    }
    const existingOid = await userRepository.findUserByEntraObjectId(entraObjectId);
    if (existingOid) {
        throw new ConflictError(`A user with Entra Object ID '${entraObjectId}' is already registered.`, 'ERR_IDENTITY_EXISTS');
    }

    // 8. Execute atomic transaction
    const createdUser = await db.withTransaction(async (transaction) => {
        // Concurrency double check inside transaction
        const inTxEmail = await userRepository.findUserByEmail(email, transaction);
        if (inTxEmail) {
            throw new ConflictError(`A user with email '${email}' is already registered.`, 'ERR_USER_EXISTS');
        }
        const inTxOid = await userRepository.findUserByEntraObjectId(entraObjectId, transaction);
        if (inTxOid) {
            throw new ConflictError(`A user with Entra Object ID '${entraObjectId}' is already registered.`, 'ERR_IDENTITY_EXISTS');
        }

        const newUser = await userRepository.createUser({
            entraObjectId,
            email,
            firstName,
            lastName,
            displayName,
            userType: 'INTERNAL_EMPLOYEE',
            department,
            isActive: true
        }, transaction);

        const assignedRoles = [];
        for (const code of uniqueRoleCodes) {
            const role = await roleRepository.findRoleByCode(code, transaction);
            if (!role) {
                throw new ValidationError(`Role '${code}' does not exist in the database.`, [{ field: 'roles', message: `Role '${code}' not found.` }], 'ERR_VALIDATION_FAILED');
            }
            await roleRepository.assignRoleToUser(newUser.user_id, role.role_id, actorUser.user_id, transaction);
            assignedRoles.push({
                role_id: role.role_id,
                role_code: role.role_code,
                role_name: role.role_name
            });
        }

        // Record immutable audit event in dbo.audit_events
        await auditRepository.createAuditEvent({
            eventCategory: 'SECURITY_POLICY',
            eventAction: 'USER_REGISTERED',
            entityType: 'USER',
            entityId: newUser.user_id,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                userId: newUser.user_id,
                email: newUser.email,
                displayName: newUser.display_name,
                entraObjectId: newUser.entra_object_id,
                department: newUser.department,
                userType: newUser.user_type,
                roles: uniqueRoleCodes,
                registeredBy: actorUser.user_id
            }
        }, transaction);

        return {
            ...newUser,
            roles: assignedRoles
        };
    });

    logger.info('Internal user registered successfully', {
        userId: createdUser.user_id,
        email: createdUser.email,
        roles: uniqueRoleCodes,
        registeredBy: actorUser.user_id
    });

    return createdUser;
}

/**
 * Lists internal application users with assigned roles and pagination.
 * @param {object} filter
 * @param {object} actorUser
 * @returns {Promise<{ users: Array, total: number, limit: number, offset: number }>}
 */
async function listUsers(filter = {}, actorUser) {
    if (!actorUser || !hasRole(actorUser.roles, 'SYSTEM_ADMIN')) {
        throw new ForbiddenError(
            'Access denied: Action requires one of the following roles: SYSTEM_ADMIN.',
            'ERR_FORBIDDEN_ROLE'
        );
    }

    const limit = Math.min(100, Math.max(1, parseInt(filter.limit, 10) || 50));
    const offset = Math.max(0, parseInt(filter.offset, 10) || 0);
    const isActive = filter.isActive !== undefined && filter.isActive !== null
        ? (filter.isActive === 'true' || filter.isActive === true)
        : undefined;
    const search = filter.search || null;
    const userType = filter.userType || 'INTERNAL_EMPLOYEE';

    const users = await userRepository.listUsers({ userType, isActive, search, limit, offset });
    const total = await userRepository.countUsers({ userType, isActive, search });

    return {
        users,
        total,
        limit,
        offset
    };
}

/**
 * Activates or deactivates an application user.
 * @param {string} userId Uniqueidentifier GUID
 * @param {boolean} isActive
 * @param {object} actorUser
 * @returns {Promise<object>}
 */
async function setUserStatus(userId, isActive, actorUser) {
    if (!actorUser || !hasRole(actorUser.roles, 'SYSTEM_ADMIN')) {
        throw new ForbiddenError(
            'Access denied: Action requires one of the following roles: SYSTEM_ADMIN.',
            'ERR_FORBIDDEN_ROLE'
        );
    }

    if (!userId || typeof userId !== 'string') {
        throw new ValidationError('User ID is required.', [{ field: 'user_id', message: 'User ID is required.' }], 'ERR_VALIDATION_FAILED');
    }

    const cleanUserId = userId.trim();
    // Prevent self-deactivation
    if (actorUser.user_id && cleanUserId.toLowerCase() === actorUser.user_id.toLowerCase() && !isActive) {
        throw new ValidationError('Administrators cannot deactivate their own account.', [{ field: 'user_id', message: 'Self-deactivation is prohibited.' }], 'ERR_SELF_DEACTIVATION_FORBIDDEN');
    }

    const targetUser = await userRepository.findUserById(cleanUserId);
    if (!targetUser) {
        throw new NotFoundError('User');
    }

    const updatedUser = await userRepository.updateUserStatus(cleanUserId, isActive);

    await auditRepository.createAuditEvent({
        eventCategory: 'SECURITY_POLICY',
        eventAction: isActive ? 'USER_ACTIVATED' : 'USER_DEACTIVATED',
        entityType: 'USER',
        entityId: cleanUserId,
        actorUserId: actorUser.user_id,
        actorType: 'USER',
        eventPayload: {
            userId: cleanUserId,
            email: targetUser.email,
            isActive: Boolean(isActive),
            updatedBy: actorUser.user_id
        }
    });

    logger.info('User status updated', {
        userId: cleanUserId,
        isActive: Boolean(isActive),
        updatedBy: actorUser.user_id
    });

    return updatedUser;
}

/**
 * Returns available governance roles for user assignment.
 * @param {object} actorUser
 * @returns {Promise<Array>}
 */
async function listAvailableRoles(actorUser) {
    if (!actorUser || !hasRole(actorUser.roles, 'SYSTEM_ADMIN')) {
        throw new ForbiddenError(
            'Access denied: Action requires one of the following roles: SYSTEM_ADMIN.',
            'ERR_FORBIDDEN_ROLE'
        );
    }

    const allRoles = await roleRepository.listRoles();
    return allRoles.filter(r => VALID_GOVERNANCE_ROLES.includes(r.role_code));
}

module.exports = {
    VALID_GOVERNANCE_ROLES,
    registerUser,
    listUsers,
    setUserStatus,
    listAvailableRoles
};
