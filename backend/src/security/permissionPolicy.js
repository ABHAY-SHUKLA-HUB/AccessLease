/**
 * AccessLease — Role-Permission Policy Engine
 * Maps enterprise database roles to granular permissions using least-privilege principles.
 */

const Permissions = require('./permissions');

/**
 * Standard Role-to-Permissions Mapping for the 6 Seeded Roles.
 */
const ROLE_PERMISSIONS = Object.freeze({
    CONTRACTOR: Object.freeze([
        Permissions.PROFILE_READ_SELF,
        Permissions.ENGAGEMENT_READ_SELF,
        Permissions.REQUEST_READ_SELF,
        Permissions.GRANT_READ_SELF
    ]),

    INTERNAL_SPONSOR: Object.freeze([
        Permissions.PROFILE_READ_SELF,
        Permissions.ENGAGEMENT_READ_SELF,
        Permissions.ENGAGEMENT_READ_ALL,
        Permissions.ENGAGEMENT_CREATE,
        Permissions.ENGAGEMENT_MANAGE,
        Permissions.REQUEST_READ_SELF,
        Permissions.REQUEST_READ_ALL,
        Permissions.REQUEST_CREATE,
        Permissions.REQUEST_APPROVE_SPONSOR,
        Permissions.RESOURCE_READ_ALL,
        Permissions.ENTITLEMENT_READ_ALL,
        Permissions.GRANT_READ_SELF,
        Permissions.GRANT_READ_ALL
    ]),

    RESOURCE_OWNER: Object.freeze([
        Permissions.PROFILE_READ_SELF,
        Permissions.RESOURCE_READ_ALL,
        Permissions.ENTITLEMENT_READ_ALL,
        Permissions.REQUEST_READ_ALL,
        Permissions.REQUEST_APPROVE_OWNER,
        Permissions.GRANT_READ_ALL,
        Permissions.REVIEW_READ_ALL,
        Permissions.REVIEW_DECIDE
    ]),

    SECURITY_OFFICER: Object.freeze([
        Permissions.PROFILE_READ_SELF,
        Permissions.ENGAGEMENT_READ_ALL,
        Permissions.RESOURCE_READ_ALL,
        Permissions.ENTITLEMENT_READ_ALL,
        Permissions.REQUEST_READ_ALL,
        Permissions.REQUEST_APPROVE_SECURITY,
        Permissions.GRANT_READ_ALL,
        Permissions.GRANT_ACTIVATE,
        Permissions.EXPOSURE_QUEUE_READ,
        Permissions.REVOCATION_TRIGGER,
        Permissions.REVOCATION_MANAGE,
        Permissions.SECURITY_POLICY_OVERRIDE,
        Permissions.REVIEW_READ_ALL,
        Permissions.REVIEW_CREATE,
        Permissions.REVIEW_DECIDE,
        Permissions.AUDIT_READ_ALL,
        Permissions.COMPLIANCE_EXPORT
    ]),

    COMPLIANCE_AUDITOR: Object.freeze([
        Permissions.PROFILE_READ_SELF,
        Permissions.ENGAGEMENT_READ_ALL,
        Permissions.RESOURCE_READ_ALL,
        Permissions.ENTITLEMENT_READ_ALL,
        Permissions.REQUEST_READ_ALL,
        Permissions.GRANT_READ_ALL,
        Permissions.EXPOSURE_QUEUE_READ,
        Permissions.REVIEW_READ_ALL,
        Permissions.AUDIT_READ_ALL,
        Permissions.COMPLIANCE_EXPORT
    ]),

    SYSTEM_ADMIN: Object.freeze(Object.values(Permissions))
});

/**
 * Computes the union set of effective permissions for a list of assigned role codes.
 * Returns an empty set if roleCodes is empty or unrecognized (fail-closed, deny-by-default).
 * 
 * @param {Array<string>|Array<{ role_code: string }>} roles Array of role code strings or objects
 * @returns {Set<string>} Set of effective permission strings
 */
function getEffectivePermissions(roles = []) {
    const permissionSet = new Set();
    if (!Array.isArray(roles) || roles.length === 0) {
        return permissionSet;
    }

    for (const r of roles) {
        const code = (typeof r === 'string' ? r : r.role_code || '').trim().toUpperCase();
        const rolePerms = ROLE_PERMISSIONS[code];
        if (rolePerms) {
            for (const perm of rolePerms) {
                permissionSet.add(perm);
            }
        }
    }

    return permissionSet;
}

/**
 * Checks if the assigned roles grant a specific permission.
 * @param {Array<string>|Array<{ role_code: string }>} roles 
 * @param {string} permission 
 * @returns {boolean}
 */
function hasPermission(roles, permission) {
    if (!permission) return false;
    const perms = getEffectivePermissions(roles);
    return perms.has(permission);
}

/**
 * Checks if the assigned roles grant any of the required permissions.
 * @param {Array<string>|Array<{ role_code: string }>} roles 
 * @param {Array<string>} requiredPermissions 
 * @returns {boolean}
 */
function hasAnyPermission(roles, requiredPermissions = []) {
    if (!Array.isArray(requiredPermissions) || requiredPermissions.length === 0) return false;
    const perms = getEffectivePermissions(roles);
    return requiredPermissions.some(p => perms.has(p));
}

/**
 * Checks if the assigned roles grant all of the required permissions.
 * @param {Array<string>|Array<{ role_code: string }>} roles 
 * @param {Array<string>} requiredPermissions 
 * @returns {boolean}
 */
function hasAllPermissions(roles, requiredPermissions = []) {
    if (!Array.isArray(requiredPermissions) || requiredPermissions.length === 0) return false;
    const perms = getEffectivePermissions(roles);
    return requiredPermissions.every(p => perms.has(p));
}

/**
 * Checks if a user holds a specific role code.
 * @param {Array<string>|Array<{ role_code: string }>} roles 
 * @param {string} roleCode 
 * @returns {boolean}
 */
function hasRole(roles, roleCode) {
    if (!roleCode || !Array.isArray(roles)) return false;
    const target = roleCode.trim().toUpperCase();
    return roles.some(r => {
        const code = (typeof r === 'string' ? r : r.role_code || '').trim().toUpperCase();
        return code === target;
    });
}

/**
 * Checks if a user holds ANY of the specified role codes.
 * @param {Array<string>|Array<{ role_code: string }>} roles 
 * @param {Array<string>} roleCodes 
 * @returns {boolean}
 */
function hasAnyRole(roles, roleCodes = []) {
    if (!Array.isArray(roleCodes) || !Array.isArray(roles)) return false;
    const targets = roleCodes.map(c => c.trim().toUpperCase());
    return roles.some(r => {
        const code = (typeof r === 'string' ? r : r.role_code || '').trim().toUpperCase();
        return targets.includes(code);
    });
}

/**
 * Checks if user is restricted strictly to read-only actions (e.g. only COMPLIANCE_AUDITOR).
 * @param {Array<string>|Array<{ role_code: string }>} roles 
 * @returns {boolean} True if user has ONLY read-only auditor role
 */
function isStrictlyReadOnlyAuditor(roles = []) {
    if (!Array.isArray(roles) || roles.length === 0) return false;
    const codes = roles.map(r => (typeof r === 'string' ? r : r.role_code || '').trim().toUpperCase());
    return codes.includes('COMPLIANCE_AUDITOR') && !codes.some(c => ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'INTERNAL_SPONSOR', 'RESOURCE_OWNER'].includes(c));
}

module.exports = {
    ROLE_PERMISSIONS,
    getEffectivePermissions,
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    hasRole,
    hasAnyRole,
    isStrictlyReadOnlyAuditor
};

