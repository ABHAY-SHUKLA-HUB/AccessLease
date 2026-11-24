/**
 * AccessLease — Canonical Security Permissions
 * Defines all granular permission strings used across the enterprise platform.
 */

const Permissions = Object.freeze({
    // User Profile
    PROFILE_READ_SELF: 'profile:read:self',

    // Contractor Engagements
    ENGAGEMENT_READ_SELF: 'engagement:read:self',
    ENGAGEMENT_READ_ALL: 'engagement:read:all',
    ENGAGEMENT_CREATE: 'engagement:create',
    ENGAGEMENT_MANAGE: 'engagement:manage',

    // Resources & Entitlements
    RESOURCE_READ_ALL: 'resource:read:all',
    RESOURCE_MANAGE: 'resource:manage',
    ENTITLEMENT_READ_ALL: 'entitlement:read:all',
    ENTITLEMENT_MANAGE: 'entitlement:manage',

    // Access Requests
    REQUEST_READ_SELF: 'request:read:self',
    REQUEST_READ_ALL: 'request:read:all',
    REQUEST_CREATE: 'request:create',
    REQUEST_APPROVE_SPONSOR: 'request:approve:sponsor',
    REQUEST_APPROVE_OWNER: 'request:approve:owner',
    REQUEST_APPROVE_SECURITY: 'request:approve:security',

    // Access Grants & Exposure Queue
    GRANT_READ_SELF: 'grant:read:self',
    GRANT_READ_ALL: 'grant:read:all',
    GRANT_ACTIVATE: 'grant:activate',
    EXPOSURE_QUEUE_READ: 'exposure_queue:read',

    // Revocation & Security Operations
    REVOCATION_TRIGGER: 'revocation:trigger',
    REVOCATION_MANAGE: 'revocation:manage',
    SECURITY_POLICY_OVERRIDE: 'security_policy:override',

    // Access Reviews & Compliance
    REVIEW_READ_ALL: 'review:read:all',
    REVIEW_CREATE: 'review:create',
    REVIEW_DECIDE: 'review:decide',
    AUDIT_READ_ALL: 'audit:read:all',
    COMPLIANCE_EXPORT: 'compliance:export',

    // System Administration
    SYSTEM_ADMIN: 'system:admin',
    ROLE_ASSIGN: 'role:assign'
});

module.exports = Permissions;

