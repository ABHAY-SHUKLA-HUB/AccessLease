/**
 * AccessLease — Contextual & Resource-Level Authorization (ABAC)
 * Enforces dynamic record ownership, resource assignment, and separation-of-duties rules.
 */

const { resourceRepository, engagementRepository, requestRepository } = require('../repositories');
const { hasAnyRole, isStrictlyReadOnlyAuditor } = require('./permissionPolicy');
const { ForbiddenError, NotFoundError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Validates whether an authenticated user is authorized to access contractor-specific data.
 * Rules:
 * - A CONTRACTOR can ONLY view their own records (user_id === targetContractorUserId).
 * - An INTERNAL_SPONSOR can view records if they are the assigned sponsor for the engagement,
 *   or if they hold governance oversight roles.
 * - SECURITY_OFFICER, SYSTEM_ADMIN, and COMPLIANCE_AUDITOR have platform-wide read oversight.
 * 
 * @param {object} user Authenticated user context
 * @param {string} targetContractorUserId GUID of the contractor
 * @param {object|string} [engagementOrId=null] Optional engagement object or GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<boolean>}
 */
async function canAccessContractorData(user, targetContractorUserId, engagementOrId = null, transaction = null) {
    if (!user || !targetContractorUserId) return false;

    const userRoles = user.roles || [];

    // 1. Governance / Oversight roles have cross-contractor access
    if (hasAnyRole(userRoles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR'])) {
        return true;
    }

    // 2. Contractor Self-Access Rule: Contractor can strictly only access their own user records
    if (hasAnyRole(userRoles, ['CONTRACTOR'])) {
        return user.user_id.toLowerCase() === targetContractorUserId.toLowerCase();
    }

    // 3. Sponsor Relationship Check: Must be the sponsor of the contractor's engagement
    if (hasAnyRole(userRoles, ['INTERNAL_SPONSOR'])) {
        if (!engagementOrId) {
            // Check if user sponsors ANY active engagement for this contractor
            const engagements = await engagementRepository.findEngagementsByContractorId(targetContractorUserId, transaction);
            return engagements.some(e => e.sponsor_user_id.toLowerCase() === user.user_id.toLowerCase());
        }

        const engagement = typeof engagementOrId === 'string'
            ? await engagementRepository.findEngagementById(engagementOrId, transaction)
            : engagementOrId;

        if (!engagement) return false;
        return engagement.sponsor_user_id.toLowerCase() === user.user_id.toLowerCase();
    }

    return false;
}

/**
 * Verifies whether the authenticated user is an authorized owner of a resource in dbo.resource_owners.
 * System Administrators bypass resource-specific ownership.
 * 
 * @param {object} user Authenticated user context
 * @param {string} resourceId GUID of the target resource
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<boolean>}
 */
async function isAuthorizedResourceOwner(user, resourceId, transaction = null) {
    if (!user || !resourceId) return false;

    const userRoles = user.roles || [];
    if (hasAnyRole(userRoles, ['SYSTEM_ADMIN'])) {
        return true;
    }

    if (!hasAnyRole(userRoles, ['RESOURCE_OWNER'])) {
        return false;
    }

    const owners = await resourceRepository.getResourceOwners(resourceId, transaction);
    const userIdLower = user.user_id.toLowerCase();

    return owners.some(o => o.owner_user_id.toLowerCase() === userIdLower);
}

/**
 * Enforces Critical Industry Requirement 1: Separation of Duties (SoD).
 * A requester MUST NOT approve their own access request under any circumstance,
 * even if they hold an approval-eligible role (e.g. Sponsor or Resource Owner).
 * 
 * @param {object} user Authenticated user context
 * @param {object|string} requestOrId Access request object or GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<boolean>} True if user is NOT the requester and may proceed to role evaluation
 */
async function validateSeparationOfDuties(user, requestOrId, transaction = null) {
    if (!user || !requestOrId) return false;

    const request = typeof requestOrId === 'string'
        ? await requestRepository.findRequestById(requestOrId, transaction)
        : requestOrId;

    if (!request) {
        throw new NotFoundError('Access Request');
    }

    // SoD Check: Requester cannot approve own request
    if (request.requested_by_user_id.toLowerCase() === user.user_id.toLowerCase()) {
        logger.warn('Separation of duties violation blocked: User attempted to approve their own request', {
            userId: user.user_id,
            requestId: request.request_id,
            requestNumber: request.request_number
        });
        return false;
    }

    return true;
}

/**
 * Validates that an engagement is currently active and within valid date boundaries.
 * @param {object|string} engagementOrId 
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<{ isValid: boolean, reason?: string }>}
 */
async function validateEngagementStatus(engagementOrId, transaction = null) {
    const engagement = typeof engagementOrId === 'string'
        ? await engagementRepository.findEngagementById(engagementOrId, transaction)
        : engagementOrId;

    if (!engagement) {
        return { isValid: false, reason: 'Engagement not found.' };
    }

    if (engagement.status !== 'ACTIVE') {
        return { isValid: false, reason: `Engagement is in status ${engagement.status}. Must be ACTIVE.` };
    }

    const todayStr = new Date().toISOString().split('T')[0];
    const startDateStr = typeof engagement.start_date === 'string' ? engagement.start_date : engagement.start_date.toISOString().split('T')[0];
    const endDateStr = typeof engagement.end_date === 'string' ? engagement.end_date : engagement.end_date.toISOString().split('T')[0];

    if (todayStr < startDateStr) {
        return { isValid: false, reason: 'Engagement has not yet started.' };
    }

    if (todayStr > endDateStr) {
        return { isValid: false, reason: 'Engagement has expired.' };
    }

    return { isValid: true };
}

module.exports = {
    canAccessContractorData,
    isAuthorizedResourceOwner,
    validateSeparationOfDuties,
    validateEngagementStatus
};

