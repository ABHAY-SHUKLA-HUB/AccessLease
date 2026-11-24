/**
 * AccessLease — Access Review & Recertification Service
 * Orchestrates campaign creation, scoped grant inclusion, reviewer authorization,
 * separation-of-duties enforcement, decision recording, and automated revocation routing.
 */

const { withTransaction } = require('../config/database');
const { reviewRepository, auditRepository, userRepository, resourceRepository } = require('../repositories');
const revocationService = require('./revocationService');
const { hasAnyRole, isStrictlyReadOnlyAuditor } = require('../security/permissionPolicy');
const { ValidationError, NotFoundError, ForbiddenError, ConflictError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Creates an access review campaign and automatically populates review items for candidate grants.
 * @param {object} campaignData
 * @param {object} actorUser User initiating the review campaign
 * @returns {Promise<object>} Created review campaign with items count
 */
async function createReviewCampaign(campaignData, actorUser) {
    if (!actorUser) throw new ForbiddenError('Actor user is required to create a review campaign.');

    // Write-access guardrail: Auditors are strictly read-only
    if (isStrictlyReadOnlyAuditor(actorUser.roles)) {
        throw new ForbiddenError(
            'Access denied: Compliance Auditor role is strictly read-only and cannot create review campaigns.',
            'ERR_AUDITOR_READ_ONLY'
        );
    }

    // Role check: Only SYSTEM_ADMIN, SECURITY_OFFICER, or RESOURCE_OWNER can create campaigns
    const canCreate = hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'RESOURCE_OWNER']);
    if (!canCreate) {
        throw new ForbiddenError(
            'Access denied: You do not have permissions to initiate access review campaigns.',
            'ERR_FORBIDDEN_REVIEW_CREATE'
        );
    }

    const {
        reviewName,
        description = null,
        campaignType = 'PERIODIC_RECERTIFICATION',
        startDate = new Date().toISOString(),
        dueDate,
        reviewerUserId = null,
        scope = {}
    } = campaignData;

    if (!reviewName || !reviewName.trim()) {
        throw new ValidationError('Review campaign name is required.');
    }
    if (!dueDate) {
        throw new ValidationError('Review due date is required.');
    }

    const start = new Date(startDate);
    const due = new Date(dueDate);
    if (isNaN(start.getTime()) || isNaN(due.getTime())) {
        throw new ValidationError('Start date and due date must be valid timestamps.');
    }
    if (due <= start) {
        throw new ValidationError('Due date must be strictly after the start date.');
    }

    // Determine assigned reviewer: defaults to designated reviewer, or actorUser
    const assignedReviewerId = reviewerUserId ? reviewerUserId.trim() : actorUser.user_id;
    const reviewer = await userRepository.findUserById(assignedReviewerId);
    if (!reviewer) {
        throw new NotFoundError('Designated reviewer user not found.', 'ERR_REVIEWER_NOT_FOUND');
    }

    // If actor is RESOURCE_OWNER, force scope to resources they own
    let finalScope = { ...scope };
    if (!hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER']) && hasAnyRole(actorUser.roles, ['RESOURCE_OWNER'])) {
        if (!finalScope.resourceId) {
            throw new ValidationError('Resource Owners must specify a resourceId within their assigned ownership scope.');
        }
        const owners = await resourceRepository.getResourceOwners(finalScope.resourceId);
        const isOwner = owners.some(o => o.owner_user_id.toLowerCase() === actorUser.user_id.toLowerCase());
        if (!isOwner) {
            throw new ForbiddenError('You are not an authorized owner of the specified resource.', 'ERR_FORBIDDEN_RESOURCE_OWNER');
        }
    }

    return await withTransaction(async (transaction) => {
        // 1. Create the campaign header
        const review = await reviewRepository.createAccessReview({
            reviewName: reviewName.trim(),
            description: description ? description.trim() : null,
            campaignType,
            startDate: start.toISOString(),
            dueDate: due.toISOString(),
            status: 'ACTIVE',
            initiatedByUserId: actorUser.user_id
        }, transaction);

        // 2. Select matching active grants for the specified scope
        const candidateGrants = await reviewRepository.findGrantsForReviewScope(finalScope, transaction);

        let itemsCreated = 0;
        for (const grant of candidateGrants) {
            // Assign reviewer: default to designated reviewer unless that reviewer is the contractor themselves
            let itemReviewerId = assignedReviewerId;
            if (grant.contractor_user_id.toLowerCase() === itemReviewerId.toLowerCase()) {
                // If designated reviewer is the contractor, fall back to sponsor or campaign initiator to avoid immediate SoD deadlock
                if (grant.sponsor_user_id && grant.sponsor_user_id.toLowerCase() !== grant.contractor_user_id.toLowerCase()) {
                    itemReviewerId = grant.sponsor_user_id;
                } else {
                    itemReviewerId = actorUser.user_id;
                }
            }

            await reviewRepository.createReviewItem({
                reviewId: review.review_id,
                grantId: grant.grant_id,
                reviewerUserId: itemReviewerId,
                decision: 'PENDING'
            }, transaction);
            itemsCreated++;
        }

        // 3. Log audit event
        await auditRepository.createAuditEvent({
            eventCategory: 'RECERTIFICATION',
            eventAction: 'REVIEW_CAMPAIGN_CREATED',
            entityType: 'access_reviews',
            entityId: review.review_id,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                reviewId: review.review_id,
                reviewName: review.review_name,
                campaignType: review.campaign_type,
                itemsCreated,
                scope: finalScope
            }
        }, transaction);

        return {
            ...review,
            total_items: itemsCreated,
            decided_items: 0,
            pending_items: itemsCreated
        };
    });
}

/**
 * Lists review campaigns with optional filtering.
 * @param {object} [filter={}]
 * @returns {Promise<Array<object>>}
 */
async function listReviews(filter = {}) {
    return await reviewRepository.listAccessReviews(filter);
}

/**
 * Retrieves details for a specific review campaign.
 * @param {string} reviewId GUID
 * @returns {Promise<object>}
 */
async function getReviewDetails(reviewId) {
    if (!reviewId) throw new ValidationError('Review ID is required.');
    const review = await reviewRepository.findAccessReviewById(reviewId);
    if (!review) {
        throw new NotFoundError('Access review campaign', 'ERR_REVIEW_NOT_FOUND');
    }
    return review;
}

/**
 * Retrieves all items in a review campaign with server-side authorization scoping.
 * - Platform administrators, Security Officers, and Compliance Auditors have platform-wide campaign visibility.
 * - Resource Owners can view only review items for resources they own.
 * - Internal Sponsors can view only review items for contractors they sponsor.
 * - Contractors are blocked from viewing review items.
 * @param {string} reviewId GUID
 * @param {object} [actorUser=null] Authenticated user requesting review items
 * @returns {Promise<Array<object>>}
 */
async function getReviewItems(reviewId, actorUser = null) {
    if (!reviewId) throw new ValidationError('Review ID is required.');
    const review = await reviewRepository.findAccessReviewById(reviewId);
    if (!review) {
        throw new NotFoundError('Access review campaign', 'ERR_REVIEW_NOT_FOUND');
    }

    const allItems = await reviewRepository.getReviewItemsByReviewId(reviewId);

    // If no actorUser passed (e.g. internal service call), return all items
    if (!actorUser) {
        return allItems;
    }

    // Platform-wide visibility for governance roles
    if (hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR'])) {
        return allItems;
    }

    // Contractors without governance roles are strictly blocked
    if (hasAnyRole(actorUser.roles, ['CONTRACTOR']) && !hasAnyRole(actorUser.roles, ['RESOURCE_OWNER', 'INTERNAL_SPONSOR'])) {
        throw new ForbiddenError(
            'Access denied: Contractors cannot access review items.',
            'ERR_FORBIDDEN_ROLE'
        );
    }

    const isResourceOwner = hasAnyRole(actorUser.roles, ['RESOURCE_OWNER']);
    const isInternalSponsor = hasAnyRole(actorUser.roles, ['INTERNAL_SPONSOR']);

    let ownedResourceIds = new Set();
    if (isResourceOwner) {
        const ids = await resourceRepository.getResourceIdsForOwner(actorUser.user_id);
        ownedResourceIds = new Set(ids.map(id => id.toLowerCase()));
    }

    const filteredItems = allItems.filter(item => {
        // Resource Owner scope: grants belonging to resources they own
        if (isResourceOwner && item.resource_id && ownedResourceIds.has(item.resource_id.toLowerCase())) {
            return true;
        }
        // Sponsor scope: grants belonging to contractors they sponsor
        if (isInternalSponsor && item.sponsor_user_id && item.sponsor_user_id.toLowerCase() === actorUser.user_id.toLowerCase()) {
            return true;
        }
        return false;
    });

    return filteredItems;
}

/**
 * Records a reviewer's decision on a specific review item.
 * Strictly enforces:
 * 1. Read-only compliance auditor block
 * 2. Contractor self-review block (Separation of Duties)
 * 3. Server-side ownership / sponsorship scope verification
 * 4. At-decision-time revalidation of grant & engagement validity in UTC for MAINTAIN
 * 5. Mandatory justification / decision notes
 * 6. Revocation workflow routing for REVOKE decisions
 * 7. Automatic campaign completion check
 * @param {string} reviewItemId GUID
 * @param {object} decisionPayload { decision: 'MAINTAIN' | 'REVOKE', decisionNotes: string }
 * @param {object} actorUser Authenticated reviewer
 * @returns {Promise<object>}
 */
async function submitReviewDecision(reviewItemId, decisionPayload, actorUser) {
    if (!reviewItemId) throw new ValidationError('Review item ID is required.');
    if (!actorUser) throw new ForbiddenError('Actor user is required.');

    // 1. Auditor read-only guardrail
    if (isStrictlyReadOnlyAuditor(actorUser.roles)) {
        throw new ForbiddenError(
            'Access denied: Compliance Auditor role is strictly read-only and cannot submit review decisions.',
            'ERR_AUDITOR_READ_ONLY'
        );
    }

    const { decision, decisionNotes } = decisionPayload;

    if (!decision || !['MAINTAIN', 'REVOKE'].includes(decision.toUpperCase())) {
        throw new ValidationError("Decision must be either 'MAINTAIN' or 'REVOKE'.", [], 'ERR_INVALID_DECISION');
    }
    const cleanDecision = decision.toUpperCase();

    if (!decisionNotes || !decisionNotes.trim()) {
        throw new ValidationError('A business justification / decision note is mandatory for access review decisions.', [], 'ERR_DECISION_NOTES_REQUIRED');
    }

    const item = await reviewRepository.findReviewItemById(reviewItemId);
    if (!item) {
        throw new NotFoundError('Review item', 'ERR_REVIEW_ITEM_NOT_FOUND');
    }

    // 2. Separation of Duties: Contractor MUST NOT review their own access
    if (item.contractor_user_id.toLowerCase() === actorUser.user_id.toLowerCase()) {
        throw new ForbiddenError(
            'Separation of Duties violation: A contractor cannot review or approve their own access entitlements.',
            'ERR_SELF_REVIEW_FORBIDDEN'
        );
    }

    if (hasAnyRole(actorUser.roles, ['CONTRACTOR']) && !hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'RESOURCE_OWNER', 'INTERNAL_SPONSOR'])) {
        throw new ForbiddenError(
            'Separation of Duties violation: A contractor cannot review or approve access entitlements.',
            'ERR_SELF_REVIEW_FORBIDDEN'
        );
    }

    // 3. Strict Server-Side Scope Authorization:
    // - Security Officers and System Administrators follow platform-wide governance permissions.
    // - Resource Owners can review only grants belonging to resources they own.
    // - Internal Sponsors can review only grants belonging to contractors they sponsor.
    const isPrivileged = hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER']);

    if (!isPrivileged) {
        const isResourceOwner = hasAnyRole(actorUser.roles, ['RESOURCE_OWNER']);
        const isInternalSponsor = hasAnyRole(actorUser.roles, ['INTERNAL_SPONSOR']);

        if (!isResourceOwner && !isInternalSponsor) {
            throw new ForbiddenError(
                'Access denied: You are not authorized to submit a decision for this review item.',
                'ERR_FORBIDDEN_REVIEW_DECISION'
            );
        }

        let isAuthorized = false;

        if (isResourceOwner) {
            const ownsResource = await resourceRepository.isUserResourceOwner(actorUser.user_id, item.resource_id);
            if (ownsResource) {
                isAuthorized = true;
            } else if (!isInternalSponsor) {
                throw new ForbiddenError(
                    'Access denied: Resource Owners can review only grants belonging to resources they own.',
                    'ERR_FORBIDDEN_RESOURCE_OWNER'
                );
            }
        }

        if (isInternalSponsor && !isAuthorized) {
            const sponsorsContractor = (item.sponsor_user_id && item.sponsor_user_id.toLowerCase() === actorUser.user_id.toLowerCase());
            if (sponsorsContractor) {
                isAuthorized = true;
            } else {
                throw new ForbiddenError(
                    'Access denied: Internal Sponsors can review only grants belonging to contractors they sponsor.',
                    'ERR_FORBIDDEN_SPONSOR_SCOPE'
                );
            }
        }

        if (!isAuthorized) {
            throw new ForbiddenError(
                'Access denied: You are not authorized to submit a decision for this review item.',
                'ERR_FORBIDDEN_REVIEW_DECISION'
            );
        }
    }

    // 4. Revalidate engagement and grant validity at decision time for MAINTAIN decisions using authoritative UTC
    if (cleanDecision === 'MAINTAIN') {
        const dbNow = item.db_current_time_utc ? new Date(item.db_current_time_utc) : new Date();
        const dbTodayStr = item.db_current_date_utc
            ? (typeof item.db_current_date_utc === 'string' ? item.db_current_date_utc.slice(0, 10) : new Date(item.db_current_date_utc).toISOString().slice(0, 10))
            : new Date().toISOString().slice(0, 10);

        // A. Revalidate grant expiration
        const grantExpired = (new Date(item.expires_at) <= dbNow) || item.grant_status !== 'ACTIVE';
        if (grantExpired) {
            throw new ConflictError(
                'Cannot maintain access: The access grant has already expired or is not active.',
                'ERR_MAINTAIN_EXPIRED_ACCESS_FORBIDDEN'
            );
        }

        // B. Revalidate engagement status
        if (['TERMINATED', 'COMPLETED', 'CANCELLED'].includes(item.engagement_status)) {
            throw new ConflictError(
                `Cannot maintain access: The contractor engagement has ended (status: ${item.engagement_status}).`,
                'ERR_MAINTAIN_ENDED_ENGAGEMENT_FORBIDDEN'
            );
        }

        // C. Revalidate engagement end date
        const engagementEndDateStr = item.engagement_end_date instanceof Date
            ? item.engagement_end_date.toISOString().slice(0, 10)
            : String(item.engagement_end_date).slice(0, 10);

        if (engagementEndDateStr < dbTodayStr) {
            throw new ConflictError(
                'Cannot maintain access: The contractor engagement has expired past its end date.',
                'ERR_MAINTAIN_ENDED_ENGAGEMENT_FORBIDDEN'
            );
        }
    }

    const decidedAt = new Date().toISOString();

    // 5. Update the review item decision
    const updatedItem = await reviewRepository.updateReviewItemDecision(reviewItemId, {
        decision: cleanDecision,
        decisionNotes: decisionNotes.trim(),
        decidedAt
    });

    // 5. If decision is REVOKE, route through the existing revocation engine!
    let revocationOutcome = null;
    if (cleanDecision === 'REVOKE') {
        logger.info('Review item rejected, triggering automated revocation', {
            reviewItemId,
            grantId: item.grant_id,
            actorId: actorUser.user_id
        });

        revocationOutcome = await revocationService.enqueueGrantRevocation(
            item.grant_id,
            'REVIEW_REJECTION',
            actorUser,
            {
                reason: `Recertification review rejection: ${decisionNotes.trim()}`,
                autoProcess: true
            }
        );
    }

    // 6. Audit event
    await auditRepository.createAuditEvent({
        eventCategory: 'RECERTIFICATION',
        eventAction: 'REVIEW_DECISION_RECORDED',
        entityType: 'review_items',
        entityId: reviewItemId,
        actorUserId: actorUser.user_id,
        actorType: 'USER',
        eventPayload: {
            reviewItemId,
            reviewId: item.review_id,
            grantId: item.grant_id,
            grantNumber: item.grant_number,
            decision: cleanDecision,
            decisionNotes: decisionNotes.trim(),
            revocationJobId: revocationOutcome?.job?.job_id || null
        }
    });

    // 7. Check if all items in the campaign are decided; if so, transition campaign to COMPLETED
    const remainingPending = await reviewRepository.countPendingItemsInReview(item.review_id);
    let campaignStatus = item.review_status;
    if (remainingPending === 0) {
        await reviewRepository.updateAccessReviewStatus(item.review_id, 'COMPLETED');
        campaignStatus = 'COMPLETED';

        await auditRepository.createAuditEvent({
            eventCategory: 'RECERTIFICATION',
            eventAction: 'REVIEW_CAMPAIGN_COMPLETED',
            entityType: 'access_reviews',
            entityId: item.review_id,
            actorUserId: actorUser.user_id,
            actorType: 'USER',
            eventPayload: {
                reviewId: item.review_id,
                reviewName: item.review_name,
                completedAt: decidedAt
            }
        });
    }

    return {
        item: updatedItem,
        campaignStatus,
        remainingPending,
        revocationJob: revocationOutcome?.job || null
    };
}

module.exports = {
    createReviewCampaign,
    listReviews,
    getReviewDetails,
    getReviewItems,
    submitReviewDecision
};
