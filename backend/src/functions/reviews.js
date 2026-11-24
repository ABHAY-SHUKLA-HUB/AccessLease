/**
 * AccessLease — Access Review & Recertification HTTP Trigger Functions
 * Azure Functions v4 REST Handlers.
 * 
 * Endpoints:
 * - POST /api/reviews                    (Protected): Create access review campaign
 * - GET  /api/reviews                    (Protected): List review campaigns
 * - GET  /api/reviews/{id}               (Protected): Get campaign details
 * - GET  /api/reviews/{id}/items         (Protected): Get review campaign items
 * - POST /api/reviews/items/{id}/decision (Protected): Submit review decision (Maintain / Revoke)
 */

const { withAuth } = require('../middleware/authMiddleware');
const reviewService = require('../services/reviewService');
const { createSuccessBody, toHttpResponse } = require('../utils/response');
const { handleAuthError } = require('../middleware/authorize');
const { hasAnyRole } = require('../security/permissionPolicy');
const { ForbiddenError, ValidationError } = require('../utils/errors');
const logger = require('../utils/logger');

function getQueryParam(request, key) {
    if (!request || !request.query) return undefined;
    if (typeof request.query.get === 'function') {
        return request.query.get(key) || undefined;
    }
    return request.query[key];
}

function getRouteParam(request, key) {
    if (!request || !request.params) return undefined;
    return request.params[key];
}

async function parseRequestBody(request) {
    if (!request) return {};
    if (typeof request.json === 'function') {
        try {
            return await request.json();
        } catch {
            return request.body || {};
        }
    }
    return request.body || {};
}

// -----------------------------------------------------------------------------
// 1. POST /api/reviews - Create access review campaign
// -----------------------------------------------------------------------------
async function createReviewCampaignHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const body = await parseRequestBody(request);

        const result = await reviewService.createReviewCampaign(body, user);
        const correlationId = context?.invocationId;
        return toHttpResponse(201, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 2. GET /api/reviews - List review campaigns
// -----------------------------------------------------------------------------
async function listReviewsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const isAuthorized = hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR', 'RESOURCE_OWNER', 'INTERNAL_SPONSOR']);
        if (!isAuthorized) {
            throw new ForbiddenError('You do not have permission to list review campaigns.', 'ERR_FORBIDDEN_ROLE');
        }

        const status = getQueryParam(request, 'status');
        const campaignType = getQueryParam(request, 'campaignType');
        const limit = parseInt(getQueryParam(request, 'limit') || '50', 10);
        const offset = parseInt(getQueryParam(request, 'offset') || '0', 10);

        const filter = { status, campaignType, limit, offset };
        const result = await reviewService.listReviews(filter);

        const correlationId = context?.invocationId;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 3. GET /api/reviews/{id} - Get review campaign details
// -----------------------------------------------------------------------------
async function getReviewByIdHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const isAuthorized = hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR', 'RESOURCE_OWNER', 'INTERNAL_SPONSOR']);
        if (!isAuthorized) {
            throw new ForbiddenError('You do not have permission to view this review campaign.', 'ERR_FORBIDDEN_ROLE');
        }

        const reviewId = getRouteParam(request, 'id') || getRouteParam(request, 'reviewId');
        const review = await reviewService.getReviewDetails(reviewId);

        const correlationId = context?.invocationId;
        return toHttpResponse(200, createSuccessBody(review, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 4. GET /api/reviews/{id}/items - Get items requiring review
// -----------------------------------------------------------------------------
async function getReviewItemsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const isAuthorized = hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR', 'RESOURCE_OWNER', 'INTERNAL_SPONSOR']);
        if (!isAuthorized) {
            throw new ForbiddenError('You do not have permission to view review items.', 'ERR_FORBIDDEN_ROLE');
        }

        const reviewId = getRouteParam(request, 'id') || getRouteParam(request, 'reviewId');
        const items = await reviewService.getReviewItems(reviewId, user);

        const correlationId = context?.invocationId;
        return toHttpResponse(200, createSuccessBody(items, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 5. POST /api/reviews/items/{id}/decision - Submit review decision
// -----------------------------------------------------------------------------
async function submitReviewDecisionHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const itemId = getRouteParam(request, 'id') || getRouteParam(request, 'itemId');
        const body = await parseRequestBody(request);

        const result = await reviewService.submitReviewDecision(itemId, body, user);

        const correlationId = context?.invocationId;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

module.exports = {
    createReviewCampaign: withAuth(createReviewCampaignHandler),
    listReviews: withAuth(listReviewsHandler),
    getReviewById: withAuth(getReviewByIdHandler),
    getReviewItems: withAuth(getReviewItemsHandler),
    submitReviewDecision: withAuth(submitReviewDecisionHandler)
};

