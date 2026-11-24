/**
 * AccessLease — Access Request & Multi-Stage Approval Workflow HTTP Trigger Functions
 * Azure Functions v4 REST Handlers.
 * 
 * Endpoints:
 * - GET  /api/catalog/resources                     (Protected): Active resource catalogue
 * - GET  /api/catalog/resources/{id}/entitlements    (Protected): Entitlements for resource
 * - POST /api/requests                              (Protected): Create contractor access request
 * - GET  /api/requests                              (Protected): List requests (scoped)
 * - GET  /api/requests/{id}                         (Protected): Full request details & approval stages
 * - POST /api/requests/{id}/cancel                  (Protected): Cancel pending request (requester)
 * - GET  /api/approvals/pending                     (Protected): Actionable pending approvals for user
 * - POST /api/approvals/{stepId}/decision           (Protected): Submit approval decision (APPROVE/REJECT)
 */

const { withAuth } = require('../middleware/authMiddleware');
const requestWorkflowService = require('../services/requestWorkflowService');
const { createSuccessBody, toHttpResponse } = require('../utils/response');
const { handleAuthError } = require('../middleware/authorize');
const logger = require('../utils/logger');

/**
 * Helper to safely extract query parameter from Azure Functions HttpRequest or mock.
 */
function getQueryParam(request, key) {
    if (!request || !request.query) return undefined;
    if (typeof request.query.get === 'function') {
        return request.query.get(key) || undefined;
    }
    return request.query[key];
}

/**
 * Helper to safely extract route parameter.
 */
function getRouteParam(request, key) {
    if (!request || !request.params) return undefined;
    return request.params[key];
}

/**
 * Helper to parse JSON body across Azure Functions HttpRequest and local server mock.
 */
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
// 1. GET /api/catalog/resources
// -----------------------------------------------------------------------------
async function listCatalogResourcesHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const result = await requestWorkflowService.listCatalogResources(user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 2. GET /api/catalog/resources/{id}/entitlements
// -----------------------------------------------------------------------------
async function listResourceEntitlementsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const resourceId = getRouteParam(request, 'id');
        const result = await requestWorkflowService.listResourceEntitlements(user, resourceId);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 3. POST /api/requests
// -----------------------------------------------------------------------------
async function createRequestHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const body = await parseRequestBody(request);
        const ipAddress = request.headers?.get ? request.headers.get('x-forwarded-for') : request.headers?.['x-forwarded-for'];

        const result = await requestWorkflowService.createAccessRequest(user, body, { ipAddress });
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(201, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 4. GET /api/requests
// -----------------------------------------------------------------------------
async function listRequestsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const status = getQueryParam(request, 'status');
        const limit = getQueryParam(request, 'limit');
        const offset = getQueryParam(request, 'offset');

        const result = await requestWorkflowService.listRequests(user, {
            status,
            limit: limit ? parseInt(limit, 10) : undefined,
            offset: offset ? parseInt(offset, 10) : undefined
        });

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 5. GET /api/requests/{id}
// -----------------------------------------------------------------------------
async function getRequestByIdHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const requestId = getRouteParam(request, 'id');
        const result = await requestWorkflowService.getRequestDetails(user, requestId);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 6. POST /api/requests/{id}/cancel
// -----------------------------------------------------------------------------
async function cancelRequestHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const requestId = getRouteParam(request, 'id');
        const body = await parseRequestBody(request);
        const reason = body?.reason;
        const ipAddress = request.headers?.get ? request.headers.get('x-forwarded-for') : request.headers?.['x-forwarded-for'];

        const result = await requestWorkflowService.cancelAccessRequest(user, requestId, reason, { ipAddress });
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 7. GET /api/approvals/pending
// -----------------------------------------------------------------------------
async function listPendingApprovalsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const result = await requestWorkflowService.listPendingApprovals(user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 8. POST /api/approvals/{stepId}/decision
// -----------------------------------------------------------------------------
async function submitApprovalDecisionHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const stepId = getRouteParam(request, 'stepId');
        const body = await parseRequestBody(request);
        const { decision, comments } = body || {};
        const ipAddress = request.headers?.get ? request.headers.get('x-forwarded-for') : request.headers?.['x-forwarded-for'];

        const result = await requestWorkflowService.submitApprovalDecision(
            user,
            stepId,
            decision,
            comments,
            { ipAddress }
        );

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

module.exports = {
    listCatalogResources: withAuth(listCatalogResourcesHandler),
    listResourceEntitlements: withAuth(listResourceEntitlementsHandler),
    createRequest: withAuth(createRequestHandler),
    listRequests: withAuth(listRequestsHandler),
    getRequestById: withAuth(getRequestByIdHandler),
    cancelRequest: withAuth(cancelRequestHandler),
    listPendingApprovals: withAuth(listPendingApprovalsHandler),
    submitApprovalDecision: withAuth(submitApprovalDecisionHandler)
};

