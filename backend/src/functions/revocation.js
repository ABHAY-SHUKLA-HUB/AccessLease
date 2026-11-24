/**
 * AccessLease — Revocation & Offboarding HTTP Trigger Functions
 * Azure Functions v4 REST Handlers.
 * 
 * Endpoints:
 * - GET  /api/revocation/jobs                 (Protected): List revocation queue jobs with filtering
 * - GET  /api/revocation/jobs/{id}            (Protected): Get details of a specific revocation job
 * - POST /api/revocation/jobs/{id}/retry      (Protected): Manually retry failed or queued job (Admin/Security only)
 * - POST /api/revocation/jobs/{id}/resolve    (Protected): Resolve manual review exception (Admin/Security only)
 * - POST /api/revocation/scan                 (Protected): Trigger scheduled access expiry & termination scan
 * - GET  /api/contractors/{id}/offboarding    (Protected): Retrieve contractor offboarding progress
 * - POST /api/contractors/engagements/{id}/terminate (Protected): Terminate engagement & trigger immediate offboarding
 */

const { withAuth } = require('../middleware/authMiddleware');
const revocationService = require('../services/revocationService');
const { createSuccessBody, toHttpResponse } = require('../utils/response');
const { handleAuthError } = require('../middleware/authorize');
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
// 1. GET /api/revocation/jobs - List revocation queue jobs
// -----------------------------------------------------------------------------
async function listRevocationJobsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const status = getQueryParam(request, 'status');
        const triggerSource = getQueryParam(request, 'triggerSource');
        const contractorUserId = getQueryParam(request, 'contractorUserId');
        const limit = parseInt(getQueryParam(request, 'limit') || '50', 10);
        const offset = parseInt(getQueryParam(request, 'offset') || '0', 10);

        const filter = { status, triggerSource, contractorUserId, limit, offset };
        const result = await revocationService.listRevocationJobs(filter, user);

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 2. GET /api/revocation/jobs/{id} - Get revocation job details
// -----------------------------------------------------------------------------
async function getRevocationJobByIdHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const jobId = getRouteParam(request, 'id') || getRouteParam(request, 'jobId');
        const result = await revocationService.getRevocationJobById(jobId, user);

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 3. POST /api/revocation/jobs/{id}/retry - Manually retry revocation job
// -----------------------------------------------------------------------------
async function retryRevocationJobHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const jobId = getRouteParam(request, 'id') || getRouteParam(request, 'jobId');
        const result = await revocationService.retryRevocationJob(jobId, user);

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 4. POST /api/revocation/jobs/{id}/resolve - Resolve manual review exception
// -----------------------------------------------------------------------------
async function resolveManualReviewHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const jobId = getRouteParam(request, 'id') || getRouteParam(request, 'jobId');
        const body = await parseRequestBody(request);
        const { decision, notes } = body || {};

        const result = await revocationService.resolveManualReview(jobId, user, decision, notes);

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 5. POST /api/revocation/scan - Trigger scheduled access expiry & termination scan
// -----------------------------------------------------------------------------
async function triggerExpiryScanHandler(request, context) {
    try {
        const body = await parseRequestBody(request);
        const batchSize = body?.batchSize ? parseInt(body.batchSize, 10) : 50;

        const result = await revocationService.processExpiredGrants({ batchSize, autoProcess: true });

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 6. GET /api/contractors/{id}/offboarding - Retrieve contractor offboarding progress
// -----------------------------------------------------------------------------
async function getOffboardingStatusHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const contractorUserId = getRouteParam(request, 'id') || getRouteParam(request, 'contractorId');
        const result = await revocationService.getOffboardingStatus(contractorUserId, user);

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 7. POST /api/contractors/engagements/{id}/terminate - Immediate offboarding
// -----------------------------------------------------------------------------
async function terminateEngagementHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const engagementId = getRouteParam(request, 'id') || getRouteParam(request, 'engagementId');
        const body = await parseRequestBody(request);
        const { reason } = body || {};

        const result = await revocationService.terminateContractorEngagement(engagementId, user, reason);

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

module.exports = {
    listRevocationJobs: withAuth(listRevocationJobsHandler),
    getRevocationJobById: withAuth(getRevocationJobByIdHandler),
    retryRevocationJob: withAuth(retryRevocationJobHandler),
    resolveManualReview: withAuth(resolveManualReviewHandler),
    triggerExpiryScan: withAuth(triggerExpiryScanHandler),
    getOffboardingStatus: withAuth(getOffboardingStatusHandler),
    terminateEngagement: withAuth(terminateEngagementHandler),

    // Raw handlers for testing
    listRevocationJobsHandler,
    getRevocationJobByIdHandler,
    retryRevocationJobHandler,
    resolveManualReviewHandler,
    triggerExpiryScanHandler,
    getOffboardingStatusHandler,
    terminateEngagementHandler
};

