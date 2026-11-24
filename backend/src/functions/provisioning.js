/**
 * AccessLease — Provisioning & Connector HTTP Trigger Functions
 * Azure Functions v4 REST Handlers.
 * 
 * Endpoints:
 * - GET  /api/connectors/github/status          (Protected): Public/authenticated connector health & config status
 * - GET  /api/connectors/github/configuration   (Protected): Detailed connector configuration (no secrets)
 * - POST /api/provisioning/requests/{id}/start  (Protected): Start/trigger provisioning for approved request
 * - GET  /api/provisioning/requests/{id}        (Protected): Inspect provisioning state & job details
 * - GET  /api/provisioning/jobs                 (Protected): List provisioning queue jobs (admin/auditor)
 * - GET  /api/provisioning/grants               (Protected): List access grants (scoped)
 * - POST /api/provisioning/jobs/{id}/retry      (Protected): Manual retry for failed jobs (admin/security)
 */

const { withAuth } = require('../middleware/authMiddleware');
const provisioningService = require('../services/provisioningService');
const githubConnector = require('../connectors/github');
const { createSuccessBody, toHttpResponse } = require('../utils/response');
const { handleAuthError } = require('../middleware/authorize');
const { hasAnyRole } = require('../security/permissionPolicy');
const { ForbiddenError } = require('../utils/errors');
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
// 1. GET /api/connectors/github/status
// -----------------------------------------------------------------------------
async function getGitHubStatusHandler(request, context) {
    try {
        const status = githubConnector.githubConfig.getStatus();
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(status, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 2. GET /api/connectors/github/configuration
// -----------------------------------------------------------------------------
async function getGitHubConfigurationHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const isAuthorized = hasAnyRole(user.roles, [
            'SYSTEM_ADMIN',
            'SECURITY_OFFICER',
            'COMPLIANCE_AUDITOR',
            'INTERNAL_SPONSOR',
            'RESOURCE_OWNER'
        ]);

        if (!isAuthorized) {
            throw new ForbiddenError(
                'Access denied: Connector configuration inspection requires an authorized governance role.',
                'ERR_FORBIDDEN_ROLE'
            );
        }

        const config = githubConnector.githubConfig.getConfig();
        const status = githubConnector.githubConfig.getStatus();

        const safeConfig = {
            ...status,
            appClientId: config.appClientId || null,
            hasPrivateKey: !!config.privateKey,
            privateKeyType: config.privateKey ? (config.privateKey.includes('RSA PRIVATE KEY') ? 'PKCS#1' : 'PKCS#8') : null
        };

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(safeConfig, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 3. POST /api/provisioning/requests/{id}/start
// -----------------------------------------------------------------------------
async function startProvisioningHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const requestId = getRouteParam(request, 'id') || getRouteParam(request, 'requestId');
        const correlationId = context && context.invocationId ? context.invocationId : undefined;

        const result = await provisioningService.createProvisioningOperation(requestId, user, {
            ipAddress: request.headers ? (request.headers.get ? request.headers.get('x-forwarded-for') : request.headers['x-forwarded-for']) : null
        });

        const statusCode = result.alreadyExists ? 200 : 201;
        return toHttpResponse(statusCode, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 4. GET /api/provisioning/requests/{id}
// -----------------------------------------------------------------------------
async function getProvisioningStateByRequestHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const requestId = getRouteParam(request, 'id') || getRouteParam(request, 'requestId');
        const correlationId = context && context.invocationId ? context.invocationId : undefined;

        const result = await provisioningService.getProvisioningStateByRequestId(requestId, user);
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 5. GET /api/provisioning/jobs
// -----------------------------------------------------------------------------
async function listProvisioningJobsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const status = getQueryParam(request, 'status');
        const connectorType = getQueryParam(request, 'connectorType');
        const limit = parseInt(getQueryParam(request, 'limit'), 10) || 50;
        const offset = parseInt(getQueryParam(request, 'offset'), 10) || 0;

        const result = await provisioningService.listJobs(user, {
            status,
            connectorType,
            limit,
            offset
        });

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 6. GET /api/provisioning/grants
// -----------------------------------------------------------------------------
async function listGrantsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const status = getQueryParam(request, 'status');
        const resourceId = getQueryParam(request, 'resourceId');
        const limit = parseInt(getQueryParam(request, 'limit'), 10) || 50;
        const offset = parseInt(getQueryParam(request, 'offset'), 10) || 0;

        const result = await provisioningService.listGrants(user, {
            status,
            resourceId,
            limit,
            offset
        });

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 7. POST /api/provisioning/jobs/{id}/retry
// -----------------------------------------------------------------------------
async function retryProvisioningJobHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const jobId = getRouteParam(request, 'id') || getRouteParam(request, 'jobId');
        const correlationId = context && context.invocationId ? context.invocationId : undefined;

        const body = request.body || {};
        const result = await provisioningService.retryJob(jobId, user, { deferExecution: !!body.deferExecution });
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

module.exports = {
    getGitHubStatus: withAuth(getGitHubStatusHandler),
    getGitHubConfiguration: withAuth(getGitHubConfigurationHandler),
    startProvisioning: withAuth(startProvisioningHandler),
    getProvisioningStateByRequest: withAuth(getProvisioningStateByRequestHandler),
    listProvisioningJobs: withAuth(listProvisioningJobsHandler),
    listGrants: withAuth(listGrantsHandler),
    retryProvisioningJob: withAuth(retryProvisioningJobHandler),

    // Raw handlers for testing
    getGitHubStatusHandler,
    getGitHubConfigurationHandler,
    startProvisioningHandler,
    getProvisioningStateByRequestHandler,
    listProvisioningJobsHandler,
    listGrantsHandler,
    retryProvisioningJobHandler
};
