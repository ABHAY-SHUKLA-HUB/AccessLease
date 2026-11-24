/**
 * AccessLease — Contractor & Engagement HTTP Trigger Functions
 * Azure Functions v4 REST Handlers.
 * 
 * Endpoints:
 * - GET  /api/contractors             (Protected): List contractors for directory
 * - GET  /api/contractors/me          (Protected): Contractor self-service profile
 * - GET  /api/contractors/{id}        (Protected): Retrieve individual contractor details
 * - GET  /api/engagements             (Protected): List engagements (scoped for contractor)
 * - GET  /api/engagements/{id}        (Protected): Retrieve single engagement details
 * - POST /api/engagements             (Protected): Create contractor engagement
 * - PUT  /api/engagements/{id}        (Protected): Update permitted engagement fields
 * - POST /api/engagements/{id}/status (Protected): Validated status transition
 */

const { withAuth } = require('../middleware/authMiddleware');
const contractorService = require('../services/contractorService');
const { createSuccessBody, createErrorBody, toHttpResponse } = require('../utils/response');
const { handleAuthError, requireRole } = require('../middleware/authorize');
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
// 1. GET /api/contractors
// -----------------------------------------------------------------------------
async function listContractorsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const search = getQueryParam(request, 'search');
        const isActive = getQueryParam(request, 'isActive');
        const limit = getQueryParam(request, 'limit');
        const offset = getQueryParam(request, 'offset');

        const result = await contractorService.listContractors(user, {
            search,
            isActive,
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
// 1b. POST /api/contractors (SYSTEM_ADMIN only)
// -----------------------------------------------------------------------------
async function createContractorHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const body = await parseRequestBody(request);
        const result = await contractorService.createContractor(user, body);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(201, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 2. GET /api/contractors/me
// -----------------------------------------------------------------------------
async function getContractorSelfHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const result = await contractorService.getContractorSelf(user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}



// -----------------------------------------------------------------------------
// 3. GET /api/contractors/{id}
// -----------------------------------------------------------------------------
async function getContractorByIdHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const contractorId = getRouteParam(request, 'id');
        const result = await contractorService.getContractorById(user, contractorId);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}



// -----------------------------------------------------------------------------
// 4. GET /api/engagements
// -----------------------------------------------------------------------------
async function listEngagementsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const status = getQueryParam(request, 'status');
        const contractorId = getQueryParam(request, 'contractorId');
        const sponsorId = getQueryParam(request, 'sponsorId');
        const search = getQueryParam(request, 'search');
        const limit = getQueryParam(request, 'limit');
        const offset = getQueryParam(request, 'offset');

        const result = await contractorService.listEngagements(user, {
            status,
            contractorId,
            sponsorId,
            search,
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
// 5. GET /api/engagements/{id}
// -----------------------------------------------------------------------------
async function getEngagementByIdHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const engagementId = getRouteParam(request, 'id');
        const result = await contractorService.getEngagementById(user, engagementId);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}



// -----------------------------------------------------------------------------
// 6. POST /api/engagements
// -----------------------------------------------------------------------------
async function createEngagementHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const body = await parseRequestBody(request);
        const ipAddress = request.headers?.get ? request.headers.get('x-forwarded-for') : request.headers?.['x-forwarded-for'];

        const result = await contractorService.createEngagement(user, body, { ipAddress });
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(201, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 7. PUT /api/engagements/{id}
// -----------------------------------------------------------------------------
async function updateEngagementHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const engagementId = getRouteParam(request, 'id');
        const body = await parseRequestBody(request);
        const ipAddress = request.headers?.get ? request.headers.get('x-forwarded-for') : request.headers?.['x-forwarded-for'];

        const result = await contractorService.updateEngagement(user, engagementId, body, { ipAddress });
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}



// -----------------------------------------------------------------------------
// 8. POST /api/engagements/{id}/status
// -----------------------------------------------------------------------------
async function transitionEngagementStatusHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const engagementId = getRouteParam(request, 'id');
        const body = await parseRequestBody(request);
        const { status, reason } = body || {};
        const ipAddress = request.headers?.get ? request.headers.get('x-forwarded-for') : request.headers?.['x-forwarded-for'];

        const result = await contractorService.transitionEngagementStatus(
            user,
            engagementId,
            status,
            reason,
            { ipAddress }
        );

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}



// -----------------------------------------------------------------------------
// 9. GET /api/contractors/me/github/link - Initiate GitHub OAuth linking flow
// -----------------------------------------------------------------------------
async function initiateGitHubLinkHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const redirectUri = getQueryParam(request, 'redirect_uri');
        const { githubOAuthService } = require('../connectors/github');

        const result = await githubOAuthService.getAuthorizationUrl(user, redirectUri);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}



// -----------------------------------------------------------------------------
// 10. POST /api/contractors/me/github/callback - Exchange code & bind verified identity
// -----------------------------------------------------------------------------
async function callbackGitHubLinkHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const body = await parseRequestBody(request);
        const code = body.code || getQueryParam(request, 'code');
        const state = body.state || getQueryParam(request, 'state');
        const redirectUri = body.redirect_uri || getQueryParam(request, 'redirect_uri');
        const ipAddress = request.headers?.get ? request.headers.get('x-forwarded-for') : request.headers?.['x-forwarded-for'];

        const { githubOAuthService } = require('../connectors/github');
        const result = await githubOAuthService.linkContractorGitHubAccount({
            user,
            code,
            state,
            redirectUri,
            ipAddress
        });

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}



// -----------------------------------------------------------------------------
// 11. DELETE /api/contractors/me/github/link - Unlink / revoke GitHub identity
// -----------------------------------------------------------------------------
async function unlinkGitHubHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const targetUserId = getQueryParam(request, 'userId') || getRouteParam(request, 'id');
        const ipAddress = request.headers?.get ? request.headers.get('x-forwarded-for') : request.headers?.['x-forwarded-for'];

        const { githubOAuthService } = require('../connectors/github');
        const result = await githubOAuthService.unlinkContractorGitHubAccount({
            user,
            targetUserId,
            ipAddress
        });

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}



// -----------------------------------------------------------------------------
// 12. GET /api/contractors/me/github/status - Inspect contractor linked identity status
// -----------------------------------------------------------------------------
async function getGitHubLinkStatusHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const targetUserId = getRouteParam(request, 'id') || user.user_id;

        // Contextual access: contractors see their own, admins/sponsors see targets
        const isSelf = targetUserId.toLowerCase() === user.user_id.toLowerCase();
        const isAdmin = user.roles && (user.roles.includes('SYSTEM_ADMIN') || user.roles.includes('SECURITY_OFFICER') || user.roles.includes('INTERNAL_SPONSOR'));

        if (!isSelf && !isAdmin) {
            const { ForbiddenError } = require('../utils/errors');
            throw new ForbiddenError('Access denied: You can only inspect your own external identity status.', 'ERR_FORBIDDEN_IDENTITY_ACCESS');
        }

        const userExternalIdentityRepository = require('../repositories/userExternalIdentityRepository');
        const identity = await userExternalIdentityRepository.findIdentityByUserAndProvider(targetUserId, 'GITHUB');

        const responseData = identity ? {
            linked: identity.verification_status === 'VERIFIED',
            identity_id: identity.identity_id,
            provider: identity.provider,
            external_username: identity.external_username,
            external_account_id: identity.external_account_id,
            verification_status: identity.verification_status,
            verified_at: identity.verified_at
        } : {
            linked: false,
            provider: 'GITHUB',
            verification_status: 'NOT_LINKED'
        };

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(responseData, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 13. POST /api/contractors/{id}/external-identities/manual-verify - Admin exception override
// -----------------------------------------------------------------------------
async function manualVerifyIdentityHandler(request, context) {
    try {
        const actorUser = request.authenticatedUser || request.user;
        const targetUserId = getRouteParam(request, 'id');
        const body = await parseRequestBody(request);
        const { external_username, external_account_id, justification } = body;
        const ipAddress = request.headers?.get ? request.headers.get('x-forwarded-for') : request.headers?.['x-forwarded-for'];

        const { githubOAuthService } = require('../connectors/github');
        const result = await githubOAuthService.manualVerifyContractorIdentity({
            actorUser,
            targetUserId,
            externalUsername: external_username,
            externalAccountId: external_account_id,
            justification,
            ipAddress
        });

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}



module.exports = {
    listContractors: withAuth(listContractorsHandler),
    createContractor: requireRole('SYSTEM_ADMIN', createContractorHandler),
    getContractorSelf: withAuth(getContractorSelfHandler),
    getContractorById: withAuth(getContractorByIdHandler),
    listEngagements: withAuth(listEngagementsHandler),
    getEngagementById: withAuth(getEngagementByIdHandler),
    createEngagement: withAuth(createEngagementHandler),
    updateEngagement: withAuth(updateEngagementHandler),
    transitionEngagementStatus: withAuth(transitionEngagementStatusHandler),
    initiateGitHubLink: withAuth(initiateGitHubLinkHandler),
    callbackGitHubLink: withAuth(callbackGitHubLinkHandler),
    unlinkGitHub: withAuth(unlinkGitHubHandler),
    getGitHubLinkStatus: withAuth(getGitHubLinkStatusHandler),
    manualVerifyIdentity: withAuth(manualVerifyIdentityHandler),

    // Raw handlers for testing
    createContractorHandler,
    initiateGitHubLinkHandler,
    callbackGitHubLinkHandler,
    unlinkGitHubHandler,
    getGitHubLinkStatusHandler,
    manualVerifyIdentityHandler
};

