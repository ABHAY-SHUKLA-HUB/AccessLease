/**
 * AccessLease — Orphan & Stale Access HTTP Trigger Functions
 * Azure Functions v4 REST Handlers.
 * 
 * Endpoints:
 * - POST /api/orphan-access/scan                 (Protected): Trigger orphan detection scan
 * - GET  /api/orphan-access/findings             (Protected): List orphan access findings
 * - GET  /api/orphan-access/findings/{id}        (Protected): Get details of a specific finding
 * - POST /api/orphan-access/findings/{id}/revoke (Protected): Authorize & initiate revocation
 * - POST /api/orphan-access/findings/{id}/resolve (Protected): Resolve or mark false positive
 */

const { withAuth } = require('../middleware/authMiddleware');
const orphanDetectionService = require('../services/orphanDetectionService');
const { createSuccessBody, toHttpResponse } = require('../utils/response');
const { handleAuthError } = require('../middleware/authorize');
const { hasAnyRole, isStrictlyReadOnlyAuditor } = require('../security/permissionPolicy');
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
// 1. POST /api/orphan-access/scan - Trigger on-demand orphan detection scan
// -----------------------------------------------------------------------------
async function triggerOrphanScanHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        if (isStrictlyReadOnlyAuditor(user.roles)) {
            throw new ForbiddenError('Compliance Auditors are strictly read-only and cannot trigger scans.', 'ERR_AUDITOR_READ_ONLY');
        }

        const isAuthorized = hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER']);
        if (!isAuthorized) {
            throw new ForbiddenError('Only Security Officers or System Administrators may trigger orphan scans.', 'ERR_FORBIDDEN_ROLE');
        }

        const result = await orphanDetectionService.runOrphanDetectionScan(user);
        const correlationId = context?.invocationId;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 2. GET /api/orphan-access/findings - List findings with filters
// -----------------------------------------------------------------------------
async function listOrphanFindingsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const isAuthorized = hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR', 'INTERNAL_SPONSOR']);
        if (!isAuthorized) {
            throw new ForbiddenError('You do not have permission to view orphan access findings.', 'ERR_FORBIDDEN_ROLE');
        }

        const status = getQueryParam(request, 'status');
        const severity = getQueryParam(request, 'severity');
        const reason = getQueryParam(request, 'reason');
        const limit = parseInt(getQueryParam(request, 'limit') || '50', 10);
        const offset = parseInt(getQueryParam(request, 'offset') || '0', 10);

        const filter = { status, severity, reason, limit, offset };
        const result = await orphanDetectionService.getFindings(filter);

        const correlationId = context?.invocationId;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 3. GET /api/orphan-access/findings/{id} - Get finding details
// -----------------------------------------------------------------------------
async function getOrphanFindingByIdHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const isAuthorized = hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR', 'INTERNAL_SPONSOR']);
        if (!isAuthorized) {
            throw new ForbiddenError('You do not have permission to view this finding.', 'ERR_FORBIDDEN_ROLE');
        }

        const findingId = getRouteParam(request, 'id') || getRouteParam(request, 'findingId');
        const finding = await orphanDetectionService.getFindingDetails(findingId);

        const correlationId = context?.invocationId;
        return toHttpResponse(200, createSuccessBody(finding, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 4. POST /api/orphan-access/findings/{id}/revoke - Initiate revocation for finding
// -----------------------------------------------------------------------------
async function revokeOrphanFindingHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        if (isStrictlyReadOnlyAuditor(user.roles)) {
            throw new ForbiddenError('Compliance Auditors are strictly read-only and cannot initiate revocation.', 'ERR_AUDITOR_READ_ONLY');
        }

        const findingId = getRouteParam(request, 'id') || getRouteParam(request, 'findingId');
        const body = await parseRequestBody(request);
        const resolutionNotes = body.resolutionNotes || body.reason || null;

        const result = await orphanDetectionService.initiateFindingRevocation(findingId, user, resolutionNotes);

        const correlationId = context?.invocationId;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 5. POST /api/orphan-access/findings/{id}/resolve - Resolve/dismiss finding
// -----------------------------------------------------------------------------
async function resolveOrphanFindingHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        if (isStrictlyReadOnlyAuditor(user.roles)) {
            throw new ForbiddenError('Compliance Auditors are strictly read-only.', 'ERR_AUDITOR_READ_ONLY');
        }

        const findingId = getRouteParam(request, 'id') || getRouteParam(request, 'findingId');
        const body = await parseRequestBody(request);
        const status = body.status || 'RESOLVED';
        const resolutionNotes = body.resolutionNotes || body.reason;

        const result = await orphanDetectionService.resolveFinding(
            findingId,
            user,
            status,
            resolutionNotes,
            { allowOverride: Boolean(body.allowOverride || body.adminOverride) }
        );

        const correlationId = context?.invocationId;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

module.exports = {
    triggerOrphanScan: withAuth(triggerOrphanScanHandler),
    listOrphanFindings: withAuth(listOrphanFindingsHandler),
    getOrphanFindingById: withAuth(getOrphanFindingByIdHandler),
    revokeOrphanFinding: withAuth(revokeOrphanFindingHandler),
    resolveOrphanFinding: withAuth(resolveOrphanFindingHandler)
};

