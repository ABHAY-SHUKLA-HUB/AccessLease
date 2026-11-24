/**
 * AccessLease — Authorization Middleware & Route Protectors
 * Enforces RBAC, permission policy, resource ownership, and separation of duties.
 */

const { withAuth } = require('./authMiddleware');
const { hasRole, hasAnyRole, hasPermission, hasAnyPermission, isStrictlyReadOnlyAuditor } = require('../security/permissionPolicy');
const { isAuthorizedResourceOwner, canAccessContractorData, validateSeparationOfDuties } = require('../security/resourceAccess');
const { ForbiddenError, UnauthorizedError, NotFoundError, AppError } = require('../utils/errors');
const { createErrorBody, toHttpResponse } = require('../utils/response');
const logger = require('../utils/logger');

/**
 * Standard error formatter for authorization rejections.
 */
function handleAuthError(err, request, context) {
    const correlationId = context && context.invocationId ? context.invocationId : undefined;
    const meta = correlationId ? { correlation_id: correlationId } : {};

    if (err instanceof UnauthorizedError) {
        logger.warn('Unauthorized request rejected', { code: err.code, message: err.message, path: request.url || request.path });
        return toHttpResponse(401, createErrorBody(err.code, err.message, err.details, meta));
    }

    if (err instanceof ForbiddenError) {
        const actingUser = request.authenticatedUser || request.user;
        logger.warn('Forbidden request rejected: Insufficient permissions', {
            code: err.code,
            message: err.message,
            userId: actingUser ? actingUser.user_id : 'anonymous',
            path: request.url || request.path
        });
        return toHttpResponse(403, createErrorBody(err.code, err.message, err.details, meta));
    }

    if (err instanceof NotFoundError) {
        return toHttpResponse(404, createErrorBody(err.code, err.message, err.details, meta));
    }

    if (err instanceof AppError) {
        return toHttpResponse(err.statusCode, createErrorBody(err.code, err.message, err.details, meta));
    }

    logger.error('Unexpected error in authorization middleware', { error: err.message });
    return toHttpResponse(500, createErrorBody('ERR_INTERNAL', 'An internal server error occurred.', [], meta));
}

/**
 * Middleware: Enforces that the authenticated user possesses ANY of the specified role codes.
 * 
 * @param {Array<string>} allowedRoles Role codes permitted (e.g. ['SECURITY_OFFICER', 'SYSTEM_ADMIN'])
 * @param {Function} handler Target handler
 * @returns {Function}
 */
function requireRole(allowedRoles, handler) {
    const roleList = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

    return withAuth(async function roleProtectedHandler(request, context) {
        try {
            const user = request.authenticatedUser || request.user;
            if (!hasAnyRole(user.roles, roleList)) {
                throw new ForbiddenError(
                    `Access denied: Action requires one of the following roles: ${roleList.join(', ')}.`,
                    'ERR_FORBIDDEN_ROLE'
                );
            }
            return await handler(request, context);
        } catch (err) {
            return handleAuthError(err, request, context);
        }
    });
}

/**
 * Middleware: Enforces that the authenticated user possesses ANY of the specified granular permissions.
 * 
 * @param {Array<string>} requiredPermissions
 * @param {Function} handler
 * @returns {Function}
 */
function requirePermission(requiredPermissions, handler) {
    const permList = Array.isArray(requiredPermissions) ? requiredPermissions : [requiredPermissions];

    return withAuth(async function permissionProtectedHandler(request, context) {
        try {
            const user = request.authenticatedUser || request.user;
            if (!hasAnyPermission(user.roles, permList)) {
                throw new ForbiddenError(
                    'Access denied: You do not have permission to perform this action.',
                    'ERR_FORBIDDEN_PERMISSION'
                );
            }
            return await handler(request, context);
        } catch (err) {
            return handleAuthError(err, request, context);
        }
    });
}

/**
 * Middleware: Enforces write-access guardrail (blocks strictly read-only auditors from modifying state).
 * 
 * @param {Function} handler
 * @returns {Function}
 */
function requireWriteAccess(handler) {
    return withAuth(async function writeProtectedHandler(request, context) {
        try {
            const user = request.authenticatedUser || request.user;
            if (isStrictlyReadOnlyAuditor(user.roles)) {
                throw new ForbiddenError(
                    'Access denied: Compliance Auditor role is strictly read-only. Data modifications are prohibited.',
                    'ERR_AUDITOR_READ_ONLY'
                );
            }
            return await handler(request, context);
        } catch (err) {
            return handleAuthError(err, request, context);
        }
    });
}

/**
 * Middleware: Enforces resource ownership for resource-specific operations.
 * Resolves the resourceId via resolver function and checks dbo.resource_owners.
 * 
 * @param {function(object): string} getResourceId Function extracting resourceId from request
 * @param {Function} handler
 * @returns {Function}
 */
function requireResourceOwner(getResourceId, handler) {
    return withAuth(async function resourceOwnerProtectedHandler(request, context) {
        try {
            const user = request.authenticatedUser || request.user;
            const resourceId = getResourceId(request);

            if (!resourceId) {
                throw new NotFoundError('Resource');
            }

            const isOwner = await isAuthorizedResourceOwner(user, resourceId);
            if (!isOwner) {
                throw new ForbiddenError(
                    'Access denied: You are not an authorized owner for this resource.',
                    'ERR_NOT_RESOURCE_OWNER'
                );
            }

            return await handler(request, context);
        } catch (err) {
            return handleAuthError(err, request, context);
        }
    });
}

/**
 * Middleware: Enforces contractor ownership or assigned sponsorship.
 * Prevents contractors from inspecting other contractors' records.
 * 
 * @param {function(object): { contractorUserId: string, engagementId?: string }} getTargetInfo 
 * @param {Function} handler
 * @returns {Function}
 */
function requireContractorAccess(getTargetInfo, handler) {
    return withAuth(async function contractorAccessHandler(request, context) {
        try {
            const user = request.authenticatedUser || request.user;
            const { contractorUserId, engagementId } = getTargetInfo(request);

            if (!contractorUserId) {
                throw new NotFoundError('Contractor Profile');
            }

            const isAuthorized = await canAccessContractorData(user, contractorUserId, engagementId);
            if (!isAuthorized) {
                throw new ForbiddenError(
                    'Access denied: You are not authorized to view or access this contractor record.',
                    'ERR_FORBIDDEN_CONTRACTOR_ACCESS'
                );
            }

            return await handler(request, context);
        } catch (err) {
            return handleAuthError(err, request, context);
        }
    });
}

/**
 * Middleware: Enforces Separation of Duties (requester cannot approve own request).
 * 
 * @param {function(object): string} getRequestId
 * @param {Function} handler
 * @returns {Function}
 */
function requireSeparationOfDuties(getRequestId, handler) {
    return withAuth(async function separationOfDutiesHandler(request, context) {
        try {
            const user = request.authenticatedUser || request.user;
            const requestId = getRequestId(request);

            if (!requestId) {
                throw new NotFoundError('Access Request');
            }

            const isSeparated = await validateSeparationOfDuties(user, requestId);
            if (!isSeparated) {
                throw new ForbiddenError(
                    'Separation of Duties violation: The creator of an access request cannot approve it.',
                    'ERR_SELF_APPROVAL_FORBIDDEN'
                );
            }

            return await handler(request, context);
        } catch (err) {
            return handleAuthError(err, request, context);
        }
    });
}

module.exports = {
    requireRole,
    requirePermission,
    requireWriteAccess,
    requireResourceOwner,
    requireContractorAccess,
    requireSeparationOfDuties,
    handleAuthError
};

