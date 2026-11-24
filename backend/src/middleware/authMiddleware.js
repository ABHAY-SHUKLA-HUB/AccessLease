/**
 * AccessLease — Authentication Middleware
 * Validates Bearer tokens and attaches authenticated user context to Azure Functions v4 invocations.
 */

const authService = require('../services/authService');
const { UnauthorizedError, ForbiddenError, AppError } = require('../utils/errors');
const { createErrorBody, toHttpResponse } = require('../utils/response');
const logger = require('../utils/logger');

/**
 * Extracts Bearer token from request headers.
 * Supports Azure Functions v4 HttpRequest (Map/get), Node IncomingMessage, or standard object.
 * 
 * @param {object} request Azure Functions HttpRequest
 * @returns {string} Extracted raw JWT string
 * @throws {UnauthorizedError} If header is missing or malformed
 */
function extractBearerToken(request) {
    if (!request || !request.headers) {
        throw new UnauthorizedError('Authorization header is required.', 'ERR_MISSING_AUTH_HEADER');
    }

    let authHeader = null;
    if (typeof request.headers.get === 'function') {
        authHeader = request.headers.get('authorization') || request.headers.get('Authorization');
    } else if (request.headers instanceof Map) {
        authHeader = request.headers.get('authorization') || request.headers.get('Authorization');
    } else {
        authHeader = request.headers['authorization'] || request.headers['Authorization'];
    }

    if (!authHeader || typeof authHeader !== 'string') {
        throw new UnauthorizedError('Authorization header is required.', 'ERR_MISSING_AUTH_HEADER');
    }

    const parts = authHeader.trim().split(/\s+/);
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
        throw new UnauthorizedError(
            'Invalid Authorization header scheme. Format must be "Bearer <token>".',
            'ERR_INVALID_AUTH_HEADER'
        );
    }

    const token = parts[1].trim();
    if (!token) {
        throw new UnauthorizedError('Bearer token is empty.', 'ERR_EMPTY_TOKEN');
    }

    return token;
}

/**
 * Authenticates an incoming request and returns the resolved application user.
 * 
 * @param {object} request Azure Functions HttpRequest
 * @param {object} [context={}] Azure Functions InvocationContext
 * @param {object} [options={}] Optional authentication overrides (for tests)
 * @returns {Promise<object>} Resolved user profile
 */
async function authenticateRequest(request, context = {}, options = {}) {
    // If request already has a verified authenticated user attached (e.g. chained middleware), reuse it
    if (request && request.authenticatedUser && typeof request.authenticatedUser === 'object' && request.authenticatedUser.user_id) {
        if (context) {
            context.authenticatedUser = request.authenticatedUser;
        }
        return request.authenticatedUser;
    }

    // Support legacy/test plain mock objects that attach request.user
    if (request && request.user && typeof request.user === 'object' && request.user.user_id) {
        request.authenticatedUser = request.user;
        if (context) {
            context.authenticatedUser = request.user;
        }
        return request.authenticatedUser;
    }

    const token = extractBearerToken(request);
    const user = await authService.authenticateToken(token, options);
    
    // Attach resolved application profile under dedicated non-reserved property
    // (HttpRequest.user is a native read-only getter in @azure/functions v4)
    request.authenticatedUser = user;
    if (context) {
        context.authenticatedUser = user;
    }

    return user;
}

/**
 * Higher-order middleware wrapper for Azure Functions v4 HTTP handlers.
 * Enforces token validation and identity mapping before invoking the target handler.
 * 
 * @param {Function} handler Target Azure Functions v4 handler: (request, context) => Promise<HttpResponse>
 * @param {object} [options={}] Optional authentication overrides
 * @returns {Function} Wrapped HTTP handler
 */
function withAuth(handler, options = {}) {
    return async function authenticatedHandler(request, context) {
        try {
            await authenticateRequest(request, context, options);
            return await handler(request, context);
        } catch (err) {
            const correlationId = context && context.invocationId ? context.invocationId : undefined;
            const meta = correlationId ? { correlation_id: correlationId } : {};

            if (err instanceof UnauthorizedError) {
                logger.warn('Unauthorized request rejected', {
                    code: err.code,
                    message: err.message,
                    path: request.url || request.path
                });
                return toHttpResponse(401, createErrorBody(err.code, err.message, err.details, meta));
            }

            if (err instanceof ForbiddenError) {
                logger.warn('Forbidden request rejected', {
                    code: err.code,
                    message: err.message,
                    path: request.url || request.path
                });
                return toHttpResponse(403, createErrorBody(err.code, err.message, err.details, meta));
            }

            if (err instanceof AppError) {
                return toHttpResponse(err.statusCode, createErrorBody(err.code, err.message, err.details, meta));
            }

            logger.error('Unexpected error in authentication middleware', {
                error: err.message,
                stack: err.stack
            });
            return toHttpResponse(500, createErrorBody('ERR_INTERNAL', 'An internal server error occurred.', [], meta));
        }
    };
}

module.exports = {
    extractBearerToken,
    authenticateRequest,
    withAuth
};

