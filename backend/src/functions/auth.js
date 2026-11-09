/**
 * AccessLease — Authentication HTTP Trigger Functions
 * 
 * Endpoints:
 * - GET /api/auth/me      (Protected): Returns authenticated user profile and roles from dbo.users
 * - GET /api/auth/config  (Public):    Returns sanitized MSAL bootstrap configuration
 */

const { withAuth } = require('../middleware/authMiddleware');
const env = require('../config/environment');
const { createSuccessBody, toHttpResponse } = require('../utils/response');
const logger = require('../utils/logger');

/**
 * GET /api/auth/me (Protected handler)
 * Returns the resolved and verified application user profile.
 * 
 * @param {object} request Azure Functions HttpRequest (with user attached by withAuth)
 * @param {object} context Azure Functions InvocationContext
 * @returns {Promise<object>} Azure Functions HTTP response
 */
async function getAuthMeHandler(request, context) {
    const user = request.user;
    const correlationId = context && context.invocationId ? context.invocationId : undefined;

    logger.info('Protected /api/auth/me accessed by authenticated user', {
        userId: user.user_id,
        userType: user.user_type,
        rolesCount: user.roles ? user.roles.length : 0
    });

    return toHttpResponse(
        200,
        createSuccessBody(
            {
                user: {
                    user_id: user.user_id,
                    entra_object_id: user.entra_object_id,
                    email: user.email,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    display_name: user.display_name,
                    user_type: user.user_type,
                    department: user.department,
                    is_active: user.is_active,
                    roles: user.roles
                },
                session: {
                    authenticated: true,
                    auth_provider: 'Microsoft Entra ID',
                    tenant_id: user.token_metadata ? user.token_metadata.tid : null,
                    expires_at: user.token_metadata ? user.token_metadata.expires_at : null
                }
            },
            correlationId ? { correlation_id: correlationId } : {}
        )
    );
}

/**
 * GET /api/auth/config (Public handler)
 * Returns non-sensitive Entra ID configuration parameters required by MSAL Browser.
 * 
 * @param {object} request Azure Functions HttpRequest
 * @param {object} context Azure Functions InvocationContext
 * @returns {Promise<object>} Azure Functions HTTP response
 */
async function getAuthConfigHandler(request, context) {
    const authConfig = env.getPublicAuthConfig();
    const correlationId = context && context.invocationId ? context.invocationId : undefined;

    return toHttpResponse(
        200,
        createSuccessBody(
            authConfig,
            correlationId ? { correlation_id: correlationId } : {}
        )
    );
}

// Protected export wrapped with withAuth middleware
const getAuthMe = withAuth(getAuthMeHandler);

module.exports = {
    getAuthMe,
    getAuthMeHandler,
    getAuthConfigHandler
};
