/**
 * AccessLease — Identity & Authentication Service
 * Orchestrates token verification, identity mapping, and profile construction.
 */

const tokenUtils = require('../utils/tokenUtils');
const userRepository = require('../repositories/userRepository');
const { UnauthorizedError, ForbiddenError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Authenticates an incoming Bearer token and resolves the application user profile.
 * 
 * Flow:
 * 1. Cryptographically verifies JWT token (signature, exp, nbf, aud, iss).
 * 2. Extracts stable Microsoft Entra Object ID (oid claim).
 * 3. Resolves user from dbo.users by entra_object_id.
 * 4. Verifies account active status (is_active = 1).
 * 5. Loads assigned RBAC roles from dbo.user_roles.
 * 6. Returns a sanitized, secure user identity object.
 * 
 * @param {string} token Bearer access token string
 * @param {object} [options={}] Optional token validation overrides (for test doubles)
 * @returns {Promise<object>} Sanitized authenticated user profile
 */
async function authenticateToken(token, options = {}) {
    // 1. Verify token cryptographic signature and standard claims
    const verifiedClaims = await tokenUtils.validateToken(token, options);

    const entraObjectId = verifiedClaims.oid;
    if (!entraObjectId) {
        throw new UnauthorizedError(
            'Token does not contain a valid Entra Object ID (oid).',
            'ERR_MISSING_OID_CLAIM'
        );
    }

    // 2. Identity mapping: Map Entra OID to internal application user
    const user = await userRepository.findUserByEntraObjectId(entraObjectId);

    // 3. Reject unknown identities not registered in AccessLease
    if (!user) {
        logger.warn('Authentication rejected: Entra identity not registered in AccessLease', {
            entraObjectId,
            email: verifiedClaims.email
        });
        throw new UnauthorizedError(
            'Authenticated identity is not registered as an authorized AccessLease user.',
            'ERR_USER_NOT_REGISTERED'
        );
    }

    // 4. Reject deactivated accounts
    if (!user.is_active) {
        logger.warn('Authentication rejected: User account is inactive', {
            userId: user.user_id,
            entraObjectId
        });
        throw new ForbiddenError(
            'Access denied: User account is currently deactivated.',
            'ERR_USER_INACTIVE'
        );
    }

    // 5. Fetch assigned system roles
    const roles = await userRepository.getUserRoles(user.user_id);

    // 6. Return sanitized application profile (Strictly NO secrets, tokens, or hashes)
    return {
        user_id: user.user_id,
        entra_object_id: user.entra_object_id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        display_name: user.display_name,
        user_type: user.user_type,
        department: user.department,
        is_active: Boolean(user.is_active),
        roles: roles.map(r => ({
            role_id: r.role_id,
            role_code: r.role_code,
            role_name: r.role_name
        })),
        token_metadata: {
            oid: verifiedClaims.oid,
            tid: verifiedClaims.tid,
            expires_at: verifiedClaims.expiresAt
        }
    };
}

module.exports = {
    authenticateToken
};
