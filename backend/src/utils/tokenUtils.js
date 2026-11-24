/**
 * AccessLease — Microsoft Entra ID Token Verification Utility
 * 
 * Verifies OAuth 2.0 / OpenID Connect Bearer access tokens issued by Microsoft Entra ID:
 * - RS256 signature verification via Microsoft JWKS endpoint
 * - Issuer validation (v1.0 STS and v2.0 endpoints)
 * - Audience validation (API Application ID URI or Client ID)
 * - Expiration (exp) and Not-Before (nbf) enforcement
 * - Mandatory claims extraction: oid (Entra Object ID), sub, email/preferred_username
 * - Rejection of unverified, unsigned, or expired tokens (HTTP 401)
 */

const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const env = require('../config/environment');
const { UnauthorizedError } = require('./errors');
const logger = require('./logger');

// Lazy-initialized JWKS client cache
let jwksClientInstance = null;

// Optional custom key resolver for unit tests and offline test doubles
let customKeyResolver = null;

/**
 * Returns or initializes the jwks-rsa client for Microsoft Entra ID.
 * @returns {jwksRsa.JwksClient|null}
 */
function getJwksClient() {
    if (customKeyResolver) {
        return null;
    }
    const jwksUri = env.ENTRA_JWKS_URI;
    if (!jwksUri) {
        return null;
    }

    // Security: Ensure JWKS endpoint strictly points to trusted Microsoft Entra ID HTTPS endpoints
    try {
        const parsed = new URL(jwksUri);
        const trustedHosts = ['login.microsoftonline.com', 'sts.windows.net'];
        const isTrustedHost = trustedHosts.some(host => 
            parsed.hostname.toLowerCase() === host || parsed.hostname.toLowerCase().endsWith('.' + host)
        );

        if (parsed.protocol !== 'https:' || !isTrustedHost) {
            logger.error('Security alert: JWKS URI directed to untrusted host', { uri: jwksUri, host: parsed.hostname });
            throw new UnauthorizedError(
                'Untrusted JWKS endpoint configuration. Entra JWKS URI must use an official Microsoft Entra ID HTTPS endpoint.',
                'ERR_UNTRUSTED_JWKS_URI'
            );
        }
    } catch (urlErr) {
        if (urlErr instanceof UnauthorizedError) throw urlErr;
        throw new UnauthorizedError('Malformed Entra JWKS URI configuration.', 'ERR_UNTRUSTED_JWKS_URI');
    }

    if (!jwksClientInstance || jwksClientInstance.jwksUri !== jwksUri) {
        jwksClientInstance = jwksRsa({
            jwksUri,
            cache: true,
            rateLimit: true,
            jwksRequestsPerMinute: 10,
            timeout: 10000
        });
        jwksClientInstance.jwksUri = jwksUri;
    }
    return jwksClientInstance;
}

/**
 * Allows test suites to inject a custom signing key or resolver function.
 * Pass null to restore live JWKS resolution.
 * @param {Function|string|Buffer|null} resolver 
 */
function setCustomKeyResolver(resolver) {
    customKeyResolver = resolver;
}

/**
 * Key retrieval callback passed to jsonwebtoken.verify.
 * @param {object} header Decoded JWT header
 * @param {Function} callback Callback (err, key)
 */
function getKey(header, callback) {
    if (customKeyResolver) {
        if (typeof customKeyResolver === 'function') {
            return customKeyResolver(header, callback);
        }
        return callback(null, customKeyResolver);
    }

    const client = getJwksClient();
    if (!client) {
        return callback(
            new UnauthorizedError(
                'Entra ID JWKS configuration is missing. Cannot verify token signature.',
                'ERR_AUTH_CONFIG_MISSING'
            )
        );
    }

    if (!header || !header.kid) {
        return callback(
            new UnauthorizedError(
                'Access token header missing key ID (kid).',
                'ERR_INVALID_TOKEN_HEADER'
            )
        );
    }

    client.getSigningKey(header.kid, (err, key) => {
        if (err) {
            logger.warn('Failed to retrieve signing key from Microsoft JWKS', {
                kid: header.kid,
                error: err.message
            });
            return callback(
                new UnauthorizedError(
                    'Unable to find matching Microsoft Entra signing key.',
                    'ERR_SIGNING_KEY_NOT_FOUND'
                )
            );
        }
        const signingKey = key.getPublicKey ? key.getPublicKey() : key.rsaPublicKey;
        callback(null, signingKey);
    });
}

/**
 * Decodes a token without signature verification to inspect claims or header.
 * @param {string} token 
 * @returns {{ header: object, payload: object }|null}
 */
function decodeToken(token) {
    if (!token || typeof token !== 'string') return null;
    return jwt.decode(token, { complete: true });
}

/**
 * Asynchronously verifies an Entra ID JWT access token.
 * 
 * @param {string} token Bearer access token string
 * @param {object} [options={}] Optional verification overrides (for testing)
 * @returns {Promise<object>} Verified and sanitized claims payload
 * @throws {UnauthorizedError} If signature, claims, audience, issuer, or expiration fail
 */
async function validateToken(token, options = {}) {
    if (!token || typeof token !== 'string') {
        throw new UnauthorizedError('Bearer access token is required.', 'ERR_MISSING_TOKEN');
    }

    const decoded = decodeToken(token);
    if (!decoded || !decoded.header || !decoded.payload) {
        throw new UnauthorizedError('Malformed access token format.', 'ERR_INVALID_TOKEN');
    }

    // Supported signing algorithms: RS256 for live Entra tokens (or HS256 in test mode)
    const allowedAlgorithms = options.algorithms || (customKeyResolver ? ['RS256', 'HS256'] : ['RS256']);
    if (!allowedAlgorithms.includes(decoded.header.alg)) {
        throw new UnauthorizedError(
            `Unsupported token signing algorithm: ${decoded.header.alg}`,
            'ERR_UNSUPPORTED_ALGORITHM'
        );
    }

    // Determine expected audience for Backend Web API:
    // Supports verified formats for the Backend Web API registration (e.g. api://<API_CLIENT_ID> and <API_CLIENT_ID>)
    let expectedAudience;
    if (options.audience !== undefined) {
        expectedAudience = Array.isArray(options.audience) ? options.audience : [options.audience];
    } else {
        const allowed = [];
        if (env.ENTRA_API_AUDIENCE) {
            allowed.push(env.ENTRA_API_AUDIENCE);
        }
        if (env.ENTRA_API_CLIENT_ID && !allowed.includes(env.ENTRA_API_CLIENT_ID)) {
            allowed.push(env.ENTRA_API_CLIENT_ID);
        }
        expectedAudience = allowed;
    }

    // Security Check: Explicitly reject tokens issued for the Frontend SPA registration (e.g. SPA ID tokens)
    const spaClientId = options.spaClientId || env.ENTRA_SPA_CLIENT_ID;
    const tokenAud = decoded.payload ? decoded.payload.aud : null;
    if (spaClientId && tokenAud) {
        const matchesSpa = Array.isArray(tokenAud) ? tokenAud.includes(spaClientId) : tokenAud === spaClientId;
        if (matchesSpa && !expectedAudience.includes(spaClientId)) {
            throw new UnauthorizedError(
                'Access token rejected: token was issued for the Frontend SPA client, not the Backend Web API.',
                'ERR_INVALID_AUDIENCE'
            );
        }
    }

    // Determine expected issuer: tenant v2.0 or STS v1.0
    const expectedTenant = options.tenantId || env.ENTRA_TENANT_ID;
    const defaultIssuers = expectedTenant ? [
        `https://login.microsoftonline.com/${expectedTenant}/v2.0`,
        `https://sts.windows.net/${expectedTenant}/`,
        env.ENTRA_ISSUER
    ].filter(Boolean) : [];
    const expectedIssuer = options.issuer !== undefined ? options.issuer : defaultIssuers;

    const verifyOptions = {
        algorithms: allowedAlgorithms,
        clockTolerance: options.clockTolerance !== undefined ? options.clockTolerance : 5 // 5 seconds clock drift
    };

    if (expectedAudience && (Array.isArray(expectedAudience) ? expectedAudience.length > 0 : Boolean(expectedAudience))) {
        verifyOptions.audience = expectedAudience;
    }

    if (expectedIssuer && (Array.isArray(expectedIssuer) ? expectedIssuer.length > 0 : Boolean(expectedIssuer))) {
        verifyOptions.issuer = expectedIssuer;
    }

    // Promise-based verification
    const verifiedPayload = await new Promise((resolve, reject) => {
        const keyHandler = options.key || getKey;
        jwt.verify(token, keyHandler, verifyOptions, (err, payload) => {
            if (err) {
                if (err instanceof UnauthorizedError) {
                    return reject(err);
                }
                if (err.name === 'TokenExpiredError') {
                    return reject(new UnauthorizedError('Access token has expired.', 'ERR_TOKEN_EXPIRED'));
                }
                if (err.name === 'NotBeforeError') {
                    return reject(new UnauthorizedError('Access token is not yet active (nbf).', 'ERR_TOKEN_NOT_ACTIVE'));
                }
                if (err.message && err.message.includes('jwt audience invalid')) {
                    return reject(new UnauthorizedError('Access token audience (aud) is invalid.', 'ERR_INVALID_AUDIENCE'));
                }
                if (err.message && err.message.includes('jwt issuer invalid')) {
                    return reject(new UnauthorizedError('Access token issuer (iss) is invalid.', 'ERR_INVALID_ISSUER'));
                }
                if (err.name === 'JsonWebTokenError') {
                    return reject(new UnauthorizedError(`Token verification failed: ${err.message}`, 'ERR_INVALID_SIGNATURE'));
                }
                return reject(new UnauthorizedError('Token verification failed.', 'ERR_UNAUTHORIZED'));
            }
            resolve(payload);
        });
    });

    // 1. Enforce Tenant Validation: Verify tid claim strictly matches expected tenant
    if (expectedTenant) {
        if (!verifiedPayload.tid) {
            throw new UnauthorizedError(
                'Access token is missing required tenant identity claim (tid).',
                'ERR_MISSING_TENANT_ID'
            );
        }
        if (verifiedPayload.tid !== expectedTenant) {
            throw new UnauthorizedError(
                `Access token tenant ID (${verifiedPayload.tid}) does not match configured tenant (${expectedTenant}).`,
                'ERR_INVALID_TENANT_ID'
            );
        }
    }

    // 2. Enforce mandatory stable user identity claim: oid (Entra Object ID)
    const entraObjectId = verifiedPayload.oid || verifiedPayload.sub;
    if (!entraObjectId) {
        throw new UnauthorizedError(
            'Access token is missing required identity claim (oid or sub).',
            'ERR_MISSING_IDENTITY_CLAIM'
        );
    }

    // Return sanitized verified identity
    return {
        oid: entraObjectId,
        sub: verifiedPayload.sub || entraObjectId,
        email: verifiedPayload.email || verifiedPayload.preferred_username || verifiedPayload.upn || null,
        name: verifiedPayload.name || verifiedPayload.display_name || null,
        tid: verifiedPayload.tid || null,
        roles: Array.isArray(verifiedPayload.roles) ? verifiedPayload.roles : [],
        scp: verifiedPayload.scp || null,
        issuedAt: verifiedPayload.iat ? new Date(verifiedPayload.iat * 1000).toISOString() : null,
        expiresAt: verifiedPayload.exp ? new Date(verifiedPayload.exp * 1000).toISOString() : null,
        rawClaims: verifiedPayload
    };
}

module.exports = {
    validateToken,
    decodeToken,
    setCustomKeyResolver,
    getJwksClient
};

