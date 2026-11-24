/**
 * AccessLease — GitHub OAuth Account Linking Service
 * Handles secure, contractor-initiated GitHub identity proof-of-ownership via OAuth 2.0.
 * 
 * Governance Rules:
 * - Replaces administrative assertion with cryptographic identity proof.
 * - CSRF state is signed with HMAC-SHA256, user-bound, and strictly time-limited.
 * - Binds immutable numeric GitHub User ID and login to the authenticated contractor.
 * - Enforces account uniqueness: A GitHub account cannot be linked to multiple AccessLease users.
 * - Zero secret leakage: OAuth tokens are used in-memory only and never logged or persisted.
 * - Administrative verification remains a strictly audited exception requiring business justification.
 */

const crypto = require('crypto');
const env = require('../../config/environment');
const userExternalIdentityRepository = require('../../repositories/userExternalIdentityRepository');
const userRepository = require('../../repositories/userRepository');
const auditRepository = require('../../repositories/auditRepository');
const oauthStateRepository = require('../../repositories/oauthStateRepository');
const { hasAnyRole } = require('../../security/permissionPolicy');
const {
    ValidationError,
    ConflictError,
    NotFoundError,
    ForbiddenError,
    ConfigurationError,
    ConnectorError
} = require('../../utils/errors');
const logger = require('../../utils/logger');

// State expiration: 10 minutes
const STATE_MAX_AGE_MS = 10 * 60 * 1000;

/**
 * Returns HMAC secret key for OAuth state signing.
 */
function getStateSecret() {
    return process.env.SESSION_SECRET ||
           process.env.ENTRA_CLIENT_SECRET ||
           process.env.APP_SECRET ||
           'accesslease-github-oauth-state-hmac-secret-v1';
}

/**
 * Generates a high-entropy PKCE code_verifier (32 random bytes, base64url-encoded).
 * @returns {string} PKCE code_verifier
 */
function generateCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url');
}

/**
 * Computes SHA-256 base64url PKCE code_challenge from a code_verifier (RFC 7636).
 * @param {string} verifier
 * @returns {string} PKCE code_challenge (S256)
 */
function generateCodeChallenge(verifier) {
    if (!verifier || typeof verifier !== 'string') {
        throw new ValidationError('code_verifier is required to generate code_challenge.');
    }
    return crypto.createHash('sha256').update(verifier).digest('base64url');
}

/**
 * Generates a signed, tamper-proof OAuth state token.
 * @param {string} userId AccessLease user GUID
 * @returns {string} Signed state token
 */
function generateOAuthState(userId) {
    if (!userId || typeof userId !== 'string') {
        throw new ValidationError('userId is required to generate OAuth state.');
    }

    const payload = {
        u: userId.trim(),
        t: Date.now(),
        n: crypto.randomBytes(16).toString('hex')
    };

    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.createHmac('sha256', getStateSecret())
        .update(encodedPayload)
        .digest('base64url');

    return `${encodedPayload}.${signature}`;
}

/**
 * Validates and unpacks an OAuth state token.
 * Enforces signature validity, user binding, and time-to-live.
 * @param {string} stateString State parameter from OAuth callback
 * @param {string} expectedUserId Authenticated contractor GUID
 * @returns {object} Validated payload
 */
function verifyOAuthState(stateString, expectedUserId) {
    if (!stateString || typeof stateString !== 'string') {
        throw new ValidationError('OAuth state parameter is required.', [], 'ERR_MISSING_OAUTH_STATE');
    }

    const parts = stateString.split('.');
    if (parts.length !== 2) {
        throw new ValidationError('Malformed OAuth state parameter format.', [], 'ERR_INVALID_OAUTH_STATE');
    }

    const [encodedPayload, signature] = parts;
    const expectedSig = crypto.createHmac('sha256', getStateSecret())
        .update(encodedPayload)
        .digest('base64url');

    const sigBuffer = Buffer.from(signature);
    const expectedSigBuffer = Buffer.from(expectedSig);

    if (sigBuffer.length !== expectedSigBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedSigBuffer)) {
        logger.warn('OAuth state HMAC signature mismatch', { expectedUserId });
        throw new ValidationError('Invalid OAuth state signature. Possible tampering detected.', [], 'ERR_INVALID_OAUTH_STATE');
    }

    let payload;
    try {
        payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    } catch {
        throw new ValidationError('Invalid OAuth state payload encoding.', [], 'ERR_INVALID_OAUTH_STATE');
    }

    if (!payload.u || !payload.t) {
        throw new ValidationError('Incomplete OAuth state payload.', [], 'ERR_INVALID_OAUTH_STATE');
    }

    // Enforce user binding
    if (expectedUserId && payload.u.toLowerCase() !== expectedUserId.trim().toLowerCase()) {
        logger.warn('OAuth state user mismatch', { expectedUserId, stateUser: payload.u });
        throw new ValidationError(
            'OAuth state does not match the currently authenticated user.',
            [],
            'ERR_OAUTH_USER_MISMATCH'
        );
    }

    // Enforce expiry (10 minutes)
    const age = Date.now() - payload.t;
    if (age > STATE_MAX_AGE_MS || age < -30000) { // allow 30s clock skew
        throw new ValidationError('OAuth state has expired. Please initiate account linking again.', [], 'ERR_OAUTH_STATE_EXPIRED');
    }

    return payload;
}

/**
 * Initiates the GitHub account-linking flow.
 * Generates signed state and GitHub authorization URL.
 * @param {object} user Authenticated AccessLease user
 * @param {string} [customRedirectUri=null]
 * @returns {Promise<object>} { authorization_url, state, expires_in_seconds }
 */
async function getAuthorizationUrl(user, customRedirectUri = null) {
    if (!user || !user.user_id) {
        throw new ValidationError('Authenticated user is required.');
    }

    // Check if contractor already has a verified GitHub account
    const existing = await userExternalIdentityRepository.findIdentityByUserAndProvider(user.user_id, 'GITHUB');
    if (existing && existing.verification_status === 'VERIFIED') {
        throw new ConflictError(
            `You already have a verified GitHub account (@${existing.external_username}) linked. Please unlink it before linking a new account.`,
            'ERR_GITHUB_ALREADY_LINKED'
        );
    }

    const clientId = env.GITHUB_OAUTH_CLIENT_ID;
    if (!clientId) {
        throw new ConfigurationError(
            'GitHub OAuth Client ID is not configured (GITHUB_OAUTH_CLIENT_ID). Account linking via OAuth cannot be initiated.',
            'ERR_GITHUB_OAUTH_NOT_CONFIGURED'
        );
    }

    const redirectUri = customRedirectUri || env.GITHUB_OAUTH_REDIRECT_URI || `${env.ENTRA_REDIRECT_URI.replace(/\/+$/, '')}/api/contractors/me/github/callback`;
    const state = generateOAuthState(user.user_id);
    const statePayload = verifyOAuthState(state, user.user_id);
    const stateNonce = statePayload.n;

    // RFC 7636 PKCE Generation
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const expiresAt = new Date(Date.now() + STATE_MAX_AGE_MS);

    // Persist OAuth state and PKCE verifier server-side for one-time atomic consumption
    await oauthStateRepository.saveOAuthState({
        stateNonce,
        userId: user.user_id,
        codeVerifier,
        expiresAt
    });

    const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: 'read:user',
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256'
    });

    const authorizationUrl = `https://github.com/login/oauth/authorize?${params.toString()}`;

    return {
        authorization_url: authorizationUrl,
        state,
        expires_in_seconds: Math.floor(STATE_MAX_AGE_MS / 1000)
    };
}

/**
 * Exchanges authorization code for an OAuth access token with GitHub.
 * Supports PKCE code_verifier transmission.
 * @param {string} code
 * @param {string} [redirectUri=null]
 * @param {string} [codeVerifier=null]
 * @returns {Promise<string>} Access token (in-memory only)
 */
async function exchangeCodeForToken(code, redirectUri = null, codeVerifier = null) {
    if (!code || typeof code !== 'string') {
        throw new ValidationError('Authorization code is required from GitHub callback.');
    }

    const clientId = env.GITHUB_OAUTH_CLIENT_ID;
    const clientSecret = env.GITHUB_OAUTH_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
        throw new ConfigurationError(
            'GitHub OAuth credentials (GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET) are not configured. Cannot exchange OAuth authorization code.',
            'ERR_GITHUB_OAUTH_CREDENTIALS_MISSING'
        );
    }

    const tokenUrl = 'https://github.com/login/oauth/access_token';
    const body = {
        client_id: clientId,
        client_secret: clientSecret,
        code: code.trim(),
        redirect_uri: redirectUri || env.GITHUB_OAUTH_REDIRECT_URI || undefined
    };

    if (codeVerifier) {
        body.code_verifier = codeVerifier.trim();
    }

    let response;
    try {
        response = await fetch(tokenUrl, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'User-Agent': 'AccessLease-Governance-Platform/1.0.0'
            },
            body: JSON.stringify(body)
        });
    } catch (err) {
        logger.error('Failed to connect to GitHub OAuth token endpoint', { error: err.message });
        throw new ConnectorError(
            `Network error connecting to GitHub OAuth token service: ${err.message}`,
            502,
            'ERR_GITHUB_OAUTH_NETWORK',
            { category: 'NETWORK_ERROR' },
            true
        );
    }

    const data = await response.json();

    if (data.error) {
        logger.warn('GitHub OAuth token exchange failed', { error: data.error, errorDescription: data.error_description });
        throw new ConnectorError(
            `GitHub OAuth token exchange rejected: ${data.error_description || data.error}`,
            400,
            'ERR_GITHUB_OAUTH_EXCHANGE_FAILED',
            { category: 'OAUTH_ERROR', error: data.error }
        );
    }

    if (!data.access_token) {
        throw new ConnectorError(
            'GitHub OAuth token endpoint returned an empty access token.',
            502,
            'ERR_GITHUB_OAUTH_EMPTY_TOKEN'
        );
    }

    return data.access_token;
}

/**
 * Queries GitHub's authenticated user API (/user) using the ephemeral OAuth token.
 * @param {string} accessToken
 * @returns {Promise<{ id: number, login: string, name: string, email: string }>}
 */
async function fetchAuthenticatedGitHubUser(accessToken) {
    let response;
    try {
        response = await fetch(`${env.GITHUB_API_BASE_URL}/user`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/vnd.github+json',
                'User-Agent': 'AccessLease-Governance-Platform/1.0.0'
            }
        });
    } catch (err) {
        logger.error('Failed querying GitHub user profile API', { error: err.message });
        throw new ConnectorError(
            `Failed to query GitHub authenticated user API: ${err.message}`,
            502,
            'ERR_GITHUB_USER_API_NETWORK',
            { category: 'NETWORK_ERROR' },
            true
        );
    }

    if (!response.ok) {
        const errorText = await response.text();
        logger.warn('GitHub /user API returned non-200', { status: response.status, body: errorText });
        throw new ConnectorError(
            `GitHub user profile lookup failed with HTTP ${response.status}`,
            response.status,
            'ERR_GITHUB_USER_LOOKUP_FAILED'
        );
    }

    const data = await response.json();
    if (!data.id || !data.login) {
        throw new ConnectorError(
            'GitHub user profile response missing required id or login fields.',
            502,
            'ERR_GITHUB_INVALID_USER_PROFILE'
        );
    }

    return {
        id: data.id,
        login: data.login,
        name: data.name || data.login,
        email: data.email || null
    };
}

/**
 * Handles the complete OAuth callback, verifies identity, binds account, and records audit trail.
 * @param {object} params
 * @param {object} params.user Authenticated AccessLease user
 * @param {string} params.code Authorization code from GitHub
 * @param {string} params.state Signed state token
 * @param {string} [params.redirectUri=null]
 * @param {string} [params.ipAddress=null]
 * @returns {Promise<object>} Safe public identity metadata (no secrets)
 */
async function linkContractorGitHubAccount({ user, code, state, redirectUri = null, ipAddress = null }) {
    if (!user || !user.user_id) {
        throw new ValidationError('Authenticated user context is required.');
    }

    // 1. Validate signed OAuth state & user binding
    const statePayload = verifyOAuthState(state, user.user_id);

    // 2. Atomically consume OAuth state nonce server-side to prevent replay attacks
    const stateConsumption = await oauthStateRepository.consumeOAuthState(statePayload.n, user.user_id);
    if (stateConsumption.outcome === 'ALREADY_CONSUMED') {
        logger.warn('OAuth state replay attack detected', { userId: user.user_id, stateNonce: statePayload.n });
        throw new ValidationError(
            'OAuth state has already been consumed. Replay attack detected. Please initiate account linking again.',
            [],
            'ERR_OAUTH_STATE_REPLAY'
        );
    }
    if (stateConsumption.outcome === 'EXPIRED') {
        throw new ValidationError(
            'OAuth state has expired. Please initiate account linking again.',
            [],
            'ERR_OAUTH_STATE_EXPIRED'
        );
    }
    if (stateConsumption.outcome === 'NOT_FOUND') {
        throw new ValidationError(
            'Invalid OAuth state. State record was not found or belongs to another user.',
            [],
            'ERR_INVALID_OAUTH_STATE'
        );
    }

    const codeVerifier = stateConsumption.state?.codeVerifier || null;

    // 3. Exchange code for temporary access token (transmitting PKCE code_verifier)
    let accessToken = await module.exports.exchangeCodeForToken(code, redirectUri, codeVerifier);

    let githubProfile;
    try {
        // 4. Query authenticated GitHub user profile
        githubProfile = await module.exports.fetchAuthenticatedGitHubUser(accessToken);
    } finally {
        // Note: Setting accessToken to null dereferences the variable for V8 garbage collection;
        // under V8 GC semantics, dereferencing does not guarantee immediate zero-wipe of process memory buffers.
        accessToken = null;
    }

    const numericAccountId = String(githubProfile.id);
    const githubUsername = githubProfile.login;

    // 5. Enforce Account Uniqueness Across AccessLease
    // 5a. Check by GitHub username
    const existingByUsername = await userExternalIdentityRepository.findUserByExternalUsername('GITHUB', githubUsername);
    if (existingByUsername && existingByUsername.user_id.toLowerCase() !== user.user_id.toLowerCase()) {
        logger.warn('GitHub account linking rejected: Username already bound to another user', {
            targetUser: user.user_id,
            existingUser: existingByUsername.user_id,
            githubUsername
        });
        throw new ConflictError(
            `GitHub account @${githubUsername} is already linked to another AccessLease user. Account sharing is strictly forbidden.`,
            'ERR_GITHUB_ACCOUNT_ALREADY_BOUND'
        );
    }

    // 5b. Check by immutable numeric GitHub ID
    const existingById = await userExternalIdentityRepository.findIdentityByProviderAndAccountId('GITHUB', numericAccountId);
    if (existingById && existingById.user_id.toLowerCase() !== user.user_id.toLowerCase()) {
        logger.warn('GitHub account linking rejected: Account ID already bound to another user', {
            targetUser: user.user_id,
            existingUser: existingById.user_id,
            numericAccountId
        });
        throw new ConflictError(
            `This GitHub account (ID: ${numericAccountId}) is already linked to another AccessLease user.`,
            'ERR_GITHUB_ACCOUNT_ALREADY_BOUND'
        );
    }

    // 6. Bind Verified Identity in Database
    const identity = await userExternalIdentityRepository.upsertExternalIdentity({
        userId: user.user_id,
        provider: 'GITHUB',
        externalAccountId: numericAccountId,
        externalUsername: githubUsername,
        verificationStatus: 'VERIFIED',
        verifiedByUserId: user.user_id // Self-verified via OAuth cryptographic proof
    });

    // 7. Record Immutable Governance Audit Event
    await auditRepository.createAuditEvent({
        eventCategory: 'PROVISIONING',
        eventAction: 'GITHUB_ACCOUNT_LINKED_OAUTH',
        entityType: 'user_external_identities',
        entityId: identity.identity_id,
        actorUserId: user.user_id,
        actorType: 'USER',
        eventPayload: {
            provider: 'GITHUB',
            external_account_id: numericAccountId,
            external_username: githubUsername,
            verification_method: 'OAUTH_AUTHORIZATION_CODE',
            linked_user_id: user.user_id
        },
        ipAddress: ipAddress || null
    });

    logger.info('Successfully verified and linked contractor GitHub account via OAuth', {
        userId: user.user_id,
        githubUsername,
        numericAccountId
    });

    return {
        identity_id: identity.identity_id,
        provider: 'GITHUB',
        external_username: githubUsername,
        external_account_id: numericAccountId,
        verification_status: 'VERIFIED',
        verified_at: identity.verified_at,
        verification_method: 'OAUTH_AUTHORIZATION_CODE'
    };
}

/**
 * Unlinks / revokes a linked GitHub identity.
 * @param {object} params
 * @param {object} params.user Authenticated user
 * @param {string} [params.targetUserId=null] Target user ID (admin or self)
 * @param {string} [params.ipAddress=null]
 * @returns {Promise<object>}
 */
async function unlinkContractorGitHubAccount({ user, targetUserId = null, ipAddress = null }) {
    if (!user || !user.user_id) {
        throw new ValidationError('Authenticated user is required.');
    }

    const effectiveTargetId = (targetUserId || user.user_id).trim();
    const isSelf = effectiveTargetId.toLowerCase() === user.user_id.toLowerCase();
    const isAdmin = hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER']);

    if (!isSelf && !isAdmin) {
        throw new ForbiddenError(
            'Access denied: You can only unlink your own external identity unless you possess SYSTEM_ADMIN or SECURITY_OFFICER privileges.',
            'ERR_FORBIDDEN_UNLINK'
        );
    }

    const existing = await userExternalIdentityRepository.findIdentityByUserAndProvider(effectiveTargetId, 'GITHUB');
    if (!existing || existing.verification_status === 'REVOKED') {
        throw new NotFoundError(`Active GitHub external identity for user '${effectiveTargetId}'`);
    }

    const revoked = await userExternalIdentityRepository.revokeExternalIdentity(existing.identity_id, user.user_id);

    await auditRepository.createAuditEvent({
        eventCategory: 'PROVISIONING',
        eventAction: 'GITHUB_ACCOUNT_UNLINKED',
        entityType: 'user_external_identities',
        entityId: existing.identity_id,
        actorUserId: user.user_id,
        actorType: 'USER',
        eventPayload: {
            target_user_id: effectiveTargetId,
            provider: 'GITHUB',
            unlinked_username: existing.external_username,
            unlinked_by_user_id: user.user_id,
            is_self_service: isSelf
        },
        ipAddress: ipAddress || null
    });

    logger.info('Revoked contractor GitHub external identity', {
        identityId: existing.identity_id,
        targetUserId: effectiveTargetId,
        actorUserId: user.user_id
    });

    return {
        success: true,
        identity_id: existing.identity_id,
        provider: 'GITHUB',
        external_username: existing.external_username,
        verification_status: 'REVOKED',
        unlinked_at: revoked ? revoked.updated_at : new Date().toISOString()
    };
}

/**
 * Controlled Administrative Verification Exception.
 * Used ONLY when an administrator manually asserts an identity without OAuth.
 * Strictly audited as a policy exception.
 * @param {object} params
 * @returns {Promise<object>}
 */
async function manualVerifyContractorIdentity({ actorUser, targetUserId, externalUsername, externalAccountId = null, justification, ipAddress = null }) {
    if (!actorUser || !actorUser.user_id) {
        throw new ValidationError('Authenticated actor user is required.');
    }

    const isAdmin = hasAnyRole(actorUser.roles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER']);
    if (!isAdmin) {
        throw new ForbiddenError(
            'Access denied: Manual identity verification without OAuth is an administrative override restricted to SYSTEM_ADMIN and SECURITY_OFFICER roles.',
            'ERR_FORBIDDEN_MANUAL_VERIFY'
        );
    }

    if (!justification || typeof justification !== 'string' || justification.trim().length < 10) {
        throw new ValidationError(
            'A detailed justification of at least 10 characters is mandatory to record an administrative identity verification exception.',
            [],
            'ERR_JUSTIFICATION_REQUIRED'
        );
    }

    if (!externalUsername || typeof externalUsername !== 'string') {
        throw new ValidationError('A valid external GitHub username is required.');
    }

    const cleanUsername = externalUsername.trim();

    // Check account uniqueness
    const existing = await userExternalIdentityRepository.findUserByExternalUsername('GITHUB', cleanUsername);
    if (existing && existing.user_id.toLowerCase() !== targetUserId.trim().toLowerCase()) {
        throw new ConflictError(
            `GitHub account @${cleanUsername} is already linked to another AccessLease user.`,
            'ERR_GITHUB_ACCOUNT_ALREADY_BOUND'
        );
    }

    const identity = await userExternalIdentityRepository.upsertExternalIdentity({
        userId: targetUserId.trim(),
        provider: 'GITHUB',
        externalAccountId: externalAccountId ? String(externalAccountId).trim() : null,
        externalUsername: cleanUsername,
        verificationStatus: 'VERIFIED',
        verifiedByUserId: actorUser.user_id
    });

    // Record high-priority audit event for manual exception
    await auditRepository.createAuditEvent({
        eventCategory: 'PROVISIONING',
        eventAction: 'IDENTITY_MANUAL_VERIFICATION_EXCEPTION',
        entityType: 'user_external_identities',
        entityId: identity.identity_id,
        actorUserId: actorUser.user_id,
        actorType: 'USER',
        eventPayload: {
            target_user_id: targetUserId.trim(),
            provider: 'GITHUB',
            external_username: cleanUsername,
            verified_by_user_id: actorUser.user_id,
            justification: justification.trim(),
            warning: 'ADMIN_MANUAL_ASSERTION_WITHOUT_OAUTH_PROOF'
        },
        ipAddress: ipAddress || null
    });

    logger.warn('Administrative identity verification exception granted without OAuth proof', {
        targetUserId,
        actorUserId: actorUser.user_id,
        externalUsername: cleanUsername,
        justification: justification.trim()
    });

    return {
        identity_id: identity.identity_id,
        provider: 'GITHUB',
        external_username: cleanUsername,
        verification_status: 'VERIFIED',
        verified_at: identity.verified_at,
        verification_method: 'ADMINISTRATIVE_EXCEPTION'
    };
}

module.exports = {
    generateCodeVerifier,
    generateCodeChallenge,
    generateOAuthState,
    verifyOAuthState,
    getAuthorizationUrl,
    exchangeCodeForToken,
    fetchAuthenticatedGitHubUser,
    linkContractorGitHubAccount,
    unlinkContractorGitHubAccount,
    manualVerifyContractorIdentity,
    STATE_MAX_AGE_MS
};
