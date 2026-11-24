/**
 * AccessLease — GitHub App Secure Authentication
 * Generates App RS256 JWTs, requests installation access tokens, and caches
 * tokens with expiration awareness and automatic renewal.
 * 
 * Target: GitHub REST API (v2022-11-28)
 */

const jwt = require('jsonwebtoken');
const githubConfig = require('./githubConfig');
const { ConnectorError } = require('../../utils/errors');
const logger = require('../../utils/logger');

// In-memory token cache: Map<installationId, { token, expiresAtMs }>
const tokenCache = new Map();

// Test hook for mocking installation token in tests
let mockInstallationTokenProvider = null;

/**
 * Sets a custom installation token provider (used by test suites).
 * Pass null to restore default behavior.
 * @param {Function|null} provider fn(installationId) => Promise<string>
 */
function setMockTokenProvider(provider) {
    mockInstallationTokenProvider = provider;
}

/**
 * Clears the internal installation token cache.
 */
function clearTokenCache() {
    tokenCache.clear();
}

/**
 * Generates an RS256 signed JWT for authenticating as the GitHub App.
 * Per GitHub specification, JWT expiration must not exceed 10 minutes.
 * @param {string} [appId] Optional override (defaults to config)
 * @param {string} [privateKey] Optional override (defaults to config)
 * @returns {string} RS256 signed JWT
 */
function generateAppJwt(appId, privateKey) {
    const config = githubConfig.getConfig();
    const effectiveAppId = appId || config.appId;
    const effectivePrivateKey = privateKey || config.privateKey;

    if (!effectiveAppId || !effectivePrivateKey) {
        throw new ConnectorError(
            'Cannot generate GitHub App JWT: Missing App ID or Private Key.',
            500,
            'ERR_GITHUB_AUTH_CONFIG',
            { category: 'CONFIGURATION_ERROR' },
            false
        );
    }

    try {
        const nowSeconds = Math.floor(Date.now() / 1000);
        const payload = {
            iat: nowSeconds - 60, // 60s in the past to allow for clock drift
            exp: nowSeconds + (10 * 60), // 10 minutes maximum allowed by GitHub
            iss: String(effectiveAppId)
        };

        return jwt.sign(payload, effectivePrivateKey, {
            algorithm: 'RS256'
        });
    } catch (err) {
        logger.error('Failed to sign GitHub App JWT', { error: err.message });
        throw new ConnectorError(
            `Failed to sign GitHub App JWT: ${err.message}`,
            500,
            'ERR_GITHUB_JWT_SIGN',
            { category: 'AUTHENTICATION_FAILURE' },
            false
        );
    }
}

/**
 * Retrieves a valid installation access token for the configured GitHub App.
 * Uses cached token if valid; requests a new token if expired or near expiration.
 * @param {string} [targetInstallationId] Optional override (defaults to config)
 * @returns {Promise<string>} Bearer installation access token
 */
async function getInstallationAccessToken(targetInstallationId) {
    if (mockInstallationTokenProvider) {
        return mockInstallationTokenProvider(targetInstallationId);
    }

    const config = githubConfig.getConfig();
    const installationId = targetInstallationId || config.installationId;

    if (!installationId) {
        throw new ConnectorError(
            'Cannot acquire GitHub installation token: Missing installation ID.',
            500,
            'ERR_GITHUB_INSTALLATION_ID_MISSING',
            { category: 'CONFIGURATION_ERROR' },
            false
        );
    }

    // 1. Check in-memory cache with 5-minute safety buffer
    const cached = tokenCache.get(installationId);
    const nowMs = Date.now();
    const safetyBufferMs = 5 * 60 * 1000; // 5 minutes

    if (cached && cached.expiresAtMs > (nowMs + safetyBufferMs)) {
        return cached.token;
    }

    // 2. Generate fresh App JWT
    const appJwt = generateAppJwt();

    // 3. Request new installation access token from GitHub API
    const url = `${config.apiBaseUrl}/app/installations/${installationId}/access_tokens`;

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${appJwt}`,
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'AccessLease-Governance-Platform'
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            let parsedError = {};
            try { parsedError = JSON.parse(errorText); } catch { /* ignore */ }

            const statusCode = response.status;
            logger.error('GitHub API installation token request failed', {
                status: statusCode,
                installationId,
                message: parsedError.message || errorText
            });

            if (statusCode === 401 || statusCode === 403) {
                throw new ConnectorError(
                    `GitHub App authentication failed (${statusCode}): ${parsedError.message || 'Unauthorized or forbidden'}`,
                    statusCode,
                    'ERR_GITHUB_AUTH_FAILED',
                    { category: 'AUTHENTICATION_FAILURE', statusCode },
                    false
                );
            }

            if (statusCode === 404) {
                throw new ConnectorError(
                    `GitHub installation ID ${installationId} not found. The app may not be installed in the target organization.`,
                    404,
                    'ERR_GITHUB_INSTALLATION_NOT_FOUND',
                    { category: 'TARGET_NOT_FOUND', statusCode },
                    false
                );
            }

            throw new ConnectorError(
                `GitHub installation token request failed with status ${statusCode}: ${parsedError.message || errorText}`,
                statusCode,
                'ERR_GITHUB_TOKEN_EXCHANGE',
                { category: statusCode >= 500 ? 'SERVER_ERROR' : 'API_ERROR', statusCode },
                statusCode >= 500
            );
        }

        const data = await response.json();
        const { token, expires_at } = data;

        if (!token) {
            throw new ConnectorError(
                'GitHub returned an empty access token in installation response.',
                502,
                'ERR_GITHUB_TOKEN_EMPTY',
                { category: 'API_ERROR' },
                false
            );
        }

        const expiresAtMs = expires_at ? new Date(expires_at).getTime() : (nowMs + 3600 * 1000);
        tokenCache.set(installationId, { token, expiresAtMs });

        return token;
    } catch (err) {
        if (err instanceof ConnectorError) throw err;

        logger.error('Network exception requesting GitHub installation token', { error: err.message });
        throw new ConnectorError(
            `Network timeout or failure reaching GitHub API: ${err.message}`,
            504,
            'ERR_GITHUB_NETWORK_ERROR',
            { category: 'NETWORK_TIMEOUT' },
            true
        );
    }
}

module.exports = {
    generateAppJwt,
    getInstallationAccessToken,
    clearTokenCache,
    setMockTokenProvider
};

