/**
 * AccessLease — GitHub API HTTP Client
 * Authenticated REST client with rate-limit tracking, backoff calculation,
 * timeout handling, and classified error handling.
 */

const githubConfig = require('./githubConfig');
const githubAuth = require('./githubAuth');
const { ConnectorError } = require('../../utils/errors');
const logger = require('../../utils/logger');

// Test hook for mocking raw API responses
let customTransport = null;

function setCustomTransport(transport) {
    customTransport = transport;
}

/**
 * Performs an authenticated request to the GitHub REST API.
 * @param {string} endpoint e.g. '/orgs/accesslease-org/teams/dev-team'
 * @param {object} [options={}] { method, body, timeoutMs, customHeaders }
 * @returns {Promise<{ status: number, data: any, headers: Headers }>}
 */
async function request(endpoint, options = {}) {
    if (customTransport) {
        return customTransport(endpoint, options);
    }

    const {
        method = 'GET',
        body = null,
        timeoutMs = 15000,
        customHeaders = {}
    } = options;

    const config = githubConfig.getConfig();
    const token = await githubAuth.getInstallationAccessToken();

    const url = endpoint.startsWith('http')
        ? endpoint
        : `${config.apiBaseUrl}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const headers = {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'AccessLease-Governance-Platform',
        ...customHeaders
    };

    if (body && typeof body === 'object') {
        headers['Content-Type'] = 'application/json';
    }

    try {
        const response = await fetch(url, {
            method,
            headers,
            body: body ? JSON.stringify(body) : null,
            signal: controller.signal
        });

        clearTimeout(timer);

        const status = response.status;
        const remainingLimit = response.headers.get('x-ratelimit-remaining');
        const resetEpoch = response.headers.get('x-ratelimit-reset');
        const retryAfterHeader = response.headers.get('retry-after');

        // Parse response body
        let data = null;
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
            try {
                data = await response.json();
            } catch {
                data = null;
            }
        } else {
            data = await response.text();
        }

        // Handle Rate Limits (HTTP 429 or HTTP 403 secondary rate limit)
        if (status === 429 || (status === 403 && (data?.message?.includes('rate limit') || data?.message?.includes('secondary rate limit')))) {
            let retryAfterSeconds = 60;
            if (retryAfterHeader) {
                retryAfterSeconds = parseInt(retryAfterHeader, 10) || 60;
            } else if (resetEpoch) {
                const nowSec = Math.floor(Date.now() / 1000);
                retryAfterSeconds = Math.max(1, parseInt(resetEpoch, 10) - nowSec);
            }

            logger.warn('GitHub rate limit encountered', {
                status,
                endpoint,
                retryAfterSeconds,
                remainingLimit
            });

            throw new ConnectorError(
                `GitHub rate limit exceeded. Retry scheduled after ${retryAfterSeconds} seconds.`,
                429,
                'ERR_GITHUB_RATE_LIMIT',
                {
                    category: 'RATE_LIMIT',
                    retryAfterSeconds,
                    resetEpoch
                },
                true
            );
        }

        // Handle Success (2xx or 204 No Content)
        if (response.ok) {
            return {
                status,
                data,
                headers: response.headers
            };
        }

        // Handle HTTP 404 (Resource Not Found)
        if (status === 404) {
            return {
                status: 404,
                data: null,
                headers: response.headers
            };
        }

        // Handle HTTP 401 / 403 (Authentication or Permissions Error)
        if (status === 401 || status === 403) {
            logger.error('GitHub permission or authentication error', {
                status,
                endpoint,
                message: data?.message
            });

            throw new ConnectorError(
                `GitHub permission denied for endpoint ${endpoint}: ${data?.message || 'Forbidden'}`,
                status,
                'ERR_GITHUB_FORBIDDEN',
                {
                    category: 'PERMISSION_DENIED',
                    statusCode: status,
                    apiMessage: data?.message
                },
                false
            );
        }

        // Handle HTTP 422 (Unprocessable Entity / Validation Error)
        if (status === 422) {
            logger.error('GitHub API validation error', {
                status,
                endpoint,
                message: data?.message,
                errors: data?.errors
            });

            throw new ConnectorError(
                `GitHub validation failed: ${data?.message || 'Invalid parameters'}`,
                422,
                'ERR_GITHUB_VALIDATION',
                {
                    category: 'VALIDATION_FAILED',
                    statusCode: 422,
                    apiMessage: data?.message,
                    errors: data?.errors
                },
                false
            );
        }

        // Handle HTTP 5xx (Server Error — Retryable)
        if (status >= 500) {
            logger.error('GitHub server error', { status, endpoint, message: data?.message });
            throw new ConnectorError(
                `GitHub server error (${status}): ${data?.message || 'Internal error in GitHub'}`,
                status,
                'ERR_GITHUB_SERVER_ERROR',
                {
                    category: 'SERVER_ERROR',
                    statusCode: status
                },
                true
            );
        }

        // Any other non-OK status
        throw new ConnectorError(
            `GitHub API request failed with status ${status}: ${data?.message || JSON.stringify(data)}`,
            status,
            'ERR_GITHUB_API_ERROR',
            {
                category: 'API_ERROR',
                statusCode: status
            },
            false
        );

    } catch (err) {
        clearTimeout(timer);
        if (err instanceof ConnectorError) throw err;

        if (err.name === 'AbortError' || err.code === 'ABORT_ERR') {
            logger.warn('GitHub API request timed out', { endpoint, timeoutMs });
            throw new ConnectorError(
                `GitHub API request timed out after ${timeoutMs}ms.`,
                504,
                'ERR_GITHUB_TIMEOUT',
                { category: 'NETWORK_TIMEOUT', timeoutMs },
                true
            );
        }

        logger.error('GitHub API network failure', { endpoint, error: err.message });
        throw new ConnectorError(
            `Network error communicating with GitHub API: ${err.message}`,
            504,
            'ERR_GITHUB_NETWORK',
            { category: 'NETWORK_TIMEOUT' },
            true
        );
    }
}

module.exports = {
    request,
    setCustomTransport
};

