/**
 * AccessLease — GitHub Connector Configuration
 * Safely resolves and validates GitHub App credentials and target allowlists.
 * Never leaks private keys or credentials to clients or logs.
 */

const env = require('../../config/environment');
const { ConfigurationError } = require('../../utils/errors');

/**
 * Returns current GitHub App configuration.
 * @returns {object}
 */
function getConfig() {
    return {
        appId: env.GITHUB_APP_ID,
        appSlug: env.GITHUB_APP_SLUG,
        privateKey: env.GITHUB_APP_PRIVATE_KEY,
        installationId: env.GITHUB_APP_INSTALLATION_ID,
        allowedOrgs: env.GITHUB_ALLOWED_ORGS,
        apiBaseUrl: env.GITHUB_API_BASE_URL,
        appClientId: env.GITHUB_APP_CLIENT_ID
    };
}

/**
 * Checks whether the connector is fully configured.
 * @returns {boolean}
 */
function isConfigured() {
    const { isValid } = env.validateGitHubConfig();
    return isValid;
}

/**
 * Asserts that the connector is properly configured; throws ConfigurationError otherwise.
 * @throws {ConfigurationError}
 */
function validateConfig() {
    const { isValid, missingFields } = env.validateGitHubConfig();
    if (!isValid) {
        throw new ConfigurationError(
            `GitHub App connector is not configured: Missing [${missingFields.join(', ')}]. Provisioning cannot proceed.`,
            missingFields,
            'ERR_GITHUB_CONNECTOR_NOT_CONFIGURED'
        );
    }
}

/**
 * Returns sanitized status for public or admin inspection.
 * Stricly omits private keys, tokens, or credentials.
 * @returns {object}
 */
function getStatus() {
    const { isValid, missingFields } = env.validateGitHubConfig();
    return {
        connector: 'GITHUB',
        configured: isValid,
        appId: env.GITHUB_APP_ID || null,
        appSlug: env.GITHUB_APP_SLUG || 'accesslease',
        installationId: env.GITHUB_APP_INSTALLATION_ID || null,
        allowedOrgs: env.GITHUB_ALLOWED_ORGS,
        apiBaseUrl: env.GITHUB_API_BASE_URL,
        requiredPermissions: {
            organization: {
                members: 'read/write',
                administration: 'read (required by official GitHub REST API for GET /orgs/{org}/audit-log with GitHub App installations; note: classic read:audit_log scope applies only to PATs/OAuth apps)'
            },
            repository: { metadata: 'read' },
            note: 'Administration: Read is read-only organization metadata required exclusively for independent provider audit log verification on supported Enterprise plans. Administration: Write or team repository permission elevation is NEVER requested or granted.'
        },
        missingFields: isValid ? [] : missingFields
    };
}

module.exports = {
    getConfig,
    isConfigured,
    validateConfig,
    getStatus
};

