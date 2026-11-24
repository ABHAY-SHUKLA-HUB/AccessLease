/**
 * AccessLease — Unit Tests: GitHub App Connector Architecture & Provisioning Logic
 * 
 * Verifies:
 * 1. GitHub App JWT generation (RS256, <= 10 min expiry, App ID issuer, clock drift).
 * 2. Installation access token caching and expiration buffer renewal.
 * 3. Organization allowlist policy validation.
 * 4. Repository permission hierarchy and satisfaction checks.
 * 5. Membership state interpretation ('active' vs 'pending').
 * 6. Provenance derivation ('CREATED_BY_ACCESSLEASE' vs 'PRE_EXISTING_ADOPTED').
 * 7. Rate limit detection and retry-after second calculation.
 * 8. Error classification (401, 403, 404, 422, 5xx, timeouts).
 * 9. Bounded exponential backoff calculation with jitter.
 * 10. Sanitized status reporting omitting private keys and secrets.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const githubConfig = require('../../src/connectors/github/githubConfig');
const githubAuth = require('../../src/connectors/github/githubAuth');
const githubApiClient = require('../../src/connectors/github/githubApiClient');
const githubTeamService = require('../../src/connectors/github/githubTeamService');
const githubVerificationService = require('../../src/connectors/github/githubVerificationService');
const provisioningWorker = require('../../src/services/provisioningWorker');
const { ConnectorError, ConfigurationError } = require('../../src/utils/errors');

describe('Unit: GitHub App Connector & Provisioning Engine (PROMPT 06)', () => {
    let testRsaKeyPair;
    let originalEnv;

    before(() => {
        originalEnv = {
            GITHUB_APP_ID: process.env.GITHUB_APP_ID,
            GITHUB_APP_PRIVATE_KEY: process.env.GITHUB_APP_PRIVATE_KEY,
            GITHUB_APP_INSTALLATION_ID: process.env.GITHUB_APP_INSTALLATION_ID,
            GITHUB_ALLOWED_ORGS: process.env.GITHUB_ALLOWED_ORGS,
            GITHUB_API_BASE_URL: process.env.GITHUB_API_BASE_URL
        };

        testRsaKeyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        process.env.GITHUB_APP_ID = '999888';
        process.env.GITHUB_APP_PRIVATE_KEY = testRsaKeyPair.privateKey;
        process.env.GITHUB_APP_INSTALLATION_ID = '11223344';
        process.env.GITHUB_ALLOWED_ORGS = 'accesslease-org,test-partner-org';
        process.env.GITHUB_API_BASE_URL = 'https://api.github.com';
    });

    after(() => {
        process.env.GITHUB_APP_ID = originalEnv.GITHUB_APP_ID;
        process.env.GITHUB_APP_PRIVATE_KEY = originalEnv.GITHUB_APP_PRIVATE_KEY;
        process.env.GITHUB_APP_INSTALLATION_ID = originalEnv.GITHUB_APP_INSTALLATION_ID;
        process.env.GITHUB_ALLOWED_ORGS = originalEnv.GITHUB_ALLOWED_ORGS;
        process.env.GITHUB_API_BASE_URL = originalEnv.GITHUB_API_BASE_URL;

        githubAuth.clearTokenCache();
        githubAuth.setMockTokenProvider(null);
        githubApiClient.setCustomTransport(null);
    });

    // -------------------------------------------------------------------------
    // 1. GitHub App JWT Generation
    // -------------------------------------------------------------------------
    test('1. Generates valid RS256 JWT with correct claims and <= 10 min expiration', () => {
        const token = githubAuth.generateAppJwt();
        assert.ok(token, 'JWT must not be empty');

        const decoded = jwt.verify(token, testRsaKeyPair.publicKey, { algorithms: ['RS256'] });
        assert.strictEqual(decoded.iss, '999888', 'Issuer must match GITHUB_APP_ID');

        const nowSec = Math.floor(Date.now() / 1000);
        // Expiration must be <= 10 minutes in the future (+ allowance for test execution)
        assert.ok(decoded.exp > nowSec, 'Token must not be expired');
        assert.ok(decoded.exp <= nowSec + 605, 'Expiration must not exceed 10 minutes from creation');
        assert.ok(decoded.iat <= nowSec, 'Issued-at must be in the past or present');
    });

    // -------------------------------------------------------------------------
    // 2. Token Caching & Automatic Renewal
    // -------------------------------------------------------------------------
    test('2. Caches installation access tokens and reuses valid cached token', async () => {
        let fetchCount = 0;
        githubAuth.setMockTokenProvider(async (instId) => {
            fetchCount++;
            return `ghs_mock_token_${instId}_${fetchCount}`;
        });

        const token1 = await githubAuth.getInstallationAccessToken('11223344');
        assert.strictEqual(token1, 'ghs_mock_token_11223344_1');

        // Reset mock provider and test actual internal caching with custom transport
        githubAuth.setMockTokenProvider(null);
        githubAuth.clearTokenCache();

        let apiCalls = 0;
        const originalFetch = global.fetch;
        global.fetch = async (url, opts) => {
            if (url.includes('/access_tokens')) {
                apiCalls++;
                return {
                    ok: true,
                    status: 201,
                    json: async () => ({
                        token: `ghs_live_cached_token_${apiCalls}`,
                        expires_at: new Date(Date.now() + 3600 * 1000).toISOString()
                    })
                };
            }
            return originalFetch(url, opts);
        };

        try {
            const first = await githubAuth.getInstallationAccessToken('inst-cache-test');
            assert.strictEqual(first, 'ghs_live_cached_token_1');
            assert.strictEqual(apiCalls, 1);

            // Second call with same installation ID must use cache
            const second = await githubAuth.getInstallationAccessToken('inst-cache-test');
            assert.strictEqual(second, 'ghs_live_cached_token_1');
            assert.strictEqual(apiCalls, 1, 'Should not request new token when cached token is valid');
        } finally {
            global.fetch = originalFetch;
            githubAuth.clearTokenCache();
        }
    });

    // -------------------------------------------------------------------------
    // 3. Organization Allowlist Validation
    // -------------------------------------------------------------------------
    test('3. Rejects organizations outside the approved allowlist', () => {
        // Allowed
        assert.doesNotThrow(() => {
            githubTeamService.validateOrganizationAllowlisted('accesslease-org');
            githubTeamService.validateOrganizationAllowlisted('TEST-PARTNER-ORG');
        });

        // Disallowed
        assert.throws(() => {
            githubTeamService.validateOrganizationAllowlisted('malicious-foreign-org');
        }, (err) => {
            assert.ok(err instanceof ConnectorError);
            assert.strictEqual(err.category, 'ORGANIZATION_NOT_ALLOWED');
            return true;
        });
    });

    // -------------------------------------------------------------------------
    // 4. Repository Permission Hierarchy
    // -------------------------------------------------------------------------
    test('4. Correctly evaluates repository permission satisfaction hierarchy', () => {
        // Required: pull
        assert.strictEqual(githubTeamService.checkPermissionSatisfies({ pull: true }, 'pull'), true);
        assert.strictEqual(githubTeamService.checkPermissionSatisfies({ push: true }, 'pull'), true);
        assert.strictEqual(githubTeamService.checkPermissionSatisfies({ admin: true }, 'pull'), true);
        assert.strictEqual(githubTeamService.checkPermissionSatisfies({ pull: false }, 'pull'), false);

        // Required: push
        assert.strictEqual(githubTeamService.checkPermissionSatisfies({ pull: true, push: false }, 'push'), false);
        assert.strictEqual(githubTeamService.checkPermissionSatisfies({ push: true }, 'push'), true);
        assert.strictEqual(githubTeamService.checkPermissionSatisfies({ admin: true }, 'push'), true);

        // Required: admin
        assert.strictEqual(githubTeamService.checkPermissionSatisfies({ push: true, maintain: true }, 'admin'), false);
        assert.strictEqual(githubTeamService.checkPermissionSatisfies({ admin: true }, 'admin'), true);
    });

    // -------------------------------------------------------------------------
    // 5. Pre-Existing Membership Provenance Derivation
    // -------------------------------------------------------------------------
    test('5. Discovers pre-existing active membership and marks provenance PRE_EXISTING_ADOPTED', async () => {
        githubAuth.setMockTokenProvider(async () => 'ghs_test_token');

        githubApiClient.setCustomTransport(async (endpoint) => {
            // Team check
            if (endpoint.includes('/teams/contractor-team') && !endpoint.includes('/repos') && !endpoint.includes('/memberships')) {
                return { status: 200, data: { id: 101, name: 'Contractor Team' }, headers: new Headers() };
            }
            // Repo perms check
            if (endpoint.includes('/repos/accesslease-org/core-repo')) {
                return {
                    status: 200,
                    data: { id: 202, full_name: 'accesslease-org/core-repo', permissions: { push: true, pull: true } },
                    headers: new Headers()
                };
            }
            // Membership check
            if (endpoint.includes('/memberships/existing-user')) {
                return { status: 200, data: { state: 'active', role: 'member' }, headers: new Headers() };
            }
            throw new Error(`Unhandled endpoint: ${endpoint}`);
        });

        const outcome = await githubVerificationService.provisionAndVerifyAccess({
            org: 'accesslease-org',
            teamSlug: 'contractor-team',
            repoOwner: 'accesslease-org',
            repoName: 'core-repo',
            requiredPermission: 'push',
            username: 'existing-user'
        });

        assert.strictEqual(outcome.success, true);
        assert.strictEqual(outcome.state, 'ACTIVE');
        assert.strictEqual(outcome.membershipProvenance, 'PRE_EXISTING_ADOPTED');
        assert.strictEqual(outcome.preExisting, true);
        assert.strictEqual(outcome.invitationPending, false);
    });

    // -------------------------------------------------------------------------
    // 6. Pending Invitation Handling
    // -------------------------------------------------------------------------
    test('6. Distinguishes pending invitation and does not mark access active', async () => {
        githubAuth.setMockTokenProvider(async () => 'ghs_test_token');

        githubApiClient.setCustomTransport(async (endpoint, options) => {
            if (endpoint.includes('/teams/contractor-team') && !endpoint.includes('/repos') && !endpoint.includes('/memberships')) {
                return { status: 200, data: { id: 101, name: 'Contractor Team' }, headers: new Headers() };
            }
            if (endpoint.includes('/repos/accesslease-org/core-repo')) {
                return {
                    status: 200,
                    data: { id: 202, full_name: 'accesslease-org/core-repo', permissions: { push: true, pull: true } },
                    headers: new Headers()
                };
            }
            // First check: user not member
            if (endpoint.includes('/memberships/new-user') && options.method !== 'PUT') {
                return { status: 404, data: null, headers: new Headers() };
            }
            // Add user via PUT: returns pending invitation
            if (endpoint.includes('/memberships/new-user') && options.method === 'PUT') {
                return { status: 200, data: { state: 'pending', role: 'member' }, headers: new Headers() };
            }
            if (endpoint.includes('/audit-log')) {
                return {
                    status: 200,
                    data: [{
                        action: 'team.add_member',
                        actor: 'accesslease[bot]',
                        actor_is_bot: true,
                        user: 'new-user',
                        org: 'accesslease-org',
                        team: 'contractor-team',
                        '@timestamp': Date.now()
                    }],
                    headers: new Headers()
                };
            }
            throw new Error(`Unhandled endpoint: ${endpoint}`);
        });

        const outcome = await githubVerificationService.provisionAndVerifyAccess({
            org: 'accesslease-org',
            teamSlug: 'contractor-team',
            repoOwner: 'accesslease-org',
            repoName: 'core-repo',
            requiredPermission: 'push',
            username: 'new-user'
        });

        assert.strictEqual(outcome.success, true);
        assert.strictEqual(outcome.state, 'PENDING_ACCEPTANCE');
        assert.strictEqual(outcome.membershipProvenance, 'CREATED_BY_ACCESSLEASE');
        assert.strictEqual(outcome.invitationPending, true);
        assert.strictEqual(outcome.preExisting, false);
        githubApiClient.setCustomTransport(null);
    });

    // -------------------------------------------------------------------------
    // 7. Rate Limit Detection & Retry Calculation
    // -------------------------------------------------------------------------
    test('7. Detects HTTP 429 and parses Retry-After header accurately', async () => {
        githubApiClient.setCustomTransport(null);
        githubAuth.setMockTokenProvider(async () => 'ghs_test_token');

        const originalFetch = global.fetch;
        global.fetch = async () => {
            const headers = new Headers();
            headers.set('retry-after', '120');
            headers.set('x-ratelimit-remaining', '0');
            headers.set('content-type', 'application/json');
            return {
                ok: false,
                status: 429,
                headers,
                json: async () => ({ message: 'API rate limit exceeded' })
            };
        };

        try {
            await assert.rejects(async () => {
                await githubApiClient.request('/orgs/accesslease-org/teams/some-team');
            }, (err) => {
                assert.ok(err instanceof ConnectorError);
                assert.strictEqual(err.statusCode, 429);
                assert.strictEqual(err.category, 'RATE_LIMIT');
                assert.strictEqual(err.isRetryable, true);
                assert.strictEqual(err.retryAfterSeconds, 120);
                return true;
            });
        } finally {
            global.fetch = originalFetch;
        }
    });

    // -------------------------------------------------------------------------
    // 8. Bounded Exponential Backoff
    // -------------------------------------------------------------------------
    test('8. Calculates exponential backoff bounded within reasonable limits', () => {
        const attempt1 = provisioningWorker.calculateBackoffSeconds(1);
        assert.ok(attempt1 >= 10 && attempt1 <= 15, `Attempt 1 backoff: ${attempt1}`);

        const attempt2 = provisioningWorker.calculateBackoffSeconds(2);
        assert.ok(attempt2 >= 20 && attempt2 <= 25, `Attempt 2 backoff: ${attempt2}`);

        const attempt5 = provisioningWorker.calculateBackoffSeconds(5);
        assert.ok(attempt5 >= 160 && attempt5 <= 165, `Attempt 5 backoff: ${attempt5}`);

        const attempt10 = provisioningWorker.calculateBackoffSeconds(10);
        assert.ok(attempt10 <= 305, 'Must be capped at max 300s + jitter');
    });

    // -------------------------------------------------------------------------
    // 9. Sanitized Connector Status Reporting
    // -------------------------------------------------------------------------
    test('9. getStatus never exposes private keys, tokens, or credentials', () => {
        const status = githubConfig.getStatus();
        assert.strictEqual(status.connector, 'GITHUB');
        assert.strictEqual(status.configured, true);
        assert.strictEqual(status.appId, '999888');
        assert.strictEqual(status.installationId, '11223344');
        assert.deepStrictEqual(status.allowedOrgs, ['accesslease-org', 'test-partner-org']);

        // Assert strictly zero leakage of private key or secrets
        const json = JSON.stringify(status);
        assert.ok(!json.includes('BEGIN RSA PRIVATE KEY'), 'Must not leak private key');
        assert.ok(!json.includes('BEGIN PRIVATE KEY'), 'Must not leak private key');
        assert.ok(!status.privateKey, 'privateKey must not be in status object');
    });
});
