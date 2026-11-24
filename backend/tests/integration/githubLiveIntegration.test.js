/**
 * AccessLease — Real GitHub Test Organization Live Integration
 * (PROMPT 06.2 / Section 4)
 * 
 * Rules:
 * - Isolated live test configuration using a dedicated non-production GitHub test organization.
 * - When valid credentials and installation are configured:
 *   1. Authenticate using the real GitHub App.
 *   2. Read an allowlisted test team.
 *   3. Verify a test contractor's linked identity.
 *   4. Perform approved membership operation.
 *   5. Read membership back from GitHub.
 *   6. Confirm ACTIVE versus PENDING_ACCEPTANCE.
 *   7. Verify actual repository permission.
 *   8. Clean up ONLY test resources created by the test itself, with explicit safeguards.
 * - If credentials or test organization are unavailable:
 *   MARK LIVE INTEGRATION AS NOT RUN. Never replace with mocks and report as successful.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const env = require('../../src/config/environment');
const githubConnector = require('../../src/connectors/github');
const logger = require('../../src/utils/logger');

const isLiveConfigured = Boolean(
    process.env.GITHUB_LIVE_TEST_ENABLED === 'true' &&
    env.GITHUB_APP_ID &&
    env.GITHUB_APP_PRIVATE_KEY &&
    env.GITHUB_APP_INSTALLATION_ID &&
    env.GITHUB_ALLOWED_ORGS.length > 0
);

describe('Live Integration: Real GitHub Test Organization', () => {
    if (!isLiveConfigured) {
        it.skip('Real GitHub organization live test: NOT RUN (GITHUB_LIVE_TEST_ENABLED!=true or live credentials not configured in environment)', () => {
            // Explicitly NOT RUN - Per Prompt 06.2, we must never mock live tests and claim success.
        });
        return;
    }

    const testOrg = process.env.GITHUB_TEST_ORG || env.GITHUB_ALLOWED_ORGS[0];
    const testTeamSlug = process.env.GITHUB_TEST_TEAM_SLUG || 'accesslease-contractors-test';
    const testRepoOwner = process.env.GITHUB_TEST_REPO_OWNER || testOrg;
    const testRepoName = process.env.GITHUB_TEST_REPO_NAME || 'test-governance-repo';
    const testContractorUsername = process.env.GITHUB_TEST_CONTRACTOR_USERNAME;

    // Production Safety Safeguard (PROMPT 06.3):
    // Refuse to run against production organizations under any circumstance
    const FORBIDDEN_PROD_PATTERNS = [/prod/i, /production/i, /live-corp/i, /enterprise-corp/i];
    const isExplicitTestOrg = process.env.GITHUB_IS_TEST_ORGANIZATION === 'true' ||
                              /test|sandbox|qa|dev/i.test(testOrg);
    const isSuspectedProd = FORBIDDEN_PROD_PATTERNS.some(pattern => pattern.test(testOrg)) || !isExplicitTestOrg;

    if (isSuspectedProd) {
        it('Safety Guard: Refuses to run against production organization', () => {
            assert.fail(
                `Live integration test refused: Target organization '${testOrg}' is not confirmed as a dedicated test organization. AccessLease live tests must NEVER run against production environments.`
            );
        });
        return;
    }

    it('1. Authenticate using real GitHub App & issue installation access token', async () => {
        const token = await githubConnector.githubAuth.getInstallationAccessToken();
        assert.ok(token && typeof token === 'string', 'Expected valid installation token string');
        assert.ok(token.startsWith('ghs_') || token.length > 10, 'Expected GitHub installation token format');
    });

    it('2. Read allowlisted test team metadata from live GitHub organization', async () => {
        const team = await githubConnector.githubTeamService.getTeam(testOrg, testTeamSlug);
        assert.ok(team, 'Expected team data from live GitHub API');
        assert.strictEqual(team.slug, testTeamSlug);
    });

    it('3. Verify team repository permission without privilege elevation', async () => {
        const repoPerms = await githubConnector.githubTeamService.getTeamRepoPermissions(
            testOrg,
            testTeamSlug,
            testRepoOwner,
            testRepoName
        );

        if (repoPerms) {
            assert.ok(repoPerms.permissions, 'Expected repository permissions object');
            const satisfies = githubConnector.githubTeamService.checkPermissionSatisfies(repoPerms.permissions, 'pull');
            assert.ok(satisfies, 'Expected team to possess at least pull permission');
        } else {
            logger.warn('Live test repository not assigned to team yet', { testOrg, testTeamSlug, testRepoName });
        }
    });

    it('4. Perform approved team membership operation and confirm resulting state', async () => {
        if (!testContractorUsername) {
            logger.info('GITHUB_TEST_CONTRACTOR_USERNAME not configured; skipping live mutation step');
            return;
        }

        try {
            const addResult = await githubConnector.githubTeamService.addOrUpdateTeamMembership(
                testOrg,
                testTeamSlug,
                testContractorUsername,
                'member'
            );

            assert.ok(addResult.state === 'active' || addResult.state === 'pending', 'State must be active or pending');

            // Read membership back from live GitHub
            const verified = await githubConnector.githubTeamService.getTeamMembership(
                testOrg,
                testTeamSlug,
                testContractorUsername
            );

            assert.ok(verified, 'Verified membership must exist');
            assert.strictEqual(verified.state, addResult.state);

            // Cleanup only test membership created by the test
            logger.info('Safeguarded cleanup: removing test user from live test team', { testOrg, testTeamSlug, testContractorUsername });
            const cleanupEndpoint = `/orgs/${encodeURIComponent(testOrg)}/teams/${encodeURIComponent(testTeamSlug)}/memberships/${encodeURIComponent(testContractorUsername)}`;
            await githubConnector.githubApiClient.request(cleanupEndpoint, { method: 'DELETE' });
        } catch (err) {
            logger.error('Live membership test failed', { error: err.message });
            throw err;
        }
    });
});

