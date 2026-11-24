/**
 * AccessLease — GitHub Team & Repository Service
 * Implements team discovery, repository permission validation,
 * contractor membership lookup, and team membership provisioning.
 * 
 * Rules:
 * - Only operates on allowlisted GitHub organizations.
 * - Enforces that the team already has the required repository permission level.
 * - Distinguishes between 'active' and 'pending' membership states.
 * - Enforces strict least-privilege permissions per official GitHub REST API specifications.
 * 
 * Official GitHub App Least-Privilege Permission Matrix (PROMPT 06.6):
 * -------------------------------------------------------------------------------------------------------------------------
 * Endpoint                                                    | Operation | Required GitHub App Permissions
 * -------------------------------------------------------------------------------------------------------------------------
 * GET /orgs/{org}/teams/{team_slug}                           | Read team | Organization: Members: Read, Metadata: Read
 * GET /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}     | Read perms| Organization: Members: Read, Repository: Metadata: Read
 *                                                             |           | (NOTE: Administration: Read is NOT required)
 * GET /orgs/{org}/teams/{team_slug}/memberships/{username}   | Read memb | Organization: Members: Read
 * PUT /orgs/{org}/teams/{team_slug}/memberships/{username}   | Add memb  | Organization: Members: Write
 * DELETE /orgs/{org}/teams/{team_slug}/memberships/{username}| Rem memb  | Organization: Members: Write
 * GET /orgs/{org}/audit-log?phrase=...                        | Audit log | Organization: Administration: Read (GHEC / GHES only;
 *                                                             |           | note: classic OAuth/PAT scope is read:audit_log)
 * -------------------------------------------------------------------------------------------------------------------------
 * Governance Policy: AccessLease requests Organization: Administration: Read strictly for independent provider-side ownership
 * verification via GitHub App installation tokens. Administration: Write or team repository permission elevation is NEVER requested or granted.
 */

const githubConfig = require('./githubConfig');
const githubApiClient = require('./githubApiClient');
const { ConnectorError } = require('../../utils/errors');
const logger = require('../../utils/logger');

// Hierarchy for repository permissions
const PERMISSION_LEVELS = {
    'pull': 1,
    'triage': 2,
    'push': 3,
    'maintain': 4,
    'admin': 5
};

/**
 * Validates that the requested GitHub organization is permitted by AccessLease governance policy.
 * @param {string} org Organization slug
 * @throws {ConnectorError}
 */
function validateOrganizationAllowlisted(org) {
    if (!org || typeof org !== 'string') {
        throw new ConnectorError(
            'Organization name is required for GitHub operations.',
            400,
            'ERR_GITHUB_INVALID_ORG',
            { category: 'VALIDATION_FAILED' }
        );
    }

    const allowedOrgs = githubConfig.getConfig().allowedOrgs;
    const normalized = org.trim().toLowerCase();

    if (!allowedOrgs.includes(normalized)) {
        logger.error('Organization is not in AccessLease allowlist', { org: normalized, allowedOrgs });
        throw new ConnectorError(
            `AccessLease Policy Violation: GitHub organization '${org}' is not in the approved organization allowlist [${allowedOrgs.join(', ')}].`,
            403,
            'ERR_GITHUB_ORG_NOT_ALLOWED',
            { category: 'ORGANIZATION_NOT_ALLOWED', org: normalized }
        );
    }
}

/**
 * Verifies that a team's actual repository permissions satisfy the required access level.
 * @param {object} permissions Object with boolean flags { pull, triage, push, maintain, admin }
 * @param {string} requiredLevel 'pull', 'triage', 'push', 'maintain', 'admin'
 * @returns {boolean}
 */
function checkPermissionSatisfies(permissions, requiredLevel) {
    if (!permissions || typeof permissions !== 'object') return false;

    const reqWeight = PERMISSION_LEVELS[String(requiredLevel).toLowerCase()] || 1;

    // Determine highest actual permission
    let highestWeight = 0;
    if (permissions.admin) highestWeight = 5;
    else if (permissions.maintain) highestWeight = 4;
    else if (permissions.push) highestWeight = 3;
    else if (permissions.triage) highestWeight = 2;
    else if (permissions.pull) highestWeight = 1;

    return highestWeight >= reqWeight;
}

/**
 * Retrieves GitHub team details to verify existence and organization membership.
 * @param {string} org Organization slug
 * @param {string} teamSlug Team slug
 * @returns {Promise<object>} Team data
 */
async function getTeam(org, teamSlug) {
    module.exports.validateOrganizationAllowlisted(org);

    const endpoint = `/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamSlug)}`;
    const result = await githubApiClient.request(endpoint);

    if (result.status === 404 || !result.data) {
        throw new ConnectorError(
            `Target team '${teamSlug}' was not found in GitHub organization '${org}'.`,
            404,
            'ERR_GITHUB_TEAM_NOT_FOUND',
            { category: 'TARGET_NOT_FOUND', org, teamSlug }
        );
    }

    return result.data;
}

/**
 * Inspects repository permissions granted to a GitHub team.
 * @param {string} org Organization slug
 * @param {string} teamSlug Team slug
 * @param {string} repoOwner Repository owner (usually the org)
 * @param {string} repoName Repository name
 * @returns {Promise<object|null>} Repository permissions or null if not assigned
 */
async function getTeamRepoPermissions(org, teamSlug, repoOwner, repoName) {
    module.exports.validateOrganizationAllowlisted(org);

    const endpoint = `/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamSlug)}/repos/${encodeURIComponent(repoOwner)}/${encodeURIComponent(repoName)}`;
    const result = await githubApiClient.request(endpoint, {
        customHeaders: {
            'Accept': 'application/vnd.github.v3.repository+json'
        }
    });

    if (result.status === 404 || !result.data) {
        return null;
    }

    return {
        id: result.data.id,
        name: result.data.name,
        full_name: result.data.full_name,
        permissions: result.data.permissions || {},
        role_name: result.data.role_name || null
    };
}

/**
 * Checks a contractor's membership status in a GitHub team.
 * @param {string} org Organization slug
 * @param {string} teamSlug Team slug
 * @param {string} username GitHub username
 * @returns {Promise<{ state: string, role: string }|null>} Membership or null if not a member
 */
async function getTeamMembership(org, teamSlug, username) {
    module.exports.validateOrganizationAllowlisted(org);

    const endpoint = `/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamSlug)}/memberships/${encodeURIComponent(username)}`;
    const result = await githubApiClient.request(endpoint);

    if (result.status === 404 || !result.data) {
        return null;
    }

    return {
        state: result.data.state, // 'active' | 'pending'
        role: result.data.role,   // 'member' | 'maintainer'
        url: result.data.url
    };
}

/**
 * Adds or updates a contractor's membership in a GitHub team.
 * @param {string} org Organization slug
 * @param {string} teamSlug Team slug
 * @param {string} username GitHub username
 * @param {string} [role='member'] Role in team ('member')
 * @returns {Promise<{ state: string, role: string }>} Resulting membership
 */
async function addOrUpdateTeamMembership(org, teamSlug, username, role = 'member') {
    module.exports.validateOrganizationAllowlisted(org);

    const endpoint = `/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamSlug)}/memberships/${encodeURIComponent(username)}`;
    const result = await githubApiClient.request(endpoint, {
        method: 'PUT',
        body: { role }
    });

    if (!result.data || typeof result.data !== 'object') {
        throw new ConnectorError(
            `Failed to add '${username}' to team '${teamSlug}' in org '${org}': Unexpected API response.`,
            502,
            'ERR_GITHUB_MEMBERSHIP_FAILED',
            { category: 'API_ERROR' }
        );
    }

    return {
        state: result.data.state, // 'active' | 'pending'
        role: result.data.role || role
    };
}

/**
 * Removes a contractor's membership from a GitHub team.
 * @param {string} org Organization slug
 * @param {string} teamSlug Team slug
 * @param {string} username GitHub username
 * @returns {Promise<{ success: boolean, removed: boolean, alreadyAbsent?: boolean, status: number }>}
 */
async function removeTeamMembership(org, teamSlug, username) {
    module.exports.validateOrganizationAllowlisted(org);

    const endpoint = `/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(teamSlug)}/memberships/${encodeURIComponent(username)}`;
    const result = await githubApiClient.request(endpoint, {
        method: 'DELETE'
    });

    if (result.status === 204) {
        return {
            success: true,
            removed: true,
            alreadyAbsent: false,
            status: 204
        };
    }

    if (result.status === 404) {
        return {
            success: true,
            removed: false,
            alreadyAbsent: true,
            status: 404
        };
    }

    return {
        success: true,
        removed: true,
        status: result.status
    };
}

module.exports = {
    validateOrganizationAllowlisted,
    checkPermissionSatisfies,
    getTeam,
    getTeamRepoPermissions,
    getTeamMembership,
    addOrUpdateTeamMembership,
    removeTeamMembership,
    PERMISSION_LEVELS
};

