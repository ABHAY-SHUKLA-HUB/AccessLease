/**
 * AccessLease — GitHub Connector Aggregator
 */

const githubConfig = require('./githubConfig');
const githubAuth = require('./githubAuth');
const githubApiClient = require('./githubApiClient');
const githubTeamService = require('./githubTeamService');
const githubVerificationService = require('./githubVerificationService');
const githubOAuthService = require('./githubOAuthService');
const githubAuditService = require('./githubAuditService');

module.exports = {
    githubConfig,
    githubAuth,
    githubApiClient,
    githubTeamService,
    githubVerificationService,
    githubOAuthService,
    githubAuditService
};

