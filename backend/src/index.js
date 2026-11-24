/**
 * AccessLease — Azure Functions v4 Application Entry Point
 * Registers HTTP routes and background event handlers.
 */

const { app } = require('@azure/functions');
const { getApplicationHealth, getDatabaseHealth } = require('./functions/health');
const { getAuthMe, getAuthConfigHandler } = require('./functions/auth');
const {
    listUsers,
    createUser,
    updateUserStatus,
    listRoles
} = require('./functions/users');
const {
    listContractors,
    createContractor,
    getContractorSelf,
    getContractorById,
    listEngagements,
    getEngagementById,
    createEngagement,
    updateEngagement,
    transitionEngagementStatus,
    initiateGitHubLink,
    callbackGitHubLink,
    unlinkGitHub,
    getGitHubLinkStatus,
    manualVerifyIdentity
} = require('./functions/contractors');
const {
    listCatalogResources,
    listResourceEntitlements,
    createRequest,
    listRequests,
    getRequestById,
    cancelRequest,
    listPendingApprovals,
    submitApprovalDecision
} = require('./functions/requests');
const {
    getGitHubStatus,
    getGitHubConfiguration,
    startProvisioning,
    getProvisioningStateByRequest,
    listProvisioningJobs,
    listGrants,
    retryProvisioningJob
} = require('./functions/provisioning');
const {
    listRevocationJobs,
    getRevocationJobById,
    retryRevocationJob,
    resolveManualReview,
    triggerExpiryScan,
    getOffboardingStatus,
    terminateEngagement
} = require('./functions/revocation');
const {
    triggerOrphanScan,
    listOrphanFindings,
    getOrphanFindingById,
    revokeOrphanFinding,
    resolveOrphanFinding
} = require('./functions/orphanAccess');
const {
    createReviewCampaign,
    listReviews,
    getReviewById,
    getReviewItems,
    submitReviewDecision
} = require('./functions/reviews');
const { getAnalyticsSummary } = require('./functions/analytics');
const { staticFrontendHandler } = require('./functions/staticFrontend');
const env = require('./config/environment');

// 1. GET /api/health - Application availability and environment status
app.http('applicationHealth', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/health',
    handler: getApplicationHealth
});

// 2. GET /api/health/db - Live SQL Server connectivity verification
app.http('databaseHealth', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/health/db',
    handler: getDatabaseHealth
});

// 3. GET /api/auth/config - Safe public authentication bootstrap parameters
app.http('authConfig', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/auth/config',
    handler: getAuthConfigHandler
});

// 4. GET /api/auth/me - Protected user profile lookup (Entra ID Bearer token)
app.http('authMe', {
    methods: ['GET'],
    authLevel: 'anonymous', // Token validated via withAuth middleware
    route: 'api/auth/me',
    handler: getAuthMe
});

// 4b. GET /api/users - List internal application users (SYSTEM_ADMIN only)
app.http('listUsers', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/users',
    handler: listUsers
});

// 4c. POST /api/users - Register new internal application user (SYSTEM_ADMIN only)
app.http('createUser', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/users',
    handler: createUser
});

// 4d. PATCH /api/users/{id}/status - Activate or deactivate internal user (SYSTEM_ADMIN only)
app.http('updateUserStatus', {
    methods: ['PATCH'],
    authLevel: 'anonymous',
    route: 'api/users/{id}/status',
    handler: updateUserStatus
});

// 4e. GET /api/roles - List assignable governance roles (SYSTEM_ADMIN only)
app.http('listRoles', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/roles',
    handler: listRoles
});

// 5. GET /api/contractors - List contractors (internal users)
app.http('listContractors', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/contractors',
    handler: listContractors
});

// 5b. POST /api/contractors - Register new contractor (SYSTEM_ADMIN only)
app.http('createContractor', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/contractors',
    handler: createContractor
});

// 6. GET /api/contractors/me - Contractor self-service
app.http('getContractorSelf', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/contractors/me',
    handler: getContractorSelf
});

// 7. GET /api/contractors/{id} - Contractor profile & engagements
app.http('getContractorById', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/contractors/{id}',
    handler: getContractorById
});

// 8. GET /api/engagements - List contractor engagements
app.http('listEngagements', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/engagements',
    handler: listEngagements
});

// 9. GET /api/engagements/{id} - Single engagement details
app.http('getEngagementById', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/engagements/{id}',
    handler: getEngagementById
});

// 10. POST /api/engagements - Create engagement
app.http('createEngagement', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/engagements',
    handler: createEngagement
});

// 11. PUT /api/engagements/{id} - Update permitted engagement fields
app.http('updateEngagement', {
    methods: ['PUT'],
    authLevel: 'anonymous',
    route: 'api/engagements/{id}',
    handler: updateEngagement
});

// 12. POST /api/engagements/{id}/status - Transition engagement status
app.http('transitionEngagementStatus', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/engagements/{id}/status',
    handler: transitionEngagementStatus
});

// 12a. GET /api/contractors/me/github/link - Initiate GitHub OAuth linking flow
app.http('initiateGitHubLink', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/contractors/me/github/link',
    handler: initiateGitHubLink
});

// 12b. POST /api/contractors/me/github/callback - Complete GitHub OAuth linking flow
app.http('callbackGitHubLink', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/contractors/me/github/callback',
    handler: callbackGitHubLink
});

// 12c. DELETE /api/contractors/me/github/link - Unlink contractor GitHub identity
app.http('unlinkGitHub', {
    methods: ['DELETE'],
    authLevel: 'anonymous',
    route: 'api/contractors/me/github/link',
    handler: unlinkGitHub
});

// 12d. GET /api/contractors/me/github/status - Inspect linked identity status
app.http('getGitHubLinkStatus', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/contractors/me/github/status',
    handler: getGitHubLinkStatus
});

// 12e. POST /api/contractors/{id}/external-identities/manual-verify - Admin verification exception
app.http('manualVerifyIdentity', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/contractors/{id}/external-identities/manual-verify',
    handler: manualVerifyIdentity
});

// 13. GET /api/catalog/resources - List catalog resources
app.http('listCatalogResources', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/catalog/resources',
    handler: listCatalogResources
});

// 14. GET /api/catalog/resources/{id}/entitlements - List resource entitlements
app.http('listResourceEntitlements', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/catalog/resources/{id}/entitlements',
    handler: listResourceEntitlements
});

// 15. POST /api/requests - Submit contractor access request
app.http('createRequest', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/requests',
    handler: createRequest
});

// 16. GET /api/requests - List access requests (scoped)
app.http('listRequests', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/requests',
    handler: listRequests
});

// 17. GET /api/requests/{id} - Full request details & approval stages
app.http('getRequestById', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/requests/{id}',
    handler: getRequestById
});

// 18. POST /api/requests/{id}/cancel - Cancel pending request
app.http('cancelRequest', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/requests/{id}/cancel',
    handler: cancelRequest
});

// 19. GET /api/approvals/pending - Actionable pending approvals for user
app.http('listPendingApprovals', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/approvals/pending',
    handler: listPendingApprovals
});

// 20. POST /api/approvals/{stepId}/decision - Submit approval decision
app.http('submitApprovalDecision', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/approvals/{stepId}/decision',
    handler: submitApprovalDecision
});

// 21. GET /api/connectors/github/status - Safe GitHub connector status
app.http('getGitHubStatus', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/connectors/github/status',
    handler: getGitHubStatus
});

// 22. GET /api/connectors/github/configuration - Detailed connector configuration (no secrets)
app.http('getGitHubConfiguration', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/connectors/github/configuration',
    handler: getGitHubConfiguration
});

// 23. POST /api/provisioning/requests/{id}/start - Start/trigger provisioning operation
app.http('startProvisioning', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/provisioning/requests/{id}/start',
    handler: startProvisioning
});

// 24. GET /api/provisioning/requests/{id} - Get provisioning and grant state for request
app.http('getProvisioningStateByRequest', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/provisioning/requests/{id}',
    handler: getProvisioningStateByRequest
});

// 25. GET /api/provisioning/jobs - List provisioning queue jobs (admin/auditor)
app.http('listProvisioningJobs', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/provisioning/jobs',
    handler: listProvisioningJobs
});

// 26. GET /api/provisioning/grants - List access grants (scoped)
app.http('listGrants', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/provisioning/grants',
    handler: listGrants
});

// 27. POST /api/provisioning/jobs/{id}/retry - Manual retry failed provisioning job (admin/security)
app.http('retryProvisioningJob', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/provisioning/jobs/{id}/retry',
    handler: retryProvisioningJob
});

// 28. Timer Trigger: Periodic background provisioning worker & reconciliation (Azure Functions Cloud Runtime)
app.timer('provisioningWorkerTimer', {
    schedule: process.env.PROVISIONING_CRON_SCHEDULE || '*/15 * * * * *',
    handler: async (timer, context) => {
        try {
            const provisioningWorker = require('./services/provisioningWorker');
            await provisioningWorker.runWorkerCycle();
        } catch (err) {
            const logger = require('./utils/logger');
            logger.error('Unhandled error in provisioning worker timer trigger', { error: err.message });
        }
    }
});

// 29. GET /api/revocation/jobs - List revocation queue jobs with filtering
app.http('listRevocationJobs', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/revocation/jobs',
    handler: listRevocationJobs
});

// 30. GET /api/revocation/jobs/{id} - Get revocation job details
app.http('getRevocationJobById', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/revocation/jobs/{id}',
    handler: getRevocationJobById
});

// 31. POST /api/revocation/jobs/{id}/retry - Manual retry failed or queued revocation job (admin/security)
app.http('retryRevocationJob', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/revocation/jobs/{id}/retry',
    handler: retryRevocationJob
});

// 32. POST /api/revocation/jobs/{id}/resolve - Resolve manual review exception
app.http('resolveManualReview', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/revocation/jobs/{id}/resolve',
    handler: resolveManualReview
});

// 33. POST /api/revocation/scan - Trigger scheduled access expiry & termination scan
app.http('triggerExpiryScan', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/revocation/scan',
    handler: triggerExpiryScan
});

// 34. GET /api/contractors/{id}/offboarding - Retrieve contractor offboarding progress
app.http('getOffboardingStatus', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/contractors/{id}/offboarding',
    handler: getOffboardingStatus
});

// 35. POST /api/contractors/engagements/{id}/terminate - Immediate offboarding
app.http('terminateEngagement', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/contractors/engagements/{id}/terminate',
    handler: terminateEngagement
});

// 36. Timer Trigger: Periodic background access expiry and revocation engine
app.timer('revocationExpiryTimer', {
    schedule: process.env.REVOCATION_CRON_SCHEDULE || '0 */5 * * * *',
    handler: async (timer, context) => {
        try {
            const revocationService = require('./services/revocationService');
            await revocationService.processExpiredGrants({ autoProcess: true });
        } catch (err) {
            const logger = require('./utils/logger');
            logger.error('Unhandled error in revocation expiry timer trigger', { error: err.message });
        }
    }
});

// 37. POST /api/orphan-access/scan - Trigger on-demand orphan detection scan
app.http('triggerOrphanScan', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/orphan-access/scan',
    handler: triggerOrphanScan
});

// 38. GET /api/orphan-access/findings - List orphan access findings with filtering
app.http('listOrphanFindings', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/orphan-access/findings',
    handler: listOrphanFindings
});

// 39. GET /api/orphan-access/findings/{id} - Get specific orphan finding details
app.http('getOrphanFindingById', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/orphan-access/findings/{id}',
    handler: getOrphanFindingById
});

// 40. POST /api/orphan-access/findings/{id}/revoke - Authorize & initiate revocation for finding
app.http('revokeOrphanFinding', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/orphan-access/findings/{id}/revoke',
    handler: revokeOrphanFinding
});

// 41. POST /api/orphan-access/findings/{id}/resolve - Resolve or mark false positive
app.http('resolveOrphanFinding', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/orphan-access/findings/{id}/resolve',
    handler: resolveOrphanFinding
});

// 42. POST /api/reviews - Create access review campaign
app.http('createReviewCampaign', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/reviews',
    handler: createReviewCampaign
});

// 43. GET /api/reviews - List access review campaigns
app.http('listReviews', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/reviews',
    handler: listReviews
});

// 44. GET /api/reviews/{id} - Get review campaign details
app.http('getReviewById', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/reviews/{id}',
    handler: getReviewById
});

// 45. GET /api/reviews/{id}/items - Get review campaign items
app.http('getReviewItems', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/reviews/{id}/items',
    handler: getReviewItems
});

// 46. POST /api/reviews/items/{id}/decision - Submit review item decision
app.http('submitReviewDecision', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'api/reviews/items/{id}/decision',
    handler: submitReviewDecision
});

// 47. GET /api/analytics/summary - Real-time security analytics and metrics summary
app.http('getAnalyticsSummary', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'api/analytics/summary',
    handler: getAnalyticsSummary
});

// 51. Static Frontend Catch-All Handler (Vanilla JS SPA + Static Assets)
app.http('staticFrontend', {
    methods: ['GET', 'HEAD'],
    authLevel: 'anonymous',
    route: '{*restOfPath}',
    handler: staticFrontendHandler
});

// 48. Timer Trigger: Periodic background orphan access detection scan
app.timer('orphanDetectionTimer', {
    schedule: process.env.ORPHAN_DETECTION_CRON_SCHEDULE || '0 */15 * * * *',
    handler: async (timer, context) => {
        try {
            const orphanDetectionService = require('./services/orphanDetectionService');
            await orphanDetectionService.runOrphanDetectionScan(null);
        } catch (err) {
            const logger = require('./utils/logger');
            logger.error('Unhandled error in orphan detection timer trigger', { error: err.message });
        }
    }
});

module.exports = { app };
