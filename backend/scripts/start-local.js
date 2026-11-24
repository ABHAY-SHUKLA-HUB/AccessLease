/**
 * AccessLease — Unified Local Development Server
 * Serves both the Vanilla JS Frontend and Azure Functions v4 API endpoints locally
 * without requiring external tooling or global Azure Functions Core Tools.
 * 
 * Exposes:
 * - Frontend UI: http://localhost:7071/
 * - GET http://localhost:7071/api/health
 * - GET http://localhost:7071/api/health/db
 * - GET http://localhost:7071/api/auth/config
 * - GET http://localhost:7071/api/auth/me (Protected with Entra ID Bearer token)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { getApplicationHealth, getDatabaseHealth } = require('../src/functions/health');
const { getAuthMe, getAuthConfigHandler } = require('../src/functions/auth');
const {
    listUsers,
    createUser,
    updateUserStatus,
    listRoles
} = require('../src/functions/users');
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
} = require('../src/functions/contractors');
const {
    listCatalogResources,
    listResourceEntitlements,
    createRequest,
    listRequests,
    getRequestById,
    cancelRequest,
    listPendingApprovals,
    submitApprovalDecision
} = require('../src/functions/requests');
const {
    getGitHubStatus,
    getGitHubConfiguration,
    startProvisioning,
    getProvisioningStateByRequest,
    listProvisioningJobs,
    listGrants,
    retryProvisioningJob
} = require('../src/functions/provisioning');
const {
    listRevocationJobs,
    getRevocationJobById,
    retryRevocationJob,
    resolveManualReview,
    triggerExpiryScan,
    getOffboardingStatus,
    terminateEngagement
} = require('../src/functions/revocation');
const {
    triggerOrphanScan,
    listOrphanFindings,
    getOrphanFindingById,
    revokeOrphanFinding,
    resolveOrphanFinding
} = require('../src/functions/orphanAccess');
const {
    createReviewCampaign,
    listReviews,
    getReviewById,
    getReviewItems,
    submitReviewDecision
} = require('../src/functions/reviews');
const { getAnalyticsSummary } = require('../src/functions/analytics');
const provisioningWorker = require('../src/services/provisioningWorker');
const env = require('../src/config/environment');
const logger = require('../src/utils/logger');

const PORT = env.PORT || 7071;
const FRONTEND_DIR = path.resolve(__dirname, '../../frontend');

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
    '.ttf': 'font/ttf'
};

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const method = req.method.toUpperCase();
    const pathname = url.pathname.replace(/\/+$/, '') || '/';

    // Standard CORS headers for local frontend integration
    const origin = req.headers.origin || '*';
    const corsHeaders = {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Requested-With, Accept',
        'Access-Control-Allow-Credentials': 'true'
    };

    if (method === 'OPTIONS') {
        res.writeHead(204, corsHeaders);
        res.end();
        return;
    }

    // -------------------------------------------------------------------------
    // 1. API Routes (/api/*)
    // -------------------------------------------------------------------------
    if (pathname.startsWith('/api')) {
        // Convert IncomingMessage headers to a Map compatible with Azure Functions v4 HttpRequest
        const headersMap = new Map();
        for (const [key, value] of Object.entries(req.headers)) {
            headersMap.set(key.toLowerCase(), value);
        }

        // Read body for POST/PUT/PATCH requests
        let parsedBody = {};
        if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
            let rawBody = '';
            for await (const chunk of req) {
                rawBody += chunk;
            }
            if (rawBody.trim()) {
                try {
                    parsedBody = JSON.parse(rawBody);
                } catch {
                    parsedBody = {};
                }
            }
        }

        const mockRequest = {
            method,
            url: req.url,
            path: pathname,
            headers: headersMap,
            body: parsedBody,
            json: async () => parsedBody,
            query: Object.fromEntries(url.searchParams.entries())
        };

        // Development-only test user resolution via LocalDB for local browser end-to-end verification
        if (process.env.NODE_ENV === 'development' && (req.headers['x-test-user-id'] || req.headers['x-test-email'])) {
            try {
                const userRepository = require('../src/repositories/userRepository');
                const { getEffectivePermissions } = require('../src/security/permissionPolicy');
                let userRecord = null;
                if (req.headers['x-test-user-id']) {
                    userRecord = await userRepository.findUserById(req.headers['x-test-user-id']);
                } else if (req.headers['x-test-email']) {
                    userRecord = await userRepository.findUserByEmail(req.headers['x-test-email']);
                }
                if (userRecord && userRecord.is_active) {
                    const roles = await userRepository.getUserRoles(userRecord.user_id);
                    const permissions = Array.from(getEffectivePermissions(roles));
                    mockRequest.user = {
                        user_id: userRecord.user_id,
                        entra_object_id: userRecord.entra_object_id,
                        email: userRecord.email,
                        display_name: userRecord.display_name,
                        user_type: userRecord.user_type,
                        department: userRecord.department,
                        is_active: userRecord.is_active,
                        roles,
                        permissions
                    };
                }
            } catch (err) {
                console.warn('[start-local] Failed to resolve test user header:', err.message);
            }
        }

        const mockContext = {
            invocationId: 'local-inv-' + Date.now(),
            log: console.log
        };

        let result = null;

        try {
            const contractorIdMatch = pathname.match(/^\/api\/contractors\/([a-zA-Z0-9-]+)$/);
            const engagementIdMatch = pathname.match(/^\/api\/engagements\/([a-zA-Z0-9-]+)$/);
            const engagementStatusMatch = pathname.match(/^\/api\/engagements\/([a-zA-Z0-9-]+)\/status$/);
            const resourceEntitlementsMatch = pathname.match(/^\/api\/catalog\/resources\/([a-zA-Z0-9-]+)\/entitlements$/);
            const requestIdMatch = pathname.match(/^\/api\/requests\/([a-zA-Z0-9-]+)$/);
            const requestCancelMatch = pathname.match(/^\/api\/requests\/([a-zA-Z0-9-]+)\/cancel$/);
            const approvalDecisionMatch = pathname.match(/^\/api\/approvals\/([a-zA-Z0-9-]+)\/decision$/);
            const provStartMatch = pathname.match(/^\/api\/provisioning\/requests\/([a-zA-Z0-9-]+)\/start$/);
            const provRequestMatch = pathname.match(/^\/api\/provisioning\/requests\/([a-zA-Z0-9-]+)$/);
            const provRetryMatch = pathname.match(/^\/api\/provisioning\/jobs\/([a-zA-Z0-9-]+)\/retry$/);
            const contractorManualVerifyMatch = pathname.match(/^\/api\/contractors\/([a-zA-Z0-9-]+)\/external-identities\/manual-verify$/);
            const contractorStatusMatch = pathname.match(/^\/api\/contractors\/([a-zA-Z0-9-]+)\/github\/status$/);
            const revocationJobIdMatch = pathname.match(/^\/api\/revocation\/jobs\/([a-zA-Z0-9-]+)$/);
            const revocationRetryMatch = pathname.match(/^\/api\/revocation\/jobs\/([a-zA-Z0-9-]+)\/retry$/);
            const revocationResolveMatch = pathname.match(/^\/api\/revocation\/jobs\/([a-zA-Z0-9-]+)\/resolve$/);
            const offboardingStatusMatch = pathname.match(/^\/api\/contractors\/([a-zA-Z0-9-]+)\/offboarding$/);
            const engagementTerminateMatch = pathname.match(/^\/api\/contractors\/engagements\/([a-zA-Z0-9-]+)\/terminate$/);

            const orphanFindingIdMatch = pathname.match(/^\/api\/orphan-access\/findings\/([a-zA-Z0-9-]+)$/);
            const orphanRevokeMatch = pathname.match(/^\/api\/orphan-access\/findings\/([a-zA-Z0-9-]+)\/revoke$/);
            const orphanResolveMatch = pathname.match(/^\/api\/orphan-access\/findings\/([a-zA-Z0-9-]+)\/resolve$/);

            const reviewItemsMatch = pathname.match(/^\/api\/reviews\/([a-zA-Z0-9-]+)\/items$/);
            const reviewIdMatch = pathname.match(/^\/api\/reviews\/([a-zA-Z0-9-]+)$/);
            const reviewDecisionMatch = pathname.match(/^\/api\/reviews\/items\/([a-zA-Z0-9-]+)\/decision$/);
            const userStatusMatch = pathname.match(/^\/api\/users\/([a-zA-Z0-9-]+)\/status$/);

            if (method === 'GET' && pathname === '/api/health') {
                result = await getApplicationHealth(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/health/db') {
                result = await getDatabaseHealth(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/auth/config') {
                result = await getAuthConfigHandler(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/auth/me') {
                result = await getAuthMe(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/users') {
                result = await listUsers(mockRequest, mockContext);
            } else if (method === 'POST' && pathname === '/api/users') {
                result = await createUser(mockRequest, mockContext);
            } else if (method === 'PATCH' && userStatusMatch) {
                mockRequest.params = { id: userStatusMatch[1] };
                result = await updateUserStatus(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/roles') {
                result = await listRoles(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/contractors') {
                result = await listContractors(mockRequest, mockContext);
            } else if (method === 'POST' && pathname === '/api/contractors') {
                result = await createContractor(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/contractors/me/github/link') {
                result = await initiateGitHubLink(mockRequest, mockContext);
            } else if (method === 'POST' && pathname === '/api/contractors/me/github/callback') {
                result = await callbackGitHubLink(mockRequest, mockContext);
            } else if (method === 'DELETE' && pathname === '/api/contractors/me/github/link') {
                result = await unlinkGitHub(mockRequest, mockContext);
            } else if (method === 'GET' && (pathname === '/api/contractors/me/github/status' || contractorStatusMatch)) {
                if (contractorStatusMatch) mockRequest.params = { id: contractorStatusMatch[1] };
                result = await getGitHubLinkStatus(mockRequest, mockContext);
            } else if (method === 'POST' && contractorManualVerifyMatch) {
                mockRequest.params = { id: contractorManualVerifyMatch[1] };
                result = await manualVerifyIdentity(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/contractors/me') {
                result = await getContractorSelf(mockRequest, mockContext);
            } else if (method === 'GET' && contractorIdMatch) {
                mockRequest.params = { id: contractorIdMatch[1] };
                result = await getContractorById(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/engagements') {
                result = await listEngagements(mockRequest, mockContext);
            } else if (method === 'POST' && pathname === '/api/engagements') {
                result = await createEngagement(mockRequest, mockContext);
            } else if (method === 'POST' && engagementStatusMatch) {
                mockRequest.params = { id: engagementStatusMatch[1] };
                result = await transitionEngagementStatus(mockRequest, mockContext);
            } else if (method === 'GET' && engagementIdMatch) {
                mockRequest.params = { id: engagementIdMatch[1] };
                result = await getEngagementById(mockRequest, mockContext);
            } else if (method === 'PUT' && engagementIdMatch) {
                mockRequest.params = { id: engagementIdMatch[1] };
                result = await updateEngagement(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/catalog/resources') {
                result = await listCatalogResources(mockRequest, mockContext);
            } else if (method === 'GET' && resourceEntitlementsMatch) {
                mockRequest.params = { id: resourceEntitlementsMatch[1] };
                result = await listResourceEntitlements(mockRequest, mockContext);
            } else if (method === 'POST' && pathname === '/api/requests') {
                result = await createRequest(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/requests') {
                result = await listRequests(mockRequest, mockContext);
            } else if (method === 'POST' && requestCancelMatch) {
                mockRequest.params = { id: requestCancelMatch[1] };
                result = await cancelRequest(mockRequest, mockContext);
            } else if (method === 'GET' && requestIdMatch) {
                mockRequest.params = { id: requestIdMatch[1] };
                result = await getRequestById(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/approvals/pending') {
                result = await listPendingApprovals(mockRequest, mockContext);
            } else if (method === 'POST' && approvalDecisionMatch) {
                mockRequest.params = { stepId: approvalDecisionMatch[1] };
                result = await submitApprovalDecision(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/connectors/github/status') {
                result = await getGitHubStatus(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/connectors/github/configuration') {
                result = await getGitHubConfiguration(mockRequest, mockContext);
            } else if (method === 'POST' && provStartMatch) {
                mockRequest.params = { id: provStartMatch[1] };
                result = await startProvisioning(mockRequest, mockContext);
            } else if (method === 'GET' && provRequestMatch) {
                mockRequest.params = { id: provRequestMatch[1] };
                result = await getProvisioningStateByRequest(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/provisioning/jobs') {
                result = await listProvisioningJobs(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/provisioning/grants') {
                result = await listGrants(mockRequest, mockContext);
            } else if (method === 'POST' && provRetryMatch) {
                mockRequest.params = { id: provRetryMatch[1] };
                result = await retryProvisioningJob(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/revocation/jobs') {
                result = await listRevocationJobs(mockRequest, mockContext);
            } else if (method === 'GET' && revocationJobIdMatch) {
                mockRequest.params = { id: revocationJobIdMatch[1] };
                result = await getRevocationJobById(mockRequest, mockContext);
            } else if (method === 'POST' && revocationRetryMatch) {
                mockRequest.params = { id: revocationRetryMatch[1] };
                result = await retryRevocationJob(mockRequest, mockContext);
            } else if (method === 'POST' && revocationResolveMatch) {
                mockRequest.params = { id: revocationResolveMatch[1] };
                result = await resolveManualReview(mockRequest, mockContext);
            } else if (method === 'POST' && pathname === '/api/revocation/scan') {
                result = await triggerExpiryScan(mockRequest, mockContext);
            } else if (method === 'GET' && offboardingStatusMatch) {
                mockRequest.params = { id: offboardingStatusMatch[1] };
                result = await getOffboardingStatus(mockRequest, mockContext);
            } else if (method === 'POST' && engagementTerminateMatch) {
                mockRequest.params = { id: engagementTerminateMatch[1] };
                result = await terminateEngagement(mockRequest, mockContext);
            } else if (method === 'POST' && pathname === '/api/orphan-access/scan') {
                result = await triggerOrphanScan(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/orphan-access/findings') {
                result = await listOrphanFindings(mockRequest, mockContext);
            } else if (method === 'GET' && orphanFindingIdMatch) {
                mockRequest.params = { id: orphanFindingIdMatch[1] };
                result = await getOrphanFindingById(mockRequest, mockContext);
            } else if (method === 'POST' && orphanRevokeMatch) {
                mockRequest.params = { id: orphanRevokeMatch[1] };
                result = await revokeOrphanFinding(mockRequest, mockContext);
            } else if (method === 'POST' && orphanResolveMatch) {
                mockRequest.params = { id: orphanResolveMatch[1] };
                result = await resolveOrphanFinding(mockRequest, mockContext);
            } else if (method === 'POST' && pathname === '/api/reviews') {
                result = await createReviewCampaign(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/reviews') {
                result = await listReviews(mockRequest, mockContext);
            } else if (method === 'GET' && reviewItemsMatch) {
                mockRequest.params = { id: reviewItemsMatch[1] };
                result = await getReviewItems(mockRequest, mockContext);
            } else if (method === 'GET' && reviewIdMatch) {
                mockRequest.params = { id: reviewIdMatch[1] };
                result = await getReviewById(mockRequest, mockContext);
            } else if (method === 'POST' && reviewDecisionMatch) {
                mockRequest.params = { id: reviewDecisionMatch[1] };
                result = await submitReviewDecision(mockRequest, mockContext);
            } else if (method === 'GET' && pathname === '/api/analytics/summary') {
                result = await getAnalyticsSummary(mockRequest, mockContext);
            } else {
                result = {
                    status: 404,
                    headers: { 'Content-Type': 'application/json; charset=utf-8' },
                    jsonBody: {
                        success: false,
                        error: {
                            code: 'ERR_NOT_FOUND',
                            message: `Route ${method} ${pathname} not found.`
                        }
                    }
                };
            }
        } catch (serverErr) {
            logger.error('Unhandled server error in local runner', { error: serverErr.message });
            result = {
                status: 500,
                headers: { 'Content-Type': 'application/json; charset=utf-8' },
                jsonBody: {
                    success: false,
                    error: {
                        code: 'ERR_INTERNAL',
                        message: 'Internal server error.'
                    }
                }
            };
        }

        const mergedHeaders = { ...corsHeaders, ...result.headers };
        res.writeHead(result.status, mergedHeaders);
        res.end(JSON.stringify(result.jsonBody));
        return;
    }

    // -------------------------------------------------------------------------
    // 2. Static Frontend Files Serving (HTML5, CSS3, Vanilla JS)
    // -------------------------------------------------------------------------
    if (method !== 'GET' && method !== 'HEAD') {
        res.writeHead(405, { 'Content-Type': 'text/plain' });
        res.end('Method Not Allowed');
        return;
    }

    const relativeFilePath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    const safeFilePath = path.normalize(path.join(FRONTEND_DIR, relativeFilePath));

    // Security: Prevent path traversal outside FRONTEND_DIR
    if (!safeFilePath.startsWith(FRONTEND_DIR)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
    }

    const ext = path.extname(safeFilePath).toLowerCase();

    fs.stat(safeFilePath, (statErr, stats) => {
        if (!statErr && stats.isFile()) {
            const contentType = MIME_TYPES[ext] || 'application/octet-stream';
            const isHtml = ext === '.html';

            res.writeHead(200, {
                'Content-Type': contentType,
                'Content-Length': stats.size,
                'X-Content-Type-Options': 'nosniff',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                ...corsHeaders
            });

            if (method === 'HEAD') {
                res.end();
                return;
            }

            const readStream = fs.createReadStream(safeFilePath);
            readStream.pipe(res);
            readStream.on('error', (streamErr) => {
                logger.error('Stream error serving static file', { error: streamErr.message });
                if (!res.headersSent) {
                    res.writeHead(500, { 'Content-Type': 'text/plain' });
                    res.end('Internal Server Error');
                }
            });
            return;
        }

        // Static assets with extensions that do not exist must return 404 (never fall back to index.html)
        if (ext) {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(`Asset not found: ${pathname}`);
            return;
        }

        // Extensionless navigation route -> Single Page Application (SPA) fallback to index.html
        const fallbackIndexPath = path.join(FRONTEND_DIR, 'index.html');
        fs.stat(fallbackIndexPath, (fallbackErr, fallbackStats) => {
            if (fallbackErr || !fallbackStats.isFile()) {
                res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
                res.end(`File not found: ${pathname}`);
                return;
            }

            res.writeHead(200, {
                'Content-Type': 'text/html; charset=utf-8',
                'Content-Length': fallbackStats.size,
                'X-Content-Type-Options': 'nosniff',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                ...corsHeaders
            });

            if (method === 'HEAD') {
                res.end();
                return;
            }

            const fallbackStream = fs.createReadStream(fallbackIndexPath);
            fallbackStream.pipe(res);
            fallbackStream.on('error', (streamErr) => {
                logger.error('Stream error serving fallback index.html', { error: streamErr.message });
                if (!res.headersSent) {
                    res.writeHead(500, { 'Content-Type': 'text/plain' });
                    res.end('Internal Server Error');
                }
            });
        });
    });
});

server.listen(PORT, () => {
    logger.info(`==================================================================`);
    logger.info(`  AccessLease Application is LIVE Locally!`);
    logger.info(`  Authentication:      Microsoft Entra ID (OAuth 2.0 PKCE)`);
    logger.info(`==================================================================`);
    logger.info(`  -> Frontend UI:      http://localhost:${PORT}/`);
    logger.info(`  -> API Health:       http://localhost:${PORT}/api/health`);
    logger.info(`  -> Database Health:  http://localhost:${PORT}/api/health/db`);
    logger.info(`  -> Auth Config API:  http://localhost:${PORT}/api/auth/config`);
    logger.info(`  -> Protected Auth:   http://localhost:${PORT}/api/auth/me`);
    logger.info(`  -> GitHub Status:    http://localhost:${PORT}/api/connectors/github/status`);
    logger.info(`==================================================================`);

    // Start durable background provisioning worker
    provisioningWorker.startWorker(10000);
});

process.on('SIGINT', () => {
    logger.info('Shutting down local server...');
    provisioningWorker.stopWorker();
    server.close(() => process.exit(0));
});
