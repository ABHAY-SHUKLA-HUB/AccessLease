/**
 * AccessLease — Security Analytics HTTP Trigger Functions
 * Azure Functions v4 REST Handlers.
 * 
 * Endpoints:
 * - GET /api/analytics/summary (Protected): Produces real-time governance metrics and status breakdowns
 */

const { withAuth } = require('../middleware/authMiddleware');
const analyticsService = require('../services/analyticsService');
const { createSuccessBody, toHttpResponse } = require('../utils/response');
const { handleAuthError } = require('../middleware/authorize');
const logger = require('../utils/logger');

// -----------------------------------------------------------------------------
// 1. GET /api/analytics/summary - Real-time aggregate security analytics
// -----------------------------------------------------------------------------
async function getAnalyticsSummaryHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const result = await analyticsService.getSecurityAnalyticsSummary(user);

        const correlationId = context?.invocationId;
        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

module.exports = {
    getAnalyticsSummary: withAuth(getAnalyticsSummaryHandler)
};

