/**
 * AccessLease — Health Check Function Handlers
 * Endpoints:
 * - GET /api/health
 * - GET /api/health/db
 */

const env = require('../config/environment');
const db = require('../config/database');
const { createSuccessBody, createErrorBody, toHttpResponse } = require('../utils/response');
const logger = require('../utils/logger');

/**
 * Handles GET /api/health
 * Returns overall service health and non-sensitive environment metadata.
 * @param {import('@azure/functions').HttpRequest} request
 * @param {import('@azure/functions').InvocationContext} context
 * @returns {Promise<import('@azure/functions').HttpResponseInit>}
 */
async function getApplicationHealth(request, context) {
    const summary = env.getPublicEnvironmentSummary();
    const correlationId = request?.headers?.get('x-correlation-id') || undefined;

    const responseData = {
        application: 'AccessLease',
        status: 'UP',
        service: 'Core Backend API',
        environment: summary.environment,
        version: summary.version,
        database_configured: summary.database_configured,
        uptime_seconds: Math.floor(process.uptime())
    };

    logger.info('Health check executed', { status: 'UP' });

    return toHttpResponse(200, createSuccessBody(responseData, { correlation_id: correlationId }));
}

/**
 * Handles GET /api/health/db
 * Attempts a live SQL Server connection check and lightweight query.
 * @param {import('@azure/functions').HttpRequest} request
 * @param {import('@azure/functions').InvocationContext} context
 * @returns {Promise<import('@azure/functions').HttpResponseInit>}
 */
async function getDatabaseHealth(request, context) {
    const correlationId = request?.headers?.get('x-correlation-id') || undefined;
    const { isValid, missingFields } = env.validateDatabaseConfig();

    if (!isValid) {
        logger.warn('Database health check requested but configuration is incomplete', {
            missing: missingFields
        });

        const errorBody = createErrorBody(
            'ERR_DATABASE_NOT_CONFIGURED',
            'Database connectivity is unavailable because required environment variables are not configured.',
            [{ reason: 'Missing required configuration keys', missing_keys: missingFields }],
            { correlation_id: correlationId }
        );

        return toHttpResponse(503, errorBody);
    }

    try {
        const checkResult = await db.checkConnection();
        logger.info('Database health check verified live connectivity', { healthy: true });

        const successBody = createSuccessBody(
            {
                database: 'Microsoft SQL Server / Azure SQL Database',
                status: 'CONNECTED',
                connectivity: checkResult.is_healthy ? 'HEALTHY' : 'DEGRADED',
                server_time: checkResult.server_time
            },
            { correlation_id: correlationId }
        );

        return toHttpResponse(200, successBody);
    } catch (err) {
        logger.error('Database health check failed to establish connectivity', err);

        const errorBody = createErrorBody(
            'ERR_DATABASE_UNAVAILABLE',
            'Database connectivity check failed. Target SQL Server could not be reached.',
            [{ reason: 'Connection timeout or network failure' }],
            { correlation_id: correlationId }
        );

        return toHttpResponse(503, errorBody);
    }
}

module.exports = {
    getApplicationHealth,
    getDatabaseHealth
};
