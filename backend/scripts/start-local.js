/**
 * AccessLease — Local Development HTTP Server
 * Allows local development and testing of HTTP trigger functions
 * without requiring global Azure Functions Core Tools installation.
 * 
 * Exposes:
 * - GET http://localhost:7071/api/health
 * - GET http://localhost:7071/api/health/db
 * - GET http://localhost:7071/api/auth/config
 * - GET http://localhost:7071/api/auth/me (Protected with Entra ID Bearer token)
 */

const http = require('http');
const { getApplicationHealth, getDatabaseHealth } = require('../src/functions/health');
const { getAuthMe, getAuthConfigHandler } = require('../src/functions/auth');
const env = require('../src/config/environment');
const logger = require('../src/utils/logger');

const PORT = env.PORT || 7071;

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const method = req.method.toUpperCase();
    const pathname = url.pathname.replace(/\/+$/, '');

    // Standard CORS headers for local frontend integration
    const origin = req.headers.origin || '*';
    const corsHeaders = {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Requested-With, Accept',
        'Access-Control-Allow-Credentials': 'true'
    };

    if (method === 'OPTIONS') {
        res.writeHead(204, corsHeaders);
        res.end();
        return;
    }

    // Convert IncomingMessage headers to a Map compatible with Azure Functions v4 HttpRequest
    const headersMap = new Map();
    for (const [key, value] of Object.entries(req.headers)) {
        headersMap.set(key.toLowerCase(), value);
    }

    const mockRequest = {
        method,
        url: req.url,
        path: pathname,
        headers: headersMap,
        query: Object.fromEntries(url.searchParams.entries())
    };

    const mockContext = {
        invocationId: 'local-inv-' + Date.now(),
        log: console.log
    };

    let result = null;

    try {
        if (method === 'GET' && pathname === '/api/health') {
            result = await getApplicationHealth(mockRequest, mockContext);
        } else if (method === 'GET' && pathname === '/api/health/db') {
            result = await getDatabaseHealth(mockRequest, mockContext);
        } else if (method === 'GET' && pathname === '/api/auth/config') {
            result = await getAuthConfigHandler(mockRequest, mockContext);
        } else if (method === 'GET' && pathname === '/api/auth/me') {
            result = await getAuthMe(mockRequest, mockContext);
        } else {
            result = {
                status: 404,
                headers: { 'Content-Type': 'application/json' },
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
            headers: { 'Content-Type': 'application/json' },
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
});

server.listen(PORT, () => {
    logger.info(`AccessLease Local API Server running at http://localhost:${PORT}`);
    logger.info(`Available endpoints:`);
    logger.info(`  -> GET http://localhost:${PORT}/api/health`);
    logger.info(`  -> GET http://localhost:${PORT}/api/health/db`);
    logger.info(`  -> GET http://localhost:${PORT}/api/auth/config`);
    logger.info(`  -> GET http://localhost:${PORT}/api/auth/me (Bearer Token Required)`);
});

process.on('SIGINT', () => {
    logger.info('Shutting down local server...');
    server.close(() => process.exit(0));
});
