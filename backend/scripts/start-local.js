/**
 * AccessLease — Local Development HTTP Server
 * Allows local development and testing of HTTP trigger functions
 * without requiring global Azure Functions Core Tools installation.
 * 
 * Exposes:
 * - GET http://localhost:7071/api/health
 * - GET http://localhost:7071/api/health/db
 */

const http = require('http');
const { getApplicationHealth, getDatabaseHealth } = require('../src/functions/health');
const env = require('../src/config/environment');
const logger = require('../src/utils/logger');

const PORT = env.PORT || 7071;

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const method = req.method.toUpperCase();
    const pathname = url.pathname.replace(/\/+$/, '');

    // Convert IncomingMessage headers to a Map compatible with Azure Functions v4 HttpRequest
    const headersMap = new Map();
    for (const [key, value] of Object.entries(req.headers)) {
        headersMap.set(key.toLowerCase(), value);
    }

    const mockRequest = {
        method,
        url: req.url,
        headers: headersMap,
        query: Object.fromEntries(url.searchParams.entries())
    };

    const mockContext = {
        invocationId: 'local-inv-' + Date.now(),
        log: console.log
    };

    let result = null;

    if (method === 'GET' && pathname === '/api/health') {
        result = await getApplicationHealth(mockRequest, mockContext);
    } else if (method === 'GET' && pathname === '/api/health/db') {
        result = await getDatabaseHealth(mockRequest, mockContext);
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

    res.writeHead(result.status, result.headers);
    res.end(JSON.stringify(result.jsonBody));
});

server.listen(PORT, () => {
    logger.info(`AccessLease Local API Server running at http://localhost:${PORT}`);
    logger.info(`Available endpoints:`);
    logger.info(`  -> GET http://localhost:${PORT}/api/health`);
    logger.info(`  -> GET http://localhost:${PORT}/api/health/db`);
});

process.on('SIGINT', () => {
    logger.info('Shutting down local server...');
    server.close(() => process.exit(0));
});

