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
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
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

    fs.stat(safeFilePath, (statErr, stats) => {
        if (statErr || !stats.isFile()) {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(`File not found: ${pathname}`);
            return;
        }

        const ext = path.extname(safeFilePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';

        res.writeHead(200, {
            'Content-Type': contentType,
            'Content-Length': stats.size,
            'X-Content-Type-Options': 'nosniff',
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
    });
});

server.listen(PORT, () => {
    logger.info(`==================================================================`);
    logger.info(`  AccessLease Application is LIVE Locally!`);
    logger.info(`==================================================================`);
    logger.info(`  -> Frontend UI:      http://localhost:${PORT}/`);
    logger.info(`  -> API Health:       http://localhost:${PORT}/api/health`);
    logger.info(`  -> Database Health:  http://localhost:${PORT}/api/health/db`);
    logger.info(`  -> Auth Config API:  http://localhost:${PORT}/api/auth/config`);
    logger.info(`  -> Protected Auth:   http://localhost:${PORT}/api/auth/me`);
    logger.info(`==================================================================`);
});

process.on('SIGINT', () => {
    logger.info('Shutting down local server...');
    server.close(() => process.exit(0));
});
