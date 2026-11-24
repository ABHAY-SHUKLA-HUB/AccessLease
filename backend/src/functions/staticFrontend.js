/**
 * AccessLease — Unified Static Frontend Azure Functions Handler
 * Target: Node.js 22 LTS / Azure Functions v4
 * 
 * Responsibilities:
 * - Serve the Vanilla JavaScript frontend from Azure Functions Linux Consumption.
 * - Enforce strict Content Security Policy, HSTS, frame protection, and security headers.
 * - Serve static files with proper MIME types and no-cache caching policy.
 * - Support Single Page Application (SPA) navigation fallback for client-side routing.
 * - Return 404 for missing static assets (never fall back to HTML for JS/CSS/images).
 * - Return 404 JSON for unknown /api/* requests (never serve HTML for API calls).
 * - Prevent path traversal attacks (including URL-encoded traversal).
 * - Support GET and HEAD methods (HEAD returns empty body).
 * - Zero leakage of filesystem paths, stack traces, or internal server details.
 */

const fs = require('fs');
const path = require('path');

// 1. Directory Resolution
// Primary bundled path: /home/site/wwwroot/public (or backend/public locally)
const BUNDLED_PUBLIC_DIR = path.resolve(__dirname, '../../public');
// Development fallback: D:\access\frontend
const DEV_FRONTEND_DIR = path.resolve(__dirname, '../../../frontend');

function getStaticDir() {
    if (process.env.STATIC_FRONTEND_DIR && fs.existsSync(process.env.STATIC_FRONTEND_DIR)) {
        return path.resolve(process.env.STATIC_FRONTEND_DIR);
    }
    if (fs.existsSync(BUNDLED_PUBLIC_DIR)) {
        return BUNDLED_PUBLIC_DIR;
    }
    if (fs.existsSync(DEV_FRONTEND_DIR)) {
        return DEV_FRONTEND_DIR;
    }
    return BUNDLED_PUBLIC_DIR;
}

// 2. MIME Types Dictionary
const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
    '.ttf': 'font/ttf',
    '.txt': 'text/plain; charset=utf-8'
};

// Recognized asset extensions that must NEVER fall back to index.html
const ASSET_EXTENSIONS = new Set([
    '.js', '.css', '.json', '.svg', '.png', '.jpg', '.jpeg', '.gif',
    '.ico', '.woff2', '.woff', '.ttf', '.map', '.txt'
]);

// 3. Security Headers
// Preserves MSAL CDN, Entra login endpoints, same-origin API calls, and inline scripts/styles
const CSP_HEADER = "default-src 'self'; script-src 'self' 'unsafe-inline' https://alcdn.msauth.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' https://login.microsoftonline.com https://*.login.microsoftonline.com; frame-src 'self' https://login.microsoftonline.com https://*.login.microsoftonline.com; frame-ancestors 'none'; object-src 'none'; base-uri 'self';";

const BASE_SECURITY_HEADERS = {
    'Content-Security-Policy': CSP_HEADER,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
};

/**
 * Checks whether an incoming Azure Functions request is served over HTTPS.
 * @param {object} request Azure Functions HttpRequest
 * @returns {boolean}
 */
function isHttpsRequest(request) {
    if (!request) return false;
    if (typeof request.url === 'string' && request.url.startsWith('https:')) {
        return true;
    }
    const headers = request.headers;
    if (!headers) return false;

    const getHeader = (name) => {
        if (typeof headers.get === 'function') return headers.get(name);
        return headers[name] || headers[name.toLowerCase()];
    };

    const proto = getHeader('x-forwarded-proto');
    if (proto && String(proto).trim().toLowerCase() === 'https') {
        return true;
    }
    const arrSsl = getHeader('x-arr-ssl');
    if (arrSsl) {
        return true;
    }
    return false;
}

/**
 * Builds standard security headers, adding HSTS only for HTTPS responses.
 * Note: Does not includeSubDomains or preload on shared azurewebsites.net domain.
 * @param {object} request Azure Functions HttpRequest
 * @returns {object}
 */
function getSecurityHeaders(request) {
    const headers = { ...BASE_SECURITY_HEADERS };
    if (isHttpsRequest(request)) {
        headers['Strict-Transport-Security'] = 'max-age=31536000';
    }
    return headers;
}

/**
 * Core handler for serving frontend static assets and SPA fallback.
 * 
 * @param {object} request Azure Functions HttpRequest
 * @param {object} [context] Azure Functions InvocationContext
 * @returns {Promise<object>} Azure Functions HttpResponseInit
 */
async function staticFrontendHandler(request, context) {
    const method = (request.method || 'GET').toUpperCase();

    // 1. Method check: only GET and HEAD are allowed
    if (method !== 'GET' && method !== 'HEAD') {
        return {
            status: 405,
            headers: {
                'Content-Type': 'text/plain; charset=utf-8',
                'Allow': 'GET, HEAD',
                ...getSecurityHeaders(request)
            },
            body: 'Method Not Allowed'
        };
    }

    // 2. Extract and decode requested path
    const rawPathParam = (request.params && request.params.restOfPath !== undefined)
        ? request.params.restOfPath
        : '';

    let decodedPath;
    try {
        decodedPath = decodeURIComponent(rawPathParam);
    } catch {
        return {
            status: 400,
            headers: {
                'Content-Type': 'text/plain; charset=utf-8',
                ...getSecurityHeaders(request)
            },
            body: 'Bad Request'
        };
    }

    // Reject null-byte poisoning
    if (decodedPath.includes('\0')) {
        return {
            status: 400,
            headers: {
                'Content-Type': 'text/plain; charset=utf-8',
                ...getSecurityHeaders(request)
            },
            body: 'Bad Request'
        };
    }

    // Strip query parameters, hash fragments, and leading slashes
    const cleanRelativePath = decodedPath.split('?')[0].split('#')[0].replace(/^\/+/, '');
    const normalizedPath = path.normalize(cleanRelativePath);

    // 3. API Path Guardrail:
    // If the path starts with 'api/' or equals 'api', it is an unhandled API route.
    // NEVER serve index.html for API requests; return structured JSON 404.
    const normalizedLower = normalizedPath.replace(/\\/g, '/').toLowerCase();
    if (normalizedLower === 'api' || normalizedLower.startsWith('api/')) {
        return {
            status: 404,
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0',
                ...getSecurityHeaders(request)
            },
            jsonBody: {
                success: false,
                error: {
                    code: 'ERR_NOT_FOUND',
                    message: `API route ${method} /${cleanRelativePath} not found.`
                }
            }
        };
    }

    // 4. Path Traversal Guardrail:
    // Ensure the normalized path stays strictly inside STATIC_DIR
    const staticDir = getStaticDir();
    if (normalizedPath.startsWith('..') || path.isAbsolute(normalizedPath)) {
        return {
            status: 403,
            headers: {
                'Content-Type': 'text/plain; charset=utf-8',
                ...getSecurityHeaders(request)
            },
            body: 'Forbidden'
        };
    }

    const resolvedFullPath = path.resolve(staticDir, normalizedPath);
    if (!resolvedFullPath.startsWith(staticDir)) {
        return {
            status: 403,
            headers: {
                'Content-Type': 'text/plain; charset=utf-8',
                ...getSecurityHeaders(request)
            },
            body: 'Forbidden'
        };
    }

    const ext = path.extname(resolvedFullPath).toLowerCase();

    // 5. Normal file handling: Check if requested target is a real file
    // Handle root '/' or empty path as 'index.html'
    const isRootRequest = !cleanRelativePath || cleanRelativePath === '/' || cleanRelativePath === 'index.html';
    const targetFilePath = isRootRequest ? path.join(staticDir, 'index.html') : resolvedFullPath;

    if (fs.existsSync(targetFilePath)) {
        let stat;
        try {
            stat = fs.statSync(targetFilePath);
        } catch {
            return {
                status: 500,
                headers: { 'Content-Type': 'text/plain; charset=utf-8', ...getSecurityHeaders(request) },
                body: 'Internal Server Error'
            };
        }

        if (stat.isFile()) {
            const targetExt = path.extname(targetFilePath).toLowerCase();
            const contentType = MIME_TYPES[targetExt] || 'application/octet-stream';
            const isHtml = targetExt === '.html';

            // Caching Policy:
            // - HTML: no-cache, no-store, must-revalidate
            // - Assets (JS, CSS, images): no-cache (no long-lived caching until fingerprinting)
            const cacheControl = isHtml
                ? 'no-cache, no-store, must-revalidate'
                : 'no-cache';

            const headers = {
                'Content-Type': contentType,
                'Content-Length': String(stat.size),
                'Cache-Control': cacheControl,
                'Pragma': 'no-cache',
                ...getSecurityHeaders(request)
            };
            if (isHtml) {
                headers['Expires'] = '0';
            }

            if (method === 'HEAD') {
                return { status: 200, headers, body: '' };
            }

            try {
                const fileBuffer = fs.readFileSync(targetFilePath);
                return { status: 200, headers, body: fileBuffer };
            } catch {
                return {
                    status: 500,
                    headers: { 'Content-Type': 'text/plain; charset=utf-8', ...getSecurityHeaders(request) },
                    body: 'Internal Server Error'
                };
            }
        }
    }

    // 6. Target file does NOT exist:
    // A. If the request had a recognized static asset extension (.js, .css, .ico, etc.)
    // MUST return 404. NEVER fall back to index.html for missing assets!
    if (ASSET_EXTENSIONS.has(ext)) {
        const headers = {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            ...getSecurityHeaders(request)
        };
        return {
            status: 404,
            headers,
            body: method === 'HEAD' ? '' : 'Asset not found'
        };
    }

    // B. Extensionless navigation route -> SPA Navigation Fallback
    // Return index.html with 200 OK to allow client-side router to handle the route
    const fallbackIndexPath = path.join(staticDir, 'index.html');
    if (fs.existsSync(fallbackIndexPath)) {
        let indexStat;
        try {
            indexStat = fs.statSync(fallbackIndexPath);
        } catch {
            return {
                status: 500,
                headers: { 'Content-Type': 'text/plain; charset=utf-8', ...getSecurityHeaders(request) },
                body: 'Internal Server Error'
            };
        }

        const headers = {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Length': String(indexStat.size),
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            ...getSecurityHeaders(request)
        };

        if (method === 'HEAD') {
            return { status: 200, headers, body: '' };
        }

        try {
            const indexContent = fs.readFileSync(fallbackIndexPath);
            return { status: 200, headers, body: indexContent };
        } catch {
            return {
                status: 500,
                headers: { 'Content-Type': 'text/plain; charset=utf-8', ...getSecurityHeaders(request) },
                body: 'Internal Server Error'
            };
        }
    }

    // Fallback if index.html is completely missing
    return {
        status: 404,
        headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            ...getSecurityHeaders(request)
        },
        body: method === 'HEAD' ? '' : 'Not Found'
    };
}

module.exports = {
    staticFrontendHandler,
    getStaticDir,
    getSecurityHeaders,
    isHttpsRequest,
    MIME_TYPES,
    ASSET_EXTENSIONS,
    BUNDLED_PUBLIC_DIR,
    DEV_FRONTEND_DIR
};

