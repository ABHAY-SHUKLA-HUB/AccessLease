/**
 * AccessLease — Integration Tests: Static Frontend Handler & Option 4 Verification
 * 
 * Verifies unified frontend serving from Azure Functions v4 runtime:
 * 1. GET / serves index.html with 200 OK and strict security headers.
 * 2. GET /index.html serves index.html with 200 OK and no-cache policy.
 * 3. GET an existing JS asset (e.g. /assets/js/main.js) serves application/javascript.
 * 4. GET an existing CSS asset (e.g. /assets/css/main.css) serves text/css.
 * 5. GET a missing JS/CSS asset returns 404 (never falls back to index.html).
 * 6. GET /api/health returns 200 OK via the dedicated health API handler.
 * 7. GET /api/invalid-route returns JSON 404 (never falls back to index.html).
 * 8. GET an extensionless SPA route (e.g. /contractors) returns index.html (SPA fallback).
 * 9. GET /favicon.ico returns 404 (never falls back to index.html).
 * 10. HEAD / returns 200 OK with Content-Length and zero response body.
 * 11. URL-encoded path traversal (e.g. /%2e%2e/%2e%2e/etc/passwd) returns 403 Forbidden.
 * 12. HTTPS request returns Strict-Transport-Security (without includeSubDomains/preload).
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');

const {
    staticFrontendHandler,
    getStaticDir,
    BUNDLED_PUBLIC_DIR,
    DEV_FRONTEND_DIR
} = require('../../src/functions/staticFrontend');
const { getApplicationHealth } = require('../../src/functions/health');

describe('Integration: Static Frontend Handler & Unified Azure Functions Hosting', () => {

    before(() => {
        // Ensure static directory is populated (via stage:frontend or dev fallback)
        const staticDir = getStaticDir();
        assert.ok(fs.existsSync(staticDir), `Static directory must exist at ${staticDir}`);
        assert.ok(fs.existsSync(path.join(staticDir, 'index.html')), 'index.html must exist in static directory');
    });

    it('1. GET /: should serve index.html with 200 OK, text/html, and security headers', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/',
            headers: {},
            params: { restOfPath: '' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['Content-Type'], 'text/html; charset=utf-8');
        assert.strictEqual(res.headers['Cache-Control'], 'no-cache, no-store, must-revalidate');
        assert.strictEqual(res.headers['X-Content-Type-Options'], 'nosniff');
        assert.strictEqual(res.headers['X-Frame-Options'], 'DENY');
        assert.ok(res.headers['Content-Security-Policy'].includes("default-src 'self'"));
        assert.ok(res.headers['Content-Security-Policy'].includes('https://alcdn.msauth.net'));
        assert.ok(res.headers['Content-Security-Policy'].includes('https://login.microsoftonline.com'));
        assert.ok(res.body.length > 0, 'Response body must not be empty');
        const bodyText = res.body.toString('utf8');
        assert.ok(bodyText.includes('<title>AccessLease'), 'Body must contain AccessLease HTML title');
    });

    it('2. GET /index.html: should serve index.html with 200 OK and no-cache policy', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/index.html',
            headers: {},
            params: { restOfPath: 'index.html' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['Content-Type'], 'text/html; charset=utf-8');
        assert.strictEqual(res.headers['Cache-Control'], 'no-cache, no-store, must-revalidate');
        assert.strictEqual(res.headers['Pragma'], 'no-cache');
        assert.strictEqual(res.headers['Expires'], '0');
    });

    it('3. GET an existing JS asset: should serve application/javascript with no-cache', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/assets/js/main.js',
            headers: {},
            params: { restOfPath: 'assets/js/main.js' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['Content-Type'], 'application/javascript; charset=utf-8');
        assert.strictEqual(res.headers['Cache-Control'], 'no-cache');
        assert.strictEqual(res.headers['X-Content-Type-Options'], 'nosniff');
        assert.ok(res.body.length > 0);
    });

    it('4. GET an existing CSS asset: should serve text/css with no-cache', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/assets/css/main.css',
            headers: {},
            params: { restOfPath: 'assets/css/main.css' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['Content-Type'], 'text/css; charset=utf-8');
        assert.strictEqual(res.headers['Cache-Control'], 'no-cache');
        assert.ok(res.body.length > 0);
    });

    it('5. GET a missing JS/CSS asset: must return 404 and NEVER fall back to index.html', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/assets/css/nonexistent-styles.css',
            headers: {},
            params: { restOfPath: 'assets/css/nonexistent-styles.css' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 404);
        assert.strictEqual(res.headers['Content-Type'], 'text/plain; charset=utf-8');
        assert.strictEqual(res.body, 'Asset not found');
        assert.ok(!res.body.includes('<html'), 'Missing asset must never return HTML');
    });

    it('6. GET /api/health: should return 200 OK via dedicated health API trigger', async () => {
        const req = {
            method: 'GET',
            headers: new Headers({}),
            url: 'http://localhost:7071/api/health'
        };
        const context = { invocationId: 'test-health-inv-1' };

        const res = await getApplicationHealth(req, context);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.jsonBody.success, true);
        assert.strictEqual(res.jsonBody.data.status, 'UP');
        assert.strictEqual(res.headers['X-Content-Type-Options'], 'nosniff');
    });

    it('7. GET /api/invalid-route: must return JSON 404 and NEVER return index.html', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/api/invalid-route',
            headers: {},
            params: { restOfPath: 'api/invalid-route' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 404);
        assert.strictEqual(res.headers['Content-Type'], 'application/json; charset=utf-8');
        assert.strictEqual(res.jsonBody.success, false);
        assert.strictEqual(res.jsonBody.error.code, 'ERR_NOT_FOUND');
        assert.ok(res.jsonBody.error.message.includes('/api/invalid-route'));
    });

    it('8. GET an extensionless SPA route (/contractors): should return index.html (SPA Fallback)', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/contractors',
            headers: {},
            params: { restOfPath: 'contractors' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['Content-Type'], 'text/html; charset=utf-8');
        assert.strictEqual(res.headers['Cache-Control'], 'no-cache, no-store, must-revalidate');
        const bodyText = res.body.toString('utf8');
        assert.ok(bodyText.includes('<title>AccessLease'), 'SPA fallback must serve index.html');
    });

    it('9. GET /favicon.ico: should return 404 if missing (never index.html)', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/favicon.ico',
            headers: {},
            params: { restOfPath: 'favicon.ico' }
        };

        const res = await staticFrontendHandler(req);

        // If favicon exists returns 200 image/x-icon; if missing must return 404 text/plain
        if (res.status === 200) {
            assert.strictEqual(res.headers['Content-Type'], 'image/x-icon');
        } else {
            assert.strictEqual(res.status, 404);
            assert.ok(!res.body.includes('<html'), 'Missing favicon must never return HTML');
        }
    });

    it('10. HEAD /: should return 200 OK with Content-Length and EMPTY response body', async () => {
        const req = {
            method: 'HEAD',
            url: 'http://localhost:7071/',
            headers: {},
            params: { restOfPath: '' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['Content-Type'], 'text/html; charset=utf-8');
        assert.ok('Content-Length' in res.headers, 'Content-Length must be present');
        assert.strictEqual(res.body, '', 'HEAD response body must be empty string');
    });

    it('11. URL-encoded path traversal (/%2e%2e/%2e%2e/etc/passwd): must return 403 Forbidden', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/%2e%2e/%2e%2e/package.json',
            headers: {},
            params: { restOfPath: '%2e%2e/%2e%2e/package.json' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 403);
        assert.strictEqual(res.headers['Content-Type'], 'text/plain; charset=utf-8');
        assert.strictEqual(res.body, 'Forbidden');
    });

    it('12. HTTPS Request: should include Strict-Transport-Security without includeSubDomains or preload', async () => {
        const req = {
            method: 'GET',
            url: 'https://func-accesslease-dev.azurewebsites.net/',
            headers: {
                'x-forwarded-proto': 'https'
            },
            params: { restOfPath: '' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['Strict-Transport-Security'], 'max-age=31536000');
        assert.ok(!res.headers['Strict-Transport-Security'].includes('includeSubDomains'), 'Must not includeSubDomains on shared domain');
        assert.ok(!res.headers['Strict-Transport-Security'].includes('preload'), 'Must not preload on shared domain');
    });

    it('13. GET /contractors?status=active: should strip query params and serve index.html (SPA Fallback)', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/contractors?status=active',
            headers: {},
            params: { restOfPath: 'contractors?status=active' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['Content-Type'], 'text/html; charset=utf-8');
        const bodyText = res.body.toString('utf8');
        assert.ok(bodyText.includes('<title>AccessLease'));
    });

    it('14. GET /contractors/: should handle trailing slash and serve index.html (SPA Fallback)', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/contractors/',
            headers: {},
            params: { restOfPath: 'contractors/' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['Content-Type'], 'text/html; charset=utf-8');
        const bodyText = res.body.toString('utf8');
        assert.ok(bodyText.includes('<title>AccessLease'));
    });

    it('15. GET /contractors/123/profile: should handle nested extensionless route and serve index.html (SPA Fallback)', async () => {
        const req = {
            method: 'GET',
            url: 'http://localhost:7071/contractors/123/profile',
            headers: {},
            params: { restOfPath: 'contractors/123/profile' }
        };

        const res = await staticFrontendHandler(req);

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers['Content-Type'], 'text/html; charset=utf-8');
        const bodyText = res.body.toString('utf8');
        assert.ok(bodyText.includes('<title>AccessLease'));
    });
});
