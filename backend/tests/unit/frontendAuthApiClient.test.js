/**
 * AccessLease — Unit Tests: Frontend Authentication & Centralized API Client Flow
 * 
 * Verifies:
 * 1. ApiClient: Endpoint classification (public vs protected).
 * 2. ApiClient: Protected endpoint automatic Bearer token injection.
 * 3. ApiClient: Protected endpoint rejection (ERR_UNAUTHORIZED) when unauthenticated, without network dispatch.
 * 4. ApiClient: Public endpoints (/api/auth/config, /api/health, /api/health/db) bypass token requirement.
 * 5. ApiClient: Explicit Authorization header preservation.
 * 6. ApiClient: Standardized 401/403/500 API error formatting.
 * 7. AuthManager: Target backend API scope verification (api://aa3b2968-201b-4cbf-b650-abc839c2ad4c/access_as_user).
 * 8. AuthManager: Silent token acquisition via MSAL acquireTokenSilent.
 * 9. AuthManager: Interactive popup fallback for InteractionRequiredAuthError and no_tokens_found.
 * 10. AuthManager: In-flight token acquisition promise deduplication.
 * 11. AuthManager: Account resolution fallback to getActiveAccount / getAllAccounts.
 * 12. AuthManager: loadUserProfile delegating to apiClient and populating SYSTEM_ADMIN role.
 * 13. AuthManager: loadUserProfile handling 401/403 with identity rejection.
 * 14. Security: Absence of tokens or credentials in logs and clean cache isolation.
 */

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const API_CLIENT_FILE = path.resolve(__dirname, '../../public/assets/js/apiClient.js');
const AUTH_FILE = path.resolve(__dirname, '../../public/assets/js/auth.js');
const EXPECTED_API_SCOPE = 'api://aa3b2968-201b-4cbf-b650-abc839c2ad4c/access_as_user';

function createMockEnvironment() {
    const mockWindow = {
        location: {
            origin: 'https://func-accesslease-dev-krfptp6h5dssa.azurewebsites.net'
        },
        msal: {
            InteractionRequiredAuthError: class InteractionRequiredAuthError extends Error {
                constructor(message, errorCode) {
                    super(message);
                    this.name = 'InteractionRequiredAuthError';
                    this.errorCode = errorCode || 'interaction_required';
                }
            },
            PublicClientApplication: class PublicClientApplication {
                constructor(config) {
                    this.config = config;
                    this.activeAccount = null;
                    this.accounts = [];
                }
                handleRedirectPromise() {
                    return Promise.resolve(null);
                }
                getActiveAccount() {
                    return this.activeAccount;
                }
                setActiveAccount(account) {
                    this.activeAccount = account;
                }
                getAllAccounts() {
                    return this.accounts;
                }
                acquireTokenSilent(req) {
                    return Promise.resolve({ accessToken: 'mock-silent-token', account: req.account });
                }
                acquireTokenPopup(req) {
                    return Promise.resolve({ accessToken: 'mock-popup-token', account: req.account });
                }
                loginPopup(req) {
                    const acc = { homeAccountId: 'user-1', username: 'admin@accesslease.com' };
                    this.activeAccount = acc;
                    return Promise.resolve({ account: acc });
                }
                logoutPopup() {
                    this.activeAccount = null;
                    return Promise.resolve();
                }
            }
        },
        console: {
            log: () => {},
            info: () => {},
            warn: () => {},
            error: () => {}
        }
    };

    mockWindow.window = mockWindow;
    return mockWindow;
}

function loadScriptsInContext(mockWindow) {
    const context = vm.createContext({
        window: mockWindow,
        console: mockWindow.console,
        Headers: globalThis.Headers,
        URL: globalThis.URL,
        URLSearchParams: globalThis.URLSearchParams,
        encodeURIComponent: globalThis.encodeURIComponent,
        FormData: globalThis.FormData || class FormData {},
        fetch: mockWindow.fetch || globalThis.fetch,
        document: {
            getElementById: () => null,
            querySelector: () => null,
            querySelectorAll: () => [],
            createElement: () => ({ appendChild: () => {}, querySelector: () => ({ addEventListener: () => {} }) }),
            addEventListener: () => {}
        },
        setTimeout: globalThis.setTimeout,
        clearTimeout: globalThis.clearTimeout
    });

    const clientSrc = fs.readFileSync(API_CLIENT_FILE, 'utf-8');
    vm.runInContext(clientSrc, context);

    const authSrc = fs.readFileSync(AUTH_FILE, 'utf-8');
    vm.runInContext(authSrc, context);

    return context;
}

describe('Unit: Frontend ApiClient (apiClient.js)', () => {
    let mockWindow;

    beforeEach(() => {
        mockWindow = createMockEnvironment();
    });

    test('1. isPublicEndpoint: should classify health and auth config as public, APIs as protected', () => {
        loadScriptsInContext(mockWindow);
        const client = mockWindow.apiClient;

        // Public endpoints
        assert.strictEqual(client.isPublicEndpoint('/api/auth/config'), true);
        assert.strictEqual(client.isPublicEndpoint('/api/health'), true);
        assert.strictEqual(client.isPublicEndpoint('/api/health/db'), true);
        assert.strictEqual(client.isPublicEndpoint('/api/auth/config?reload=true'), true);
        assert.strictEqual(client.isPublicEndpoint('https://func-accesslease.azurewebsites.net/api/health'), true);
        assert.strictEqual(client.isPublicEndpoint('/assets/css/main.css'), true);
        assert.strictEqual(client.isPublicEndpoint('/index.html'), true);

        // Protected endpoints
        assert.strictEqual(client.isPublicEndpoint('/api/auth/me'), false);
        assert.strictEqual(client.isPublicEndpoint('/api/contractors'), false);
        assert.strictEqual(client.isPublicEndpoint('/api/contractors/me'), false);
        assert.strictEqual(client.isPublicEndpoint('/api/contractors?limit=50&isActive=true'), false);
        assert.strictEqual(client.isPublicEndpoint('/api/engagements'), false);
        assert.strictEqual(client.isPublicEndpoint('/api/requests'), false);
        assert.strictEqual(client.isPublicEndpoint('/api/analytics/summary'), false);
    });

    test('2. Protected request: attaches Authorization: Bearer <token> when token is available', async () => {
        let capturedUrl = null;
        let capturedHeaders = null;

        mockWindow.fetch = async (url, options) => {
            capturedUrl = url;
            capturedHeaders = options.headers;
            return {
                ok: true,
                status: 200,
                headers: new Headers({ 'content-type': 'application/json' }),
                json: async () => ({ success: true, data: { contractors: [{ user_id: '123' }] } })
            };
        };

        loadScriptsInContext(mockWindow);

        // Mock AccessLeaseAuth to return a valid access token
        mockWindow.AccessLeaseAuth.getAccessToken = async () => 'mock-jwt-access-token';

        const res = await mockWindow.apiClient.get('/api/contractors?limit=50');

        assert.ok(res.success);
        assert.strictEqual(capturedUrl, 'https://func-accesslease-dev-krfptp6h5dssa.azurewebsites.net/api/contractors?limit=50');
        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer mock-jwt-access-token');
        assert.strictEqual(capturedHeaders.get('Accept'), 'application/json');
    });

    test('3. Protected request: throws ERR_UNAUTHORIZED and blocks network dispatch when token is missing', async () => {
        let fetchDispatched = false;

        mockWindow.fetch = async () => {
            fetchDispatched = true;
            return { ok: true, status: 200, headers: new Headers() };
        };

        loadScriptsInContext(mockWindow);

        // Return null token (unauthenticated state)
        mockWindow.AccessLeaseAuth.getAccessToken = async () => null;

        await assert.rejects(
            async () => {
                await mockWindow.apiClient.get('/api/contractors');
            },
            (err) => {
                assert.strictEqual(err.code, 'ERR_UNAUTHORIZED');
                assert.strictEqual(err.status, 401);
                assert.ok(err.message.includes('Authentication required'));
                return true;
            }
        );

        assert.strictEqual(fetchDispatched, false, 'Fetch must not be dispatched when unauthenticated on protected routes');
    });

    test('4. Public endpoint: dispatches without token and does not throw even if unauthenticated', async () => {
        let capturedHeaders = null;

        mockWindow.fetch = async (url, options) => {
            capturedHeaders = options.headers;
            return {
                ok: true,
                status: 200,
                headers: new Headers({ 'content-type': 'application/json' }),
                json: async () => ({ success: true, data: { configured: true, apiScope: EXPECTED_API_SCOPE } })
            };
        };

        loadScriptsInContext(mockWindow);

        // Unauthenticated
        mockWindow.AccessLeaseAuth.getAccessToken = async () => null;

        const res = await mockWindow.apiClient.get('/api/auth/config');

        assert.ok(res.success);
        assert.strictEqual(res.data.configured, true);
        assert.strictEqual(capturedHeaders.has('Authorization'), false, 'Public endpoint must not include Authorization header');
    });

    test('5. Explicit Authorization header: preserves caller-supplied Authorization header', async () => {
        let capturedHeaders = null;

        mockWindow.fetch = async (url, options) => {
            capturedHeaders = options.headers;
            return {
                ok: true,
                status: 200,
                headers: new Headers({ 'content-type': 'application/json' }),
                json: async () => ({ success: true, data: {} })
            };
        };

        loadScriptsInContext(mockWindow);
        mockWindow.AccessLeaseAuth.getAccessToken = async () => 'default-token';

        await mockWindow.apiClient.get('/api/contractors', {
            headers: {
                'Authorization': 'Bearer custom-explicit-token'
            }
        });

        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer custom-explicit-token');
    });

    test('6. Standardized error: parses backend 401 ERR_MISSING_AUTH_HEADER into structured ApiError', async () => {
        mockWindow.fetch = async () => {
            return {
                ok: false,
                status: 401,
                statusText: 'Unauthorized',
                headers: new Headers({ 'content-type': 'application/json' }),
                json: async () => ({
                    success: false,
                    error: {
                        code: 'ERR_MISSING_AUTH_HEADER',
                        message: 'Authorization header is required.',
                        details: []
                    }
                })
            };
        };

        loadScriptsInContext(mockWindow);
        mockWindow.AccessLeaseAuth.getAccessToken = async () => 'some-token';

        await assert.rejects(
            async () => {
                await mockWindow.apiClient.get('/api/contractors');
            },
            (err) => {
                assert.strictEqual(err.status, 401);
                assert.strictEqual(err.code, 'ERR_MISSING_AUTH_HEADER');
                assert.strictEqual(err.message, 'Authorization header is required.');
                return true;
            }
        );
    });

    test('6b. isPublicEndpoint: correctly classifies catalog endpoints with or without leading slashes and mixed case as protected', () => {
        loadScriptsInContext(mockWindow);
        const client = mockWindow.apiClient;

        // Catalog endpoints must be strictly protected regardless of leading slash or casing
        assert.strictEqual(client.isPublicEndpoint('/api/catalog/resources'), false);
        assert.strictEqual(client.isPublicEndpoint('api/catalog/resources'), false);
        assert.strictEqual(client.isPublicEndpoint('/API/CATALOG/RESOURCES'), false);
        assert.strictEqual(client.isPublicEndpoint('api/catalog/resources?active=true'), false);
        assert.strictEqual(client.isPublicEndpoint('/api/catalog/resources/res-123/entitlements'), false);
        assert.strictEqual(client.isPublicEndpoint('api/catalog/resources/res-123/entitlements'), false);
        assert.strictEqual(client.isPublicEndpoint('/API/catalog/resources/res-123/entitlements'), false);
    });

    test('6c. Protected request: listCatalogResources propagates Authorization: Bearer <token>', async () => {
        let capturedUrl = null;
        let capturedHeaders = null;

        mockWindow.fetch = async (url, options) => {
            capturedUrl = url;
            capturedHeaders = options.headers;
            return {
                ok: true,
                status: 200,
                headers: new Headers({ 'content-type': 'application/json' }),
                json: async () => ({
                    success: true,
                    data: [
                        { resource_id: 'RES-01', resource_code: 'RES-KUBE', resource_name: 'Kubernetes' }
                    ]
                })
            };
        };

        loadScriptsInContext(mockWindow);
        mockWindow.AccessLeaseAuth.getAccessToken = async () => 'catalog-jwt-token-xyz';

        const res = await mockWindow.apiClient.listCatalogResources();

        assert.ok(res.success);
        assert.strictEqual(capturedUrl, 'https://func-accesslease-dev-krfptp6h5dssa.azurewebsites.net/api/catalog/resources');
        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer catalog-jwt-token-xyz');
        assert.strictEqual(capturedHeaders.get('Accept'), 'application/json');
    });

    test('6d. Protected request: listResourceEntitlements propagates Authorization: Bearer <token> with encoded ID', async () => {
        let capturedUrl = null;
        let capturedHeaders = null;

        mockWindow.fetch = async (url, options) => {
            capturedUrl = url;
            capturedHeaders = options.headers;
            return {
                ok: true,
                status: 200,
                headers: new Headers({ 'content-type': 'application/json' }),
                json: async () => ({
                    success: true,
                    data: [
                        { entitlement_id: 'ENT-01', entitlement_code: 'CLUSTER_ADMIN' }
                    ]
                })
            };
        };

        loadScriptsInContext(mockWindow);
        mockWindow.AccessLeaseAuth.getAccessToken = async () => 'entitlements-jwt-token-abc';

        const res = await mockWindow.apiClient.listResourceEntitlements('res-kube-99');

        assert.ok(res.success);
        assert.strictEqual(capturedUrl, 'https://func-accesslease-dev-krfptp6h5dssa.azurewebsites.net/api/catalog/resources/res-kube-99/entitlements');
        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer entitlements-jwt-token-abc');
    });

    test('6e. Token acquisition failure: rethrows explicit error and never silently dispatches unauthenticated request', async () => {
        let fetchDispatched = false;

        mockWindow.fetch = async () => {
            fetchDispatched = true;
            return { ok: true, status: 200, headers: new Headers() };
        };

        loadScriptsInContext(mockWindow);

        // Simulate token acquisition failure (e.g. popup blocker or interaction rejection)
        mockWindow.AccessLeaseAuth.getAccessToken = async () => {
            const err = new Error('Popup window blocked by browser policy.');
            err.code = 'popup_window_error';
            throw err;
        };

        await assert.rejects(
            async () => {
                await mockWindow.apiClient.listCatalogResources();
            },
            (err) => {
                assert.strictEqual(err.status, 401);
                assert.strictEqual(err.code, 'popup_window_error');
                assert.ok(err.message.includes('Popup window blocked'));
                return true;
            }
        );

        assert.strictEqual(fetchDispatched, false, 'Fetch must never be dispatched when token acquisition throws');
    });

    test('6f. Protected request: empty or invalid Authorization header triggers token acquisition and attaches valid Bearer', async () => {
        let capturedHeaders = null;

        mockWindow.fetch = async (url, options) => {
            capturedHeaders = options.headers;
            return {
                ok: true,
                status: 200,
                headers: new Headers({ 'content-type': 'application/json' }),
                json: async () => ({ success: true, data: [] })
            };
        };

        loadScriptsInContext(mockWindow);
        mockWindow.AccessLeaseAuth.getAccessToken = async () => 'acquired-valid-token-123';

        // Call with empty string Authorization header
        await mockWindow.apiClient.get('/api/catalog/resources', {
            headers: { 'Authorization': '' }
        });

        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer acquired-valid-token-123');

        // Call with 'Bearer ' or 'Bearer null'
        await mockWindow.apiClient.get('/api/catalog/resources', {
            headers: { 'Authorization': 'Bearer null' }
        });

        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer acquired-valid-token-123');
    });

    test('6g. Request workflow convenience methods: propagate Bearer token across all lifecycle operations', async () => {
        let capturedUrl = null;
        let capturedMethod = null;
        let capturedHeaders = null;

        mockWindow.fetch = async (url, options) => {
            capturedUrl = url;
            capturedMethod = options.method;
            capturedHeaders = options.headers;
            return {
                ok: true,
                status: 200,
                headers: new Headers({ 'content-type': 'application/json' }),
                json: async () => ({ success: true, data: {} })
            };
        };

        loadScriptsInContext(mockWindow);
        mockWindow.AccessLeaseAuth.getAccessToken = async () => 'workflow-auth-token';

        // createAccessRequest
        await mockWindow.apiClient.createAccessRequest({ resourceId: 'RES-1' });
        assert.strictEqual(capturedMethod, 'POST');
        assert.strictEqual(capturedUrl, 'https://func-accesslease-dev-krfptp6h5dssa.azurewebsites.net/api/requests');
        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer workflow-auth-token');

        // listAccessRequests
        await mockWindow.apiClient.listAccessRequests({ status: 'PENDING_APPROVAL' });
        assert.strictEqual(capturedMethod, 'GET');
        assert.strictEqual(capturedUrl, 'https://func-accesslease-dev-krfptp6h5dssa.azurewebsites.net/api/requests?status=PENDING_APPROVAL');
        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer workflow-auth-token');

        // getAccessRequest
        await mockWindow.apiClient.getAccessRequest('REQ-001');
        assert.strictEqual(capturedMethod, 'GET');
        assert.strictEqual(capturedUrl, 'https://func-accesslease-dev-krfptp6h5dssa.azurewebsites.net/api/requests/REQ-001');
        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer workflow-auth-token');

        // cancelAccessRequest
        await mockWindow.apiClient.cancelAccessRequest('REQ-001', 'Changed requirements');
        assert.strictEqual(capturedMethod, 'POST');
        assert.strictEqual(capturedUrl, 'https://func-accesslease-dev-krfptp6h5dssa.azurewebsites.net/api/requests/REQ-001/cancel');
        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer workflow-auth-token');

        // listPendingApprovals
        await mockWindow.apiClient.listPendingApprovals();
        assert.strictEqual(capturedMethod, 'GET');
        assert.strictEqual(capturedUrl, 'https://func-accesslease-dev-krfptp6h5dssa.azurewebsites.net/api/approvals/pending');
        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer workflow-auth-token');

        // submitApprovalDecision
        await mockWindow.apiClient.submitApprovalDecision('STEP-001', { decision: 'APPROVE', comments: 'Approved' });
        assert.strictEqual(capturedMethod, 'POST');
        assert.strictEqual(capturedUrl, 'https://func-accesslease-dev-krfptp6h5dssa.azurewebsites.net/api/approvals/STEP-001/decision');
        assert.strictEqual(capturedHeaders.get('Authorization'), 'Bearer workflow-auth-token');
    });
});

describe('Unit: Frontend AuthManager (auth.js)', () => {
    let mockWindow;

    beforeEach(() => {
        mockWindow = createMockEnvironment();
    });

    test('7. Target API Scope: verifies default scope matches verified Entra ID configuration', () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        assert.strictEqual(auth.getApiScope(), EXPECTED_API_SCOPE);
        assert.strictEqual(auth.tokenRequest.scopes[0], EXPECTED_API_SCOPE);
        assert.ok(auth.loginRequest.scopes.includes(EXPECTED_API_SCOPE));
    });

    test('8. getAccessToken: acquires token silently using active account and configured scope', async () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        let requestedScope = null;
        let requestedAccount = null;

        auth.msalInstance = {
            getActiveAccount: () => ({ homeAccountId: 'acc-1', username: 'admin@accesslease.com' }),
            acquireTokenSilent: async (req) => {
                requestedScope = req.scopes[0];
                requestedAccount = req.account;
                return { accessToken: 'silent-acquired-jwt-token' };
            }
        };
        auth.activeAccount = { homeAccountId: 'acc-1', username: 'admin@accesslease.com' };

        const token = await auth.getAccessToken();

        assert.strictEqual(token, 'silent-acquired-jwt-token');
        assert.strictEqual(requestedScope, EXPECTED_API_SCOPE);
        assert.strictEqual(requestedAccount.username, 'admin@accesslease.com');
    });

    test('9. getAccessToken: falls back to acquireTokenPopup when InteractionRequiredAuthError occurs', async () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        let popupCalled = false;
        let popupScope = null;

        auth.msalInstance = {
            getActiveAccount: () => ({ homeAccountId: 'acc-1' }),
            acquireTokenSilent: async () => {
                throw new mockWindow.msal.InteractionRequiredAuthError('Consent required', 'consent_required');
            },
            acquireTokenPopup: async (req) => {
                popupCalled = true;
                popupScope = req.scopes[0];
                return { accessToken: 'interactive-popup-jwt-token', account: { homeAccountId: 'acc-1' } };
            },
            setActiveAccount: () => {}
        };
        auth.activeAccount = { homeAccountId: 'acc-1' };

        const token = await auth.getAccessToken();

        assert.strictEqual(popupCalled, true, 'acquireTokenPopup must be called on InteractionRequiredAuthError');
        assert.strictEqual(token, 'interactive-popup-jwt-token');
        assert.strictEqual(popupScope, EXPECTED_API_SCOPE);
    });

    test('10. getAccessToken: falls back to popup when silent error code is no_tokens_found', async () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        let popupCalled = false;

        auth.msalInstance = {
            getActiveAccount: () => ({ homeAccountId: 'acc-1' }),
            acquireTokenSilent: async () => {
                const err = new Error('No tokens found in cache for scope.');
                err.errorCode = 'no_tokens_found';
                throw err;
            },
            acquireTokenPopup: async () => {
                popupCalled = true;
                return { accessToken: 'popup-token-after-no-tokens-found', account: { homeAccountId: 'acc-1' } };
            },
            setActiveAccount: () => {}
        };
        auth.activeAccount = { homeAccountId: 'acc-1' };

        const token = await auth.getAccessToken();

        assert.strictEqual(popupCalled, true);
        assert.strictEqual(token, 'popup-token-after-no-tokens-found');
    });

    test('11. In-flight token deduplication: concurrent calls share a single promise', async () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        let silentCallCount = 0;

        auth.msalInstance = {
            getActiveAccount: () => ({ homeAccountId: 'acc-1' }),
            acquireTokenSilent: async () => {
                silentCallCount++;
                // Simulate network latency
                await new Promise((res) => setTimeout(res, 20));
                return { accessToken: 'deduped-shared-token' };
            }
        };
        auth.activeAccount = { homeAccountId: 'acc-1' };

        // Launch 4 concurrent token acquisitions
        const [t1, t2, t3, t4] = await Promise.all([
            auth.getAccessToken(),
            auth.getAccessToken(),
            auth.getAccessToken(),
            auth.getAccessToken()
        ]);

        assert.strictEqual(silentCallCount, 1, 'acquireTokenSilent must only be called ONCE for concurrent requests');
        assert.strictEqual(t1, 'deduped-shared-token');
        assert.strictEqual(t2, 'deduped-shared-token');
        assert.strictEqual(t3, 'deduped-shared-token');
        assert.strictEqual(t4, 'deduped-shared-token');
        assert.strictEqual(auth.inFlightTokenPromise, null, 'inFlightTokenPromise must reset to null after completion');
    });

    test('12. Account resolution: restores active account from getActiveAccount or getAllAccounts with tenant validation', async () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        const tenantId = '6e020805-70a1-44ae-a6c4-9f7dbc605905';
        auth.config = { tenantId: tenantId };

        const storedAccount = { homeAccountId: 'recovered-1', tenantId: tenantId, username: 'sponsor@accesslease.com' };
        let activeAccountSet = null;

        auth.msalInstance = {
            getActiveAccount: () => null,
            getAllAccounts: () => [storedAccount],
            setActiveAccount: (acc) => {
                activeAccountSet = acc;
            },
            acquireTokenSilent: async () => ({ accessToken: 'recovered-account-token' })
        };
        auth.activeAccount = null; // Stored account lost in memory

        const token = await auth.getAccessToken();

        assert.strictEqual(token, 'recovered-account-token');
        assert.strictEqual(activeAccountSet.username, 'sponsor@accesslease.com');
        assert.strictEqual(auth.activeAccount.username, 'sponsor@accesslease.com');
    });

    test('13. loadUserProfile: queries /api/auth/me, stores SYSTEM_ADMIN role, and notifies listeners', async () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        const expectedUser = {
            user_id: 'USER-ADMIN-01',
            email: 'admin@accesslease.com',
            display_name: 'AccessLease Administrator',
            user_type: 'EMPLOYEE',
            department: 'Identity Security',
            roles: [
                { role_code: 'SYSTEM_ADMIN', role_name: 'System Administrator' },
                { role_code: 'INTERNAL_SPONSOR', role_name: 'Internal Business Sponsor' }
            ]
        };

        mockWindow.apiClient.get = async (endpoint) => {
            if (endpoint === '/api/auth/me') {
                return {
                    success: true,
                    data: {
                        user: expectedUser,
                        session: { expiresAt: new Date(Date.now() + 3600000).toISOString() }
                    }
                };
            }
            throw new Error(`Unexpected endpoint: ${endpoint}`);
        };

        let listenerNotified = false;
        let notifiedUser = null;
        auth.subscribe((user) => {
            listenerNotified = true;
            notifiedUser = user;
        });

        await auth.loadUserProfile();

        assert.strictEqual(listenerNotified, true);
        assert.strictEqual(notifiedUser.user_id, 'USER-ADMIN-01');
        assert.strictEqual(auth.getUser().display_name, 'AccessLease Administrator');
        assert.ok(auth.getUser().roles.some(r => r.role_code === 'SYSTEM_ADMIN'));
    });

    test('14. loadUserProfile: catches 401/403 and triggers identity rejection banner without crashing', async () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        let rejectionRendered = false;
        auth.renderIdentityRejected = (code, msg) => {
            rejectionRendered = true;
            assert.strictEqual(code, 'ERR_USER_NOT_FOUND');
            assert.ok(msg.includes('not provisioned'));
        };

        mockWindow.apiClient.get = async (endpoint) => {
            if (endpoint === '/api/auth/me') {
                const err = new Error('User not provisioned in database.');
                err.code = 'ERR_USER_NOT_FOUND';
                err.status = 401;
                throw err;
            }
        };

        await auth.loadUserProfile();

        assert.strictEqual(rejectionRendered, true, 'Identity rejection banner must be rendered on 401/403');
    });

    test('15. signOut: clears active user, session, and active account', async () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        auth.currentUser = { user_id: 'USER-1' };
        auth.currentSession = { token: 'active' };
        auth.activeAccount = { homeAccountId: 'acc-1' };
        auth.msalInstance = {
            logoutPopup: async () => {}
        };

        await auth.signOut();

        assert.strictEqual(auth.getUser(), null);
        assert.strictEqual(auth.getSession(), null);
        assert.strictEqual(auth.activeAccount, null);
    });

    test('16. resolveActiveAccount: fails closed and returns null when configured tenantId is missing or empty', () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        const candidate = { homeAccountId: 'user-1', tenantId: '6e020805-70a1-44ae-a6c4-9f7dbc605905', username: 'admin@accesslease.com' };

        // Test with null config
        auth.config = null;
        auth.msalInstance = {
            getActiveAccount: () => null,
            getAllAccounts: () => [candidate],
            setActiveAccount: () => {}
        };
        assert.strictEqual(auth.resolveActiveAccount(), null, 'Must return null when config is null');

        // Test with empty string tenantId
        auth.config = { tenantId: '   ' };
        assert.strictEqual(auth.resolveActiveAccount(), null, 'Must return null when tenantId is empty whitespace');

        // Test with undefined tenantId
        auth.config = { tenantId: undefined };
        assert.strictEqual(auth.resolveActiveAccount(), null, 'Must return null when tenantId is undefined');
    });

    test('17. resolveActiveAccount: returns null when cached account tenantId does not match configured tenant', () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        const configuredTenant = '6e020805-70a1-44ae-a6c4-9f7dbc605905';
        const foreignAccount = {
            homeAccountId: 'user-foreign',
            tenantId: 'unauthorized-foreign-tenant-guid',
            username: 'contractor@external.com'
        };

        auth.config = { tenantId: configuredTenant };
        auth.msalInstance = {
            getActiveAccount: () => null,
            getAllAccounts: () => [foreignAccount],
            setActiveAccount: () => {}
        };

        const resolved = auth.resolveActiveAccount();
        assert.strictEqual(resolved, null, 'Must return null when tenantId does not match configured tenant');
    });

    test('18. resolveActiveAccount: disambiguates when multiple accounts exist and exactly one matches configured tenant', () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        const configuredTenant = '6e020805-70a1-44ae-a6c4-9f7dbc605905';
        const corpAccount = {
            homeAccountId: 'admin.corp',
            tenantId: configuredTenant,
            username: 'admin@accesslease.com'
        };
        const guestAccount = {
            homeAccountId: 'guest.partner',
            tenantId: 'partner-tenant-guid',
            username: 'partner@external.com'
        };

        let activeAccountSet = null;
        auth.config = { tenantId: configuredTenant };
        auth.msalInstance = {
            getActiveAccount: () => null,
            getAllAccounts: () => [guestAccount, corpAccount],
            setActiveAccount: (acc) => {
                activeAccountSet = acc;
            }
        };

        const resolved = auth.resolveActiveAccount();
        assert.strictEqual(resolved, corpAccount, 'Must select the account strictly matching configured tenant');
        assert.strictEqual(activeAccountSet, corpAccount, 'Must re-establish active account in MSAL');
    });

    test('19. resolveActiveAccount: returns null when multiple accounts match the same configured tenant (no arbitrary selection)', () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        const configuredTenant = '6e020805-70a1-44ae-a6c4-9f7dbc605905';
        const account1 = {
            homeAccountId: 'admin1.corp',
            tenantId: configuredTenant,
            username: 'admin1@accesslease.com'
        };
        const account2 = {
            homeAccountId: 'admin2.corp',
            tenantId: configuredTenant,
            username: 'admin2@accesslease.com'
        };

        let activeAccountSet = null;
        auth.config = { tenantId: configuredTenant };
        auth.msalInstance = {
            getActiveAccount: () => null,
            getAllAccounts: () => [account1, account2],
            setActiveAccount: (acc) => {
                activeAccountSet = acc;
            }
        };

        const resolved = auth.resolveActiveAccount();
        assert.strictEqual(resolved, null, 'Must return null when multiple accounts match tenant (interactive selection required)');
        assert.strictEqual(activeAccountSet, null, 'Must not call setActiveAccount when ambiguous');
    });

    test('20. initialize: same-tab session restoration assigns activeAccount and calls loadUserProfile without rendering unauthenticated UI', async () => {
        loadScriptsInContext(mockWindow);
        const auth = mockWindow.AccessLeaseAuth;

        const configuredTenant = '6e020805-70a1-44ae-a6c4-9f7dbc605905';
        const validAccount = {
            homeAccountId: 'user-admin-oid',
            tenantId: configuredTenant,
            username: 'admin@accesslease.com'
        };

        let profileLoaded = false;
        let unauthRendered = false;

        auth.renderLoading = () => {};
        auth.renderError = () => {};
        auth.renderUnauthenticated = () => {
            unauthRendered = true;
        };
        auth.loadUserProfile = async () => {
            profileLoaded = true;
        };

        // Mock backend /api/auth/config response
        mockWindow.apiClient.get = async (endpoint) => {
            if (endpoint === '/api/auth/config') {
                return {
                    data: {
                        configured: true,
                        clientId: '934b724c-19ac-45a7-b463-a2f31a9fa9fb',
                        tenantId: configuredTenant,
                        authority: `https://login.microsoftonline.com/${configuredTenant}`,
                        apiScope: 'api://aa3b2968-201b-4cbf-b650-abc839c2ad4c/access_as_user'
                    }
                };
            }
            throw new Error(`Unexpected endpoint: ${endpoint}`);
        };

        // Mock PCA where getActiveAccount() returns null initially (pointer lost on reload),
        // but getAllAccounts() returns the 1 valid account from sessionStorage.
        let msalActiveAccountSet = null;
        mockWindow.msal.PublicClientApplication = class MockPCA {
            constructor(config) {
                this.config = config;
            }
            async handleRedirectPromise() {
                return null; // Normal for reload after popup login
            }
            getActiveAccount() {
                return msalActiveAccountSet;
            }
            getAllAccounts() {
                return [validAccount];
            }
            setActiveAccount(acc) {
                msalActiveAccountSet = acc;
            }
        };

        await auth.initialize();

        assert.strictEqual(unauthRendered, false, 'renderUnauthenticated() must NOT be called on successful account recovery');
        assert.strictEqual(profileLoaded, true, 'loadUserProfile() must be called to restore profile');
        assert.deepStrictEqual(auth.activeAccount, validAccount, 'this.activeAccount must be assigned the resolved account before UI decision');
        assert.deepStrictEqual(msalActiveAccountSet, validAccount, 'msalInstance.setActiveAccount() must be synchronized');
    });
});
