/**
 * AccessLease — Centralized API Client Module
 * Target: Vanilla JavaScript (ES6+)
 * 
 * Responsibilities:
 * - Centralized HTTP client for all frontend API communication.
 * - Dynamic base URL resolution (defaults to current origin, supports custom override).
 * - Automatic Authorization Bearer token attachment via window.AccessLeaseAuth.
 * - Standardized request/response error handling and JSON serialization.
 * - Zero external framework dependencies.
 */

(function (window) {
    'use strict';

    class ApiClient {
        constructor() {
            // Priority: explicit window override, otherwise window.location.origin
            this.baseUrl = (window.ACCESSLEASE_API_URL || window.location.origin).replace(/\/+$/, '');
        }

        /**
         * Sets or updates the base URL for API requests.
         * @param {string} url 
         */
        setBaseUrl(url) {
            if (url && typeof url === 'string') {
                this.baseUrl = url.replace(/\/+$/, '');
            }
        }

        /**
         * Checks if the given endpoint is a public endpoint that does not require authentication.
         * Normalizes paths with or without leading slashes and handles case-insensitivity.
         * @param {string} endpoint
         * @returns {boolean}
         */
        isPublicEndpoint(endpoint) {
            if (!endpoint || typeof endpoint !== 'string') return false;
            const urlPath = endpoint.startsWith('http')
                ? new URL(endpoint).pathname
                : endpoint.split('?')[0];
            const cleanPath = urlPath.startsWith('/') ? urlPath : `/${urlPath}`;
            const normalized = cleanPath.toLowerCase().replace(/\/+$/, '') || '/';
            const publicEndpoints = [
                '/api/auth/config',
                '/api/health',
                '/api/health/db'
            ];
            if (publicEndpoints.includes(normalized)) {
                return true;
            }
            // Non-API endpoints (e.g. static assets, index.html) do not require Bearer token
            if (!normalized.startsWith('/api/')) {
                return true;
            }
            return false;
        }

        /**
         * Retrieves the current active access token from the authentication manager if available.
         * Throws explicit error on token acquisition failures rather than silently swallowing.
         * @returns {Promise<string|null>}
         */
        async getAuthToken() {
            if (window.AccessLeaseAuth && typeof window.AccessLeaseAuth.getAccessToken === 'function') {
                try {
                    const token = await window.AccessLeaseAuth.getAccessToken();
                    if (!token || typeof token !== 'string' || token.trim().length === 0) {
                        return null;
                    }
                    return token.trim();
                } catch (err) {
                    console.error('[ApiClient] Failed to acquire access token:', err.message || err);
                    const authErr = new Error(`Authentication token acquisition failed: ${err.message || err}`);
                    authErr.code = err.code || 'ERR_TOKEN_ACQUISITION_FAILED';
                    authErr.status = 401;
                    authErr.cause = err;
                    throw authErr;
                }
            }
            return null;
        }

        /**
         * Core request dispatcher with automatic headers, token injection, and error formatting.
         * @param {string} endpoint Relative or absolute path (e.g. '/api/health')
         * @param {object} [options={}] Fetch options
         * @returns {Promise<object>} Parsed canonical JSON response { success, data, meta }
         */
        async request(endpoint, options = {}) {
            const path = endpoint.startsWith('http') ? endpoint : `${this.baseUrl}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;
            const headers = new Headers(options.headers || {});

            if (!headers.has('Accept')) {
                headers.set('Accept', 'application/json');
            }

            const isPublic = this.isPublicEndpoint(endpoint);

            // Automatically attach Bearer token on protected endpoints if not explicitly provided or invalid
            const existingAuth = headers.get('Authorization');
            const hasExplicitValidAuth = existingAuth && typeof existingAuth === 'string' && existingAuth.trim().length > 0 && existingAuth.trim() !== 'Bearer' && existingAuth.trim() !== 'Bearer null' && existingAuth.trim() !== 'Bearer undefined';

            if (!hasExplicitValidAuth) {
                if (!isPublic) {
                    const token = await this.getAuthToken();
                    if (token && typeof token === 'string' && token.trim().length > 0) {
                        headers.set('Authorization', `Bearer ${token.trim()}`);
                    } else {
                        const unauthErr = new Error('Authentication required. Please sign in to access this resource.');
                        unauthErr.code = 'ERR_UNAUTHORIZED';
                        unauthErr.status = 401;
                        throw unauthErr;
                    }
                }
            }

            // Set Content-Type for requests with body
            if (options.body && typeof options.body === 'object' && !(typeof FormData !== 'undefined' && options.body instanceof FormData)) {
                headers.set('Content-Type', 'application/json');
                options.body = JSON.stringify(options.body);
            }

            const fetchOptions = {
                ...options,
                headers
            };

            let response;
            try {
                response = await fetch(path, fetchOptions);
            } catch (networkErr) {
                const err = new Error(`Network failure connecting to ${path}: ${networkErr.message}`);
                err.code = 'ERR_NETWORK_FAILURE';
                err.status = 0;
                throw err;
            }

            let responseBody = null;
            const contentType = response.headers.get('content-type') || '';
            if (contentType.includes('application/json')) {
                try {
                    responseBody = await response.json();
                } catch {
                    responseBody = null;
                }
            } else {
                const text = await response.text();
                responseBody = { rawText: text };
            }

            if (!response.ok) {
                const errorCode = responseBody?.error?.code || `HTTP_${response.status}`;
                const errorMessage = responseBody?.error?.message || response.statusText || 'An API error occurred.';
                const errorDetails = responseBody?.error?.details || [];

                const apiError = new Error(errorMessage);
                apiError.code = errorCode;
                apiError.status = response.status;
                apiError.details = errorDetails;
                apiError.response = responseBody;
                throw apiError;
            }

            return responseBody;
        }

        /**
         * HTTP GET convenience method
         * @param {string} endpoint 
         * @param {object} [options={}] 
         * @returns {Promise<object>}
         */
        async get(endpoint, options = {}) {
            return this.request(endpoint, { ...options, method: 'GET' });
        }

        /**
         * HTTP POST convenience method
         * @param {string} endpoint 
         * @param {any} body 
         * @param {object} [options={}] 
         * @returns {Promise<object>}
         */
        async post(endpoint, body, options = {}) {
            return this.request(endpoint, { ...options, method: 'POST', body });
        }

        /**
         * HTTP PUT convenience method
         * @param {string} endpoint 
         * @param {any} body 
         * @param {object} [options={}] 
         * @returns {Promise<object>}
         */
        async put(endpoint, body, options = {}) {
            return this.request(endpoint, { ...options, method: 'PUT', body });
        }

        /**
         * HTTP DELETE convenience method
         * @param {string} endpoint 
         * @param {object} [options={}] 
         * @returns {Promise<object>}
         */
        async delete(endpoint, options = {}) {
            return this.request(endpoint, { ...options, method: 'DELETE' });
        }

        // ---------------------------------------------------------------------
        // Provisioning & Connector API Convenience Methods
        // ---------------------------------------------------------------------
        async getGitHubStatus() {
            return this.get('/api/connectors/github/status');
        }

        async getGitHubConfiguration() {
            return this.get('/api/connectors/github/configuration');
        }

        async startProvisioning(requestId) {
            return this.post(`/api/provisioning/requests/${requestId}/start`, {});
        }

        async getProvisioningState(requestId) {
            return this.get(`/api/provisioning/requests/${requestId}`);
        }

        async listProvisioningJobs(params = {}) {
            const search = new URLSearchParams(params).toString();
            return this.get(`/api/provisioning/jobs${search ? '?' + search : ''}`);
        }

        async listGrants(params = {}) {
            const search = new URLSearchParams(params).toString();
            return this.get(`/api/provisioning/grants${search ? '?' + search : ''}`);
        }

        async retryProvisioningJob(jobId) {
            return this.post(`/api/provisioning/jobs/${jobId}/retry`, {});
        }

        // ---------------------------------------------------------------------
        // Access Request & Catalog Governance API Convenience Methods
        // ---------------------------------------------------------------------
        async listCatalogResources(params = {}) {
            const query = new URLSearchParams();
            for (const [k, v] of Object.entries(params)) {
                if (v !== undefined && v !== null && v !== '') {
                    query.set(k, String(v));
                }
            }
            const qStr = query.toString();
            return this.get(`/api/catalog/resources${qStr ? '?' + qStr : ''}`);
        }

        async getCatalogResource(resourceId) {
            if (!resourceId) throw new Error('Resource ID is required.');
            return this.get(`/api/catalog/resources/${encodeURIComponent(resourceId)}`);
        }

        async createCatalogResource(payload) {
            return this.post('/api/catalog/resources', payload);
        }

        async updateCatalogResource(resourceId, payload) {
            if (!resourceId) throw new Error('Resource ID is required.');
            return this.put(`/api/catalog/resources/${encodeURIComponent(resourceId)}`, payload);
        }

        async setCatalogResourceStatus(resourceId, isActive) {
            if (!resourceId) throw new Error('Resource ID is required.');
            return this.patch(`/api/catalog/resources/${encodeURIComponent(resourceId)}/status`, { isActive });
        }

        async assignCatalogResourceOwner(resourceId, payload) {
            if (!resourceId) throw new Error('Resource ID is required.');
            return this.post(`/api/catalog/resources/${encodeURIComponent(resourceId)}/owners`, payload);
        }

        async removeCatalogResourceOwner(resourceId, ownerUserId) {
            if (!resourceId || !ownerUserId) throw new Error('Resource ID and Owner User ID are required.');
            return this.delete(`/api/catalog/resources/${encodeURIComponent(resourceId)}/owners/${encodeURIComponent(ownerUserId)}`);
        }

        async listResourceEntitlements(resourceId, params = {}) {
            if (!resourceId) throw new Error('Resource ID is required to fetch entitlements.');
            const query = new URLSearchParams();
            for (const [k, v] of Object.entries(params)) {
                if (v !== undefined && v !== null && v !== '') {
                    query.set(k, String(v));
                }
            }
            const qStr = query.toString();
            return this.get(`/api/catalog/resources/${encodeURIComponent(resourceId)}/entitlements${qStr ? '?' + qStr : ''}`);
        }

        async createResourceEntitlement(resourceId, payload) {
            if (!resourceId) throw new Error('Resource ID is required.');
            return this.post(`/api/catalog/resources/${encodeURIComponent(resourceId)}/entitlements`, payload);
        }

        async updateResourceEntitlement(entitlementId, payload) {
            if (!entitlementId) throw new Error('Entitlement ID is required.');
            return this.put(`/api/catalog/entitlements/${encodeURIComponent(entitlementId)}`, payload);
        }

        async setResourceEntitlementStatus(entitlementId, isActive) {
            if (!entitlementId) throw new Error('Entitlement ID is required.');
            return this.patch(`/api/catalog/entitlements/${encodeURIComponent(entitlementId)}/status`, { isActive });
        }

        async createAccessRequest(payload) {
            return this.post('/api/requests', payload);
        }

        async listAccessRequests(params = {}) {
            const search = new URLSearchParams(params).toString();
            return this.get(`/api/requests${search ? '?' + search : ''}`);
        }

        async getAccessRequest(requestId) {
            if (!requestId) throw new Error('Request ID is required.');
            return this.get(`/api/requests/${encodeURIComponent(requestId)}`);
        }

        async cancelAccessRequest(requestId, reason = 'Cancelled by requester.') {
            if (!requestId) throw new Error('Request ID is required.');
            return this.post(`/api/requests/${encodeURIComponent(requestId)}/cancel`, { reason });
        }

        async listPendingApprovals() {
            return this.get('/api/approvals/pending');
        }

        async submitApprovalDecision(stepId, decisionPayload) {
            if (!stepId) throw new Error('Approval step ID is required.');
            return this.post(`/api/approvals/${encodeURIComponent(stepId)}/decision`, decisionPayload);
        }
    }

    // Export singleton instance
    window.AccessLeaseApiClient = ApiClient;
    window.apiClient = new ApiClient();

})(window);

