/**
 * AccessLease — Centralized Microsoft Entra ID Authentication Module
 * 
 * Rules:
 * - Pure Vanilla JavaScript (ES6+)
 * - Zero frontend frameworks (No React, Angular, Vue, Next.js)
 * - Microsoft Entra ID with OAuth 2.0 PKCE via MSAL Browser
 * - The same authentication architecture runs on localhost and production
 * - Zero fake/fabricated authentication bypasses
 * - Transparent configuration error handling when Entra credentials are not configured
 */

(function (window) {
    'use strict';

    const DEFAULT_API_SCOPE = 'api://aa3b2968-201b-4cbf-b650-abc839c2ad4c/access_as_user';

    class AuthManager {
        constructor() {
            this.msalInstance = null;
            this.config = null;
            this.currentUser = null;
            this.currentSession = null;
            this.activeAccount = null;
            this.authListeners = [];
            this.inFlightTokenPromise = null;
            this.isInteracting = false;

            this.loginRequest = {
                scopes: ['openid', 'profile', 'email', DEFAULT_API_SCOPE]
            };
            this.tokenRequest = {
                scopes: [DEFAULT_API_SCOPE]
            };
        }

        /**
         * Returns the target backend API scope.
         * @returns {string}
         */
        getApiScope() {
            return (this.config && this.config.apiScope) ? this.config.apiScope : DEFAULT_API_SCOPE;
        }

        /**
         * Resolves the active account from cache or existing accounts.
         * Validates AccountInfo.tenantId against the configured AccessLease tenant.
         * Fails closed: missing tenant configuration returns null.
         * If exactly one account matches, re-establishes it in MSAL and returns it.
         * If zero or multiple accounts match, returns null to avoid privilege confusion.
         * @returns {object|null}
         */
        resolveActiveAccount() {
            if (!this.msalInstance) return null;
            try {
                const targetTenantId = (this.config && typeof this.config.tenantId === 'string')
                    ? this.config.tenantId.trim()
                    : '';

                // Fail-closed: Cannot validate tenancy without configured tenant ID
                if (!targetTenantId) {
                    console.warn('[AuthManager] Configured tenantId is missing or empty. Cannot validate account tenant.');
                    return null;
                }

                let active = this.msalInstance.getActiveAccount();
                if (active) {
                    if (active.tenantId === targetTenantId) {
                        return active;
                    }
                    console.warn('[AuthManager] Active account tenant mismatch. Clearing active pointer.');
                    active = null;
                }

                const accounts = this.msalInstance.getAllAccounts();
                if (!accounts || accounts.length === 0) {
                    return null;
                }

                // Filter strictly by exact tenantId equality (no homeAccountId inference)
                const matchingAccounts = accounts.filter(a => a && a.tenantId === targetTenantId);

                if (matchingAccounts.length === 1) {
                    const selected = matchingAccounts[0];
                    this.msalInstance.setActiveAccount(selected);
                    return selected;
                }

                if (matchingAccounts.length > 1) {
                    console.warn('[AuthManager] Multiple accounts found matching configured tenant; requiring explicit selection.');
                    return null;
                }

                return null;
            } catch (e) {
                console.warn('[AuthManager] Error resolving active account:', e);
            }
            return null;
        }

        /**
         * Determines if an error returned by MSAL requires interactive authentication.
         * @param {Error|object} err
         * @returns {boolean}
         */
        isInteractionRequiredError(err) {
            if (!err) return false;
            if (window.msal?.InteractionRequiredAuthError && err instanceof window.msal.InteractionRequiredAuthError) {
                return true;
            }
            if (err.name === 'InteractionRequiredAuthError') {
                return true;
            }
            const code = String(err.errorCode || err.code || '').toLowerCase();
            const msg = String(err.message || err.errorMessage || '').toLowerCase();
            const interactionCodes = [
                'interaction_required',
                'consent_required',
                'login_required',
                'no_tokens_found',
                'invalid_grant',
                'user_null'
            ];
            return interactionCodes.some(c => code.includes(c) || msg.includes(c));
        }

        /**
         * Subscribes a listener function to authentication state changes.
         * @param {Function} callback (user, session) => void
         */
        onAuthStateChanged(callback) {
            if (typeof callback === 'function') {
                this.authListeners.push(callback);
                // Immediately notify if user is already resolved
                if (this.currentUser) {
                    try {
                        callback(this.currentUser, this.currentSession);
                    } catch (e) {
                        console.error('[AuthManager] Listener error:', e);
                    }
                }
            }
        }

        /**
         * Alias for onAuthStateChanged.
         * @param {Function} callback (user, session) => void
         */
        subscribe(callback) {
            return this.onAuthStateChanged(callback);
        }

        /**
         * Dispatches authentication state change to all registered listeners.
         */
        notifyListeners() {
            for (const listener of this.authListeners) {
                try {
                    listener(this.currentUser, this.currentSession);
                } catch (e) {
                    console.error('[AuthManager] Listener error:', e);
                }
            }
        }

        /**
         * Returns the current resolved user profile from dbo.users.
         * @returns {object|null}
         */
        getUser() {
            return this.currentUser;
        }

        /**
         * Returns the current session metadata.
         * @returns {object|null}
         */
        getSession() {
            return this.currentSession;
        }

        /**
         * Returns whether a verified user session is currently active.
         * @returns {boolean}
         */
        isAuthenticated() {
            return Boolean(this.currentUser && this.activeAccount);
        }

        /**
         * Returns the public configuration object.
         * @returns {object|null}
         */
        getConfig() {
            return this.config;
        }

        /**
         * Initializes the authentication subsystem by querying /api/auth/config.
         */
        async initialize() {
            try {
                this.renderLoading(true);

                // 1. Fetch public authentication configuration from backend API
                const res = await window.apiClient.get('/api/auth/config');
                this.config = res.data;

                // 2. Validate whether real Entra configuration is provided
                if (!this.config || !this.config.configured) {
                    console.warn('[AccessLease Auth] Microsoft Entra ID is not configured.');
                    this.renderConfigNotice(this.config ? this.config.missingConfiguration : ['Entra ID Credentials']);
                    return;
                }

                // 3. Update token request with verified API scope
                const apiScope = this.getApiScope();
                this.tokenRequest.scopes = [apiScope];
                this.loginRequest.scopes = ['openid', 'profile', 'email', apiScope];

                // 4. Verify MSAL Browser library availability from CDN
                if (typeof window.msal === 'undefined') {
                    this.renderError('Microsoft Authentication Library (MSAL Browser) is not loaded.');
                    return;
                }

                // 5. Configure MSAL Browser instance
                const redirectUri = this.config.redirectUri || window.location.origin;
                const msalConfig = {
                    auth: {
                        clientId: this.config.clientId,
                        authority: this.config.authority,
                        redirectUri: redirectUri,
                        postLogoutRedirectUri: redirectUri
                    },
                    cache: {
                        cacheLocation: 'sessionStorage',
                        storeAuthStateInCookie: false
                    },
                    system: {
                        loggerOptions: {
                            loggerCallback: (level, message, containsPii) => {
                                if (containsPii) return;
                            },
                            logLevel: window.msal.LogLevel ? window.msal.LogLevel.Warning : 2
                        }
                    }
                };

                this.msalInstance = new window.msal.PublicClientApplication(msalConfig);

                // Handle incoming redirect response if returning from Microsoft login
                const redirectResponse = await this.msalInstance.handleRedirectPromise();
                if (redirectResponse && redirectResponse.account) {
                    this.activeAccount = redirectResponse.account;
                    this.msalInstance.setActiveAccount(this.activeAccount);
                } else {
                    const account = this.resolveActiveAccount();
                    if (account) {
                        this.activeAccount = account;
                        this.msalInstance.setActiveAccount(this.activeAccount);
                    }
                }

                // If user has an active Entra session, acquire access token and load profile
                if (this.activeAccount) {
                    await this.loadUserProfile();
                } else {
                    this.renderUnauthenticated();
                }
            } catch (err) {
                console.error('[AuthManager] Initialization failed:', err);
                this.renderError(`Authentication initialization failed: ${err.message}`);
            } finally {
                this.renderLoading(false);
            }
        }

        /**
         * Triggers interactive sign-in using MSAL Popup flow.
         */
        async signIn() {
            try {
                this.renderLoading(true);
                if (!this.msalInstance) {
                    throw new Error('MSAL instance is not initialized. Please ensure Entra ID configuration is set.');
                }

                const apiScope = this.getApiScope();
                const request = {
                    scopes: ['openid', 'profile', 'email', apiScope]
                };

                const loginResponse = await this.msalInstance.loginPopup(request);
                if (loginResponse && loginResponse.account) {
                    this.activeAccount = loginResponse.account;
                    this.msalInstance.setActiveAccount(this.activeAccount);
                    await this.loadUserProfile();
                }
            } catch (err) {
                console.error('[AuthManager] Sign in failed:', err);
                if (err.errorCode !== 'user_cancelled') {
                    this.renderError(`Sign in failed: ${err.message}`);
                }
            } finally {
                this.renderLoading(false);
            }
        }

        /**
         * Signs out the active account and clears session state.
         */
        async signOut() {
            try {
                this.renderLoading(true);
                this.currentUser = null;
                this.currentSession = null;
                this.notifyListeners();

                if (this.msalInstance && this.activeAccount) {
                    const logoutRequest = {
                        account: this.activeAccount,
                        postLogoutRedirectUri: this.config?.redirectUri || window.location.origin
                    };
                    try {
                        await this.msalInstance.logoutPopup(logoutRequest);
                    } catch (popupErr) {
                        if (popupErr.errorCode === 'popup_window_error') {
                            await this.msalInstance.logoutRedirect(logoutRequest);
                            return;
                        }
                        console.warn('[AuthManager] Popup logout warning:', popupErr.message);
                    }
                }
                this.activeAccount = null;
                this.renderUnauthenticated();
            } catch (err) {
                console.error('[AuthManager] Sign out error:', err);
                window.location.reload();
            } finally {
                this.renderLoading(false);
            }
        }

        /**
         * Acquires a valid Bearer access token for the backend API.
         * Tries silent acquisition first; falls back to popup if required.
         * De-duplicates concurrent in-flight requests.
         * @returns {Promise<string|null>}
         */
        async getAccessToken() {
            if (!this.msalInstance) {
                return null;
            }

            let account = this.activeAccount;
            if (!account) {
                account = this.resolveActiveAccount();
                if (account) {
                    this.activeAccount = account;
                    this.msalInstance.setActiveAccount(account);
                }
            }

            if (!account) {
                return null;
            }

            // De-duplicate concurrent token requests
            if (this.inFlightTokenPromise) {
                return this.inFlightTokenPromise;
            }

            this.inFlightTokenPromise = this._acquireTokenInternal(account).finally(() => {
                this.inFlightTokenPromise = null;
            });

            return this.inFlightTokenPromise;
        }

        /**
         * Internal token acquisition worker handling silent cache lookup with interactive fallback.
         * @private
         * @param {object} account MSAL AccountInfo
         * @returns {Promise<string|null>}
         */
        async _acquireTokenInternal(account) {
            const apiScope = this.getApiScope();
            const request = {
                scopes: [apiScope],
                account: account
            };

            try {
                const response = await this.msalInstance.acquireTokenSilent(request);
                if (response && response.accessToken) {
                    return response.accessToken;
                }
            } catch (silentErr) {
                console.warn('[AuthManager] Silent token acquisition failed:', silentErr.message || silentErr);

                if (this.isInteractionRequiredError(silentErr)) {
                    if (this.isInteracting) {
                        return null;
                    }
                    try {
                        this.isInteracting = true;
                        const popupRes = await this.msalInstance.acquireTokenPopup(request);
                        if (popupRes && popupRes.accessToken) {
                            if (popupRes.account) {
                                this.activeAccount = popupRes.account;
                                this.msalInstance.setActiveAccount(this.activeAccount);
                            }
                            return popupRes.accessToken;
                        }
                    } catch (popupErr) {
                        console.error('[AuthManager] Interactive token acquisition failed:', popupErr.message || popupErr);
                        if (popupErr.errorCode === 'user_cancelled') {
                            return null;
                        }
                        throw popupErr;
                    } finally {
                        this.isInteracting = false;
                    }
                } else {
                    throw silentErr;
                }
            }
            return null;
        }

        /**
         * Calls the protected GET /api/auth/me endpoint using the acquired Bearer token.
         */
        async loadUserProfile() {
            try {
                let resData;
                try {
                    resData = await window.apiClient.get('/api/auth/me');
                } catch (apiErr) {
                    if (apiErr.status === 401 || apiErr.status === 403) {
                        const code = apiErr.code || 'ERR_UNAUTHORIZED';
                        const msg = apiErr.message || 'Access denied.';
                        this.renderIdentityRejected(code, msg);
                        return;
                    }
                    throw apiErr;
                }

                if (!resData || !resData.data || !resData.data.user) {
                    throw new Error('Malformed user profile response received from server.');
                }

                this.currentUser = resData.data.user;
                this.currentSession = resData.data.session;
                this.notifyListeners();
                this.renderAuthenticated(this.currentUser, this.currentSession);
            } catch (err) {
                console.error('[AuthManager] Failed to load profile:', err);
                this.renderError(`Failed to load user profile: ${err.message}`);
            }
        }

        // -------------------------------------------------------------------------
        // DOM Rendering Helpers (Pure Vanilla JavaScript)
        // -------------------------------------------------------------------------

        renderLoading(isLoading) {
            const spinner = document.getElementById('auth-loading-indicator');
            if (spinner) {
                spinner.style.display = isLoading ? 'inline-block' : 'none';
            }
        }

        renderUnauthenticated() {
            const authCard = document.getElementById('auth-status-container');
            if (!authCard) return;

            authCard.innerHTML = `
                <div class="auth-box auth-box-unauth">
                    <div class="auth-header-row">
                        <span class="auth-badge auth-badge-pending">Not Authenticated</span>
                        <span class="auth-provider-pill">Microsoft Entra ID</span>
                    </div>
                    <h3>Sign In to AccessLease</h3>
                    <p class="auth-desc">
                        Authenticate with your corporate Microsoft Entra ID account to access contractor leases,
                        sponsorship governance workflows, and entitlement review dashboards.
                    </p>
                    <div class="auth-actions">
                        <button id="btn-login" class="btn btn-primary" type="button">
                            <svg class="ms-icon" viewBox="0 0 21 21" width="18" height="18" aria-hidden="true">
                                <rect x="1" y="1" width="9" height="9" fill="#f25022"/>
                                <rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
                                <rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
                                <rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
                            </svg>
                            Sign In with Microsoft
                        </button>
                    </div>
                </div>
            `;

            const btnLogin = document.getElementById('btn-login');
            if (btnLogin) {
                btnLogin.addEventListener('click', () => this.signIn());
            }

            // Also hide authenticated shell view if present
            const shellView = document.getElementById('authenticated-shell-view');
            if (shellView) {
                shellView.style.display = 'none';
            }
        }

        renderAuthenticated(user, session) {
            const authCard = document.getElementById('auth-status-container');
            if (authCard) {
                authCard.innerHTML = ''; // Replaced by the full authenticated workspace
            }

            const shellView = document.getElementById('authenticated-shell-view');
            if (shellView) {
                shellView.style.display = 'block';
            }

            // Populate user details in workspace
            const nameEl = document.getElementById('shell-user-name');
            const emailEl = document.getElementById('shell-user-email');
            const typeEl = document.getElementById('shell-user-type');
            const uidEl = document.getElementById('shell-user-id');
            const oidEl = document.getElementById('shell-user-oid');
            const deptEl = document.getElementById('shell-user-dept');
            const rolesEl = document.getElementById('shell-user-roles');

            if (nameEl) nameEl.textContent = user.display_name || user.email;
            if (emailEl) emailEl.textContent = user.email;
            if (typeEl) {
                typeEl.textContent = user.user_type;
                typeEl.className = `user-type-tag ${user.user_type === 'CONTRACTOR' ? 'badge-contractor' : 'badge-employee'}`;
            }
            if (uidEl) uidEl.textContent = user.user_id;
            if (oidEl) oidEl.textContent = user.entra_object_id;
            if (deptEl) deptEl.textContent = user.department || 'Not Assigned';

            if (rolesEl) {
                if (user.roles && user.roles.length > 0) {
                    rolesEl.innerHTML = user.roles.map(r => 
                        `<span class="role-chip">${this.escapeHtml(r.role_name || r.role_code || r)}</span>`
                    ).join('');
                } else {
                    rolesEl.innerHTML = '<span class="role-chip role-chip-empty">Standard User (No Elevated Roles)</span>';
                }
            }

            // Update top header profile pill
            const headerProfile = document.getElementById('header-user-profile');
            if (headerProfile) {
                headerProfile.style.display = 'flex';
                const avatar = document.getElementById('header-user-avatar');
                const headerName = document.getElementById('header-user-name');
                const headerRole = headerProfile.querySelector('.header-user-role');
                if (avatar) {
                    const initials = (user.first_name ? user.first_name[0] : 'U') + (user.last_name ? user.last_name[0] : '');
                    avatar.textContent = initials.toUpperCase();
                }
                if (headerName) {
                    headerName.textContent = user.display_name || user.email;
                }
                if (headerRole) {
                    const rolesList = Array.isArray(user.roles) ? user.roles : [];
                    headerRole.textContent = rolesList.length > 0
                        ? rolesList.map(r => r.role_name || r.role_code || r).join(', ')
                        : 'Standard User';
                }
            }

            // Toggle admin-only navigation links (e.g. User Management)
            const hasAdmin = user.roles && user.roles.some(r => (r.role_code || r) === 'SYSTEM_ADMIN');
            const navUsers = document.getElementById('nav-link-users');
            if (navUsers) {
                navUsers.style.display = hasAdmin ? 'flex' : 'none';
            }
        }

        renderIdentityRejected(code, message) {
            const authCard = document.getElementById('auth-status-container');
            if (!authCard) return;

            const shellView = document.getElementById('authenticated-shell-view');
            if (shellView) {
                shellView.style.display = 'none';
            }

            const headerProfile = document.getElementById('header-user-profile');
            if (headerProfile) {
                headerProfile.style.display = 'none';
            }

            authCard.innerHTML = `
                <div class="auth-box auth-box-rejected">
                    <div class="auth-header-row">
                        <span class="auth-badge auth-badge-rejected">Access Denied</span>
                        <span class="auth-provider-pill">Identity Unmapped</span>
                    </div>
                    <h3>Account Not Registered in Governance Database</h3>
                    <p class="auth-desc">
                        Your corporate Microsoft account was successfully authenticated with Microsoft Entra ID.
                        However, your Entra Object ID is not mapped to an active record in the AccessLease <code>dbo.users</code> table.
                    </p>
                    <div class="error-banner">
                        <strong>${this.escapeHtml(code)}:</strong> ${this.escapeHtml(message)}
                    </div>
                    <div class="setup-instructions">
                        <h4>Remediation Steps:</h4>
                        <ol>
                            <li>Contact your AccessLease Security Administrator or Identity Sponsor.</li>
                            <li>Provide your Microsoft Entra Object ID (OID) for provisioning in <code>dbo.users</code>.</li>
                            <li>Once provisioned and assigned appropriate governance roles, click below to retry.</li>
                        </ol>
                    </div>
                    <div class="auth-actions">
                        <button id="btn-retry" class="btn btn-secondary" type="button">Sign Out and Retry</button>
                    </div>
                </div>
            `;

            const btnRetry = document.getElementById('btn-retry');
            if (btnRetry) {
                btnRetry.addEventListener('click', () => this.signOut());
            }
        }

        renderConfigNotice(missingFields) {
            const authCard = document.getElementById('auth-status-container');
            if (!authCard) return;

            const shellView = document.getElementById('authenticated-shell-view');
            if (shellView) {
                shellView.style.display = 'none';
            }

            const fieldsList = missingFields.map(f => `<li><code>${this.escapeHtml(f)}</code></li>`).join('');

            authCard.innerHTML = `
                <div class="auth-box auth-box-notice">
                    <div class="auth-header-row">
                        <span class="auth-badge auth-badge-notice">Entra ID Setup Required</span>
                        <span class="auth-provider-pill">Production-Ready Architecture</span>
                    </div>
                    <h3>Microsoft Entra ID App Registration Required</h3>
                    <p class="auth-desc">
                        AccessLease enforces real enterprise cloud identity governance using 
                        <strong>Microsoft Entra ID</strong> (OAuth 2.0 Authorization Code Flow with PKCE).
                        No mock or fabricated authentication bypasses are permitted.
                    </p>
                    <div class="setup-instructions">
                        <h4>Missing Configuration Parameters:</h4>
                        <ul>${fieldsList}</ul>
                        <h4 style="margin-top: 12px;">Dual App Registration Configuration Instructions:</h4>
                        <ol>
                            <li><strong>Backend Web API Registration:</strong> Name: <code>AccessLease Governance Platform</code>, App ID URI: <code>api://&lt;API_CLIENT_ID&gt;</code>, Scope: <code>access_as_user</code>.</li>
                            <li><strong>Frontend SPA Registration:</strong> Name: <code>AccessLease Governance Platform - SPA</code>, Platform: <strong>Single-page application (SPA)</strong>, Redirect URI: <code>http://localhost:7071/</code>.</li>
                            <li>Configure the following keys in <code>backend/.env</code>:
                                <pre><code>ENTRA_TENANT_ID=&lt;your-azure-tenant-guid&gt;
ENTRA_SPA_CLIENT_ID=&lt;your-spa-client-guid&gt;
ENTRA_API_CLIENT_ID=&lt;your-api-client-guid&gt;
ENTRA_API_AUDIENCE=api://&lt;your-api-client-guid&gt;
ENTRA_API_SCOPE=api://&lt;your-api-client-guid&gt;/access_as_user
ENTRA_REDIRECT_URI=http://localhost:7071/</code></pre>
                            </li>
                            <li>Restart the server (<code>npm start</code>) and reload this page.</li>
                        </ol>
                    </div>
                    <div class="auth-actions">
                        <button class="btn btn-secondary btn-sm" onclick="window.location.reload()">Check Configuration Again</button>
                    </div>
                </div>
            `;
        }

        renderError(message) {
            const authCard = document.getElementById('auth-status-container');
            if (!authCard) return;

            authCard.innerHTML = `
                <div class="auth-box auth-box-error">
                    <span class="auth-badge auth-badge-rejected">Authentication Error</span>
                    <h3>Initialization Error</h3>
                    <p class="error-message">${this.escapeHtml(message)}</p>
                    <button class="btn btn-secondary btn-sm" onclick="window.location.reload()">Reload Application</button>
                </div>
            `;
        }

        escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }
    }

    // Export singleton instance to window
    window.AccessLeaseAuth = new AuthManager();

})(window);
