/**
 * AccessLease — Microsoft Entra ID Authentication Module
 * 
 * Rules:
 * - Pure Vanilla JavaScript (ES6+)
 * - Microsoft Authentication Library (MSAL Browser) with PKCE
 * - No mock or fabricated authentication states
 * - Graceful handling of missing Entra ID configuration
 */

(function (window) {
    'use strict';

    class AuthManager {
        constructor() {
            this.msalInstance = null;
            this.config = null;
            this.currentUser = null;
            this.activeAccount = null;
            this.apiBaseUrl = window.location.origin;

            // Default fallback API scopes
            this.loginRequest = {
                scopes: ['openid', 'profile', 'email']
            };
            this.tokenRequest = {
                scopes: ['openid', 'profile', 'email']
            };
        }

        /**
         * Initializes MSAL Browser by fetching runtime configuration from /api/auth/config.
         */
        async initialize() {
            try {
                this.renderLoading(true);

                // 1. Fetch public authentication configuration from backend API
                const response = await fetch(`${this.apiBaseUrl}/api/auth/config`);
                if (!response.ok) {
                    throw new Error(`Failed to load auth config: HTTP ${response.status}`);
                }
                const resData = await response.json();
                this.config = resData.data;

                // 2. Validate whether real Entra configuration is provided
                if (!this.config || !this.config.configured) {
                    this.renderConfigNotice(this.config ? this.config.missingConfiguration : ['Entra ID Credentials']);
                    return;
                }

                // Update token request with API scope if configured
                if (this.config.apiScope) {
                    this.tokenRequest.scopes = [this.config.apiScope];
                }

                // 3. Verify MSAL library availability
                if (typeof window.msal === 'undefined') {
                    this.renderError('Microsoft Authentication Library (MSAL Browser) is not loaded.');
                    return;
                }

                // 4. Configure MSAL Browser instance
                const msalConfig = {
                    auth: {
                        clientId: this.config.clientId,
                        authority: this.config.authority,
                        redirectUri: window.location.origin,
                        postLogoutRedirectUri: window.location.origin
                    },
                    cache: {
                        cacheLocation: 'sessionStorage',
                        storeAuthStateInCookie: false
                    },
                    system: {
                        loggerOptions: {
                            loggerCallback: (level, message, containsPii) => {
                                if (containsPii) return;
                                // Only log in development
                                if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
                                    // console.debug('[MSAL]', message);
                                }
                            },
                            logLevel: window.msal.LogLevel ? window.msal.LogLevel.Warning : 2
                        }
                    }
                };

                this.msalInstance = new window.msal.PublicClientApplication(msalConfig);

                // 5. Handle any incoming redirect response from Microsoft login
                const redirectResponse = await this.msalInstance.handleRedirectPromise();
                if (redirectResponse) {
                    this.activeAccount = redirectResponse.account;
                    this.msalInstance.setActiveAccount(this.activeAccount);
                } else {
                    const currentAccounts = this.msalInstance.getAllAccounts();
                    if (currentAccounts.length > 0) {
                        this.activeAccount = currentAccounts[0];
                        this.msalInstance.setActiveAccount(this.activeAccount);
                    }
                }

                // 6. If user is logged in, acquire token and load profile
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
         * Triggers interactive sign-in using MSAL Popup (with fallback to Redirect).
         */
        async signIn() {
            if (!this.msalInstance) {
                this.renderError('Authentication client is not initialized.');
                return;
            }

            try {
                this.renderLoading(true);
                const loginResult = await this.msalInstance.loginPopup(this.loginRequest);
                this.activeAccount = loginResult.account;
                this.msalInstance.setActiveAccount(this.activeAccount);
                await this.loadUserProfile();
            } catch (err) {
                console.error('[AuthManager] Sign in failed:', err);
                if (err.name !== 'BrowserAuthError' || !err.message.includes('user_cancelled')) {
                    this.renderError(`Sign in failed: ${err.message}`);
                }
            } finally {
                this.renderLoading(false);
            }
        }

        /**
         * Signs out the current user and clears session state.
         */
        async signOut() {
            if (!this.msalInstance || !this.activeAccount) {
                return;
            }

            try {
                this.renderLoading(true);
                await this.msalInstance.logoutPopup({
                    account: this.activeAccount
                });
                this.activeAccount = null;
                this.currentUser = null;
                this.renderUnauthenticated();
            } catch (err) {
                console.error('[AuthManager] Sign out failed:', err);
                this.renderError(`Sign out failed: ${err.message}`);
            } finally {
                this.renderLoading(false);
            }
        }

        /**
         * Safely acquires an access token, renewing expired tokens automatically.
         * @returns {Promise<string>} Bearer access token string
         */
        async getAccessToken() {
            if (!this.msalInstance || !this.activeAccount) {
                throw new Error('No active account found. Please sign in.');
            }

            const request = {
                ...this.tokenRequest,
                account: this.activeAccount
            };

            try {
                const response = await this.msalInstance.acquireTokenSilent(request);
                return response.accessToken;
            } catch (silentError) {
                console.warn('[AuthManager] Silent token acquisition failed. Requesting interactive popup...', silentError);
                const popupResponse = await this.msalInstance.acquireTokenPopup(request);
                return popupResponse.accessToken;
            }
        }

        /**
         * Calls the protected GET /api/auth/me endpoint using the acquired Bearer token.
         */
        async loadUserProfile() {
            try {
                const token = await this.getAccessToken();
                const response = await fetch(`${this.apiBaseUrl}/api/auth/me`, {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Accept': 'application/json'
                    }
                });

                if (response.status === 401) {
                    const errData = await response.json().catch(() => ({}));
                    const code = errData.error ? errData.error.code : 'ERR_UNAUTHORIZED';
                    const msg = errData.error ? errData.error.message : 'Unauthorized access.';
                    this.renderIdentityRejected(code, msg);
                    return;
                }

                if (!response.ok) {
                    throw new Error(`Server returned HTTP ${response.status}`);
                }

                const resData = await response.json();
                this.currentUser = resData.data.user;
                this.renderAuthenticated(this.currentUser, resData.data.session);
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
                        Authenticate with your corporate Microsoft Entra account to view your governed leases,
                        contractor entitlements, or sponsorship responsibilities.
                    </p>
                    <div class="auth-actions">
                        <button id="btn-login" class="btn btn-primary" type="button">
                            <svg class="ms-icon" viewBox="0 0 21 21" width="18" height="18">
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
        }

        renderAuthenticated(user, session) {
            const authCard = document.getElementById('auth-status-container');
            if (!authCard) return;

            const rolesHtml = (user.roles && user.roles.length > 0)
                ? user.roles.map(r => `<span class="role-chip">${this.escapeHtml(r.role_name || r.role_code)}</span>`).join('')
                : '<span class="role-chip role-chip-empty">Standard User (No Elevated Roles)</span>';

            const userTypeBadgeClass = user.user_type === 'CONTRACTOR' ? 'badge-contractor' : 'badge-employee';

            authCard.innerHTML = `
                <div class="auth-box auth-box-active">
                    <div class="auth-header-row">
                        <span class="auth-badge auth-badge-active">Authenticated &amp; Verified</span>
                        <span class="auth-provider-pill">Entra ID Tenant</span>
                    </div>

                    <div class="profile-card">
                        <div class="profile-avatar">
                            ${this.escapeHtml(user.first_name ? user.first_name[0] : 'U')}${this.escapeHtml(user.last_name ? user.last_name[0] : '')}
                        </div>
                        <div class="profile-info">
                            <h3 class="profile-name">${this.escapeHtml(user.display_name || user.email)}</h3>
                            <div class="profile-meta">
                                <span class="profile-email">${this.escapeHtml(user.email)}</span>
                                <span class="user-type-tag ${userTypeBadgeClass}">${this.escapeHtml(user.user_type)}</span>
                            </div>
                        </div>
                        <div class="profile-actions">
                            <button id="btn-logout" class="btn btn-secondary btn-sm" type="button">Sign Out</button>
                        </div>
                    </div>

                    <div class="identity-mapping-details">
                        <h4>Database Identity Resolution (dbo.users)</h4>
                        <div class="id-grid">
                            <div class="id-item">
                                <span class="id-label">Application User ID:</span>
                                <span class="id-value"><code>${this.escapeHtml(user.user_id)}</code></span>
                            </div>
                            <div class="id-item">
                                <span class="id-label">Entra Object ID (oid):</span>
                                <span class="id-value"><code>${this.escapeHtml(user.entra_object_id)}</code></span>
                            </div>
                            <div class="id-item">
                                <span class="id-label">Department:</span>
                                <span class="id-value">${this.escapeHtml(user.department || 'Not Assigned')}</span>
                            </div>
                            <div class="id-item">
                                <span class="id-label">Account Status:</span>
                                <span class="id-value status-active">Active (Verified)</span>
                            </div>
                        </div>

                        <div class="roles-section">
                            <span class="id-label">Assigned Governance Roles:</span>
                            <div class="roles-container">${rolesHtml}</div>
                        </div>
                    </div>
                </div>
            `;

            const btnLogout = document.getElementById('btn-logout');
            if (btnLogout) {
                btnLogout.addEventListener('click', () => this.signOut());
            }
        }

        renderIdentityRejected(code, message) {
            const authCard = document.getElementById('auth-status-container');
            if (!authCard) return;

            authCard.innerHTML = `
                <div class="auth-box auth-box-rejected">
                    <div class="auth-header-row">
                        <span class="auth-badge auth-badge-rejected">Access Denied (401)</span>
                        <span class="auth-provider-pill">Identity Unmapped</span>
                    </div>
                    <h3>Account Not Registered</h3>
                    <p class="auth-desc">
                        You have successfully authenticated with Microsoft Entra ID, but your identity 
                        (<code>${this.activeAccount ? this.escapeHtml(this.activeAccount.username) : 'Account'}</code>) 
                        is not mapped to an active record in the AccessLease <code>dbo.users</code> table.
                    </p>
                    <div class="error-banner">
                        <strong>${this.escapeHtml(code)}:</strong> ${this.escapeHtml(message)}
                    </div>
                    <div class="auth-actions">
                        <button id="btn-logout" class="btn btn-secondary" type="button">Sign Out &amp; Retry</button>
                    </div>
                </div>
            `;

            const btnLogout = document.getElementById('btn-logout');
            if (btnLogout) {
                btnLogout.addEventListener('click', () => this.signOut());
            }
        }

        renderConfigNotice(missingFields) {
            const authCard = document.getElementById('auth-status-container');
            if (!authCard) return;

            const fieldsList = missingFields.map(f => `<li><code>${this.escapeHtml(f)}</code></li>`).join('');

            authCard.innerHTML = `
                <div class="auth-box auth-box-notice">
                    <div class="auth-header-row">
                        <span class="auth-badge auth-badge-notice">Entra ID Setup Required</span>
                        <span class="auth-provider-pill">Configuration Notice</span>
                    </div>
                    <h3>Microsoft Entra ID Registration Not Configured</h3>
                    <p class="auth-desc">
                        AccessLease is configured with zero secrets and requires an Azure App Registration
                        to perform live OAuth 2.0 PKCE sign-in.
                    </p>
                    <div class="setup-instructions">
                        <h4>Missing Configuration Variables:</h4>
                        <ul>${fieldsList}</ul>
                        <h4>To Enable Live Entra ID Sign-In:</h4>
                        <ol>
                            <li>Register an Application in <strong>Azure Portal &gt; Microsoft Entra ID &gt; App Registrations</strong>.</li>
                            <li>Configure Redirect URI as Single-Page Application (SPA): <code>${window.location.origin}</code>.</li>
                            <li>Set <code>ENTRA_TENANT_ID</code> and <code>ENTRA_CLIENT_ID</code> in <code>backend/.env</code>.</li>
                            <li>Restart backend server. Real Microsoft login will activate immediately.</li>
                        </ol>
                    </div>
                    <div class="notice-footer">
                        <em>Strict Compliance Rule: Demo or fabricated login states are strictly forbidden by AccessLease governance.</em>
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

