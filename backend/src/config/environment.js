/**
 * AccessLease — Centralized Environment Configuration
 * Target: Node.js / Azure Functions
 * 
 * Rules:
 * - Dynamic getters to reflect runtime and test environment state.
 * - Never hardcode secrets.
 * - Support both standard SQL_* and AZURE_SQL_* naming.
 * - Provide safe, non-sensitive public metadata summaries.
 */

const path = require('path');
const dotenv = require('dotenv');

// Load environment variables from backend/.env or root .env if present
dotenv.config({ path: path.resolve(__dirname, '../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

function parseBoolean(value, defaultValue = false) {
    if (value === undefined || value === null || value === '') return defaultValue;
    if (typeof value === 'boolean') return value;
    const lower = String(value).trim().toLowerCase();
    return lower === 'true' || lower === '1' || lower === 'yes';
}

function parseInteger(value, defaultValue) {
    if (value === undefined || value === null || value === '') return defaultValue;
    const parsed = parseInt(String(value).trim(), 10);
    return Number.isNaN(parsed) ? defaultValue : parsed;
}

const environment = {
    // Runtime Mode
    get NODE_ENV() {
        return process.env.NODE_ENV || process.env.AZURE_FUNCTIONS_ENVIRONMENT || 'development';
    },
    get PORT() {
        return parseInteger(process.env.PORT, 7071);
    },
    get LOG_LEVEL() {
        return process.env.LOG_LEVEL || 'info';
    },

    // Azure Functions Host
    get FUNCTIONS_WORKER_RUNTIME() {
        return process.env.FUNCTIONS_WORKER_RUNTIME || 'node';
    },
    get AzureWebJobsStorage() {
        return process.env.AzureWebJobsStorage || 'UseDevelopmentStorage=true';
    },

    // Microsoft SQL Server / Azure SQL Database Configuration
    // Transparently supports either SQL_* or AZURE_SQL_* prefix
    // Authentication Modes:
    // - 'localdb': Windows LocalDB dynamic named pipe (integrated security, no credentials)
    // - 'sql-password': Local/remote TCP SQL connection using SQL credentials (SQL_USER + SQL_PASSWORD)
    // - 'azure-identity': Azure SQL using Microsoft Entra System-Assigned Managed Identity (zero secrets)
    get SQL_AUTH_MODE() {
        const raw = (process.env.SQL_AUTH_MODE || process.env.AZURE_SQL_AUTH_MODE || '').trim().toLowerCase();
        if (raw) {
            if (raw === 'localdb' || raw === 'namedpipe' || raw === 'named-pipe') return 'localdb';
            if (raw === 'sql-password' || raw === 'password' || raw === 'sql' || raw === 'sql_password') return 'sql-password';
            if (raw === 'azure-identity' || raw === 'managed-identity' || raw === 'azure-managed-identity' || raw === 'entra-id' || raw === 'aad' || raw === 'msi') return 'azure-identity';
            return raw; // Preserve unrecognized mode for explicit validation failure
        }

        // Automatic inference when SQL_AUTH_MODE is unset:
        const server = this.SQL_SERVER.toLowerCase();
        if (server.includes('(localdb)') || server.includes('localdb#') || server.startsWith('np:')) {
            return 'localdb';
        }
        if (server.endsWith('.database.windows.net') && !this.SQL_USER && !this.SQL_PASSWORD) {
            return 'azure-identity';
        }
        if (this.SQL_USER || this.SQL_PASSWORD) {
            return 'sql-password';
        }
        return 'sql-password';
    },

    get AZURE_CLIENT_ID() {
        return (process.env.AZURE_CLIENT_ID || process.env.SQL_MANAGED_IDENTITY_CLIENT_ID || '').trim() || undefined;
    },

    get SQL_SERVER() {
        return (process.env.SQL_SERVER || process.env.AZURE_SQL_SERVER || '').trim();
    },
    get SQL_DATABASE() {
        return (process.env.SQL_DATABASE || process.env.AZURE_SQL_DATABASE || '').trim();
    },
    get SQL_USER() {
        return (process.env.SQL_USER || process.env.AZURE_SQL_USER || '').trim();
    },
    get SQL_PASSWORD() {
        return process.env.SQL_PASSWORD || process.env.AZURE_SQL_PASSWORD || '';
    },
    get SQL_PORT() {
        return parseInteger(process.env.SQL_PORT || process.env.AZURE_SQL_PORT, 1433);
    },
    get SQL_ENCRYPT() {
        return parseBoolean(process.env.SQL_ENCRYPT ?? process.env.AZURE_SQL_ENCRYPT, true);
    },
    get SQL_TRUST_SERVER_CERTIFICATE() {
        return parseBoolean(
            process.env.SQL_TRUST_SERVER_CERTIFICATE ?? process.env.AZURE_SQL_TRUST_SERVER_CERTIFICATE,
            false
        );
    },
    get SQL_CONNECTION_TIMEOUT() {
        return parseInteger(
            process.env.SQL_CONNECTION_TIMEOUT ?? process.env.AZURE_SQL_CONNECTION_TIMEOUT,
            30000
        );
    },
    get SQL_REQUEST_TIMEOUT() {
        return parseInteger(process.env.SQL_REQUEST_TIMEOUT, 30000);
    },
    get SQL_POOL_MAX() {
        return parseInteger(process.env.SQL_POOL_MAX, 10);
    },
    get SQL_POOL_MIN() {
        return parseInteger(process.env.SQL_POOL_MIN, 1);
    },

    // CORS & Security
    get CORS_ALLOWED_ORIGINS() {
        return process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:3000,http://127.0.0.1:5500';
    },

    // Microsoft Entra ID (Azure Active Directory) Authentication — Dual Registration Topology

    // GitHub App Connector Configuration (Provisioning Engine)
    get GITHUB_APP_ID() {
        return (process.env.GITHUB_APP_ID || '').trim();
    },
    get GITHUB_APP_SLUG() {
        return (process.env.GITHUB_APP_SLUG || 'accesslease').trim();
    },
    get GITHUB_APP_PRIVATE_KEY() {
        const rawKey = process.env.GITHUB_APP_PRIVATE_KEY || '';
        if (!rawKey) return '';
        // If it starts with "-----BEGIN", return as is (replace literal \n if present)
        if (rawKey.includes('BEGIN')) {
            return rawKey.replace(/\\n/g, '\n');
        }
        // If it's a file path pointing to an existing file
        try {
            const fs = require('fs');
            if (fs.existsSync(rawKey)) {
                return fs.readFileSync(rawKey, 'utf8');
            }
        } catch {
            // Ignore fs errors in edge environments
        }
        // If base64 encoded PEM
        try {
            const decoded = Buffer.from(rawKey, 'base64').toString('utf8');
            if (decoded.includes('BEGIN')) {
                return decoded;
            }
        } catch {
            // Ignore decoding error
        }
        return rawKey;
    },
    get GITHUB_APP_INSTALLATION_ID() {
        return (process.env.GITHUB_APP_INSTALLATION_ID || '').trim();
    },
    get GITHUB_ALLOWED_ORGS() {
        const orgs = (process.env.GITHUB_ALLOWED_ORGS || '').trim();
        return orgs ? orgs.split(',').map(s => s.trim().toLowerCase()).filter(Boolean) : [];
    },
    get GITHUB_API_BASE_URL() {
        return (process.env.GITHUB_API_BASE_URL || 'https://api.github.com').trim().replace(/\/+$/, '');
    },
    get GITHUB_APP_CLIENT_ID() {
        return (process.env.GITHUB_APP_CLIENT_ID || '').trim();
    },
    get GITHUB_OAUTH_CLIENT_ID() {
        return (process.env.GITHUB_OAUTH_CLIENT_ID || process.env.GITHUB_APP_CLIENT_ID || '').trim();
    },
    get GITHUB_OAUTH_CLIENT_SECRET() {
        return (process.env.GITHUB_OAUTH_CLIENT_SECRET || '').trim();
    },
    get GITHUB_OAUTH_REDIRECT_URI() {
        return (process.env.GITHUB_OAUTH_REDIRECT_URI || '').trim();
    },
    get hasGitHubOAuth() {
        return Boolean(this.GITHUB_OAUTH_CLIENT_ID && this.GITHUB_OAUTH_CLIENT_SECRET);
    },

    /**
     * Validates whether GitHub App connector configuration is populated and valid.
     * @returns {{ isValid: boolean, missingFields: string[] }}
     */
    validateGitHubConfig() {
        const missingFields = [];
        if (!this.GITHUB_APP_ID) missingFields.push('GitHub App ID (GITHUB_APP_ID)');
        if (!this.GITHUB_APP_PRIVATE_KEY) missingFields.push('GitHub App Private Key (GITHUB_APP_PRIVATE_KEY)');
        if (!this.GITHUB_APP_INSTALLATION_ID) missingFields.push('GitHub Installation ID (GITHUB_APP_INSTALLATION_ID)');
        if (this.GITHUB_ALLOWED_ORGS.length === 0) missingFields.push('GitHub Allowed Organizations (GITHUB_ALLOWED_ORGS)');

        return {
            isValid: missingFields.length === 0,
            missingFields
        };
    },

    // 1. Entra Directory (Tenant) ID
    get ENTRA_TENANT_ID() {
        return (process.env.ENTRA_TENANT_ID || '').trim();
    },

    // 2. Frontend SPA Registration (AccessLease Governance Platform - SPA)
    get ENTRA_SPA_CLIENT_ID() {
        const explicitSpa = (process.env.ENTRA_SPA_CLIENT_ID || '').trim();
        if (explicitSpa) return explicitSpa;
        // In production, fallback must NOT allow silent single client ID usage
        if (this.NODE_ENV === 'production') return '';
        // Explicit non-production fallback for tests or legacy configuration
        return (process.env.ENTRA_CLIENT_ID || '').trim();
    },

    // 3. Backend Web API Registration (AccessLease Governance Platform)
    get ENTRA_API_CLIENT_ID() {
        const explicitApi = (process.env.ENTRA_API_CLIENT_ID || '').trim();
        if (explicitApi) return explicitApi;
        // In production, fallback must NOT allow silent single client ID usage
        if (this.NODE_ENV === 'production') return '';
        // Explicit non-production fallback for tests or legacy configuration
        return (process.env.ENTRA_CLIENT_ID || '').trim();
    },

    // Legacy alias (returns ENTRA_SPA_CLIENT_ID or ENTRA_API_CLIENT_ID)
    get ENTRA_CLIENT_ID() {
        return this.ENTRA_SPA_CLIENT_ID || this.ENTRA_API_CLIENT_ID;
    },

    get ENTRA_CLIENT_SECRET() {
        return process.env.ENTRA_CLIENT_SECRET || '';
    },

    // 4. Expected Token Audience for Backend Web API
    get ENTRA_API_AUDIENCE() {
        if (process.env.ENTRA_API_AUDIENCE) {
            return process.env.ENTRA_API_AUDIENCE.trim();
        }
        return this.ENTRA_API_CLIENT_ID ? `api://${this.ENTRA_API_CLIENT_ID}` : '';
    },

    // 5. Delegated Scope exposed by Backend Web API
    get ENTRA_API_SCOPE() {
        if (process.env.ENTRA_API_SCOPE) {
            return process.env.ENTRA_API_SCOPE.trim();
        }
        const audience = this.ENTRA_API_AUDIENCE;
        if (audience) {
            return `${audience.replace(/\/+$/, '')}/access_as_user`;
        }
        return this.ENTRA_API_CLIENT_ID ? `api://${this.ENTRA_API_CLIENT_ID}/access_as_user` : '';
    },

    // 6. SPA Redirect URI
    get ENTRA_REDIRECT_URI() {
        return (process.env.ENTRA_REDIRECT_URI || 'http://localhost:7071/').trim();
    },

    // Shared Tenant Authority, Issuer, and JWKS Endpoint
    get ENTRA_AUTHORITY() {
        if (process.env.ENTRA_AUTHORITY) {
            return process.env.ENTRA_AUTHORITY.trim().replace(/\/+$/, '');
        }
        return this.ENTRA_TENANT_ID
            ? `https://login.microsoftonline.com/${this.ENTRA_TENANT_ID}`
            : '';
    },
    get ENTRA_ISSUER() {
        if (process.env.ENTRA_ISSUER) {
            return process.env.ENTRA_ISSUER.trim().replace(/\/+$/, '');
        }
        return this.ENTRA_TENANT_ID
            ? `https://login.microsoftonline.com/${this.ENTRA_TENANT_ID}/v2.0`
            : '';
    },
    get ENTRA_JWKS_URI() {
        if (process.env.ENTRA_JWKS_URI) {
            return process.env.ENTRA_JWKS_URI.trim();
        }
        return this.ENTRA_TENANT_ID
            ? `https://login.microsoftonline.com/${this.ENTRA_TENANT_ID}/discovery/v2.0/keys`
            : '';
    },

    /**
     * Checks if Microsoft Entra ID dual-registration configuration is valid.
     * @returns {{ isValid: boolean, missingFields: string[] }}
     */
    validateEntraConfig() {
        const missingFields = [];
        const isPlaceholder = (val) => !val || val.includes('00000000-0000-0000-0000-000000000000') || val.includes('your-');

        if (isPlaceholder(this.ENTRA_TENANT_ID)) {
            missingFields.push('Entra Tenant ID (ENTRA_TENANT_ID)');
        }
        if (isPlaceholder(this.ENTRA_SPA_CLIENT_ID)) {
            missingFields.push('Entra SPA Client ID (ENTRA_SPA_CLIENT_ID)');
        }
        if (isPlaceholder(this.ENTRA_API_CLIENT_ID) && isPlaceholder(this.ENTRA_API_AUDIENCE)) {
            missingFields.push('Entra API Client ID or Audience (ENTRA_API_CLIENT_ID / ENTRA_API_AUDIENCE)');
        }

        // Strict Production Security Guardrail: Production MUST NOT use identical client IDs for SPA and Backend Web API
        if (this.NODE_ENV === 'production') {
            if (!isPlaceholder(this.ENTRA_SPA_CLIENT_ID) && !isPlaceholder(this.ENTRA_API_CLIENT_ID)) {
                if (this.ENTRA_SPA_CLIENT_ID.toLowerCase() === this.ENTRA_API_CLIENT_ID.toLowerCase()) {
                    missingFields.push('Separate SPA and Backend API App Registrations required (cannot share one Client ID in production)');
                }
            }
        }

        return {
            isValid: missingFields.length === 0,
            missingFields
        };
    },

    /**
     * Returns sanitized public authentication metadata for MSAL / frontend bootstrap.
     * Strictly omits all secrets (client secret, connection strings, etc.).
     * @returns {object}
     */
    getPublicAuthConfig() {
        const { isValid, missingFields } = this.validateEntraConfig();
        return {
            configured: isValid,
            clientId: isValid ? this.ENTRA_SPA_CLIENT_ID : null, // Supplies Frontend SPA Client ID for MSAL Browser
            tenantId: isValid ? this.ENTRA_TENANT_ID : null,
            authority: isValid ? this.ENTRA_AUTHORITY : null,
            apiAudience: isValid ? this.ENTRA_API_AUDIENCE : null,
            apiScope: isValid ? this.ENTRA_API_SCOPE : null,      // Supplies Backend Web API delegated scope
            redirectUri: this.ENTRA_REDIRECT_URI,
            missingConfiguration: isValid ? [] : missingFields
        };
    },

    /**
     * Checks if database configuration has required minimum fields for the active authentication mode.
     * Mode requirements:
     * - 'localdb': Server + Database Name (no credentials needed)
     * - 'sql-password': Server + Database Name + SQL_USER + SQL_PASSWORD
     * - 'azure-identity': Server + Database Name (no credentials needed; uses Entra Managed Identity)
     * 
     * @returns {{ isValid: boolean, missingFields: string[] }}
     */
    validateDatabaseConfig() {
        const missingFields = [];
        if (!this.SQL_SERVER) missingFields.push('Database Server');
        if (!this.SQL_DATABASE) missingFields.push('Database Name');
        
        const mode = this.SQL_AUTH_MODE;
        const validModes = ['localdb', 'sql-password', 'azure-identity'];

        if (!validModes.includes(mode)) {
            missingFields.push(`Unsupported SQL authentication mode: "${mode}". Allowed modes: 'localdb', 'sql-password', 'azure-identity'`);
            return {
                isValid: false,
                missingFields
            };
        }

        if (mode === 'sql-password') {
            if (!this.SQL_USER || !this.SQL_PASSWORD) {
                missingFields.push('Database Credentials');
            }
        }

        return {
            isValid: missingFields.length === 0,
            missingFields
        };
    },

    /**
     * Returns sanitized public metadata safe to expose in health checks.
     * Strictly omits server hostnames, credentials, and connection strings.
     * @returns {object}
     */
    getPublicEnvironmentSummary() {
        const { isValid: dbValid } = this.validateDatabaseConfig();
        const { isValid: authValid } = this.validateEntraConfig();
        return {
            status: 'online',
            environment: this.NODE_ENV,
            version: '0.1.0',
            node_version: process.version,
            database_configured: dbValid,
            sql_auth_mode: this.SQL_AUTH_MODE,
            auth_configured: authValid,
            timestamp: new Date().toISOString()
        };
    }
};

module.exports = environment;
