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

    // Microsoft Entra ID (Azure Active Directory) Authentication
    get ENTRA_TENANT_ID() {
        return (process.env.ENTRA_TENANT_ID || '').trim();
    },
    get ENTRA_CLIENT_ID() {
        return (process.env.ENTRA_CLIENT_ID || '').trim();
    },
    get ENTRA_CLIENT_SECRET() {
        return process.env.ENTRA_CLIENT_SECRET || '';
    },
    get ENTRA_AUTHORITY() {
        if (process.env.ENTRA_AUTHORITY) {
            return process.env.ENTRA_AUTHORITY.trim().replace(/\/+$/, '');
        }
        return this.ENTRA_TENANT_ID
            ? `https://login.microsoftonline.com/${this.ENTRA_TENANT_ID}`
            : '';
    },
    get ENTRA_API_AUDIENCE() {
        if (process.env.ENTRA_API_AUDIENCE) {
            return process.env.ENTRA_API_AUDIENCE.trim();
        }
        return this.ENTRA_CLIENT_ID ? `api://${this.ENTRA_CLIENT_ID}` : '';
    },
    get ENTRA_API_SCOPE() {
        if (process.env.ENTRA_API_SCOPE) {
            return process.env.ENTRA_API_SCOPE.trim();
        }
        return this.ENTRA_CLIENT_ID ? `api://${this.ENTRA_CLIENT_ID}/access_as_user` : '';
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
     * Checks if Microsoft Entra ID authentication has required non-placeholder configuration.
     * @returns {{ isValid: boolean, missingFields: string[] }}
     */
    validateEntraConfig() {
        const missingFields = [];
        const isPlaceholder = (val) => !val || val.includes('00000000-0000-0000-0000-000000000000') || val.includes('your-');

        if (isPlaceholder(this.ENTRA_TENANT_ID)) {
            missingFields.push('Entra Tenant ID');
        }
        if (isPlaceholder(this.ENTRA_CLIENT_ID)) {
            missingFields.push('Entra Client ID');
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
            clientId: isValid ? this.ENTRA_CLIENT_ID : null,
            tenantId: isValid ? this.ENTRA_TENANT_ID : null,
            authority: isValid ? this.ENTRA_AUTHORITY : null,
            apiAudience: isValid ? this.ENTRA_API_AUDIENCE : null,
            apiScope: isValid ? this.ENTRA_API_SCOPE : null,
            missingConfiguration: isValid ? [] : missingFields
        };
    },

    /**
     * Checks if database configuration has required minimum fields.
     * @returns {{ isValid: boolean, missingFields: string[] }}
     */
    validateDatabaseConfig() {
        const missingFields = [];
        if (!this.SQL_SERVER) missingFields.push('Database Server');
        if (!this.SQL_DATABASE) missingFields.push('Database Name');
        
        // For LocalDB or Named Pipe connections, Windows integrated auth is used;
        // for standard TCP connections, credentials are required.
        const isLocalDb = this.SQL_SERVER.toLowerCase().includes('(localdb)') || 
                          this.SQL_SERVER.toLowerCase().includes('localdb#') ||
                          this.SQL_SERVER.toLowerCase().startsWith('np:');
        if (!isLocalDb) {
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
            auth_configured: authValid,
            timestamp: new Date().toISOString()
        };
    }
};

module.exports = environment;
