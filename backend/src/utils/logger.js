/**
 * AccessLease — Secure Structured Logger
 * Sanitizes sensitive credentials and secrets before outputting JSON logs.
 */

const SENSITIVE_KEYS = new Set([
    'password',
    'sql_password',
    'azure_sql_password',
    'secret',
    'client_secret',
    'entra_client_secret',
    'token',
    'access_token',
    'refresh_token',
    'authorization',
    'connectionstring',
    'azure_storage_connection_string',
    'key',
    'account_key'
]);

function sanitizeValue(key, value) {
    if (value === null || value === undefined) return value;
    if (SENSITIVE_KEYS.has(String(key).toLowerCase())) {
        return '[REDACTED_SECRET]';
    }
    if (typeof value === 'object' && !Array.isArray(value)) {
        return sanitizeObject(value);
    }
    if (Array.isArray(value)) {
        return value.map(item => (typeof item === 'object' ? sanitizeObject(item) : item));
    }
    return value;
}

function sanitizeObject(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    const sanitized = {};
    for (const [k, v] of Object.entries(obj)) {
        sanitized[k] = sanitizeValue(k, v);
    }
    return sanitized;
}

const logger = {
    info(message, context = {}) {
        const payload = {
            level: 'INFO',
            timestamp: new Date().toISOString(),
            message,
            context: sanitizeObject(context)
        };
        console.log(JSON.stringify(payload));
    },

    warn(message, context = {}) {
        const payload = {
            level: 'WARN',
            timestamp: new Date().toISOString(),
            message,
            context: sanitizeObject(context)
        };
        console.warn(JSON.stringify(payload));
    },

    error(message, error = null, context = {}) {
        const payload = {
            level: 'ERROR',
            timestamp: new Date().toISOString(),
            message,
            error: error ? {
                name: error.name,
                message: error.message,
                code: error.code
            } : null,
            context: sanitizeObject(context)
        };
        console.error(JSON.stringify(payload));
    },

    sanitizeObject
};

module.exports = logger;

