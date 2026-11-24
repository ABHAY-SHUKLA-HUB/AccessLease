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
    'account_key',
    'private_key',
    'github_app_private_key',
    'privatekey',
    'app_jwt',
    'installation_token'
]);

function sanitizeValue(key, value) {
    if (value === null || value === undefined) return value;
    const lowerKey = String(key).toLowerCase();
    if (SENSITIVE_KEYS.has(lowerKey) || lowerKey.includes('private_key') || lowerKey.includes('privatekey')) {
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
        let errObj = null;
        let ctxObj = context;

        if (error instanceof Error) {
            errObj = {
                name: error.name,
                message: error.message,
                code: error.code
            };
        } else if (error && typeof error === 'object') {
            if (error.name || error.message || error.code) {
                errObj = {
                    name: error.name || 'Error',
                    message: error.message || String(error),
                    code: error.code
                };
            } else if (error.error) {
                errObj = {
                    name: 'Error',
                    message: String(error.error)
                };
                const { error: _, ...rest } = error;
                ctxObj = { ...rest, ...ctxObj };
            } else {
                ctxObj = { ...error, ...ctxObj };
            }
        }

        const payload = {
            level: 'ERROR',
            timestamp: new Date().toISOString(),
            message,
            error: errObj,
            context: sanitizeObject(ctxObj)
        };
        console.error(JSON.stringify(payload));
    },

    sanitizeObject
};

module.exports = logger;

