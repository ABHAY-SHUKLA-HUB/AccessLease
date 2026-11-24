/**
 * AccessLease — Application Error Hierarchy
 * Provides structured operational errors with safe client messages.
 */

class AppError extends Error {
    constructor(message, statusCode = 500, code = 'ERR_INTERNAL', details = []) {
        super(message);
        this.name = this.constructor.name;
        this.statusCode = statusCode;
        this.code = code;
        this.details = details;
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}

class ValidationError extends AppError {
    constructor(message = 'Validation failed', details = [], code = 'ERR_VALIDATION_FAILED') {
        super(message, 400, code, details);
    }
}

class DatabaseError extends AppError {
    constructor(message = 'Database operation failed', originalError = null) {
        // Safe sanitization: Never expose credentials or connection strings
        super(message, 503, 'ERR_DATABASE_UNAVAILABLE');
        this.originalMessage = originalError ? originalError.message : null;
    }
}

class NotFoundError extends AppError {
    constructor(resource = 'Resource') {
        super(`${resource} not found`, 404, 'ERR_NOT_FOUND');
    }
}

class ConflictError extends AppError {
    constructor(message = 'Resource state conflict', code = 'ERR_CONFLICT') {
        super(message, 409, code);
    }
}

class UnauthorizedError extends AppError {
    constructor(message = 'Authentication required', code = 'ERR_UNAUTHORIZED', details = []) {
        super(message, 401, code, details);
    }
}

class ForbiddenError extends AppError {
    constructor(message = 'Access forbidden', code = 'ERR_FORBIDDEN', details = []) {
        super(message, 403, code, details);
    }
}

class ConfigurationError extends AppError {
    constructor(message = 'Service configuration error', details = [], code = 'ERR_CONFIGURATION_INVALID') {
        super(message, 500, code, details);
    }
}

class ConnectorError extends AppError {
    constructor(message = 'External connector error', statusCode = 502, code = 'ERR_CONNECTOR_FAILED', details = {}, isRetryable = false) {
        super(message, statusCode, code, details);
        this.isRetryable = isRetryable;
        this.category = details.category || 'CONNECTOR_ERROR';
        this.retryAfterSeconds = details.retryAfterSeconds || null;
    }
}

module.exports = {
    AppError,
    ValidationError,
    DatabaseError,
    NotFoundError,
    ConflictError,
    UnauthorizedError,
    ForbiddenError,
    ConfigurationError,
    ConnectorError
};

