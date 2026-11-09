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
    constructor(message = 'Validation failed', details = []) {
        super(message, 400, 'ERR_VALIDATION_FAILED', details);
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
    constructor(message = 'Resource state conflict') {
        super(message, 409, 'ERR_CONFLICT');
    }
}

module.exports = {
    AppError,
    ValidationError,
    DatabaseError,
    NotFoundError,
    ConflictError
};

