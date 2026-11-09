/**
 * AccessLease — Standardized API Response Envelope
 * Formats responses conforming to the canonical API specification.
 */

const { randomUUID } = require('crypto');

/**
 * Builds a standardized success response body.
 * @param {any} data Response payload
 * @param {object} meta Additional metadata
 * @returns {object} Standard JSON response structure
 */
function createSuccessBody(data, meta = {}) {
    return {
        success: true,
        data: data !== undefined ? data : null,
        meta: {
            correlation_id: meta.correlation_id || randomUUID(),
            timestamp: new Date().toISOString(),
            ...meta
        }
    };
}

/**
 * Builds a standardized error response body.
 * @param {string} code Machine-readable error code
 * @param {string} message Human-readable safe error message
 * @param {Array} details Detailed validation or field issues
 * @param {object} meta Additional metadata
 * @returns {object} Standard JSON error response structure
 */
function createErrorBody(code, message, details = [], meta = {}) {
    return {
        success: false,
        error: {
            code: code || 'ERR_INTERNAL',
            message: message || 'An unexpected error occurred.',
            details: Array.isArray(details) ? details : [details]
        },
        meta: {
            correlation_id: meta.correlation_id || randomUUID(),
            timestamp: new Date().toISOString(),
            ...meta
        }
    };
}

/**
 * Formats an Azure Functions HTTP response object.
 * @param {number} status HTTP status code
 * @param {object} body JSON payload
 * @param {object} customHeaders Additional headers
 * @returns {object} Azure Functions v4 response object
 */
function toHttpResponse(status, body, customHeaders = {}) {
    return {
        status,
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            ...customHeaders
        },
        jsonBody: body
    };
}

module.exports = {
    createSuccessBody,
    createErrorBody,
    toHttpResponse
};
