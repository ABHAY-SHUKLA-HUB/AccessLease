/**
 * AccessLease — User Governance & Administration HTTP Trigger Functions
 * Azure Functions v4 REST Handlers.
 * 
 * Endpoints:
 * - GET   /api/users               (Protected, SYSTEM_ADMIN): List internal users with pagination
 * - POST  /api/users               (Protected, SYSTEM_ADMIN): Register new internal user and assign roles
 * - PATCH /api/users/{id}/status   (Protected, SYSTEM_ADMIN): Activate or deactivate internal user
 * - GET   /api/roles               (Protected, SYSTEM_ADMIN): List assignable governance roles
 */

const userService = require('../services/userService');
const { createSuccessBody, createErrorBody, toHttpResponse } = require('../utils/response');
const { handleAuthError, requireRole } = require('../middleware/authorize');
const { AppError } = require('../utils/errors');
const logger = require('../utils/logger');

function getQueryParam(request, key) {
    if (!request || !request.query) return undefined;
    if (typeof request.query.get === 'function') {
        return request.query.get(key) || undefined;
    }
    return request.query[key];
}

function getRouteParam(request, key) {
    if (!request || !request.params) return undefined;
    return request.params[key];
}

async function parseRequestBody(request) {
    if (!request) return {};
    if (typeof request.json === 'function') {
        try {
            return await request.json();
        } catch {
            return request.body || {};
        }
    }
    return request.body || {};
}

// -----------------------------------------------------------------------------
// 1. GET /api/users
// -----------------------------------------------------------------------------
async function listUsersHandler(request, context) {
    try {
        const actingUser = request.authenticatedUser || request.user;
        const filter = {
            search: getQueryParam(request, 'search'),
            isActive: getQueryParam(request, 'isActive') || getQueryParam(request, 'is_active'),
            userType: getQueryParam(request, 'userType') || getQueryParam(request, 'user_type') || 'INTERNAL_EMPLOYEE',
            limit: getQueryParam(request, 'limit'),
            offset: getQueryParam(request, 'offset')
        };

        const result = await userService.listUsers(filter, actingUser);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;

        return toHttpResponse(200, createSuccessBody(result, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 2. POST /api/users
// -----------------------------------------------------------------------------
async function createUserHandler(request, context) {
    try {
        const actingUser = request.authenticatedUser || request.user;
        const body = await parseRequestBody(request);

        const createdUser = await userService.registerUser(body, actingUser);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;

        return toHttpResponse(201, createSuccessBody(
            { user: createdUser },
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 3. PATCH /api/users/{id}/status
// -----------------------------------------------------------------------------
async function updateUserStatusHandler(request, context) {
    try {
        const actingUser = request.authenticatedUser || request.user;
        const userId = getRouteParam(request, 'id');
        const body = await parseRequestBody(request);

        const isActive = body.isActive !== undefined ? body.isActive : body.is_active;
        const updatedUser = await userService.setUserStatus(userId, isActive, actingUser);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;

        return toHttpResponse(200, createSuccessBody(
            { user: updatedUser },
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 4. GET /api/roles
// -----------------------------------------------------------------------------
async function listRolesHandler(request, context) {
    try {
        const actingUser = request.authenticatedUser || request.user;
        const roles = await userService.listAvailableRoles(actingUser);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;

        return toHttpResponse(200, createSuccessBody(
            { roles },
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// Protected exports wrapped with requireRole(['SYSTEM_ADMIN'])
const listUsers = requireRole(['SYSTEM_ADMIN'], listUsersHandler);
const createUser = requireRole(['SYSTEM_ADMIN'], createUserHandler);
const updateUserStatus = requireRole(['SYSTEM_ADMIN'], updateUserStatusHandler);
const listRoles = requireRole(['SYSTEM_ADMIN'], listRolesHandler);

module.exports = {
    listUsers,
    createUser,
    updateUserStatus,
    listRoles,
    listUsersHandler,
    createUserHandler,
    updateUserStatusHandler,
    listRolesHandler
};
