/**
 * AccessLease — Resource & Entitlement Catalogue HTTP Trigger Handlers
 * Azure Functions v4 REST Handlers.
 */

const catalogService = require('../services/catalogService');
const { createSuccessBody, toHttpResponse } = require('../utils/response');
const { handleAuthError } = require('../middleware/authorize');
const { withAuth } = require('../middleware/authMiddleware');

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
// 1. GET /api/catalog/resources
// -----------------------------------------------------------------------------
async function listCatalogResourcesHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const filter = {
            search: getQueryParam(request, 'search'),
            resourceType: getQueryParam(request, 'resourceType') || getQueryParam(request, 'type'),
            riskLevel: getQueryParam(request, 'riskLevel') || getQueryParam(request, 'risk'),
            isActive: getQueryParam(request, 'isActive') || getQueryParam(request, 'active'),
            limit: getQueryParam(request, 'limit') ? parseInt(getQueryParam(request, 'limit'), 10) : undefined,
            offset: getQueryParam(request, 'offset') ? parseInt(getQueryParam(request, 'offset'), 10) : undefined
        };

        const result = await catalogService.listResources(filter, user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(
            result,
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 2. POST /api/catalog/resources
// -----------------------------------------------------------------------------
async function createCatalogResourceHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const body = await parseRequestBody(request);

        const created = await catalogService.createResource(body, user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(201, createSuccessBody(
            { resource: created },
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 3. GET /api/catalog/resources/{id}
// -----------------------------------------------------------------------------
async function getCatalogResourceByIdHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const resourceId = getRouteParam(request, 'id');

        const result = await catalogService.getResourceById(resourceId, user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(
            { resource: result },
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 4. PUT /api/catalog/resources/{id}
// -----------------------------------------------------------------------------
async function updateCatalogResourceHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const resourceId = getRouteParam(request, 'id');
        const body = await parseRequestBody(request);

        const updated = await catalogService.updateResource(resourceId, body, user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(
            { resource: updated },
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 5. PATCH /api/catalog/resources/{id}/status
// -----------------------------------------------------------------------------
async function setCatalogResourceStatusHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const resourceId = getRouteParam(request, 'id');
        const body = await parseRequestBody(request);
        const isActive = body.isActive !== undefined ? body.isActive : body.is_active;

        const updated = await catalogService.setResourceStatus(resourceId, isActive, user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(
            { resource: updated },
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 6. POST /api/catalog/resources/{id}/owners
// -----------------------------------------------------------------------------
async function assignCatalogResourceOwnerHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const resourceId = getRouteParam(request, 'id');
        const body = await parseRequestBody(request);

        const assigned = await catalogService.assignResourceOwner(resourceId, body, user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(201, createSuccessBody(
            { owner: assigned },
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 7. DELETE /api/catalog/resources/{id}/owners/{ownerUserId}
// -----------------------------------------------------------------------------
async function removeCatalogResourceOwnerHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const resourceId = getRouteParam(request, 'id');
        const ownerUserId = getRouteParam(request, 'ownerUserId');

        const result = await catalogService.removeResourceOwner(resourceId, ownerUserId, user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(
            result,
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 8. GET /api/catalog/resources/{id}/entitlements
// -----------------------------------------------------------------------------
async function listCatalogResourceEntitlementsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const resourceId = getRouteParam(request, 'id');
        const filter = {
            isActive: getQueryParam(request, 'isActive') || getQueryParam(request, 'active')
        };

        const result = await catalogService.listEntitlements(resourceId, filter, user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(
            result,
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 9. POST /api/catalog/resources/{id}/entitlements
// -----------------------------------------------------------------------------
async function createCatalogResourceEntitlementHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const resourceId = getRouteParam(request, 'id');
        const body = await parseRequestBody(request);

        const created = await catalogService.createEntitlement(resourceId, body, user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(201, createSuccessBody(
            { entitlement: created },
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 10. PUT /api/catalog/entitlements/{id}
// -----------------------------------------------------------------------------
async function updateCatalogResourceEntitlementHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const entitlementId = getRouteParam(request, 'id');
        const body = await parseRequestBody(request);

        const updated = await catalogService.updateEntitlement(entitlementId, body, user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(
            { entitlement: updated },
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 11. PATCH /api/catalog/entitlements/{id}/status
// -----------------------------------------------------------------------------
async function setCatalogResourceEntitlementStatusHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        const entitlementId = getRouteParam(request, 'id');
        const body = await parseRequestBody(request);
        const isActive = body.isActive !== undefined ? body.isActive : body.is_active;

        const updated = await catalogService.setEntitlementStatus(entitlementId, isActive, user);
        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody(
            { entitlement: updated },
            correlationId ? { correlation_id: correlationId } : {}
        ));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

module.exports = {
    listCatalogResources: withAuth(listCatalogResourcesHandler),
    createCatalogResource: withAuth(createCatalogResourceHandler),
    getCatalogResourceById: withAuth(getCatalogResourceByIdHandler),
    updateCatalogResource: withAuth(updateCatalogResourceHandler),
    setCatalogResourceStatus: withAuth(setCatalogResourceStatusHandler),
    assignCatalogResourceOwner: withAuth(assignCatalogResourceOwnerHandler),
    removeCatalogResourceOwner: withAuth(removeCatalogResourceOwnerHandler),
    listResourceEntitlements: withAuth(listCatalogResourceEntitlementsHandler),
    createResourceEntitlement: withAuth(createCatalogResourceEntitlementHandler),
    updateResourceEntitlement: withAuth(updateCatalogResourceEntitlementHandler),
    setResourceEntitlementStatus: withAuth(setCatalogResourceEntitlementStatusHandler)
};
