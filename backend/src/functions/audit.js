/**
 * AccessLease — Audit & Compliance Trail HTTP Trigger Functions
 * Azure Functions v4 REST Handlers.
 *
 * Endpoints:
 * - GET /api/audit/events       (Protected): List audit events with filtering, search, and pagination
 * - GET /api/audit/events/{id}  (Protected): Get single audit event with full parsed payload
 * - GET /api/audit/stats        (Protected): Aggregated audit metrics and category counts
 */

const { withAuth } = require('../middleware/authMiddleware');
const auditRepository = require('../repositories/auditRepository');
const { hasAnyRole } = require('../security/permissionPolicy');
const { createSuccessBody, toHttpResponse } = require('../utils/response');
const { handleAuthError } = require('../middleware/authorize');
const { ForbiddenError, NotFoundError } = require('../utils/errors');
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

/**
 * Checks if the user is authorized to view audit events.
 * Only governance roles (Admin, Security, Auditor, Sponsor) may access compliance logs.
 */
function assertAuditAccess(user) {
    if (!user) {
        throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
    }
    const authorized = hasAnyRole(user.roles, [
        'SYSTEM_ADMIN',
        'SECURITY_OFFICER',
        'COMPLIANCE_AUDITOR',
        'INTERNAL_SPONSOR'
    ]);
    if (!authorized) {
        throw new ForbiddenError(
            'Access denied: You do not have permission to view the audit and compliance trail.',
            'ERR_FORBIDDEN_ROLE'
        );
    }
}

// -----------------------------------------------------------------------------
// 1. GET /api/audit/events - List immutable audit events
// -----------------------------------------------------------------------------
async function listAuditEventsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        assertAuditAccess(user);

        const eventCategory = getQueryParam(request, 'eventCategory');
        const entityType = getQueryParam(request, 'entityType');
        const entityId = getQueryParam(request, 'entityId');
        const actorUserId = getQueryParam(request, 'actorUserId');
        const search = getQueryParam(request, 'search');
        const limit = parseInt(getQueryParam(request, 'limit') || '50', 10);
        const offset = parseInt(getQueryParam(request, 'offset') || '0', 10);

        const filter = {
            eventCategory,
            entityType,
            entityId,
            actorUserId,
            search,
            limit: Math.min(100, Math.max(1, isNaN(limit) ? 50 : limit)),
            offset: Math.max(0, isNaN(offset) ? 0 : offset)
        };

        const result = await auditRepository.listAuditEvents(filter);
        const total = result.length > 0 && result[0].total_count !== undefined
            ? Number(result[0].total_count)
            : (await auditRepository.getAuditCount(filter));

        // Format and clean payload for JSON response
        const events = result.map(evt => {
            let parsedPayload = evt.event_payload;
            if (typeof parsedPayload === 'string') {
                try {
                    parsedPayload = JSON.parse(parsedPayload);
                } catch {
                    // keep raw string
                }
            }
            return {
                eventId: evt.event_id,
                eventCategory: evt.event_category,
                eventAction: evt.event_action,
                entityType: evt.entity_type,
                entityId: evt.entity_id,
                actorUserId: evt.actor_user_id,
                actorType: evt.actor_type,
                actorName: evt.actor_name || null,
                actorEmail: evt.actor_email || null,
                ipAddress: evt.ip_address || null,
                payload: parsedPayload,
                createdAt: evt.created_at
            };
        });

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody({
            events,
            total,
            limit: filter.limit,
            offset: filter.offset
        }, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 2. GET /api/audit/events/{id} - Get single event details
// -----------------------------------------------------------------------------
async function getAuditEventByIdHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        assertAuditAccess(user);

        const eventId = getRouteParam(request, 'id') || getRouteParam(request, 'eventId');
        if (!eventId) {
            throw new NotFoundError('Audit Event ID is required.', 'ERR_EVENT_ID_REQUIRED');
        }

        const evt = await auditRepository.getAuditEventById(eventId);
        if (!evt) {
            throw new NotFoundError(`Audit event #${eventId} not found.`, 'ERR_EVENT_NOT_FOUND');
        }

        let parsedPayload = evt.event_payload;
        if (typeof parsedPayload === 'string') {
            try {
                parsedPayload = JSON.parse(parsedPayload);
            } catch {
                // keep as string
            }
        }

        const correlationId = context && context.invocationId ? context.invocationId : undefined;
        return toHttpResponse(200, createSuccessBody({
            event: {
                eventId: evt.event_id,
                eventCategory: evt.event_category,
                eventAction: evt.event_action,
                entityType: evt.entity_type,
                entityId: evt.entity_id,
                actorUserId: evt.actor_user_id,
                actorType: evt.actor_type,
                actorName: evt.actor_name || null,
                actorEmail: evt.actor_email || null,
                ipAddress: evt.ip_address || null,
                payload: parsedPayload,
                createdAt: evt.created_at
            }
        }, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

// -----------------------------------------------------------------------------
// 3. GET /api/audit/stats - Aggregated stats for compliance dashboard
// -----------------------------------------------------------------------------
async function getAuditStatsHandler(request, context) {
    try {
        const user = request.authenticatedUser || request.user;
        assertAuditAccess(user);

        const stats = await auditRepository.getAuditStats();
        const correlationId = context && context.invocationId ? context.invocationId : undefined;

        return toHttpResponse(200, createSuccessBody({
            stats
        }, correlationId ? { correlation_id: correlationId } : {}));
    } catch (err) {
        return handleAuthError(err, request, context);
    }
}

module.exports = {
    listAuditEvents: withAuth(listAuditEventsHandler),
    getAuditEventById: withAuth(getAuditEventByIdHandler),
    getAuditStats: withAuth(getAuditStatsHandler)
};
