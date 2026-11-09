/**
 * AccessLease — Azure Functions v4 Application Entry Point
 * Registers HTTP routes and background event handlers.
 */

const { app } = require('@azure/functions');
const { getApplicationHealth, getDatabaseHealth } = require('./functions/health');
const { getAuthMe, getAuthConfigHandler } = require('./functions/auth');

// 1. GET /api/health - Application availability and environment status
app.http('applicationHealth', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'health',
    handler: getApplicationHealth
});

// 2. GET /api/health/db - Live SQL Server connectivity verification
app.http('databaseHealth', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'health/db',
    handler: getDatabaseHealth
});

// 3. GET /api/auth/config - Safe public Microsoft Entra ID bootstrap parameters
app.http('authConfig', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'auth/config',
    handler: getAuthConfigHandler
});

// 4. GET /api/auth/me - Protected user profile lookup with Entra ID bearer token
app.http('authMe', {
    methods: ['GET'],
    authLevel: 'anonymous', // Entra ID Bearer token validated via withAuth middleware
    route: 'auth/me',
    handler: getAuthMe
});

module.exports = { app };

