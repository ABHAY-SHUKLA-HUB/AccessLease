/**
 * AccessLease — Azure Functions v4 Application Entry Point
 * Registers HTTP routes and background event handlers.
 */

const { app } = require('@azure/functions');
const { getApplicationHealth, getDatabaseHealth } = require('./functions/health');

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

module.exports = { app };
