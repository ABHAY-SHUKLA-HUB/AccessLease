/**
 * AccessLease — Access Request UI & Client-Side Validation Unit Tests
 * Tests static HTML pre-rendering, modal form fields, policy calculation, and script inclusion.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

describe('Unit: Access Request & Approvals UI Verification', () => {
    const indexPath = path.resolve(__dirname, '../../../frontend/index.html');
    const requestsJsPath = path.resolve(__dirname, '../../../frontend/assets/js/requests.js');

    test('1. Static HTML pre-renders Access Requests & Leases view with action button', () => {
        const html = fs.readFileSync(indexPath, 'utf-8');

        assert.ok(html.includes('id="view-requests"'), 'Must have #view-requests container');
        assert.ok(html.includes('id="btn-open-request-modal"'), 'Must have #btn-open-request-modal button');
        assert.ok(html.includes('id="requests-table-wrapper"'), 'Must have #requests-table-wrapper container');
        assert.ok(html.includes('id="request-status-filter"'), 'Must have #request-status-filter select');
        assert.ok(html.includes('id="new-request-modal-container"'), 'Must have #new-request-modal-container');
    });

    test('2. Static HTML pre-renders Multi-Stage Approvals view', () => {
        const html = fs.readFileSync(indexPath, 'utf-8');

        assert.ok(html.includes('id="view-approvals"'), 'Must have #view-approvals container');
        assert.ok(html.includes('id="btn-refresh-approvals"'), 'Must have #btn-refresh-approvals button');
        assert.ok(html.includes('id="approvals-table-wrapper"'), 'Must have #approvals-table-wrapper container');
        assert.ok(html.includes('id="approval-decision-modal-container"'), 'Must have #approval-decision-modal-container');
    });

    test('3. requests.js file exists and exports AccessLeaseRequests singleton', () => {
        assert.ok(fs.existsSync(requestsJsPath), 'requests.js must exist in frontend assets');
        const code = fs.readFileSync(requestsJsPath, 'utf-8');

        assert.ok(code.includes('window.AccessLeaseRequests = new RequestWorkflowModule()'), 'Must export window.AccessLeaseRequests');
        assert.ok(code.includes('openNewRequestModal('), 'Must define openNewRequestModal method');
        assert.ok(code.includes('updatePolicyPreview('), 'Must define updatePolicyPreview method');
        assert.ok(code.includes('req-engagement-select'), 'Must reference #req-engagement-select in form');
        assert.ok(code.includes('req-contractor-select'), 'Must reference #req-contractor-select in form');
    });

    test('4. Script tags include requests.js in index.html in correct order', () => {
        const html = fs.readFileSync(indexPath, 'utf-8');

        assert.ok(html.includes('<script src="assets/js/apiClient.js"></script>'), 'Must load apiClient.js');
        assert.ok(html.includes('<script src="assets/js/requests.js"></script>'), 'Must load requests.js');

        const apiClientPos = html.indexOf('assets/js/apiClient.js');
        const requestsPos = html.indexOf('assets/js/requests.js');
        const mainPos = html.indexOf('assets/js/main.js');

        assert.ok(apiClientPos < requestsPos, 'apiClient.js must load before requests.js');
        assert.ok(requestsPos < mainPos, 'requests.js must load before main.js');
    });
});
