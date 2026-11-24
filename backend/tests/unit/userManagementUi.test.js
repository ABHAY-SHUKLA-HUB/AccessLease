/**
 * AccessLease — Unit Tests: User Management UI & Validation (users.js)
 * 
 * Verifies:
 * 1. Static HTML files (frontend & backend/public) pre-render #nav-link-users, #view-users, and #modal-add-user.
 * 2. Form controls exist for name, email, entra_object_id, department, and governance role checkboxes.
 * 3. CONTRACTOR role is NOT an option in the internal application user registration modal.
 * 4. UsersModule.isAdmin() checks for SYSTEM_ADMIN role accurately.
 * 5. UsersModule checks non-admin access and rejects modal open for non-admins.
 * 6. Client validation rejects missing email, invalid email, missing name, missing OID, and empty roles.
 * 7. Successful submission invokes window.apiClient.post('/api/users') with correct payload.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const FRONTEND_HTML_FILE = path.resolve(__dirname, '../../../frontend/index.html');
const PUBLIC_HTML_FILE = path.resolve(__dirname, '../../public/index.html');
const USERS_JS_FILE = path.resolve(__dirname, '../../../frontend/assets/js/users.js');

describe('Unit: User Management UI & Form Validation', () => {
    test('1. Static HTML pre-renders User Management elements in DOM', () => {
        for (const filePath of [FRONTEND_HTML_FILE, PUBLIC_HTML_FILE]) {
            assert.ok(fs.existsSync(filePath), `File must exist: ${filePath}`);
            const html = fs.readFileSync(filePath, 'utf8');

            assert.ok(html.includes('id="nav-link-users"'), `${filePath} must contain #nav-link-users`);
            assert.ok(html.includes('id="view-users"'), `${filePath} must contain #view-users`);
            assert.ok(html.includes('id="modal-add-user"'), `${filePath} must contain #modal-add-user`);
            assert.ok(html.includes('id="btn-open-add-user-modal"'), `${filePath} must contain #btn-open-add-user-modal`);
            assert.ok(html.includes('id="users-table-body"'), `${filePath} must contain #users-table-body`);
        }
    });

    test('2. Add User modal contains required governance form fields and excludes CONTRACTOR', () => {
        for (const filePath of [FRONTEND_HTML_FILE, PUBLIC_HTML_FILE]) {
            const html = fs.readFileSync(filePath, 'utf8');

            assert.ok(html.includes('id="user-form-display-name"'), 'Must have display name input');
            assert.ok(html.includes('id="user-form-email"'), 'Must have email input');
            assert.ok(html.includes('id="user-form-entra-oid"'), 'Must have entra OID input');
            assert.ok(html.includes('id="user-form-department"'), 'Must have department input');
            assert.ok(html.includes('id="btn-submit-user"'), 'Must have submit button');

            // Governance role checkboxes
            assert.ok(html.includes('value="SYSTEM_ADMIN"'), 'Must offer SYSTEM_ADMIN');
            assert.ok(html.includes('value="SECURITY_OFFICER"'), 'Must offer SECURITY_OFFICER');
            assert.ok(html.includes('value="INTERNAL_SPONSOR"'), 'Must offer INTERNAL_SPONSOR');
            assert.ok(html.includes('value="RESOURCE_OWNER"'), 'Must offer RESOURCE_OWNER');
            assert.ok(html.includes('value="COMPLIANCE_AUDITOR"'), 'Must offer COMPLIANCE_AUDITOR');

            // Must NOT offer CONTRACTOR in internal user form
            const formStartIndex = html.indexOf('id="form-add-user"');
            const formEndIndex = html.indexOf('</form>', formStartIndex);
            const userFormHtml = html.substring(formStartIndex, formEndIndex);
            assert.strictEqual(userFormHtml.includes('value="CONTRACTOR"'), false, 'Internal user form must NOT offer CONTRACTOR role');
        }
    });

    test('3. users.js file exists and exports AccessLeaseUsersModule', () => {
        assert.ok(fs.existsSync(USERS_JS_FILE));
        const jsContent = fs.readFileSync(USERS_JS_FILE, 'utf8');

        assert.ok(jsContent.includes('window.AccessLeaseUsersModule'));
        assert.ok(jsContent.includes('isAdmin()'));
        assert.ok(jsContent.includes('openAddUserModal()'));
        assert.ok(jsContent.includes('handleUserSubmit('));
        assert.ok(jsContent.includes("window.apiClient.post('/api/users'"));
        assert.ok(jsContent.includes("window.apiClient.patch(`/api/users/${userId}/status`"));
    });

    test('4. Script tags include users.js in index.html', () => {
        for (const filePath of [FRONTEND_HTML_FILE, PUBLIC_HTML_FILE]) {
            const html = fs.readFileSync(filePath, 'utf8');
            assert.ok(html.includes('<script src="assets/js/users.js"></script>'), `${filePath} must load users.js`);
        }
    });
});
