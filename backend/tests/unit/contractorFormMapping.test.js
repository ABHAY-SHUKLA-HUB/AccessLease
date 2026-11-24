/**
 * AccessLease — Unit Tests: Contractor ID Mapping in New Engagement Form (contractors.js)
 * 
 * Verifies:
 * 1. Dropdown options map each contractor to their database primary key (contractor_id / user_id).
 * 2. Dropdown labels display user-friendly display_name and email format.
 * 3. Dropdown excludes inactive contractors from new engagement eligibility.
 * 4. Selection change retains the selected contractor's database primary key in form state.
 * 5. Preselected contractor ID automatically preselects option and retains ID in form state.
 * 6. Engagement submission includes selected contractor ID under exact field name contractorUserId.
 * 7. IDs are never derived from names, emails, or freeform text.
 * 8. Rejects submission with user-friendly error when no contractor is selected.
 * 9. Form contains zero manual Contractor ID text input fields.
 */

const { test, describe, beforeEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const CONTRACTORS_JS_FILE = path.resolve(__dirname, '../../public/assets/js/contractors.js');

function createMockDomEnvironment() {
    // Basic DOM node implementation for VM
    class MockElement {
        constructor(tagName = 'div', id = '') {
            this.tagName = tagName.toUpperCase();
            this.id = id;
            this.attributes = {};
            this.children = [];
            this.eventListeners = {};
            this.innerHTMLString = '';
            this.value = '';
            this.style = {};
            this.dataset = {};
            this.className = '';
            this.classList = {
                add: (c) => {},
                remove: (c) => {},
                contains: () => false
            };
        }

        reset() {
            this.value = '';
        }

        focus() {}

        appendChild(child) {
            this.children.push(child);
            return child;
        }

        get innerHTML() {
            return this.innerHTMLString;
        }

        set innerHTML(val) {
            this.innerHTMLString = val;
            this.children = this._parseHtmlSimple(val);
        }

        addEventListener(event, handler) {
            if (!this.eventListeners[event]) {
                this.eventListeners[event] = [];
            }
            this.eventListeners[event].push(handler);
        }

        async dispatchEvent(eventObj) {
            const handlers = this.eventListeners[eventObj.type] || [];
            for (const h of handlers) {
                await h(eventObj);
            }
            const onProp = `on${eventObj.type}`;
            if (typeof this[onProp] === 'function' && !handlers.includes(this[onProp])) {
                await this[onProp](eventObj);
            }
        }

        getAttribute(attr) {
            return this.attributes[attr] || null;
        }

        setAttribute(attr, val) {
            this.attributes[attr] = val;
        }

        querySelector(sel) {
            return this._findFirst(sel);
        }

        querySelectorAll(sel) {
            const results = [];
            this._findAll(sel, results);
            return results;
        }

        _findFirst(sel) {
            const all = this.querySelectorAll(sel);
            return all.length > 0 ? all[0] : null;
        }

        _findAll(sel, results) {
            for (const child of this.children) {
                if (sel.startsWith('#') && child.id === sel.slice(1)) {
                    results.push(child);
                } else if (sel.startsWith('.') && child.className.includes(sel.slice(1))) {
                    results.push(child);
                } else if (child.tagName === sel.toUpperCase()) {
                    results.push(child);
                }
                child._findAll(sel, results);
            }
        }

        _parseHtmlSimple(html) {
            const elements = [];
            // Parse <option value="...">
            const optionRegex = /<option\s+value="([^"]*)"([^>]*)>([\s\S]*?)<\/option>/gi;
            let match;
            while ((match = optionRegex.exec(html)) !== null) {
                const opt = new MockElement('option');
                opt.value = match[1];
                if (match[2].includes('selected')) {
                    opt.setAttribute('selected', 'selected');
                }
                opt.textContent = match[3].trim();
                elements.push(opt);
            }

            // Parse any tag with an id attribute
            const tagWithIdRegex = /<([a-z0-9]+)\s+([^>]*id="([^"]+)"[^>]*)>/gi;
            while ((match = tagWithIdRegex.exec(html)) !== null) {
                const tagName = match[1];
                const rawAttrs = match[2];
                const id = match[3];
                const el = new MockElement(tagName, id);
                const valMatch = /value="([^"]*)"/i.exec(rawAttrs);
                if (valMatch) el.value = valMatch[1];
                const classMatch = /class="([^"]*)"/i.exec(rawAttrs);
                if (classMatch) el.className = classMatch[1];
                const styleMatch = /style="([^"]*)"/i.exec(rawAttrs);
                if (styleMatch) {
                    const stylePairs = styleMatch[1].split(';');
                    for (const pair of stylePairs) {
                        const colonIdx = pair.indexOf(':');
                        if (colonIdx > 0) {
                            const prop = pair.slice(0, colonIdx).trim();
                            const val = pair.slice(colonIdx + 1).trim();
                            if (prop && val) {
                                el.style[prop] = val;
                            }
                        }
                    }
                }
                if (tagName.toLowerCase() === 'select') {
                    // Find closing select
                    const selectCloseRegex = new RegExp(`<select\\s+[^>]*id="${id}"[^>]*>([\\s\\S]*?)<\\/select>`, 'i');
                    const selMatch = selectCloseRegex.exec(html);
                    if (selMatch) {
                        el.children = this._parseHtmlSimple(selMatch[1]);
                        const selectedOpt = el.children.find(c => c.getAttribute('selected') === 'selected');
                        el.value = selectedOpt ? selectedOpt.value : (el.children[0]?.value || '');
                    }
                }
                elements.push(el);
            }

            return elements;
        }
    }

    const elementsById = new Map();
    const modalContainer = new MockElement('div', 'contractor-modal-container');
    const viewContainer = new MockElement('div', 'view-contractors');
    const alertContainer = new MockElement('div', 'module-alert-container');

    elementsById.set('contractor-modal-container', modalContainer);
    elementsById.set('view-contractors', viewContainer);
    elementsById.set('module-alert-container', alertContainer);

    const documentMock = {
        getElementById: (id) => {
            if (elementsById.has(id)) return elementsById.get(id);
            // Search inside modalContainer and viewContainer
            return modalContainer._findFirst(`#${id}`) || viewContainer._findFirst(`#${id}`);
        },
        querySelector: (sel) => {
            if (sel.startsWith('#')) return documentMock.getElementById(sel.slice(1));
            return modalContainer.querySelector(sel) || viewContainer.querySelector(sel);
        },
        querySelectorAll: (sel) => modalContainer.querySelectorAll(sel),
        createElement: (tag) => new MockElement(tag),
        addEventListener: () => {},
        removeEventListener: () => {}
    };

    const mockWindow = {
        document: documentMock,
        location: { origin: 'http://localhost:7071' },
        apiClient: {
            get: async () => ({ success: true, data: {} }),
            post: async () => ({ success: true, data: {} }),
            put: async () => ({ success: true, data: {} })
        },
        AccessLeaseAuth: {
            subscribe: (cb) => {
                cb({
                    user_id: 'SPONSOR-UUID-001',
                    roles: [{ role_code: 'SYSTEM_ADMIN' }]
                });
            }
        },
        console: { log: () => {}, info: () => {}, warn: () => {}, error: () => {} }
    };
    mockWindow.window = mockWindow;

    return { mockWindow, modalContainer };
}

describe('Unit: Contractor ID Mapping in New Engagement Form', () => {
    let mockWindow;
    let modalContainer;

    const sampleContractors = [
        {
            user_id: '11111111-2222-3333-4444-555555555551',
            contractor_id: '11111111-2222-3333-4444-555555555551',
            display_name: 'Sarah Connor',
            email: 'sarah.connor@cyberdyne-vendor.com',
            department: 'SecOps Contractor',
            user_type: 'CONTRACTOR',
            is_active: true
        },
        {
            user_id: '22222222-3333-4444-5555-666666666662',
            contractor_id: '22222222-3333-4444-5555-666666666662',
            display_name: 'Kyle Reese',
            email: 'kyle.reese@resistance-vendor.com',
            department: 'Network Operations',
            user_type: 'CONTRACTOR',
            is_active: true
        },
        {
            user_id: '33333333-4444-5555-6666-777777777773',
            contractor_id: '33333333-4444-5555-6666-777777777773',
            display_name: 'Miles Dyson (Deactivated)',
            email: 'miles.dyson@cyberdyne-vendor.com',
            department: 'AI Systems',
            user_type: 'CONTRACTOR',
            is_active: false // Inactive contractor
        }
    ];

    beforeEach(() => {
        const env = createMockDomEnvironment();
        mockWindow = env.mockWindow;
        modalContainer = env.modalContainer;

        const context = vm.createContext({
            window: mockWindow,
            document: mockWindow.document,
            console: mockWindow.console,
            setTimeout: globalThis.setTimeout,
            clearTimeout: globalThis.clearTimeout
        });

        const scriptSrc = fs.readFileSync(CONTRACTORS_JS_FILE, 'utf-8');
        vm.runInContext(scriptSrc, context);
    });

    test('1. Dropdown options map each active contractor to their database primary key UUID', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.contractorsList = [...sampleContractors];

        await mod.openEngagementModal();

        const selectEl = modalContainer._findFirst('#form-contractor-id');
        assert.ok(selectEl, '#form-contractor-id dropdown must exist');

        const options = selectEl.children.filter(c => c.tagName === 'OPTION');
        // 1 placeholder + 2 active contractors (Miles Dyson must be excluded)
        assert.strictEqual(options.length, 3, 'Must render placeholder option + 2 active contractors');

        const placeholder = options[0];
        assert.strictEqual(placeholder.value, '');
        assert.ok(placeholder.textContent.includes('Select an active contractor'));

        const opt1 = options[1];
        assert.strictEqual(opt1.value, '11111111-2222-3333-4444-555555555551');
        assert.strictEqual(opt1.textContent, 'Sarah Connor (sarah.connor@cyberdyne-vendor.com)');

        const opt2 = options[2];
        assert.strictEqual(opt2.value, '22222222-3333-4444-5555-666666666662');
        assert.strictEqual(opt2.textContent, 'Kyle Reese (kyle.reese@resistance-vendor.com)');
    });

    test('2. Dropdown excludes inactive contractors from new engagement creation', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.contractorsList = [...sampleContractors];

        await mod.openEngagementModal();

        const selectEl = modalContainer._findFirst('#form-contractor-id');
        const optionValues = selectEl.children.map(o => o.value);

        assert.ok(!optionValues.includes('33333333-4444-5555-6666-777777777773'), 'Inactive contractor must not appear as an option');
    });

    test('3. No manual Contractor ID text input exists in the New Engagement form', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.contractorsList = [...sampleContractors];

        await mod.openEngagementModal();

        const allInputs = modalContainer.querySelectorAll('input');
        const manualIdInput = allInputs.find(i => i.id.toLowerCase().includes('contractor') && i.tagName === 'INPUT');
        assert.strictEqual(manualIdInput, undefined, 'Form must NOT contain any manual Contractor ID text input');
    });

    test('4. Selecting a contractor updates and retains the exact database ID in form state', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.contractorsList = [...sampleContractors];

        await mod.openEngagementModal();

        const selectEl = modalContainer._findFirst('#form-contractor-id');
        assert.ok(selectEl);

        // Simulate user selecting Kyle Reese
        selectEl.value = '22222222-3333-4444-5555-666666666662';
        selectEl.dispatchEvent({ type: 'change', target: selectEl });

        assert.strictEqual(
            mod.currentEngagementFormState.contractorId,
            '22222222-3333-4444-5555-666666666662',
            'Form state must retain the selected contractor database UUID'
        );
    });

    test('5. Preselected contractor ID retains selection in dropdown and form state', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.contractorsList = [...sampleContractors];

        const preselectedId = '22222222-3333-4444-5555-666666666662';
        await mod.openEngagementModal(null, preselectedId);

        assert.strictEqual(
            mod.currentEngagementFormState.contractorId,
            preselectedId,
            'Preselected contractor ID must be stored in form state'
        );

        const selectEl = modalContainer._findFirst('#form-contractor-id');
        const selectedOpt = selectEl.children.find(c => c.getAttribute('selected') === 'selected');
        assert.ok(selectedOpt, 'Preselected contractor option must have selected attribute');
        assert.strictEqual(selectedOpt.value, preselectedId);
    });

    test('6. Form submission sends contractorUserId with the selected database ID', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.contractorsList = [...sampleContractors];

        let postedEndpoint = null;
        let postedPayload = null;

        mockWindow.apiClient.post = async (endpoint, payload) => {
            postedEndpoint = endpoint;
            postedPayload = payload;
            return { success: true, data: { engagement_id: 'ENG-NEW-01' } };
        };

        await mod.openEngagementModal();

        // Fill form fields
        const selectEl = modalContainer._findFirst('#form-contractor-id');
        selectEl.value = '11111111-2222-3333-4444-555555555551';
        selectEl.dispatchEvent({ type: 'change', target: selectEl });

        const vendorInput = modalContainer._findFirst('#form-vendor-name');
        vendorInput.value = 'Cyberdyne Systems';

        const contractRefInput = modalContainer._findFirst('#form-contract-ref');
        contractRefInput.value = 'SOW-2026-CS-001';

        const startDateInput = modalContainer._findFirst('#form-start-date');
        startDateInput.value = '2026-11-20';

        const endDateInput = modalContainer._findFirst('#form-end-date');
        endDateInput.value = '2027-05-31';

        const formEl = modalContainer._findFirst('#form-engagement');
        assert.ok(formEl);

        let preventDefaultCalled = false;
        await formEl.dispatchEvent({
            type: 'submit',
            preventDefault: () => { preventDefaultCalled = true; }
        });

        assert.strictEqual(preventDefaultCalled, true);
        assert.strictEqual(postedEndpoint, '/api/engagements');
        assert.ok(postedPayload, 'Payload must be dispatched to API client');
        assert.strictEqual(postedPayload.contractorUserId, '11111111-2222-3333-4444-555555555551');
        assert.strictEqual(postedPayload.vendorName, 'Cyberdyne Systems');
        assert.strictEqual(postedPayload.contractReference, 'SOW-2026-CS-001');
        assert.strictEqual(postedPayload.status, 'ACTIVE');

        // Confirm ID was not derived or transformed
        assert.strictEqual(
            postedPayload.contractorUserId,
            sampleContractors[0].user_id,
            'Submitted contractorUserId must exactly equal database primary key'
        );
    });

    test('7. Form submission rejects with alert if no contractor is selected', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.contractorsList = [...sampleContractors];

        let apiCalled = false;
        mockWindow.apiClient.post = async () => {
            apiCalled = true;
            return { success: true };
        };

        await mod.openEngagementModal();

        // Leave contractor select empty
        const selectEl = modalContainer._findFirst('#form-contractor-id');
        selectEl.value = '';
        selectEl.dispatchEvent({ type: 'change', target: selectEl });

        const vendorInput = modalContainer._findFirst('#form-vendor-name');
        vendorInput.value = 'Some Vendor';

        const contractRefInput = modalContainer._findFirst('#form-contract-ref');
        contractRefInput.value = 'SOW-REF-TEST';

        const startDateInput = modalContainer._findFirst('#form-start-date');
        startDateInput.value = '2026-11-20';

        const endDateInput = modalContainer._findFirst('#form-end-date');
        endDateInput.value = '2027-05-31';

        const formEl = modalContainer._findFirst('#form-engagement');
        await formEl.dispatchEvent({
            type: 'submit',
            preventDefault: () => {}
        });

        assert.strictEqual(apiCalled, false, 'API call must not be made when no contractor is selected');
        const alertBox = modalContainer._findFirst('#modal-form-alert');
        assert.ok(alertBox.textContent.includes('Please select an active contractor'));
    });

    test('8. Static HTML files (frontend & backend/public) pre-render #form-contractor-id in the live DOM', () => {
        const frontendHtmlPath = path.resolve(__dirname, '../../../frontend/index.html');
        const publicHtmlPath = path.resolve(__dirname, '../../public/index.html');

        for (const htmlPath of [frontendHtmlPath, publicHtmlPath]) {
            assert.ok(fs.existsSync(htmlPath), `File must exist: ${htmlPath}`);
            const htmlContent = fs.readFileSync(htmlPath, 'utf8');

            // 1. Must contain #contractor-modal-container
            assert.ok(
                htmlContent.includes('id="contractor-modal-container"'),
                `${path.basename(htmlPath)} must contain #contractor-modal-container`
            );

            // 2. Must contain #form-contractor-id dropdown select
            assert.ok(
                htmlContent.includes('id="form-contractor-id"'),
                `${path.basename(htmlPath)} must contain #form-contractor-id`
            );
            assert.ok(
                /<select[^>]+id="form-contractor-id"/i.test(htmlContent),
                `${path.basename(htmlPath)} must contain <select id="form-contractor-id">`
            );

            // 3. Must contain user-friendly label
            assert.ok(
                htmlContent.includes('for="form-contractor-id"'),
                `${path.basename(htmlPath)} must contain label with for="form-contractor-id"`
            );

            // 4. Must NOT contain manual contractor ID input
            assert.ok(
                !/<input[^>]+id="form-contractor-id"/i.test(htmlContent),
                `${path.basename(htmlPath)} must NOT contain manual text input for contractor ID`
            );
        }
    });

    test('9. Pre-rendered static modal retains #form-contractor-id in DOM across open and close cycles', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.contractorsList = [...sampleContractors];

        // Simulate static modal already present in DOM (as in index.html)
        modalContainer.innerHTML = `
            <div class="modal-backdrop" id="engagement-modal-backdrop" style="display: none;">
                <div class="modal-dialog">
                    <h3 id="modal-title">Register New Contractor Engagement</h3>
                    <button type="button" id="btn-close-modal">&times;</button>
                    <form id="form-engagement">
                        <div id="modal-form-alert" style="display: none;"></div>
                        <div id="form-group-contractor-select">
                            <label for="form-contractor-id">Contractor Identity</label>
                            <select id="form-contractor-id" class="form-select" required>
                                <option value="">Select an active contractor...</option>
                            </select>
                        </div>
                        <div id="form-group-contractor-static" style="display: none;">
                            <strong id="form-static-contractor-name"></strong>
                            <span id="form-static-contractor-email"></span>
                        </div>
                        <input type="text" id="form-vendor-name" value="">
                        <input type="text" id="form-contract-ref" value="">
                        <input type="date" id="form-start-date" value="2026-11-20">
                        <input type="date" id="form-end-date" value="2027-05-30">
                        <select id="form-initial-status"><option value="ACTIVE" selected>ACTIVE</option></select>
                        <button type="button" id="btn-cancel-modal">Cancel</button>
                        <button type="submit" id="btn-submit-engagement">Create Engagement</button>
                    </form>
                </div>
            </div>
        `;

        const backdropEl = modalContainer._findFirst('#engagement-modal-backdrop');
        assert.ok(backdropEl, 'Static backdrop must exist');
        assert.strictEqual(backdropEl.style.display, 'none', 'Initially modal is hidden');

        // Confirm #form-contractor-id is in the DOM before opening
        const selectBefore = modalContainer._findFirst('#form-contractor-id');
        assert.ok(selectBefore, '#form-contractor-id must be present in DOM before opening modal');

        // Open Modal
        await mod.openEngagementModal();
        assert.strictEqual(backdropEl.style.display, 'flex', 'Modal backdrop must be displayed as flex when open');

        // Options must be populated with active contractors
        const options = selectBefore.children.filter(c => c.tagName === 'OPTION');
        assert.strictEqual(options.length, 3, 'Must populate options with active contractors');
        assert.strictEqual(options[1].value, '11111111-2222-3333-4444-555555555551');
        assert.strictEqual(options[2].value, '22222222-3333-4444-5555-666666666662');

        // Select a contractor
        selectBefore.value = '11111111-2222-3333-4444-555555555551';
        selectBefore.dispatchEvent({ type: 'change', target: selectBefore });
        assert.strictEqual(mod.currentEngagementFormState.contractorId, '11111111-2222-3333-4444-555555555551');

        // Close modal via close button
        const closeBtn = modalContainer._findFirst('#btn-close-modal');
        closeBtn.dispatchEvent({ type: 'click' });

        // Verify modal is hidden, but #form-contractor-id REMAINS in the DOM
        assert.strictEqual(backdropEl.style.display, 'none', 'Modal backdrop must be hidden on close');
        const selectAfterClose = modalContainer._findFirst('#form-contractor-id');
        assert.ok(selectAfterClose, '#form-contractor-id must still exist in the DOM after modal is closed');
        assert.strictEqual(mod.currentEngagementFormState.contractorId, null, 'Form state must be reset on close');
    });

    test('10. Regression: Exact API response shape { success: true, data: { contractors: [...] } } populates 4 contractors', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.contractorsList = []; // Clear local list to force API fetch

        const apiContractors = [
            {
                contractor_id: '44444444-1111-2222-3333-444444444441',
                user_id: '44444444-1111-2222-3333-444444444441',
                display_name: 'Carlos Contractor',
                email: 'carlos@contoso-vendor.com',
                user_type: 'CONTRACTOR',
                is_active: true
            },
            {
                contractor_id: '55555555-2222-3333-4444-555555555552',
                user_id: '55555555-2222-3333-4444-555555555552',
                display_name: 'Ghost User',
                email: 'ghost1@shadow-vendor.com',
                user_type: 'CONTRACTOR',
                is_active: true
            },
            {
                contractor_id: '66666666-3333-4444-5555-666666666663',
                user_id: '66666666-3333-4444-5555-666666666663',
                display_name: 'Ghost User',
                email: 'ghost2@shadow-vendor.com',
                user_type: 'CONTRACTOR',
                is_active: true
            },
            {
                contractor_id: '77777777-4444-5555-6666-777777777774',
                user_id: '77777777-4444-5555-6666-777777777774',
                display_name: 'Uma Unmapped Contractor',
                email: 'uma@unmapped-vendor.com',
                user_type: 'CONTRACTOR',
                is_active: true
            },
            // Non-eligible records that must be filtered out
            {
                contractor_id: '88888888-5555-6666-7777-888888888885',
                user_id: '88888888-5555-6666-7777-888888888885',
                display_name: 'Inactive Bob',
                email: 'bob@vendor.com',
                user_type: 'CONTRACTOR',
                is_active: false
            },
            {
                contractor_id: '99999999-6666-7777-8888-999999999996',
                user_id: '99999999-6666-7777-8888-999999999996',
                display_name: 'Employee Alice',
                email: 'alice@company.com',
                user_type: 'INTERNAL_EMPLOYEE',
                is_active: true
            }
        ];

        // Mock exact API response structure
        mockWindow.apiClient.get = async (url) => {
            if (url.includes('/api/contractors')) {
                return {
                    success: true,
                    data: {
                        contractors: apiContractors,
                        total: 4,
                        limit: 100,
                        offset: 0
                    }
                };
            }
            return { success: true, data: {} };
        };

        let submittedPayload = null;
        mockWindow.apiClient.post = async (url, body) => {
            submittedPayload = body;
            return { success: true, data: { engagement_id: 'NEW-ENG-UUID-001' } };
        };

        await mod.openEngagementModal();

        const selectEl = modalContainer._findFirst('#form-contractor-id');
        assert.ok(selectEl, '#form-contractor-id dropdown must exist');

        const options = selectEl.children.filter(c => c.tagName === 'OPTION');
        // Must contain 1 placeholder + exactly 4 active contractors
        assert.strictEqual(options.length, 5, 'Must render placeholder option + exactly 4 active contractors');

        // Placeholder
        assert.strictEqual(options[0].value, '');
        assert.ok(options[0].textContent.includes('Select an active contractor'));

        // 1. Carlos Contractor
        assert.strictEqual(options[1].value, '44444444-1111-2222-3333-444444444441');
        assert.strictEqual(options[1].textContent, 'Carlos Contractor (carlos@contoso-vendor.com)');

        // 2. Ghost User 1
        assert.strictEqual(options[2].value, '55555555-2222-3333-4444-555555555552');
        assert.strictEqual(options[2].textContent, 'Ghost User (ghost1@shadow-vendor.com)');

        // 3. Ghost User 2 (MUST remain separate option, never merged by name or email)
        assert.strictEqual(options[3].value, '66666666-3333-4444-5555-666666666663');
        assert.strictEqual(options[3].textContent, 'Ghost User (ghost2@shadow-vendor.com)');
        assert.notStrictEqual(options[2].value, options[3].value, 'Ghost User records must have distinct database UUIDs');

        // 4. Uma Unmapped Contractor
        assert.strictEqual(options[4].value, '77777777-4444-5555-6666-777777777774');
        assert.strictEqual(options[4].textContent, 'Uma Unmapped Contractor (uma@unmapped-vendor.com)');

        // Verify inactive and non-contractor records are NOT in the dropdown
        const allOptionValues = options.map(o => o.value);
        assert.ok(!allOptionValues.includes('88888888-5555-6666-7777-888888888885'), 'Inactive contractor must be excluded');
        assert.ok(!allOptionValues.includes('99999999-6666-7777-8888-999999999996'), 'Internal employee must be excluded');

        // Verify selection updates form state (select Ghost User 2)
        selectEl.value = '66666666-3333-4444-5555-666666666663';
        await selectEl.dispatchEvent({ type: 'change', target: selectEl });
        assert.strictEqual(mod.currentEngagementFormState.contractorId, '66666666-3333-4444-5555-666666666663');

        // Fill form fields and submit
        modalContainer._findFirst('#form-vendor-name').value = 'Shadow Vendor LLC';
        modalContainer._findFirst('#form-contract-ref').value = 'SOW-GHOST-2026';
        modalContainer._findFirst('#form-start-date').value = '2026-11-20';
        modalContainer._findFirst('#form-end-date').value = '2027-05-30';

        const form = modalContainer._findFirst('#form-engagement');
        await form.dispatchEvent({ type: 'submit' });

        assert.ok(submittedPayload, 'Form submission must send payload');
        assert.strictEqual(submittedPayload.contractorUserId, '66666666-3333-4444-5555-666666666663', 'Submission payload must send contractorUserId with selected UUID');
        assert.strictEqual(submittedPayload.vendorName, 'Shadow Vendor LLC');
        assert.strictEqual(submittedPayload.contractReference, 'SOW-GHOST-2026');
    });

    test('11. Regression: Shows meaningful error and disables submission when API returns no active contractors or fails', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.contractorsList = [];

        // Case A: API returns 0 active contractors
        mockWindow.apiClient.get = async (url) => {
            return {
                success: true,
                data: {
                    contractors: [],
                    total: 0,
                    limit: 100,
                    offset: 0
                }
            };
        };

        await mod.openEngagementModal();

        const selectEl = modalContainer._findFirst('#form-contractor-id');
        const submitBtn = modalContainer._findFirst('#btn-submit-engagement');
        const alertBox = modalContainer._findFirst('#modal-form-alert');

        assert.ok(selectEl.innerHTML.includes('No eligible active contractors found'));
        assert.strictEqual(selectEl.disabled, true, 'Select must be disabled when no contractors available');
        assert.strictEqual(submitBtn.disabled, true, 'Submit button must be disabled when no contractors available');
        assert.strictEqual(alertBox.style.display, 'block', 'Alert banner must be displayed');
        assert.ok(alertBox.textContent.includes('No active contractor accounts found'));

        // Case B: API throws network error
        mockWindow.apiClient.get = async () => {
            throw new Error('Network timeout connecting to backend');
        };

        await mod.openEngagementModal();
        assert.ok(selectEl.innerHTML.includes('Failed to load contractors'));
        assert.strictEqual(selectEl.disabled, true);
        assert.strictEqual(submitBtn.disabled, true);
        assert.ok(alertBox.textContent.includes('Failed to load contractors'));
        assert.ok(alertBox.textContent.includes('Network timeout'));
    });

    test('12. Add Contractor Modal: opens modal, resets inputs, rejects non-admin', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;

        // Non-admin check
        mod.currentUser = { roles: [{ role_code: 'INTERNAL_SPONSOR' }] };
        let alertMsg = '';
        mod.showAlert = (msg) => { alertMsg = msg; };
        mod.openAddContractorModal();
        assert.ok(alertMsg.includes('Only System Administrators'), 'Must reject non-admin users');

        // Admin opens modal
        mod.currentUser = { roles: [{ role_code: 'SYSTEM_ADMIN' }] };
        mod.openAddContractorModal();

        const modalBackdrop = modalContainer._findFirst('#add-contractor-modal-backdrop');
        assert.ok(modalBackdrop, '#add-contractor-modal-backdrop must be created');
        assert.strictEqual(modalBackdrop.style.display, 'flex');

        const nameInput = modalContainer._findFirst('#add-contractor-name');
        const emailInput = modalContainer._findFirst('#add-contractor-email');
        const companyInput = modalContainer._findFirst('#add-contractor-company');
        const phoneInput = modalContainer._findFirst('#add-contractor-phone');
        assert.ok(nameInput, 'Name input must exist');
        assert.ok(emailInput, 'Email input must exist');
        assert.ok(companyInput, 'Company input must exist');
        assert.ok(phoneInput, 'Phone input must exist');

        // Close modal
        mod.closeAddContractorModal();
        assert.strictEqual(modalBackdrop.style.display, 'none');
    });

    test('13. Add Contractor: client validation, API submission, and automatic dropdown refresh', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.currentUser = { roles: [{ role_code: 'SYSTEM_ADMIN' }] };
        mod.contractorsList = [...sampleContractors];

        // First open engagement modal so dropdown exists in DOM
        await mod.openEngagementModal();
        const selectEl = modalContainer._findFirst('#form-contractor-id');
        assert.ok(selectEl, '#form-contractor-id must exist in engagement modal');

        // Open Add Contractor modal
        mod.openAddContractorModal();
        const modalBackdrop = modalContainer._findFirst('#add-contractor-modal-backdrop');
        const alertBox = modalContainer._findFirst('#modal-contractor-alert');
        const nameInput = modalContainer._findFirst('#add-contractor-name');
        const emailInput = modalContainer._findFirst('#add-contractor-email');
        const companyInput = modalContainer._findFirst('#add-contractor-company');

        // 1. Client validation: empty name
        nameInput.value = '';
        emailInput.value = 'valid@vendor.com';
        await mod.handleAddContractorSubmit(modalBackdrop);
        assert.strictEqual(alertBox.style.display, 'block');
        assert.ok(alertBox.textContent.includes('valid contractor full name'));

        // 2. Client validation: invalid email
        nameInput.value = 'John Tester';
        emailInput.value = 'invalid-email';
        await mod.handleAddContractorSubmit(modalBackdrop);
        assert.strictEqual(alertBox.style.display, 'block');
        assert.ok(alertBox.textContent.includes('valid email address'));

        // 3. Successful submission
        nameInput.value = 'John Tester';
        emailInput.value = 'john.tester@newpartner.com';
        companyInput.value = 'New Partner Tech';

        const newContractorRecord = {
            user_id: '99999999-8888-7777-6666-555555555555',
            contractor_id: '99999999-8888-7777-6666-555555555555',
            display_name: 'John Tester',
            email: 'john.tester@newpartner.com',
            department: 'New Partner Tech',
            user_type: 'CONTRACTOR',
            is_active: true
        };

        let postPayload = null;
        mockWindow.apiClient.post = async (url, data) => {
            postPayload = data;
            return {
                success: true,
                data: {
                    contractor: newContractorRecord,
                    status: 'REGISTERED'
                }
            };
        };

        // When loadContractors/populateContractorDropdown calls GET /api/contractors
        mockWindow.apiClient.get = async (url) => {
            return {
                success: true,
                data: {
                    contractors: [...sampleContractors.filter(c => c.is_active), newContractorRecord]
                }
            };
        };

        let successAlert = '';
        mod.showAlert = (msg, type) => {
            if (type === 'success') successAlert = msg;
        };

        await mod.handleAddContractorSubmit(modalBackdrop);

        // Check POST payload
        assert.ok(postPayload, 'Must call apiClient.post');
        assert.strictEqual(postPayload.name, 'John Tester');
        assert.strictEqual(postPayload.email, 'john.tester@newpartner.com');
        assert.strictEqual(postPayload.company, 'New Partner Tech');

        // Check modal closed and success alert shown
        assert.strictEqual(modalBackdrop.style.display, 'none');
        assert.ok(successAlert.includes('successfully registered'));

        // Check newly registered contractor is preselected in dropdown
        assert.strictEqual(selectEl.value, '99999999-8888-7777-6666-555555555555');
        assert.strictEqual(mod.currentEngagementFormState.contractorId, '99999999-8888-7777-6666-555555555555');
    });

    test('14. Directory Toolbar: single Add Contractor button rendered in header, duplicate toolbar button removed', () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.currentUser = { roles: [{ role_code: 'SYSTEM_ADMIN' }] };

        const viewContainer = mockWindow.document.getElementById('view-contractors');
        mod.renderInternalGovernanceView(viewContainer);

        const headerBtn = viewContainer._findFirst('#btn-open-add-contractor');
        assert.ok(headerBtn, 'Header "+ Add Contractor" button (#btn-open-add-contractor) must exist');

        const toolbarBtn = viewContainer._findFirst('#btn-open-add-contractor-toolbar');
        assert.strictEqual(toolbarBtn, null, 'Duplicate toolbar "+ Add Contractor" button (#btn-open-add-contractor-toolbar) must not exist');

        // Verify clicking the header button opens the modal
        mod.openAddContractorModal();
        const modalBackdrop = modalContainer._findFirst('#add-contractor-modal-backdrop');
        assert.ok(modalBackdrop, 'Modal backdrop must be created');
        assert.strictEqual(modalBackdrop.style.display, 'flex');
        mod.closeAddContractorModal();
    });

    test('15. Contractor Directory: strictly filters and displays only user_type CONTRACTOR records', async () => {
        const mod = mockWindow.AccessLeaseContractorModule;
        mod.currentUser = { roles: [{ role_code: 'SYSTEM_ADMIN' }] };

        const viewContainer = mockWindow.document.getElementById('view-contractors');
        mod.renderInternalGovernanceView(viewContainer);

        // Mock API response containing both CONTRACTOR and INTERNAL_EMPLOYEE records
        const mixedRecords = [
            {
                user_id: 'aaaa1111-0000-0000-0000-000000000001',
                contractor_id: 'aaaa1111-0000-0000-0000-000000000001',
                display_name: 'External Contractor Alice',
                email: 'alice@external-corp.com',
                department: 'External Engineering',
                user_type: 'CONTRACTOR',
                is_active: true
            },
            {
                user_id: 'bbbb2222-0000-0000-0000-000000000002',
                contractor_id: 'bbbb2222-0000-0000-0000-000000000002',
                display_name: 'System Administrator Bob',
                email: 'bob.admin@internal-corp.com',
                department: 'IT Admin',
                user_type: 'INTERNAL_EMPLOYEE',
                is_active: true
            },
            {
                user_id: 'cccc3333-0000-0000-0000-000000000003',
                contractor_id: 'cccc3333-0000-0000-0000-000000000003',
                display_name: 'Internal Sponsor Charlie',
                email: 'charlie.sponsor@internal-corp.com',
                department: 'Procurement',
                user_type: 'INTERNAL_EMPLOYEE',
                is_active: true
            },
            {
                user_id: 'dddd4444-0000-0000-0000-000000000004',
                contractor_id: 'dddd4444-0000-0000-0000-000000000004',
                display_name: 'External Contractor Dave',
                email: 'dave@security-vendor.com',
                department: 'SecOps',
                user_type: 'CONTRACTOR',
                is_active: true
            }
        ];

        mockWindow.apiClient.get = async (url) => {
            return {
                success: true,
                data: {
                    contractors: mixedRecords,
                    total: mixedRecords.length,
                    limit: 100,
                    offset: 0
                }
            };
        };

        await mod.loadContractors();

        // 1. contractorsList must only contain CONTRACTOR records
        assert.strictEqual(mod.contractorsList.length, 2, 'Only CONTRACTOR records must be retained in directory list');
        assert.ok(mod.contractorsList.every(c => c.user_type === 'CONTRACTOR'), 'All records must have user_type CONTRACTOR');
        assert.strictEqual(mod.contractorsList[0].display_name, 'External Contractor Alice');
        assert.strictEqual(mod.contractorsList[1].display_name, 'External Contractor Dave');

        // 2. Table HTML must render only contractor records and never internal employee records
        const tableContainer = mockWindow.document.getElementById('contractor-directory-table-container');
        assert.ok(tableContainer, 'Table container must exist');
        assert.ok(tableContainer.innerHTML.includes('External Contractor Alice'));
        assert.ok(tableContainer.innerHTML.includes('External Contractor Dave'));
        assert.ok(!tableContainer.innerHTML.includes('System Administrator Bob'), 'INTERNAL_EMPLOYEE Bob must not appear in rendered table');
        assert.ok(!tableContainer.innerHTML.includes('Internal Sponsor Charlie'), 'INTERNAL_EMPLOYEE Charlie must not appear in rendered table');

        // 3. Dropdown population must also only include CONTRACTOR records
        await mod.openEngagementModal();
        const selectEl = modalContainer._findFirst('#form-contractor-id');
        assert.ok(selectEl, 'Engagement dropdown must exist');
        const options = selectEl.children.filter(c => c.tagName === 'OPTION');
        // 1 placeholder + 2 contractors
        assert.strictEqual(options.length, 3);
        assert.strictEqual(options[1].value, 'aaaa1111-0000-0000-0000-000000000001');
        assert.strictEqual(options[2].value, 'dddd4444-0000-0000-0000-000000000004');
    });
});
