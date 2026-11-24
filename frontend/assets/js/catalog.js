/**
 * AccessLease — Enterprise Resource & Entitlement Catalogue Frontend Controller
 * Pure Vanilla JavaScript (ES6+) — Zero external UI frameworks.
 */

(function (window) {
    'use strict';

    class CatalogModule {
        constructor() {
            this.currentUser = null;
            this.resourcesList = [];
            this.usersList = [];
            this.searchQuery = '';
            this.typeFilter = 'ALL';
            this.riskFilter = 'ALL';
            this.statusFilter = 'ALL';
            this.initialized = false;
            this.currentDetailsResource = null;
        }

        async init() {
            if (this.initialized) return;

            if (window.AccessLeaseAuth) {
                if (window.AccessLeaseAuth.currentUser) {
                    this.currentUser = window.AccessLeaseAuth.currentUser;
                }

                window.AccessLeaseAuth.subscribe((user) => {
                    this.currentUser = user;
                    this.updateRoleVisibility();
                    const catalogView = document.getElementById('view-catalog');
                    if (catalogView && catalogView.style.display !== 'none') {
                        this.loadCatalog();
                    }
                });
            }

            this.setupEventHandlers();
            this.initialized = true;
        }

        isAdmin() {
            if (!this.currentUser || !this.currentUser.roles) return false;
            return this.currentUser.roles.some(r => (r.role_code || r) === 'SYSTEM_ADMIN');
        }

        isResourceOwner(resource) {
            if (!this.currentUser) return false;
            if (this.isAdmin()) return true;
            if (!resource) return false;

            const myId = (this.currentUser.user_id || '').toLowerCase();
            if (resource.owner_user_id && resource.owner_user_id.toLowerCase() === myId) {
                return true;
            }
            if (resource.owners && Array.isArray(resource.owners)) {
                return resource.owners.some(o => (o.owner_user_id || '').toLowerCase() === myId);
            }
            return false;
        }

        canManageResource(resource) {
            return this.isAdmin() || this.isResourceOwner(resource);
        }

        updateRoleVisibility() {
            const btnCreate = document.getElementById('btn-open-create-resource-modal');
            if (btnCreate) {
                btnCreate.style.display = this.isAdmin() ? 'inline-flex' : 'none';
            }
        }

        setupEventHandlers() {
            // Register Resource button
            const btnCreate = document.getElementById('btn-open-create-resource-modal');
            if (btnCreate) {
                btnCreate.addEventListener('click', () => this.openCreateResourceModal());
            }

            // Search input with debounce
            const searchInput = document.getElementById('catalog-search-input');
            if (searchInput) {
                let debounceTimer;
                searchInput.addEventListener('input', (e) => {
                    clearTimeout(debounceTimer);
                    this.searchQuery = e.target.value.trim();
                    debounceTimer = setTimeout(() => this.filterAndRenderTable(), 250);
                });
            }

            // Filters
            const typeSelect = document.getElementById('catalog-type-filter');
            if (typeSelect) {
                typeSelect.addEventListener('change', (e) => {
                    this.typeFilter = e.target.value;
                    this.filterAndRenderTable();
                });
            }

            const riskSelect = document.getElementById('catalog-risk-filter');
            if (riskSelect) {
                riskSelect.addEventListener('change', (e) => {
                    this.riskFilter = e.target.value;
                    this.filterAndRenderTable();
                });
            }

            const statusSelect = document.getElementById('catalog-status-filter');
            if (statusSelect) {
                statusSelect.addEventListener('change', (e) => {
                    this.statusFilter = e.target.value;
                    this.filterAndRenderTable();
                });
            }
        }

        async loadCatalog() {
            const tableBody = document.getElementById('catalog-table-body');
            const emptyState = document.getElementById('catalog-empty-state');
            const loadingIndicator = document.getElementById('catalog-loading-indicator');

            if (loadingIndicator) loadingIndicator.style.display = 'block';
            if (emptyState) emptyState.style.display = 'none';

            try {
                // Fetch catalogue resources
                const res = await window.apiClient.listCatalogResources({ isActive: 'all' });
                this.resourcesList = res?.data?.resources || res?.data || [];

                // Pre-load internal users list for owner dropdown if admin
                if (this.isAdmin() && this.usersList.length === 0) {
                    try {
                        const usersRes = await window.apiClient.get('/api/users?limit=100&isActive=true');
                        this.usersList = usersRes?.data?.users || usersRes?.data || [];
                    } catch (e) {
                        console.warn('[AccessLeaseCatalog] Could not preload users:', e.message);
                    }
                }

                this.updateMetrics();
                this.filterAndRenderTable();
            } catch (err) {
                console.error('[AccessLeaseCatalog] Failed to load resources:', err);
                if (tableBody) {
                    tableBody.innerHTML = `
                        <tr>
                            <td colspan="7" class="text-center" style="padding: 2rem; color: #dc2626;">
                                <strong>Error loading resource catalogue:</strong> ${this.escapeHtml(err.message || 'Network error')}
                            </td>
                        </tr>
                    `;
                }
            } finally {
                if (loadingIndicator) loadingIndicator.style.display = 'none';
            }
        }

        updateMetrics() {
            const totalEl = document.getElementById('catalog-stat-total');
            const entsEl = document.getElementById('catalog-stat-entitlements');
            const critEl = document.getElementById('catalog-stat-critical');
            const cloudEl = document.getElementById('catalog-stat-cloud');

            if (totalEl) totalEl.textContent = this.resourcesList.length;

            const totalEnts = this.resourcesList.reduce((acc, r) => acc + (parseInt(r.active_entitlements_count, 10) || 0), 0);
            if (entsEl) entsEl.textContent = totalEnts;

            const critCount = this.resourcesList.filter(r => r.risk_level === 'CRITICAL' && r.is_active).length;
            if (critEl) critEl.textContent = critCount;

            const cloudCount = this.resourcesList.filter(r => (r.resource_type === 'CLOUD_SUBSCRIPTION' || r.resource_type === 'SAAS') && r.is_active).length;
            if (cloudEl) cloudEl.textContent = cloudCount;
        }

        filterAndRenderTable() {
            const tableBody = document.getElementById('catalog-table-body');
            const emptyState = document.getElementById('catalog-empty-state');
            if (!tableBody) return;

            const filtered = this.resourcesList.filter(r => {
                // Search query
                if (this.searchQuery) {
                    const q = this.searchQuery.toLowerCase();
                    const code = (r.resource_code || '').toLowerCase();
                    const name = (r.resource_name || '').toLowerCase();
                    const desc = (r.description || '').toLowerCase();
                    const owner = (r.owner_name || '').toLowerCase();
                    if (!code.includes(q) && !name.includes(q) && !desc.includes(q) && !owner.includes(q)) {
                        return false;
                    }
                }

                // Type filter
                if (this.typeFilter !== 'ALL' && r.resource_type !== this.typeFilter) {
                    return false;
                }

                // Risk filter
                if (this.riskFilter !== 'ALL' && r.risk_level !== this.riskFilter) {
                    return false;
                }

                // Status filter
                if (this.statusFilter === 'ACTIVE' && !r.is_active) return false;
                if (this.statusFilter === 'INACTIVE' && r.is_active) return false;

                return true;
            });

            if (filtered.length === 0) {
                tableBody.innerHTML = '';
                if (emptyState) emptyState.style.display = 'block';
                return;
            }

            if (emptyState) emptyState.style.display = 'none';

            tableBody.innerHTML = filtered.map(r => {
                const env = r.environment || 'PRODUCTION';
                const envBadgeClass = env === 'PRODUCTION' ? 'badge-risk-critical' : env === 'STAGING' ? 'badge-risk-high' : 'badge-risk-low';
                const riskBadgeClass = `badge-risk-${(r.risk_level || 'medium').toLowerCase()}`;
                const canManage = this.canManageResource(r);
                const isAdmin = this.isAdmin();

                return `
                    <tr class="catalog-row ${!r.is_active ? 'row-inactive' : ''}" data-id="${this.escapeHtml(r.resource_id)}">
                        <td>
                            <div class="resource-code-cell">
                                <strong class="resource-code-text">${this.escapeHtml(r.resource_code)}</strong>
                                <div class="resource-name-text">${this.escapeHtml(r.resource_name)}</div>
                            </div>
                        </td>
                        <td>
                            <div class="type-cell">
                                <span class="status-pill status-pill-neutral">${this.escapeHtml(this.formatType(r.resource_type))}</span>
                                <span class="badge-risk ${envBadgeClass}" style="font-size: 0.65rem; margin-top: 2px;">${this.escapeHtml(env)}</span>
                            </div>
                        </td>
                        <td>
                            <span class="badge-risk ${riskBadgeClass}">${this.escapeHtml(r.risk_level || 'MEDIUM')}</span>
                            ${r.requires_security_approval ? '<div class="form-help" style="font-size: 0.7rem; color: #b45309;">Requires 2-Stage Approval</div>' : ''}
                        </td>
                        <td>
                            ${r.owner_name ? `
                                <div class="owner-cell">
                                    <div class="strong" style="font-size: 0.85rem;">${this.escapeHtml(r.owner_name)}</div>
                                    <div class="form-help" style="font-size: 0.75rem;">${this.escapeHtml(r.owner_email || '')}</div>
                                </div>
                            ` : `<span class="form-help" style="font-style: italic;">Unassigned</span>`}
                        </td>
                        <td>
                            <button type="button" class="btn btn-sm btn-outline btn-view-entitlements" data-id="${this.escapeHtml(r.resource_id)}" title="Manage Entitlements">
                                <span style="font-weight: 600;">${r.active_entitlements_count || 0}</span> Active (${r.total_entitlements_count || 0} Total) &rarr;
                            </button>
                        </td>
                        <td>
                            <span class="status-pill ${r.is_active ? 'status-pill-success' : 'status-pill-warning'}">
                                ${r.is_active ? 'Active' : 'Inactive'}
                            </span>
                        </td>
                        <td>
                            <div class="table-actions-cell" style="display: flex; gap: 6px; align-items: center;">
                                <button type="button" class="btn btn-sm btn-secondary btn-resource-details" data-id="${this.escapeHtml(r.resource_id)}" title="View Full Details">
                                    Details
                                </button>
                                ${canManage ? `
                                    <button type="button" class="btn btn-sm btn-outline btn-resource-edit" data-id="${this.escapeHtml(r.resource_id)}" title="Edit Resource">
                                        Edit
                                    </button>
                                ` : ''}
                                ${isAdmin ? `
                                    <button type="button" class="btn btn-sm ${r.is_active ? 'btn-outline-danger' : 'btn-outline-success'} btn-resource-toggle-status" data-id="${this.escapeHtml(r.resource_id)}" data-active="${r.is_active}">
                                        ${r.is_active ? 'Deactivate' : 'Activate'}
                                    </button>
                                ` : ''}
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');

            // Wire row button events
            tableBody.querySelectorAll('.btn-view-entitlements, .btn-resource-details').forEach(btn => {
                btn.addEventListener('click', () => {
                    const id = btn.getAttribute('data-id');
                    this.openResourceDetailsModal(id);
                });
            });

            tableBody.querySelectorAll('.btn-resource-edit').forEach(btn => {
                btn.addEventListener('click', () => {
                    const id = btn.getAttribute('data-id');
                    this.openEditResourceModal(id);
                });
            });

            tableBody.querySelectorAll('.btn-resource-toggle-status').forEach(btn => {
                btn.addEventListener('click', () => {
                    const id = btn.getAttribute('data-id');
                    const isActive = btn.getAttribute('data-active') === 'true';
                    this.toggleResourceStatus(id, isActive);
                });
            });
        }

        formatType(type) {
            const map = {
                'SAAS': 'SaaS Application',
                'CLOUD_SUBSCRIPTION': 'Cloud Subscription',
                'DATABASE': 'Database Server',
                'REPOSITORY': 'Source Repository',
                'NETWORK_VPN': 'Corporate VPN',
                'INTERNAL_APP': 'Internal Application'
            };
            return map[type] || type || 'General Resource';
        }

        async openCreateResourceModal() {
            if (!this.isAdmin()) {
                alert('Only System Administrators are authorized to register resources.');
                return;
            }

            const modalContainer = document.getElementById('catalog-modal-container');
            if (!modalContainer) return;

            modalContainer.innerHTML = `
                <div class="modal-backdrop" id="modal-resource-form-backdrop">
                    <div class="modal-dialog modal-dialog-lg" role="dialog" aria-modal="true" aria-labelledby="modal-resource-title">
                        <div class="modal-header">
                            <h3 id="modal-resource-title">Register Enterprise Resource</h3>
                            <button type="button" class="btn-close" id="modal-resource-close" aria-label="Close">&times;</button>
                        </div>
                        <form id="form-resource-create">
                            <div class="modal-body" style="padding: 1.5rem;">
                                <div id="resource-form-error" class="error-banner" style="display: none; margin-bottom: 1rem;"></div>

                                <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                    <div class="form-group">
                                        <label class="form-label required" for="res-input-code">Resource Code</label>
                                        <input type="text" id="res-input-code" class="form-control" required placeholder="e.g. RES-PROD-KUBE" maxlength="50" style="text-transform: uppercase;">
                                        <div class="form-help">Unique uppercase identifier (alphanumeric, dashes, underscores).</div>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label required" for="res-input-name">Resource Name</label>
                                        <input type="text" id="res-input-name" class="form-control" required placeholder="e.g. Production Kubernetes Cluster" maxlength="150">
                                    </div>
                                </div>

                                <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem;">
                                    <div class="form-group">
                                        <label class="form-label required" for="res-input-type">Resource Type</label>
                                        <select id="res-input-type" class="form-select" required>
                                            <option value="SAAS">SaaS Application</option>
                                            <option value="CLOUD_SUBSCRIPTION">Cloud Subscription (AWS/Azure/GCP)</option>
                                            <option value="DATABASE">Database Server</option>
                                            <option value="REPOSITORY">Source Code Repository</option>
                                            <option value="NETWORK_VPN">Corporate Network / VPN</option>
                                            <option value="INTERNAL_APP">Internal Enterprise App</option>
                                        </select>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label required" for="res-input-env">Target Environment</label>
                                        <select id="res-input-env" class="form-select" required>
                                            <option value="PRODUCTION" selected>Production</option>
                                            <option value="STAGING">Staging</option>
                                            <option value="DEVELOPMENT">Development</option>
                                            <option value="CORPORATE">Corporate</option>
                                        </select>
                                    </div>
                                </div>

                                <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem;">
                                    <div class="form-group">
                                        <label class="form-label required" for="res-input-risk">Risk Classification</label>
                                        <select id="res-input-risk" class="form-select" required>
                                            <option value="LOW">LOW — Minimal Sensitivity</option>
                                            <option value="MEDIUM" selected>MEDIUM — Standard Business Data</option>
                                            <option value="HIGH">HIGH — Confidential / Sensitive</option>
                                            <option value="CRITICAL">CRITICAL — Mission-Critical Production</option>
                                        </select>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label required" for="res-input-duration">Max Lease Duration (Days)</label>
                                        <input type="number" id="res-input-duration" class="form-control" required min="1" max="365" value="90">
                                        <div class="form-help">Maximum duration allowed for contractor access leases.</div>
                                    </div>
                                </div>

                                <div class="form-row" style="display: grid; grid-template-columns: 1fr; gap: 1rem; margin-top: 1rem;">
                                    <div class="form-group">
                                        <label class="form-label" for="res-input-owner">Primary Resource Owner</label>
                                        <select id="res-input-owner" class="form-select">
                                            <option value="">-- Unassigned (System Admin Owned) --</option>
                                            ${this.usersList.map(u => `
                                                <option value="${this.escapeHtml(u.user_id)}">${this.escapeHtml(u.display_name)} (${this.escapeHtml(u.email)})</option>
                                            `).join('')}
                                        </select>
                                        <div class="form-help">Responsible for Stage 2 approval routing and access reviews.</div>
                                    </div>
                                </div>

                                <div class="form-group" style="margin-top: 1rem;">
                                    <label class="form-label" for="res-input-desc">Description & Governance Scope</label>
                                    <textarea id="res-input-desc" class="form-control" rows="3" placeholder="Describe the system, target workload, and usage guidelines..."></textarea>
                                </div>

                                <div class="form-group" style="margin-top: 1rem;">
                                    <label class="checkbox-label" style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                        <input type="checkbox" id="res-input-security">
                                        <span><strong>Enforce 2-Stage Security Approval</strong> (Requires mandatory Sponsor &amp; Resource Owner sign-off)</span>
                                    </label>
                                </div>
                            </div>
                            <div class="modal-footer" style="padding: 1rem 1.5rem; display: flex; justify-content: flex-end; gap: 0.5rem; border-top: 1px solid #e2e8f0;">
                                <button type="button" class="btn btn-secondary" id="modal-resource-cancel">Cancel</button>
                                <button type="submit" class="btn btn-primary" id="btn-submit-resource">Register Resource</button>
                            </div>
                        </form>
                    </div>
                </div>
            `;

            const closeModal = () => { modalContainer.innerHTML = ''; };
            document.getElementById('modal-resource-close')?.addEventListener('click', closeModal);
            document.getElementById('modal-resource-cancel')?.addEventListener('click', closeModal);

            const form = document.getElementById('form-resource-create');
            const errBanner = document.getElementById('resource-form-error');
            const submitBtn = document.getElementById('btn-submit-resource');

            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                errBanner.style.display = 'none';
                submitBtn.disabled = true;
                submitBtn.textContent = 'Registering...';

                try {
                    const payload = {
                        resourceCode: document.getElementById('res-input-code').value.trim(),
                        resourceName: document.getElementById('res-input-name').value.trim(),
                        resourceType: document.getElementById('res-input-type').value,
                        environment: document.getElementById('res-input-env').value,
                        riskLevel: document.getElementById('res-input-risk').value,
                        maxLeaseDurationDays: parseInt(document.getElementById('res-input-duration').value, 10),
                        requiresSecurityApproval: document.getElementById('res-input-security').checked,
                        primaryOwnerUserId: document.getElementById('res-input-owner').value || null,
                        description: document.getElementById('res-input-desc').value.trim()
                    };

                    await window.apiClient.createCatalogResource(payload);
                    closeModal();
                    await this.loadCatalog();
                } catch (err) {
                    errBanner.textContent = err.message || 'Failed to create resource.';
                    errBanner.style.display = 'block';
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Register Resource';
                }
            });
        }

        async openEditResourceModal(resourceId) {
            const modalContainer = document.getElementById('catalog-modal-container');
            if (!modalContainer) return;

            try {
                const res = await window.apiClient.getCatalogResource(resourceId);
                const r = res?.data?.resource || res?.data;
                if (!r) throw new Error('Resource not found.');

                const env = r.environment || 'PRODUCTION';
                const cleanDesc = r.clean_description !== undefined ? r.clean_description : (r.description || '');
                const currentOwnerId = r.primary_owner ? r.primary_owner.owner_user_id : (r.owner_user_id || '');
                const isAdmin = this.isAdmin();

                modalContainer.innerHTML = `
                    <div class="modal-backdrop" id="modal-resource-edit-backdrop">
                        <div class="modal-dialog modal-dialog-lg" role="dialog" aria-modal="true" aria-labelledby="modal-edit-title">
                            <div class="modal-header">
                                <h3 id="modal-edit-title">Edit Resource: ${this.escapeHtml(r.resource_code)}</h3>
                                <button type="button" class="btn-close" id="modal-edit-close" aria-label="Close">&times;</button>
                            </div>
                            <form id="form-resource-edit">
                                <div class="modal-body" style="padding: 1.5rem;">
                                    <div id="resource-edit-error" class="error-banner" style="display: none; margin-bottom: 1rem;"></div>

                                    <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                        <div class="form-group">
                                            <label class="form-label" for="edit-res-code">Resource Code</label>
                                            <input type="text" id="edit-res-code" class="form-control" value="${this.escapeHtml(r.resource_code)}" disabled style="background-color: #f8fafc;">
                                        </div>
                                        <div class="form-group">
                                            <label class="form-label required" for="edit-res-name">Resource Name</label>
                                            <input type="text" id="edit-res-name" class="form-control" required value="${this.escapeHtml(r.resource_name)}" maxlength="150">
                                        </div>
                                    </div>

                                    <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem;">
                                        <div class="form-group">
                                            <label class="form-label required" for="edit-res-type">Resource Type</label>
                                            <select id="edit-res-type" class="form-select" required>
                                                <option value="SAAS" ${r.resource_type === 'SAAS' ? 'selected' : ''}>SaaS Application</option>
                                                <option value="CLOUD_SUBSCRIPTION" ${r.resource_type === 'CLOUD_SUBSCRIPTION' ? 'selected' : ''}>Cloud Subscription</option>
                                                <option value="DATABASE" ${r.resource_type === 'DATABASE' ? 'selected' : ''}>Database Server</option>
                                                <option value="REPOSITORY" ${r.resource_type === 'REPOSITORY' ? 'selected' : ''}>Source Code Repository</option>
                                                <option value="NETWORK_VPN" ${r.resource_type === 'NETWORK_VPN' ? 'selected' : ''}>Corporate Network / VPN</option>
                                                <option value="INTERNAL_APP" ${r.resource_type === 'INTERNAL_APP' ? 'selected' : ''}>Internal Enterprise App</option>
                                            </select>
                                        </div>
                                        <div class="form-group">
                                            <label class="form-label required" for="edit-res-env">Environment</label>
                                            <select id="edit-res-env" class="form-select" required>
                                                <option value="PRODUCTION" ${env === 'PRODUCTION' ? 'selected' : ''}>Production</option>
                                                <option value="STAGING" ${env === 'STAGING' ? 'selected' : ''}>Staging</option>
                                                <option value="DEVELOPMENT" ${env === 'DEVELOPMENT' ? 'selected' : ''}>Development</option>
                                                <option value="CORPORATE" ${env === 'CORPORATE' ? 'selected' : ''}>Corporate</option>
                                            </select>
                                        </div>
                                    </div>

                                    <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem;">
                                        <div class="form-group">
                                            <label class="form-label required" for="edit-res-risk">Risk Classification</label>
                                            <select id="edit-res-risk" class="form-select" required>
                                                <option value="LOW" ${r.risk_level === 'LOW' ? 'selected' : ''}>LOW</option>
                                                <option value="MEDIUM" ${r.risk_level === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option>
                                                <option value="HIGH" ${r.risk_level === 'HIGH' ? 'selected' : ''}>HIGH</option>
                                                <option value="CRITICAL" ${r.risk_level === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option>
                                            </select>
                                        </div>
                                        <div class="form-group">
                                            <label class="form-label required" for="edit-res-duration">Max Lease Duration (Days)</label>
                                            <input type="number" id="edit-res-duration" class="form-control" required min="1" max="365" value="${r.max_lease_duration_days || 90}">
                                        </div>
                                    </div>

                                    ${isAdmin ? `
                                        <div class="form-row" style="margin-top: 1rem;">
                                            <div class="form-group">
                                                <label class="form-label" for="edit-res-owner">Primary Resource Owner</label>
                                                <select id="edit-res-owner" class="form-select">
                                                    <option value="">-- Unassigned --</option>
                                                    ${this.usersList.map(u => `
                                                        <option value="${this.escapeHtml(u.user_id)}" ${u.user_id === currentOwnerId ? 'selected' : ''}>${this.escapeHtml(u.display_name)} (${this.escapeHtml(u.email)})</option>
                                                    `).join('')}
                                                </select>
                                            </div>
                                        </div>
                                    ` : ''}

                                    <div class="form-group" style="margin-top: 1rem;">
                                        <label class="form-label" for="edit-res-desc">Description</label>
                                        <textarea id="edit-res-desc" class="form-control" rows="3">${this.escapeHtml(cleanDesc)}</textarea>
                                    </div>

                                    <div class="form-group" style="margin-top: 1rem;">
                                        <label class="checkbox-label" style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                            <input type="checkbox" id="edit-res-security" ${r.requires_security_approval ? 'checked' : ''}>
                                            <span><strong>Enforce 2-Stage Security Approval</strong></span>
                                        </label>
                                    </div>
                                </div>
                                <div class="modal-footer" style="padding: 1rem 1.5rem; display: flex; justify-content: flex-end; gap: 0.5rem; border-top: 1px solid #e2e8f0;">
                                    <button type="button" class="btn btn-secondary" id="modal-edit-cancel">Cancel</button>
                                    <button type="submit" class="btn btn-primary" id="btn-submit-resource-edit">Save Changes</button>
                                </div>
                            </form>
                        </div>
                    </div>
                `;

                const closeModal = () => { modalContainer.innerHTML = ''; };
                document.getElementById('modal-edit-close')?.addEventListener('click', closeModal);
                document.getElementById('modal-edit-cancel')?.addEventListener('click', closeModal);

                const form = document.getElementById('form-resource-edit');
                const errBanner = document.getElementById('resource-edit-error');
                const submitBtn = document.getElementById('btn-submit-resource-edit');

                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    errBanner.style.display = 'none';
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Saving...';

                    try {
                        const payload = {
                            resourceName: document.getElementById('edit-res-name').value.trim(),
                            resourceType: document.getElementById('edit-res-type').value,
                            environment: document.getElementById('edit-res-env').value,
                            riskLevel: document.getElementById('edit-res-risk').value,
                            maxLeaseDurationDays: parseInt(document.getElementById('edit-res-duration').value, 10),
                            requiresSecurityApproval: document.getElementById('edit-res-security').checked,
                            description: document.getElementById('edit-res-desc').value.trim()
                        };

                        if (isAdmin) {
                            payload.primaryOwnerUserId = document.getElementById('edit-res-owner')?.value || null;
                        }

                        await window.apiClient.updateCatalogResource(resourceId, payload);
                        closeModal();
                        await this.loadCatalog();
                    } catch (err) {
                        errBanner.textContent = err.message || 'Failed to update resource.';
                        errBanner.style.display = 'block';
                        submitBtn.disabled = false;
                        submitBtn.textContent = 'Save Changes';
                    }
                });
            } catch (err) {
                alert('Error opening edit modal: ' + err.message);
            }
        }

        async toggleResourceStatus(resourceId, currentActive) {
            const action = currentActive ? 'deactivate' : 'activate';
            const confirmed = confirm(`Are you sure you want to ${action} this resource? ${currentActive ? 'Contractors will no longer be able to request access to this resource.' : ''}`);
            if (!confirmed) return;

            try {
                await window.apiClient.setCatalogResourceStatus(resourceId, !currentActive);
                await this.loadCatalog();
            } catch (err) {
                alert(`Failed to ${action} resource: ` + err.message);
            }
        }

        async openResourceDetailsModal(resourceId) {
            const modalContainer = document.getElementById('catalog-modal-container');
            if (!modalContainer) return;

            try {
                const res = await window.apiClient.getCatalogResource(resourceId);
                const r = res?.data?.resource || res?.data;
                if (!r) throw new Error('Resource not found.');

                this.currentDetailsResource = r;
                const env = r.environment || 'PRODUCTION';
                const canManage = this.canManageResource(r);
                const entitlements = r.entitlements || [];

                modalContainer.innerHTML = `
                    <div class="modal-backdrop" id="modal-details-backdrop">
                        <div class="modal-dialog modal-dialog-lg" role="dialog" aria-modal="true" aria-labelledby="modal-details-title">
                            <div class="modal-header">
                                <div style="display: flex; align-items: center; gap: 8px;">
                                    <h3 id="modal-details-title">${this.escapeHtml(r.resource_name)}</h3>
                                    <span class="status-pill ${r.is_active ? 'status-pill-success' : 'status-pill-warning'}">
                                        ${r.is_active ? 'Active' : 'Inactive'}
                                    </span>
                                </div>
                                <button type="button" class="btn-close" id="modal-details-close" aria-label="Close">&times;</button>
                            </div>
                            <div class="modal-body" style="padding: 1.5rem;">
                                <!-- Summary Info Grid -->
                                <div class="identity-profile-card" style="margin-bottom: 1.5rem; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 1rem;">
                                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                                        <div>
                                            <span class="id-label" style="font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Resource Code</span>
                                            <div style="font-weight: 600; font-family: monospace;">${this.escapeHtml(r.resource_code)}</div>
                                        </div>
                                        <div>
                                            <span class="id-label" style="font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Type &amp; Environment</span>
                                            <div>${this.escapeHtml(this.formatType(r.resource_type))} &bull; <strong>${this.escapeHtml(env)}</strong></div>
                                        </div>
                                        <div>
                                            <span class="id-label" style="font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Risk Classification</span>
                                            <div><span class="badge-risk badge-risk-${(r.risk_level || 'medium').toLowerCase()}">${this.escapeHtml(r.risk_level)}</span></div>
                                        </div>
                                        <div>
                                            <span class="id-label" style="font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Max Lease Duration</span>
                                            <div>${r.max_lease_duration_days} Days</div>
                                        </div>
                                        <div style="grid-column: 1 / -1;">
                                            <span class="id-label" style="font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Primary Owner</span>
                                            <div>${r.primary_owner ? `<strong>${this.escapeHtml(r.primary_owner.owner_name)}</strong> (${this.escapeHtml(r.primary_owner.owner_email || '')})` : '<em style="color: #94a3b8;">None designated</em>'}</div>
                                        </div>
                                        ${r.clean_description ? `
                                            <div style="grid-column: 1 / -1;">
                                                <span class="id-label" style="font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Description</span>
                                                <div style="color: #334155; font-size: 0.9rem; margin-top: 2px;">${this.escapeHtml(r.clean_description)}</div>
                                            </div>
                                        ` : ''}
                                    </div>
                                </div>

                                <!-- Entitlements Section -->
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                                    <h4 style="font-size: 1.05rem; margin: 0; color: #0f172a;">Entitlements &amp; Permissions</h4>
                                    ${canManage ? `
                                        <button type="button" class="btn btn-sm btn-primary" id="btn-add-entitlement">
                                            + Add Entitlement
                                        </button>
                                    ` : ''}
                                </div>

                                <div id="entitlements-table-wrapper" style="overflow-x: auto; border: 1px solid #e2e8f0; border-radius: 6px;">
                                    <table class="data-table" style="width: 100%; font-size: 0.85rem;">
                                        <thead>
                                            <tr style="background-color: #f8fafc; border-bottom: 1px solid #e2e8f0;">
                                                <th style="padding: 8px 12px; text-align: left;">Code</th>
                                                <th style="padding: 8px 12px; text-align: left;">Entitlement Name</th>
                                                <th style="padding: 8px 12px; text-align: left;">Sensitivity</th>
                                                <th style="padding: 8px 12px; text-align: left;">Status</th>
                                                ${canManage ? '<th style="padding: 8px 12px; text-align: right;">Actions</th>' : ''}
                                            </tr>
                                        </thead>
                                        <tbody id="entitlements-tbody">
                                            ${entitlements.length === 0 ? `
                                                <tr>
                                                    <td colspan="${canManage ? 5 : 4}" style="padding: 2rem; text-align: center; color: #64748b;">
                                                        No entitlements defined for this resource yet. ${canManage ? 'Click "+ Add Entitlement" above to define permissions.' : ''}
                                                    </td>
                                                </tr>
                                            ` : entitlements.map(e => `
                                                <tr class="${!e.is_active ? 'row-inactive' : ''}">
                                                    <td style="padding: 8px 12px; font-family: monospace; font-weight: 600;">${this.escapeHtml(e.entitlement_code)}</td>
                                                    <td style="padding: 8px 12px;">
                                                        <div><strong>${this.escapeHtml(e.entitlement_name)}</strong></div>
                                                        ${e.description ? `<div style="font-size: 0.75rem; color: #64748b;">${this.escapeHtml(e.description)}</div>` : ''}
                                                    </td>
                                                    <td style="padding: 8px 12px;">
                                                        <span class="badge-risk badge-risk-${(e.sensitivity_level || 'medium').toLowerCase()}" style="font-size: 0.7rem;">
                                                            ${this.escapeHtml(e.sensitivity_level || 'MEDIUM')}
                                                        </span>
                                                    </td>
                                                    <td style="padding: 8px 12px;">
                                                        <span class="status-pill ${e.is_active ? 'status-pill-success' : 'status-pill-warning'}" style="font-size: 0.7rem;">
                                                            ${e.is_active ? 'Active' : 'Inactive'}
                                                        </span>
                                                    </td>
                                                    ${canManage ? `
                                                        <td style="padding: 8px 12px; text-align: right;">
                                                            <div style="display: flex; gap: 4px; justify-content: flex-end;">
                                                                <button type="button" class="btn btn-sm btn-outline btn-edit-ent" data-id="${this.escapeHtml(e.entitlement_id)}" title="Edit Entitlement">
                                                                    Edit
                                                                </button>
                                                                <button type="button" class="btn btn-sm ${e.is_active ? 'btn-outline-danger' : 'btn-outline-success'} btn-toggle-ent" data-id="${this.escapeHtml(e.entitlement_id)}" data-active="${e.is_active}">
                                                                    ${e.is_active ? 'Deactivate' : 'Activate'}
                                                                </button>
                                                            </div>
                                                        </td>
                                                    ` : ''}
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            <div class="modal-footer" style="padding: 1rem 1.5rem; display: flex; justify-content: flex-end; border-top: 1px solid #e2e8f0;">
                                <button type="button" class="btn btn-secondary" id="modal-details-close-btn">Close</button>
                            </div>
                        </div>
                    </div>
                `;

                const closeModal = () => { modalContainer.innerHTML = ''; };
                document.getElementById('modal-details-close')?.addEventListener('click', closeModal);
                document.getElementById('modal-details-close-btn')?.addEventListener('click', closeModal);

                // Add entitlement button
                document.getElementById('btn-add-entitlement')?.addEventListener('click', () => {
                    this.openEntitlementFormModal(resourceId, null);
                });

                // Edit entitlement buttons
                modalContainer.querySelectorAll('.btn-edit-ent').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const entId = btn.getAttribute('data-id');
                        const ent = entitlements.find(e => e.entitlement_id === entId);
                        if (ent) this.openEntitlementFormModal(resourceId, ent);
                    });
                });

                // Toggle entitlement status buttons
                modalContainer.querySelectorAll('.btn-toggle-ent').forEach(btn => {
                    btn.addEventListener('click', async () => {
                        const entId = btn.getAttribute('data-id');
                        const isActive = btn.getAttribute('data-active') === 'true';
                        await this.toggleEntitlementStatus(entId, isActive, resourceId);
                    });
                });
            } catch (err) {
                alert('Failed to load resource details: ' + err.message);
            }
        }

        async openEntitlementFormModal(resourceId, existingEntitlement = null) {
            const submodalContainer = document.getElementById('catalog-submodal-container');
            if (!submodalContainer) return;

            const isEdit = Boolean(existingEntitlement);

            submodalContainer.innerHTML = `
                <div class="modal-backdrop" id="modal-ent-form-backdrop" style="z-index: 1050;">
                    <div class="modal-dialog modal-dialog-sm" role="dialog" aria-modal="true" aria-labelledby="modal-ent-title">
                        <div class="modal-header">
                            <h3 id="modal-ent-title">${isEdit ? 'Edit Entitlement' : 'Add New Entitlement'}</h3>
                            <button type="button" class="btn-close" id="modal-ent-close" aria-label="Close">&times;</button>
                        </div>
                        <form id="form-entitlement">
                            <div class="modal-body" style="padding: 1.25rem;">
                                <div id="ent-form-error" class="error-banner" style="display: none; margin-bottom: 1rem;"></div>

                                <div class="form-group">
                                    <label class="form-label required" for="ent-input-code">Entitlement Code</label>
                                    <input type="text" id="ent-input-code" class="form-control" required ${isEdit ? 'disabled' : ''} value="${this.escapeHtml(existingEntitlement?.entitlement_code || '')}" placeholder="e.g. CLUSTER_ADMIN" maxlength="50" style="text-transform: uppercase;">
                                    <div class="form-help">Unique uppercase identifier under this resource.</div>
                                </div>

                                <div class="form-group" style="margin-top: 1rem;">
                                    <label class="form-label required" for="ent-input-name">Entitlement Name</label>
                                    <input type="text" id="ent-input-name" class="form-control" required value="${this.escapeHtml(existingEntitlement?.entitlement_name || '')}" placeholder="e.g. Kubernetes Cluster Admin" maxlength="150">
                                </div>

                                <div class="form-group" style="margin-top: 1rem;">
                                    <label class="form-label required" for="ent-input-sensitivity">Sensitivity Level</label>
                                    <select id="ent-input-sensitivity" class="form-select" required>
                                        <option value="LOW" ${existingEntitlement?.sensitivity_level === 'LOW' ? 'selected' : ''}>LOW</option>
                                        <option value="MEDIUM" ${!existingEntitlement || existingEntitlement?.sensitivity_level === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option>
                                        <option value="HIGH" ${existingEntitlement?.sensitivity_level === 'HIGH' ? 'selected' : ''}>HIGH</option>
                                        <option value="CRITICAL" ${existingEntitlement?.sensitivity_level === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option>
                                    </select>
                                </div>

                                <div class="form-group" style="margin-top: 1rem;">
                                    <label class="form-label" for="ent-input-desc">Description</label>
                                    <textarea id="ent-input-desc" class="form-control" rows="2" placeholder="Permission scope and access rights...">${this.escapeHtml(existingEntitlement?.description || '')}</textarea>
                                </div>
                            </div>
                            <div class="modal-footer" style="padding: 0.75rem 1.25rem; display: flex; justify-content: flex-end; gap: 0.5rem; border-top: 1px solid #e2e8f0;">
                                <button type="button" class="btn btn-secondary" id="modal-ent-cancel">Cancel</button>
                                <button type="submit" class="btn btn-primary" id="btn-submit-ent">${isEdit ? 'Save Changes' : 'Create Entitlement'}</button>
                            </div>
                        </form>
                    </div>
                </div>
            `;

            const closeSubmodal = () => { submodalContainer.innerHTML = ''; };
            document.getElementById('modal-ent-close')?.addEventListener('click', closeSubmodal);
            document.getElementById('modal-ent-cancel')?.addEventListener('click', closeSubmodal);

            const form = document.getElementById('form-entitlement');
            const errBanner = document.getElementById('ent-form-error');
            const submitBtn = document.getElementById('btn-submit-ent');

            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                errBanner.style.display = 'none';
                submitBtn.disabled = true;
                submitBtn.textContent = 'Saving...';

                try {
                    const payload = {
                        entitlementName: document.getElementById('ent-input-name').value.trim(),
                        sensitivityLevel: document.getElementById('ent-input-sensitivity').value,
                        description: document.getElementById('ent-input-desc').value.trim()
                    };

                    if (isEdit) {
                        await window.apiClient.updateResourceEntitlement(existingEntitlement.entitlement_id, payload);
                    } else {
                        payload.entitlementCode = document.getElementById('ent-input-code').value.trim();
                        await window.apiClient.createResourceEntitlement(resourceId, payload);
                    }

                    closeSubmodal();
                    // Refresh details modal and catalog table
                    await this.openResourceDetailsModal(resourceId);
                    await this.loadCatalog();
                } catch (err) {
                    errBanner.textContent = err.message || 'Failed to save entitlement.';
                    errBanner.style.display = 'block';
                    submitBtn.disabled = false;
                    submitBtn.textContent = isEdit ? 'Save Changes' : 'Create Entitlement';
                }
            });
        }

        async toggleEntitlementStatus(entitlementId, currentActive, resourceId) {
            const action = currentActive ? 'deactivate' : 'activate';
            const confirmed = confirm(`Are you sure you want to ${action} this entitlement?`);
            if (!confirmed) return;

            try {
                await window.apiClient.setResourceEntitlementStatus(entitlementId, !currentActive);
                await this.openResourceDetailsModal(resourceId);
                await this.loadCatalog();
            } catch (err) {
                alert(`Failed to ${action} entitlement: ` + err.message);
            }
        }

        escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }
    }

    // Export singleton
    window.AccessLeaseCatalogModule = CatalogModule;
    window.AccessLeaseCatalog = new CatalogModule();

    document.addEventListener('DOMContentLoaded', () => {
        window.AccessLeaseCatalog.init();
    });

})(window);
