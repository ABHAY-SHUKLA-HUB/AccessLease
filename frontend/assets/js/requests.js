/**
 * AccessLease — Access Request & Multi-Stage Approval Workflow Frontend Controller
 * Rules:
 * - Pure Vanilla JavaScript (ES6+)
 * - No frontend frameworks
 * - Role-aware rendering (contractor self-service vs approver governance)
 * - Real API integration via window.apiClient
 * - Dynamic modals, timeline view, real-time validation, policy preview
 */

(function (window) {
    'use strict';

    class RequestWorkflowModule {
        constructor() {
            this.currentUser = null;
            this.requestsList = [];
            this.pendingApprovalsList = [];
            this.catalogResources = [];
            this.selectedResourceEntitlements = [];
            this.currentStatusFilter = 'ALL';
            this.initialized = false;
        }

        async init() {
            if (this.initialized) return;

            if (window.AccessLeaseAuth) {
                window.AccessLeaseAuth.onAuthStateChanged((user) => {
                    this.currentUser = user;
                    if (user) {
                        this.renderViews();
                    }
                });
            }

            this.setupEventHandlers();
            this.initialized = true;
        }

        hasRole(roleCode) {
            if (!this.currentUser || !Array.isArray(this.currentUser.roles)) return false;
            return this.currentUser.roles.some(r => r.role_code === roleCode);
        }

        hasAnyRole(roleCodes) {
            if (!this.currentUser || !Array.isArray(this.currentUser.roles)) return false;
            return this.currentUser.roles.some(r => roleCodes.includes(r.role_code));
        }

        async renderViews() {
            await Promise.all([
                this.renderRequestsView(),
                this.renderApprovalsView()
            ]);
        }

        // =====================================================================
        // 1. Requests View (#view-requests)
        // =====================================================================
        async renderRequestsView() {
            const container = document.getElementById('view-requests');
            if (!container) return;

            const isContractor = this.hasRole('CONTRACTOR');

            container.innerHTML = `
                <section class="content-card">
                    <div class="card-header-row">
                        <div>
                            <span class="badge-status">Access Request Governance</span>
                            <h2>Time-Bound Access Requests &amp; Leases</h2>
                            <p class="lead-text">
                                ${isContractor 
                                    ? 'Request time-bound contractor access to authorized enterprise systems with multi-stage approval routing.' 
                                    : 'Enterprise contractor access request directory, policy derivations, and multi-stage approval tracking.'}
                            </p>
                        </div>
                        <div class="header-actions">
                            ${isContractor ? `
                                <button id="btn-open-request-modal" class="btn btn-primary">
                                    <span aria-hidden="true">+</span> New Access Request
                                </button>
                            ` : ''}
                        </div>
                    </div>

                    <!-- Filter Bar -->
                    <div class="filter-bar" style="margin-top: 1.25rem;">
                        <div class="filter-group">
                            <label class="filter-label" for="request-status-filter">Status Filter:</label>
                            <select id="request-status-filter" class="form-select filter-select">
                                <option value="ALL">All Statuses</option>
                                <option value="PENDING_APPROVAL">Pending Approval</option>
                                <option value="APPROVED">Approved</option>
                                <option value="REJECTED">Rejected</option>
                                <option value="CANCELLED">Cancelled</option>
                            </select>
                        </div>
                        <button id="btn-refresh-requests" class="btn btn-secondary btn-sm" title="Refresh request list">
                            Refresh
                        </button>
                    </div>

                    <!-- Requests Table Container -->
                    <div id="requests-table-wrapper" class="table-container" style="margin-top: 1rem;">
                        <div class="table-loading-state">Loading access requests...</div>
                    </div>
                </section>

                <!-- Modal Container for New Request -->
                <div id="new-request-modal-container"></div>
                <!-- Modal Container for Request Details -->
                <div id="request-details-modal-container"></div>
            `;

            // Wire filter and refresh events
            const statusFilter = document.getElementById('request-status-filter');
            if (statusFilter) {
                statusFilter.value = this.currentStatusFilter;
                statusFilter.addEventListener('change', (e) => {
                    this.currentStatusFilter = e.target.value;
                    this.loadRequestsTable();
                });
            }

            const refreshBtn = document.getElementById('btn-refresh-requests');
            if (refreshBtn) {
                refreshBtn.addEventListener('click', () => this.loadRequestsTable());
            }

            const newReqBtn = document.getElementById('btn-open-request-modal');
            if (newReqBtn) {
                newReqBtn.addEventListener('click', () => this.openNewRequestModal());
            }

            await this.loadRequestsTable();
        }

        async loadRequestsTable() {
            const wrapper = document.getElementById('requests-table-wrapper');
            if (!wrapper) return;

            try {
                wrapper.innerHTML = '<div class="table-loading-state">Loading access requests...</div>';

                const filter = {};
                if (this.currentStatusFilter && this.currentStatusFilter !== 'ALL') {
                    filter.status = this.currentStatusFilter;
                }

                const res = await window.apiClient.get('/api/requests', filter);
                this.requestsList = res?.data || [];

                if (this.requestsList.length === 0) {
                    wrapper.innerHTML = `
                        <div class="empty-state-box">
                            <p>No access requests found</p>
                            <span class="sub-text">
                                ${this.hasRole('CONTRACTOR') 
                                    ? 'Click "+ New Access Request" to request access to an enterprise resource.' 
                                    : 'No contractor access requests match the selected status filter.'}
                            </span>
                        </div>
                    `;
                    return;
                }

                wrapper.innerHTML = `
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Request #</th>
                                <th>Resource &amp; Entitlement</th>
                                <th>Requested Period</th>
                                <th>Duration</th>
                                <th>Risk &amp; Stages</th>
                                <th>Status</th>
                                <th style="text-align: right;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${this.requestsList.map(req => {
                                const statusClass = this.getStatusBadgeClass(req.status);
                                const riskClass = this.getRiskBadgeClass(req.requires_security_approval ? 'HIGH' : 'LOW');
                                const startDate = this.formatDate(req.requested_start_date);
                                const endDate = this.formatDate(req.requested_end_date);
                                const isOwner = this.currentUser && req.requested_by_user_id && req.requested_by_user_id.toLowerCase() === this.currentUser.user_id.toLowerCase();
                                const canCancel = isOwner && ['SUBMITTED', 'PENDING_APPROVAL'].includes(req.status);

                                return `
                                    <tr>
                                        <td>
                                            <span class="strong font-mono">${this.escapeHtml(req.request_number)}</span>
                                            <div class="form-help">${this.formatDateTime(req.created_at)}</div>
                                        </td>
                                        <td>
                                            <div class="strong">${this.escapeHtml(req.resource_name || req.resource_code || 'Resource')}</div>
                                            <div class="form-help">Entitlement: <code>${this.escapeHtml(req.entitlement_code || 'Standard')}</code></div>
                                        </td>
                                        <td>
                                            <div>${startDate} &rarr; ${endDate}</div>
                                        </td>
                                        <td>
                                            <span>${this.calculateDurationDays(req.requested_start_date, req.requested_end_date)} days</span>
                                        </td>
                                        <td>
                                            <div style="display: flex; flex-direction: column; gap: 4px;">
                                                <span class="badge-risk ${riskClass}">
                                                    ${req.requires_security_approval ? '3 Stages (Sec Review)' : '2 Stages (Standard)'}
                                                </span>
                                            </div>
                                        </td>
                                        <td>
                                            <span class="status-pill ${statusClass}">${this.escapeHtml(req.status)}</span>
                                        </td>
                                        <td style="text-align: right;">
                                            <button class="btn btn-secondary btn-sm btn-view-request" data-id="${req.request_id}">
                                                Details
                                            </button>
                                            ${canCancel ? `
                                                <button class="btn btn-danger btn-sm btn-cancel-request" data-id="${req.request_id}" data-num="${this.escapeHtml(req.request_number)}" style="margin-left: 4px;">
                                                    Cancel
                                                </button>
                                            ` : ''}
                                        </td>
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                `;

                // Bind details & cancel clicks
                wrapper.querySelectorAll('.btn-view-request').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const id = btn.getAttribute('data-id');
                        this.openRequestDetailsModal(id);
                    });
                });

                wrapper.querySelectorAll('.btn-cancel-request').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const id = btn.getAttribute('data-id');
                        const num = btn.getAttribute('data-num');
                        this.handleCancelRequest(id, num);
                    });
                });

            } catch (err) {
                console.error('[AccessLeaseRequests] Failed to load requests:', err);
                wrapper.innerHTML = `
                    <div class="error-banner">
                        <strong>Error loading access requests:</strong> ${this.escapeHtml(err.message)}
                    </div>
                `;
            }
        }

        // =====================================================================
        // 2. Multi-Stage Approvals View (#view-approvals)
        // =====================================================================
        async renderApprovalsView() {
            const container = document.getElementById('view-approvals');
            if (!container) return;

            container.innerHTML = `
                <section class="content-card">
                    <div class="card-header-row">
                        <div>
                            <span class="badge-status">Governance Decision Queue</span>
                            <h2>Multi-Stage Approval Queue</h2>
                            <p class="lead-text">
                                Review, endorse, or reject contractor access requests assigned to your governance role.
                                Decisions require cryptographic accountability and are immutably logged to the compliance trail.
                            </p>
                        </div>
                        <div class="header-actions">
                            <button id="btn-refresh-approvals" class="btn btn-secondary btn-sm" title="Refresh approval inbox">
                                Refresh Queue
                            </button>
                        </div>
                    </div>

                    <!-- Approvals Table Container -->
                    <div id="approvals-table-wrapper" class="table-container" style="margin-top: 1.25rem;">
                        <div class="table-loading-state">Checking pending approvals queue...</div>
                    </div>
                </section>

                <!-- Modal Container for Approver Decision -->
                <div id="approval-decision-modal-container"></div>
            `;

            const refreshBtn = document.getElementById('btn-refresh-approvals');
            if (refreshBtn) {
                refreshBtn.addEventListener('click', () => this.loadApprovalsTable());
            }

            await this.loadApprovalsTable();
        }

        async loadApprovalsTable() {
            const wrapper = document.getElementById('approvals-table-wrapper');
            if (!wrapper) return;

            try {
                wrapper.innerHTML = '<div class="table-loading-state">Checking pending approvals queue...</div>';

                const res = await window.apiClient.get('/api/approvals/pending');
                this.pendingApprovalsList = res?.data || [];

                if (this.pendingApprovalsList.length === 0) {
                    wrapper.innerHTML = `
                        <div class="empty-state-box">
                            <p>No Pending Approvals</p>
                            <span class="sub-text">You have no active approval requests awaiting your decision at this time.</span>
                        </div>
                    `;
                    return;
                }

                wrapper.innerHTML = `
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Request #</th>
                                <th>Requester</th>
                                <th>Resource &amp; Entitlement</th>
                                <th>Approval Stage</th>
                                <th>Requested Period</th>
                                <th>Risk Level</th>
                                <th style="text-align: right;">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${this.pendingApprovalsList.map(step => {
                                const stageName = this.getStepTypeLabel(step.step_type, step.step_number);
                                const riskClass = this.getRiskBadgeClass(step.resource_risk || 'MEDIUM');
                                const startDate = this.formatDate(step.requested_start_date);
                                const endDate = this.formatDate(step.requested_end_date);

                                return `
                                    <tr>
                                        <td>
                                            <span class="strong font-mono">${this.escapeHtml(step.request_number)}</span>
                                            <div class="form-help">${this.formatDateTime(step.created_at)}</div>
                                        </td>
                                        <td>
                                            <div class="strong">${this.escapeHtml(step.contractor_name || 'Contractor')}</div>
                                            <div class="form-help">${this.escapeHtml(step.contractor_email || '')}</div>
                                        </td>
                                        <td>
                                            <div class="strong">${this.escapeHtml(step.resource_name || step.resource_code || 'Resource')}</div>
                                            <div class="form-help">Entitlement: <code>${this.escapeHtml(step.entitlement_code || 'Access')}</code></div>
                                        </td>
                                        <td>
                                            <span class="stage-pill status-pending">${stageName}</span>
                                        </td>
                                        <td>
                                            <div>${startDate} &rarr; ${endDate}</div>
                                            <div class="form-help">${this.calculateDurationDays(step.requested_start_date, step.requested_end_date)} days</div>
                                        </td>
                                        <td>
                                            <span class="badge-risk ${riskClass}">
                                                ${this.escapeHtml(step.resource_risk || 'MEDIUM')}
                                            </span>
                                        </td>
                                        <td style="text-align: right;">
                                            <button class="btn btn-primary btn-sm btn-review-approval" data-id="${step.approval_step_id}" data-reqid="${step.request_id}">
                                                Review &amp; Decide
                                            </button>
                                        </td>
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                `;

                wrapper.querySelectorAll('.btn-review-approval').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const stepId = btn.getAttribute('data-id');
                        const reqId = btn.getAttribute('data-reqid');
                        this.openApprovalDecisionModal(stepId, reqId);
                    });
                });

            } catch (err) {
                console.error('[AccessLeaseApprovals] Failed to load pending approvals:', err);
                wrapper.innerHTML = `
                    <div class="error-banner">
                        <strong>Error loading pending approvals:</strong> ${this.escapeHtml(err.message)}
                    </div>
                `;
            }
        }

        // =====================================================================
        // 3. Modals & Actions
        // =====================================================================

        async openNewRequestModal() {
            const container = document.getElementById('new-request-modal-container');
            if (!container) return;

            try {
                // Fetch catalog resources
                const catRes = await window.apiClient.get('/api/catalog/resources');
                this.catalogResources = catRes?.data || [];
            } catch (e) {
                alert('Failed to load resource catalog: ' + e.message);
                return;
            }

            const tomorrow = new Date();
            tomorrow.setDate(tomorrow.getDate() + 1);
            const defaultStartStr = tomorrow.toISOString().split('T')[0];

            const defaultEnd = new Date();
            defaultEnd.setDate(defaultEnd.getDate() + 14);
            const defaultEndStr = defaultEnd.toISOString().split('T')[0];

            container.innerHTML = `
                <div class="modal-backdrop" id="modal-new-request">
                    <div class="modal-dialog" style="max-width: 650px;">
                        <div class="modal-header">
                            <div>
                                <h3 class="modal-title">New Access Lease Request</h3>
                                <div class="form-help">Submit time-bound access request with automated multi-stage governance routing.</div>
                            </div>
                            <button type="button" class="btn-close" id="btn-close-new-request-modal">&times;</button>
                        </div>
                        <form id="form-new-request" class="modal-body">
                            <div id="new-request-error-banner" class="error-banner" style="display: none; margin-bottom: 1rem;"></div>

                            <!-- Resource Selection -->
                            <div class="form-group">
                                <label class="form-label required" for="req-resource-select">Target Resource</label>
                                <select id="req-resource-select" class="form-select" required>
                                    <option value="">-- Select Enterprise Resource --</option>
                                    ${this.catalogResources.map(r => `
                                        <option value="${r.resource_id}" data-max="${r.max_lease_duration_days || 90}" data-risk="${r.risk_level}" data-sec="${r.requires_security_approval ? '1' : '0'}">
                                            ${this.escapeHtml(r.resource_name)} (${r.resource_code}) — [${r.risk_level} Risk, Max ${r.max_lease_duration_days}d]
                                        </option>
                                    `).join('')}
                                </select>
                                <span class="form-help">Select the protected resource system you require access to.</span>
                            </div>

                            <!-- Entitlement Selection -->
                            <div class="form-group">
                                <label class="form-label required" for="req-entitlement-select">Requested Entitlement / Role</label>
                                <select id="req-entitlement-select" class="form-select" required disabled>
                                    <option value="">-- Select Resource First --</option>
                                </select>
                                <span class="form-help">Entitlements define the permission boundary and data classification scope.</span>
                            </div>

                            <!-- Dates Row -->
                            <div class="form-row">
                                <div class="col-half">
                                    <label class="form-label required" for="req-start-date">Requested Start Date</label>
                                    <input type="date" id="req-start-date" class="form-input" value="${defaultStartStr}" required>
                                </div>
                                <div class="col-half">
                                    <label class="form-label required" for="req-end-date">Requested End Date</label>
                                    <input type="date" id="req-end-date" class="form-input" value="${defaultEndStr}" required>
                                </div>
                            </div>

                            <!-- Duration Counter & Policy Preview -->
                            <div id="policy-preview-box" class="policy-evaluation-box" style="display: none;">
                                <h4>Governance Policy Evaluation</h4>
                                <div id="policy-duration-text" style="font-weight: 600; margin-bottom: 4px;">Duration: 14 days</div>
                                <div id="policy-stages-preview">Estimated Stages: Sponsor &rarr; Resource Owner</div>
                            </div>

                            <!-- Justification -->
                            <div class="form-group">
                                <label class="form-label required" for="req-justification">Business Justification</label>
                                <textarea id="req-justification" class="form-textarea" rows="3" required minlength="10" maxlength="1000" placeholder="Provide specific business context, work item tickets, or project objectives necessitating this access lease..."></textarea>
                                <span class="form-help">Mandatory for audit trail and compliance verification (minimum 10 characters).</span>
                            </div>

                            <div class="modal-actions" style="margin-top: 1.5rem; display: flex; justify-content: flex-end; gap: 0.5rem;">
                                <button type="button" class="btn btn-secondary" id="btn-cancel-new-request">Cancel</button>
                                <button type="submit" class="btn btn-primary" id="btn-submit-new-request">Submit Access Request</button>
                            </div>
                        </form>
                    </div>
                </div>
            `;

            // Setup listeners
            const modal = document.getElementById('modal-new-request');
            const closeBtn = document.getElementById('btn-close-new-request-modal');
            const cancelBtn = document.getElementById('btn-cancel-new-request');
            const resourceSelect = document.getElementById('req-resource-select');
            const entitlementSelect = document.getElementById('req-entitlement-select');
            const startDateInput = document.getElementById('req-start-date');
            const endDateInput = document.getElementById('req-end-date');
            const form = document.getElementById('form-new-request');

            const closeModal = () => { container.innerHTML = ''; };
            closeBtn.addEventListener('click', closeModal);
            cancelBtn.addEventListener('click', closeModal);

            // Handle resource selection change -> fetch entitlements
            resourceSelect.addEventListener('change', async (e) => {
                const resId = e.target.value;
                if (!resId) {
                    entitlementSelect.innerHTML = '<option value="">-- Select Resource First --</option>';
                    entitlementSelect.disabled = true;
                    this.updatePolicyPreview();
                    return;
                }

                entitlementSelect.disabled = true;
                entitlementSelect.innerHTML = '<option value="">Loading entitlements...</option>';

                try {
                    const entRes = await window.apiClient.get(`/api/catalog/resources/${resId}/entitlements`);
                    this.selectedResourceEntitlements = entRes?.data || [];

                    if (this.selectedResourceEntitlements.length === 0) {
                        entitlementSelect.innerHTML = '<option value="">No active entitlements found</option>';
                    } else {
                        entitlementSelect.innerHTML = `
                            <option value="">-- Select Entitlement --</option>
                            ${this.selectedResourceEntitlements.map(ent => `
                                <option value="${ent.entitlement_id}" data-sens="${ent.sensitivity_level}">
                                    ${this.escapeHtml(ent.entitlement_name)} (${ent.entitlement_code}) — [${ent.sensitivity_level} Sensitivity]
                                </option>
                            `).join('')}
                        `;
                        entitlementSelect.disabled = false;
                    }
                } catch (err) {
                    entitlementSelect.innerHTML = '<option value="">Error loading entitlements</option>';
                }

                this.updatePolicyPreview();
            });

            entitlementSelect.addEventListener('change', () => this.updatePolicyPreview());
            startDateInput.addEventListener('change', () => this.updatePolicyPreview());
            endDateInput.addEventListener('change', () => this.updatePolicyPreview());

            // Handle form submission
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const errBanner = document.getElementById('new-request-error-banner');
                const submitBtn = document.getElementById('btn-submit-new-request');

                errBanner.style.display = 'none';
                submitBtn.disabled = true;
                submitBtn.textContent = 'Submitting...';

                try {
                    const resourceId = resourceSelect.value;
                    const entitlementId = entitlementSelect.value;
                    const requestedStartDate = startDateInput.value;
                    const requestedEndDate = endDateInput.value;
                    const businessJustification = document.getElementById('req-justification').value;

                    await window.apiClient.post('/api/requests', {
                        resourceId,
                        entitlementId,
                        requestedStartDate,
                        requestedEndDate,
                        businessJustification
                    });

                    closeModal();
                    await this.loadRequestsTable();
                } catch (err) {
                    errBanner.textContent = err.message || 'Failed to submit request.';
                    errBanner.style.display = 'block';
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Submit Access Request';
                }
            });
        }

        updatePolicyPreview() {
            const previewBox = document.getElementById('policy-preview-box');
            const durationText = document.getElementById('policy-duration-text');
            const stagesPreview = document.getElementById('policy-stages-preview');
            const resourceSelect = document.getElementById('req-resource-select');
            const entitlementSelect = document.getElementById('req-entitlement-select');
            const startDateInput = document.getElementById('req-start-date');
            const endDateInput = document.getElementById('req-end-date');

            if (!previewBox) return;

            const resOption = resourceSelect.selectedOptions[0];
            const entOption = entitlementSelect.selectedOptions[0];

            if (!resOption || !resOption.value) {
                previewBox.style.display = 'none';
                return;
            }

            const maxDays = parseInt(resOption.getAttribute('data-max') || '90', 10);
            const resRisk = resOption.getAttribute('data-risk') || 'LOW';
            const requiresSec = resOption.getAttribute('data-sec') === '1';
            const entSens = entOption?.getAttribute('data-sens') || 'LOW';

            const start = new Date(startDateInput.value);
            const end = new Date(endDateInput.value);
            let days = 0;
            if (!isNaN(start.getTime()) && !isNaN(end.getTime()) && end > start) {
                days = Math.ceil((end - start) / (1000 * 60 * 60 * 24));
            }

            const isHighRisk = ['HIGH', 'CRITICAL'].includes(resRisk) || ['HIGH', 'CRITICAL'].includes(entSens) || requiresSec || (days > 60 && resRisk !== 'LOW');

            durationText.innerHTML = `Duration: <strong>${days} days</strong> (Resource max allowed: ${maxDays} days)`;
            if (days > maxDays) {
                durationText.innerHTML += ` <span style="color: #dc2626; font-weight: bold;">(EXCEEDS MAX CAP)</span>`;
            }

            if (isHighRisk) {
                previewBox.className = 'policy-evaluation-box requires-security';
                stagesPreview.innerHTML = `
                    Estimated Stages: <strong>3 Stages</strong>
                    <ul>
                        <li>Stage 1: Internal Business Sponsor Approval</li>
                        <li>Stage 2: Resource Owner Approval</li>
                        <li>Stage 3: <strong>Security Officer Approval (Triggered: High Risk / Elevated Privileges)</strong></li>
                    </ul>
                `;
            } else {
                previewBox.className = 'policy-evaluation-box';
                stagesPreview.innerHTML = `
                    Estimated Stages: <strong>2 Stages</strong>
                    <ul>
                        <li>Stage 1: Internal Business Sponsor Approval</li>
                        <li>Stage 2: Resource Owner Approval</li>
                    </ul>
                `;
            }

            previewBox.style.display = 'block';
        }

        async openRequestDetailsModal(requestId) {
            const container = document.getElementById('request-details-modal-container');
            if (!container) return;

            container.innerHTML = `
                <div class="modal-backdrop" id="modal-request-details">
                    <div class="modal-dialog" style="max-width: 700px;">
                        <div class="modal-header">
                            <div>
                                <h3 class="modal-title">Access Request Details</h3>
                                <div class="form-help">Sequential governance verification and immutable approval audit trail.</div>
                            </div>
                            <button type="button" class="btn-close" id="btn-close-details-modal">&times;</button>
                        </div>
                        <div class="modal-body">
                            <div class="table-loading-state">Loading request details...</div>
                        </div>
                    </div>
                </div>
            `;

            const modal = document.getElementById('modal-request-details');
            const closeBtn = document.getElementById('btn-close-details-modal');
            const closeModal = () => { container.innerHTML = ''; };
            closeBtn.addEventListener('click', closeModal);

            try {
                const res = await window.apiClient.get(`/api/requests/${requestId}`);
                const req = res?.data;
                if (!req) throw new Error('Request not found');

                const statusClass = this.getStatusBadgeClass(req.status);
                const steps = req.approval_steps || [];

                let provisioningHtml = '';
                if (req.status === 'APPROVED') {
                    try {
                        const provRes = await window.apiClient.getProvisioningState(requestId);
                        const provData = provRes?.data;
                        if (provData && provData.target_mapping) {
                            const isProvActive = provData.grant?.status === 'ACTIVE';
                            const isProvPending = provData.grant?.status === 'PENDING_ACCEPTANCE';
                            const isProvFailed = provData.grant?.status === 'PROVISIONING_FAILED' || provData.job?.status === 'PERMANENT_FAILURE';
                            const isProvInProgress = provData.grant?.status === 'PROVISIONING_IN_PROGRESS' || provData.job?.status === 'PROCESSING' || provData.job?.status === 'QUEUED';

                            let pillClass = 'status-pending';
                            let pillLabel = 'Provisioning Queued';
                            if (isProvActive) {
                                pillClass = 'status-approved';
                                pillLabel = 'Access Active & Verified';
                            } else if (isProvPending) {
                                pillClass = 'status-skipped';
                                pillLabel = 'Invitation Awaiting Acceptance';
                            } else if (isProvFailed) {
                                pillClass = 'status-rejected';
                                pillLabel = 'Provisioning Failed';
                            } else if (isProvInProgress) {
                                pillClass = 'status-pending';
                                pillLabel = 'Provisioning In Progress';
                            }

                            const canRetry = (this.hasRole('SYSTEM_ADMIN') || this.hasRole('SECURITY_OFFICER')) && provData.job && provData.job.status !== 'SUCCEEDED';

                            provisioningHtml = `
                                <div class="form-group" style="margin-top: 1.5rem; padding: 1.25rem; border-radius: 8px; border: 1px solid #cbd5e1; background: #f8fafc;">
                                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                                        <div style="display: flex; align-items: center; gap: 8px;">
                                            <span style="font-weight: 700; font-size: 0.95rem; color: #1e293b;">Automated GitHub Team Provisioning</span>
                                            <span style="font-size: 0.75rem; background: #e2e8f0; color: #475569; padding: 2px 6px; border-radius: 4px; font-weight: 600;">GitHub App</span>
                                        </div>
                                        <span class="status-pill ${pillClass}">${pillLabel}</span>
                                    </div>

                                    <div class="identity-details-grid" style="grid-template-columns: repeat(2, 1fr); gap: 0.75rem; margin-bottom: 1rem; font-size: 0.85rem;">
                                        <div>
                                            <span class="id-label">Target Organization</span>
                                            <span class="id-value font-mono"><strong>${this.escapeHtml(provData.target_mapping.github_org)}</strong></span>
                                        </div>
                                        <div>
                                            <span class="id-label">Target Team</span>
                                            <span class="id-value font-mono">@${this.escapeHtml(provData.target_mapping.github_team_slug)}</span>
                                        </div>
                                        <div>
                                            <span class="id-label">Target Repository</span>
                                            <span class="id-value font-mono">${this.escapeHtml(provData.target_mapping.github_repo)} (${this.escapeHtml(provData.target_mapping.required_permission)})</span>
                                        </div>
                                        <div>
                                            <span class="id-label">Verified Contractor GitHub ID</span>
                                            <span class="id-value">
                                                ${provData.contractor.verified_github_username
                                                    ? `<strong style="color: #0284c7;">@${this.escapeHtml(provData.contractor.verified_github_username)}</strong> <span style="color: #16a34a;">&#10003; Verified</span>`
                                                    : `<span style="color: #dc2626;">&#10007; Not Linked (${this.escapeHtml(provData.contractor.identity_verification_status)})</span>`}
                                            </span>
                                        </div>
                                    </div>

                                    ${isProvActive ? `
                                        <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 0.75rem; margin-bottom: 0.75rem; font-size: 0.85rem;">
                                            <div style="font-weight: 600; color: #15803d; margin-bottom: 2px;">Confirmed Active GitHub Membership</div>
                                            <div style="color: #166534;">Grant <strong>${this.escapeHtml(provData.grant?.grant_number || '—')}</strong> is active and verified. Provenance: <em>${provData.grant?.membership_provenance === 'PRE_EXISTING_ADOPTED' ? 'Pre-Existing Membership Adopted' : 'Created & Provisioned by AccessLease'}</em>.</div>
                                            <div style="margin-top: 6px;">
                                                <a href="https://github.com/orgs/${encodeURIComponent(provData.target_mapping.github_org)}/teams/${encodeURIComponent(provData.target_mapping.github_team_slug)}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm" style="display: inline-block;">
                                                    View Team on GitHub &rarr;
                                                </a>
                                            </div>
                                        </div>
                                    ` : ''}

                                    ${isProvPending ? `
                                        <div style="background: #fffbeb; border: 1px solid #fde68a; border-radius: 6px; padding: 0.75rem; margin-bottom: 0.75rem; font-size: 0.85rem;">
                                            <div style="font-weight: 600; color: #b45309; margin-bottom: 2px;">Invitation Pending Acceptance</div>
                                            <div style="color: #92400e;">GitHub sent a team invitation to @${this.escapeHtml(provData.contractor.verified_github_username)}. The contractor must accept the invitation at <a href="https://github.com/orgs/${encodeURIComponent(provData.target_mapping.github_org)}/teams/${encodeURIComponent(provData.target_mapping.github_team_slug)}" target="_blank" rel="noopener noreferrer" style="color: #b45309; text-decoration: underline;">GitHub</a> to complete access activation.</div>
                                        </div>
                                    ` : ''}

                                    ${isProvFailed ? `
                                        <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 0.75rem; margin-bottom: 0.75rem; font-size: 0.85rem;">
                                            <div style="font-weight: 600; color: #b91c1c; margin-bottom: 2px;">Provisioning Failed: [${this.escapeHtml(provData.job?.last_error_category || provData.grant?.failure_category || 'ERROR')}]</div>
                                            <div style="color: #991b1b;">${this.escapeHtml(provData.job?.last_error_message || 'Provisioning operation could not be completed.')}</div>
                                            ${canRetry ? `
                                                <div style="margin-top: 8px;">
                                                    <button type="button" id="btn-manual-retry-prov" class="btn btn-danger btn-sm" data-jobid="${provData.job?.job_id}">
                                                        Retry Provisioning Job
                                                    </button>
                                                </div>
                                            ` : ''}
                                        </div>
                                    ` : ''}

                                    ${!provData.job ? `
                                        <div style="margin-top: 0.75rem;">
                                            <button type="button" id="btn-trigger-start-prov" class="btn btn-primary btn-sm">
                                                Start Provisioning Operation
                                            </button>
                                        </div>
                                    ` : ''}
                                </div>
                            `;
                        }
                    } catch (provErr) {
                        console.warn('[AccessLease] Could not fetch provisioning state:', provErr.message);
                    }
                }

                modal.querySelector('.modal-body').innerHTML = `
                    <!-- Request Overview Grid -->
                    <div class="identity-details-grid" style="margin-bottom: 1.25rem;">
                        <div class="identity-item">
                            <span class="id-label">Request Number</span>
                            <span class="id-value strong font-mono">${this.escapeHtml(req.request_number)}</span>
                        </div>
                        <div class="identity-item">
                            <span class="id-label">Request Status</span>
                            <div><span class="status-pill ${statusClass}">${this.escapeHtml(req.status)}</span></div>
                        </div>
                        <div class="identity-item">
                            <span class="id-label">Target Resource</span>
                            <span class="id-value strong">${this.escapeHtml(req.resource_name || req.resource_code || '—')}</span>
                        </div>
                        <div class="identity-item">
                            <span class="id-label">Requested Entitlement</span>
                            <span class="id-value"><code>${this.escapeHtml(req.entitlement_code || '—')}</code></span>
                        </div>
                        <div class="identity-item">
                            <span class="id-label">Validity Period</span>
                            <span class="id-value">${this.formatDate(req.requested_start_date)} &rarr; ${this.formatDate(req.requested_end_date)}</span>
                        </div>
                        <div class="identity-item">
                            <span class="id-label">Lease Duration</span>
                            <span class="id-value">${this.calculateDurationDays(req.requested_start_date, req.requested_end_date)} days</span>
                        </div>
                    </div>

                    <!-- Business Justification -->
                    <div class="form-group" style="margin-bottom: 1.5rem;">
                        <span class="id-label">Business Justification</span>
                        <div class="form-static-value" style="font-style: italic;">
                            ${this.escapeHtml(req.business_justification || 'No justification recorded.')}
                        </div>
                    </div>

                    <!-- Multi-Stage Approval Timeline -->
                    <div class="form-group">
                        <span class="id-label" style="margin-bottom: 0.75rem; display: block;">Sequential Multi-Stage Approval Steps</span>
                        ${steps.length === 0 ? '<p class="form-help">No approval steps generated.</p>' : steps.map(step => {
                            const isPending = step.status === 'PENDING';
                            const isApproved = step.status === 'APPROVED';
                            const isRejected = step.status === 'REJECTED';
                            const isSkipped = step.status === 'SKIPPED';
                            const pillClass = isApproved ? 'status-approved' : (isRejected ? 'status-rejected' : (isSkipped ? 'status-skipped' : 'status-pending'));

                            return `
                                <div class="timeline-card ${isPending ? 'current-step' : ''}">
                                    <div class="timeline-card-header">
                                        <div class="timeline-step-title">
                                            Stage ${step.step_number}: ${this.getStepTypeLabel(step.step_type, step.step_number)}
                                        </div>
                                        <span class="stage-pill ${pillClass}">${this.escapeHtml(step.status)}</span>
                                    </div>
                                    <div class="timeline-step-meta">
                                        Approver: <strong>${this.escapeHtml(step.assigned_approver_name || step.assigned_approver_email || 'Assigned Governance Role')}</strong>
                                        ${step.decided_at ? ` &bull; Decided: ${this.formatDateTime(step.decided_at)}` : ''}
                                    </div>
                                    ${step.decision_comments ? `
                                        <div class="timeline-step-comments">
                                            &ldquo;${this.escapeHtml(step.decision_comments)}&rdquo;
                                        </div>
                                    ` : ''}
                                </div>
                            `;
                        }).join('')}
                    </div>

                    ${provisioningHtml}

                    <div class="modal-actions" style="margin-top: 1.5rem; display: flex; justify-content: flex-end;">
                        <button type="button" class="btn btn-secondary" id="btn-close-details-action">Close</button>
                    </div>
                `;

                modal.querySelector('#btn-close-details-action').addEventListener('click', closeModal);

                // Provisioning Action Handlers
                const startProvBtn = modal.querySelector('#btn-trigger-start-prov');
                if (startProvBtn) {
                    startProvBtn.addEventListener('click', async () => {
                        startProvBtn.disabled = true;
                        startProvBtn.textContent = 'Initiating...';
                        try {
                            await window.apiClient.startProvisioning(requestId);
                            closeModal();
                            this.openRequestDetailsModal(requestId);
                        } catch (e) {
                            alert('Failed to start provisioning: ' + e.message);
                            startProvBtn.disabled = false;
                            startProvBtn.textContent = 'Start Provisioning Operation';
                        }
                    });
                }

                const retryProvBtn = modal.querySelector('#btn-manual-retry-prov');
                if (retryProvBtn) {
                    retryProvBtn.addEventListener('click', async () => {
                        const jobId = retryProvBtn.getAttribute('data-jobid');
                        retryProvBtn.disabled = true;
                        retryProvBtn.textContent = 'Retrying...';
                        try {
                            await window.apiClient.retryProvisioningJob(jobId);
                            closeModal();
                            this.openRequestDetailsModal(requestId);
                        } catch (e) {
                            alert('Failed to retry provisioning job: ' + e.message);
                            retryProvBtn.disabled = false;
                            retryProvBtn.textContent = 'Retry Provisioning Job';
                        }
                    });
                }

            } catch (err) {
                modal.querySelector('.modal-body').innerHTML = `
                    <div class="error-banner">
                        <strong>Error loading request details:</strong> ${this.escapeHtml(err.message)}
                    </div>
                `;
            }
        }

        async openApprovalDecisionModal(stepId, requestId) {
            const container = document.getElementById('approval-decision-modal-container');
            if (!container) return;

            container.innerHTML = `
                <div class="modal-backdrop" id="modal-approval-decision">
                    <div class="modal-dialog" style="max-width: 650px;">
                        <div class="modal-header">
                            <div>
                                <h3 class="modal-title">Review &amp; Decide Access Request</h3>
                                <div class="form-help">Cryptographically accountable decision logged to compliance trail.</div>
                            </div>
                            <button type="button" class="btn-close" id="btn-close-decision-modal">&times;</button>
                        </div>
                        <div class="modal-body">
                            <div class="table-loading-state">Loading request details for decision...</div>
                        </div>
                    </div>
                </div>
            `;

            const modal = document.getElementById('modal-approval-decision');
            const closeBtn = document.getElementById('btn-close-decision-modal');
            const closeModal = () => { container.innerHTML = ''; };
            closeBtn.addEventListener('click', closeModal);

            try {
                const res = await window.apiClient.get(`/api/requests/${requestId}`);
                const req = res?.data;
                if (!req) throw new Error('Request not found');

                const currentStep = (req.approval_steps || []).find(s => s.approval_step_id === stepId) || {};
                const stageLabel = this.getStepTypeLabel(currentStep.step_type, currentStep.step_number);

                modal.querySelector('.modal-body').innerHTML = `
                    <div id="decision-error-banner" class="error-banner" style="display: none; margin-bottom: 1rem;"></div>

                    <!-- Summary Grid -->
                    <div class="identity-details-grid" style="margin-bottom: 1.25rem;">
                        <div class="identity-item">
                            <span class="id-label">Request Number</span>
                            <span class="id-value strong font-mono">${this.escapeHtml(req.request_number)}</span>
                        </div>
                        <div class="identity-item">
                            <span class="id-label">Current Stage</span>
                            <span class="id-value strong">${stageLabel}</span>
                        </div>
                        <div class="identity-item">
                            <span class="id-label">Target Resource</span>
                            <span class="id-value">${this.escapeHtml(req.resource_name || req.resource_code || '—')}</span>
                        </div>
                        <div class="identity-item">
                            <span class="id-label">Entitlement Scope</span>
                            <span class="id-value"><code>${this.escapeHtml(req.entitlement_code || '—')}</code></span>
                        </div>
                        <div class="identity-item">
                            <span class="id-label">Requested Period</span>
                            <span class="id-value">${this.formatDate(req.requested_start_date)} &rarr; ${this.formatDate(req.requested_end_date)}</span>
                        </div>
                        <div class="identity-item">
                            <span class="id-label">Lease Duration</span>
                            <span class="id-value">${this.calculateDurationDays(req.requested_start_date, req.requested_end_date)} days</span>
                        </div>
                    </div>

                    <!-- Contractor Justification -->
                    <div class="form-group" style="margin-bottom: 1.25rem;">
                        <span class="id-label">Contractor Business Justification</span>
                        <div class="form-static-value" style="font-style: italic;">
                            ${this.escapeHtml(req.business_justification || 'No justification provided.')}
                        </div>
                    </div>

                    <!-- Decision Toggle -->
                    <div class="form-group">
                        <label class="form-label required">Select Decision</label>
                        <div class="decision-toggle-group">
                            <div class="decision-option selected-approve" id="opt-approve" data-value="APPROVE">
                                <h4>Approve Request</h4>
                                <p>Endorse and advance to next stage or activation</p>
                            </div>
                            <div class="decision-option" id="opt-reject" data-value="REJECT">
                                <h4>Reject Request</h4>
                                <p>Deny access and conclude workflow</p>
                            </div>
                        </div>
                    </div>

                    <!-- Decision Comments -->
                    <div class="form-group">
                        <label class="form-label" id="label-decision-comments" for="decision-comments">
                            Decision Notes &amp; Governance Justification
                        </label>
                        <textarea id="decision-comments" class="form-textarea" rows="3" placeholder="Provide governance endorsement or rejection reasoning..."></textarea>
                        <span class="form-help" id="help-decision-comments">Optional for approval; mandatory (min 5 characters) for rejection.</span>
                    </div>

                    <div class="modal-actions" style="margin-top: 1.5rem; display: flex; justify-content: flex-end; gap: 0.5rem;">
                        <button type="button" class="btn btn-secondary" id="btn-cancel-decision">Cancel</button>
                        <button type="button" class="btn btn-primary" id="btn-submit-decision">Submit Decision</button>
                    </div>
                `;

                let selectedDecision = 'APPROVE';
                const optApprove = modal.querySelector('#opt-approve');
                const optReject = modal.querySelector('#opt-reject');
                const labelComments = modal.querySelector('#label-decision-comments');
                const commentsInput = modal.querySelector('#decision-comments');
                const submitBtn = modal.querySelector('#btn-submit-decision');
                const cancelBtn = modal.querySelector('#btn-cancel-decision');

                cancelBtn.addEventListener('click', closeModal);

                optApprove.addEventListener('click', () => {
                    selectedDecision = 'APPROVE';
                    optApprove.className = 'decision-option selected-approve';
                    optReject.className = 'decision-option';
                    labelComments.className = 'form-label';
                    submitBtn.className = 'btn btn-primary';
                    submitBtn.textContent = 'Submit Approval';
                });

                optReject.addEventListener('click', () => {
                    selectedDecision = 'REJECT';
                    optReject.className = 'decision-option selected-reject';
                    optApprove.className = 'decision-option';
                    labelComments.className = 'form-label required';
                    submitBtn.className = 'btn btn-danger';
                    submitBtn.textContent = 'Submit Rejection';
                });

                submitBtn.addEventListener('click', async () => {
                    const errBanner = modal.querySelector('#decision-error-banner');
                    errBanner.style.display = 'none';

                    const comments = commentsInput.value.trim();

                    if (selectedDecision === 'REJECT' && comments.length < 5) {
                        errBanner.textContent = 'Rejection requires an audit justification of at least 5 characters.';
                        errBanner.style.display = 'block';
                        return;
                    }

                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Processing Decision...';

                    try {
                        await window.apiClient.post(`/api/approvals/${stepId}/decision`, {
                            decision: selectedDecision,
                            comments
                        });

                        closeModal();
                        await Promise.all([
                            this.loadApprovalsTable(),
                            this.loadRequestsTable()
                        ]);
                    } catch (err) {
                        errBanner.textContent = err.message || 'Failed to submit decision.';
                        errBanner.style.display = 'block';
                        submitBtn.disabled = false;
                        submitBtn.textContent = selectedDecision === 'REJECT' ? 'Submit Rejection' : 'Submit Approval';
                    }
                });

            } catch (err) {
                modal.querySelector('.modal-body').innerHTML = `
                    <div class="error-banner">
                        <strong>Error:</strong> ${this.escapeHtml(err.message)}
                    </div>
                `;
            }
        }

        async handleCancelRequest(requestId, requestNumber) {
            const confirmed = window.confirm(`Are you sure you want to cancel access request ${requestNumber}? Any pending approval steps will be skipped.`);
            if (!confirmed) return;

            try {
                await window.apiClient.post(`/api/requests/${requestId}/cancel`, {
                    reason: 'Cancelled by requester via web portal'
                });
                await this.loadRequestsTable();
            } catch (err) {
                alert('Failed to cancel request: ' + err.message);
            }
        }

        setupEventHandlers() {
            // Global event listeners if any
        }

        // =====================================================================
        // Helpers
        // =====================================================================
        getStepTypeLabel(stepType, stepNumber) {
            switch (stepType) {
                case 'SPONSOR_APPROVAL':
                    return 'Business Sponsor';
                case 'RESOURCE_OWNER_APPROVAL':
                    return 'Resource Owner';
                case 'SECURITY_APPROVAL':
                    return 'Security Officer';
                default:
                    return `Stage ${stepNumber || 1}`;
            }
        }

        getStatusBadgeClass(status) {
            switch (status) {
                case 'APPROVED':
                    return 'status-pill-success';
                case 'PENDING_APPROVAL':
                case 'SUBMITTED':
                    return 'status-pill-warning';
                case 'REJECTED':
                    return 'status-pill-danger';
                case 'CANCELLED':
                default:
                    return 'status-pill-neutral';
            }
        }

        getRiskBadgeClass(riskLevel) {
            switch ((riskLevel || '').toUpperCase()) {
                case 'LOW':
                    return 'badge-risk-low';
                case 'MEDIUM':
                    return 'badge-risk-medium';
                case 'HIGH':
                    return 'badge-risk-high';
                case 'CRITICAL':
                    return 'badge-risk-critical';
                default:
                    return 'badge-risk-medium';
            }
        }

        calculateDurationDays(startStr, endStr) {
            if (!startStr || !endStr) return 0;
            const s = new Date(startStr);
            const e = new Date(endStr);
            if (isNaN(s.getTime()) || isNaN(e.getTime())) return 0;
            return Math.max(1, Math.ceil((e - s) / (1000 * 60 * 60 * 24)));
        }

        formatDate(dateVal) {
            if (!dateVal) return '—';
            try {
                const d = new Date(dateVal);
                return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
            } catch {
                return String(dateVal).split('T')[0];
            }
        }

        formatDateTime(dateVal) {
            if (!dateVal) return '—';
            try {
                const d = new Date(dateVal);
                return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
            } catch {
                return String(dateVal);
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

    window.AccessLeaseRequests = new RequestWorkflowModule();
    document.addEventListener('DOMContentLoaded', () => {
        window.AccessLeaseRequests.init();
    });

})(window);
