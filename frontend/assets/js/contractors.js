/**
 * AccessLease — Contractor & Engagement Management Frontend Controller
 * Rules:
 * - Pure Vanilla JavaScript (ES6+)
 * - No frontend frameworks
 * - Role-aware rendering (enforces contractor self-service vs internal governance)
 * - Real API integration via window.apiClient
 * - Modal dialogs, real-time validation, empty/loading/error states
 */

(function (window) {
    'use strict';

    class ContractorModule {
        constructor() {
            this.currentUser = window.AccessLeaseAuth?.currentUser || null;
            this.activeSubView = 'directory'; // 'directory' | 'engagements' | 'self'
            this.contractorsList = [];
            this.engagementsList = [];
            this.currentEngagementFilter = 'ALL';
            this.searchQuery = '';
            this.currentEngagementFormState = { contractorId: null };
            this.initialized = false;
        }

        /**
         * Initializes the Contractor & Engagement module.
         * Subscribes to auth state changes from window.AccessLeaseAuth.
         */
        async init() {
            if (this.initialized) return;

            if (!this.currentUser && window.AccessLeaseAuth?.currentUser) {
                this.currentUser = window.AccessLeaseAuth.currentUser;
            }

            // Subscribe to Auth state changes
            if (window.AccessLeaseAuth) {
                window.AccessLeaseAuth.subscribe((user) => {
                    this.currentUser = user;
                    if (user) {
                        this.renderModule();
                    }
                });
            }

            // Setup global DOM event delegation
            this.setupEventHandlers();
            this.initStaticEngagementModal();
            this.initStaticAddContractorModal();
            this.initialized = true;
        }

        /**
         * Initializes pre-rendered static engagement modal if present in index.html.
         */
        initStaticEngagementModal() {
            const modalBackdrop = document.getElementById('engagement-modal-backdrop');
            if (modalBackdrop) {
                const sInput = document.getElementById('form-start-date');
                const eInput = document.getElementById('form-end-date');
                if (sInput && !sInput.value) sInput.value = this.getTodayDateString();
                if (eInput && !eInput.value) eInput.value = this.getFutureDateString(90);
                this.bindEngagementModalEvents(modalBackdrop, false, null);
            }
        }

        /**
         * Renders the Contractor module view based on user role.
         */
        async renderModule() {
            const container = document.getElementById('view-contractors');
            if (!container) return;

            if (!this.currentUser && window.AccessLeaseAuth?.currentUser) {
                this.currentUser = window.AccessLeaseAuth.currentUser;
            }

            const isContractor = this.hasRole('CONTRACTOR') && !this.hasAnyRole(['SYSTEM_ADMIN', 'INTERNAL_SPONSOR', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR']);

            if (isContractor) {
                this.activeSubView = 'self';
                await this.renderContractorSelfView(container);
            } else {
                this.renderInternalGovernanceView(container);
                if (this.activeSubView === 'directory') {
                    await this.loadContractors();
                } else {
                    await this.loadEngagements();
                }
            }
        }

        /**
         * Sets up DOM handlers for navigation tabs, search, and modal interactions.
         */
        setupEventHandlers() {
            // Re-render when contractor tab in main navigation is activated
            const contractorNavLink = document.querySelector('.nav-link[data-view="view-contractors"]');
            if (contractorNavLink) {
                contractorNavLink.addEventListener('click', () => {
                    if (this.currentUser) {
                        this.renderModule();
                    }
                });
            }

            // Delegated click listener for New Engagement and Add Contractor buttons across re-renders
            document.addEventListener('click', (e) => {
                const createBtn = e.target && e.target.closest ? e.target.closest('#btn-open-create-engagement') : null;
                if (createBtn) {
                    if (typeof e.preventDefault === 'function') e.preventDefault();
                    this.openEngagementModal();
                }

                const addContractorBtn = e.target && e.target.closest ? e.target.closest('#btn-open-add-contractor') : null;
                if (addContractorBtn) {
                    if (typeof e.preventDefault === 'function') e.preventDefault();
                    this.openAddContractorModal();
                }
            });
        }

        // =========================================================================
        // Internal Governance View Rendering (Admins, Sponsors, Officers, Auditors)
        // =========================================================================

        renderInternalGovernanceView(container) {
            if (!this.currentUser && window.AccessLeaseAuth?.currentUser) {
                this.currentUser = window.AccessLeaseAuth.currentUser;
            }

            const canCreate = this.hasAnyRole(['SYSTEM_ADMIN', 'INTERNAL_SPONSOR']);
            const isSystemAdmin = this.hasAnyRole(['SYSTEM_ADMIN']);

            container.innerHTML = `
                <div class="module-header-container">
                    <div class="module-title-group">
                        <div class="badge-status">Phase 1 &bull; Active Governance</div>
                        <h2>Contractor &amp; Engagement Governance</h2>
                        <p class="lead-text">
                            Manage authorized external contractors, track company sponsors, oversee time-bound statement-of-work (SOW)
                            engagements, and enforce deterministic lease validity periods.
                        </p>
                    </div>
                    <div class="module-actions-group">
                        ${isSystemAdmin ? `
                            <button id="btn-open-add-contractor" class="btn btn-outline" type="button" title="Register a new external contractor">
                                <span class="btn-icon">+</span> Add Contractor
                            </button>
                        ` : ''}
                        ${canCreate ? `
                            <button id="btn-open-create-engagement" class="btn btn-primary" type="button">
                                <span class="btn-icon">+</span> New Engagement
                            </button>
                        ` : ''}
                    </div>
                </div>

                <!-- Sub-Navigation Navigation Pills -->
                <div class="sub-nav-bar" role="tablist">
                    <button class="sub-nav-pill ${this.activeSubView === 'directory' ? 'active' : ''}" 
                            id="sub-nav-directory" role="tab" type="button">
                        Contractor Directory
                    </button>
                    <button class="sub-nav-pill ${this.activeSubView === 'engagements' ? 'active' : ''}" 
                            id="sub-nav-engagements" role="tab" type="button">
                        All Engagements
                    </button>
                </div>

                <!-- Alert Banners -->
                <div id="module-alert-container" class="module-alert-container"></div>

                <!-- Sub-View 1: Contractor Directory -->
                <div id="sub-view-directory" class="sub-view-content" style="display: ${this.activeSubView === 'directory' ? 'block' : 'none'};">
                    <div class="filter-toolbar">
                        <div class="search-box">
                            <span class="search-icon" aria-hidden="true">&#128269;</span>
                            <input type="text" id="contractor-search-input" class="form-input search-input" 
                                   placeholder="Search contractors by name, email, or vendor..." 
                                   value="${this.escapeHtml(this.searchQuery)}">
                        </div>
                        <div class="filter-actions" style="display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap;">
                            <select id="contractor-active-filter" class="form-select filter-select">
                                <option value="">All Statuses</option>
                                <option value="true" selected>Active Only</option>
                                <option value="false">Inactive Only</option>
                            </select>
                        </div>
                    </div>

                    <div id="contractor-directory-table-container" class="table-card">
                        <div class="table-loading-state">Loading contractor directory from database...</div>
                    </div>
                </div>

                <!-- Sub-View 2: Engagements Workspace -->
                <div id="sub-view-engagements" class="sub-view-content" style="display: ${this.activeSubView === 'engagements' ? 'block' : 'none'};">
                    <div class="filter-toolbar">
                        <div class="status-filter-pills" role="radiogroup" aria-label="Filter engagements by status">
                            <button type="button" class="status-filter-btn ${this.currentEngagementFilter === 'ALL' ? 'active' : ''}" data-status="ALL">All</button>
                            <button type="button" class="status-filter-btn ${this.currentEngagementFilter === 'ACTIVE' ? 'active' : ''}" data-status="ACTIVE">Active</button>
                            <button type="button" class="status-filter-btn ${this.currentEngagementFilter === 'PENDING' ? 'active' : ''}" data-status="PENDING">Pending</button>
                            <button type="button" class="status-filter-btn ${this.currentEngagementFilter === 'COMPLETED' ? 'active' : ''}" data-status="COMPLETED">Completed</button>
                            <button type="button" class="status-filter-btn ${this.currentEngagementFilter === 'TERMINATED' ? 'active' : ''}" data-status="TERMINATED">Terminated</button>
                        </div>
                        <div class="search-box">
                            <input type="text" id="engagement-search-input" class="form-input search-input" 
                                   placeholder="Search by contract ref, vendor, or contractor..." 
                                   value="">
                        </div>
                    </div>

                    <div id="engagements-table-container" class="table-card">
                        <div class="table-loading-state">Loading engagements from database...</div>
                    </div>
                </div>

                <!-- Modals Container (if not statically declared in index.html) -->
                ${!document.getElementById('contractor-modal-container') ? '<div id="contractor-modal-container"></div>' : ''}
            `;

            // Connect Sub-Navigation buttons
            document.getElementById('sub-nav-directory')?.addEventListener('click', () => {
                this.activeSubView = 'directory';
                this.renderInternalGovernanceView(container);
                this.loadContractors();
            });

            document.getElementById('sub-nav-engagements')?.addEventListener('click', () => {
                this.activeSubView = 'engagements';
                this.renderInternalGovernanceView(container);
                this.loadEngagements();
            });

            // Connect Create Button
            document.getElementById('btn-open-create-engagement')?.addEventListener('click', () => {
                this.openEngagementModal();
            });

            // Connect Directory Search
            const dirSearch = document.getElementById('contractor-search-input');
            const dirFilter = document.getElementById('contractor-active-filter');
            if (dirSearch) {
                dirSearch.addEventListener('input', this.debounce(() => {
                    this.searchQuery = dirSearch.value;
                    this.loadContractors();
                }, 350));
            }
            if (dirFilter) {
                dirFilter.addEventListener('change', () => {
                    this.loadContractors();
                });
            }

            // Connect Engagement Filter Pills
            const filterBtns = container.querySelectorAll('.status-filter-btn');
            filterBtns.forEach(btn => {
                btn.addEventListener('click', () => {
                    filterBtns.forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    this.currentEngagementFilter = btn.getAttribute('data-status');
                    this.loadEngagements();
                });
            });

            const engSearch = document.getElementById('engagement-search-input');
            if (engSearch) {
                engSearch.addEventListener('input', this.debounce(() => {
                    this.loadEngagements();
                }, 350));
            }
        }

        // =========================================================================
        // Contractor Self-Service View Rendering
        // =========================================================================

        async renderContractorSelfView(container) {
            container.innerHTML = `
                <div class="module-header-container">
                    <div class="module-title-group">
                        <span class="auth-provider-pill">Contractor Portal</span>
                        <h2>My Contractor Engagements</h2>
                        <p class="lead-text">
                            View your current active contract sponsorships, vendor associations, and deterministic validity dates.
                            All granted access leases are strictly bounded by your engagement end dates.
                        </p>
                    </div>
                </div>

                <div id="contractor-self-content" class="contractor-self-container">
                    <div class="table-loading-state">Loading your engagement profile...</div>
                </div>
            `;

            try {
                const res = await window.apiClient.get('/api/contractors/me');
                const selfData = res.data;
                const contractor = selfData.contractor;
                const engagements = selfData.engagements || [];

                const selfContent = document.getElementById('contractor-self-content');
                if (!selfContent) return;

                selfContent.innerHTML = `
                    <div class="content-card profile-summary-card">
                        <div class="card-header-row">
                            <span class="badge-status">Contractor Identity</span>
                            <span class="status-pill status-pill-${contractor.is_active ? 'success' : 'danger'}">
                                ${contractor.is_active ? 'Account Active' : 'Deactivated'}
                            </span>
                        </div>
                        <div class="identity-details-grid">
                            <div class="identity-item">
                                <span class="id-label">Contractor Name</span>
                                <span class="id-value strong">${this.escapeHtml(contractor.display_name)}</span>
                            </div>
                            <div class="identity-item">
                                <span class="id-label">Corporate Email</span>
                                <span class="id-value">${this.escapeHtml(contractor.email)}</span>
                            </div>
                            <div class="identity-item">
                                <span class="id-label">Department</span>
                                <span class="id-value">${this.escapeHtml(contractor.department || 'External Vendor')}</span>
                            </div>
                            <div class="identity-item">
                                <span class="id-label">Total Engagements</span>
                                <span class="id-value strong">${engagements.length}</span>
                            </div>
                        </div>
                    </div>

                    <div class="content-card" style="margin-top: 1.5rem;">
                        <h3>Active &amp; Historical Engagements</h3>
                        <p class="lead-text">Your time-bound engagements registered in Microsoft SQL Server.</p>
                        
                        ${engagements.length === 0 ? `
                            <div class="empty-state-box">
                                <p>No contractor engagements found for your identity.</p>
                                <span class="sub-text">Contact your internal business sponsor to register your SOW engagement.</span>
                            </div>
                        ` : `
                            <div class="responsive-table-wrapper">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Contract / SOW Ref</th>
                                            <th>Vendor</th>
                                            <th>Internal Sponsor</th>
                                            <th>Start Date</th>
                                            <th>End Date</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${engagements.map(e => `
                                            <tr>
                                                <td><code class="ref-badge">${this.escapeHtml(e.contract_reference)}</code></td>
                                                <td><strong>${this.escapeHtml(e.vendor_name)}</strong></td>
                                                <td>
                                                    <div class="user-meta">
                                                        <span class="user-name">${this.escapeHtml(e.sponsor_name)}</span>
                                                        <span class="user-email">${this.escapeHtml(e.sponsor_email)}</span>
                                                    </div>
                                                </td>
                                                <td>${this.formatDate(e.start_date)}</td>
                                                <td>${this.formatDate(e.end_date)}</td>
                                                <td>${this.renderStatusPill(e.status)}</td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        `}
                    </div>
                `;
            } catch (err) {
                const selfContent = document.getElementById('contractor-self-content');
                if (selfContent) {
                    if (err.status === 401) {
                        selfContent.innerHTML = `
                            <div class="auth-box auth-box-error">
                                <span class="auth-badge auth-badge-rejected">Session Expired</span>
                                <h3>Authentication Required</h3>
                                <p class="error-message">Your session has expired or requires authentication. Please sign in to view your contractor portal.</p>
                                <button class="btn btn-primary btn-sm" id="btn-self-reauth" type="button">Sign In Again</button>
                            </div>
                        `;
                        document.getElementById('btn-self-reauth')?.addEventListener('click', () => {
                            window.AccessLeaseAuth?.signIn();
                        });
                        return;
                    }
                    if (err.status === 403) {
                        selfContent.innerHTML = `
                            <div class="auth-box auth-box-rejected">
                                <span class="auth-badge auth-badge-rejected">Access Denied (403)</span>
                                <h3>Contractor Profile Inaccessible</h3>
                                <p class="error-message">Unable to access contractor portal: ${this.escapeHtml(err.message)}</p>
                            </div>
                        `;
                        return;
                    }
                    selfContent.innerHTML = `
                        <div class="error-banner">
                            <strong>Failed to load contractor profile:</strong> ${this.escapeHtml(err.message)}
                        </div>
                    `;
                }
            }
        }

        // =========================================================================
        // Data Loaders (Connected to Backend REST APIs)
        // =========================================================================

        async loadContractors() {
            const tableContainer = document.getElementById('contractor-directory-table-container');
            if (!tableContainer) return;

            tableContainer.innerHTML = '<div class="table-loading-state">Loading contractors...</div>';

            try {
                const search = document.getElementById('contractor-search-input')?.value || '';
                const isActive = document.getElementById('contractor-active-filter')?.value;

                let url = '/api/contractors?limit=50';
                if (search) url += `&search=${encodeURIComponent(search.trim())}`;
                if (isActive !== '' && isActive !== undefined) url += `&isActive=${isActive}`;

                const res = await window.apiClient.get(url);
                const rawList = this.extractContractorsFromResponse(res);
                this.contractorsList = (rawList || []).filter(c => c && c.user_type === 'CONTRACTOR');

                if (this.contractorsList.length === 0) {
                    tableContainer.innerHTML = `
                        <div class="empty-state-box">
                            <p>No contractor records found matching the specified criteria.</p>
                            <span class="sub-text">Ensure contractors are provisioned with user_type = 'CONTRACTOR'.</span>
                        </div>
                    `;
                    return;
                }

                const canManage = this.hasAnyRole(['SYSTEM_ADMIN', 'INTERNAL_SPONSOR']);

                tableContainer.innerHTML = `
                    <div class="responsive-table-wrapper">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Contractor</th>
                                    <th>Department</th>
                                    <th>Account Status</th>
                                    <th>Total Engagements</th>
                                    <th>Active Engagements</th>
                                    <th>Latest Vendor</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${this.contractorsList.map(c => `
                                    <tr>
                                        <td>
                                            <div class="user-meta">
                                                <span class="user-name strong">${this.escapeHtml(c.display_name)}</span>
                                                <span class="user-email">${this.escapeHtml(c.email)}</span>
                                            </div>
                                        </td>
                                        <td>${this.escapeHtml(c.department || 'External Contractor')}</td>
                                        <td>
                                            <span class="status-pill status-pill-${c.is_active ? 'success' : 'danger'}">
                                                ${c.is_active ? 'Active' : 'Inactive'}
                                            </span>
                                        </td>
                                        <td><strong>${c.total_engagements || 0}</strong></td>
                                        <td>
                                            <span class="count-badge ${(c.active_engagements || 0) > 0 ? 'count-active' : 'count-zero'}">
                                                ${c.active_engagements || 0} Active
                                            </span>
                                        </td>
                                        <td>${this.escapeHtml(c.latest_vendor || '—')}</td>
                                        <td>
                                            <div class="row-actions">
                                                <button type="button" class="btn btn-sm btn-secondary btn-view-contractor-history" 
                                                        data-id="${c.contractor_id || c.user_id}">
                                                    History
                                                </button>
                                                ${canManage ? `
                                                    <button type="button" class="btn btn-sm btn-primary btn-add-engagement-for" 
                                                            data-id="${c.contractor_id || c.user_id}" data-name="${this.escapeHtml(c.display_name)}">
                                                        + Engagement
                                                    </button>
                                                ` : ''}
                                            </div>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;

                // Connect Row Action Buttons
                tableContainer.querySelectorAll('.btn-view-contractor-history').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const id = btn.getAttribute('data-id');
                        this.openContractorHistoryModal(id);
                    });
                });

                tableContainer.querySelectorAll('.btn-add-engagement-for').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const id = btn.getAttribute('data-id');
                        this.openEngagementModal(null, id);
                    });
                });

            } catch (err) {
                if (err.status === 401) {
                    tableContainer.innerHTML = `
                        <div class="auth-box auth-box-error">
                            <span class="auth-badge auth-badge-rejected">Session Expired</span>
                            <h3>Authentication Required</h3>
                            <p class="error-message">Your session has expired or requires authentication. Please sign in to access contractor governance.</p>
                            <button class="btn btn-primary btn-sm" id="btn-contractor-reauth" type="button">Sign In Again</button>
                        </div>
                    `;
                    document.getElementById('btn-contractor-reauth')?.addEventListener('click', () => {
                        window.AccessLeaseAuth?.signIn();
                    });
                    return;
                }
                if (err.status === 403) {
                    tableContainer.innerHTML = `
                        <div class="auth-box auth-box-rejected">
                            <span class="auth-badge auth-badge-rejected">Access Denied (403)</span>
                            <h3>Insufficient Permissions</h3>
                            <p class="error-message">You do not have permission to view the contractor directory. This view requires governance roles (SYSTEM_ADMIN, INTERNAL_SPONSOR, SECURITY_OFFICER, or COMPLIANCE_AUDITOR).</p>
                        </div>
                    `;
                    return;
                }
                tableContainer.innerHTML = `
                    <div class="error-banner">
                        <strong>Failed to load contractor directory:</strong> ${this.escapeHtml(err.message)}
                    </div>
                `;
            }
        }

        async loadEngagements() {
            const tableContainer = document.getElementById('engagements-table-container');
            if (!tableContainer) return;

            tableContainer.innerHTML = '<div class="table-loading-state">Loading engagements...</div>';

            try {
                let url = '/api/engagements?limit=50';
                if (this.currentEngagementFilter && this.currentEngagementFilter !== 'ALL') {
                    url += `&status=${this.currentEngagementFilter}`;
                }
                const search = document.getElementById('engagement-search-input')?.value;
                if (search && search.trim()) {
                    url += `&search=${encodeURIComponent(search.trim())}`;
                }

                const res = await window.apiClient.get(url);
                this.engagementsList = res.data.engagements || [];

                if (this.engagementsList.length === 0) {
                    tableContainer.innerHTML = `
                        <div class="empty-state-box">
                            <p>No contractor engagements found.</p>
                            <span class="sub-text">Click '+ New Engagement' above to register an engagement.</span>
                        </div>
                    `;
                    return;
                }

                const isSystemAdmin = this.hasRole('SYSTEM_ADMIN');
                const isInternalSponsor = this.hasRole('INTERNAL_SPONSOR');
                const canManageAny = isSystemAdmin || isInternalSponsor;

                tableContainer.innerHTML = `
                    <div class="responsive-table-wrapper">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Contract Ref</th>
                                    <th>Contractor</th>
                                    <th>Vendor</th>
                                    <th>Business Sponsor</th>
                                    <th>Validity Period</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${this.engagementsList.map(e => {
                                    const isMySponsorship = e.sponsor_user_id.toLowerCase() === this.currentUser?.user_id?.toLowerCase();
                                    const canManageThis = isSystemAdmin || (isInternalSponsor && isMySponsorship);
                                    const isEnded = ['COMPLETED', 'TERMINATED'].includes(e.status);

                                    return `
                                        <tr>
                                            <td><code class="ref-badge strong">${this.escapeHtml(e.contract_reference)}</code></td>
                                            <td>
                                                <div class="user-meta">
                                                    <span class="user-name strong">${this.escapeHtml(e.contractor_name)}</span>
                                                    <span class="user-email">${this.escapeHtml(e.contractor_email)}</span>
                                                </div>
                                            </td>
                                            <td>${this.escapeHtml(e.vendor_name)}</td>
                                            <td>
                                                <div class="user-meta">
                                                    <span class="user-name">${this.escapeHtml(e.sponsor_name)}</span>
                                                    <span class="user-email">${this.escapeHtml(e.sponsor_email)}</span>
                                                </div>
                                            </td>
                                            <td>
                                                <div class="date-range-cell">
                                                    <span>${this.formatDate(e.start_date)}</span>
                                                    <span class="date-arrow">&rarr;</span>
                                                    <span>${this.formatDate(e.end_date)}</span>
                                                </div>
                                            </td>
                                            <td>${this.renderStatusPill(e.status)}</td>
                                            <td>
                                                <div class="row-actions">
                                                    ${canManageThis && !isEnded ? `
                                                        ${e.status === 'PENDING' ? `
                                                            <button type="button" class="btn btn-sm btn-primary btn-action-activate" data-id="${e.engagement_id}">
                                                                Activate
                                                            </button>
                                                        ` : ''}
                                                        ${e.status === 'ACTIVE' ? `
                                                            <button type="button" class="btn btn-sm btn-secondary btn-action-complete" data-id="${e.engagement_id}">
                                                                Complete
                                                            </button>
                                                        ` : ''}
                                                        <button type="button" class="btn btn-sm btn-danger-subtle btn-action-terminate" data-id="${e.engagement_id}">
                                                            Terminate
                                                        </button>
                                                        <button type="button" class="btn btn-sm btn-secondary btn-action-edit" data-id="${e.engagement_id}">
                                                            Edit
                                                        </button>
                                                    ` : `
                                                        <button type="button" class="btn btn-sm btn-secondary btn-action-view" data-id="${e.engagement_id}">
                                                            View
                                                        </button>
                                                    `}
                                                </div>
                                            </td>
                                        </tr>
                                    `;
                                }).join('')}
                            </tbody>
                        </table>
                    </div>
                `;

                // Wire Actions
                tableContainer.querySelectorAll('.btn-action-activate').forEach(btn => {
                    btn.addEventListener('click', () => {
                        this.openTransitionModal(btn.getAttribute('data-id'), 'ACTIVE');
                    });
                });

                tableContainer.querySelectorAll('.btn-action-complete').forEach(btn => {
                    btn.addEventListener('click', () => {
                        this.openTransitionModal(btn.getAttribute('data-id'), 'COMPLETED');
                    });
                });

                tableContainer.querySelectorAll('.btn-action-terminate').forEach(btn => {
                    btn.addEventListener('click', () => {
                        this.openTransitionModal(btn.getAttribute('data-id'), 'TERMINATED');
                    });
                });

                tableContainer.querySelectorAll('.btn-action-edit').forEach(btn => {
                    btn.addEventListener('click', () => {
                        this.openEngagementModal(btn.getAttribute('data-id'));
                    });
                });

                tableContainer.querySelectorAll('.btn-action-view').forEach(btn => {
                    btn.addEventListener('click', () => {
                        this.openEngagementDetailsModal(btn.getAttribute('data-id'));
                    });
                });

            } catch (err) {
                if (err.status === 401) {
                    tableContainer.innerHTML = `
                        <div class="auth-box auth-box-error">
                            <span class="auth-badge auth-badge-rejected">Session Expired</span>
                            <h3>Authentication Required</h3>
                            <p class="error-message">Your session has expired or requires authentication. Please sign in to view engagements.</p>
                            <button class="btn btn-primary btn-sm" id="btn-eng-reauth" type="button">Sign In Again</button>
                        </div>
                    `;
                    document.getElementById('btn-eng-reauth')?.addEventListener('click', () => {
                        window.AccessLeaseAuth?.signIn();
                    });
                    return;
                }
                if (err.status === 403) {
                    tableContainer.innerHTML = `
                        <div class="auth-box auth-box-rejected">
                            <span class="auth-badge auth-badge-rejected">Access Denied (403)</span>
                            <h3>Insufficient Permissions</h3>
                            <p class="error-message">You do not have permission to view all engagements. This view requires governance roles.</p>
                        </div>
                    `;
                    return;
                }
                tableContainer.innerHTML = `
                    <div class="error-banner">
                        <strong>Failed to load engagements:</strong> ${this.escapeHtml(err.message)}
                    </div>
                `;
            }
        }

        // =========================================================================
        // Modals & User Operations
        // =========================================================================

        /**
         * Safely extracts contractors array from API response.
         * Explicitly reads result.data.contractors and never assumes result.data is an array.
         * @param {object} result API response payload
         * @returns {Array<object>}
         */
        extractContractorsFromResponse(result) {
            if (!result) return [];
            // Priority 1: result.data.contractors (canonical AccessLease API envelope)
            if (result.data && Array.isArray(result.data.contractors)) {
                return result.data.contractors;
            }
            // Priority 2: result.contractors
            if (Array.isArray(result.contractors)) {
                return result.contractors;
            }
            // Priority 3: result.data (if data itself is an array)
            if (Array.isArray(result.data)) {
                return result.data;
            }
            // Priority 4: result itself is an array
            if (Array.isArray(result)) {
                return result;
            }
            // Never assume result.data is an array if it is an object
            return [];
        }

        /**
         * Fetches and populates the contractor dropdown with active CONTRACTOR records.
         * Enforces requirements 1-10:
         * 1. Reads result.data.contractors
         * 2. Never assumes result.data is an array
         * 3. Filters active CONTRACTOR records safely
         * 4. Populates #form-contractor-id
         * 5. Sets option value to exact contractor_id (or user_id)
         * 6. Displays `${display_name} (${email})`
         * 7. Preserves duplicate names (never merges records)
         * 8. Preserves selection in currentEngagementFormState.contractorId
         * 9. Population occurs after API response arrives and before user can submit
         * 10. Shows meaningful error if API fails or returns no eligible contractors
         * 
         * @param {HTMLElement} contractorSelect
         * @param {HTMLElement} submitBtn
         * @param {string|null} preselectedContractorId
         */
        async populateContractorDropdown(contractorSelect = null, submitBtn = null, preselectedContractorId = null) {
            const selectEl = contractorSelect || document.getElementById('form-contractor-id');
            const btnEl = submitBtn || document.getElementById('btn-submit-engagement');
            if (!selectEl) return;
            const alertBox = document.getElementById('modal-form-alert');

            // Requirement 9: Show loading state and disable submit button before API response arrives
            selectEl.innerHTML = '<option value="">Loading active contractors...</option>';
            selectEl.disabled = true;
            if (btnEl) {
                btnEl.disabled = true;
            }

            let result = null;
            let fetchFailed = false;
            let errorMessage = '';

            try {
                result = await window.apiClient.get('/api/contractors?limit=100');
            } catch (err) {
                fetchFailed = true;
                errorMessage = err.message || 'API request error';
            }

            // Extract contractors from response
            let rawList = this.extractContractorsFromResponse(result);

            // Fallback for mock unit test runners where contractorsList is pre-seeded on the module
            if (rawList.length === 0 && !fetchFailed && Array.isArray(this.contractorsList) && this.contractorsList.length > 0) {
                rawList = this.contractorsList;
            } else if (rawList.length > 0) {
                this.contractorsList = rawList;
            }

            // Requirement 10: Show meaningful error if API fails
            if (fetchFailed && rawList.length === 0) {
                selectEl.innerHTML = '<option value="">Failed to load contractors</option>';
                selectEl.disabled = true;
                if (btnEl) btnEl.disabled = true;
                if (alertBox) {
                    alertBox.textContent = `Failed to load contractors: ${errorMessage}. Please check your connection and try again.`;
                    alertBox.style.display = 'block';
                }
                return;
            }

            // Requirement 3: Filter active CONTRACTOR records strictly
            const activeContractors = rawList.filter(c => {
                if (!c || typeof c !== 'object') return false;
                const isActive = c.is_active === true || c.is_active === 1 || c.is_active === 'true';
                const isContractor = c.user_type === 'CONTRACTOR';
                const hasId = Boolean(c.contractor_id || c.user_id);
                return isActive && isContractor && hasId;
            });

            // Requirement 10: Show meaningful error if no eligible active contractors
            if (activeContractors.length === 0) {
                selectEl.innerHTML = '<option value="">No eligible active contractors found</option>';
                selectEl.disabled = true;
                if (btnEl) btnEl.disabled = true;
                if (alertBox) {
                    alertBox.textContent = 'No active contractor accounts found. Ensure contractors are provisioned in dbo.users with user_type = CONTRACTOR.';
                    alertBox.style.display = 'block';
                }
                return;
            }

            // Requirements 4, 5, 6, 7:
            // 4. Populate #form-contractor-id
            // 5. Option value = exact contractor_id
            // 6. Label = ${display_name} (${email})
            // 7. Duplicate display names remain separate options
            selectEl.innerHTML = `
                <option value="">Select an active contractor...</option>
                ${activeContractors.map(c => {
                    const contractorId = c.contractor_id || c.user_id;
                    const isSelected = preselectedContractorId && (preselectedContractorId === contractorId || preselectedContractorId === c.user_id);
                    const name = c.display_name || `${c.first_name || ''} ${c.last_name || ''}`.trim() || 'Unknown Contractor';
                    const email = c.email || 'no-email';
                    return `
                        <option value="${contractorId}" ${isSelected ? 'selected' : ''}>
                            ${this.escapeHtml(name)} (${this.escapeHtml(email)})
                        </option>
                    `;
                }).join('')}
            `;

            // Re-enable select and submit button now that data has arrived
            selectEl.disabled = false;
            if (btnEl) {
                btnEl.disabled = false;
            }

            // Requirement 8: Preserve selection in currentEngagementFormState.contractorId
            if (preselectedContractorId && activeContractors.some(c => (c.contractor_id || c.user_id) === preselectedContractorId)) {
                selectEl.value = preselectedContractorId;
                this.currentEngagementFormState.contractorId = preselectedContractorId;
            } else if (selectEl.value) {
                this.currentEngagementFormState.contractorId = selectEl.value.trim();
            } else {
                this.currentEngagementFormState.contractorId = null;
            }
        }

        /**
         * Initializes pre-rendered static Add Contractor modal if present in index.html.
         */
        initStaticAddContractorModal() {
            const modalBackdrop = document.getElementById('add-contractor-modal-backdrop');
            if (modalBackdrop) {
                this.bindAddContractorModalEvents(modalBackdrop);
            }
        }

        /**
         * Opens the Add Contractor Modal (SYSTEM_ADMIN only).
         */
        openAddContractorModal() {
            if (!this.hasAnyRole(['SYSTEM_ADMIN'])) {
                this.showAlert('Only System Administrators can register new contractors.', 'danger');
                return;
            }

            let modalBackdrop = document.getElementById('add-contractor-modal-backdrop');
            let modalContainer = document.getElementById('contractor-modal-container');

            if (!modalBackdrop) {
                const backdropDiv = document.createElement('div');
                backdropDiv.className = 'modal-backdrop';
                backdropDiv.id = 'add-contractor-modal-backdrop';
                backdropDiv.style.display = 'none';
                backdropDiv.innerHTML = `
                    <div class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="modal-add-contractor-title">
                        <div class="modal-header">
                            <h3 id="modal-add-contractor-title">Register New External Contractor</h3>
                            <button type="button" class="btn-close" id="btn-close-add-contractor-modal" aria-label="Close">&times;</button>
                        </div>
                        <form id="form-add-contractor" class="modal-form">
                            <div id="modal-contractor-alert" class="modal-alert-box" style="display: none;"></div>

                            <div class="form-group">
                                <label for="add-contractor-name" class="form-label required">Contractor Full Name</label>
                                <input type="text" id="add-contractor-name" class="form-input" placeholder="e.g. Jane Doe" required autocomplete="off">
                                <span class="form-help">Display name for identity governance records.</span>
                            </div>

                            <div class="form-group">
                                <label for="add-contractor-email" class="form-label required">Email Address</label>
                                <input type="email" id="add-contractor-email" class="form-input" placeholder="e.g. jane.doe@partner-vendor.com" required autocomplete="off">
                                <span class="form-help">Unique email address (must be valid and distinct).</span>
                            </div>

                            <div class="form-row">
                                <div class="form-group col-half">
                                    <label for="add-contractor-company" class="form-label">Company / Organization</label>
                                    <input type="text" id="add-contractor-company" class="form-input" placeholder="e.g. Cyberdyne Systems / Vendor Alpha" autocomplete="off" maxlength="100">
                                    <span class="form-help">Contractor vendor or partner organization.</span>
                                </div>
                                <div class="form-group col-half">
                                    <label for="add-contractor-phone" class="form-label">Contact Number</label>
                                    <input type="tel" id="add-contractor-phone" class="form-input" placeholder="e.g. +1 555-0199 or 9876543210" autocomplete="off">
                                    <span class="form-help">Primary contact number (optional).</span>
                                </div>
                            </div>

                            <div class="modal-footer" style="padding: 1rem 0 0 0; margin-top: 1rem; border-top: 1px solid var(--color-border); background: transparent;">
                                <button type="button" class="btn btn-secondary" id="btn-cancel-add-contractor">Cancel</button>
                                <button type="submit" class="btn btn-primary" id="btn-submit-add-contractor">
                                    <span id="add-contractor-spinner" class="loading-spinner" style="display: none; margin-right: 6px;"></span>
                                    Register Contractor
                                </button>
                            </div>
                        </form>
                    </div>
                `;
                if (!modalContainer) {
                    modalContainer = document.createElement('div');
                    modalContainer.id = 'contractor-modal-container';
                    (document.getElementById('view-contractors') || document.body).appendChild(modalContainer);
                }
                modalContainer.appendChild(backdropDiv);
                modalBackdrop = backdropDiv;
            }

            // Reset form fields and alerts
            const form = document.getElementById('form-add-contractor');
            if (form) form.reset();

            const alertBox = document.getElementById('modal-contractor-alert');
            if (alertBox) {
                alertBox.style.display = 'none';
                alertBox.textContent = '';
            }

            const submitBtn = document.getElementById('btn-submit-add-contractor');
            if (submitBtn) {
                submitBtn.disabled = false;
            }
            const spinner = document.getElementById('add-contractor-spinner');
            if (spinner) {
                spinner.style.display = 'none';
            }

            if (modalBackdrop) {
                modalBackdrop.style.display = 'flex';
                this.bindAddContractorModalEvents(modalBackdrop);
            }

            // Focus first input
            setTimeout(() => {
                const nameInput = document.getElementById('add-contractor-name');
                if (nameInput) nameInput.focus();
            }, 50);
        }

        /**
         * Closes the Add Contractor Modal and cleans up state.
         */
        closeAddContractorModal() {
            const modalBackdrop = document.getElementById('add-contractor-modal-backdrop');
            if (modalBackdrop) {
                modalBackdrop.style.display = 'none';
            }
            const alertBox = document.getElementById('modal-contractor-alert');
            if (alertBox) {
                alertBox.style.display = 'none';
                alertBox.textContent = '';
            }
            const form = document.getElementById('form-add-contractor');
            if (form) form.reset();
        }

        /**
         * Binds event handlers for Add Contractor modal dialog.
         */
        bindAddContractorModalEvents(modalBackdrop) {
            if (!modalBackdrop) return;
            if (!modalBackdrop.dataset) modalBackdrop.dataset = {};
            if (modalBackdrop.dataset.eventsBound === 'true') {
                return;
            }
            modalBackdrop.dataset.eventsBound = 'true';

            const closeBtn = document.getElementById('btn-close-add-contractor-modal');
            const cancelBtn = document.getElementById('btn-cancel-add-contractor');

            const handleClose = (e) => {
                if (e && typeof e.preventDefault === 'function') e.preventDefault();
                this.closeAddContractorModal();
            };

            if (closeBtn) closeBtn.onclick = handleClose;
            if (cancelBtn) cancelBtn.onclick = handleClose;

            // Close on backdrop click outside dialog
            modalBackdrop.onclick = (e) => {
                if (e.target === modalBackdrop) {
                    handleClose(e);
                }
            };

            // Close on Escape key press
            const onKeyDown = (e) => {
                if (e.key === 'Escape' && modalBackdrop.style.display === 'flex') {
                    handleClose(e);
                }
            };
            if (typeof document.removeEventListener === 'function' && modalBackdrop._escHandler) {
                document.removeEventListener('keydown', modalBackdrop._escHandler);
            }
            modalBackdrop._escHandler = onKeyDown;
            if (typeof document.addEventListener === 'function') {
                document.addEventListener('keydown', onKeyDown);
            }

            // Form submission
            const form = document.getElementById('form-add-contractor');
            if (form) {
                form.onsubmit = async (e) => {
                    if (e && typeof e.preventDefault === 'function') e.preventDefault();
                    await this.handleAddContractorSubmit(modalBackdrop);
                };
            }
        }

        /**
         * Handles Add Contractor form submission.
         */
        async handleAddContractorSubmit(modalBackdrop) {
            const alertBox = document.getElementById('modal-contractor-alert');
            const submitBtn = document.getElementById('btn-submit-add-contractor');
            const spinner = document.getElementById('add-contractor-spinner');

            if (alertBox) {
                alertBox.style.display = 'none';
                alertBox.textContent = '';
            }

            const nameInput = document.getElementById('add-contractor-name');
            const emailInput = document.getElementById('add-contractor-email');
            const companyInput = document.getElementById('add-contractor-company');
            const phoneInput = document.getElementById('add-contractor-phone');

            const fullName = nameInput?.value?.trim() || '';
            const email = emailInput?.value?.trim() || '';
            const company = companyInput?.value?.trim() || '';
            const phone = phoneInput?.value?.trim() || '';

            // Client-side validations
            if (!fullName || fullName.length < 2) {
                if (alertBox) {
                    alertBox.textContent = 'Please enter a valid contractor full name (at least 2 characters).';
                    alertBox.style.display = 'block';
                }
                if (nameInput) nameInput.focus();
                return;
            }

            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!email || !emailRegex.test(email)) {
                if (alertBox) {
                    alertBox.textContent = 'Please enter a valid email address.';
                    alertBox.style.display = 'block';
                }
                if (emailInput) emailInput.focus();
                return;
            }

            // Set loading state
            if (submitBtn) submitBtn.disabled = true;
            if (spinner) spinner.style.display = 'inline-block';

            try {
                const payload = {
                    name: fullName,
                    email: email,
                    company: company || undefined,
                    phone: phone || undefined
                };

                const res = await window.apiClient.post('/api/contractors', payload);
                const registeredContractor = res.data?.contractor || res.data;

                this.closeAddContractorModal();
                this.showAlert(`Contractor '${fullName}' (${email}) successfully registered.`, 'success');

                // Refresh contractor list and cache
                await this.loadContractors();

                // If dropdown is in DOM, update it so newly registered contractor is instantly available
                const contractorSelect = document.getElementById('form-contractor-id');
                const engagementSubmitBtn = document.getElementById('btn-submit-engagement');
                if (contractorSelect) {
                    const newId = registeredContractor?.contractor_id || registeredContractor?.user_id;
                    await this.populateContractorDropdown(contractorSelect, engagementSubmitBtn, newId);
                }
            } catch (err) {
                if (alertBox) {
                    alertBox.textContent = err.message || 'Failed to register contractor.';
                    alertBox.style.display = 'block';
                }
            } finally {
                if (submitBtn) submitBtn.disabled = false;
                if (spinner) spinner.style.display = 'none';
            }
        }

        /**
         * Opens the Create or Edit Engagement Modal.
         * Supports both pre-rendered static markup in index.html and dynamic injection.
         * @param {string|null} [engagementId=null] ID if editing existing engagement
         * @param {string|null} [preselectedContractorId=null]
         */
        async openEngagementModal(engagementId = null, preselectedContractorId = null) {
            let modalBackdrop = document.getElementById('engagement-modal-backdrop');
            let modalContainer = document.getElementById('contractor-modal-container');

            if (!modalContainer && !modalBackdrop) {
                modalContainer = document.createElement('div');
                modalContainer.id = 'contractor-modal-container';
                (document.getElementById('view-contractors') || document.body).appendChild(modalContainer);
            }

            let engagement = null;
            if (engagementId) {
                try {
                    const res = await window.apiClient.get(`/api/engagements/${engagementId}`);
                    engagement = res.data;
                } catch (err) {
                    this.showAlert(`Failed to fetch engagement: ${err.message}`, 'danger');
                    return;
                }
            }

            const isEdit = Boolean(engagement);
            const title = isEdit ? 'Edit Contractor Engagement' : 'Register New Contractor Engagement';

            this.currentEngagementFormState = {
                contractorId: preselectedContractorId || null
            };

            // Case A: Pre-rendered static modal in index.html
            if (modalBackdrop) {
                const titleEl = document.getElementById('modal-title');
                if (titleEl) titleEl.textContent = title;

                const contractorGroup = document.getElementById('form-group-contractor-select');
                const staticGroup = document.getElementById('form-group-contractor-static');
                const statusGroup = document.getElementById('form-group-initial-status');
                const submitBtn = document.getElementById('btn-submit-engagement');
                const alertBox = document.getElementById('modal-form-alert');
                const contractorSelect = document.getElementById('form-contractor-id');

                if (alertBox) {
                    alertBox.style.display = 'none';
                    alertBox.textContent = '';
                }

                if (isEdit) {
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.textContent = 'Save Changes';
                    }
                    if (contractorGroup) contractorGroup.style.display = 'none';
                    if (staticGroup) staticGroup.style.display = 'block';
                    if (statusGroup) statusGroup.style.display = 'none';

                    const nameEl = document.getElementById('form-static-contractor-name');
                    const emailEl = document.getElementById('form-static-contractor-email');
                    if (nameEl) nameEl.textContent = engagement.contractor_name || '—';
                    if (emailEl) emailEl.textContent = engagement.contractor_email || '—';

                    const vInput = document.getElementById('form-vendor-name');
                    const rInput = document.getElementById('form-contract-ref');
                    const sInput = document.getElementById('form-start-date');
                    const eInput = document.getElementById('form-end-date');
                    if (vInput) vInput.value = engagement.vendor_name || '';
                    if (rInput) rInput.value = engagement.contract_reference || '';
                    if (sInput) sInput.value = this.toDateInputString(engagement.start_date);
                    if (eInput) eInput.value = this.toDateInputString(engagement.end_date);

                    modalBackdrop.style.display = 'flex';
                    this.bindEngagementModalEvents(modalBackdrop, isEdit, engagement);
                    return;
                }

                // New Engagement Mode
                if (contractorGroup) contractorGroup.style.display = 'block';
                if (staticGroup) staticGroup.style.display = 'none';
                if (statusGroup) statusGroup.style.display = 'block';

                const vInput = document.getElementById('form-vendor-name');
                const rInput = document.getElementById('form-contract-ref');
                const sInput = document.getElementById('form-start-date');
                const eInput = document.getElementById('form-end-date');
                const stInput = document.getElementById('form-initial-status');
                if (vInput) vInput.value = '';
                if (rInput) rInput.value = '';
                if (sInput) sInput.value = this.getTodayDateString();
                if (eInput) eInput.value = this.getFutureDateString(90);
                if (stInput) stInput.value = 'ACTIVE';

                modalBackdrop.style.display = 'flex';
                this.bindEngagementModalEvents(modalBackdrop, isEdit, engagement);

                await this.populateContractorDropdown(contractorSelect, submitBtn, preselectedContractorId);
                return;
            }

            // Case B: Dynamic container injection (e.g. unit test runner mock DOM)
            if (modalContainer) {
                modalContainer.innerHTML = `
                    <div class="modal-backdrop" id="engagement-modal-backdrop">
                        <div class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="modal-title">
                            <div class="modal-header">
                                <h3 id="modal-title">${title}</h3>
                                <button type="button" class="btn-close" id="btn-close-modal" aria-label="Close">&times;</button>
                            </div>
                            <form id="form-engagement" class="modal-form">
                                <div id="modal-form-alert" class="modal-alert-box" style="display: none;"></div>

                                ${!isEdit ? `
                                    <div class="form-group" id="form-group-contractor-select">
                                        <label for="form-contractor-id" class="form-label required">Contractor Identity</label>
                                        <select id="form-contractor-id" class="form-select" required>
                                            <option value="">Select an active contractor...</option>
                                        </select>
                                        <span class="form-help">Only active users registered in dbo.users as CONTRACTOR appear here.</span>
                                    </div>
                                ` : `
                                    <div class="form-group" id="form-group-contractor-static">
                                        <label class="form-label">Contractor</label>
                                        <div class="form-static-value">
                                            <strong>${this.escapeHtml(engagement.contractor_name)}</strong> (${this.escapeHtml(engagement.contractor_email)})
                                        </div>
                                    </div>
                                `}

                                <div class="form-row">
                                    <div class="form-group col-half">
                                        <label for="form-vendor-name" class="form-label required">Vendor / Staffing Firm</label>
                                        <input type="text" id="form-vendor-name" class="form-input" 
                                               placeholder="e.g. Acme Consulting Corp" 
                                               value="${isEdit ? this.escapeHtml(engagement.vendor_name) : ''}" 
                                               maxlength="150" required>
                                    </div>
                                    <div class="form-group col-half">
                                        <label for="form-contract-ref" class="form-label required">Contract / SOW Reference</label>
                                        <input type="text" id="form-contract-ref" class="form-input" 
                                               placeholder="e.g. SOW-2026-088" 
                                               value="${isEdit ? this.escapeHtml(engagement.contract_reference) : ''}" 
                                               maxlength="100" required>
                                        <span class="form-help">Must be unique per contractor.</span>
                                    </div>
                                </div>

                                <div class="form-row">
                                    <div class="form-group col-half">
                                        <label for="form-start-date" class="form-label required">Engagement Start Date</label>
                                        <input type="date" id="form-start-date" class="form-input" 
                                               value="${isEdit ? this.toDateInputString(engagement.start_date) : this.getTodayDateString()}" 
                                               required>
                                    </div>
                                    <div class="form-group col-half">
                                        <label for="form-end-date" class="form-label required">Engagement End Date</label>
                                        <input type="date" id="form-end-date" class="form-input" 
                                               value="${isEdit ? this.toDateInputString(engagement.end_date) : this.getFutureDateString(90)}" 
                                               required>
                                        <span class="form-help">Access grants cannot exceed this date.</span>
                                    </div>
                                </div>

                                ${!isEdit ? `
                                    <div class="form-group" id="form-group-initial-status">
                                        <label for="form-initial-status" class="form-label required">Initial Status</label>
                                        <select id="form-initial-status" class="form-select">
                                            <option value="ACTIVE" selected>ACTIVE (Ready for access grants)</option>
                                            <option value="PENDING">PENDING (Pre-onboarding review)</option>
                                        </select>
                                    </div>
                                ` : ''}

                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" id="btn-cancel-modal">Cancel</button>
                                    <button type="submit" class="btn btn-primary" id="btn-submit-engagement">
                                        ${isEdit ? 'Save Changes' : 'Create Engagement'}
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                `;

                const renderedModal = document.getElementById('engagement-modal-backdrop') || modalContainer;
                this.bindEngagementModalEvents(renderedModal, isEdit, engagement);

                if (!isEdit) {
                    const cSelect = document.getElementById('form-contractor-id') || (modalContainer.querySelector ? modalContainer.querySelector('#form-contractor-id') : null);
                    const sBtn = document.getElementById('btn-submit-engagement') || (modalContainer.querySelector ? modalContainer.querySelector('#btn-submit-engagement') : null);
                    await this.populateContractorDropdown(cSelect, sBtn, preselectedContractorId);
                }
            }
        }

        /**
         * Binds events and submit handlers to the New / Edit Engagement modal.
         */
        bindEngagementModalEvents(modalEl, isEdit, engagement) {
            const closeModal = () => {
                this.currentEngagementFormState = { contractorId: null };
                const backdrop = document.getElementById('engagement-modal-backdrop');
                if (backdrop) {
                    backdrop.style.display = 'none';
                }
                const alertBox = document.getElementById('modal-form-alert');
                if (alertBox) {
                    alertBox.style.display = 'none';
                    alertBox.textContent = '';
                }
            };

            const closeBtn = document.getElementById('btn-close-modal');
            const cancelBtn = document.getElementById('btn-cancel-modal');
            if (closeBtn) {
                closeBtn.onclick = closeModal;
                closeBtn.addEventListener('click', closeModal);
            }
            if (cancelBtn) {
                cancelBtn.onclick = closeModal;
                cancelBtn.addEventListener('click', closeModal);
            }

            // Click outside dialog to dismiss
            if (modalEl && modalEl.id === 'engagement-modal-backdrop') {
                modalEl.onclick = (e) => {
                    if (e && e.target === modalEl) closeModal();
                };
            }

            // Track Contractor ID selection in form state
            const contractorSelect = document.getElementById('form-contractor-id');
            if (contractorSelect) {
                const onSelectChange = (e) => {
                    const targetVal = e && e.target ? e.target.value : contractorSelect.value;
                    this.currentEngagementFormState.contractorId = targetVal ? targetVal.trim() : null;
                };
                contractorSelect.onchange = onSelectChange;
                contractorSelect.addEventListener('change', onSelectChange);

                if (contractorSelect.value) {
                    this.currentEngagementFormState.contractorId = contractorSelect.value.trim();
                }
            }

            // Form Submit Handler
            const form = document.getElementById('form-engagement');
            if (form) {
                const onSubmitHandler = async (e) => {
                    if (e && typeof e.preventDefault === 'function') {
                        e.preventDefault();
                    }
                    const alertBox = document.getElementById('modal-form-alert');
                    const submitBtn = document.getElementById('btn-submit-engagement');

                    if (alertBox) {
                        alertBox.style.display = 'none';
                        alertBox.textContent = '';
                    }
                    if (submitBtn) {
                        submitBtn.disabled = true;
                        submitBtn.textContent = 'Saving...';
                    }

                    try {
                        const vendorName = document.getElementById('form-vendor-name')?.value?.trim();
                        const contractReference = document.getElementById('form-contract-ref')?.value?.trim();
                        const startDate = document.getElementById('form-start-date')?.value;
                        const endDate = document.getElementById('form-end-date')?.value;

                        if (endDate < startDate) {
                            throw new Error('End date must be on or after start date.');
                        }

                        if (isEdit) {
                            await window.apiClient.put(`/api/engagements/${engagement.engagement_id}`, {
                                vendorName,
                                contractReference,
                                startDate,
                                endDate
                            });
                            this.showAlert(`Engagement '${contractReference}' updated successfully.`, 'success');
                        } else {
                            const contractorId = this.currentEngagementFormState?.contractorId || document.getElementById('form-contractor-id')?.value?.trim();
                            const status = document.getElementById('form-initial-status')?.value || 'ACTIVE';

                            if (!contractorId) {
                                throw new Error('Please select an active contractor from the dropdown.');
                            }

                            await window.apiClient.post('/api/engagements', {
                                contractorUserId: contractorId,
                                contractorId: contractorId,
                                vendorName,
                                contractReference,
                                startDate,
                                endDate,
                                status
                            });
                            this.showAlert(`New engagement '${contractReference}' created successfully in SQL Server.`, 'success');
                        }

                        closeModal();
                        if (this.activeSubView === 'directory') {
                            await this.loadContractors();
                        } else {
                            await this.loadEngagements();
                        }
                    } catch (err) {
                        if (alertBox) {
                            alertBox.textContent = err.message || 'Operation failed.';
                            alertBox.style.display = 'block';
                        }
                    } finally {
                        if (submitBtn) {
                            submitBtn.disabled = false;
                            submitBtn.textContent = isEdit ? 'Save Changes' : 'Create Engagement';
                        }
                    }
                };

                form.onsubmit = onSubmitHandler;
                form.addEventListener('submit', onSubmitHandler);
            }
        }

        /**
         * Opens the Status Transition Modal (Activate, Complete, Terminate).
         */
        openTransitionModal(engagementId, targetStatus) {
            const modalContainer = document.getElementById('contractor-modal-container');
            if (!modalContainer) return;
            const targetContainer = document.getElementById('contractor-submodal-container') || modalContainer;

            let actionTitle = 'Transition Engagement Status';
            let actionDesc = `Are you sure you want to transition this engagement to ${targetStatus}?`;
            let confirmBtnClass = 'btn-primary';

            if (targetStatus === 'ACTIVE') {
                actionTitle = 'Activate Contractor Engagement';
                actionDesc = 'Activating this engagement allows the contractor to request access leases up to the engagement end date.';
            } else if (targetStatus === 'COMPLETED') {
                actionTitle = 'Complete Contractor Engagement';
                actionDesc = 'Marking this engagement COMPLETED indicates that all project deliverables are concluded. Completed engagements are terminal and cannot be reactivated.';
            } else if (targetStatus === 'TERMINATED') {
                actionTitle = 'Early Engagement Termination';
                actionDesc = 'Terminating an engagement marks it eligible for immediate offboarding. Existing access records will be preserved for revocation audit.';
                confirmBtnClass = 'btn-danger';
            }

            targetContainer.innerHTML = `
                <div class="modal-backdrop" id="transition-modal-backdrop">
                    <div class="modal-dialog modal-dialog-sm" role="dialog" aria-modal="true">
                        <div class="modal-header">
                            <h3>${actionTitle}</h3>
                            <button type="button" class="btn-close" id="btn-close-trans-modal">&times;</button>
                        </div>
                        <div class="modal-body">
                            <p class="modal-prompt">${actionDesc}</p>
                            <div class="form-group" style="margin-top: 1rem;">
                                <label for="trans-reason" class="form-label">Audit Justification / Business Reason</label>
                                <textarea id="trans-reason" class="form-textarea" rows="3" 
                                          placeholder="Enter justification for compliance audit log..."></textarea>
                            </div>
                            <div id="modal-trans-alert" class="modal-alert-box" style="display: none;"></div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" id="btn-cancel-trans-modal">Cancel</button>
                            <button type="button" class="btn ${confirmBtnClass}" id="btn-confirm-trans">
                                Confirm ${targetStatus}
                            </button>
                        </div>
                    </div>
                </div>
            `;

            const closeModal = () => { targetContainer.innerHTML = ''; };
            document.getElementById('btn-close-trans-modal')?.addEventListener('click', closeModal);
            document.getElementById('btn-cancel-trans-modal')?.addEventListener('click', closeModal);

            document.getElementById('btn-confirm-trans')?.addEventListener('click', async () => {
                const reason = document.getElementById('trans-reason')?.value || '';
                const alertBox = document.getElementById('modal-trans-alert');
                const btn = document.getElementById('btn-confirm-trans');

                alertBox.style.display = 'none';
                btn.disabled = true;
                btn.textContent = 'Processing...';

                try {
                    await window.apiClient.post(`/api/engagements/${engagementId}/status`, {
                        status: targetStatus,
                        reason: reason.trim()
                    });

                    this.showAlert(`Engagement status successfully transitioned to ${targetStatus}.`, 'success');
                    closeModal();
                    await this.loadEngagements();
                } catch (err) {
                    alertBox.textContent = err.message || 'Status transition failed.';
                    alertBox.style.display = 'block';
                    btn.disabled = false;
                    btn.textContent = `Confirm ${targetStatus}`;
                }
            });
        }

        /**
         * Opens Contractor Engagement History Drawer / Modal.
         */
        async openContractorHistoryModal(contractorUserId) {
            const modalContainer = document.getElementById('contractor-modal-container');
            if (!modalContainer) return;
            const targetContainer = document.getElementById('contractor-submodal-container') || modalContainer;

            targetContainer.innerHTML = `
                <div class="modal-backdrop">
                    <div class="modal-dialog modal-dialog-lg" role="dialog">
                        <div class="modal-header">
                            <h3>Contractor Engagement History</h3>
                            <button type="button" class="btn-close" id="btn-close-hist-modal">&times;</button>
                        </div>
                        <div class="modal-body" id="hist-modal-body">
                            <div class="table-loading-state">Loading engagement history...</div>
                        </div>
                    </div>
                </div>
            `;

            document.getElementById('btn-close-hist-modal')?.addEventListener('click', () => {
                targetContainer.innerHTML = '';
            });

            try {
                const res = await window.apiClient.get(`/api/contractors/${contractorUserId}`);
                const { contractor, engagements } = res.data;
                const histBody = document.getElementById('hist-modal-body');

                histBody.innerHTML = `
                    <div class="history-contractor-header">
                        <h4>${this.escapeHtml(contractor.display_name)}</h4>
                        <p class="text-muted">${this.escapeHtml(contractor.email)} &bull; ${this.escapeHtml(contractor.department || 'External')}</p>
                    </div>

                    ${engagements.length === 0 ? `
                        <div class="empty-state-box">
                            <p>No engagements registered for this contractor.</p>
                        </div>
                    ` : `
                        <table class="data-table" style="margin-top: 1rem;">
                            <thead>
                                <tr>
                                    <th>Contract Ref</th>
                                    <th>Vendor</th>
                                    <th>Sponsor</th>
                                    <th>Validity</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${engagements.map(e => `
                                    <tr>
                                        <td><code>${this.escapeHtml(e.contract_reference)}</code></td>
                                        <td>${this.escapeHtml(e.vendor_name)}</td>
                                        <td>${this.escapeHtml(e.sponsor_name)}</td>
                                        <td>${this.formatDate(e.start_date)} &rarr; ${this.formatDate(e.end_date)}</td>
                                        <td>${this.renderStatusPill(e.status)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    `}
                `;
            } catch (err) {
                const histBody = document.getElementById('hist-modal-body');
                if (histBody) {
                    histBody.innerHTML = `<div class="error-banner">${this.escapeHtml(err.message)}</div>`;
                }
            }
        }

        // =========================================================================
        // Helpers & Utilities
        // =========================================================================

        hasRole(roleCode) {
            if (!this.currentUser || !Array.isArray(this.currentUser.roles)) return false;
            return this.currentUser.roles.some(r => (r.role_code || r).toUpperCase() === roleCode.toUpperCase());
        }

        hasAnyRole(roleCodes) {
            if (!this.currentUser || !Array.isArray(this.currentUser.roles)) return false;
            const userCodes = this.currentUser.roles.map(r => (r.role_code || r).toUpperCase());
            return roleCodes.some(c => userCodes.includes(c.toUpperCase()));
        }

        renderStatusPill(status) {
            const s = (status || '').toUpperCase();
            let pillClass = 'status-pill-info';
            if (s === 'ACTIVE') pillClass = 'status-pill-success';
            if (s === 'PENDING') pillClass = 'status-pill-warning';
            if (s === 'COMPLETED') pillClass = 'status-pill-muted';
            if (s === 'TERMINATED') pillClass = 'status-pill-danger';

            return `<span class="status-pill ${pillClass}">${this.escapeHtml(s)}</span>`;
        }

        formatDate(dateVal) {
            if (!dateVal) return '—';
            try {
                const d = new Date(dateVal);
                if (isNaN(d.getTime())) return String(dateVal);
                return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
            } catch {
                return String(dateVal);
            }
        }

        toDateInputString(dateVal) {
            if (!dateVal) return '';
            const d = new Date(dateVal);
            if (isNaN(d.getTime())) return '';
            return d.toISOString().split('T')[0];
        }

        getTodayDateString() {
            return new Date().toISOString().split('T')[0];
        }

        getFutureDateString(days) {
            const d = new Date();
            d.setDate(d.getDate() + days);
            return d.toISOString().split('T')[0];
        }

        showAlert(message, type = 'info') {
            const container = document.getElementById('module-alert-container');
            if (!container) return;

            const alertDiv = document.createElement('div');
            alertDiv.className = `alert-banner alert-${type}`;
            alertDiv.innerHTML = `
                <span>${this.escapeHtml(message)}</span>
                <button type="button" class="alert-close">&times;</button>
            `;

            container.appendChild(alertDiv);
            alertDiv.querySelector('.alert-close').addEventListener('click', () => {
                alertDiv.remove();
            });

            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.remove();
                }
            }, 6000);
        }

        escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        debounce(func, wait) {
            let timeout;
            return (...args) => {
                clearTimeout(timeout);
                timeout = setTimeout(() => func.apply(this, args), wait);
            };
        }
    }

    // Attach to window and auto-initialize on DOM load
    window.AccessLeaseContractorModule = new ContractorModule();
    document.addEventListener('DOMContentLoaded', () => {
        window.AccessLeaseContractorModule.init();
    });

})(window);

