/**
 * AccessLease — Audit & Compliance Trail Module
 * Connects to live dbo.audit_events via /api/audit/events.
 * Provides real-time filtering, cryptographic payload inspection, and regulatory export packages.
 */

(function(window) {
    'use strict';

    class AccessLeaseAuditModule {
        constructor() {
            this.eventsList = [];
            this.stats = null;
            this.totalEvents = 0;
            this.currentPage = 1;
            this.pageSize = 50;
            this.searchQuery = '';
            this.categoryFilter = '';
            this.entityFilter = '';
            this.debounceTimer = null;
            this.initialized = false;
        }

        init() {
            if (this.initialized) return;
            this.initialized = true;

            // Wire refresh
            document.getElementById('btn-refresh-audit')?.addEventListener('click', () => {
                this.loadAuditTrail(true);
            });

            // Wire search with debouncing
            const searchInput = document.getElementById('audit-search-input');
            if (searchInput) {
                searchInput.addEventListener('input', (e) => {
                    clearTimeout(this.debounceTimer);
                    this.debounceTimer = setTimeout(() => {
                        this.searchQuery = e.target.value.trim();
                        this.currentPage = 1;
                        this.loadEventsTable();
                    }, 350);
                });
            }

            // Wire category filter
            document.getElementById('audit-filter-category')?.addEventListener('change', (e) => {
                this.categoryFilter = e.target.value;
                this.currentPage = 1;
                this.loadEventsTable();
            });

            // Wire entity type filter
            document.getElementById('audit-filter-entity')?.addEventListener('change', (e) => {
                this.entityFilter = e.target.value;
                this.currentPage = 1;
                this.loadEventsTable();
            });

            // Wire page size filter
            document.getElementById('audit-filter-limit')?.addEventListener('change', (e) => {
                this.pageSize = parseInt(e.target.value, 10) || 50;
                this.currentPage = 1;
                this.loadEventsTable();
            });

            // Wire pagination buttons
            document.getElementById('audit-page-prev')?.addEventListener('click', () => {
                if (this.currentPage > 1) {
                    this.currentPage--;
                    this.loadEventsTable();
                }
            });

            document.getElementById('audit-page-next')?.addEventListener('click', () => {
                const maxPage = Math.ceil(this.totalEvents / this.pageSize) || 1;
                if (this.currentPage < maxPage) {
                    this.currentPage++;
                    this.loadEventsTable();
                }
            });

            // Wire export buttons
            document.getElementById('btn-export-audit-csv')?.addEventListener('click', () => {
                this.exportToCsv();
            });

            document.getElementById('btn-export-audit-json')?.addEventListener('click', () => {
                this.exportToJson();
            });
        }

        async loadAuditTrail(refreshStats = true) {
            this.init();
            if (refreshStats) {
                await this.loadStats();
            }
            await this.loadEventsTable();
        }

        async loadStats() {
            try {
                const res = await window.apiClient.getAuditStats();
                this.stats = res?.data?.stats || null;
                this.renderStats();
            } catch (err) {
                console.warn('[AccessLeaseAudit] Could not load audit stats:', err.message);
            }
        }

        renderStats() {
            if (!this.stats) return;

            const totalEl = document.getElementById('audit-stat-total');
            const todayEl = document.getElementById('audit-stat-today');
            const securityEl = document.getElementById('audit-stat-security');
            const revocationEl = document.getElementById('audit-stat-revocation');

            if (totalEl) totalEl.textContent = Number(this.stats.totalEvents || 0).toLocaleString();
            if (todayEl) todayEl.textContent = Number(this.stats.todayEvents || 0).toLocaleString();
            if (securityEl) securityEl.textContent = Number(this.stats.securityEvents || 0).toLocaleString();
            if (revocationEl) revocationEl.textContent = Number(this.stats.revocationEvents || 0).toLocaleString();
        }

        async loadEventsTable() {
            const tableBody = document.getElementById('audit-table-body');
            const emptyState = document.getElementById('audit-empty-state');
            const paginationInfo = document.getElementById('audit-pagination-info');
            const prevBtn = document.getElementById('audit-page-prev');
            const nextBtn = document.getElementById('audit-page-next');

            if (!tableBody) return;

            tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center" style="padding: 2.5rem; color: var(--color-text-secondary, #64748b);">
                        <div class="table-loading-spinner" style="margin-bottom: 0.5rem;">Loading immutable audit trail records...</div>
                    </td>
                </tr>
            `;

            try {
                const offset = (this.currentPage - 1) * this.pageSize;
                const params = {
                    limit: this.pageSize,
                    offset: offset
                };

                if (this.searchQuery) params.search = this.searchQuery;
                if (this.categoryFilter) params.eventCategory = this.categoryFilter;
                if (this.entityFilter) params.entityType = this.entityFilter;

                const res = await window.apiClient.listAuditEvents(params);
                this.eventsList = res?.data?.events || [];
                this.totalEvents = res?.data?.total || 0;

                if (this.eventsList.length === 0) {
                    tableBody.innerHTML = '';
                    if (emptyState) emptyState.style.display = 'block';
                    if (paginationInfo) paginationInfo.textContent = '0 - 0 of 0 events';
                    if (prevBtn) prevBtn.disabled = true;
                    if (nextBtn) nextBtn.disabled = true;
                    return;
                }

                if (emptyState) emptyState.style.display = 'none';

                // Render rows
                tableBody.innerHTML = this.eventsList.map(evt => this.renderTableRow(evt)).join('');

                // Wire payload modal triggers
                tableBody.querySelectorAll('.btn-inspect-payload').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const eventId = btn.getAttribute('data-id');
                        this.openPayloadModal(eventId);
                    });
                });

                // Update pagination controls
                const startIdx = offset + 1;
                const endIdx = Math.min(offset + this.eventsList.length, this.totalEvents);
                const maxPage = Math.ceil(this.totalEvents / this.pageSize) || 1;

                if (paginationInfo) {
                    paginationInfo.textContent = `Showing ${startIdx.toLocaleString()} – ${endIdx.toLocaleString()} of ${this.totalEvents.toLocaleString()} events (Page ${this.currentPage} of ${maxPage})`;
                }
                if (prevBtn) prevBtn.disabled = (this.currentPage <= 1);
                if (nextBtn) nextBtn.disabled = (this.currentPage >= maxPage);

            } catch (err) {
                console.error('[AccessLeaseAudit] Failed to load events:', err);
                tableBody.innerHTML = `
                    <tr>
                        <td colspan="6" class="text-center" style="padding: 2rem; color: #dc2626;">
                            <strong>Failed to load audit events:</strong> ${this.escapeHtml(err.message || 'Unknown error')}
                        </td>
                    </tr>
                `;
            }
        }

        renderTableRow(evt) {
            const categoryBadgeClass = this.getCategoryBadgeClass(evt.eventCategory);
            const formattedTime = this.formatDateTime(evt.createdAt);
            const actorDisplay = evt.actorName || evt.actorEmail || evt.actorUserId || 'System Engine';
            const actorSub = evt.actorEmail && evt.actorName ? evt.actorEmail : (evt.actorType || 'SYSTEM');

            return `
                <tr class="audit-row" data-id="${evt.eventId}">
                    <td>
                        <div class="strong font-mono" style="font-size: 0.85rem;">#${evt.eventId}</div>
                        <div class="form-help" style="font-size: 0.75rem;">${formattedTime}</div>
                    </td>
                    <td>
                        <span class="nav-badge ${categoryBadgeClass}" style="margin-bottom: 0.25rem;">${this.escapeHtml(evt.eventCategory || 'AUDIT')}</span>
                        <div class="strong" style="font-size: 0.8rem; font-family: monospace;">${this.escapeHtml(evt.eventAction || '')}</div>
                    </td>
                    <td>
                        <div class="strong" style="font-size: 0.85rem;">${this.escapeHtml(evt.entityType || 'entity')}</div>
                        <div class="form-help font-mono" style="font-size: 0.75rem; max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${this.escapeHtml(String(evt.entityId || ''))}">
                            ${this.escapeHtml(String(evt.entityId || ''))}
                        </div>
                    </td>
                    <td>
                        <div class="strong" style="font-size: 0.85rem;">${this.escapeHtml(actorDisplay)}</div>
                        <div class="form-help" style="font-size: 0.75rem;">${this.escapeHtml(actorSub)}</div>
                    </td>
                    <td>
                        <span class="font-mono" style="font-size: 0.8rem; color: var(--color-text-secondary, #64748b);">
                            ${this.escapeHtml(evt.ipAddress || 'Internal')}
                        </span>
                    </td>
                    <td style="text-align: right;">
                        <button type="button" class="btn btn-sm btn-outline btn-inspect-payload" data-id="${evt.eventId}">
                            Inspect Payload &rarr;
                        </button>
                    </td>
                </tr>
            `;
        }

        openPayloadModal(eventId) {
            const evt = this.eventsList.find(e => String(e.eventId) === String(eventId));
            if (!evt) return;

            const modalContainer = document.getElementById('audit-payload-modal-container');
            if (!modalContainer) return;

            const jsonPretty = JSON.stringify(evt.payload || {}, null, 2);

            modalContainer.innerHTML = `
                <div class="modal-backdrop" id="audit-modal-backdrop">
                    <div class="modal-dialog modal-lg" role="dialog" aria-modal="true" style="max-width: 720px;">
                        <div class="modal-header" style="display: flex; justify-content: space-between; align-items: flex-start; padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--color-border);">
                            <div>
                                <div class="badge-status" style="margin-bottom: 0.25rem;">Immutable Cryptographic Record</div>
                                <h3 style="margin: 0; font-size: 1.2rem;">Audit Event Ledger #${evt.eventId}</h3>
                                <div class="form-help" style="font-size: 0.8rem; margin-top: 0.25rem;">
                                    Recorded at ${this.formatDateTime(evt.createdAt)} UTC &bull; Category: ${this.escapeHtml(evt.eventCategory)}
                                </div>
                            </div>
                            <button type="button" class="btn-close" id="btn-close-audit-modal" aria-label="Close modal">&times;</button>
                        </div>
                        <div class="modal-body" style="padding: 1.25rem 1.5rem; max-height: calc(85vh - 160px); overflow-y: auto;">
                            <!-- Metadata Grid -->
                            <div class="identity-details-grid" style="margin-bottom: 1.25rem;">
                                <div class="id-detail-item">
                                    <span class="id-label">Event Action</span>
                                    <span class="id-value font-mono strong">${this.escapeHtml(evt.eventAction)}</span>
                                </div>
                                <div class="id-detail-item">
                                    <span class="id-label">Target Entity</span>
                                    <span class="id-value font-mono">${this.escapeHtml(evt.entityType)} &bull; ${this.escapeHtml(String(evt.entityId))}</span>
                                </div>
                                <div class="id-detail-item">
                                    <span class="id-label">Actor Attribution</span>
                                    <span class="id-value">${this.escapeHtml(evt.actorName || evt.actorEmail || evt.actorType || 'SYSTEM')}</span>
                                </div>
                                <div class="id-detail-item">
                                    <span class="id-label">Client IP / Origin</span>
                                    <span class="id-value font-mono">${this.escapeHtml(evt.ipAddress || 'Internal Azure Services')}</span>
                                </div>
                            </div>

                            <!-- Structured Payload Block -->
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                                <label class="form-label" style="margin: 0;"><strong>Cryptographic Event Payload (JSON)</strong></label>
                                <button type="button" class="btn btn-sm btn-outline" id="btn-copy-payload">Copy JSON</button>
                            </div>
                            <pre style="background: #0f172a; color: #38bdf8; padding: 1rem; border-radius: var(--border-radius, 8px); font-family: monospace; font-size: 0.8rem; overflow-x: auto; max-height: 280px; border: 1px solid #1e293b;"><code>${this.escapeHtml(jsonPretty)}</code></pre>
                        </div>
                        <div class="modal-footer" style="padding: 1rem 1.5rem; display: flex; justify-content: flex-end; gap: 0.5rem; border-top: 1px solid var(--color-border);">
                            <button type="button" class="btn btn-secondary" id="btn-modal-audit-close">Close</button>
                        </div>
                    </div>
                </div>
            `;

            const closeModal = () => { modalContainer.innerHTML = ''; };
            document.getElementById('btn-close-audit-modal')?.addEventListener('click', closeModal);
            document.getElementById('btn-modal-audit-close')?.addEventListener('click', closeModal);
            document.getElementById('audit-modal-backdrop')?.addEventListener('click', (e) => {
                if (e.target.id === 'audit-modal-backdrop') closeModal();
            });

            // Copy JSON
            document.getElementById('btn-copy-payload')?.addEventListener('click', () => {
                navigator.clipboard.writeText(jsonPretty).then(() => {
                    const btn = document.getElementById('btn-copy-payload');
                    if (btn) btn.textContent = 'Copied!';
                    setTimeout(() => { if (btn) btn.textContent = 'Copy JSON'; }, 2000);
                });
            });
        }

        exportToCsv() {
            if (!this.eventsList.length) {
                alert('No audit events currently loaded to export.');
                return;
            }

            const headers = ['Event ID', 'Timestamp (UTC)', 'Category', 'Action', 'Entity Type', 'Entity ID', 'Actor Name', 'Actor Email', 'Actor Type', 'IP Address'];
            const rows = this.eventsList.map(e => [
                e.eventId,
                new Date(e.createdAt).toISOString(),
                e.eventCategory,
                e.eventAction,
                e.entityType,
                e.entityId,
                e.actorName || '',
                e.actorEmail || '',
                e.actorType || '',
                e.ipAddress || ''
            ]);

            const csvContent = [
                headers.map(h => `"${h}"`).join(','),
                ...rows.map(row => row.map(val => `"${String(val).replace(/"/g, '""')}"`).join(','))
            ].join('\r\n');

            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.setAttribute('href', url);
            link.setAttribute('download', `accesslease-compliance-audit-export-${new Date().toISOString().slice(0, 10)}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        exportToJson() {
            if (!this.eventsList.length) {
                alert('No audit events currently loaded to export.');
                return;
            }

            const exportData = {
                exportMetadata: {
                    platform: 'AccessLease Enterprise IGA',
                    exportDate: new Date().toISOString(),
                    totalRecords: this.eventsList.length,
                    standard: 'SOC2-ISO27001-ITGC Compliance Package'
                },
                auditEvents: this.eventsList
            };

            const jsonStr = JSON.stringify(exportData, null, 2);
            const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.setAttribute('href', url);
            link.setAttribute('download', `accesslease-compliance-audit-package-${new Date().toISOString().slice(0, 10)}.json`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        getCategoryBadgeClass(category) {
            const cat = (category || '').toUpperCase();
            switch (cat) {
                case 'APPROVAL':
                case 'GRANT':
                    return 'nav-badge-active';
                case 'SECURITY':
                case 'SECURITY_OFFICER':
                    return 'nav-badge-admin';
                case 'REVOCATION':
                    return 'badge-rejected';
                case 'ORPHAN_DETECTION':
                    return 'badge-pending';
                default:
                    return 'badge-active';
            }
        }

        formatDateTime(isoString) {
            if (!isoString) return '—';
            try {
                const date = new Date(isoString);
                if (isNaN(date.getTime())) return isoString;
                return date.toLocaleString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    year: 'numeric',
                    hour: 'numeric',
                    minute: '2-digit',
                    hour12: true,
                    timeZone: 'UTC'
                }) + ' UTC';
            } catch {
                return isoString;
            }
        }

        escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }
    }

    // Export singleton
    window.AccessLeaseAudit = new AccessLeaseAuditModule();

})(window);
