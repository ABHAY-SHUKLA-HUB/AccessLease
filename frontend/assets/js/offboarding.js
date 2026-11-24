/**
 * AccessLease — Automated Expiry, Revocation & Offboarding Frontend Module
 * 
 * Rules:
 * - Pure Vanilla JavaScript (ES6+)
 * - No mock or hardcoded statistics — all data loaded from backend APIs
 * - Live offboarding queue, manual retry for authorized roles, manual review resolution
 */

(function () {
    'use strict';

    let currentFilterStatus = '';

    /**
     * Initializes the Offboarding & Revocation UI module.
     */
    function init() {
        console.info('[AccessLease Offboarding] Initializing module...');
        attachEventListeners();
    }

    /**
     * Attaches event listeners for actions and filters.
     */
    function attachEventListeners() {
        const scanBtn = document.getElementById('btn-trigger-expiry-scan');
        if (scanBtn) {
            scanBtn.addEventListener('click', triggerExpiryScan);
        }

        const refreshBtn = document.getElementById('btn-refresh-revocation-queue');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', loadOffboardingView);
        }

        const statusFilter = document.getElementById('revocation-status-filter');
        if (statusFilter) {
            statusFilter.addEventListener('change', (e) => {
                currentFilterStatus = e.target.value;
                loadRevocationQueue();
            });
        }

        const terminateBtn = document.getElementById('btn-terminate-engagement');
        if (terminateBtn) {
            terminateBtn.addEventListener('click', handleTerminateEngagement);
        }
    }

    /**
     * Loads the entire offboarding view including KPIs and queue table.
     */
    async function loadOffboardingView() {
        console.info('[AccessLease Offboarding] Loading offboarding data...');
        await Promise.all([
            loadRevocationQueue(),
            loadExpiringGrantsOverview()
        ]);
    }

    /**
     * Fetches and renders the revocation queue and updates metric cards.
     */
    async function loadRevocationQueue() {
        const tableBody = document.getElementById('revocation-jobs-tbody');
        const emptyState = document.getElementById('revocation-empty-state');
        const loadingState = document.getElementById('revocation-loading-state');

        if (loadingState) loadingState.style.display = 'block';
        if (emptyState) emptyState.style.display = 'none';

        try {
            let url = '/api/revocation/jobs?limit=50';
            if (currentFilterStatus) {
                url += `&status=${encodeURIComponent(currentFilterStatus)}`;
            }

            const response = await window.apiClient.get(url);
            const data = response?.data || {};
            const items = data.items || [];

            updateMetricCards(items);

            if (loadingState) loadingState.style.display = 'none';

            if (!items || items.length === 0) {
                if (tableBody) tableBody.innerHTML = '';
                if (emptyState) emptyState.style.display = 'block';
                return;
            }

            if (emptyState) emptyState.style.display = 'none';
            if (tableBody) {
                tableBody.innerHTML = items.map(job => renderJobRow(job)).join('');
                attachRowActionHandlers(tableBody);
            }
        } catch (err) {
            console.error('[AccessLease Offboarding] Failed to load revocation queue:', err);
            if (loadingState) loadingState.style.display = 'none';
            if (tableBody) {
                tableBody.innerHTML = `<tr><td colspan="7" class="text-error text-center">Failed to load revocation queue: ${escapeHtml(err.message)}</td></tr>`;
            }
        }
    }

    /**
     * Fetches expiring grants overview to populate upcoming expiries.
     */
    async function loadExpiringGrantsOverview() {
        const container = document.getElementById('expiring-grants-list');
        if (!container) return;

        try {
            const response = await window.apiClient.get('/api/provisioning/grants?status=ACTIVE&limit=20');
            const grants = response?.data?.items || response?.data || [];

            const now = new Date();
            const soon = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // next 7 days

            const expiringSoon = grants.filter(g => {
                if (!g.expires_at) return false;
                const exp = new Date(g.expires_at);
                return exp <= soon;
            });

            const kpiExpiring = document.getElementById('kpi-expiring-grants-count');
            if (kpiExpiring) {
                kpiExpiring.textContent = expiringSoon.length;
            }

            if (expiringSoon.length === 0) {
                container.innerHTML = '<p class="text-muted">No active access grants expiring within the next 7 days.</p>';
                return;
            }

            container.innerHTML = `
                <div class="table-responsive">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Grant #</th>
                                <th>Contractor</th>
                                <th>Target Team</th>
                                <th>Expires At (UTC)</th>
                                <th>Provenance</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${expiringSoon.map(g => `
                                <tr>
                                    <td><code>${escapeHtml(g.grant_number || g.grant_id?.substring(0, 8))}</code></td>
                                    <td>${escapeHtml(g.contractor_name || g.external_username || '—')}</td>
                                    <td>${escapeHtml((g.target_org ? g.target_org + '/' : '') + (g.target_team_slug || '—'))}</td>
                                    <td>${g.expires_at ? new Date(g.expires_at).toUTCString() : '—'}</td>
                                    <td><span class="status-pill status-pill-neutral">${escapeHtml(g.membership_provenance || 'UNKNOWN')}</span></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } catch (err) {
            console.warn('[AccessLease Offboarding] Failed to load expiring grants overview:', err.message);
        }
    }

    /**
     * Updates KPI metric cards based on current queue items.
     */
    function updateMetricCards(items) {
        const queuedCount = items.filter(j => ['QUEUED', 'PROCESSING', 'IN_PROGRESS'].includes(j.status)).length;
        const confirmedCount = items.filter(j => ['REVOKED', 'CONFIRMED'].includes(j.status)).length;
        const reviewCount = items.filter(j => j.status === 'MANUAL_REVIEW_REQUIRED').length;
        const failedCount = items.filter(j => ['FAILED_RETRY', 'PERMANENT_FAILURE'].includes(j.status)).length;

        const kpiQueued = document.getElementById('kpi-queued-revocations');
        const kpiConfirmed = document.getElementById('kpi-confirmed-revocations');
        const kpiReview = document.getElementById('kpi-review-required');
        const kpiFailed = document.getElementById('kpi-failed-revocations');

        if (kpiQueued) kpiQueued.textContent = queuedCount;
        if (kpiConfirmed) kpiConfirmed.textContent = confirmedCount;
        if (kpiReview) kpiReview.textContent = reviewCount;
        if (kpiFailed) kpiFailed.textContent = failedCount;
    }

    /**
     * Renders a table row for a revocation job.
     */
    function renderJobRow(job) {
        const statusClass = getStatusPillClass(job.status);
        const provenanceClass = job.membership_provenance === 'CREATED_BY_ACCESSLEASE' ? 'status-pill-success' : 'status-pill-warning';

        const canRetry = ['FAILED_RETRY', 'PERMANENT_FAILURE', 'MANUAL_REVIEW_REQUIRED'].includes(job.status);
        const isManualReview = job.status === 'MANUAL_REVIEW_REQUIRED';

        let statusBadge = `<span class="status-pill ${statusClass}">${escapeHtml(job.status)}</span>`;
        if (job.status === 'REVOKED' || job.status === 'CONFIRMED') {
            const isShared = (job.connector_response && typeof job.connector_response === 'string' && job.connector_response.includes('SHARED_MEMBERSHIP_RETAINED'))
                || (job.connector_response && job.connector_response.reason === 'SHARED_MEMBERSHIP_RETAINED')
                || (job.last_error_message && job.last_error_message.includes('Shared membership'));
            if (isShared) {
                statusBadge = `<span class="status-pill status-pill-info" title="Team membership retained for another active grant">RETAINED (Shared)</span>`;
            } else {
                statusBadge = `<span class="status-pill status-pill-success" title="Provider membership deleted and verified absent">REVOKED (Removed)</span>`;
            }
        }

        let actionHtml = '—';
        if (isManualReview) {
            actionHtml = `
                <div class="btn-group">
                    <button class="btn btn-sm btn-warning btn-resolve-review" data-job-id="${job.job_id}">Resolve</button>
                    <button class="btn btn-sm btn-outline btn-retry-job" data-job-id="${job.job_id}">Retry</button>
                </div>
            `;
        } else if (canRetry) {
            actionHtml = `<button class="btn btn-sm btn-outline btn-retry-job" data-job-id="${job.job_id}">Retry</button>`;
        }

        return `
            <tr data-job-id="${job.job_id}">
                <td>
                    <strong>${escapeHtml(job.grant_number || job.grant_id?.substring(0, 8))}</strong>
                    <div class="text-muted small">${job.job_id.substring(0, 8)}...</div>
                </td>
                <td>
                    <div>${escapeHtml(job.contractor_name || 'Contractor')}</div>
                    <div class="text-muted small">@${escapeHtml(job.external_username || 'unlinked')}</div>
                </td>
                <td>
                    <div>${escapeHtml((job.target_org ? job.target_org + '/' : '') + (job.target_team_slug || '—'))}</div>
                    <div class="text-muted small">${escapeHtml(job.trigger_source || '—')}</div>
                </td>
                <td>
                    <span class="status-pill ${provenanceClass}">${escapeHtml(job.membership_provenance || 'UNKNOWN')}</span>
                </td>
                <td>
                    ${statusBadge}
                    ${job.retry_count > 0 ? `<span class="text-muted small"> (Try ${job.retry_count}/${job.max_retries})</span>` : ''}
                </td>
                <td>
                    <div class="text-truncate" style="max-width: 220px;" title="${escapeHtml(job.last_error_message || job.error_details || '—')}">
                        ${escapeHtml(job.last_error_message || job.error_details || '—')}
                    </div>
                    ${job.confirmed_at ? `<div class="text-success small">Confirmed: ${new Date(job.confirmed_at).toLocaleTimeString()}</div>` : ''}
                </td>
                <td>${actionHtml}</td>
            </tr>
        `;
    }

    /**
     * Attaches click handlers to action buttons in the revocation table.
     */
    function attachRowActionHandlers(tbody) {
        tbody.querySelectorAll('.btn-retry-job').forEach(btn => {
            btn.addEventListener('click', async () => {
                const jobId = btn.getAttribute('data-job-id');
                btn.disabled = true;
                btn.textContent = 'Retrying...';
                try {
                    await window.apiClient.post(`/api/revocation/jobs/${jobId}/retry`);
                    alert('Job requeued and processed for manual retry.');
                    await loadRevocationQueue();
                } catch (err) {
                    alert(`Retry failed: ${err.message}`);
                    btn.disabled = false;
                    btn.textContent = 'Retry';
                }
            });
        });

        tbody.querySelectorAll('.btn-resolve-review').forEach(btn => {
            btn.addEventListener('click', async () => {
                const jobId = btn.getAttribute('data-job-id');
                const decision = prompt(
                    'Enter resolution decision:\n' +
                    '- CONFIRMED_REVOKED: Manually confirm access has been revoked externally\n' +
                    '- RETRY: Re-attempt automated revocation\n' +
                    '- DISMISSED: Keep existing membership without further action',
                    'CONFIRMED_REVOKED'
                );

                if (!decision) return;

                const notes = prompt('Enter resolution investigation notes (optional):', 'Manually verified via GitHub security console');

                try {
                    await window.apiClient.post(`/api/revocation/jobs/${jobId}/resolve`, {
                        decision: decision.trim().toUpperCase(),
                        notes: notes ? notes.trim() : null
                    });
                    alert('Manual review exception resolved successfully.');
                    await loadRevocationQueue();
                } catch (err) {
                    alert(`Resolution failed: ${err.message}`);
                }
            });
        });
    }

    /**
     * Triggers the scheduled expiry and termination scan.
     */
    async function triggerExpiryScan() {
        const btn = document.getElementById('btn-trigger-expiry-scan');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Scanning...';
        }

        try {
            const res = await window.apiClient.post('/api/revocation/scan', { batchSize: 50 });
            const data = res?.data || {};
            alert(`Expiry scan completed!\nScanned: ${data.scannedCount || 0}\nJobs Enqueued: ${data.jobsCreated || 0}`);
            await loadOffboardingView();
        } catch (err) {
            alert(`Expiry scan failed: ${err.message}`);
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Trigger Expiry Scan';
            }
        }
    }

    /**
     * Handles immediate contractor engagement termination.
     */
    async function handleTerminateEngagement() {
        const engagementIdInput = document.getElementById('offboarding-engagement-id');
        const reasonInput = document.getElementById('offboarding-reason');
        const progressContainer = document.getElementById('offboarding-progress-display');

        const engagementId = engagementIdInput ? engagementIdInput.value.trim() : '';
        const reason = reasonInput ? reasonInput.value.trim() : 'Administrative offboarding';

        if (!engagementId) {
            alert('Please enter or select a valid Engagement ID to offboard.');
            return;
        }

        const confirmTermination = confirm(`Are you sure you want to terminate engagement '${engagementId}' and immediately revoke all associated access grants?`);
        if (!confirmTermination) return;

        try {
            const res = await window.apiClient.post(`/api/contractors/engagements/${engagementId}/terminate`, { reason });
            const data = res?.data || {};

            alert(`Engagement terminated successfully. Enqueued ${data.grantsQueued || 0} grant revocation(s).`);

            if (progressContainer && data.offboardingStatus) {
                const s = data.offboardingStatus;
                progressContainer.innerHTML = `
                    <div class="alert alert-info">
                        <strong>Offboarding Status: ${escapeHtml(s.overallState)}</strong>
                        <div>Total Grants: ${s.totalGrants} | Revoked: ${s.revokedGrants} | Pending: ${s.pendingJobs} | Review Required: ${s.manualReviewJobs}</div>
                    </div>
                `;
            }

            await loadOffboardingView();
        } catch (err) {
            alert(`Offboarding failed: ${err.message}`);
        }
    }

    function getStatusPillClass(status) {
        switch (status) {
            case 'REVOKED':
            case 'CONFIRMED':
                return 'status-pill-success';
            case 'QUEUED':
            case 'PROCESSING':
            case 'IN_PROGRESS':
                return 'status-pill-warning';
            case 'FAILED_RETRY':
                return 'status-pill-warning';
            case 'PERMANENT_FAILURE':
                return 'status-pill-danger';
            case 'MANUAL_REVIEW_REQUIRED':
                return 'status-pill-danger';
            default:
                return 'status-pill-neutral';
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    window.AccessLeaseOffboarding = {
        init,
        loadOffboardingView,
        loadRevocationQueue,
        triggerExpiryScan
    };

    document.addEventListener('DOMContentLoaded', init);
})();

