/**
 * AccessLease — Orphan & Stale Access Findings Frontend Module
 * 
 * Rules:
 * - Pure Vanilla JavaScript (ES6+)
 * - Real API-driven table and operations
 * - Live detection scan triggering and immediate revocation initiation
 */

(function (window) {
    'use strict';

    let currentFilters = {
        status: 'OPEN',
        severity: '',
        reason: ''
    };

    function init() {
        console.info('[AccessLease Orphan Findings] Initializing module...');
        attachEventListeners();
    }

    function attachEventListeners() {
        const scanBtn = document.getElementById('btn-trigger-orphan-scan');
        if (scanBtn) {
            scanBtn.addEventListener('click', handleTriggerScan);
        }

        const refreshBtn = document.getElementById('btn-refresh-orphan-findings');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', loadFindings);
        }

        const statusFilter = document.getElementById('orphan-status-filter');
        if (statusFilter) {
            statusFilter.addEventListener('change', (e) => {
                currentFilters.status = e.target.value;
                loadFindings();
            });
        }

        const severityFilter = document.getElementById('orphan-severity-filter');
        if (severityFilter) {
            severityFilter.addEventListener('change', (e) => {
                currentFilters.severity = e.target.value;
                loadFindings();
            });
        }

        const reasonFilter = document.getElementById('orphan-reason-filter');
        if (reasonFilter) {
            reasonFilter.addEventListener('change', (e) => {
                currentFilters.reason = e.target.value;
                loadFindings();
            });
        }
    }

    async function handleTriggerScan() {
        const scanBtn = document.getElementById('btn-trigger-orphan-scan');
        const alertBanner = document.getElementById('orphan-scan-alert');

        if (scanBtn) {
            scanBtn.disabled = true;
            scanBtn.textContent = 'Scanning Database...';
        }

        try {
            const response = await window.apiClient.post('/api/orphan-access/scan', {});
            const data = response?.data || {};

            if (alertBanner) {
                alertBanner.className = 'status-banner banner-success';
                alertBanner.style.display = 'block';
                alertBanner.textContent = `Scan Complete: Detected ${data.totalDetected || 0} candidate grants (${data.newCount || 0} new open findings, ${data.updatedCount || 0} refreshed).`;
            }

            await loadFindings();
        } catch (err) {
            console.error('[AccessLease Orphan Findings] Scan failed:', err);
            if (alertBanner) {
                alertBanner.className = 'status-banner banner-danger';
                alertBanner.style.display = 'block';
                alertBanner.textContent = `Scan Failed: ${err.message || 'Error executing orphan access detection.'}`;
            }
        } finally {
            if (scanBtn) {
                scanBtn.disabled = false;
                scanBtn.textContent = 'Trigger Orphan Detection Scan';
            }
        }
    }

    async function loadFindings() {
        const tbody = document.getElementById('orphan-findings-tbody');
        const loadingState = document.getElementById('orphan-loading-state');
        const emptyState = document.getElementById('orphan-empty-state');
        const errorState = document.getElementById('orphan-error-state');

        if (loadingState) loadingState.style.display = 'block';
        if (emptyState) emptyState.style.display = 'none';
        if (errorState) errorState.style.display = 'none';

        try {
            const queryParams = new URLSearchParams();
            if (currentFilters.status) queryParams.set('status', currentFilters.status);
            if (currentFilters.severity) queryParams.set('severity', currentFilters.severity);
            if (currentFilters.reason) queryParams.set('reason', currentFilters.reason);
            queryParams.set('limit', '50');

            const response = await window.apiClient.get(`/api/orphan-access/findings?${queryParams.toString()}`);
            const data = response?.data || {};
            const findings = data.findings || [];

            if (loadingState) loadingState.style.display = 'none';

            if (!findings || findings.length === 0) {
                if (tbody) tbody.innerHTML = '';
                if (emptyState) emptyState.style.display = 'block';
                // Load KPIs from a full (unfiltered) snapshot when no results for the current filter
                await refreshKPIs();
                return;
            }

            if (tbody) {
                tbody.innerHTML = findings.map(f => renderFindingRow(f)).join('');
                attachRowActionHandlers(tbody);
            }

            await refreshKPIs();
        } catch (err) {
            console.error('[AccessLease Orphan Findings] Failed to load findings:', err);
            if (loadingState) loadingState.style.display = 'none';
            if (errorState) {
                errorState.style.display = 'block';
                const msg = document.getElementById('orphan-error-message');
                if (msg) msg.textContent = err.message || 'Failed to retrieve findings from backend.';
            }
        }
    }

    async function refreshKPIs() {
        try {
            // Fetch all findings without status filter to compute KPI breakdown
            const allRes = await window.apiClient.get('/api/orphan-access/findings?limit=200');
            const allFindings = allRes?.data?.findings || [];

            const open = allFindings.filter(f => f.status === 'OPEN').length;
            const investigating = allFindings.filter(f => f.status === 'INVESTIGATING').length;
            const critHigh = allFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
            const revInitiated = allFindings.filter(f => f.status === 'REVOCATION_INITIATED').length;
            const resolved = allFindings.filter(f => f.status === 'RESOLVED' || f.status === 'FALSE_POSITIVE').length;

            const setKpi = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
            setKpi('orphan-kpi-open', open + investigating);
            setKpi('orphan-kpi-critical', critHigh);
            setKpi('orphan-kpi-revocation', revInitiated);
            setKpi('orphan-kpi-resolved', resolved);
        } catch (_) {
            // KPI refresh failure is non-critical — silently skip
        }
    }

    function renderFindingRow(f) {
        const severityClass = {
            CRITICAL: 'badge-risk-critical',
            HIGH: 'badge-risk-high',
            MEDIUM: 'badge-risk-medium',
            LOW: 'badge-risk-low'
        }[f.severity] || 'badge-risk-medium';

        const statusPillClass = {
            OPEN: 'status-pill-danger',
            INVESTIGATING: 'status-pill-warning',
            REVOCATION_INITIATED: 'status-pill-warning',
            RESOLVED: 'status-pill-success',
            FALSE_POSITIVE: 'status-pill-neutral'
        }[f.status] || 'status-pill-neutral';

        const detectedDate = f.last_detected_at ? new Date(f.last_detected_at).toLocaleString() : '—';
        const reasonLabel = (f.finding_reason || '').replace(/_/g, ' ');

        const canAct = ['OPEN', 'INVESTIGATING'].includes(f.status);

        return `
            <tr data-finding-id="${f.finding_id}">
                <td>
                    <div class="strong">${escapeHtml(f.grant_number || '—')}</div>
                    <div class="text-muted small">${escapeHtml(f.finding_id.substring(0, 8))}...</div>
                </td>
                <td>
                    <div class="strong">${escapeHtml(f.contractor_name || '—')}</div>
                    <div class="text-muted small">${escapeHtml(f.contractor_email || '—')}</div>
                </td>
                <td>
                    <div>${escapeHtml(f.resource_name || '—')}</div>
                    <div class="text-muted small">${escapeHtml(f.entitlement_name || '—')}</div>
                </td>
                <td>
                    <span class="badge-risk ${severityClass}">${escapeHtml(f.severity)}</span>
                    <div class="small" style="margin-top: 4px;">${escapeHtml(reasonLabel)}</div>
                </td>
                <td class="small">
                    <div>${escapeHtml(detectedDate)}</div>
                    <div class="text-muted">Grant: ${escapeHtml(f.grant_status || '—')}</div>
                </td>
                <td>
                    <span class="status-pill ${statusPillClass}">${escapeHtml(f.status)}</span>
                </td>
                <td>
                    ${canAct ? `
                        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                            <button class="btn btn-sm btn-danger btn-revoke-orphan" data-id="${f.finding_id}" data-grant="${escapeHtml(f.grant_number)}">
                                Initiate Revocation
                            </button>
                            <button class="btn btn-sm btn-outline btn-resolve-orphan" data-id="${f.finding_id}">
                                Resolve
                            </button>
                        </div>
                    ` : `
                        <span class="text-muted small">${f.status === 'REVOCATION_INITIATED' ? 'Revocation in progress' : 'Resolved'}</span>
                    `}
                </td>
            </tr>
        `;
    }

    function attachRowActionHandlers(container) {
        container.querySelectorAll('.btn-revoke-orphan').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const findingId = btn.getAttribute('data-id');
                const grantNumber = btn.getAttribute('data-grant');

                const confirmed = window.confirm(
                    `Are you sure you want to initiate automated revocation for grant ${grantNumber}? This will queue a verified provider deprovisioning job via the AccessLease revocation engine.`
                );
                if (!confirmed) return;

                btn.disabled = true;
                btn.textContent = 'Enqueuing...';

                try {
                    const res = await window.apiClient.post(`/api/orphan-access/findings/${findingId}/revoke`, {
                        reason: `Orphan access confirmed by security officer for grant ${grantNumber}`
                    });
                    window.alert(`Revocation job enqueued successfully! Job ID: ${res?.data?.revocationJob?.job_id || 'Active'}`);
                    await loadFindings();
                } catch (err) {
                    console.error('[AccessLease Orphan Findings] Revocation error:', err);
                    window.alert(`Failed to initiate revocation: ${err.message || 'Internal error'}`);
                    btn.disabled = false;
                    btn.textContent = 'Initiate Revocation';
                }
            });
        });

        container.querySelectorAll('.btn-resolve-orphan').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const findingId = btn.getAttribute('data-id');
                const notes = window.prompt('Enter justification for resolving this finding (or leave note for False Positive):');
                if (notes === null) return;
                if (!notes.trim()) {
                    window.alert('A resolution note is required.');
                    return;
                }

                btn.disabled = true;
                btn.textContent = 'Resolving...';

                try {
                    await window.apiClient.post(`/api/orphan-access/findings/${findingId}/resolve`, {
                        status: 'RESOLVED',
                        resolutionNotes: notes.trim()
                    });
                    window.alert('Finding resolved successfully.');
                    await loadFindings();
                } catch (err) {
                    console.error('[AccessLease Orphan Findings] Resolve error:', err);
                    window.alert(`Failed to resolve finding: ${err.message || 'Internal error'}`);
                    btn.disabled = false;
                    btn.textContent = 'Resolve';
                }
            });
        });
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

    window.AccessLeaseOrphanFindings = {
        init,
        loadFindings,
        refreshKPIs
    };

    document.addEventListener('DOMContentLoaded', init);
})(window);

