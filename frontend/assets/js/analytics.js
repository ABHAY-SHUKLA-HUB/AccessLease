/**
 * AccessLease — Security Analytics & Governance Dashboard Frontend Module
 * 
 * Rules:
 * - Pure Vanilla JavaScript (ES6+)
 * - Strictly real API-driven metrics from /api/analytics/summary
 * - Avoids duplicate counting; provides live governance and exposure metrics
 */

(function (window) {
    'use strict';

    function init() {
        console.info('[AccessLease Analytics] Initializing analytics module...');
        const refreshBtn = document.getElementById('btn-refresh-analytics');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', loadAnalyticsSummary);
        }
    }

    async function loadAnalyticsSummary() {
        const loadingState = document.getElementById('analytics-loading-state');
        const contentContainer = document.getElementById('analytics-content-container');
        const errorState = document.getElementById('analytics-error-state');
        const refreshBtn = document.getElementById('btn-refresh-analytics');

        if (loadingState) loadingState.style.display = 'block';
        if (errorState) errorState.style.display = 'none';
        if (refreshBtn) refreshBtn.disabled = true;

        try {
            const response = await window.apiClient.get('/api/analytics/summary');
            const data = response?.data || {};
            const metrics = data.metrics || {};

            renderMetrics(metrics, data);

            if (loadingState) loadingState.style.display = 'none';
            if (contentContainer) contentContainer.style.display = 'block';
        } catch (err) {
            console.error('[AccessLease Analytics] Failed to load analytics metrics:', err);
            if (loadingState) loadingState.style.display = 'none';
            if (errorState) {
                errorState.style.display = 'block';
                const msgEl = document.getElementById('analytics-error-message');
                if (msgEl) msgEl.textContent = err.message || 'Failed to load security analytics metrics from backend.';
            }
        } finally {
            if (refreshBtn) refreshBtn.disabled = false;
        }
    }

    function renderMetrics(metrics, envelope) {
        // Scope pill & updated timestamp
        const scopePill = document.getElementById('analytics-scope-pill');
        if (scopePill) {
            scopePill.textContent = envelope.scope ? envelope.scope.replace(/_/g, ' ') : 'ENTERPRISE';
        }

        const updatedEl = document.getElementById('analytics-last-updated');
        if (updatedEl && envelope.timestamp) {
            updatedEl.textContent = `Updated: ${new Date(envelope.timestamp).toLocaleTimeString()}`;
        }

        // Primary KPIs
        setMetricText('metric-active-engagements', metrics.activeContractorEngagements ?? '0');
        setMetricText('metric-active-grants', metrics.activeAccessGrants ?? '0');
        setMetricText('metric-expiring-soon', metrics.expiringGrantsSoon7d ?? '0');
        setMetricText('metric-pending-requests', metrics.pendingAccessRequests ?? '0');
        setMetricText('metric-pending-approvals', metrics.pendingApprovals ?? '0');
        setMetricText('metric-open-orphans', metrics.orphanFindings?.totalOpen ?? '0');
        setMetricText('metric-pending-revocations', metrics.revocations?.pending ?? '0');
        setMetricText('metric-failed-revocations', (metrics.revocations?.failed || 0) + (metrics.revocations?.manualReview || 0));
        setMetricText('metric-open-reviews', metrics.accessReviews?.open ?? '0');
        setMetricText('metric-completed-reviews', metrics.accessReviews?.completed ?? '0');

        // Orphan severity breakdown
        const findings = metrics.orphanFindings || {};
        setMetricText('breakdown-critical-findings', findings.critical ?? '0');
        setMetricText('breakdown-high-findings', findings.high ?? '0');
        setMetricText('breakdown-medium-findings', findings.medium ?? '0');
        setMetricText('breakdown-low-findings', findings.low ?? '0');

        // Revocation status breakdown
        const revocations = metrics.revocations || {};
        setMetricText('breakdown-rev-pending', revocations.pending ?? '0');
        setMetricText('breakdown-rev-confirmed', revocations.confirmed ?? '0');
        setMetricText('breakdown-rev-review', revocations.manualReview ?? '0');
        setMetricText('breakdown-rev-failed', revocations.failed ?? '0');
    }

    function setMetricText(elementId, val) {
        const el = document.getElementById(elementId);
        if (el) {
            el.textContent = String(val);
        }
    }

    window.AccessLeaseAnalytics = {
        init,
        loadAnalyticsSummary
    };

    document.addEventListener('DOMContentLoaded', init);
})(window);

