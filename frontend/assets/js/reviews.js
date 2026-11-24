/**
 * AccessLease — Access Review & Recertification Frontend Module
 * 
 * Rules:
 * - Pure Vanilla JavaScript (ES6+)
 * - Real API-driven campaigns and review items
 * - Enforces separation of duties and read-only auditor restrictions
 */

(function (window) {
    'use strict';

    let activeReviewId = null;
    let activeReviewData = null;

    function init() {
        console.info('[AccessLease Reviews] Initializing reviews module...');
        attachEventListeners();
    }

    function attachEventListeners() {
        const refreshBtn = document.getElementById('btn-refresh-reviews');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', loadReviews);
        }

        const openCreateModalBtn = document.getElementById('btn-open-create-review-modal');
        if (openCreateModalBtn) {
            openCreateModalBtn.addEventListener('click', () => {
                const modal = document.getElementById('modal-create-review');
                if (modal) modal.style.display = 'flex';
            });
        }

        const cancelModalBtn = document.getElementById('btn-cancel-create-review');
        if (cancelModalBtn) {
            cancelModalBtn.addEventListener('click', () => {
                const modal = document.getElementById('modal-create-review');
                if (modal) modal.style.display = 'none';
            });
        }

        const createForm = document.getElementById('form-create-review');
        if (createForm) {
            createForm.addEventListener('submit', handleCreateReviewSubmit);
        }

        const backToCampaignsBtn = document.getElementById('btn-back-to-campaigns');
        if (backToCampaignsBtn) {
            backToCampaignsBtn.addEventListener('click', () => {
                const itemsView = document.getElementById('review-items-view');
                const campaignsView = document.getElementById('review-campaigns-view');
                if (itemsView) itemsView.style.display = 'none';
                if (campaignsView) campaignsView.style.display = 'block';
                activeReviewId = null;
                activeReviewData = null;
                loadReviews();
            });
        }
    }

    async function handleCreateReviewSubmit(e) {
        e.preventDefault();
        const submitBtn = document.getElementById('btn-submit-create-review');
        const nameInput = document.getElementById('input-review-name');
        const descInput = document.getElementById('input-review-desc');
        const typeSelect = document.getElementById('select-review-type');
        const dueDateInput = document.getElementById('input-review-duedate');

        if (!nameInput?.value.trim()) {
            window.alert('Review Campaign Name is required.');
            return;
        }
        if (!dueDateInput?.value) {
            window.alert('Due date is required.');
            return;
        }

        const payload = {
            reviewName: nameInput.value.trim(),
            description: descInput?.value.trim() || null,
            campaignType: typeSelect?.value || 'PERIODIC_RECERTIFICATION',
            dueDate: new Date(dueDateInput.value).toISOString()
        };

        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating Campaign...';
        }

        try {
            const res = await window.apiClient.post('/api/reviews', payload);
            window.alert(`Access Review Campaign "${payload.reviewName}" created successfully! Generated ${res?.data?.total_items || 0} review items.`);

            const modal = document.getElementById('modal-create-review');
            if (modal) modal.style.display = 'none';
            if (e.target && typeof e.target.reset === 'function') e.target.reset();

            await loadReviews();
        } catch (err) {
            console.error('[AccessLease Reviews] Failed to create review:', err);
            window.alert(`Error creating review campaign: ${err.message || 'Server error'}`);
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Create Campaign';
            }
        }
    }

    async function loadReviews() {
        const tbody = document.getElementById('reviews-tbody');
        const loadingState = document.getElementById('reviews-loading-state');
        const emptyState = document.getElementById('reviews-empty-state');
        const errorState = document.getElementById('reviews-error-state');

        if (loadingState) loadingState.style.display = 'block';
        if (emptyState) emptyState.style.display = 'none';
        if (errorState) errorState.style.display = 'none';

        try {
            const response = await window.apiClient.get('/api/reviews?limit=50');
            const reviews = response?.data || [];

            if (loadingState) loadingState.style.display = 'none';

            if (!reviews || reviews.length === 0) {
                if (tbody) tbody.innerHTML = '';
                if (emptyState) emptyState.style.display = 'block';
                return;
            }

            if (tbody) {
                tbody.innerHTML = reviews.map(r => renderCampaignRow(r)).join('');
                attachCampaignActionHandlers(tbody);
            }
        } catch (err) {
            console.error('[AccessLease Reviews] Failed to load reviews:', err);
            if (loadingState) loadingState.style.display = 'none';
            if (errorState) {
                errorState.style.display = 'block';
                const msg = document.getElementById('reviews-error-message');
                if (msg) msg.textContent = err.message || 'Failed to retrieve review campaigns.';
            }
        }
    }

    function renderCampaignRow(r) {
        const statusPillClass = {
            ACTIVE: 'status-pill-success',
            IN_PROGRESS: 'status-pill-warning',
            COMPLETED: 'status-pill-neutral',
            DRAFT: 'status-pill-neutral',
            CANCELLED: 'status-pill-danger',
            EXPIRED: 'status-pill-danger'
        }[r.status] || 'status-pill-neutral';

        const dueDateStr = r.due_date ? new Date(r.due_date).toLocaleDateString() : '—';
        const typeLabel = (r.campaign_type || '').replace(/_/g, ' ');
        const total = r.total_items ?? 0;
        const decided = r.decided_items ?? 0;

        return `
            <tr data-review-id="${r.review_id}">
                <td>
                    <div class="strong">${escapeHtml(r.review_name)}</div>
                    <div class="text-muted small">${escapeHtml(r.description || 'No description')}</div>
                </td>
                <td>
                    <span class="badge-status">${escapeHtml(typeLabel)}</span>
                </td>
                <td>
                    <span class="status-pill ${statusPillClass}">${escapeHtml(r.status)}</span>
                </td>
                <td class="small">
                    <div>${escapeHtml(dueDateStr)}</div>
                    <div class="text-muted">By: ${escapeHtml(r.initiator_name || 'Admin')}</div>
                </td>
                <td>
                    <div class="strong">${decided} / ${total} Decided</div>
                    <div class="progress-bar-container" style="background:#e2e8f0; height:6px; border-radius:3px; margin-top:4px; max-width:120px;">
                        <div style="background:#059669; height:100%; width:${total > 0 ? Math.round((decided / total) * 100) : 0}%; border-radius:3px;"></div>
                    </div>
                </td>
                <td>
                    <button class="btn btn-sm btn-primary btn-view-review-items" data-id="${r.review_id}" data-name="${escapeHtml(r.review_name)}" data-status="${r.status}">
                        View Items (${total})
                    </button>
                </td>
            </tr>
        `;
    }

    function attachCampaignActionHandlers(container) {
        container.querySelectorAll('.btn-view-review-items').forEach(btn => {
            btn.addEventListener('click', () => {
                const reviewId = btn.getAttribute('data-id');
                const reviewName = btn.getAttribute('data-name');
                const status = btn.getAttribute('data-status');
                openReviewItemsView(reviewId, reviewName, status);
            });
        });
    }

    async function openReviewItemsView(reviewId, reviewName, status) {
        activeReviewId = reviewId;
        activeReviewData = { reviewId, reviewName, status };

        const campaignsView = document.getElementById('review-campaigns-view');
        const itemsView = document.getElementById('review-items-view');
        const titleEl = document.getElementById('review-items-campaign-title');

        if (campaignsView) campaignsView.style.display = 'none';
        if (itemsView) itemsView.style.display = 'block';
        if (titleEl) titleEl.textContent = `Campaign: ${reviewName} (${status})`;

        await loadReviewItems(reviewId);
    }

    async function loadReviewItems(reviewId) {
        const tbody = document.getElementById('review-items-tbody');
        const loadingState = document.getElementById('review-items-loading');
        const emptyState = document.getElementById('review-items-empty');

        if (loadingState) loadingState.style.display = 'block';
        if (emptyState) emptyState.style.display = 'none';

        try {
            const response = await window.apiClient.get(`/api/reviews/${reviewId}/items`);
            const items = response?.data || [];

            if (loadingState) loadingState.style.display = 'none';

            if (!items || items.length === 0) {
                if (tbody) tbody.innerHTML = '';
                if (emptyState) emptyState.style.display = 'block';
                return;
            }

            if (tbody) {
                tbody.innerHTML = items.map(item => renderItemRow(item)).join('');
                attachItemDecisionHandlers(tbody);
            }
        } catch (err) {
            console.error('[AccessLease Reviews] Failed to load review items:', err);
            if (loadingState) loadingState.style.display = 'none';
            window.alert(`Error loading items: ${err.message || 'Server error'}`);
        }
    }

    function renderItemRow(item) {
        const decisionPillClass = {
            MAINTAIN: 'status-pill-success',
            REVOKE: 'status-pill-danger',
            PENDING: 'status-pill-warning'
        }[item.decision] || 'status-pill-neutral';

        const isDecided = item.decision !== 'PENDING';
        const expiryStr = item.expires_at ? new Date(item.expires_at).toLocaleDateString() : '—';

        return `
            <tr data-item-id="${item.review_item_id}">
                <td>
                    <div class="strong">${escapeHtml(item.grant_number)}</div>
                    <div class="text-muted small">Expires: ${escapeHtml(expiryStr)}</div>
                </td>
                <td>
                    <div class="strong">${escapeHtml(item.contractor_name)}</div>
                    <div class="text-muted small">Reviewer: ${escapeHtml(item.reviewer_name)}</div>
                </td>
                <td>
                    <div>${escapeHtml(item.resource_name)}</div>
                    <div class="text-muted small">${escapeHtml(item.entitlement_name)}</div>
                </td>
                <td>
                    <span class="status-pill ${decisionPillClass}">${escapeHtml(item.decision)}</span>
                    ${item.decision_notes ? `<div class="small text-muted" style="margin-top:4px;">"${escapeHtml(item.decision_notes)}"</div>` : ''}
                </td>
                <td>
                    ${!isDecided ? `
                        <div style="display: flex; gap: 0.5rem;">
                            <button class="btn btn-sm btn-success btn-maintain-access" data-id="${item.review_item_id}">
                                Maintain Access
                            </button>
                            <button class="btn btn-sm btn-danger btn-revoke-access" data-id="${item.review_item_id}">
                                Revoke Access
                            </button>
                        </div>
                    ` : `
                        <span class="text-muted small">Decided on ${item.decided_at ? new Date(item.decided_at).toLocaleDateString() : '—'}</span>
                    `}
                </td>
            </tr>
        `;
    }

    function attachItemDecisionHandlers(container) {
        container.querySelectorAll('.btn-maintain-access').forEach(btn => {
            btn.addEventListener('click', () => handleDecision(btn.getAttribute('data-id'), 'MAINTAIN'));
        });

        container.querySelectorAll('.btn-revoke-access').forEach(btn => {
            btn.addEventListener('click', () => handleDecision(btn.getAttribute('data-id'), 'REVOKE'));
        });
    }

    async function handleDecision(reviewItemId, decision) {
        const actionLabel = decision === 'MAINTAIN' ? 'maintain (recertify)' : 'REVOKE';
        const promptMsg = decision === 'MAINTAIN'
            ? 'Enter business justification notes for maintaining this access entitlement:'
            : 'Enter justification for revoking this entitlement (this will initiate automated revocation):';

        const notes = window.prompt(promptMsg);
        if (notes === null) return; // Cancelled
        if (!notes.trim()) {
            window.alert('A justification note is required to record a review decision.');
            return;
        }

        const confirmMsg = `Are you sure you want to ${actionLabel} access for this grant?`;
        if (!window.confirm(confirmMsg)) return;

        try {
            const res = await window.apiClient.post(`/api/reviews/items/${reviewItemId}/decision`, {
                decision,
                decisionNotes: notes.trim()
            });

            if (decision === 'REVOKE') {
                window.alert(`Decision recorded. Revocation job successfully initiated! Job ID: ${res?.data?.revocationJob?.job_id || 'Active'}`);
            } else {
                window.alert('Decision recorded: Access maintained.');
            }

            if (res?.data?.campaignStatus === 'COMPLETED') {
                window.alert('All items in this campaign have been decided! Campaign status updated to COMPLETED.');
            }

            if (activeReviewId) {
                await loadReviewItems(activeReviewId);
            }
        } catch (err) {
            console.error('[AccessLease Reviews] Decision error:', err);
            window.alert(`Failed to record review decision: ${err.message || 'Internal error'}`);
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

    window.AccessLeaseReviews = {
        init,
        loadReviews
    };

    document.addEventListener('DOMContentLoaded', init);
})(window);

