/**
 * AccessLease — Application Shell Controller
 * 
 * Rules:
 * - Pure Vanilla JavaScript (ES6+)
 * - No frontend frameworks
 * - Accessible UI interactions
 * - Centralized API calls via window.apiClient
 * - Unified state synchronization with window.AccessLeaseAuth
 */

document.addEventListener('DOMContentLoaded', async () => {
    console.info('[AccessLease] Initializing Application Shell...');

    // 1. Initialize System Health Indicators
    await checkSystemHealth();

    // 2. Setup Navigation Tab Switching
    setupNavigation();

    // 3. Connect Header Sign-Out Action
    const headerLogoutBtn = document.getElementById('btn-header-logout');
    if (headerLogoutBtn) {
        headerLogoutBtn.addEventListener('click', () => {
            if (window.AccessLeaseAuth) {
                window.AccessLeaseAuth.signOut();
            }
        });
    }

    // 4. Initialize Microsoft Entra ID Authentication
    if (window.AccessLeaseAuth) {
        await window.AccessLeaseAuth.initialize();
    } else {
        console.error('[AccessLease] Authentication module (auth.js) is not loaded.');
    }
});

/**
 * Checks backend and database health endpoints via the centralized apiClient.
 */
async function checkSystemHealth() {
    const healthBadge = document.getElementById('system-health-badge');
    const dbHealthBadge = document.getElementById('db-health-badge');

    try {
        if (!window.apiClient) return;

        // Check backend service health
        const healthRes = await window.apiClient.get('/api/health');
        if (healthBadge && healthRes?.data?.status === 'UP') {
            healthBadge.textContent = 'API: Online';
            healthBadge.className = 'status-pill status-pill-success';
            healthBadge.title = `AccessLease Core Backend v${healthRes.data.version} (${healthRes.data.environment})`;
        }

        // Check database connectivity
        const dbRes = await window.apiClient.get('/api/health/db');
        if (dbHealthBadge && dbRes?.data?.status === 'CONNECTED') {
            dbHealthBadge.textContent = 'Database: Connected';
            dbHealthBadge.className = 'status-pill status-pill-success';
            dbHealthBadge.title = `Connected to ${dbRes.data.database}`;
        }
    } catch (err) {
        console.warn('[AccessLease] Health check warning:', err.message);
        if (healthBadge) {
            healthBadge.textContent = 'API: Checking';
            healthBadge.className = 'status-pill status-pill-warning';
        }
        if (dbHealthBadge) {
            dbHealthBadge.textContent = 'Database: Pending';
            dbHealthBadge.className = 'status-pill status-pill-warning';
        }
    }
}

/**
 * Sets up accessible tab switching between the Governance Shell and scheduled lifecycle tabs.
 */
function setupNavigation() {
    const navItems = document.querySelectorAll('.nav-link[data-view]');
    const viewContainers = document.querySelectorAll('.workspace-view');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetViewId = item.getAttribute('data-view');

            // Update active state on nav links
            navItems.forEach(nav => {
                nav.classList.remove('active');
                nav.removeAttribute('aria-current');
            });
            item.classList.add('active');
            item.setAttribute('aria-current', 'page');

            // Switch view display
            viewContainers.forEach(view => {
                if (view.id === targetViewId) {
                    view.style.display = 'block';
                    
                    // Trigger refresh on dynamic module views
                    if (targetViewId === 'view-requests' && window.AccessLeaseRequests) {
                        window.AccessLeaseRequests.loadRequestsTable();
                    } else if (targetViewId === 'view-approvals' && window.AccessLeaseRequests) {
                        window.AccessLeaseRequests.loadApprovalsTable();
                    } else if (targetViewId === 'view-contractors' && window.AccessLeaseContractorModule) {
                        window.AccessLeaseContractorModule.renderModule();
                    } else if (targetViewId === 'view-offboarding' && window.AccessLeaseOffboarding) {
                        window.AccessLeaseOffboarding.loadOffboardingView();
                    } else if (targetViewId === 'view-analytics' && window.AccessLeaseAnalytics) {
                        window.AccessLeaseAnalytics.loadAnalyticsSummary();
                    } else if (targetViewId === 'view-orphan-findings' && window.AccessLeaseOrphanFindings) {
                        window.AccessLeaseOrphanFindings.loadFindings();
                    } else if (targetViewId === 'view-reviews' && window.AccessLeaseReviews) {
                        window.AccessLeaseReviews.loadReviews();
                    } else if (targetViewId === 'view-users' && window.AccessLeaseUsersModule) {
                        window.AccessLeaseUsersModule.loadUsers();
                    }
                } else {
                    view.style.display = 'none';
                }
            });
        });
    });
}
