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

    // 3. Setup Dashboard Card Direct Navigation
    setupCardNavigation();

    // 4. Setup Responsive Mobile Navigation Drawer
    setupMobileSidebar();

    // 5. Connect Header Sign-Out Action
    const headerLogoutBtn = document.getElementById('btn-header-logout');
    if (headerLogoutBtn) {
        headerLogoutBtn.addEventListener('click', () => {
            if (window.AccessLeaseAuth) {
                window.AccessLeaseAuth.signOut();
            }
        });
    }

    // 6. Initialize Microsoft Entra ID Authentication & Role Listeners
    if (window.AccessLeaseAuth) {
        window.AccessLeaseAuth.subscribe((user) => {
            const moduleCardUsers = document.getElementById('module-card-users');
            if (moduleCardUsers) {
                const hasAdmin = user && user.roles && user.roles.some(r => (r.role_code || r) === 'SYSTEM_ADMIN');
                moduleCardUsers.style.display = hasAdmin ? 'flex' : 'none';
            }
            if (user) {
                loadDashboardMetrics();
            }
        });

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
                    
                    const mainEl = document.getElementById('main-content');
                    if (mainEl) mainEl.scrollTop = 0;
                    
                    // Trigger refresh on dynamic module views
                    if (targetViewId === 'view-governance-shell') {
                        loadDashboardMetrics();
                    } else if (targetViewId === 'view-catalog' && window.AccessLeaseCatalog) {
                        window.AccessLeaseCatalog.loadCatalog();
                    } else if (targetViewId === 'view-requests' && window.AccessLeaseRequests) {
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
                        window.AccessLeaseOrphanFindings.refreshKPIs();
                    } else if (targetViewId === 'view-reviews' && window.AccessLeaseReviews) {
                        window.AccessLeaseReviews.loadReviews();
                        window.AccessLeaseReviews.refreshReviewKPIs();
                    } else if (targetViewId === 'view-audit' && window.AccessLeaseAudit) {
                        window.AccessLeaseAudit.loadAuditTrail();
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

/**
 * Enables direct module card action buttons (data-navigate="view-...") to activate target views.
 */
function setupCardNavigation() {
    const cardButtons = document.querySelectorAll('.module-nav-btn[data-navigate]');
    cardButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const targetViewId = btn.getAttribute('data-navigate');
            if (!targetViewId) return;

            const matchingNavLink = document.querySelector(`.nav-link[data-view="${targetViewId}"]`);
            if (matchingNavLink) {
                matchingNavLink.click();
                const mainEl = document.getElementById('main-content');
                if (mainEl) mainEl.scrollTop = 0;
            }
        });
    });
}

/**
 * Sets up accessible responsive mobile sidebar drawer toggle and backdrop handling.
 */
function setupMobileSidebar() {
    const mobileBtn = document.getElementById('btn-mobile-nav');
    const sidebar = document.getElementById('app-sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');

    if (!mobileBtn || !sidebar) return;

    function toggleSidebar(open) {
        const isOpen = typeof open === 'boolean' ? open : !sidebar.classList.contains('sidebar-open');
        sidebar.classList.toggle('sidebar-open', isOpen);
        mobileBtn.setAttribute('aria-expanded', String(isOpen));
        if (backdrop) {
            backdrop.style.display = isOpen ? 'block' : 'none';
        }
    }

    mobileBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleSidebar();
    });

    if (backdrop) {
        backdrop.addEventListener('click', () => {
            toggleSidebar(false);
        });
    }

    // Close mobile drawer when a navigation link is clicked
    const navLinks = sidebar.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            if (window.innerWidth <= 992) {
                toggleSidebar(false);
            }
        });
    });

    // Close drawer on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && sidebar.classList.contains('sidebar-open')) {
            toggleSidebar(false);
        }
    });
}

/**
 * Loads real-time database-driven governance metrics & charts on the Main Dashboard.
 */
async function loadDashboardMetrics() {
    try {
        if (!window.apiClient) return;

        // Fetch live database metrics
        const [analyticsRes, contractorsRes] = await Promise.allSettled([
            window.apiClient.get('/api/analytics/summary'),
            window.apiClient.get('/api/contractors')
        ]);

        const metrics = (analyticsRes.status === 'fulfilled' && analyticsRes.value?.data?.metrics) || {};
        const contractors = (contractorsRes.status === 'fulfilled' && contractorsRes.value?.data?.contractors) || [];

        // Update KPI values
        const setEl = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = String(val ?? 0);
        };

        setEl('dash-metric-contractors', contractors.length);
        setEl('dash-metric-engagements', metrics.activeContractorEngagements ?? 0);
        setEl('dash-metric-active-grants', metrics.activeAccessGrants ?? 0);
        setEl('dash-metric-pending-requests', metrics.pendingAccessRequests ?? 0);
        setEl('dash-metric-pending-approvals', metrics.pendingApprovals ?? 0);
        setEl('dash-metric-expiring-soon', metrics.expiringGrantsSoon7d ?? 0);
        setEl('dash-metric-open-orphans', metrics.orphanFindings?.totalOpen ?? 0);

        // Update Orphan Risk Exposure Chart
        const orphans = metrics.orphanFindings || {};
        const totalOrphans = Math.max((orphans.totalOpen || 0), 1);
        setEl('dash-chart-critical-count', orphans.critical ?? 0);
        setEl('dash-chart-high-count', orphans.high ?? 0);
        setEl('dash-chart-medium-count', orphans.medium ?? 0);
        setEl('dash-chart-low-count', orphans.low ?? 0);

        const setBar = (id, count, total) => {
            const el = document.getElementById(id);
            if (el) {
                const pct = count > 0 ? Math.max(Math.round((count / total) * 100), 12) : 0;
                el.style.width = `${pct}%`;
            }
        };

        setBar('dash-chart-critical-bar', orphans.critical || 0, totalOrphans);
        setBar('dash-chart-high-bar', orphans.high || 0, totalOrphans);
        setBar('dash-chart-medium-bar', orphans.medium || 0, totalOrphans);
        setBar('dash-chart-low-bar', orphans.low || 0, totalOrphans);

        // Update Revocation Pipeline Chart
        const rev = metrics.revocations || {};
        const totalRev = Math.max(((rev.confirmed || 0) + (rev.manualReview || 0) + (rev.pending || 0) + (rev.failed || 0)), 1);
        setEl('dash-chart-confirmed-count', rev.confirmed ?? 0);
        setEl('dash-chart-review-count', rev.manualReview ?? 0);
        setEl('dash-chart-pending-count', rev.pending ?? 0);
        setEl('dash-chart-failed-count', rev.failed ?? 0);

        setBar('dash-chart-confirmed-bar', rev.confirmed || 0, totalRev);
        setBar('dash-chart-review-bar', rev.manualReview || 0, totalRev);
        setBar('dash-chart-pending-bar', rev.pending || 0, totalRev);
        setBar('dash-chart-failed-bar', rev.failed || 0, totalRev);

    } catch (err) {
        console.warn('[AccessLease Main] Failed to compute dashboard metrics:', err.message);
    }
}

