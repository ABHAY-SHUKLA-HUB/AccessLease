/**
 * AccessLease — Internal User Governance & Administration Frontend Controller
 *
 * Rules:
 * - Pure Vanilla JavaScript (ES6+)
 * - Zero external frontend frameworks
 * - Visible and operational only for authenticated SYSTEM_ADMIN users
 * - Full administrative onboarding for internal application users with governance roles
 * - Real API integration via window.apiClient
 * - Clear error states, input validation, loading indicators
 */

(function (window) {
    'use strict';

    class UsersModule {
        constructor() {
            this.currentUser = null;
            this.usersList = [];
            this.searchQuery = '';
            this.statusFilter = 'ALL';
            this.initialized = false;
        }

        async init() {
            if (this.initialized) return;

            if (window.AccessLeaseAuth) {
                // If user is already resolved
                if (window.AccessLeaseAuth.currentUser) {
                    this.currentUser = window.AccessLeaseAuth.currentUser;
                    this.checkAdminAccess();
                }

                // Subscribe to future auth state updates
                window.AccessLeaseAuth.subscribe((user) => {
                    this.currentUser = user;
                    this.checkAdminAccess();
                    if (this.isAdmin()) {
                        this.loadUsers();
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

        checkAdminAccess() {
            const navLink = document.getElementById('nav-link-users');
            if (navLink) {
                navLink.style.display = this.isAdmin() ? 'flex' : 'none';
            }
        }

        setupEventHandlers() {
            // Add user modal open
            const btnOpenModal = document.getElementById('btn-open-add-user-modal');
            if (btnOpenModal) {
                btnOpenModal.addEventListener('click', () => this.openAddUserModal());
            }

            // Close / cancel modal buttons
            const btnCloseModal = document.getElementById('btn-close-user-modal');
            const btnCancelModal = document.getElementById('btn-cancel-user-modal');
            if (btnCloseModal) btnCloseModal.addEventListener('click', () => this.closeAddUserModal());
            if (btnCancelModal) btnCancelModal.addEventListener('click', () => this.closeAddUserModal());

            // User form submit
            const form = document.getElementById('form-add-user');
            if (form) {
                form.addEventListener('submit', (e) => this.handleUserSubmit(e));
            }

            // Search filter with debouncing
            const searchInput = document.getElementById('users-search-input');
            if (searchInput) {
                let debounceTimeout;
                searchInput.addEventListener('input', (e) => {
                    clearTimeout(debounceTimeout);
                    debounceTimeout = setTimeout(() => {
                        this.searchQuery = e.target.value.trim();
                        this.loadUsers();
                    }, 300);
                });
            }

            // Status filter
            const statusFilter = document.getElementById('users-status-filter');
            if (statusFilter) {
                statusFilter.addEventListener('change', (e) => {
                    this.statusFilter = e.target.value;
                    this.loadUsers();
                });
            }

            // Refresh button
            const btnRefresh = document.getElementById('btn-refresh-users');
            if (btnRefresh) {
                btnRefresh.addEventListener('click', () => this.loadUsers());
            }
        }

        openAddUserModal() {
            if (!this.isAdmin()) {
                alert('Access denied: Action requires SYSTEM_ADMIN privileges.');
                return;
            }

            const modal = document.getElementById('modal-add-user');
            if (!modal) return;

            // Reset form
            const form = document.getElementById('form-add-user');
            if (form) form.reset();

            // Clear errors
            const errorBox = document.getElementById('user-form-error');
            if (errorBox) {
                errorBox.style.display = 'none';
                errorBox.textContent = '';
            }

            // Uncheck role checkboxes
            const checkboxes = document.querySelectorAll('input[name="user-roles"]');
            checkboxes.forEach(cb => { cb.checked = false; });

            modal.style.display = 'flex';
        }

        closeAddUserModal() {
            const modal = document.getElementById('modal-add-user');
            if (modal) modal.style.display = 'none';
        }

        async handleUserSubmit(e) {
            e.preventDefault();
            const errorBox = document.getElementById('user-form-error');
            const submitBtn = document.getElementById('btn-submit-user');

            if (errorBox) {
                errorBox.style.display = 'none';
                errorBox.textContent = '';
            }

            const email = (document.getElementById('user-form-email')?.value || '').trim();
            const displayName = (document.getElementById('user-form-display-name')?.value || '').trim();
            const entraObjectId = (document.getElementById('user-form-entra-oid')?.value || '').trim();
            const department = (document.getElementById('user-form-department')?.value || '').trim();

            const checkedRoles = Array.from(document.querySelectorAll('input[name="user-roles"]:checked'))
                .map(cb => cb.value);

            // Client-side validations
            if (!email) {
                this.showFormError('Corporate email address is required.');
                return;
            }
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                this.showFormError('Please enter a valid corporate email address.');
                return;
            }
            if (!displayName || displayName.length < 2) {
                this.showFormError('Display name must be at least 2 characters.');
                return;
            }
            if (!entraObjectId || entraObjectId.length < 3) {
                this.showFormError('Microsoft Entra Object ID (oid UUID) is required.');
                return;
            }
            if (checkedRoles.length === 0) {
                this.showFormError('Please assign at least one governance role.');
                return;
            }

            try {
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Registering...';
                }

                const res = await window.apiClient.post('/api/users', {
                    email,
                    displayName,
                    entraObjectId,
                    department: department || null,
                    roleCodes: checkedRoles
                });

                if (res && res.success) {
                    this.closeAddUserModal();
                    await this.loadUsers();
                    this.showNotification(`User '${displayName}' registered successfully!`, 'success');
                } else {
                    const msg = res?.error?.message || 'Failed to register user.';
                    this.showFormError(msg);
                }
            } catch (err) {
                const msg = err?.message || err?.error?.message || 'Registration failed.';
                this.showFormError(msg);
            } finally {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Register User';
                }
            }
        }

        showFormError(msg) {
            const errorBox = document.getElementById('user-form-error');
            if (errorBox) {
                errorBox.textContent = msg;
                errorBox.style.display = 'block';
            }
        }

        async loadUsers() {
            const tableBody = document.getElementById('users-table-body');
            const countEl = document.getElementById('users-total-count');
            if (!tableBody) return;

            tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-muted" style="padding: 2rem;">Loading registered users...</td></tr>`;

            try {
                let url = '/api/users?limit=100';
                if (this.searchQuery) {
                    url += `&search=${encodeURIComponent(this.searchQuery)}`;
                }
                if (this.statusFilter === 'ACTIVE') {
                    url += '&isActive=true';
                } else if (this.statusFilter === 'INACTIVE') {
                    url += '&isActive=false';
                }

                const res = await window.apiClient.get(url);
                const users = res?.data?.users || [];
                const total = res?.data?.total || users.length;
                this.usersList = users;

                if (countEl) {
                    countEl.textContent = `${total} User${total === 1 ? '' : 's'}`;
                }

                if (users.length === 0) {
                    tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-muted" style="padding: 2rem;">No registered internal users found.</td></tr>`;
                    return;
                }

                tableBody.innerHTML = users.map(u => this.renderUserRow(u)).join('');
                this.attachActionHandlers();
            } catch (err) {
                console.error('[UsersModule] Failed to load users:', err);
                tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-danger" style="padding: 2rem;">Failed to load users: ${this.escapeHtml(err.message)}</td></tr>`;
            }
        }

        renderUserRow(user) {
            const isActive = user.is_active;
            const rolesHtml = (user.roles && user.roles.length > 0)
                ? user.roles.map(r => `<span class="role-chip" style="font-size: 0.75rem; padding: 2px 8px; margin: 2px;">${this.escapeHtml(r.role_name || r.role_code || r)}</span>`).join('')
                : '<span class="text-muted">—</span>';

            const statusBadge = isActive
                ? '<span class="status-pill status-pill-success" style="font-size: 0.75rem;">Active</span>'
                : '<span class="status-pill status-pill-warning" style="font-size: 0.75rem;">Inactive</span>';

            const isCurrent = this.currentUser && this.currentUser.user_id === user.user_id;
            const toggleBtnText = isActive ? 'Deactivate' : 'Activate';
            const toggleBtnClass = isActive ? 'btn-danger' : 'btn-secondary';

            const actionBtn = isCurrent
                ? '<span class="text-muted" style="font-size: 0.8rem;">Current Account</span>'
                : `<button class="btn btn-sm ${toggleBtnClass} btn-toggle-user-status" data-id="${user.user_id}" data-active="${isActive}">${toggleBtnText}</button>`;

            return `
                <tr data-user-id="${user.user_id}">
                    <td>
                        <div style="font-weight: 600; color: var(--color-neutral-dark);">${this.escapeHtml(user.display_name)}</div>
                        <div style="font-size: 0.85rem; color: var(--color-neutral-muted);">${this.escapeHtml(user.email)}</div>
                    </td>
                    <td><code style="font-size: 0.8rem;">${this.escapeHtml(user.entra_object_id || '—')}</code></td>
                    <td>${this.escapeHtml(user.department || '—')}</td>
                    <td><div style="display: flex; flex-wrap: wrap;">${rolesHtml}</div></td>
                    <td>${statusBadge}</td>
                    <td class="text-right">${actionBtn}</td>
                </tr>
            `;
        }

        attachActionHandlers() {
            const buttons = document.querySelectorAll('.btn-toggle-user-status');
            buttons.forEach(btn => {
                btn.addEventListener('click', async () => {
                    if (this.isUpdatingStatus || btn.disabled) {
                        return;
                    }

                    const userId = btn.getAttribute('data-id');
                    const currentActive = btn.getAttribute('data-active') === 'true';
                    const targetState = !currentActive;
                    const actionName = targetState ? 'activate' : 'deactivate';
                    const originalText = btn.textContent;

                    if (!confirm(`Are you sure you want to ${actionName} this user account?`)) {
                        return;
                    }

                    this.isUpdatingStatus = true;
                    btn.disabled = true;
                    btn.textContent = 'Updating...';

                    try {
                        const res = await window.apiClient.patch(`/api/users/${userId}/status`, {
                            is_active: targetState
                        });
                        if (res && res.success) {
                            await this.loadUsers();
                            this.showNotification(`User account ${actionName}d successfully.`, 'success');
                        } else {
                            const errorMsg = res?.error?.message || `Failed to ${actionName} user.`;
                            this.showNotification(errorMsg, 'error');
                        }
                    } catch (err) {
                        const errorMsg = err?.message || err?.error?.message || `Failed to ${actionName} user.`;
                        this.showNotification(errorMsg, 'error');
                    } finally {
                        this.isUpdatingStatus = false;
                        if (btn && btn.isConnected) {
                            btn.disabled = false;
                            btn.textContent = originalText;
                        }
                    }
                });
            });
        }

        showNotification(message, type = 'info') {
            const existingAlert = document.getElementById('user-mgmt-toast');
            if (existingAlert) existingAlert.remove();

            const toast = document.createElement('div');
            toast.id = 'user-mgmt-toast';
            const alertClass = type === 'success' ? 'alert-success' : (type === 'error' ? 'alert-danger' : 'alert-info');
            toast.className = `alert-banner ${alertClass}`;

            const bgColor = type === 'success' ? '#f0fdf4' : (type === 'error' ? '#fef2f2' : '#eff6ff');
            const borderColor = type === 'success' ? '#bbf7d0' : (type === 'error' ? '#fecaca' : '#bfdbfe');
            const textColor = type === 'success' ? '#166534' : (type === 'error' ? '#991b1b' : '#1e40af');

            toast.style.cssText = `position: fixed; bottom: 20px; right: 20px; z-index: 9999; padding: 12px 20px; border-radius: 6px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); animation: fadeIn 0.2s; background-color: ${bgColor}; border: 1px solid ${borderColor}; color: ${textColor}; font-weight: 500; font-size: 0.9rem; max-width: 400px;`;
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => { toast.remove(); }, 4000);
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

    window.AccessLeaseUsersModule = new UsersModule();

    document.addEventListener('DOMContentLoaded', () => {
        window.AccessLeaseUsersModule.init();
    });

})(window);
