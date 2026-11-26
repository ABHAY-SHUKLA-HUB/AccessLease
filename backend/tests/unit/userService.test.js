/**
 * AccessLease — Unit Tests: User Service & Status Management
 *
 * Verifies:
 * 1. setUserStatus enforces SYSTEM_ADMIN role guard (rejects non-admins with ForbiddenError).
 * 2. setUserStatus prevents self-deactivation (throws ERR_SELF_DEACTIVATION_FORBIDDEN).
 * 3. setUserStatus rejects missing or invalid user ID.
 * 4. setUserStatus throws NotFoundError when target user does not exist.
 * 5. setUserStatus updates user record and records immutable audit event.
 * 6. updateUserStatusHandler handles HTTP request, extracts params, and returns HTTP 200.
 */

const { describe, test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const userService = require('../../src/services/userService');
const { updateUserStatusHandler } = require('../../src/functions/users');
const { userRepository, auditRepository } = require('../../src/repositories');
const { ForbiddenError, ValidationError, NotFoundError } = require('../../src/utils/errors');

describe('Unit: UserService & Status Management (userService.js)', () => {
    const adminUser = {
        user_id: 'USER-ADMIN-001',
        display_name: 'Admin User',
        roles: [{ role_code: 'SYSTEM_ADMIN' }]
    };

    const regularUser = {
        user_id: 'USER-SPONSOR-001',
        display_name: 'Sponsor User',
        roles: [{ role_code: 'INTERNAL_SPONSOR' }]
    };

    const targetUserId = 'USER-TARGET-999';
    const mockTargetUser = {
        user_id: targetUserId,
        email: 'target.user@accesslease.corp',
        display_name: 'Target User',
        is_active: true
    };

    let originalFindUserById;
    let originalUpdateUserStatus;
    let originalCreateAuditEvent;

    beforeEach(() => {
        originalFindUserById = userRepository.findUserById;
        originalUpdateUserStatus = userRepository.updateUserStatus;
        originalCreateAuditEvent = auditRepository.createAuditEvent;

        userRepository.findUserById = async (id) => {
            if (id === targetUserId) return { ...mockTargetUser };
            return null;
        };

        userRepository.updateUserStatus = async (id, isActive) => ({
            ...mockTargetUser,
            user_id: id,
            is_active: isActive
        });

        auditRepository.createAuditEvent = async () => ({ event_id: 'AUDIT-101' });
    });

    test('1. setUserStatus requires SYSTEM_ADMIN role', async () => {
        await assert.rejects(
            async () => {
                await userService.setUserStatus(targetUserId, false, regularUser);
            },
            (err) => {
                assert.ok(err instanceof ForbiddenError);
                assert.strictEqual(err.code, 'ERR_FORBIDDEN_ROLE');
                return true;
            }
        );
    });

    test('2. setUserStatus prevents self-deactivation', async () => {
        await assert.rejects(
            async () => {
                await userService.setUserStatus(adminUser.user_id, false, adminUser);
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                assert.strictEqual(err.code, 'ERR_SELF_DEACTIVATION_FORBIDDEN');
                assert.ok(err.message.includes('cannot deactivate their own account'));
                return true;
            }
        );
    });

    test('3. setUserStatus rejects missing or whitespace user ID', async () => {
        await assert.rejects(
            async () => {
                await userService.setUserStatus('', false, adminUser);
            },
            (err) => {
                assert.ok(err instanceof ValidationError);
                return true;
            }
        );
    });

    test('4. setUserStatus throws NotFoundError when target user does not exist', async () => {
        await assert.rejects(
            async () => {
                await userService.setUserStatus('NON-EXISTENT-USER', false, adminUser);
            },
            (err) => {
                assert.ok(err instanceof NotFoundError);
                return true;
            }
        );
    });

    test('5. setUserStatus updates user status and records immutable audit event', async () => {
        let capturedAuditEvent = null;
        let capturedUserId = null;
        let capturedStatus = null;

        userRepository.updateUserStatus = async (id, isActive) => {
            capturedUserId = id;
            capturedStatus = isActive;
            return { ...mockTargetUser, is_active: isActive };
        };

        auditRepository.createAuditEvent = async (event) => {
            capturedAuditEvent = event;
            return { event_id: 'AUDIT-NEW-1' };
        };

        const result = await userService.setUserStatus(targetUserId, false, adminUser);

        assert.strictEqual(result.is_active, false);
        assert.strictEqual(capturedUserId, targetUserId);
        assert.strictEqual(capturedStatus, false);

        assert.ok(capturedAuditEvent);
        assert.strictEqual(capturedAuditEvent.eventCategory, 'SECURITY_POLICY');
        assert.strictEqual(capturedAuditEvent.eventAction, 'USER_DEACTIVATED');
        assert.strictEqual(capturedAuditEvent.entityId, targetUserId);
        assert.strictEqual(capturedAuditEvent.actorUserId, adminUser.user_id);
    });

    test('6. updateUserStatusHandler handles valid PATCH request and returns HTTP 200', async () => {
        const mockRequest = {
            authenticatedUser: adminUser,
            params: { id: targetUserId },
            json: async () => ({ is_active: false })
        };
        const mockContext = { invocationId: 'inv-test-123' };

        const response = await updateUserStatusHandler(mockRequest, mockContext);

        assert.strictEqual(response.status, 200);
        const body = response.jsonBody;
        assert.strictEqual(body.success, true);
        assert.strictEqual(body.data.user.is_active, false);
    });
});
