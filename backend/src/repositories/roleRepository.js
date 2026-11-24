/**
 * AccessLease — RBAC Role Repository
 * Handles data access for dbo.roles and dbo.user_roles.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Lists all defined RBAC roles.
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listRoles(transaction = null) {
    try {
        const runner = transaction || await getPool();
        const result = await runner.request().query(`
            SELECT
                r.role_id,
                r.role_code,
                r.role_name,
                r.description,
                r.created_at
            FROM dbo.roles r
            ORDER BY r.role_id ASC;
        `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listRoles', { error: err.message });
        throw new DatabaseError('Failed to list roles.', err);
    }
}

/**
 * Finds a role by its unique role_code.
 * @param {string} roleCode E.g. 'RESOURCE_OWNER'
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findRoleByCode(roleCode, transaction = null) {
    if (!roleCode || typeof roleCode !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('roleCode', sql.NVarChar(50), roleCode.trim().toUpperCase())
            .query(`
                SELECT TOP 1
                    r.role_id,
                    r.role_code,
                    r.role_name,
                    r.description,
                    r.created_at
                FROM dbo.roles r
                WHERE r.role_code = @roleCode;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findRoleByCode', { roleCode, error: err.message });
        throw new DatabaseError('Failed to find role by code.', err);
    }
}

/**
 * Finds a role by primary key role_id.
 * @param {number} roleId
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findRoleById(roleId, transaction = null) {
    if (!roleId || typeof roleId !== 'number') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('roleId', sql.Int, roleId)
            .query(`
                SELECT TOP 1
                    r.role_id,
                    r.role_code,
                    r.role_name,
                    r.description,
                    r.created_at
                FROM dbo.roles r
                WHERE r.role_id = @roleId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findRoleById', { roleId, error: err.message });
        throw new DatabaseError('Failed to find role by ID.', err);
    }
}

/**
 * Assigns an RBAC role to a user.
 * @param {string} userId GUID
 * @param {number} roleId Integer
 * @param {string} [assignedByUserId=null] GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function assignRoleToUser(userId, roleId, assignedByUserId = null, transaction = null) {
    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('userId', sql.UniqueIdentifier, userId.trim())
            .input('roleId', sql.Int, roleId)
            .input('assignedByUserId', sql.UniqueIdentifier, assignedByUserId ? assignedByUserId.trim() : null)
            .query(`
                IF NOT EXISTS (SELECT 1 FROM dbo.user_roles WHERE user_id = @userId AND role_id = @roleId)
                BEGIN
                    INSERT INTO dbo.user_roles (user_id, role_id, assigned_by_user_id)
                    OUTPUT
                        INSERTED.user_id,
                        INSERTED.role_id,
                        INSERTED.assigned_at,
                        INSERTED.assigned_by_user_id
                    VALUES (@userId, @roleId, @assignedByUserId);
                END
                ELSE
                BEGIN
                    SELECT TOP 1 user_id, role_id, assigned_at, assigned_by_user_id
                    FROM dbo.user_roles
                    WHERE user_id = @userId AND role_id = @roleId;
                END
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database query failed in assignRoleToUser', { userId, roleId, error: err.message });
        throw new DatabaseError('Failed to assign role to user.', err);
    }
}

/**
 * Removes an assigned role from a user.
 * @param {string} userId GUID
 * @param {number} roleId Integer
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<boolean>}
 */
async function removeRoleFromUser(userId, roleId, transaction = null) {
    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('userId', sql.UniqueIdentifier, userId.trim())
            .input('roleId', sql.Int, roleId)
            .query(`
                DELETE FROM dbo.user_roles
                WHERE user_id = @userId AND role_id = @roleId;
            `);

        return result.rowsAffected[0] > 0;
    } catch (err) {
        logger.error('Database query failed in removeRoleFromUser', { userId, roleId, error: err.message });
        throw new DatabaseError('Failed to remove role from user.', err);
    }
}

/**
 * Retrieves all assigned roles for a given user.
 * @param {string} userId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function getUserRoles(userId, transaction = null) {
    if (!userId || typeof userId !== 'string') return [];

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('userId', sql.UniqueIdentifier, userId.trim())
            .query(`
                SELECT
                    r.role_id,
                    r.role_code,
                    r.role_name,
                    r.description,
                    ur.assigned_at
                FROM dbo.user_roles ur
                INNER JOIN dbo.roles r ON ur.role_id = r.role_id
                WHERE ur.user_id = @userId
                ORDER BY r.role_code ASC;
            `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in getUserRoles', { userId, error: err.message });
        throw new DatabaseError('Failed to get user roles.', err);
    }
}

module.exports = {
    listRoles,
    findRoleByCode,
    findRoleById,
    assignRoleToUser,
    removeRoleFromUser,
    getUserRoles
};

