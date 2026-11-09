/**
 * AccessLease — User Data Access Repository
 * Executes parameterized queries against dbo.users and dbo.user_roles.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Finds an application user by their stable Microsoft Entra Object ID (oid).
 * @param {string} entraObjectId Microsoft Entra Object ID (UUID string)
 * @returns {Promise<object|null>} User record or null if not found
 */
async function findUserByEntraObjectId(entraObjectId) {
    if (!entraObjectId || typeof entraObjectId !== 'string') {
        return null;
    }

    try {
        const pool = await getPool();
        const result = await pool.request()
            .input('entraObjectId', sql.NVarChar(64), entraObjectId.trim())
            .query(`
                SELECT TOP 1
                    u.user_id,
                    u.entra_object_id,
                    u.email,
                    u.first_name,
                    u.last_name,
                    u.display_name,
                    u.user_type,
                    u.department,
                    u.is_active,
                    u.created_at,
                    u.updated_at
                FROM dbo.users u
                WHERE u.entra_object_id = @entraObjectId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findUserByEntraObjectId', {
            entraObjectId,
            error: err.message
        });
        throw new DatabaseError('Failed to retrieve user by Entra Object ID.', err);
    }
}

/**
 * Finds an application user by their primary key user_id.
 * @param {string} userId Uniqueidentifier GUID string
 * @returns {Promise<object|null>} User record or null if not found
 */
async function findUserById(userId) {
    if (!userId || typeof userId !== 'string') {
        return null;
    }

    try {
        const pool = await getPool();
        const result = await pool.request()
            .input('userId', sql.UniqueIdentifier, userId.trim())
            .query(`
                SELECT TOP 1
                    u.user_id,
                    u.entra_object_id,
                    u.email,
                    u.first_name,
                    u.last_name,
                    u.display_name,
                    u.user_type,
                    u.department,
                    u.is_active,
                    u.created_at,
                    u.updated_at
                FROM dbo.users u
                WHERE u.user_id = @userId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findUserById', {
            userId,
            error: err.message
        });
        throw new DatabaseError('Failed to retrieve user by ID.', err);
    }
}

/**
 * Finds an application user by their email address.
 * @param {string} email Email address
 * @returns {Promise<object|null>} User record or null if not found
 */
async function findUserByEmail(email) {
    if (!email || typeof email !== 'string') {
        return null;
    }

    try {
        const pool = await getPool();
        const result = await pool.request()
            .input('email', sql.NVarChar(256), email.trim().toLowerCase())
            .query(`
                SELECT TOP 1
                    u.user_id,
                    u.entra_object_id,
                    u.email,
                    u.first_name,
                    u.last_name,
                    u.display_name,
                    u.user_type,
                    u.department,
                    u.is_active,
                    u.created_at,
                    u.updated_at
                FROM dbo.users u
                WHERE LOWER(u.email) = @email;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findUserByEmail', {
            email,
            error: err.message
        });
        throw new DatabaseError('Failed to retrieve user by email.', err);
    }
}

/**
 * Retrieves the assigned RBAC roles for a user.
 * @param {string} userId Uniqueidentifier GUID string
 * @returns {Promise<Array<object>>} List of assigned role records
 */
async function getUserRoles(userId) {
    if (!userId || typeof userId !== 'string') {
        return [];
    }

    try {
        const pool = await getPool();
        const result = await pool.request()
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
        logger.error('Database query failed in getUserRoles', {
            userId,
            error: err.message
        });
        throw new DatabaseError('Failed to retrieve user roles.', err);
    }
}

/**
 * Inserts a new user record into dbo.users.
 * @param {object} userData
 * @returns {Promise<object>} Created user record
 */
async function createUser(userData) {
    const {
        entraObjectId,
        email,
        firstName,
        lastName,
        displayName,
        userType = 'INTERNAL_EMPLOYEE',
        department = null,
        isActive = true
    } = userData;

    try {
        const pool = await getPool();
        const result = await pool.request()
            .input('entraObjectId', sql.NVarChar(64), entraObjectId.trim())
            .input('email', sql.NVarChar(256), email.trim().toLowerCase())
            .input('firstName', sql.NVarChar(64), firstName.trim())
            .input('lastName', sql.NVarChar(64), lastName.trim())
            .input('displayName', sql.NVarChar(128), displayName.trim())
            .input('userType', sql.NVarChar(30), userType)
            .input('department', sql.NVarChar(100), department)
            .input('isActive', sql.Bit, isActive ? 1 : 0)
            .query(`
                INSERT INTO dbo.users (
                    entra_object_id,
                    email,
                    first_name,
                    last_name,
                    display_name,
                    user_type,
                    department,
                    is_active
                )
                OUTPUT
                    INSERTED.user_id,
                    INSERTED.entra_object_id,
                    INSERTED.email,
                    INSERTED.first_name,
                    INSERTED.last_name,
                    INSERTED.display_name,
                    INSERTED.user_type,
                    INSERTED.department,
                    INSERTED.is_active,
                    INSERTED.created_at,
                    INSERTED.updated_at
                VALUES (
                    @entraObjectId,
                    @email,
                    @firstName,
                    @lastName,
                    @displayName,
                    @userType,
                    @department,
                    @isActive
                );
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in createUser', {
            entraObjectId,
            email,
            error: err.message
        });
        throw new DatabaseError('Failed to create user record.', err);
    }
}

module.exports = {
    findUserByEntraObjectId,
    findUserById,
    findUserByEmail,
    getUserRoles,
    createUser
};

