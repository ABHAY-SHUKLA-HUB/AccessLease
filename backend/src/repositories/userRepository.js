/**
 * AccessLease — User Data Access Repository
 * Executes parameterized queries against dbo.users and dbo.user_roles.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { randomUUID } = require('crypto');
const { getPool } = require('../config/database');
const { DatabaseError, ConflictError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Finds an application user by their stable Microsoft Entra Object ID (oid).
 * @param {string} entraObjectId Microsoft Entra Object ID (UUID string)
 * @param {sql.Transaction} [transaction=null] Optional active transaction
 * @returns {Promise<object|null>} User record or null if not found
 */
async function findUserByEntraObjectId(entraObjectId, transaction = null) {
    if (!entraObjectId || typeof entraObjectId !== 'string') {
        return null;
    }

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
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
 * @param {sql.Transaction} [transaction=null] Optional active transaction
 * @returns {Promise<object|null>} User record or null if not found
 */
async function findUserById(userId, transaction = null) {
    if (!userId || typeof userId !== 'string') {
        return null;
    }

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
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
 * @param {sql.Transaction} [transaction=null] Optional active transaction
 * @returns {Promise<object|null>} User record or null if not found
 */
async function findUserByEmail(email, transaction = null) {
    if (!email || typeof email !== 'string') {
        return null;
    }

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
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
 * @param {sql.Transaction} [transaction=null] Optional active transaction
 * @returns {Promise<Array<object>>} List of assigned role records
 */
async function getUserRoles(userId, transaction = null) {
    if (!userId || typeof userId !== 'string') {
        return [];
    }

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
        logger.error('Database query failed in getUserRoles', {
            userId,
            error: err.message
        });
        throw new DatabaseError('Failed to retrieve user roles.', err);
    }
}

/**
 * Lists application users with optional filtering.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null] Optional active transaction
 * @returns {Promise<Array<object>>}
 */
async function listUsers(filter = {}, transaction = null) {
    const { userType, isActive, search, limit = 50, offset = 0 } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
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
                u.updated_at,
                STRING_AGG(r.role_code, ',') WITHIN GROUP (ORDER BY r.role_code ASC) AS role_codes,
                STRING_AGG(r.role_name, ',') WITHIN GROUP (ORDER BY r.role_code ASC) AS role_names
            FROM dbo.users u
            LEFT JOIN dbo.user_roles ur ON u.user_id = ur.user_id
            LEFT JOIN dbo.roles r ON ur.role_id = r.role_id
            WHERE 1=1
        `;

        if (userType) {
            sqlQuery += ` AND u.user_type = @userType`;
            request.input('userType', sql.NVarChar(30), userType);
        }

        if (isActive !== undefined && isActive !== null) {
            sqlQuery += ` AND u.is_active = @isActive`;
            request.input('isActive', sql.Bit, isActive ? 1 : 0);
        }

        if (search && typeof search === 'string' && search.trim()) {
            sqlQuery += ` AND (u.display_name LIKE @search OR u.email LIKE @search OR u.first_name LIKE @search OR u.last_name LIKE @search OR u.department LIKE @search)`;
            request.input('search', sql.NVarChar(128), `%${search.trim()}%`);
        }

        sqlQuery += `
            GROUP BY
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
            ORDER BY u.display_name ASC
            OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;
        `;
        request.input('offset', sql.Int, Math.max(0, offset));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, limit)));

        const result = await request.query(sqlQuery);
        const rows = result.recordset || [];
        return rows.map(u => {
            const roleCodes = u.role_codes ? u.role_codes.split(',') : [];
            const roleNames = u.role_names ? u.role_names.split(',') : [];
            const roles = roleCodes.map((code, idx) => ({
                role_code: code,
                role_name: roleNames[idx] || code
            }));
            return {
                ...u,
                roles
            };
        });
    } catch (err) {
        logger.error('Database query failed in listUsers', { error: err.message });
        throw new DatabaseError('Failed to list users.', err);
    }
}

/**
 * Counts application users matching filter.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<number>}
 */
async function countUsers(filter = {}, transaction = null) {
    const { userType, isActive, search } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `SELECT COUNT(1) AS total FROM dbo.users u WHERE 1=1`;

        if (userType) {
            sqlQuery += ` AND u.user_type = @userType`;
            request.input('userType', sql.NVarChar(30), userType);
        }

        if (isActive !== undefined && isActive !== null) {
            sqlQuery += ` AND u.is_active = @isActive`;
            request.input('isActive', sql.Bit, isActive ? 1 : 0);
        }

        if (search && typeof search === 'string' && search.trim()) {
            sqlQuery += ` AND (u.display_name LIKE @search OR u.email LIKE @search OR u.first_name LIKE @search OR u.last_name LIKE @search)`;
            request.input('search', sql.NVarChar(128), `%${search.trim()}%`);
        }

        const result = await request.query(sqlQuery);
        return result.recordset && result.recordset[0] ? result.recordset[0].total : 0;
    } catch (err) {
        logger.error('Database query failed in countUsers', { error: err.message });
        throw new DatabaseError('Failed to count users.', err);
    }
}

/**
 * Lists contractors enriched with engagement summary metrics.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listContractors(filter = {}, transaction = null) {
    const { isActive, search, limit = 50, offset = 0 } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
                u.user_id,
                u.user_id AS contractor_id,
                u.entra_object_id,
                u.email,
                u.first_name,
                u.last_name,
                u.display_name,
                u.user_type,
                u.department,
                u.is_active,
                u.created_at,
                u.updated_at,
                COUNT(ce.engagement_id) AS total_engagements,
                SUM(CASE WHEN ce.status = 'ACTIVE' THEN 1 ELSE 0 END) AS active_engagements,
                MAX(ce.vendor_name) AS latest_vendor
            FROM dbo.users u
            LEFT JOIN dbo.contractor_engagements ce ON u.user_id = ce.contractor_user_id
            WHERE u.user_type = 'CONTRACTOR'
        `;

        if (isActive !== undefined && isActive !== null) {
            sqlQuery += ` AND u.is_active = @isActive`;
            request.input('isActive', sql.Bit, isActive ? 1 : 0);
        }

        if (search && typeof search === 'string' && search.trim()) {
            sqlQuery += ` AND (u.display_name LIKE @search OR u.email LIKE @search OR u.first_name LIKE @search OR u.last_name LIKE @search OR ce.vendor_name LIKE @search)`;
            request.input('search', sql.NVarChar(128), `%${search.trim()}%`);
        }

        sqlQuery += `
            GROUP BY
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
            ORDER BY u.display_name ASC
            OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;
        `;

        request.input('offset', sql.Int, Math.max(0, offset));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, limit)));

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listContractors', { error: err.message });
        throw new DatabaseError('Failed to list contractors with metrics.', err);
    }
}

/**
 * Counts contractors matching filter criteria for directory pagination.
 * Strictly scopes to user_type = 'CONTRACTOR'.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<number>}
 */
async function countContractors(filter = {}, transaction = null) {
    const { isActive, search } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT COUNT(DISTINCT u.user_id) AS total
            FROM dbo.users u
            LEFT JOIN dbo.contractor_engagements ce ON u.user_id = ce.contractor_user_id
            WHERE u.user_type = 'CONTRACTOR'
        `;

        if (isActive !== undefined && isActive !== null) {
            sqlQuery += ` AND u.is_active = @isActive`;
            request.input('isActive', sql.Bit, isActive ? 1 : 0);
        }

        if (search && typeof search === 'string' && search.trim()) {
            sqlQuery += ` AND (u.display_name LIKE @search OR u.email LIKE @search OR u.first_name LIKE @search OR u.last_name LIKE @search OR ce.vendor_name LIKE @search)`;
            request.input('search', sql.NVarChar(128), `%${search.trim()}%`);
        }

        const result = await request.query(sqlQuery);
        return result.recordset && result.recordset[0] ? result.recordset[0].total : 0;
    } catch (err) {
        logger.error('Database query failed in countContractors', { error: err.message });
        throw new DatabaseError('Failed to count contractors.', err);
    }
}

/**
 * Inserts a new user record into dbo.users.
 * @param {object} userData
 * @param {sql.Transaction} [transaction=null] Optional active transaction
 * @returns {Promise<object>} Created user record
 */
async function createUser(userData, transaction = null) {
    const {
        entraObjectId = `LOCAL-CONTRACTOR-${randomUUID().toLowerCase()}`,
        email,
        firstName,
        lastName,
        displayName,
        userType = 'INTERNAL_EMPLOYEE',
        department = null,
        isActive = true
    } = userData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
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
        if (err.number === 2627 || err.number === 2601) {
            if (err.message && err.message.includes('UQ_users_email')) {
                throw new ConflictError(`A user with email '${email}' is already registered.`, 'ERR_CONTRACTOR_EXISTS');
            }
            if (err.message && err.message.includes('UQ_users_entra_object_id')) {
                throw new ConflictError('A user with this identity reference is already registered.', 'ERR_IDENTITY_EXISTS');
            }
            throw new ConflictError('A user with these unique attributes already exists.', 'ERR_CONFLICT');
        }

        logger.error('Database insert failed in createUser', {
            entraObjectId,
            email,
            error: err.message
        });
        throw new DatabaseError('Failed to create user record.', err);
    }
}

/**
 * Updates the active status of an application user.
 * @param {string} userId Uniqueidentifier GUID
 * @param {boolean} isActive
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function updateUserStatus(userId, isActive, transaction = null) {
    if (!userId || typeof userId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('userId', sql.UniqueIdentifier, userId.trim())
            .input('isActive', sql.Bit, isActive ? 1 : 0)
            .query(`
                UPDATE dbo.users
                SET is_active = @isActive, updated_at = SYSDATETIMEOFFSET()
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
                    INSERTED.updated_at
                WHERE user_id = @userId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database update failed in updateUserStatus', { userId, isActive, error: err.message });
        throw new DatabaseError('Failed to update user status.', err);
    }
}

/**
 * Deletes a user record and their role assignments (used for test cleanup).
 * @param {string} userId Uniqueidentifier GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<boolean>}
 */
async function deleteUser(userId, transaction = null) {
    if (!userId || typeof userId !== 'string') return false;

    try {
        const runner = transaction || await getPool();
        await runner.request()
            .input('userId', sql.UniqueIdentifier, userId.trim())
            .query('DELETE FROM dbo.user_roles WHERE user_id = @userId;');

        const result = await runner.request()
            .input('userId', sql.UniqueIdentifier, userId.trim())
            .query('DELETE FROM dbo.users WHERE user_id = @userId;');

        return result.rowsAffected && result.rowsAffected[0] > 0;
    } catch (err) {
        logger.error('Database delete failed in deleteUser', { userId, error: err.message });
        throw new DatabaseError('Failed to delete user record.', err);
    }
}

module.exports = {
    findUserByEntraObjectId,
    findUserById,
    findUserByEmail,
    getUserRoles,
    listUsers,
    countUsers,
    listContractors,
    countContractors,
    createUser,
    updateUserStatus,
    deleteUser
};

