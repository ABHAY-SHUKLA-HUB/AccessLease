/**
 * AccessLease — Resource & Entitlement Repository
 * Handles data access for dbo.resources, dbo.entitlements, and dbo.resource_owners.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Finds a resource by primary key resource_id.
 * @param {string} resourceId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findResourceById(resourceId, transaction = null) {
    if (!resourceId || typeof resourceId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('resourceId', sql.UniqueIdentifier, resourceId.trim())
            .query(`
                SELECT TOP 1
                    r.resource_id,
                    r.resource_code,
                    r.resource_name,
                    r.resource_type,
                    r.description,
                    r.risk_level,
                    r.requires_security_approval,
                    r.max_lease_duration_days,
                    r.is_active,
                    r.created_at,
                    r.updated_at
                FROM dbo.resources r
                WHERE r.resource_id = @resourceId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findResourceById', { resourceId, error: err.message });
        throw new DatabaseError('Failed to find resource by ID.', err);
    }
}

/**
 * Finds a resource by its unique resource_code.
 * @param {string} resourceCode
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findResourceByCode(resourceCode, transaction = null) {
    if (!resourceCode || typeof resourceCode !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('resourceCode', sql.NVarChar(50), resourceCode.trim().toUpperCase())
            .query(`
                SELECT TOP 1
                    r.resource_id,
                    r.resource_code,
                    r.resource_name,
                    r.resource_type,
                    r.description,
                    r.risk_level,
                    r.requires_security_approval,
                    r.max_lease_duration_days,
                    r.is_active,
                    r.created_at,
                    r.updated_at
                FROM dbo.resources r
                WHERE r.resource_code = @resourceCode;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findResourceByCode', { resourceCode, error: err.message });
        throw new DatabaseError('Failed to find resource by code.', err);
    }
}

/**
 * Lists resources with optional filtering.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listResources(filter = {}, transaction = null) {
    const { resourceType, riskLevel, isActive, limit = 50, offset = 0 } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
                r.resource_id,
                r.resource_code,
                r.resource_name,
                r.resource_type,
                r.description,
                r.risk_level,
                r.requires_security_approval,
                r.max_lease_duration_days,
                r.is_active,
                r.created_at,
                r.updated_at
            FROM dbo.resources r
            WHERE 1=1
        `;

        if (resourceType) {
            sqlQuery += ` AND r.resource_type = @resourceType`;
            request.input('resourceType', sql.NVarChar(50), resourceType);
        }

        if (riskLevel) {
            sqlQuery += ` AND r.risk_level = @riskLevel`;
            request.input('riskLevel', sql.NVarChar(20), riskLevel);
        }

        if (isActive !== undefined && isActive !== null) {
            sqlQuery += ` AND r.is_active = @isActive`;
            request.input('isActive', sql.Bit, isActive ? 1 : 0);
        }

        sqlQuery += ` ORDER BY r.resource_name ASC OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;`;
        request.input('offset', sql.Int, Math.max(0, offset));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, limit)));

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listResources', { error: err.message });
        throw new DatabaseError('Failed to list resources.', err);
    }
}

/**
 * Creates a new resource.
 * @param {object} resourceData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function createResource(resourceData, transaction = null) {
    const {
        resourceCode,
        resourceName,
        resourceType,
        description = null,
        riskLevel = 'MEDIUM',
        requiresSecurityApproval = false,
        maxLeaseDurationDays = 90,
        isActive = true
    } = resourceData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('resourceCode', sql.NVarChar(50), resourceCode.trim().toUpperCase())
            .input('resourceName', sql.NVarChar(150), resourceName.trim())
            .input('resourceType', sql.NVarChar(50), resourceType)
            .input('description', sql.NVarChar(500), description)
            .input('riskLevel', sql.NVarChar(20), riskLevel)
            .input('requiresSecurityApproval', sql.Bit, requiresSecurityApproval ? 1 : 0)
            .input('maxLeaseDurationDays', sql.Int, maxLeaseDurationDays)
            .input('isActive', sql.Bit, isActive ? 1 : 0)
            .query(`
                INSERT INTO dbo.resources (
                    resource_code,
                    resource_name,
                    resource_type,
                    description,
                    risk_level,
                    requires_security_approval,
                    max_lease_duration_days,
                    is_active
                )
                OUTPUT
                    INSERTED.resource_id,
                    INSERTED.resource_code,
                    INSERTED.resource_name,
                    INSERTED.resource_type,
                    INSERTED.description,
                    INSERTED.risk_level,
                    INSERTED.requires_security_approval,
                    INSERTED.max_lease_duration_days,
                    INSERTED.is_active,
                    INSERTED.created_at,
                    INSERTED.updated_at
                VALUES (
                    @resourceCode,
                    @resourceName,
                    @resourceType,
                    @description,
                    @riskLevel,
                    @requiresSecurityApproval,
                    @maxLeaseDurationDays,
                    @isActive
                );
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in createResource', { resourceCode, error: err.message });
        throw new DatabaseError('Failed to create resource.', err);
    }
}

/**
 * Finds an entitlement by primary key entitlement_id.
 * @param {string} entitlementId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findEntitlementById(entitlementId, transaction = null) {
    if (!entitlementId || typeof entitlementId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('entitlementId', sql.UniqueIdentifier, entitlementId.trim())
            .query(`
                SELECT TOP 1
                    e.entitlement_id,
                    e.resource_id,
                    e.entitlement_code,
                    e.entitlement_name,
                    e.description,
                    e.sensitivity_level,
                    e.is_active,
                    e.created_at,
                    e.updated_at,
                    r.resource_code,
                    r.resource_name,
                    r.risk_level AS resource_risk_level
                FROM dbo.entitlements e
                INNER JOIN dbo.resources r ON e.resource_id = r.resource_id
                WHERE e.entitlement_id = @entitlementId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findEntitlementById', { entitlementId, error: err.message });
        throw new DatabaseError('Failed to find entitlement by ID.', err);
    }
}

/**
 * Lists entitlements belonging to a resource.
 * @param {string} resourceId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listEntitlementsByResourceId(resourceId, transaction = null) {
    if (!resourceId || typeof resourceId !== 'string') return [];

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('resourceId', sql.UniqueIdentifier, resourceId.trim())
            .query(`
                SELECT
                    e.entitlement_id,
                    e.resource_id,
                    e.entitlement_code,
                    e.entitlement_name,
                    e.description,
                    e.sensitivity_level,
                    e.is_active,
                    e.created_at,
                    e.updated_at
                FROM dbo.entitlements e
                WHERE e.resource_id = @resourceId
                ORDER BY e.entitlement_name ASC;
            `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listEntitlementsByResourceId', { resourceId, error: err.message });
        throw new DatabaseError('Failed to list entitlements for resource.', err);
    }
}

/**
 * Creates a new entitlement under a resource.
 * @param {object} entitlementData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function createEntitlement(entitlementData, transaction = null) {
    const {
        resourceId,
        entitlementCode,
        entitlementName,
        description = null,
        sensitivityLevel = 'MEDIUM',
        isActive = true
    } = entitlementData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('resourceId', sql.UniqueIdentifier, resourceId.trim())
            .input('entitlementCode', sql.NVarChar(50), entitlementCode.trim().toUpperCase())
            .input('entitlementName', sql.NVarChar(150), entitlementName.trim())
            .input('description', sql.NVarChar(500), description)
            .input('sensitivityLevel', sql.NVarChar(20), sensitivityLevel)
            .input('isActive', sql.Bit, isActive ? 1 : 0)
            .query(`
                INSERT INTO dbo.entitlements (
                    resource_id,
                    entitlement_code,
                    entitlement_name,
                    description,
                    sensitivity_level,
                    is_active
                )
                OUTPUT
                    INSERTED.entitlement_id,
                    INSERTED.resource_id,
                    INSERTED.entitlement_code,
                    INSERTED.entitlement_name,
                    INSERTED.description,
                    INSERTED.sensitivity_level,
                    INSERTED.is_active,
                    INSERTED.created_at,
                    INSERTED.updated_at
                VALUES (
                    @resourceId,
                    @entitlementCode,
                    @entitlementName,
                    @description,
                    @sensitivityLevel,
                    @isActive
                );
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in createEntitlement', { resourceId, entitlementCode, error: err.message });
        throw new DatabaseError('Failed to create entitlement.', err);
    }
}

/**
 * Retrieves designated owners for a resource.
 * @param {string} resourceId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function getResourceOwners(resourceId, transaction = null) {
    if (!resourceId || typeof resourceId !== 'string') return [];

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('resourceId', sql.UniqueIdentifier, resourceId.trim())
            .query(`
                SELECT
                    ro.resource_owner_id,
                    ro.resource_id,
                    ro.owner_user_id,
                    ro.ownership_type,
                    ro.assigned_at,
                    u.display_name AS owner_name,
                    u.email AS owner_email,
                    u.department AS owner_department
                FROM dbo.resource_owners ro
                INNER JOIN dbo.users u ON ro.owner_user_id = u.user_id
                WHERE ro.resource_id = @resourceId
                ORDER BY ro.ownership_type ASC;
            `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in getResourceOwners', { resourceId, error: err.message });
        throw new DatabaseError('Failed to retrieve resource owners.', err);
    }
}

/**
 * Assigns an owner to a resource.
 * @param {string} resourceId GUID
 * @param {string} ownerUserId GUID
 * @param {string} [ownershipType='PRIMARY'] 'PRIMARY', 'DELEGATE', 'TECHNICAL_CONTACT'
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function assignResourceOwner(resourceId, ownerUserId, ownershipType = 'PRIMARY', transaction = null) {
    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('resourceId', sql.UniqueIdentifier, resourceId.trim())
            .input('ownerUserId', sql.UniqueIdentifier, ownerUserId.trim())
            .input('ownershipType', sql.NVarChar(30), ownershipType)
            .query(`
                INSERT INTO dbo.resource_owners (
                    resource_id,
                    owner_user_id,
                    ownership_type
                )
                OUTPUT
                    INSERTED.resource_owner_id,
                    INSERTED.resource_id,
                    INSERTED.owner_user_id,
                    INSERTED.ownership_type,
                    INSERTED.assigned_at
                VALUES (
                    @resourceId,
                    @ownerUserId,
                    @ownershipType
                );
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in assignResourceOwner', { resourceId, ownerUserId, error: err.message });
        throw new DatabaseError('Failed to assign resource owner.', err);
    }
}

/**
 * Checks if a user is an owner of the specified resource.
 * @param {string} ownerUserId GUID
 * @param {string} resourceId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<boolean>}
 */
async function isUserResourceOwner(ownerUserId, resourceId, transaction = null) {
    if (!ownerUserId || !resourceId || typeof ownerUserId !== 'string' || typeof resourceId !== 'string') {
        return false;
    }

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('ownerUserId', sql.UniqueIdentifier, ownerUserId.trim())
            .input('resourceId', sql.UniqueIdentifier, resourceId.trim())
            .query(`
                SELECT TOP 1 1 AS is_owner
                FROM dbo.resource_owners
                WHERE owner_user_id = @ownerUserId AND resource_id = @resourceId;
            `);

        return result.recordset.length > 0;
    } catch (err) {
        logger.error('Database query failed in isUserResourceOwner', { ownerUserId, resourceId, error: err.message });
        throw new DatabaseError('Failed to verify resource owner.', err);
    }
}

/**
 * Retrieves all resource IDs owned by a user.
 * @param {string} ownerUserId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<string>>}
 */
async function getResourceIdsForOwner(ownerUserId, transaction = null) {
    if (!ownerUserId || typeof ownerUserId !== 'string') return [];

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('ownerUserId', sql.UniqueIdentifier, ownerUserId.trim())
            .query(`
                SELECT resource_id
                FROM dbo.resource_owners
                WHERE owner_user_id = @ownerUserId;
            `);

        return result.recordset.map(r => r.resource_id);
    } catch (err) {
        logger.error('Database query failed in getResourceIdsForOwner', { ownerUserId, error: err.message });
        throw new DatabaseError('Failed to retrieve resource IDs for owner.', err);
    }
}

module.exports = {
    findResourceById,
    findResourceByCode,
    listResources,
    createResource,
    findEntitlementById,
    listEntitlementsByResourceId,
    createEntitlement,
    getResourceOwners,
    assignResourceOwner,
    isUserResourceOwner,
    getResourceIdsForOwner
};

