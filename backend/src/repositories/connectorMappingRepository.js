/**
 * AccessLease — Connector Resource Mapping Repository
 * Handles data access for dbo.connector_resource_mappings.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Resolves connector resource mapping for an approved resource and entitlement.
 * @param {string} resourceId GUID
 * @param {string} entitlementId GUID
 * @param {string} [connectorType='GITHUB']
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findMappingByResourceAndEntitlement(resourceId, entitlementId, connectorType = 'GITHUB', transaction = null) {
    if (!resourceId || !entitlementId) return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('resourceId', sql.UniqueIdentifier, resourceId.trim())
            .input('entitlementId', sql.UniqueIdentifier, entitlementId.trim())
            .input('connectorType', sql.NVarChar(50), connectorType.trim().toUpperCase())
            .query(`
                SELECT TOP 1
                    crm.mapping_id,
                    crm.resource_id,
                    crm.entitlement_id,
                    crm.connector_type,
                    crm.github_org,
                    crm.github_team_slug,
                    crm.github_repo_owner,
                    crm.github_repo_name,
                    crm.required_permission,
                    crm.is_active,
                    crm.created_at,
                    crm.updated_at,
                    r.resource_code,
                    r.resource_name,
                    e.entitlement_code,
                    e.entitlement_name
                FROM dbo.connector_resource_mappings crm
                INNER JOIN dbo.resources r ON crm.resource_id = r.resource_id
                INNER JOIN dbo.entitlements e ON crm.entitlement_id = e.entitlement_id
                WHERE crm.resource_id = @resourceId
                  AND crm.entitlement_id = @entitlementId
                  AND crm.connector_type = @connectorType
                  AND crm.is_active = 1;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findMappingByResourceAndEntitlement', { resourceId, entitlementId, connectorType, error: err.message });
        throw new DatabaseError('Failed to find connector resource mapping.', err);
    }
}

/**
 * Creates or updates a connector resource mapping.
 * @param {object} mappingData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function upsertConnectorMapping(mappingData, transaction = null) {
    const {
        resourceId,
        entitlementId,
        connectorType = 'GITHUB',
        githubOrg,
        githubTeamSlug,
        githubRepoOwner,
        githubRepoName,
        requiredPermission = 'pull',
        isActive = 1
    } = mappingData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('resourceId', sql.UniqueIdentifier, resourceId.trim())
            .input('entitlementId', sql.UniqueIdentifier, entitlementId.trim())
            .input('connectorType', sql.NVarChar(50), connectorType.trim().toUpperCase())
            .input('githubOrg', sql.NVarChar(100), githubOrg.trim().toLowerCase())
            .input('githubTeamSlug', sql.NVarChar(100), githubTeamSlug.trim().toLowerCase())
            .input('githubRepoOwner', sql.NVarChar(100), githubRepoOwner.trim())
            .input('githubRepoName', sql.NVarChar(100), githubRepoName.trim())
            .input('requiredPermission', sql.NVarChar(50), requiredPermission.trim().toLowerCase())
            .input('isActive', sql.Bit, isActive ? 1 : 0)
            .query(`
                MERGE dbo.connector_resource_mappings WITH (HOLDLOCK) AS target
                USING (SELECT @resourceId AS resource_id, @entitlementId AS entitlement_id, @connectorType AS connector_type) AS source
                ON (target.resource_id = source.resource_id AND target.entitlement_id = source.entitlement_id AND target.connector_type = source.connector_type)
                WHEN MATCHED THEN
                    UPDATE SET
                        github_org = @githubOrg,
                        github_team_slug = @githubTeamSlug,
                        github_repo_owner = @githubRepoOwner,
                        github_repo_name = @githubRepoName,
                        required_permission = @requiredPermission,
                        is_active = @isActive,
                        updated_at = SYSDATETIMEOFFSET()
                WHEN NOT MATCHED THEN
                    INSERT (
                        resource_id,
                        entitlement_id,
                        connector_type,
                        github_org,
                        github_team_slug,
                        github_repo_owner,
                        github_repo_name,
                        required_permission,
                        is_active,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        @resourceId,
                        @entitlementId,
                        @connectorType,
                        @githubOrg,
                        @githubTeamSlug,
                        @githubRepoOwner,
                        @githubRepoName,
                        @requiredPermission,
                        @isActive,
                        SYSDATETIMEOFFSET(),
                        SYSDATETIMEOFFSET()
                    )
                OUTPUT
                    INSERTED.mapping_id,
                    INSERTED.resource_id,
                    INSERTED.entitlement_id,
                    INSERTED.connector_type,
                    INSERTED.github_org,
                    INSERTED.github_team_slug,
                    INSERTED.github_repo_owner,
                    INSERTED.github_repo_name,
                    INSERTED.required_permission,
                    INSERTED.is_active,
                    INSERTED.created_at,
                    INSERTED.updated_at;
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database query failed in upsertConnectorMapping', { resourceId, entitlementId, error: err.message });
        throw new DatabaseError('Failed to upsert connector resource mapping.', err);
    }
}

/**
 * Lists connector resource mappings.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listConnectorMappings(filter = {}, transaction = null) {
    const { resourceId, connectorType, isActive = true } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT
                crm.mapping_id,
                crm.resource_id,
                crm.entitlement_id,
                crm.connector_type,
                crm.github_org,
                crm.github_team_slug,
                crm.github_repo_owner,
                crm.github_repo_name,
                crm.required_permission,
                crm.is_active,
                crm.created_at,
                crm.updated_at,
                r.resource_code,
                r.resource_name,
                e.entitlement_code,
                e.entitlement_name
            FROM dbo.connector_resource_mappings crm
            INNER JOIN dbo.resources r ON crm.resource_id = r.resource_id
            INNER JOIN dbo.entitlements e ON crm.entitlement_id = e.entitlement_id
            WHERE 1=1
        `;

        if (resourceId) {
            sqlQuery += ` AND crm.resource_id = @resourceId`;
            request.input('resourceId', sql.UniqueIdentifier, resourceId.trim());
        }

        if (connectorType) {
            sqlQuery += ` AND crm.connector_type = @connectorType`;
            request.input('connectorType', sql.NVarChar(50), connectorType.trim().toUpperCase());
        }

        if (isActive !== null && isActive !== undefined) {
            sqlQuery += ` AND crm.is_active = @isActive`;
            request.input('isActive', sql.Bit, isActive ? 1 : 0);
        }

        sqlQuery += ` ORDER BY r.resource_name ASC, e.entitlement_name ASC;`;

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listConnectorMappings', { error: err.message });
        throw new DatabaseError('Failed to list connector resource mappings.', err);
    }
}

module.exports = {
    findMappingByResourceAndEntitlement,
    upsertConnectorMapping,
    listConnectorMappings
};

