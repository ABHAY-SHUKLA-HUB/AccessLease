/**
 * AccessLease — Access Request & Approval Workflow Repository
 * Handles data access for dbo.access_requests and dbo.approval_steps.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Finds an access request by primary key request_id.
 * @param {string} requestId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findRequestById(requestId, transaction = null) {
    if (!requestId || typeof requestId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('requestId', sql.UniqueIdentifier, requestId.trim())
            .query(`
                SELECT TOP 1
                    ar.request_id,
                    ar.request_number,
                    ar.contractor_engagement_id,
                    ar.requested_by_user_id,
                    ar.resource_id,
                    ar.entitlement_id,
                    ar.requested_start_date,
                    ar.requested_end_date,
                    ar.business_justification,
                    ar.status,
                    ar.requires_security_approval,
                    ar.created_at,
                    ar.updated_at,
                    r.resource_code,
                    r.resource_name,
                    r.risk_level AS resource_risk_level,
                    e.entitlement_code,
                    e.entitlement_name,
                    req_u.display_name AS requester_name,
                    req_u.email AS requester_email,
                    ce.vendor_name,
                    ce.contract_reference
                FROM dbo.access_requests ar
                INNER JOIN dbo.resources r ON ar.resource_id = r.resource_id
                INNER JOIN dbo.entitlements e ON ar.entitlement_id = e.entitlement_id
                INNER JOIN dbo.users req_u ON ar.requested_by_user_id = req_u.user_id
                INNER JOIN dbo.contractor_engagements ce ON ar.contractor_engagement_id = ce.engagement_id
                WHERE ar.request_id = @requestId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findRequestById', { requestId, error: err.message });
        throw new DatabaseError('Failed to find access request by ID.', err);
    }
}

/**
 * Finds an access request by unique human-readable request_number.
 * @param {string} requestNumber E.g. 'AR-2026-0001'
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findRequestByNumber(requestNumber, transaction = null) {
    if (!requestNumber || typeof requestNumber !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('requestNumber', sql.NVarChar(30), requestNumber.trim())
            .query(`
                SELECT TOP 1
                    ar.request_id,
                    ar.request_number,
                    ar.contractor_engagement_id,
                    ar.requested_by_user_id,
                    ar.resource_id,
                    ar.entitlement_id,
                    ar.requested_start_date,
                    ar.requested_end_date,
                    ar.business_justification,
                    ar.status,
                    ar.requires_security_approval,
                    ar.created_at,
                    ar.updated_at
                FROM dbo.access_requests ar
                WHERE ar.request_number = @requestNumber;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findRequestByNumber', { requestNumber, error: err.message });
        throw new DatabaseError('Failed to find access request by number.', err);
    }
}

/**
 * Lists access requests with optional filtering and contextual role-based scoping.
 * @param {object} [filter={}]
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listRequests(filter = {}, transaction = null) {
    const {
        status,
        requestedByUserId,
        contractorEngagementId,
        scopedUser,
        limit = 50,
        offset = 0
    } = filter;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let sqlQuery = `
            SELECT DISTINCT
                ar.request_id,
                ar.request_number,
                ar.contractor_engagement_id,
                ar.requested_by_user_id,
                ar.resource_id,
                ar.entitlement_id,
                ar.requested_start_date,
                ar.requested_end_date,
                ar.business_justification,
                ar.status,
                ar.requires_security_approval,
                ar.created_at,
                ar.updated_at,
                r.resource_name,
                e.entitlement_name,
                req_u.display_name AS requester_name
            FROM dbo.access_requests ar
            INNER JOIN dbo.resources r ON ar.resource_id = r.resource_id
            INNER JOIN dbo.entitlements e ON ar.entitlement_id = e.entitlement_id
            INNER JOIN dbo.users req_u ON ar.requested_by_user_id = req_u.user_id
            INNER JOIN dbo.contractor_engagements ce ON ar.contractor_engagement_id = ce.engagement_id
        `;

        // If scopedUser is provided and is not admin or compliance auditor, restrict to authorized scope
        const isSystemAdmin = scopedUser && Array.isArray(scopedUser.roles) && scopedUser.roles.some(r => (r.role_code || r) === 'SYSTEM_ADMIN');
        const isAuditor = scopedUser && Array.isArray(scopedUser.roles) && scopedUser.roles.some(r => (r.role_code || r) === 'COMPLIANCE_AUDITOR');
        const isSecurityOfficer = scopedUser && Array.isArray(scopedUser.roles) && scopedUser.roles.some(r => (r.role_code || r) === 'SECURITY_OFFICER');

        if (scopedUser && !isSystemAdmin && !isAuditor) {
            sqlQuery += `
                LEFT JOIN dbo.resource_owners ro ON ar.resource_id = ro.resource_id AND ro.owner_user_id = @scopedUserId
                LEFT JOIN dbo.approval_steps ast ON ar.request_id = ast.request_id AND ast.assigned_approver_user_id = @scopedUserId
                WHERE 1=1
                  AND (
                      ar.requested_by_user_id = @scopedUserId
                      OR ce.sponsor_user_id = @scopedUserId
                      OR ro.owner_user_id IS NOT NULL
                      OR ast.approval_step_id IS NOT NULL
                      OR (@isSecOfficer = 1 AND ar.requires_security_approval = 1)
                  )
            `;
            request.input('scopedUserId', sql.UniqueIdentifier, scopedUser.user_id.trim());
            request.input('isSecOfficer', sql.Bit, isSecurityOfficer ? 1 : 0);
        } else {
            sqlQuery += ` WHERE 1=1`;
        }

        if (status) {
            sqlQuery += ` AND ar.status = @status`;
            request.input('status', sql.NVarChar(30), status);
        }

        if (requestedByUserId) {
            sqlQuery += ` AND ar.requested_by_user_id = @requestedByUserId`;
            request.input('requestedByUserId', sql.UniqueIdentifier, requestedByUserId.trim());
        }

        if (contractorEngagementId) {
            sqlQuery += ` AND ar.contractor_engagement_id = @contractorEngagementId`;
            request.input('contractorEngagementId', sql.UniqueIdentifier, contractorEngagementId.trim());
        }

        sqlQuery += ` ORDER BY ar.created_at DESC OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY;`;
        request.input('offset', sql.Int, Math.max(0, offset));
        request.input('limit', sql.Int, Math.min(100, Math.max(1, limit)));

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listRequests', { error: err.message });
        throw new DatabaseError('Failed to list access requests.', err);
    }
}

/**
 * Creates a new access request.
 * @param {object} requestData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function createAccessRequest(requestData, transaction = null) {
    const {
        requestNumber,
        contractorEngagementId,
        requestedByUserId,
        resourceId,
        entitlementId,
        requestedStartDate,
        requestedEndDate,
        businessJustification,
        status = 'SUBMITTED',
        requiresSecurityApproval = false
    } = requestData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('requestNumber', sql.NVarChar(30), requestNumber.trim())
            .input('contractorEngagementId', sql.UniqueIdentifier, contractorEngagementId.trim())
            .input('requestedByUserId', sql.UniqueIdentifier, requestedByUserId.trim())
            .input('resourceId', sql.UniqueIdentifier, resourceId.trim())
            .input('entitlementId', sql.UniqueIdentifier, entitlementId.trim())
            .input('requestedStartDate', sql.DateTimeOffset, requestedStartDate)
            .input('requestedEndDate', sql.DateTimeOffset, requestedEndDate)
            .input('businessJustification', sql.NVarChar(1000), businessJustification.trim())
            .input('status', sql.NVarChar(30), status)
            .input('requiresSecurityApproval', sql.Bit, requiresSecurityApproval ? 1 : 0)
            .query(`
                INSERT INTO dbo.access_requests (
                    request_number,
                    contractor_engagement_id,
                    requested_by_user_id,
                    resource_id,
                    entitlement_id,
                    requested_start_date,
                    requested_end_date,
                    business_justification,
                    status,
                    requires_security_approval
                )
                OUTPUT
                    INSERTED.request_id,
                    INSERTED.request_number,
                    INSERTED.contractor_engagement_id,
                    INSERTED.requested_by_user_id,
                    INSERTED.resource_id,
                    INSERTED.entitlement_id,
                    INSERTED.requested_start_date,
                    INSERTED.requested_end_date,
                    INSERTED.business_justification,
                    INSERTED.status,
                    INSERTED.requires_security_approval,
                    INSERTED.created_at,
                    INSERTED.updated_at
                VALUES (
                    @requestNumber,
                    @contractorEngagementId,
                    @requestedByUserId,
                    @resourceId,
                    @entitlementId,
                    @requestedStartDate,
                    @requestedEndDate,
                    @businessJustification,
                    @status,
                    @requiresSecurityApproval
                );
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in createAccessRequest', { requestNumber, error: err.message });
        throw new DatabaseError('Failed to create access request.', err);
    }
}

/**
 * Updates status of an access request.
 * @param {string} requestId GUID
 * @param {string} status 'SUBMITTED', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'CANCELLED'
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function updateRequestStatus(requestId, status, transaction = null) {
    if (!requestId || !status) return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('requestId', sql.UniqueIdentifier, requestId.trim())
            .input('status', sql.NVarChar(30), status)
            .query(`
                UPDATE dbo.access_requests
                SET status = @status, updated_at = SYSDATETIMEOFFSET()
                OUTPUT
                    INSERTED.request_id,
                    INSERTED.request_number,
                    INSERTED.status,
                    INSERTED.updated_at
                WHERE request_id = @requestId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database update failed in updateRequestStatus', { requestId, status, error: err.message });
        throw new DatabaseError('Failed to update access request status.', err);
    }
}

/**
 * Retrieves all approval workflow steps for a request.
 * @param {string} requestId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function getApprovalSteps(requestId, transaction = null) {
    if (!requestId || typeof requestId !== 'string') return [];

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('requestId', sql.UniqueIdentifier, requestId.trim())
            .query(`
                SELECT
                    ast.approval_step_id,
                    ast.request_id,
                    ast.step_number,
                    ast.step_type,
                    ast.assigned_approver_user_id,
                    ast.status,
                    ast.decision_comments,
                    ast.decided_at,
                    ast.created_at,
                    u.display_name AS approver_name,
                    u.email AS approver_email
                FROM dbo.approval_steps ast
                INNER JOIN dbo.users u ON ast.assigned_approver_user_id = u.user_id
                WHERE ast.request_id = @requestId
                ORDER BY ast.step_number ASC;
            `);

        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in getApprovalSteps', { requestId, error: err.message });
        throw new DatabaseError('Failed to retrieve approval steps.', err);
    }
}

/**
 * Creates an approval step for a request.
 * @param {object} stepData
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object>}
 */
async function createApprovalStep(stepData, transaction = null) {
    const {
        requestId,
        stepNumber,
        stepType,
        assignedApproverUserId,
        status = 'PENDING'
    } = stepData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('requestId', sql.UniqueIdentifier, requestId.trim())
            .input('stepNumber', sql.Int, stepNumber)
            .input('stepType', sql.NVarChar(50), stepType)
            .input('assignedApproverUserId', sql.UniqueIdentifier, assignedApproverUserId.trim())
            .input('status', sql.NVarChar(30), status)
            .query(`
                INSERT INTO dbo.approval_steps (
                    request_id,
                    step_number,
                    step_type,
                    assigned_approver_user_id,
                    status
                )
                OUTPUT
                    INSERTED.approval_step_id,
                    INSERTED.request_id,
                    INSERTED.step_number,
                    INSERTED.step_type,
                    INSERTED.assigned_approver_user_id,
                    INSERTED.status,
                    INSERTED.created_at
                VALUES (
                    @requestId,
                    @stepNumber,
                    @stepType,
                    @assignedApproverUserId,
                    @status
                );
            `);

        return result.recordset[0];
    } catch (err) {
        logger.error('Database insert failed in createApprovalStep', { requestId, stepNumber, error: err.message });
        throw new DatabaseError('Failed to create approval step.', err);
    }
}

/**
 * Records an approval or rejection decision on a step.
 * @param {string} stepId GUID
 * @param {object} decisionData { status, decisionComments, decidedAt }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function updateApprovalStep(stepId, decisionData, transaction = null) {
    const { status, decisionComments = null, decidedAt = new Date() } = decisionData;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('stepId', sql.UniqueIdentifier, stepId.trim())
            .input('status', sql.NVarChar(30), status)
            .input('decisionComments', sql.NVarChar(1000), decisionComments)
            .input('decidedAt', sql.DateTimeOffset, decidedAt)
            .query(`
                UPDATE dbo.approval_steps
                SET status = @status,
                    decision_comments = @decisionComments,
                    decided_at = @decidedAt
                OUTPUT
                    INSERTED.approval_step_id,
                    INSERTED.request_id,
                    INSERTED.step_number,
                    INSERTED.step_type,
                    INSERTED.status,
                    INSERTED.decision_comments,
                    INSERTED.decided_at
                WHERE approval_step_id = @stepId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database update failed in updateApprovalStep', { stepId, status, error: err.message });
        throw new DatabaseError('Failed to update approval step.', err);
    }
}

/**
 * Finds an access request by primary key request_id with exclusive row update lock.
 * Prevents concurrent modifications and race conditions during approval evaluation.
 * @param {string} requestId GUID
 * @param {sql.Transaction} transaction Mandatory active transaction
 * @returns {Promise<object|null>}
 */
async function findRequestByIdForUpdate(requestId, transaction) {
    if (!requestId || !transaction) return null;

    try {
        const result = await transaction.request()
            .input('requestId', sql.UniqueIdentifier, requestId.trim())
            .query(`
                SELECT TOP 1
                    ar.request_id,
                    ar.request_number,
                    ar.contractor_engagement_id,
                    ar.requested_by_user_id,
                    ar.resource_id,
                    ar.entitlement_id,
                    ar.requested_start_date,
                    ar.requested_end_date,
                    ar.business_justification,
                    ar.status,
                    ar.requires_security_approval,
                    ar.created_at,
                    ar.updated_at
                FROM dbo.access_requests ar WITH (UPDLOCK, ROWLOCK)
                WHERE ar.request_id = @requestId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findRequestByIdForUpdate', { requestId, error: err.message });
        throw new DatabaseError('Failed to lock access request for update.', err);
    }
}

/**
 * Finds an individual approval step by primary key approval_step_id.
 * @param {string} stepId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findApprovalStepById(stepId, transaction = null) {
    if (!stepId || typeof stepId !== 'string') return null;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('stepId', sql.UniqueIdentifier, stepId.trim())
            .query(`
                SELECT TOP 1
                    ast.approval_step_id,
                    ast.request_id,
                    ast.step_number,
                    ast.step_type,
                    ast.assigned_approver_user_id,
                    ast.status,
                    ast.decision_comments,
                    ast.decided_at,
                    ast.created_at,
                    u.display_name AS approver_name,
                    u.email AS approver_email
                FROM dbo.approval_steps ast
                INNER JOIN dbo.users u ON ast.assigned_approver_user_id = u.user_id
                WHERE ast.approval_step_id = @stepId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findApprovalStepById', { stepId, error: err.message });
        throw new DatabaseError('Failed to retrieve approval step by ID.', err);
    }
}

/**
 * Finds an approval step with exclusive row update lock.
 * @param {string} stepId GUID
 * @param {sql.Transaction} transaction Mandatory active transaction
 * @returns {Promise<object|null>}
 */
async function findApprovalStepByIdForUpdate(stepId, transaction) {
    if (!stepId || !transaction) return null;

    try {
        const result = await transaction.request()
            .input('stepId', sql.UniqueIdentifier, stepId.trim())
            .query(`
                SELECT TOP 1
                    ast.approval_step_id,
                    ast.request_id,
                    ast.step_number,
                    ast.step_type,
                    ast.assigned_approver_user_id,
                    ast.status,
                    ast.decision_comments,
                    ast.decided_at,
                    ast.created_at
                FROM dbo.approval_steps ast WITH (UPDLOCK, ROWLOCK)
                WHERE ast.approval_step_id = @stepId;
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findApprovalStepByIdForUpdate', { stepId, error: err.message });
        throw new DatabaseError('Failed to lock approval step for update.', err);
    }
}

/**
 * Checks if an active (SUBMITTED or PENDING_APPROVAL) request already exists for the contractor and entitlement.
 * @param {string} engagementId GUID
 * @param {string} resourceId GUID
 * @param {string} entitlementId GUID
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<object|null>}
 */
async function findActiveRequest(engagementId, resourceId, entitlementId, transaction = null) {
    if (!engagementId || !resourceId || !entitlementId) return null;

    try {
        const runner = transaction || await getPool();
        const lockHint = transaction ? 'WITH (UPDLOCK, HOLDLOCK)' : '';
        const result = await runner.request()
            .input('engagementId', sql.UniqueIdentifier, engagementId.trim())
            .input('resourceId', sql.UniqueIdentifier, resourceId.trim())
            .input('entitlementId', sql.UniqueIdentifier, entitlementId.trim())
            .query(`
                SELECT TOP 1
                    ar.request_id,
                    ar.request_number,
                    ar.status,
                    ar.created_at
                FROM dbo.access_requests ar ${lockHint}
                WHERE ar.contractor_engagement_id = @engagementId
                  AND ar.resource_id = @resourceId
                  AND ar.entitlement_id = @entitlementId
                  AND ar.status IN ('SUBMITTED', 'PENDING_APPROVAL');
            `);

        return result.recordset.length > 0 ? result.recordset[0] : null;
    } catch (err) {
        logger.error('Database query failed in findActiveRequest', { error: err.message });
        throw new DatabaseError('Failed to check active request conflict.', err);
    }
}

/**
 * Lists currently actionable pending approval steps for an approver.
 * A step is actionable ONLY if all prerequisite prior steps on the same request are APPROVED.
 * @param {string} approverUserId GUID (or null if admin viewing all)
 * @param {object} [options={}] { isSystemAdmin, isSecurityOfficer }
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<Array<object>>}
 */
async function listActionablePendingSteps(approverUserId, options = {}, transaction = null) {
    const { isSystemAdmin = false, isSecurityOfficer = false } = options;

    try {
        const runner = transaction || await getPool();
        const request = runner.request();

        let approverCondition = 'ast.assigned_approver_user_id = @approverUserId';
        if (approverUserId) {
            request.input('approverUserId', sql.UniqueIdentifier, approverUserId.trim());
        }

        if (isSystemAdmin) {
            // System Administrator can view all actionable pending tasks across the platform
            approverCondition = '1=1';
        } else if (isSecurityOfficer) {
            // Security Officer can see tasks assigned to them OR unassigned/general SECURITY_APPROVAL steps
            approverCondition = '(ast.assigned_approver_user_id = @approverUserId OR ast.step_type = \'SECURITY_APPROVAL\')';
        }

        const sqlQuery = `
            SELECT
                ast.approval_step_id,
                ast.request_id,
                ast.step_number,
                ast.step_type,
                ast.assigned_approver_user_id,
                ast.status AS step_status,
                ast.created_at AS step_created_at,
                ar.request_number,
                ar.requested_start_date,
                ar.requested_end_date,
                ar.business_justification,
                ar.requires_security_approval,
                r.resource_name,
                r.resource_code,
                r.risk_level AS resource_risk_level,
                e.entitlement_name,
                e.entitlement_code,
                e.sensitivity_level AS entitlement_sensitivity,
                req_u.user_id AS contractor_user_id,
                req_u.display_name AS contractor_name,
                req_u.email AS contractor_email,
                ce.vendor_name,
                ce.contract_reference
            FROM dbo.approval_steps ast
            INNER JOIN dbo.access_requests ar ON ast.request_id = ar.request_id
            INNER JOIN dbo.resources r ON ar.resource_id = r.resource_id
            INNER JOIN dbo.entitlements e ON ar.entitlement_id = e.entitlement_id
            INNER JOIN dbo.users req_u ON ar.requested_by_user_id = req_u.user_id
            INNER JOIN dbo.contractor_engagements ce ON ar.contractor_engagement_id = ce.engagement_id
            WHERE ast.status = 'PENDING'
              AND ar.status = 'PENDING_APPROVAL'
              AND ${approverCondition}
              AND NOT EXISTS (
                  -- Guardrail: All prior step numbers on this request MUST be APPROVED
                  SELECT 1
                  FROM dbo.approval_steps prior_step
                  WHERE prior_step.request_id = ast.request_id
                    AND prior_step.step_number < ast.step_number
                    AND prior_step.status <> 'APPROVED'
              )
            ORDER BY ar.created_at ASC;
        `;

        const result = await request.query(sqlQuery);
        return result.recordset || [];
    } catch (err) {
        logger.error('Database query failed in listActionablePendingSteps', { error: err.message });
        throw new DatabaseError('Failed to list pending approval tasks.', err);
    }
}

/**
 * Marks any remaining pending steps for a request as SKIPPED.
 * @param {string} requestId GUID
 * @param {number} [afterStepNumber=0] Step number after which to skip
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<number>} Number of skipped steps
 */
async function skipRemainingSteps(requestId, afterStepNumber = 0, transaction = null) {
    if (!requestId) return 0;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('requestId', sql.UniqueIdentifier, requestId.trim())
            .input('afterStepNumber', sql.Int, afterStepNumber)
            .query(`
                UPDATE dbo.approval_steps
                SET status = 'SKIPPED', decided_at = SYSDATETIMEOFFSET(), decision_comments = 'Skipped due to terminal workflow resolution'
                OUTPUT INSERTED.approval_step_id
                WHERE request_id = @requestId
                  AND step_number > @afterStepNumber
                  AND status = 'PENDING';
            `);

        return result.rowsAffected[0] || 0;
    } catch (err) {
        logger.error('Database update failed in skipRemainingSteps', { requestId, error: err.message });
        throw new DatabaseError('Failed to skip remaining approval steps.', err);
    }
}

/**
 * Generates the next sequential unique request number (e.g. AR-2026-0001).
 * @param {sql.Transaction} [transaction=null]
 * @returns {Promise<string>}
 */
async function generateNextRequestNumber(transaction = null) {
    const year = new Date().getFullYear();
    const prefix = `AR-${year}-`;

    try {
        const runner = transaction || await getPool();
        const result = await runner.request()
            .input('pattern', sql.NVarChar(50), `${prefix}[0-9][0-9][0-9][0-9]`)
            .query(`
                SELECT TOP 1 request_number
                FROM dbo.access_requests WITH (UPDLOCK, HOLDLOCK)
                WHERE request_number LIKE @pattern
                  AND LEN(request_number) = 12
                ORDER BY request_number DESC;
            `);

        let nextSeq = 1;
        if (result.recordset.length > 0) {
            const lastNum = result.recordset[0].request_number;
            const parts = lastNum.split('-');
            const parsed = parseInt(parts[parts.length - 1], 10);
            if (!isNaN(parsed)) {
                nextSeq = parsed + 1;
            }
        }

        return `${prefix}${String(nextSeq).padStart(4, '0')}`;
    } catch (err) {
        logger.error('Failed to generate next request number', { error: err.message });
        // Fallback to timestamp-based unique code if query fails
        return `${prefix}${Date.now().toString().slice(-4)}`;
    }
}

module.exports = {
    findRequestById,
    findRequestByIdForUpdate,
    findRequestByNumber,
    findApprovalStepById,
    findApprovalStepByIdForUpdate,
    findActiveRequest,
    listRequests,
    listActionablePendingSteps,
    createAccessRequest,
    updateRequestStatus,
    getApprovalSteps,
    createApprovalStep,
    updateApprovalStep,
    skipRemainingSteps,
    generateNextRequestNumber
};

