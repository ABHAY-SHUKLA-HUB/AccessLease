/**
 * AccessLease — Security Analytics & Metrics Service
 * Produces real-time, database-driven governance metrics, status distributions,
 * and compliance exposure summaries with strict RBAC scoping.
 */

const sql = require('mssql');
const { getPool } = require('../config/database');
const { hasAnyRole } = require('../security/permissionPolicy');
const { DatabaseError, ForbiddenError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Retrieves aggregate security and governance metrics tailored to the user's role scope.
 * @param {object} actorUser Authenticated user
 * @returns {Promise<object>}
 */
async function getSecurityAnalyticsSummary(actorUser) {
    if (!actorUser) throw new ForbiddenError('Actor user is required for analytics.');

    const userRoles = actorUser.roles || [];
    const isGlobalGovernance = hasAnyRole(userRoles, ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR']);
    const isSponsor = hasAnyRole(userRoles, ['INTERNAL_SPONSOR']);
    const isResourceOwner = hasAnyRole(userRoles, ['RESOURCE_OWNER']);
    const isContractor = hasAnyRole(userRoles, ['CONTRACTOR']);

    try {
        const pool = await getPool();
        const request = pool.request();
        const userId = actorUser.user_id;
        request.input('userId', sql.UniqueIdentifier, userId);

        let engWhere = "ce.status = 'ACTIVE' AND ce.end_date >= CAST(SYSUTCDATETIME() AS DATE)";
        let grantWhere = "ag.status = 'ACTIVE'";
        let reqWhere = "ar.status IN ('SUBMITTED', 'PENDING_APPROVAL')";
        let appWhere = "asp.status = 'PENDING'";
        let findingWhere = "oaf.status = 'OPEN'";
        let revWhere = "1=1";
        let reviewWhere = "1=1";

        if (!isGlobalGovernance) {
            if (isContractor) {
                engWhere += " AND ce.contractor_user_id = @userId";
                grantWhere += " AND ag.contractor_engagement_id IN (SELECT engagement_id FROM dbo.contractor_engagements WHERE contractor_user_id = @userId)";
                reqWhere += " AND ar.contractor_engagement_id IN (SELECT engagement_id FROM dbo.contractor_engagements WHERE contractor_user_id = @userId)";
                appWhere += " AND 1=0"; // Contractors have no pending approvals
                findingWhere += " AND ag.contractor_engagement_id IN (SELECT engagement_id FROM dbo.contractor_engagements WHERE contractor_user_id = @userId)";
                revWhere += " AND rj.grant_id IN (SELECT grant_id FROM dbo.access_grants ag INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id WHERE ce.contractor_user_id = @userId)";
                reviewWhere += " AND 1=0";
            } else if (isSponsor) {
                engWhere += " AND ce.sponsor_user_id = @userId";
                grantWhere += " AND ag.contractor_engagement_id IN (SELECT engagement_id FROM dbo.contractor_engagements WHERE sponsor_user_id = @userId)";
                reqWhere += " AND ar.contractor_engagement_id IN (SELECT engagement_id FROM dbo.contractor_engagements WHERE sponsor_user_id = @userId)";
                appWhere += " AND asp.assigned_approver_user_id = @userId";
                findingWhere += " AND ag.contractor_engagement_id IN (SELECT engagement_id FROM dbo.contractor_engagements WHERE sponsor_user_id = @userId)";
                revWhere += " AND rj.grant_id IN (SELECT grant_id FROM dbo.access_grants ag INNER JOIN dbo.contractor_engagements ce ON ag.contractor_engagement_id = ce.engagement_id WHERE ce.sponsor_user_id = @userId)";
                reviewWhere += " AND arw.review_id IN (SELECT review_id FROM dbo.review_items WHERE reviewer_user_id = @userId)";
            } else if (isResourceOwner) {
                grantWhere += " AND ag.resource_id IN (SELECT resource_id FROM dbo.resource_owners WHERE owner_user_id = @userId)";
                reqWhere += " AND ar.resource_id IN (SELECT resource_id FROM dbo.resource_owners WHERE owner_user_id = @userId)";
                appWhere += " AND asp.assigned_approver_user_id = @userId";
                findingWhere += " AND ag.resource_id IN (SELECT resource_id FROM dbo.resource_owners WHERE owner_user_id = @userId)";
                revWhere += " AND rj.grant_id IN (SELECT grant_id FROM dbo.access_grants WHERE resource_id IN (SELECT resource_id FROM dbo.resource_owners WHERE owner_user_id = @userId))";
                reviewWhere += " AND arw.review_id IN (SELECT review_id FROM dbo.review_items WHERE reviewer_user_id = @userId)";
            }
        }

        const metricsQuery = `
            -- 1. Engagements
            SELECT COUNT(*) AS active_engagements
            FROM dbo.contractor_engagements ce
            WHERE ${engWhere};

            -- 2. Grants
            SELECT
                COUNT(*) AS total_active_grants,
                SUM(CASE WHEN ag.expires_at <= DATEADD(DAY, 7, TODATETIMEOFFSET(SYSUTCDATETIME(), '+00:00')) THEN 1 ELSE 0 END) AS expiring_soon_7d
            FROM dbo.access_grants ag
            WHERE ${grantWhere};

            -- 3. Access Requests
            SELECT COUNT(*) AS pending_requests
            FROM dbo.access_requests ar
            WHERE ${reqWhere};

            -- 4. Approvals
            SELECT COUNT(*) AS pending_approvals
            FROM dbo.approval_steps asp
            WHERE ${appWhere};

            -- 5. Orphan Access Findings
            SELECT
                COUNT(*) AS total_open_findings,
                SUM(CASE WHEN oaf.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_findings,
                SUM(CASE WHEN oaf.severity = 'HIGH' THEN 1 ELSE 0 END) AS high_findings,
                SUM(CASE WHEN oaf.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_findings,
                SUM(CASE WHEN oaf.severity = 'LOW' THEN 1 ELSE 0 END) AS low_findings
            FROM dbo.orphan_access_findings oaf
            INNER JOIN dbo.access_grants ag ON oaf.grant_id = ag.grant_id
            WHERE ${findingWhere};

            -- 6. Revocations
            SELECT
                SUM(CASE WHEN rj.status IN ('QUEUED', 'PROCESSING') THEN 1 ELSE 0 END) AS pending_revocations,
                SUM(CASE WHEN rj.status = 'MANUAL_REVIEW_REQUIRED' THEN 1 ELSE 0 END) AS manual_review_revocations,
                SUM(CASE WHEN rj.status IN ('FAILED_RETRY', 'PERMANENT_FAILURE') THEN 1 ELSE 0 END) AS failed_revocations,
                SUM(CASE WHEN rj.status IN ('REVOKED', 'CONFIRMED') THEN 1 ELSE 0 END) AS confirmed_revocations
            FROM dbo.revocation_jobs rj
            WHERE ${revWhere};

            -- 7. Reviews
            SELECT
                SUM(CASE WHEN arw.status IN ('ACTIVE', 'IN_PROGRESS', 'DRAFT') THEN 1 ELSE 0 END) AS open_reviews,
                SUM(CASE WHEN arw.status = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_reviews
            FROM dbo.access_reviews arw
            WHERE ${reviewWhere};
        `;

        const result = await request.query(metricsQuery);

        const engRecord = result.recordsets[0][0] || {};
        const grantRecord = result.recordsets[1][0] || {};
        const reqRecord = result.recordsets[2][0] || {};
        const appRecord = result.recordsets[3][0] || {};
        const findingRecord = result.recordsets[4][0] || {};
        const revRecord = result.recordsets[5][0] || {};
        const reviewRecord = result.recordsets[6][0] || {};

        return {
            timestamp: new Date().toISOString(),
            scope: isGlobalGovernance ? 'GLOBAL_ENTERPRISE' : (isSponsor ? 'SPONSORED_SCOPE' : (isResourceOwner ? 'RESOURCE_SCOPE' : 'CONTRACTOR_SCOPE')),
            metrics: {
                activeContractorEngagements: engRecord.active_engagements || 0,
                activeAccessGrants: grantRecord.total_active_grants || 0,
                expiringGrantsSoon7d: grantRecord.expiring_soon_7d || 0,
                pendingAccessRequests: reqRecord.pending_requests || 0,
                pendingApprovals: appRecord.pending_approvals || 0,
                orphanFindings: {
                    totalOpen: findingRecord.total_open_findings || 0,
                    critical: findingRecord.critical_findings || 0,
                    high: findingRecord.high_findings || 0,
                    medium: findingRecord.medium_findings || 0,
                    low: findingRecord.low_findings || 0
                },
                revocations: {
                    pending: revRecord.pending_revocations || 0,
                    manualReview: revRecord.manual_review_revocations || 0,
                    failed: revRecord.failed_revocations || 0,
                    confirmed: revRecord.confirmed_revocations || 0
                },
                accessReviews: {
                    open: reviewRecord.open_reviews || 0,
                    completed: reviewRecord.completed_reviews || 0
                }
            }
        };
    } catch (err) {
        logger.error('Database query failed in getSecurityAnalyticsSummary', { userId: actorUser.user_id, error: err.message });
        throw new DatabaseError('Failed to retrieve security analytics summary.', err);
    }
}

module.exports = {
    getSecurityAnalyticsSummary
};
