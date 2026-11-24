/**
 * AccessLease — Risk & Policy Evaluation Engine
 * Evaluates request risk, enforces enterprise governance guardrails, and determines approval routing.
 */

const { ValidationError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Ordered Risk Priority Hierarchy.
 */
const RISK_HIERARCHY = Object.freeze({
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4
});

/**
 * Converts date or ISO string to UTC date string (YYYY-MM-DD).
 * @param {string|Date} dateVal 
 * @returns {string}
 */
function toDateStr(dateVal) {
    if (!dateVal) return '';
    const d = new Date(dateVal);
    if (isNaN(d.getTime())) return '';
    return d.toISOString().split('T')[0];
}

class PolicyEngine {
    /**
     * Evaluates access request against enterprise security policies and derives approval stages.
     * 
     * @param {object} params
     * @param {object} params.resource Resource record
     * @param {object} params.entitlement Entitlement record
     * @param {object} params.engagement Contractor engagement record
     * @param {string|Date} params.requestedStartDate
     * @param {string|Date} params.requestedEndDate
     * @param {string} params.justification Business justification text
     * @returns {object} Deterministic policy evaluation result
     */
    evaluatePolicy(params) {
        const {
            resource,
            entitlement,
            engagement,
            requestedStartDate,
            requestedEndDate,
            justification
        } = params;

        const validationErrors = [];
        const policyReasons = [];

        // 1. Validate Resource & Entitlement Active State
        if (!resource || !resource.is_active) {
            validationErrors.push('Requested resource does not exist or is currently inactive.');
        }

        if (!entitlement || !entitlement.is_active) {
            validationErrors.push('Requested entitlement does not exist or is currently inactive.');
        } else if (resource && entitlement.resource_id && entitlement.resource_id.toLowerCase() !== resource.resource_id.toLowerCase()) {
            validationErrors.push('Requested entitlement does not belong to the selected resource.');
        }

        // 2. Validate Contractor Engagement Active State
        if (!engagement) {
            validationErrors.push('No valid contractor engagement found.');
        } else {
            if (engagement.status !== 'ACTIVE') {
                validationErrors.push(`Contractor engagement is not active (current status: ${engagement.status}).`);
            }

            const todayStr = toDateStr(new Date());
            const engagementStartStr = toDateStr(engagement.start_date);
            const engagementEndStr = toDateStr(engagement.end_date);

            if (engagementEndStr < todayStr) {
                validationErrors.push(`Contractor engagement expired on ${engagementEndStr}. New access cannot be requested.`);
            }
        }

        // 3. Validate Date Boundaries & Prohibit Permanent Access
        if (!requestedStartDate) {
            validationErrors.push('Requested start date is required.');
        }
        if (!requestedEndDate) {
            validationErrors.push('Requested end date is required. Permanent contractor access is strictly prohibited.');
        }

        let durationDays = 0;
        if (requestedStartDate && requestedEndDate) {
            const reqStartStr = toDateStr(requestedStartDate);
            const reqEndStr = toDateStr(requestedEndDate);
            const todayStr = toDateStr(new Date());

            if (!reqStartStr || !reqEndStr) {
                validationErrors.push('Requested dates must be valid ISO date strings.');
            } else if (reqEndStr <= reqStartStr) {
                validationErrors.push('Requested end date must be strictly after the requested start date.');
            } else {
                if (reqStartStr < todayStr) {
                    validationErrors.push('Requested start date cannot be in the past.');
                }

                // Strict calendar-day duration calculation with UTC date-only semantics
                const sDate = new Date(reqStartStr + 'T00:00:00Z');
                const eDate = new Date(reqEndStr + 'T00:00:00Z');
                durationDays = Math.round((eDate - sDate) / (1000 * 60 * 60 * 24));

                // Guardrail: Max Lease Duration on Resource
                if (resource && resource.max_lease_duration_days && durationDays > resource.max_lease_duration_days) {
                    validationErrors.push(
                        `Requested duration of ${durationDays} days exceeds maximum allowable lease of ${resource.max_lease_duration_days} days for this resource.`
                    );
                }

                // Guardrail: End Date Cannot Exceed Contractor Engagement End Date
                if (engagement) {
                    const engEndStr = toDateStr(engagement.end_date);
                    if (reqEndStr > engEndStr) {
                        validationErrors.push(
                            `Requested access expiry (${reqEndStr}) exceeds the contractor engagement end date (${engEndStr}).`
                        );
                    }
                }
            }
        }

        // 4. Validate Business Justification
        if (!justification || typeof justification !== 'string' || justification.trim().length < 10) {
            validationErrors.push('A meaningful business justification of at least 10 characters is mandatory.');
        } else if (justification.trim().length > 1000) {
            validationErrors.push('Business justification must not exceed 1000 characters.');
        }

        // If hard validation guardrails failed, throw structured ValidationError
        if (validationErrors.length > 0) {
            throw new ValidationError('Access request policy validation failed.', validationErrors);
        }

        // 5. Deterministic Risk Evaluation
        const resourceRisk = (resource.risk_level || 'MEDIUM').toUpperCase();
        const entitlementSensitivity = (entitlement.sensitivity_level || 'MEDIUM').toUpperCase();

        const resourceScore = RISK_HIERARCHY[resourceRisk] || 2;
        const entitlementScore = RISK_HIERARCHY[entitlementSensitivity] || 2;
        const maxScore = Math.max(resourceScore, entitlementScore);

        let evaluatedRiskLevel = 'MEDIUM';
        if (maxScore === 1) evaluatedRiskLevel = 'LOW';
        if (maxScore === 2) evaluatedRiskLevel = 'MEDIUM';
        if (maxScore === 3) evaluatedRiskLevel = 'HIGH';
        if (maxScore === 4) evaluatedRiskLevel = 'CRITICAL';

        // 6. Security Approval Triggers
        let requiresSecurityApproval = Boolean(resource.requires_security_approval);

        if (requiresSecurityApproval) {
            policyReasons.push(`Resource '${resource.resource_code}' explicitly requires Security Officer approval.`);
        }

        if (evaluatedRiskLevel === 'CRITICAL' || evaluatedRiskLevel === 'HIGH') {
            requiresSecurityApproval = true;
            policyReasons.push(
                `High-risk access classification (Resource Risk: ${resourceRisk}, Entitlement Sensitivity: ${entitlementSensitivity}) requires Security Officer approval.`
            );
        }

        // Duration escalation rule: duration > 60 days on Medium/High risk
        if (durationDays > 60 && evaluatedRiskLevel !== 'LOW') {
            requiresSecurityApproval = true;
            policyReasons.push(`Extended lease duration (${durationDays} days) triggers mandatory security review.`);
        }

        if (!requiresSecurityApproval) {
            policyReasons.push('Standard multi-stage governance: Requires Sponsor and Resource Owner approvals.');
        }

        // 7. Define Sequential Approval Stages
        const stages = [
            {
                stepNumber: 1,
                stepType: 'SPONSOR_APPROVAL',
                name: 'Internal Business Sponsor Approval',
                description: 'Verifies contractor business requirement and oversight endorsement.'
            },
            {
                stepNumber: 2,
                stepType: 'RESOURCE_OWNER_APPROVAL',
                name: 'Resource Owner Approval',
                description: 'Verifies system access justification, least-privilege boundary, and data classification.'
            }
        ];

        if (requiresSecurityApproval) {
            stages.push({
                stepNumber: 3,
                stepType: 'SECURITY_APPROVAL',
                name: 'Security Officer Approval',
                description: 'Verifies threat risk, elevated privilege justification, and compliance guardrails.'
            });
        }

        return {
            isPermitted: true,
            evaluatedRiskLevel,
            requiresSecurityApproval,
            durationDays,
            reasons: policyReasons,
            stages
        };
    }
}

module.exports = new PolicyEngine();
