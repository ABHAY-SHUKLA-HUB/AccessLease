/**
 * AccessLease — Access Request & Multi-Stage Approval Workflow Service
 * Enforces multi-stage routing, separation of duties, concurrency locks, state transitions, and audit trails.
 */

const sql = require('mssql');
const {
    requestRepository,
    resourceRepository,
    engagementRepository,
    userRepository,
    roleRepository,
    auditRepository
} = require('../repositories');
const policyEngine = require('./policyEngine');
const { withTransaction } = require('../config/database');
const Permissions = require('../security/permissions');
const { hasRole, hasAnyRole, hasPermission, hasAnyPermission, isStrictlyReadOnlyAuditor } = require('../security/permissionPolicy');
const {
    ValidationError,
    NotFoundError,
    ForbiddenError,
    ConflictError,
    AppError
} = require('../utils/errors');
const logger = require('../utils/logger');

class RequestWorkflowService {
    /**
     * Lists active catalogue resources available for requesting.
     * @param {object} user Authenticated user
     * @returns {Promise<Array<object>>}
     */
    async listCatalogResources(user) {
        if (!user) throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
        return await resourceRepository.listResources({ isActive: true, limit: 100 });
    }

    /**
     * Lists active entitlements belonging to a specific resource.
     * @param {object} user Authenticated user
     * @param {string} resourceId GUID
     * @returns {Promise<Array<object>>}
     */
    async listResourceEntitlements(user, resourceId) {
        if (!user) throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
        if (!resourceId) throw new ValidationError('Resource ID is required.');

        const resource = await resourceRepository.findResourceById(resourceId);
        if (!resource || !resource.is_active) {
            throw new NotFoundError('Resource');
        }

        const entitlements = await resourceRepository.listEntitlementsByResourceId(resourceId);
        return entitlements.filter(e => e.is_active);
    }

    /**
     * Creates an access request for an authenticated contractor.
     * Evaluates security policy, derives required approval stages, and resolves approvers.
     * 
     * @param {object} user Authenticated user context
     * @param {object} data Input data { contractorEngagementId, resourceId, entitlementId, requestedStartDate, requestedEndDate, businessJustification }
     * @param {object} [options={}] Additional context (ipAddress)
     * @returns {Promise<object>} Created access request with approval steps
     */
    async createAccessRequest(user, data, options = {}) {
        if (!user) throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');

        const {
            contractorEngagementId,
            contractorUserId,
            resourceId,
            entitlementId,
            requestedStartDate,
            requestedEndDate,
            businessJustification
        } = data || {};

        // Role authorization check:
        // 1) Active CONTRACTOR submitting self-service request.
        // 2) INTERNAL_SPONSOR or SYSTEM_ADMIN submitting on behalf of a contractor (with engagement specified).
        const isContractor = user.user_type === 'CONTRACTOR' || hasRole(user.roles, 'CONTRACTOR');
        const canManageRequests = hasRole(user.roles, 'INTERNAL_SPONSOR') || hasRole(user.roles, 'SYSTEM_ADMIN');

        if (!isContractor) {
            if (!canManageRequests || (!contractorEngagementId && !contractorUserId)) {
                throw new ForbiddenError(
                    'Access denied: Only users classified as CONTRACTOR can submit contractor access requests.',
                    'ERR_FORBIDDEN_NOT_CONTRACTOR'
                );
            }
        }

        if (!user.is_active) {
            throw new ForbiddenError('Access denied: Contractor account is deactivated.', 'ERR_USER_INACTIVE');
        }

        if (!resourceId) throw new ValidationError('Resource ID is required.');
        if (!entitlementId) throw new ValidationError('Entitlement ID is required.');

        // 1. Resolve Contractor Engagement in Real Database
        let engagement = null;
        if (contractorEngagementId) {
            engagement = await engagementRepository.findEngagementById(contractorEngagementId);
            if (!engagement) {
                throw new ValidationError('Specified engagement does not exist.');
            }
            if (isContractor && engagement.contractor_user_id.toLowerCase() !== user.user_id.toLowerCase()) {
                throw new ValidationError('Specified engagement does not belong to the authenticated contractor.');
            }
        } else if (contractorUserId) {
            const activeEngagements = await engagementRepository.findEngagementsByContractorId(contractorUserId);
            engagement = activeEngagements.find(e => e.status === 'ACTIVE');
        } else {
            // Find active engagement for this contractor
            const activeEngagements = await engagementRepository.findEngagementsByContractorId(user.user_id);
            engagement = activeEngagements.find(e => e.status === 'ACTIVE');
        }

        if (!engagement || engagement.status !== 'ACTIVE') {
            throw new ValidationError(
                'No active engagement found for contractor. An active engagement is mandatory to request access.',
                [],
                'ERR_NO_ACTIVE_ENGAGEMENT'
            );
        }

        const targetContractorUserId = engagement.contractor_user_id;
        const targetContractor = await userRepository.findUserById(targetContractorUserId);
        if (!targetContractor || !targetContractor.is_active) {
            throw new ForbiddenError('Access denied: Contractor account is deactivated.', 'ERR_USER_INACTIVE');
        }

        // 2. Resolve Resource and Entitlement in Real Database
        const [resource, entitlement] = await Promise.all([
            resourceRepository.findResourceById(resourceId),
            resourceRepository.findEntitlementById(entitlementId)
        ]);

        if (!resource || !resource.is_active) {
            throw new NotFoundError('Resource');
        }

        if (!entitlement || !entitlement.is_active || entitlement.resource_id.toLowerCase() !== resource.resource_id.toLowerCase()) {
            throw new ValidationError('Requested entitlement does not exist or does not belong to the selected resource.');
        }

        // 3. Evaluate Risk & Security Policy Engine
        const policyOutcome = policyEngine.evaluatePolicy({
            resource,
            entitlement,
            engagement,
            requestedStartDate,
            requestedEndDate,
            justification: businessJustification
        });

        // 4. Resolve Mandatory Approvers with Strict Separation of Duties (SoD)
        // Stage 1 Approver: Internal Sponsor from engagement
        const sponsorUserId = engagement.sponsor_user_id;
        const sponsorUser = await userRepository.findUserById(sponsorUserId);
        if (!sponsorUser || !sponsorUser.is_active) {
            throw new ValidationError('Assigned business sponsor account is invalid or inactive.', [], 'ERR_MISSING_MANDATORY_APPROVER');
        }

        // SoD Check: Requester cannot be sponsor
        if (sponsorUserId.toLowerCase() === targetContractorUserId.toLowerCase()) {
            throw new ForbiddenError('Separation of Duties violation: Requester cannot sponsor their own engagement.', 'ERR_SELF_APPROVAL_FORBIDDEN');
        }

        // Stage 2 Approver: Resource Owner from dbo.resource_owners
        // SoD Check: Must be an independent individual (neither requester nor business sponsor)
        const owners = await resourceRepository.getResourceOwners(resource.resource_id);
        const eligibleOwner = owners.find(o =>
            o.owner_user_id.toLowerCase() !== targetContractorUserId.toLowerCase() &&
            o.owner_user_id.toLowerCase() !== sponsorUserId.toLowerCase()
        );

        if (!eligibleOwner) {
            if (owners.some(o => o.owner_user_id.toLowerCase() === sponsorUserId.toLowerCase())) {
                throw new ForbiddenError(
                    'Separation of Duties violation: The business sponsor cannot also serve as the resource owner for this access request. Independent multi-stage approval is required.',
                    'ERR_DUAL_APPROVAL_FORBIDDEN'
                );
            }
            throw new ValidationError(
                `No eligible independent Resource Owner configured for resource '${resource.resource_code}'. Requests cannot proceed without an independent designated system owner.`,
                [],
                'ERR_MISSING_MANDATORY_APPROVER'
            );
        }

        // Stage 3 Approver: Security Officer (if policy indicates high-risk)
        // SoD Check: Must be an independent Security Officer (not requester, not sponsor, not resource owner)
        let securityOfficerUserId = null;
        if (policyOutcome.requiresSecurityApproval) {
            const securityRole = await roleRepository.findRoleByCode('SECURITY_OFFICER');
            let secUser = null;

            if (securityRole) {
                const runner = await require('../config/database').getPool();
                const secUsersResult = await runner.request()
                    .input('roleId', securityRole.role_id)
                    .query(`
                        SELECT u.user_id, u.is_active
                        FROM dbo.user_roles ur
                        INNER JOIN dbo.users u ON ur.user_id = u.user_id
                        WHERE ur.role_id = @roleId AND u.is_active = 1;
                    `);

                secUser = secUsersResult.recordset.find(su =>
                    su.user_id.toLowerCase() !== targetContractorUserId.toLowerCase() &&
                    su.user_id.toLowerCase() !== sponsorUserId.toLowerCase() &&
                    su.user_id.toLowerCase() !== eligibleOwner.owner_user_id.toLowerCase()
                );
            }

            if (!secUser) {
                throw new ValidationError(
                    'No eligible independent Security Officer available for high-risk approval. Security sign-off must be performed by an independent Security Officer.',
                    [],
                    'ERR_MISSING_MANDATORY_APPROVER'
                );
            }

            securityOfficerUserId = secUser.user_id;
        }

        // 5. Execute Request Creation Atomically with Concurrency Control & Audit
        return await withTransaction(async (transaction) => {
            // Concurrency Guard: Enforce single active request under exclusive table/range lock
            const activeExisting = await requestRepository.findActiveRequest(
                engagement.engagement_id,
                resource.resource_id,
                entitlement.entitlement_id,
                transaction
            );

            if (activeExisting) {
                throw new ConflictError(
                    `An active access request (${activeExisting.request_number}) is already pending review for this entitlement. Duplicate requests are prohibited.`,
                    'ERR_DUPLICATE_ACTIVE_REQUEST'
                );
            }

            const requestNumber = await requestRepository.generateNextRequestNumber(transaction);

            const createdRequest = await requestRepository.createAccessRequest({
                requestNumber,
                contractorEngagementId: engagement.engagement_id,
                requestedByUserId: targetContractorUserId,
                resourceId: resource.resource_id,
                entitlementId: entitlement.entitlement_id,
                requestedStartDate: new Date(requestedStartDate),
                requestedEndDate: new Date(requestedEndDate),
                businessJustification: businessJustification.trim(),
                status: 'PENDING_APPROVAL',
                requiresSecurityApproval: policyOutcome.requiresSecurityApproval
            }, transaction);

            // Create Stage 1 Step: Sponsor
            const step1 = await requestRepository.createApprovalStep({
                requestId: createdRequest.request_id,
                stepNumber: 1,
                stepType: 'SPONSOR_APPROVAL',
                assignedApproverUserId: sponsorUserId,
                status: 'PENDING'
            }, transaction);

            // Create Stage 2 Step: Resource Owner
            const step2 = await requestRepository.createApprovalStep({
                requestId: createdRequest.request_id,
                stepNumber: 2,
                stepType: 'RESOURCE_OWNER_APPROVAL',
                assignedApproverUserId: eligibleOwner.owner_user_id,
                status: 'PENDING'
            }, transaction);

            // Create Stage 3 Step: Security Officer (if required)
            let step3 = null;
            if (policyOutcome.requiresSecurityApproval && securityOfficerUserId) {
                step3 = await requestRepository.createApprovalStep({
                    requestId: createdRequest.request_id,
                    stepNumber: 3,
                    stepType: 'SECURITY_APPROVAL',
                    assignedApproverUserId: securityOfficerUserId,
                    status: 'PENDING'
                }, transaction);
            }

            // Record Immutable Audit Event
            await auditRepository.createAuditEvent({
                eventCategory: 'ACCESS_REQUEST',
                eventAction: 'REQUEST_CREATED',
                entityType: 'access_requests',
                entityId: createdRequest.request_id,
                actorUserId: user.user_id,
                actorType: 'USER',
                eventPayload: {
                    request_number: requestNumber,
                    contractor_user_id: targetContractorUserId,
                    contractor_name: targetContractor.display_name,
                    submitted_by_user_id: user.user_id,
                    contractor_engagement_id: engagement.engagement_id,
                    resource_code: resource.resource_code,
                    entitlement_code: entitlement.entitlement_code,
                    requested_start_date: requestedStartDate,
                    requested_end_date: requestedEndDate,
                    duration_days: policyOutcome.durationDays,
                    evaluated_risk: policyOutcome.evaluatedRiskLevel,
                    requires_security_approval: policyOutcome.requiresSecurityApproval,
                    policy_reasons: policyOutcome.reasons,
                    stages: [
                        { step_number: 1, type: 'SPONSOR_APPROVAL', approver_user_id: sponsorUserId },
                        { step_number: 2, type: 'RESOURCE_OWNER_APPROVAL', approver_user_id: eligibleOwner.owner_user_id },
                        ...(step3 ? [{ step_number: 3, type: 'SECURITY_APPROVAL', approver_user_id: securityOfficerUserId }] : [])
                    ]
                },
                ipAddress: options.ipAddress || null
            }, transaction);

            logger.info('Access request successfully created with multi-stage workflow', {
                requestId: createdRequest.request_id,
                requestNumber,
                requiresSecurityApproval: policyOutcome.requiresSecurityApproval,
                actorUserId: user.user_id
            });

            const steps = [step1, step2];
            if (step3) steps.push(step3);

            return {
                ...createdRequest,
                policy: policyOutcome,
                approval_steps: steps
            };
        });
    }

    /**
     * Submits an approval decision (APPROVE or REJECT) on an approval step.
     * Enforces sequential execution, optimistic row concurrency locks, SoD, and audit logging.
     * 
     * @param {object} user Authenticated approver
     * @param {string} stepId GUID of the approval step
     * @param {string} decision 'APPROVE' or 'REJECT'
     * @param {string} [comments=''] Decision notes / justification
     * @param {object} [options={}] Additional context (ipAddress)
     * @returns {Promise<object>} Updated request and step
     */
    async submitApprovalDecision(user, stepId, decision, comments = '', options = {}) {
        if (!user || !stepId) throw new ValidationError('Step ID and decision are required.');

        // Compliance Auditors are strictly read-only and cannot mutate workflow state
        if (isStrictlyReadOnlyAuditor(user.roles)) {
            throw new ForbiddenError(
                'Compliance auditors hold strictly read-only oversight permissions and cannot approve or reject access requests.',
                'ERR_AUDITOR_READ_ONLY'
            );
        }

        const cleanDecision = (decision || '').trim().toUpperCase();
        if (!['APPROVE', 'REJECT'].includes(cleanDecision)) {
            throw new ValidationError("Invalid decision: must be either 'APPROVE' or 'REJECT'.");
        }

        if (cleanDecision === 'REJECT' && (!comments || comments.trim().length < 5)) {
            throw new ValidationError('A rejection justification of at least 5 characters is mandatory for audit accountability.');
        }

        // Execute atomically with exclusive concurrency locks on request & step
        const result = await withTransaction(async (transaction) => {
            // Lock the step
            const step = await requestRepository.findApprovalStepByIdForUpdate(stepId, transaction);
            if (!step) {
                throw new NotFoundError('Approval Step');
            }

            // Lock the parent request
            const request = await requestRepository.findRequestByIdForUpdate(step.request_id, transaction);
            if (!request) {
                throw new NotFoundError('Access Request');
            }

            // Guardrail 1: Request must be PENDING_APPROVAL
            if (request.status !== 'PENDING_APPROVAL') {
                throw new ValidationError(
                    `Cannot decide step: Access request is in status '${request.status}' and is no longer pending approval.`,
                    [],
                    'ERR_REQUEST_NOT_PENDING'
                );
            }

            // Guardrail 2: Step must be PENDING (idempotency check)
            if (step.status !== 'PENDING') {
                throw new ValidationError(
                    `This approval step has already been resolved with status '${step.status}'. Duplicate submissions are rejected.`,
                    [],
                    'ERR_STEP_ALREADY_DECIDED'
                );
            }

            // Guardrail 3: Out-of-Order Approval Prevention
            // All prior steps (step_number < this.step_number) MUST be APPROVED
            const allSteps = await requestRepository.getApprovalSteps(request.request_id, transaction);
            const priorUnapproved = allSteps.find(s => s.step_number < step.step_number && s.status !== 'APPROVED');

            if (priorUnapproved) {
                throw new ValidationError(
                    `Cannot process Step ${step.step_number} (${step.step_type}): Prerequisite Step ${priorUnapproved.step_number} (${priorUnapproved.step_type}) has not been approved.`,
                    [],
                    'ERR_OUT_OF_ORDER_APPROVAL'
                );
            }

            // Guardrail 4: Separation of Duties (SoD)
            // A requester MUST NEVER approve their own access request under any circumstance
            if (request.requested_by_user_id.toLowerCase() === user.user_id.toLowerCase()) {
                // Record security audit event outside the failing transaction so it is permanently logged
                await auditRepository.createAuditEvent({
                    eventCategory: 'APPROVAL',
                    eventAction: 'SOD_VIOLATION_BLOCKED',
                    entityType: 'access_requests',
                    entityId: request.request_id,
                    actorUserId: user.user_id,
                    actorType: 'USER',
                    eventPayload: {
                        attempted_action: 'SELF_APPROVAL',
                        step_id: step.approval_step_id,
                        step_number: step.step_number
                    },
                    ipAddress: options.ipAddress || null
                });

                throw new ForbiddenError(
                    'Separation of Duties violation: The creator of an access request cannot approve it.',
                    'ERR_SELF_APPROVAL_FORBIDDEN'
                );
            }

            // Guardrail 4b: Dual-Stage SoD Enforcement
            // The same individual cannot unintentionally satisfy multiple mandatory approval stages
            const priorDecidersResult = await transaction.request()
                .input('requestId', sql.UniqueIdentifier, request.request_id)
                .query(`
                    SELECT actor_user_id
                    FROM dbo.audit_events
                    WHERE entity_id = @requestId
                      AND event_category = 'APPROVAL'
                      AND event_action IN ('STEP_APPROVED', 'REQUEST_APPROVED');
                `);

            const hasApprovedPriorStage = priorDecidersResult.recordset.some(
                r => r.actor_user_id && r.actor_user_id.toLowerCase() === user.user_id.toLowerCase()
            );

            if (hasApprovedPriorStage) {
                await auditRepository.createAuditEvent({
                    eventCategory: 'APPROVAL',
                    eventAction: 'SOD_VIOLATION_BLOCKED',
                    entityType: 'access_requests',
                    entityId: request.request_id,
                    actorUserId: user.user_id,
                    actorType: 'USER',
                    eventPayload: {
                        attempted_action: 'DUAL_STAGE_APPROVAL',
                        step_id: step.approval_step_id,
                        step_number: step.step_number
                    },
                    ipAddress: options.ipAddress || null
                });

                throw new ForbiddenError(
                    'Separation of Duties violation: An individual who approved a prior stage cannot satisfy subsequent approval stages on the same request.',
                    'ERR_DUAL_APPROVAL_FORBIDDEN'
                );
            }

            // Guardrail 5: Mandatory Role Verification at Time-of-Decision (No Administrator Bypass)
            const isAssigned = step.assigned_approver_user_id.toLowerCase() === user.user_id.toLowerCase();

            if (step.step_type === 'SECURITY_APPROVAL') {
                // Security Officer approval MUST be performed by an account with the SECURITY_OFFICER role
                if (!hasRole(user.roles, 'SECURITY_OFFICER')) {
                    throw new ForbiddenError(
                        'Access denied: Step requires a verified SECURITY_OFFICER role. System Administrator privileges cannot bypass mandatory security officer approvals.',
                        'ERR_FORBIDDEN_ROLE'
                    );
                }
            } else if (step.step_type === 'RESOURCE_OWNER_APPROVAL') {
                // Resource Owner approval MUST be performed by a verified owner of the resource in dbo.resource_owners
                const isOwner = await require('../security/resourceAccess').isAuthorizedResourceOwner(user, request.resource_id, transaction);
                if (!isOwner && !isAssigned) {
                    throw new ForbiddenError(
                        'Access denied: You are not an authorized resource owner for this resource in dbo.resource_owners. System Administrator privileges cannot bypass resource owner approvals.',
                        'ERR_NOT_RESOURCE_OWNER'
                    );
                }
            } else if (step.step_type === 'SPONSOR_APPROVAL') {
                const isSponsor = isAssigned || (user.user_id && request.contractor_engagement_id && await (async () => {
                    const eng = await engagementRepository.findEngagementById(request.contractor_engagement_id, transaction);
                    return eng && eng.sponsor_user_id.toLowerCase() === user.user_id.toLowerCase();
                })());

                if (!isSponsor && !hasRole(user.roles, 'SYSTEM_ADMIN')) {
                    throw new ForbiddenError(
                        'Access denied: You are not the designated internal business sponsor for this contractor engagement.',
                        'ERR_UNAUTHORIZED_APPROVER'
                    );
                }
            }

            // -----------------------------------------------------------------
            // Process Decision
            // -----------------------------------------------------------------
            const decidedAt = new Date();
            let newRequestStatus = request.status;

            if (cleanDecision === 'APPROVE') {
                // 1. Update this step to APPROVED
                const updatedStep = await requestRepository.updateApprovalStep(
                    step.approval_step_id,
                    {
                        status: 'APPROVED',
                        decisionComments: comments ? comments.trim() : null,
                        decidedAt
                    },
                    transaction
                );

                // 2. Check if this is the final step
                const remainingPending = allSteps.filter(s => s.step_number > step.step_number);

                if (remainingPending.length === 0) {
                    // Final stage reached: request becomes APPROVED
                    newRequestStatus = 'APPROVED';
                    await requestRepository.updateRequestStatus(request.request_id, 'APPROVED', transaction);
                }

                // Record Audit Event
                await auditRepository.createAuditEvent({
                    eventCategory: 'APPROVAL',
                    eventAction: newRequestStatus === 'APPROVED' ? 'REQUEST_APPROVED' : 'STEP_APPROVED',
                    entityType: 'access_requests',
                    entityId: request.request_id,
                    actorUserId: user.user_id,
                    actorType: 'USER',
                    eventPayload: {
                        step_id: step.approval_step_id,
                        step_number: step.step_number,
                        step_type: step.step_type,
                        decision: 'APPROVED',
                        comments: comments || null,
                        final_request_status: newRequestStatus
                    },
                    ipAddress: options.ipAddress || null
                }, transaction);

                return {
                    request_id: request.request_id,
                    request_number: request.request_number,
                    request_status: newRequestStatus,
                    step: updatedStep
                };

            } else {
                // Decision is REJECT
                // 1. Update this step to REJECTED
                const updatedStep = await requestRepository.updateApprovalStep(
                    step.approval_step_id,
                    {
                        status: 'REJECTED',
                        decisionComments: comments.trim(),
                        decidedAt
                    },
                    transaction
                );

                // 2. Skip any subsequent pending steps
                await requestRepository.skipRemainingSteps(request.request_id, step.step_number, transaction);

                // 3. Mark request as REJECTED
                await requestRepository.updateRequestStatus(request.request_id, 'REJECTED', transaction);

                // Record Audit Event
                await auditRepository.createAuditEvent({
                    eventCategory: 'APPROVAL',
                    eventAction: 'REQUEST_REJECTED',
                    entityType: 'access_requests',
                    entityId: request.request_id,
                    actorUserId: user.user_id,
                    actorType: 'USER',
                    eventPayload: {
                        step_id: step.approval_step_id,
                        step_number: step.step_number,
                        step_type: step.step_type,
                        decision: 'REJECTED',
                        reason: comments.trim(),
                        final_request_status: 'REJECTED'
                    },
                    ipAddress: options.ipAddress || null
                }, transaction);

                return {
                    request_id: request.request_id,
                    request_number: request.request_number,
                    request_status: 'REJECTED',
                    step: updatedStep
                };
            }
        });

        // If request became fully APPROVED, automatically initiate durable provisioning if mapped
        if (result && result.request_status === 'APPROVED') {
            let provisioned = false;
            try {
                const provisioningService = require('./provisioningService');
                await provisioningService.createProvisioningOperation(result.request_id, user, options);
                provisioned = true;
            } catch (provErr) {
                logger.info('Automatic provisioning initiation outcome after approval', {
                    requestId: result.request_id,
                    info: provErr.message
                });
            }

            // If no automated connector exists or provisioning was not applicable, activate approved grant directly
            if (!provisioned) {
                try {
                    const grantRepository = require('../repositories/grantRepository');
                    const activated = await grantRepository.activateApprovedGrant(result.request_id, user.user_id);
                    logger.info('Grant activated via dbo.sp_ActivateApprovedGrant', {
                        requestId: result.request_id,
                        grantId: activated.grantId,
                        grantNumber: activated.grantNumber
                    });
                } catch (actErr) {
                    logger.error('Failed to activate grant via sp_ActivateApprovedGrant after approval', {
                        requestId: result.request_id,
                        error: actErr.message
                    });
                }
            }
        }

        return result;
    }

    /**
     * Cancels an access request by the requester.
     * @param {object} user Authenticated requester
     * @param {string} requestId GUID
     * @param {string} [reason=''] Cancellation justification
     * @param {object} [options={}]
     * @returns {Promise<object>}
     */
    async cancelAccessRequest(user, requestId, reason = '', options = {}) {
        if (!user || !requestId) throw new ValidationError('Request ID is required.');

        return await withTransaction(async (transaction) => {
            const request = await requestRepository.findRequestByIdForUpdate(requestId, transaction);
            if (!request) {
                throw new NotFoundError('Access Request');
            }

            const isOwner = request.requested_by_user_id.toLowerCase() === user.user_id.toLowerCase();
            const isAdmin = hasRole(user.roles, 'SYSTEM_ADMIN');

            if (!isOwner && !isAdmin) {
                throw new ForbiddenError(
                    'Access denied: You can only cancel your own access requests.',
                    'ERR_FORBIDDEN_CANCEL_REQUEST'
                );
            }

            if (!['SUBMITTED', 'PENDING_APPROVAL'].includes(request.status)) {
                throw new ValidationError(
                    `Cannot cancel access request: Request is already resolved with status '${request.status}'.`,
                    [],
                    'ERR_REQUEST_ALREADY_RESOLVED'
                );
            }

            await requestRepository.updateRequestStatus(request.request_id, 'CANCELLED', transaction);
            await requestRepository.skipRemainingSteps(request.request_id, 0, transaction);

            await auditRepository.createAuditEvent({
                eventCategory: 'ACCESS_REQUEST',
                eventAction: 'REQUEST_CANCELLED',
                entityType: 'access_requests',
                entityId: request.request_id,
                actorUserId: user.user_id,
                actorType: 'USER',
                eventPayload: {
                    request_number: request.request_number,
                    reason: reason ? reason.trim() : 'Cancelled by requester'
                },
                ipAddress: options.ipAddress || null
            }, transaction);

            return {
                request_id: request.request_id,
                request_number: request.request_number,
                status: 'CANCELLED'
            };
        });
    }

    /**
     * Lists currently actionable approval tasks assigned to the authenticated approver.
     * @param {object} user Authenticated approver
     * @returns {Promise<Array<object>>}
     */
    async listPendingApprovals(user) {
        if (!user) throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');

        const isSystemAdmin = hasRole(user.roles, 'SYSTEM_ADMIN');
        const isSecurityOfficer = hasRole(user.roles, 'SECURITY_OFFICER');

        return await requestRepository.listActionablePendingSteps(
            user.user_id,
            { isSystemAdmin, isSecurityOfficer }
        );
    }

    /**
     * Lists access requests with role-based scoping and data isolation.
     * @param {object} user Authenticated user
     * @param {object} [filter={}] { status, limit, offset }
     * @returns {Promise<Array<object>>}
     */
    async listRequests(user, filter = {}) {
        if (!user) throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
        if (!user.is_active) throw new ForbiddenError('Access denied: Account is deactivated.', 'ERR_USER_INACTIVE');

        const isContractor = hasRole(user.roles, 'CONTRACTOR') && !hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'INTERNAL_SPONSOR', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR']);

        const queryFilter = {
            ...filter,
            requestedByUserId: isContractor ? user.user_id : filter.requestedByUserId,
            scopedUser: user
        };

        return await requestRepository.listRequests(queryFilter);
    }

    /**
     * Retrieves full details of an access request with strict contextual authorization and IDOR prevention.
     * @param {object} user Authenticated user
     * @param {string} requestId GUID
     * @returns {Promise<object>}
     */
    async getRequestDetails(user, requestId) {
        if (!user || !requestId) throw new ValidationError('Request ID is required.');
        if (!user.is_active) throw new ForbiddenError('Access denied: Account is deactivated.', 'ERR_USER_INACTIVE');

        const request = await requestRepository.findRequestById(requestId);
        if (!request) {
            throw new NotFoundError('Access Request');
        }

        const isAdmin = hasRole(user.roles, 'SYSTEM_ADMIN');
        const isAuditor = hasRole(user.roles, 'COMPLIANCE_AUDITOR');
        const isRequester = request.requested_by_user_id.toLowerCase() === user.user_id.toLowerCase();

        let isAuthorized = isAdmin || isAuditor || isRequester;

        // Contextual sponsorship verification
        if (!isAuthorized && hasRole(user.roles, 'INTERNAL_SPONSOR')) {
            const engagement = await engagementRepository.findEngagementById(request.contractor_engagement_id);
            if (engagement && engagement.sponsor_user_id.toLowerCase() === user.user_id.toLowerCase()) {
                isAuthorized = true;
            }
        }

        // Contextual resource ownership verification
        if (!isAuthorized && hasRole(user.roles, 'RESOURCE_OWNER')) {
            const isOwner = await require('../security/resourceAccess').isAuthorizedResourceOwner(user, request.resource_id);
            if (isOwner) {
                isAuthorized = true;
            }
        }

        // Contextual security officer verification (only for requests requiring security review)
        if (!isAuthorized && hasRole(user.roles, 'SECURITY_OFFICER') && request.requires_security_approval) {
            isAuthorized = true;
        }

        const steps = await requestRepository.getApprovalSteps(request.request_id);

        // Assigned approver verification
        if (!isAuthorized && steps.some(s => s.assigned_approver_user_id.toLowerCase() === user.user_id.toLowerCase())) {
            isAuthorized = true;
        }

        // IDOR Prevention: Deny all unassociated users
        if (!isAuthorized) {
            throw new ForbiddenError(
                'Access denied: You are not authorized to view this contractor access request.',
                'ERR_FORBIDDEN_REQUEST_ACCESS'
            );
        }

        return {
            ...request,
            approval_steps: steps
        };
    }
}

module.exports = new RequestWorkflowService();
