/**
 * AccessLease — Contractor & Engagement Management Service
 * Enforces enterprise business rules, state transitions, ABAC, and audit trail persistence.
 */

const { randomUUID } = require('crypto');
const { userRepository, engagementRepository, auditRepository, grantRepository, revocationRepository, roleRepository } = require('../repositories');
const db = require('../config/database');
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

/**
 * Valid state transitions for contractor engagements.
 * Terminal states (COMPLETED, TERMINATED) have no outgoing transitions.
 */
const VALID_STATUS_TRANSITIONS = Object.freeze({
    PENDING: ['ACTIVE', 'TERMINATED'],
    ACTIVE: ['COMPLETED', 'TERMINATED'],
    COMPLETED: [],
    TERMINATED: []
});

/**
 * Validates ISO date string format (YYYY-MM-DD).
 * @param {string} dateStr 
 * @returns {boolean}
 */
function isValidDateString(dateStr) {
    if (!dateStr || typeof dateStr !== 'string') return false;
    const regex = /^\d{4}-\d{2}-\d{2}$/;
    if (!regex.test(dateStr)) return false;
    const d = new Date(dateStr + 'T00:00:00Z');
    return !isNaN(d.getTime());
}

/**
 * Strips time component for clean date-only comparison.
 * @param {string|Date} dateVal 
 * @returns {string} YYYY-MM-DD
 */
function toDateOnlyString(dateVal) {
    if (!dateVal) return '';
    const d = new Date(dateVal);
    if (isNaN(d.getTime())) return '';
    return d.toISOString().split('T')[0];
}

class ContractorService {
    /**
     * Registers a new external contractor directly into dbo.users.
     * Restricted strictly to SYSTEM_ADMIN.
     * Does NOT create Microsoft Entra ID users, credentials, or login invitations.
     * Newly registered contractors are immediately available for engagement creation.
     * 
     * @param {object} user Authenticated SYSTEM_ADMIN user context
     * @param {object} contractorData { display_name, email, company, contact_number }
     * @returns {Promise<{ contractor: object, status: string, message: string }>}
     */
    async createContractor(user, contractorData) {
        if (!user) {
            throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
        }

        // 1. Authorization: Only SYSTEM_ADMIN may register new contractors
        if (!hasRole(user.roles, 'SYSTEM_ADMIN')) {
            throw new ForbiddenError(
                'Access denied: Only System Administrators may register new contractors.',
                'ERR_FORBIDDEN_ROLE'
            );
        }

        if (!contractorData || typeof contractorData !== 'object') {
            throw new ValidationError('Contractor registration data is required.', [], 'ERR_INVALID_PAYLOAD');
        }

        // 2. Validate and normalize email
        const rawEmail = contractorData.email;
        if (!rawEmail || typeof rawEmail !== 'string' || !rawEmail.trim()) {
            throw new ValidationError('Email address is required.', [{ field: 'email', message: 'Email cannot be blank.' }], 'ERR_VALIDATION_FAILED');
        }
        const email = rawEmail.trim().toLowerCase();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email) || email.length > 256) {
            throw new ValidationError('A valid email address is required.', [{ field: 'email', message: 'Email address format is invalid.' }], 'ERR_INVALID_EMAIL');
        }

        // 3. Validate and parse full name
        const rawName = contractorData.display_name || contractorData.name || contractorData.full_name;
        if (!rawName || typeof rawName !== 'string' || !rawName.trim()) {
            throw new ValidationError('Contractor full name is required.', [{ field: 'display_name', message: 'Name cannot be blank.' }], 'ERR_CONTRACTOR_NAME_REQUIRED');
        }
        const displayName = rawName.trim();
        if (displayName.length < 2 || displayName.length > 128) {
            throw new ValidationError('Contractor full name must be between 2 and 128 characters.', [{ field: 'display_name', message: 'Name length invalid.' }], 'ERR_VALIDATION_FAILED');
        }

        // Parse first and last names (required by schema)
        const nameParts = displayName.split(/\s+/);
        let firstName, lastName;
        if (nameParts.length === 1) {
            firstName = nameParts[0];
            lastName = 'Contractor';
        } else {
            lastName = nameParts.pop();
            firstName = nameParts.join(' ');
        }
        firstName = firstName.substring(0, 64);
        lastName = lastName.substring(0, 64);

        // 4. Optional company / organization (persisted in existing department column: NVARCHAR(100))
        const rawCompany = contractorData.company || contractorData.organization || contractorData.department;
        const department = (typeof rawCompany === 'string' && rawCompany.trim()) ? rawCompany.trim().substring(0, 100) : null;

        // Note: contact_number is received but reported as unpersisted since dbo.users does not have a phone column
        const contactNumber = (typeof contractorData.contact_number === 'string' && contractorData.contact_number.trim()) ? contractorData.contact_number.trim() : null;

        // 5. Pre-check email uniqueness before opening transaction
        const existingUser = await userRepository.findUserByEmail(email);
        if (existingUser) {
            throw new ConflictError(`A user with email '${email}' is already registered.`, 'ERR_CONTRACTOR_EXISTS');
        }

        // 6. Execute atomic insertion inside transaction
        const syntheticOid = `LOCAL-CONTRACTOR-${randomUUID().toLowerCase()}`;

        const createdUser = await db.withTransaction(async (transaction) => {
            // Re-check inside transaction for concurrency safety
            const existingInTx = await userRepository.findUserByEmail(email, transaction);
            if (existingInTx) {
                throw new ConflictError(`A user with email '${email}' is already registered.`, 'ERR_CONTRACTOR_EXISTS');
            }

            const newUser = await userRepository.createUser({
                entraObjectId: syntheticOid,
                email,
                firstName,
                lastName,
                displayName,
                userType: 'CONTRACTOR',
                department,
                isActive: true
            }, transaction);

            // Assign CONTRACTOR role in dbo.user_roles if defined
            try {
                const contractorRole = await roleRepository.findRoleByCode('CONTRACTOR', transaction);
                if (contractorRole) {
                    await roleRepository.assignRoleToUser(newUser.user_id, contractorRole.role_id, user.user_id, transaction);
                }
            } catch (roleErr) {
                logger.warn('Could not assign CONTRACTOR role to registered contractor', {
                    userId: newUser.user_id,
                    error: roleErr.message
                });
            }

            // Record immutable audit event in dbo.audit_events
            try {
                await auditRepository.createAuditEvent({
                    eventCategory: 'SECURITY_POLICY',
                    eventAction: 'CONTRACTOR_REGISTERED',
                    entityType: 'USER',
                    entityId: newUser.user_id,
                    actorUserId: user.user_id,
                    actorType: 'USER',
                    eventPayload: {
                        userId: newUser.user_id,
                        email: newUser.email,
                        displayName: newUser.display_name,
                        department: newUser.department,
                        contactNumberProvided: !!contactNumber,
                        userType: newUser.user_type,
                        registeredBy: user.email || user.user_id
                    }
                }, transaction);
            } catch (auditErr) {
                logger.warn('Could not record audit event for contractor registration', {
                    userId: newUser.user_id,
                    error: auditErr.message
                });
            }

            return newUser;
        });

        logger.info('Contractor registered successfully', {
            contractorUserId: createdUser.user_id,
            email: createdUser.email,
            registeredBy: user.user_id
        });

        return {
            contractor: {
                user_id: createdUser.user_id,
                contractor_id: createdUser.user_id,
                display_name: createdUser.display_name,
                email: createdUser.email,
                first_name: createdUser.first_name,
                last_name: createdUser.last_name,
                user_type: createdUser.user_type,
                department: createdUser.department,
                company: createdUser.department,
                is_active: createdUser.is_active,
                created_at: createdUser.created_at
            },
            status: 'REGISTERED',
            message: 'Contractor successfully registered.'
        };
    }

    /**
     * Lists contractors for authorized internal governance roles.
     * Contractors are prohibited from accessing this directory.
     * 
     * @param {object} user Authenticated user context
     * @param {object} [filter={}] { search, isActive, limit, offset }
     * @returns {Promise<{ contractors: Array<object>, total: number, limit: number, offset: number }>}
     */
    async listContractors(user, filter = {}) {
        if (!user) {
            throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
        }

        // Contractors must not access the complete directory
        if (hasRole(user.roles, 'CONTRACTOR') && !hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'INTERNAL_SPONSOR', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR'])) {
            throw new ForbiddenError(
                'Access denied: Contractors are not authorized to view the contractor directory.',
                'ERR_FORBIDDEN_CONTRACTOR_DIRECTORY'
            );
        }

        // Enforce read permission
        if (!hasAnyPermission(user.roles, [Permissions.ENGAGEMENT_READ_ALL])) {
            throw new ForbiddenError(
                'Access denied: Insufficient permissions to view contractor directory.',
                'ERR_FORBIDDEN_PERMISSION'
            );
        }

        const limit = Math.min(100, Math.max(1, parseInt(filter.limit, 10) || 50));
        const offset = Math.max(0, parseInt(filter.offset, 10) || 0);
        const search = typeof filter.search === 'string' ? filter.search.trim() : null;
        let isActive = null;
        if (filter.isActive === 'true' || filter.isActive === true) isActive = true;
        if (filter.isActive === 'false' || filter.isActive === false) isActive = false;

        const queryFilter = { search, isActive, limit, offset };

        const countFn = typeof userRepository.countContractors === 'function'
            ? userRepository.countContractors({ search, isActive })
            : userRepository.countUsers({ userType: 'CONTRACTOR', search, isActive });

        const [contractors, total] = await Promise.all([
            userRepository.listContractors(queryFilter),
            countFn
        ]);

        // Defensive server-side enforcement: Strictly include records with user_type === 'CONTRACTOR'
        const eligibleContractors = (contractors || []).filter(c => c && c.user_type === 'CONTRACTOR');

        return {
            contractors: eligibleContractors,
            total,
            limit,
            offset
        };
    }

    /**
     * Retrieves an individual contractor record along with their engagement history.
     * 
     * @param {object} user Authenticated user
     * @param {string} contractorUserId GUID of the contractor
     * @returns {Promise<object>}
     */
    async getContractorById(user, contractorUserId) {
        if (!user || !contractorUserId) {
            throw new ValidationError('Contractor user ID is required.');
        }

        const targetId = contractorUserId.trim().toLowerCase();
        const callerId = user.user_id.toLowerCase();
        const isContractorCaller = hasRole(user.roles, 'CONTRACTOR') && !hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'INTERNAL_SPONSOR', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR']);

        // A contractor must never access another contractor's information
        if (isContractorCaller && callerId !== targetId) {
            throw new ForbiddenError(
                'Access denied: You are not authorized to view another contractor profile.',
                'ERR_FORBIDDEN_CONTRACTOR_ACCESS'
            );
        }

        // Internal users must have read access
        if (!isContractorCaller && !hasAnyPermission(user.roles, [Permissions.ENGAGEMENT_READ_ALL, Permissions.ENGAGEMENT_READ_SELF])) {
            throw new ForbiddenError('Access denied: Insufficient permissions.', 'ERR_FORBIDDEN_PERMISSION');
        }

        const contractor = await userRepository.findUserById(targetId);
        if (!contractor || contractor.user_type !== 'CONTRACTOR') {
            throw new NotFoundError('Contractor profile');
        }

        const engagements = await engagementRepository.findEngagementsByContractorId(targetId);

        return {
            contractor: {
                user_id: contractor.user_id,
                contractor_id: contractor.user_id,
                email: contractor.email,
                first_name: contractor.first_name,
                last_name: contractor.last_name,
                display_name: contractor.display_name,
                user_type: contractor.user_type,
                department: contractor.department,
                is_active: contractor.is_active,
                created_at: contractor.created_at
            },
            engagements
        };
    }

    /**
     * Contractor Self-Service: Returns authenticated contractor's profile and engagements.
     * 
     * @param {object} user Authenticated user
     * @returns {Promise<object>}
     */
    async getContractorSelf(user) {
        if (!user) {
            throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
        }

        return this.getContractorById(user, user.user_id);
    }

    /**
     * Lists engagements with filtering, pagination, and role-based scoping.
     * Contractors can ONLY view their own engagements.
     * 
     * @param {object} user Authenticated user
     * @param {object} [filter={}] { status, contractorId, sponsorId, search, limit, offset }
     * @returns {Promise<{ engagements: Array<object>, total: number, limit: number, offset: number }>}
     */
    async listEngagements(user, filter = {}) {
        if (!user) {
            throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
        }

        const limit = Math.min(100, Math.max(1, parseInt(filter.limit, 10) || 50));
        const offset = Math.max(0, parseInt(filter.offset, 10) || 0);
        const search = typeof filter.search === 'string' ? filter.search.trim() : null;
        const status = typeof filter.status === 'string' && filter.status.trim() ? filter.status.trim().toUpperCase() : null;

        let contractorUserId = filter.contractorId ? filter.contractorId.trim() : null;
        let sponsorUserId = filter.sponsorId ? filter.sponsorId.trim() : null;

        // Contractor Self-Service Isolation: Force filter to contractor's own user_id
        if (hasRole(user.roles, 'CONTRACTOR') && !hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'INTERNAL_SPONSOR', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR'])) {
            contractorUserId = user.user_id;
            sponsorUserId = null; // Do not allow contractor to filter by sponsor
        } else {
            // Internal users must have read permission
            if (!hasAnyPermission(user.roles, [Permissions.ENGAGEMENT_READ_ALL])) {
                throw new ForbiddenError('Access denied: Insufficient permissions to list engagements.', 'ERR_FORBIDDEN_PERMISSION');
            }
        }

        const queryFilter = {
            status,
            contractorUserId,
            sponsorUserId,
            search,
            limit,
            offset
        };

        const [engagements, total] = await Promise.all([
            engagementRepository.listEngagements(queryFilter),
            engagementRepository.countEngagements(queryFilter)
        ]);

        return {
            engagements,
            total,
            limit,
            offset
        };
    }

    /**
     * Retrieves engagement details by ID.
     * Enforces that contractors can only view their own engagement.
     * 
     * @param {object} user Authenticated user
     * @param {string} engagementId GUID
     * @returns {Promise<object>}
     */
    async getEngagementById(user, engagementId) {
        if (!user || !engagementId) {
            throw new ValidationError('Engagement ID is required.');
        }

        const engagement = await engagementRepository.findEngagementById(engagementId);
        if (!engagement) {
            throw new NotFoundError('Contractor Engagement');
        }

        const callerId = user.user_id.toLowerCase();
        const isContractorCaller = hasRole(user.roles, 'CONTRACTOR') && !hasAnyRole(user.roles, ['SYSTEM_ADMIN', 'INTERNAL_SPONSOR', 'SECURITY_OFFICER', 'COMPLIANCE_AUDITOR']);

        // A contractor must never access another contractor's engagement
        if (isContractorCaller && engagement.contractor_user_id.toLowerCase() !== callerId) {
            throw new ForbiddenError(
                'Access denied: You are not authorized to view this contractor engagement.',
                'ERR_FORBIDDEN_CONTRACTOR_ACCESS'
            );
        }

        // Internal users must have read access
        if (!isContractorCaller && !hasAnyPermission(user.roles, [Permissions.ENGAGEMENT_READ_ALL, Permissions.ENGAGEMENT_READ_SELF])) {
            throw new ForbiddenError('Access denied: Insufficient permissions.', 'ERR_FORBIDDEN_PERMISSION');
        }

        return engagement;
    }

    /**
     * Creates a new contractor engagement backed by real database records and audit trail.
     * 
     * @param {object} user Authenticated creator (Sponsor or Admin)
     * @param {object} data Input data
     * @param {object} [options={}] Additional context (e.g. ipAddress)
     * @returns {Promise<object>} Created engagement
     */
    async createEngagement(user, data, options = {}) {
        if (!user) {
            throw new ForbiddenError('Authentication required.', 'ERR_UNAUTHORIZED');
        }

        // Rule 1: Only authorized internal roles can create engagements
        if (!hasAnyPermission(user.roles, [Permissions.ENGAGEMENT_CREATE])) {
            throw new ForbiddenError(
                'Access denied: Only authorized internal sponsors or administrators can create engagements.',
                'ERR_FORBIDDEN_ENGAGEMENT_CREATE'
            );
        }

        // Rule 4: Disabled internal users cannot perform management operations
        if (!user.is_active) {
            throw new ForbiddenError('Access denied: User account is deactivated.', 'ERR_USER_INACTIVE');
        }

        // Read-only auditors are strictly blocked
        if (isStrictlyReadOnlyAuditor(user.roles)) {
            throw new ForbiddenError('Access denied: Compliance Auditor is strictly read-only.', 'ERR_AUDITOR_READ_ONLY');
        }

        const rawContractorId = (data && (data.contractorUserId || data.contractorId || data.contractor_id));
        const contractorUserId = typeof rawContractorId === 'string' ? rawContractorId.trim() : rawContractorId;

        const {
            vendorName,
            contractReference,
            startDate,
            endDate,
            status = 'ACTIVE'
        } = data || {};

        const validationErrors = [];

        // 1. Validate Contractor
        const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!contractorUserId || typeof contractorUserId !== 'string') {
            validationErrors.push('contractorUserId is required and must be a valid GUID.');
        } else if (!UUID_REGEX.test(contractorUserId)) {
            validationErrors.push('contractorUserId must be a valid UUID format (8-4-4-4-12 hex).');
        }

        // 2. Validate Vendor Name
        if (!vendorName || typeof vendorName !== 'string' || !vendorName.trim()) {
            validationErrors.push('vendorName is required and cannot be blank.');
        } else if (vendorName.trim().length > 150) {
            validationErrors.push('vendorName must not exceed 150 characters.');
        }

        // 3. Validate Contract Reference
        if (!contractReference || typeof contractReference !== 'string' || !contractReference.trim()) {
            validationErrors.push('contractReference is required and cannot be blank.');
        } else if (contractReference.trim().length > 100) {
            validationErrors.push('contractReference must not exceed 100 characters.');
        }

        // 4. Validate Dates
        if (!isValidDateString(startDate)) {
            validationErrors.push('startDate must be a valid date in YYYY-MM-DD format.');
        }
        if (!isValidDateString(endDate)) {
            validationErrors.push('endDate must be a valid date in YYYY-MM-DD format.');
        }

        if (isValidDateString(startDate) && isValidDateString(endDate)) {
            if (endDate < startDate) {
                validationErrors.push('End date must be on or after start date.');
            }
        }

        // 5. Validate Status
        const cleanStatus = typeof status === 'string' ? status.trim().toUpperCase() : 'ACTIVE';
        if (!['PENDING', 'ACTIVE'].includes(cleanStatus)) {
            validationErrors.push('Initial engagement status must be either PENDING or ACTIVE.');
        }

        // Rule 6: An engagement cannot be marked active outside its permitted validity period
        if (cleanStatus === 'ACTIVE' && isValidDateString(endDate)) {
            const todayStr = toDateOnlyString(new Date());
            if (endDate < todayStr) {
                validationErrors.push('Cannot mark engagement ACTIVE when the end date is already in the past.');
            }
        }

        if (validationErrors.length > 0) {
            throw new ValidationError('Validation failed for contractor engagement creation.', validationErrors);
        }

        // Determine Sponsor
        // Rule 3: Sponsors must only manage engagements within their authorized responsibility.
        // If caller is an internal sponsor without SYSTEM_ADMIN role, they MUST be the sponsor.
        let targetSponsorUserId = user.user_id;
        if (hasRole(user.roles, 'SYSTEM_ADMIN') && data.sponsorUserId) {
            targetSponsorUserId = data.sponsorUserId.trim();
        }

        // Verify contractor existence and type in real database
        const contractor = await userRepository.findUserById(contractorUserId.trim());
        if (!contractor || contractor.user_type !== 'CONTRACTOR') {
            throw new ValidationError('Contractor not found or user is not classified as a CONTRACTOR.', [
                `No active contractor found with ID ${contractorUserId}`
            ]);
        }
        if (!contractor.is_active) {
            throw new ValidationError('Contractor record is currently deactivated.');
        }

        // Verify sponsor existence and type in real database
        const sponsor = await userRepository.findUserById(targetSponsorUserId);
        if (!sponsor || sponsor.user_type !== 'INTERNAL_EMPLOYEE') {
            throw new ValidationError('Sponsor not found or user is not an internal employee.', [
                `No active internal sponsor found with ID ${targetSponsorUserId}`
            ]);
        }
        if (!sponsor.is_active) {
            throw new ValidationError('Sponsor record is currently deactivated.');
        }

        // Verify unique constraint: (contractor_user_id, contract_reference)
        const existingRef = await engagementRepository.findEngagementByContractReference(
            contractor.user_id,
            contractReference.trim()
        );
        if (existingRef) {
            throw new ConflictError(
                `Contract reference '${contractReference.trim()}' is already assigned to this contractor.`
            );
        }

        // Execute creation atomically with transaction and audit trail
        const cleanContractorId = contractor.user_id;
        const cleanVendor = vendorName.trim();
        const cleanRef = contractReference.trim();

        return await db.withTransaction(async (transaction) => {
            const created = await engagementRepository.createEngagement({
                contractorUserId: cleanContractorId,
                sponsorUserId: targetSponsorUserId,
                vendorName: cleanVendor,
                contractReference: cleanRef,
                startDate,
                endDate,
                status: cleanStatus
            }, transaction);

            // Record audit event in dbo.audit_events
            await auditRepository.createAuditEvent({
                eventCategory: 'SECURITY_POLICY',
                eventAction: 'ENGAGEMENT_CREATED',
                entityType: 'contractor_engagements',
                entityId: created.engagement_id,
                actorUserId: user.user_id,
                actorType: 'USER',
                eventPayload: {
                    engagement_id: created.engagement_id,
                    contractor_user_id: cleanContractorId,
                    contractor_name: contractor.display_name,
                    sponsor_user_id: targetSponsorUserId,
                    sponsor_name: sponsor.display_name,
                    vendor_name: cleanVendor,
                    contract_reference: cleanRef,
                    start_date: startDate,
                    end_date: endDate,
                    status: cleanStatus
                },
                ipAddress: options.ipAddress || null
            }, transaction);

            logger.info('Contractor engagement created successfully', {
                engagementId: created.engagement_id,
                contractorUserId: cleanContractorId,
                sponsorUserId: targetSponsorUserId,
                actorUserId: user.user_id
            });

            return created;
        });
    }

    /**
     * Updates permitted mutable fields of an existing engagement.
     * 
     * @param {object} user Authenticated user (Sponsor or Admin)
     * @param {string} engagementId GUID
     * @param {object} updates { vendorName, contractReference, startDate, endDate }
     * @param {object} [options={}]
     * @returns {Promise<object>} Updated engagement
     */
    async updateEngagement(user, engagementId, updates, options = {}) {
        if (!user || !engagementId) {
            throw new ValidationError('Engagement ID is required.');
        }

        if (!hasAnyPermission(user.roles, [Permissions.ENGAGEMENT_MANAGE])) {
            throw new ForbiddenError('Access denied: Insufficient permissions to manage engagements.', 'ERR_FORBIDDEN_PERMISSION');
        }

        if (!user.is_active) {
            throw new ForbiddenError('Access denied: User account is deactivated.', 'ERR_USER_INACTIVE');
        }

        if (isStrictlyReadOnlyAuditor(user.roles)) {
            throw new ForbiddenError('Access denied: Compliance Auditor is strictly read-only.', 'ERR_AUDITOR_READ_ONLY');
        }

        const existing = await engagementRepository.findEngagementById(engagementId);
        if (!existing) {
            throw new NotFoundError('Contractor Engagement');
        }

        // Rule 3: Sponsors must only manage engagements within their authorized responsibility
        const isSystemAdmin = hasRole(user.roles, 'SYSTEM_ADMIN');
        if (!isSystemAdmin && existing.sponsor_user_id.toLowerCase() !== user.user_id.toLowerCase()) {
            throw new ForbiddenError(
                'Access denied: Sponsors can only update engagements for which they are the designated sponsor.',
                'ERR_FORBIDDEN_SPONSOR_MISMATCH'
            );
        }

        // Terminal state check: completed or terminated engagements cannot be mutated
        if (['COMPLETED', 'TERMINATED'].includes(existing.status)) {
            throw new ValidationError(
                `Cannot modify an engagement that has already ended (status: ${existing.status}).`,
                ['Ended engagements are immutable. A new engagement must be created if re-engaging.']
            );
        }

        const validationErrors = [];
        const payloadUpdates = {};

        if (updates.vendorName !== undefined) {
            if (typeof updates.vendorName !== 'string' || !updates.vendorName.trim()) {
                validationErrors.push('vendorName cannot be blank.');
            } else if (updates.vendorName.trim().length > 150) {
                validationErrors.push('vendorName must not exceed 150 characters.');
            } else {
                payloadUpdates.vendorName = updates.vendorName.trim();
            }
        }

        if (updates.contractReference !== undefined) {
            if (typeof updates.contractReference !== 'string' || !updates.contractReference.trim()) {
                validationErrors.push('contractReference cannot be blank.');
            } else if (updates.contractReference.trim().length > 100) {
                validationErrors.push('contractReference must not exceed 100 characters.');
            } else {
                payloadUpdates.contractReference = updates.contractReference.trim();
            }
        }

        const newStartDate = updates.startDate !== undefined ? updates.startDate : toDateOnlyString(existing.start_date);
        const newEndDate = updates.endDate !== undefined ? updates.endDate : toDateOnlyString(existing.end_date);

        if (updates.startDate !== undefined) {
            if (!isValidDateString(updates.startDate)) {
                validationErrors.push('startDate must be in YYYY-MM-DD format.');
            } else {
                payloadUpdates.startDate = updates.startDate;
            }
        }

        if (updates.endDate !== undefined) {
            if (!isValidDateString(updates.endDate)) {
                validationErrors.push('endDate must be in YYYY-MM-DD format.');
            } else {
                payloadUpdates.endDate = updates.endDate;
            }
        }

        if (isValidDateString(newStartDate) && isValidDateString(newEndDate)) {
            if (newEndDate < newStartDate) {
                validationErrors.push('End date must be on or after start date.');
            }
        }

        if (validationErrors.length > 0) {
            throw new ValidationError('Validation failed for engagement update.', validationErrors);
        }

        // Check contractReference uniqueness if changed
        if (payloadUpdates.contractReference && payloadUpdates.contractReference !== existing.contract_reference) {
            const duplicate = await engagementRepository.findEngagementByContractReference(
                existing.contractor_user_id,
                payloadUpdates.contractReference
            );
            if (duplicate && duplicate.engagement_id.toLowerCase() !== existing.engagement_id.toLowerCase()) {
                throw new ConflictError(
                    `Contract reference '${payloadUpdates.contractReference}' is already in use for this contractor.`
                );
            }
        }

        return await db.withTransaction(async (transaction) => {
            const updated = await engagementRepository.updateEngagement(existing.engagement_id, payloadUpdates, transaction);

            await auditRepository.createAuditEvent({
                eventCategory: 'SECURITY_POLICY',
                eventAction: 'ENGAGEMENT_UPDATED',
                entityType: 'contractor_engagements',
                entityId: existing.engagement_id,
                actorUserId: user.user_id,
                actorType: 'USER',
                eventPayload: {
                    engagement_id: existing.engagement_id,
                    contractor_user_id: existing.contractor_user_id,
                    changes: payloadUpdates,
                    previous: {
                        vendor_name: existing.vendor_name,
                        contract_reference: existing.contract_reference,
                        start_date: toDateOnlyString(existing.start_date),
                        end_date: toDateOnlyString(existing.end_date)
                    }
                },
                ipAddress: options.ipAddress || null
            }, transaction);

            return updated;
        });
    }

    /**
     * Executes validated state transitions for an engagement.
     * Enforces that ended engagements cannot be silently reactivated.
     * 
     * @param {object} user Authenticated user
     * @param {string} engagementId GUID
     * @param {string} targetStatus 'ACTIVE', 'COMPLETED', 'TERMINATED'
     * @param {string} [reason=''] Audit justification
     * @param {object} [options={}]
     * @returns {Promise<object>} Updated engagement
     */
    async transitionEngagementStatus(user, engagementId, targetStatus, reason = '', options = {}) {
        if (!user || !engagementId || !targetStatus) {
            throw new ValidationError('Engagement ID and target status are required.');
        }

        if (!hasAnyPermission(user.roles, [Permissions.ENGAGEMENT_MANAGE])) {
            throw new ForbiddenError('Access denied: Insufficient permissions to manage engagement status.', 'ERR_FORBIDDEN_PERMISSION');
        }

        if (!user.is_active) {
            throw new ForbiddenError('Access denied: User account is deactivated.', 'ERR_USER_INACTIVE');
        }

        if (isStrictlyReadOnlyAuditor(user.roles)) {
            throw new ForbiddenError('Access denied: Compliance Auditor is strictly read-only.', 'ERR_AUDITOR_READ_ONLY');
        }

        const existing = await engagementRepository.findEngagementById(engagementId);
        if (!existing) {
            throw new NotFoundError('Contractor Engagement');
        }

        // Rule 3: Sponsors must only manage engagements within their authorized responsibility
        const isSystemAdmin = hasRole(user.roles, 'SYSTEM_ADMIN');
        if (!isSystemAdmin && existing.sponsor_user_id.toLowerCase() !== user.user_id.toLowerCase()) {
            throw new ForbiddenError(
                'Access denied: Sponsors can only transition engagements for which they are the designated sponsor.',
                'ERR_FORBIDDEN_SPONSOR_MISMATCH'
            );
        }

        const currentStatus = existing.status.toUpperCase();
        const cleanTargetStatus = targetStatus.trim().toUpperCase();

        // Check if transition is valid
        const allowedNextStates = VALID_STATUS_TRANSITIONS[currentStatus] || [];

        if (['COMPLETED', 'TERMINATED'].includes(currentStatus)) {
            throw new ValidationError(
                `Cannot transition engagement: Engagement is already in terminal state '${currentStatus}'. Ended engagements cannot be silently reactivated.`,
                [],
                'ERR_ENGAGEMENT_ALREADY_ENDED'
            );
        }

        if (!allowedNextStates.includes(cleanTargetStatus)) {
            throw new ValidationError(
                `Invalid status transition from '${currentStatus}' to '${cleanTargetStatus}'. Allowed transitions: ${allowedNextStates.join(', ') || 'None'}.`,
                [],
                'ERR_INVALID_STATUS_TRANSITION'
            );
        }

        // Rule 6: An engagement cannot be marked active outside its permitted validity period
        if (cleanTargetStatus === 'ACTIVE') {
            const todayStr = toDateOnlyString(new Date());
            const endDateStr = toDateOnlyString(existing.end_date);
            if (endDateStr < todayStr) {
                throw new ValidationError(
                    `Cannot activate engagement: The engagement end date (${endDateStr}) has already passed.`,
                    [],
                    'ERR_ENGAGEMENT_EXPIRED'
                );
            }
        }

        // Audit action name
        let auditAction = 'ENGAGEMENT_STATUS_CHANGED';
        if (cleanTargetStatus === 'ACTIVE') auditAction = 'ENGAGEMENT_ACTIVATED';
        if (cleanTargetStatus === 'COMPLETED') auditAction = 'ENGAGEMENT_COMPLETED';
        if (cleanTargetStatus === 'TERMINATED') auditAction = 'ENGAGEMENT_TERMINATED';

        const result = await db.withTransaction(async (transaction) => {
            const updated = await engagementRepository.updateEngagementStatus(
                existing.engagement_id,
                cleanTargetStatus,
                transaction
            );

            // Rule 8: Ending an engagement must create the necessary auditable event and make it eligible for future offboarding
            await auditRepository.createAuditEvent({
                eventCategory: 'SECURITY_POLICY',
                eventAction: auditAction,
                entityType: 'contractor_engagements',
                entityId: existing.engagement_id,
                actorUserId: user.user_id,
                actorType: 'USER',
                eventPayload: {
                    engagement_id: existing.engagement_id,
                    contractor_user_id: existing.contractor_user_id,
                    sponsor_user_id: existing.sponsor_user_id,
                    previous_status: currentStatus,
                    new_status: cleanTargetStatus,
                    reason: reason ? String(reason).trim() : null,
                    offboarding_eligible: ['COMPLETED', 'TERMINATED'].includes(cleanTargetStatus)
                },
                ipAddress: options.ipAddress || null
            }, transaction);

            // If transitioned to TERMINATED or COMPLETED, enqueue revocation jobs for all active grants
            if (['COMPLETED', 'TERMINATED'].includes(cleanTargetStatus)) {
                const activeGrants = await revocationRepository.findActiveGrantsByEngagementId(existing.engagement_id, transaction);
                for (const grant of activeGrants) {
                    const idempotencyKey = `REVOCATION_ACTIVE_${grant.grant_id}`;
                    await revocationRepository.createRevocationJob({
                        grantId: grant.grant_id,
                        triggerSource: cleanTargetStatus === 'TERMINATED' ? 'ENGAGEMENT_TERMINATION' : 'SCHEDULED_EXPIRATION',
                        connectorName: 'GITHUB',
                        idempotencyKey
                    }, transaction);

                    await grantRepository.updateGrantStatus(grant.grant_id, 'REVOKE_PENDING', {}, transaction);

                    await auditRepository.createAuditEvent({
                        eventCategory: 'REVOCATION',
                        eventAction: 'REVOCATION_JOB_QUEUED',
                        entityType: 'access_grants',
                        entityId: grant.grant_id,
                        actorUserId: user.user_id,
                        actorType: 'USER',
                        eventPayload: {
                            grantId: grant.grant_id,
                            engagementId: existing.engagement_id,
                            trigger: cleanTargetStatus === 'TERMINATED' ? 'ENGAGEMENT_TERMINATION' : 'SCHEDULED_EXPIRATION'
                        }
                    }, transaction);
                }
            }

            logger.info(`Engagement status transitioned: ${currentStatus} -> ${cleanTargetStatus}`, {
                engagementId: existing.engagement_id,
                actorUserId: user.user_id,
                previousStatus: currentStatus,
                newStatus: cleanTargetStatus
            });

            return updated;
        });

        // Trigger worker cycle to process newly enqueued jobs
        if (['COMPLETED', 'TERMINATED'].includes(cleanTargetStatus)) {
            try {
                const revocationWorker = require('./revocationWorker');
                await revocationWorker.runWorkerCycle();
            } catch (err) {
                logger.warn('Failed background revocation cycle following engagement transition', { error: err.message });
            }
        }

        return result;
    }
}

module.exports = new ContractorService();

