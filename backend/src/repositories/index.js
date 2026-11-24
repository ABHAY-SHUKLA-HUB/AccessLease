/**
 * AccessLease — Database Repositories Aggregator
 * Centralized data access layer covering all 15 governance tables, views, and stored procedures.
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 */

const userRepository = require('./userRepository');
const engagementRepository = require('./engagementRepository');
const roleRepository = require('./roleRepository');
const resourceRepository = require('./resourceRepository');
const requestRepository = require('./requestRepository');
const grantRepository = require('./grantRepository');
const provisioningRepository = require('./provisioningRepository');
const revocationRepository = require('./revocationRepository');
const reviewRepository = require('./reviewRepository');
const auditRepository = require('./auditRepository');
const userExternalIdentityRepository = require('./userExternalIdentityRepository');
const connectorMappingRepository = require('./connectorMappingRepository');
const oauthStateRepository = require('./oauthStateRepository');
const orphanFindingRepository = require('./orphanFindingRepository');

module.exports = {
    userRepository,
    engagementRepository,
    roleRepository,
    resourceRepository,
    requestRepository,
    grantRepository,
    provisioningRepository,
    revocationRepository,
    reviewRepository,
    auditRepository,
    userExternalIdentityRepository,
    connectorMappingRepository,
    oauthStateRepository,
    orphanFindingRepository
};

