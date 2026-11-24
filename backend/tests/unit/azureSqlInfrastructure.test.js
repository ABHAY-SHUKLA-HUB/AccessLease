/**
 * AccessLease — Unit Tests: Azure SQL Infrastructure Security & Managed Identity
 * 
 * Verifies:
 * - Function App Bicep configuration excludes SQL administrator credentials.
 * - Function App appSettings configure SQL_AUTH_MODE = 'azure-identity'.
 * - Function App retains System-Assigned Managed Identity.
 * - Azure SQL Bicep configures Microsoft Entra administrator support and disables public network access.
 * - main.bicep outputs Function App principal ID and does not pass admin credentials to Function App.
 * - SQL setup script enforces least-privilege role without db_owner.
 * - Flex Consumption hosting architecture (FC1, FlexConsumption tier, Node 22).
 * - Regional VNet integration delegated to Microsoft.App/environments.
 * - Dedicated Private Endpoint subnet and Azure SQL Private Endpoint with sqlServer group ID.
 * - Private DNS Zone privatelink.database.windows.net with auto-registration zone group.
 * - Blob-based package storage in app-packages container and identity-based AzureWebJobsStorage.
 * - Storage RBAC roles: Storage Blob Data Owner (Queue and Table roles omitted for least-privilege).
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '../../../');
const FUNCTION_APP_BICEP = path.join(ROOT_DIR, 'infrastructure/azure/modules/functionApp.bicep');
const SQL_BICEP = path.join(ROOT_DIR, 'infrastructure/azure/modules/sql.bicep');
const STORAGE_BICEP = path.join(ROOT_DIR, 'infrastructure/azure/modules/storage.bicep');
const STORAGE_ROLE_BICEP = path.join(ROOT_DIR, 'infrastructure/azure/modules/storageRole.bicep');
const NETWORK_BICEP = path.join(ROOT_DIR, 'infrastructure/azure/modules/network.bicep');
const MAIN_BICEP = path.join(ROOT_DIR, 'infrastructure/azure/main.bicep');
const MAIN_BICEPPARAM = path.join(ROOT_DIR, 'infrastructure/azure/main.bicepparam');
const SETUP_SQL_SCRIPT = path.join(ROOT_DIR, 'database/scripts/setup_managed_identity_user.sql');

describe('Unit: Azure SQL Infrastructure & Managed Identity Verification', () => {

    test('functionApp.bicep must NOT declare or accept SQL admin credentials', () => {
        const content = fs.readFileSync(FUNCTION_APP_BICEP, 'utf8');

        assert.strictEqual(content.includes('param sqlAdminLogin'), false, 'functionApp.bicep must not declare sqlAdminLogin');
        assert.strictEqual(content.includes('param sqlAdminPassword'), false, 'functionApp.bicep must not declare sqlAdminPassword');
    });

    test('functionApp.bicep appSettings must exclude SQL_USER and SQL_PASSWORD', () => {
        const content = fs.readFileSync(FUNCTION_APP_BICEP, 'utf8');

        assert.strictEqual(content.includes("'SQL_USER'"), false, 'appSettings must not contain SQL_USER');
        assert.strictEqual(content.includes("'SQL_PASSWORD'"), false, 'appSettings must not contain SQL_PASSWORD');
    });

    test('functionApp.bicep appSettings must configure SQL_AUTH_MODE as azure-identity with TLS encryption', () => {
        const content = fs.readFileSync(FUNCTION_APP_BICEP, 'utf8');

        assert.ok(content.includes("'SQL_AUTH_MODE'"), 'appSettings must configure SQL_AUTH_MODE');
        assert.ok(content.includes("'azure-identity'"), "SQL_AUTH_MODE must be set to 'azure-identity'");
        assert.ok(content.includes("'SQL_ENCRYPT'"), 'appSettings must configure SQL_ENCRYPT');
        assert.ok(content.includes("'SQL_TRUST_SERVER_CERTIFICATE'"), 'appSettings must configure SQL_TRUST_SERVER_CERTIFICATE');
    });

    test('functionApp.bicep must retain SystemAssigned Managed Identity', () => {
        const content = fs.readFileSync(FUNCTION_APP_BICEP, 'utf8');

        assert.ok(content.includes("type: 'SystemAssigned'"), "functionApp must configure SystemAssigned identity");
        assert.ok(content.includes('functionApp.identity.principalId'), "functionApp must output principalId");
    });

    test('sql.bicep must support Microsoft Entra administrator configuration and staged migration connectivity', () => {
        const content = fs.readFileSync(SQL_BICEP, 'utf8');

        assert.ok(content.includes('entraAdminLogin'), 'sql.bicep must accept entraAdminLogin');
        assert.ok(content.includes('entraAdminSid'), 'sql.bicep must accept entraAdminSid');
        assert.ok(content.includes("Microsoft.Sql/servers/administrators"), 'sql.bicep must declare Entra administrators resource');
        assert.strictEqual(content.includes("param allowAllAzureIps bool = false"), true, 'allowAllAzureIps must default to false');
        assert.ok(content.includes("param publicNetworkAccess string = !empty(clientIpAddress) ? 'Enabled' : 'Disabled'"), 'sql.bicep must default publicNetworkAccess based on clientIpAddress');
        assert.ok(content.includes("publicNetworkAccess: publicNetworkAccess"), 'sql.bicep must apply publicNetworkAccess to server');
        assert.ok(content.includes("publicNetworkAccess == 'Enabled'"), 'allowClientMigrationIpRule must require publicNetworkAccess == Enabled');
    });

    test('main.bicep and functionApp.bicep must output Function App principal ID and exclude client ID extension reference', () => {
        const mainContent = fs.readFileSync(MAIN_BICEP, 'utf8');
        const fnContent = fs.readFileSync(FUNCTION_APP_BICEP, 'utf8');

        // Verify functionApp.bicep outputs
        assert.ok(fnContent.includes('output functionAppPrincipalId string'), 'functionApp.bicep must output functionAppPrincipalId');
        assert.strictEqual(fnContent.includes('output functionAppClientId string'), false, 'functionApp.bicep must not declare functionAppClientId');
        assert.strictEqual(fnContent.includes("Microsoft.ManagedIdentity/Identities/default"), false, 'functionApp.bicep must not reference unsupported ManagedIdentity extension resource');

        // Verify main.bicep outputs
        assert.ok(mainContent.includes('output functionAppPrincipalId string'), 'main.bicep must output functionAppPrincipalId');
        assert.strictEqual(mainContent.includes('output functionAppClientId string'), false, 'main.bicep must not forward functionAppClientId');
        assert.ok(mainContent.includes('output functionAppName string'), 'main.bicep must output functionAppName');
        assert.ok(mainContent.includes('output sqlServerName string'), 'main.bicep must output sqlServerName');

        // Extract functionAppModule invocation
        const fnModuleBlock = mainContent.match(/module functionAppModule[\s\S]*?params:\s*\{([\s\S]*?)\n\s*\}/);
        assert.ok(fnModuleBlock, 'functionAppModule invocation must be present');
        const paramsText = fnModuleBlock[1];
        assert.strictEqual(paramsText.includes('sqlAdminLogin'), false, 'functionAppModule params must not include sqlAdminLogin');
        assert.strictEqual(paramsText.includes('sqlAdminPassword'), false, 'functionAppModule params must not include sqlAdminPassword');
    });

    test('setup_managed_identity_user.sql must enforce least-privilege without db_owner and support Client ID SID', () => {
        const content = fs.readFileSync(SETUP_SQL_SCRIPT, 'utf8');

        assert.ok(content.includes('db_accesslease_app'), 'Script must define db_accesslease_app role');
        assert.ok(content.includes('CREATE USER'), 'Script must include CREATE USER statement');
        assert.ok(content.includes('WITH SID ='), 'Script must support WITH SID syntax for Client ID');
        assert.ok(content.includes('TYPE = E'), 'Script must specify TYPE = E for external identity SID');
        assert.ok(content.includes('FROM EXTERNAL PROVIDER'), 'Script must retain fallback FROM EXTERNAL PROVIDER');
        assert.ok(content.includes('MANAGED_IDENTITY_CLIENT_ID'), 'Script must accept MANAGED_IDENTITY_CLIENT_ID variable');
        assert.ok(content.includes('sys.fn_varbintohexstr'), 'Script must use sys.fn_varbintohexstr for hex conversion');
        assert.ok(content.includes('sp_ActivateApprovedGrant'), 'Script must grant EXECUTE on sp_ActivateApprovedGrant');
        assert.ok(content.includes('v_AccessExposureQueue'), 'Script must grant SELECT on v_AccessExposureQueue');

        // Verify distinction: Client ID for SID, Principal ID for RBAC
        assert.ok(content.includes('Client ID (Application ID): Converted to varbinary(16) SID'), 'Script must document Client ID for SID');
        assert.ok(content.includes('Principal ID (Object ID): Reserved for Azure RBAC'), 'Script must document Principal ID for RBAC');

        // Strictly forbidden broad privileges
        assert.strictEqual(content.toLowerCase().includes('add member [db_owner]'), false, 'Must not grant db_owner');
        assert.strictEqual(content.toLowerCase().includes('add member [db_securityadmin]'), false, 'Must not grant db_securityadmin');
        assert.strictEqual(content.toLowerCase().includes('grant control'), false, 'Must not grant CONTROL permission');

        // Append-only audit and event tables must not receive UPDATE or DELETE privileges
        assert.strictEqual(content.includes('UPDATE ON dbo.audit_events'), false, 'Must not grant UPDATE on audit_events');
        assert.strictEqual(content.includes('UPDATE ON dbo.provisioning_events'), false, 'Must not grant UPDATE on provisioning_events');
        assert.strictEqual(content.includes('DELETE ON dbo.audit_events'), false, 'Must not grant DELETE on audit_events');
        assert.strictEqual(content.includes('DELETE ON dbo.provisioning_events'), false, 'Must not grant DELETE on provisioning_events');

        // Role membership must be checked using sys.database_role_members before adding member
        assert.ok(content.includes('sys.database_role_members'), 'Script must check sys.database_role_members before adding member');
    });

    test('functionApp.bicep must configure Azure Functions Flex Consumption (FC1, Node 22, VNet)', () => {
        const content = fs.readFileSync(FUNCTION_APP_BICEP, 'utf8');

        // Hosting plan assertions
        assert.ok(content.includes("name: 'FC1'"), 'Hosting plan SKU name must be FC1');
        assert.ok(content.includes("tier: 'FlexConsumption'"), 'Hosting plan SKU tier must be FlexConsumption');
        assert.ok(content.includes("family: 'FC'"), 'Hosting plan SKU family must be FC');
        assert.ok(content.includes("kind: 'functionapp,linux'"), 'Hosting plan must be functionapp,linux');

        // Flex Consumption configuration assertions
        assert.ok(content.includes('functionAppConfig:'), 'functionApp must declare functionAppConfig');
        assert.ok(content.includes("name: 'node'"), 'Runtime name must be node');
        assert.ok(content.includes("version: '22'"), 'Runtime version must be 22');
        assert.ok(content.includes("type: 'blobContainer'"), 'Deployment storage type must be blobContainer');
        assert.ok(content.includes("type: 'SystemAssignedIdentity'"), 'Deployment storage authentication must be SystemAssignedIdentity');
        assert.ok(content.includes('app-packages'), 'Deployment storage must reference app-packages container');

        // Networking assertions
        assert.ok(content.includes('virtualNetworkSubnetId: virtualNetworkSubnetId'), 'Must configure virtualNetworkSubnetId directly under properties');
        assert.strictEqual(content.includes('vnetRouteAllEnabled'), false, 'Must NOT contain legacy vnetRouteAllEnabled in Flex Consumption');

        // Scale & concurrency cost-control assertions
        assert.ok(content.includes('maximumInstanceCount: maximumInstanceCount'), 'Must configure maximumInstanceCount from parameter');
        assert.ok(content.includes('instanceMemoryMB: 2048'), 'Must configure 2048 MB instance memory');
        assert.strictEqual(content.includes('alwaysReady'), false, 'Must NOT configure alwaysReady instances (keep at 0)');

        // Identity-based AzureWebJobsStorage assertions
        assert.ok(content.includes("'AzureWebJobsStorage__accountName'"), 'Must configure AzureWebJobsStorage__accountName');
        assert.ok(content.includes("'AzureWebJobsStorage__credential'"), 'Must configure AzureWebJobsStorage__credential');
        assert.ok(content.includes("'managedidentity'"), "AzureWebJobsStorage__credential must be 'managedidentity'");
        assert.ok(content.includes("'AzureWebJobsStorage__blobServiceUri'"), 'Must configure AzureWebJobsStorage__blobServiceUri');
        assert.strictEqual(content.includes("'AzureWebJobsStorage__queueServiceUri'"), false, 'Must NOT configure AzureWebJobsStorage__queueServiceUri when Queue storage is unused');
        assert.strictEqual(content.includes("'AzureWebJobsStorage__tableServiceUri'"), false, 'Must NOT configure AzureWebJobsStorage__tableServiceUri when Table storage is unused');

        // Elimination of legacy SMB and deprecated settings
        assert.strictEqual(content.includes('WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'), false, 'Must NOT contain WEBSITE_CONTENTAZUREFILECONNECTIONSTRING');
        assert.strictEqual(content.includes('WEBSITE_CONTENTSHARE'), false, 'Must NOT contain WEBSITE_CONTENTSHARE');
        assert.strictEqual(content.includes('linuxFxVersion'), false, 'Must NOT contain linuxFxVersion');
        assert.strictEqual(content.includes('WEBSITE_NODE_DEFAULT_VERSION'), false, 'Must NOT contain WEBSITE_NODE_DEFAULT_VERSION');
        assert.strictEqual(content.includes('FUNCTIONS_WORKER_RUNTIME'), false, 'Must NOT contain FUNCTIONS_WORKER_RUNTIME');
        assert.strictEqual(content.includes('listKeys()'), false, 'Must NOT invoke storageAccount.listKeys()');
    });

    test('network.bicep must declare VNet with flex delegation, private endpoint subnet, and private DNS', () => {
        const content = fs.readFileSync(NETWORK_BICEP, 'utf8');

        // Address space and subnets
        assert.ok(content.includes("'10.0.0.0/16'"), 'VNet address space must be 10.0.0.0/16');
        assert.ok(content.includes("'snet-func'"), 'Must declare snet-func subnet');
        assert.ok(content.includes("'10.0.1.0/24'"), 'snet-func prefix must be 10.0.1.0/24');
        assert.ok(content.includes("'Microsoft.App/environments'"), 'snet-func must be delegated to Microsoft.App/environments');

        assert.ok(content.includes("'snet-pe'"), 'Must declare snet-pe subnet');
        assert.ok(content.includes("'10.0.2.0/24'"), 'snet-pe prefix must be 10.0.2.0/24');
        assert.ok(content.includes("privateEndpointNetworkPolicies: 'Disabled'"), 'snet-pe must disable private endpoint network policies');

        // Private DNS and link
        assert.ok(content.includes('privatelink'), 'Must configure privatelink DNS zone');
        assert.ok(content.includes("location: 'global'"), 'Private DNS zone must use global location');
        assert.ok(content.includes('Microsoft.Network/privateDnsZones/virtualNetworkLinks'), 'Must link Private DNS zone to VNet');

        // Private Endpoint and Zone Group
        assert.ok(content.includes("Microsoft.Network/privateEndpoints"), 'Must declare private endpoint');
        assert.ok(content.includes("'sqlServer'"), "Private endpoint group ID must be 'sqlServer'");
        assert.ok(content.includes("Microsoft.Network/privateEndpoints/privateDnsZoneGroups"), 'Must declare private DNS zone group for auto-registration');

        // Outputs
        assert.ok(content.includes('output vnetId string'), 'Must output vnetId');
        assert.ok(content.includes('output functionSubnetId string'), 'Must output functionSubnetId');
        assert.ok(content.includes('output peSubnetId string'), 'Must output peSubnetId');
        assert.ok(content.includes('output privateEndpointId string'), 'Must output privateEndpointId');
        assert.ok(content.includes('output privateDnsZoneId string'), 'Must output privateDnsZoneId');
    });

    test('storage.bicep must provision app-packages container and export blob endpoint', () => {
        const content = fs.readFileSync(STORAGE_BICEP, 'utf8');

        assert.ok(content.includes("'app-packages'"), 'storage.bicep must define app-packages container');
        assert.ok(content.includes("publicAccess: 'None'"), 'app-packages container must have publicAccess: None');
        assert.ok(content.includes('output appPackagesContainerName string'), 'Must output appPackagesContainerName');
        assert.ok(content.includes('output primaryBlobEndpoint string'), 'Must output primaryBlobEndpoint');
    });

    test('storageRole.bicep must assign Storage Blob Data Owner, strictly excluding unnecessary Queue and Table roles', () => {
        const content = fs.readFileSync(STORAGE_ROLE_BICEP, 'utf8');

        // Storage Blob Data Owner: b7e6dc6d-f1e8-4753-8033-0f276bb0955b
        assert.ok(content.includes('b7e6dc6d-f1e8-4753-8033-0f276bb0955b'), 'Must assign Storage Blob Data Owner role');
        assert.strictEqual(content.includes('b7e6dc6d-f1e8-47e4-8453-bf8d29193791'), false, 'Must NOT contain incorrect Storage Blob Data Owner GUID');

        // Storage Queue Data Contributor: must NOT be assigned (least-privilege: zero queue triggers/bindings)
        assert.strictEqual(content.includes('974c5e8b-45b9-4653-a4e6-074d817470fb'), false, 'Must NOT assign Storage Queue Data Contributor role');
        assert.strictEqual(content.includes('queueRoleAssignment'), false, 'Must NOT declare queueRoleAssignment');

        // Storage Table Data Contributor: must NOT be assigned (least-privilege: timer triggers use blob leases)
        assert.strictEqual(content.includes('0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'), false, 'Must NOT assign Storage Table Data Contributor role');
        assert.strictEqual(content.includes('tableRoleAssignment'), false, 'Must NOT declare tableRoleAssignment');

        // Scoped to storageAccount
        assert.ok(content.includes('scope: storageAccount'), 'Role assignments must be scoped to storageAccount');
        assert.ok(content.includes("principalType: 'ServicePrincipal'"), 'principalType must be ServicePrincipal');
    });

    test('main.bicep must orchestrate network, storage roles, and output private endpoint resources', () => {
        const content = fs.readFileSync(MAIN_BICEP, 'utf8');

        assert.ok(content.includes("module networkModule 'modules/network.bicep'"), 'main.bicep must orchestrate networkModule');
        assert.ok(content.includes("module storageRoleModule 'modules/storageRole.bicep'"), 'main.bicep must orchestrate storageRoleModule');
        assert.ok(content.includes('storageAccountBlobUri: storageModule.outputs.primaryBlobEndpoint'), 'main.bicep must pass primaryBlobEndpoint to functionAppModule');
        assert.ok(content.includes('virtualNetworkSubnetId: networkModule.outputs.functionSubnetId'), 'main.bicep must pass functionSubnetId to functionAppModule');
        assert.ok(content.includes('publicNetworkAccess: sqlPublicNetworkAccess'), 'main.bicep must pass sqlPublicNetworkAccess to sqlModule');
        assert.ok(content.includes('maximumInstanceCount: maximumInstanceCount'), 'main.bicep must pass maximumInstanceCount to functionAppModule');
        assert.ok(content.includes('param maximumInstanceCount int = 3'), 'main.bicep must default maximumInstanceCount to 3');

        assert.ok(content.includes('output vnetId string'), 'main.bicep must output vnetId');
        assert.ok(content.includes('output vnetName string'), 'main.bicep must output vnetName');
        assert.ok(content.includes('output privateEndpointId string'), 'main.bicep must output privateEndpointId');
        assert.ok(content.includes('output privateDnsZoneId string'), 'main.bicep must output privateDnsZoneId');
        assert.ok(content.includes('output appPackagesContainer string'), 'main.bicep must output appPackagesContainer');

        // Parameter file verification
        const paramContent = fs.readFileSync(MAIN_BICEPPARAM, 'utf8');
        assert.ok(paramContent.includes("using './main.bicep'"), "main.bicepparam must declare using './main.bicep'");
        assert.ok(paramContent.includes("readEnvironmentVariable('ACCESSLEASE_SQL_ADMIN_PASSWORD')"), 'main.bicepparam must source sqlAdminPassword from ACCESSLEASE_SQL_ADMIN_PASSWORD');
        assert.ok(paramContent.includes("readEnvironmentVariable('ACCESSLEASE_SQL_CLIENT_IP', '')"), 'main.bicepparam must source clientIpAddress from ACCESSLEASE_SQL_CLIENT_IP with empty fallback');
    });
});
