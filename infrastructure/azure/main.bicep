@description('Project name prefix for all provisioned resources.')
@minLength(3)
@maxLength(15)
param appNamePrefix string = 'accesslease'

@description('Target deployment environment.')
@allowed([
  'dev'
  'test'
  'prod'
])
param environment string = 'dev'

@description('Primary Azure region for all regional resources.')
param location string = resourceGroup().location

@description('Azure SQL Server administrator login username.')
param sqlAdminLogin string = 'sqladmin'

@description('Azure SQL Server administrator password. Must satisfy SQL Server password complexity requirements.')
@secure()
param sqlAdminPassword string

@description('SKU for Azure SQL Database. Default is Basic for cost-effective academic deployment.')
@allowed([
  'Basic'
  'S0'
  'S1'
  'GP_S_Gen5_1'
])
param sqlDatabaseSku string = 'Basic'

@description('Tier for Azure SQL Database.')
@allowed([
  'Basic'
  'Standard'
  'GeneralPurpose'
])
param sqlDatabaseTier string = 'Basic'

@description('SECURITY WARNING: Explicit opt-in to permit Azure-internal traffic (firewall rule 0.0.0.0). When true, this allows network connections from ANY Azure resource across ANY subscription or tenant. Disabled by default (false). Only enable for student/dev consumption plan if VNet/Private Endpoint is not deployed.')
param allowAllAzureIps bool = false

@description('Optional client IPv4 address of the developer/administrator workstation allowed through the firewall to run database migrations.')
param clientIpAddress string = ''

@description('Whether public network access is allowed for the SQL Server. Defaults to Enabled only if clientIpAddress is provided for initial migration; set to Disabled for production zero-trust lockdown.')
@allowed([
  'Enabled'
  'Disabled'
])
param sqlPublicNetworkAccess string = !empty(clientIpAddress) ? 'Enabled' : 'Disabled'

@description('Maximum instance count for Function App scaling. Defaults to 3 for academic cost control.')
@minValue(1)
@maxValue(100)
param maximumInstanceCount int = 3

@description('Login name / UPN / group name for the Microsoft Entra SQL administrator.')
param sqlEntraAdminLogin string = ''

@description('Object ID (Principal ID) of the Microsoft Entra SQL administrator user or group.')
param sqlEntraAdminSid string = ''

@description('Tenant ID for Microsoft Entra SQL administrator. Defaults to the subscription tenant ID.')
param sqlEntraAdminTenantId string = subscription().tenantId

@description('Microsoft Entra Directory (Tenant) ID for OAuth 2.0 PKCE authentication.')
param entraTenantId string = ''

@description('Microsoft Entra Frontend SPA Client ID.')
param entraSpaClientId string = ''

@description('Microsoft Entra Backend Web API Client ID.')
param entraApiClientId string = ''

@description('Microsoft Entra Backend Web API Audience (e.g. api://<api-client-id>).')
param entraApiAudience string = ''

@description('Microsoft Entra Backend Web API Delegated Scope (e.g. api://<api-client-id>/access_as_user).')
param entraApiScope string = ''

@description('CORS allowed origins for the Function App API.')
param corsAllowedOrigins array = [
  'http://localhost:7071'
  'http://localhost:3000'
  'http://127.0.0.1:5500'
]

@description('Application Insights Connection String for monitoring telemetry.')
param appInsightsConnectionString string = ''

@description('Standard resource tags applied to all provisioned resources.')
param tags object = {
  Project: 'AccessLease'
  Environment: environment
  ManagedBy: 'Bicep'
  Workload: 'ContractorGovernance'
}

// Deterministic resource naming variables
var uniqueId = uniqueString(resourceGroup().id)
var appNameClean = toLower(replace(replace(appNamePrefix, '-', ''), '_', ''))
var storageAccountName = take('st${appNameClean}${environment}${uniqueId}', 24)
var sqlServerName = take('sql-${appNamePrefix}-${environment}-${uniqueId}', 63)
var sqlDatabaseName = 'accesslease-db'
var keyVaultName = take('kv-${appNamePrefix}-${environment}-${uniqueId}', 24)
var functionAppName = take('func-${appNamePrefix}-${environment}-${uniqueId}', 60)
var hostingPlanName = take('plan-${appNamePrefix}-${environment}-${uniqueId}', 60)
var vnetName = take('vnet-${appNamePrefix}-${environment}-${uniqueId}', 64)

// 1. Storage Account Module (Standard_LRS General Purpose v2 with proof containers and app-packages)
module storageModule 'modules/storage.bicep' = {
  name: 'storageDeployment'
  params: {
    location: location
    storageAccountName: storageAccountName
    storageSku: 'Standard_LRS'
    tags: tags
  }
}

// 2. Azure SQL Database Module (Basic 5 DTU Tier with private endpoint connectivity)
module sqlModule 'modules/sql.bicep' = {
  name: 'sqlDeployment'
  params: {
    location: location
    sqlServerName: sqlServerName
    sqlDatabaseName: sqlDatabaseName
    sqlAdminLogin: sqlAdminLogin
    sqlAdminPassword: sqlAdminPassword
    sqlDatabaseSku: sqlDatabaseSku
    sqlDatabaseTier: sqlDatabaseTier
    allowAllAzureIps: allowAllAzureIps
    clientIpAddress: clientIpAddress
    publicNetworkAccess: sqlPublicNetworkAccess
    entraAdminLogin: sqlEntraAdminLogin
    entraAdminSid: sqlEntraAdminSid
    entraAdminTenantId: sqlEntraAdminTenantId
    tags: tags
  }
}

// 3. Virtual Network & Private Endpoint Module (Regional VNet, Flex Subnet, PE Subnet, Private DNS, SQL PE)
module networkModule 'modules/network.bicep' = {
  name: 'networkDeployment'
  params: {
    location: location
    vnetName: vnetName
    sqlServerId: sqlModule.outputs.sqlServerId
    tags: tags
  }
}

// 4. Azure Key Vault Module (Standard Tier with RBAC Authorization)
module keyVaultModule 'modules/keyVault.bicep' = {
  name: 'keyVaultDeployment'
  params: {
    location: location
    keyVaultName: keyVaultName
    tags: tags
  }
}

// 5. Azure Function App Module (Unified Flex Consumption Host for Backend API + Static Frontend)
module functionAppModule 'modules/functionApp.bicep' = {
  name: 'functionAppDeployment'
  params: {
    location: location
    functionAppName: functionAppName
    hostingPlanName: hostingPlanName
    storageAccountName: storageModule.outputs.storageAccountName
    storageAccountBlobUri: storageModule.outputs.primaryBlobEndpoint
    virtualNetworkSubnetId: networkModule.outputs.functionSubnetId
    maximumInstanceCount: maximumInstanceCount
    sqlServerFqdn: sqlModule.outputs.sqlServerFqdn
    sqlDatabaseName: sqlModule.outputs.sqlDatabaseName
    entraTenantId: entraTenantId
    entraSpaClientId: entraSpaClientId
    entraApiClientId: entraApiClientId
    entraApiAudience: entraApiAudience
    entraApiScope: entraApiScope
    entraRedirectUri: 'https://${functionAppName}.azurewebsites.net/'
    corsAllowedOrigins: corsAllowedOrigins
    appInsightsConnectionString: appInsightsConnectionString
    tags: tags
  }
}

// 6. Key Vault RBAC Role Assignment Module (Assigns Key Vault Secrets User to Function App Identity)
module keyVaultRoleModule 'modules/keyVaultRole.bicep' = {
  name: 'keyVaultRoleDeployment'
  params: {
    keyVaultName: keyVaultModule.outputs.keyVaultName
    principalId: functionAppModule.outputs.functionAppPrincipalId
  }
}

// 7. Storage RBAC Role Assignment Module (Assigns Storage Blob Data Owner to Function App Identity)
module storageRoleModule 'modules/storageRole.bicep' = {
  name: 'storageRoleDeployment'
  params: {
    storageAccountName: storageModule.outputs.storageAccountName
    principalId: functionAppModule.outputs.functionAppPrincipalId
  }
}

// Deployment Outputs
@description('Primary HTTPS endpoint of the unified AccessLease application (Frontend & API).')
output functionAppUrl string = 'https://${functionAppModule.outputs.functionAppDefaultHostName}'

@description('Principal ID (Object ID) of the Function App System-Assigned Managed Identity, used for RBAC role assignments.')
output functionAppPrincipalId string = functionAppModule.outputs.functionAppPrincipalId

@description('Resource name of the Function App.')
output functionAppName string = functionAppModule.outputs.functionAppName

@description('Frontend entry URL (aliased to Function App for backwards compatibility).')
output staticWebAppUrl string = 'https://${functionAppModule.outputs.functionAppDefaultHostName}'

@description('Fully Qualified Domain Name of the Azure SQL Server.')
output sqlServerFqdn string = sqlModule.outputs.sqlServerFqdn

@description('Name of the Azure SQL Logical Server.')
output sqlServerName string = sqlModule.outputs.sqlServerName

@description('Resource ID of the Azure SQL Logical Server.')
output sqlServerId string = sqlModule.outputs.sqlServerId

@description('Name of the 3NF relational database.')
output sqlDatabaseName string = sqlModule.outputs.sqlDatabaseName

@description('Resource ID of the Azure SQL Database.')
output sqlDatabaseId string = sqlModule.outputs.sqlDatabaseId

@description('Resource ID of the Azure Key Vault instance.')
output keyVaultId string = keyVaultModule.outputs.keyVaultId

@description('HTTPS URI of the Azure Key Vault instance.')
output keyVaultUri string = keyVaultModule.outputs.keyVaultUri

@description('Name of the provisioned Azure Storage Account.')
output storageAccountName string = storageModule.outputs.storageAccountName

@description('Name of the blob container storing cryptographic revocation proof receipts.')
output revocationProofsContainer string = storageModule.outputs.revocationProofsContainerName

@description('Name of the blob container storing Flex Consumption application deployment packages.')
output appPackagesContainer string = storageModule.outputs.appPackagesContainerName

@description('Resource ID of the Virtual Network.')
output vnetId string = networkModule.outputs.vnetId

@description('Name of the Virtual Network.')
output vnetName string = networkModule.outputs.vnetName

@description('Resource ID of the Azure SQL Private Endpoint.')
output privateEndpointId string = networkModule.outputs.privateEndpointId

@description('Resource ID of the Azure Private DNS Zone for SQL Server.')
output privateDnsZoneId string = networkModule.outputs.privateDnsZoneId

