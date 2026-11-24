@description('The Azure region into which the SQL resources should be deployed.')
param location string = resourceGroup().location

@description('Globally unique name for the Azure SQL Server (1-63 lowercase alphanumeric characters and hyphens).')
param sqlServerName string

@description('Name of the Azure SQL Database.')
param sqlDatabaseName string = 'accesslease-db'

@description('Administrator username for Azure SQL Server.')
param sqlAdminLogin string = 'sqladmin'

@description('Administrator password for Azure SQL Server.')
@secure()
param sqlAdminPassword string

@description('The SKU name of the Azure SQL Database. Default is Basic for cost-conscious academic projects.')
@allowed([
  'Basic'
  'S0'
  'S1'
  'GP_S_Gen5_1'
])
param sqlDatabaseSku string = 'Basic'

@description('The SKU tier of the Azure SQL Database.')
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

@description('Whether public network access is allowed for the SQL Server. Defaults to Enabled ONLY if clientIpAddress is specified for initial migration, otherwise Disabled.')
@allowed([
  'Enabled'
  'Disabled'
])
param publicNetworkAccess string = !empty(clientIpAddress) ? 'Enabled' : 'Disabled'

@description('Login name / UPN / group name for the Microsoft Entra SQL administrator.')
param entraAdminLogin string = ''

@description('Object ID (Principal ID) of the Microsoft Entra SQL administrator user or group.')
param entraAdminSid string = ''

@description('Tenant ID for Microsoft Entra SQL administrator. Defaults to the subscription tenant ID.')
param entraAdminTenantId string = subscription().tenantId

@description('Resource tags.')
param tags object = {}

// Azure SQL Logical Server
resource sqlServer 'Microsoft.Sql/servers@2022-05-01-preview' = {
  name: sqlServerName
  location: location
  tags: tags
  properties: {
    administratorLogin: sqlAdminLogin
    administratorLoginPassword: sqlAdminPassword
    version: '12.0'
    minimalTlsVersion: '1.2'
    publicNetworkAccess: publicNetworkAccess
  }
}

// Azure SQL Database (3NF Relational Authority)
resource sqlDatabase 'Microsoft.Sql/servers/databases@2022-05-01-preview' = {
  parent: sqlServer
  name: sqlDatabaseName
  location: location
  tags: tags
  sku: {
    name: sqlDatabaseSku
    tier: sqlDatabaseTier
  }
  properties: {
    collation: 'SQL_Latin1_General_CP1_CI_AS'
    maxSizeBytes: sqlDatabaseSku == 'Basic' ? 2147483648 : 34359738368 // 2 GB for Basic, 32 GB for standard/general purpose
    zoneRedundant: false
    readScale: 'Disabled'
  }
}

// Firewall Rule: AllowAllWindowsAzureIps (0.0.0.0 - 0.0.0.0)
// SECURITY WARNING:
// Setting startIpAddress and endIpAddress to '0.0.0.0' enables the Azure SQL "Allow Azure services
// and resources to access this server" rule. This does NOT restrict access to resources in your
// subscription; any Azure tenant or resource can reach the SQL gateway (port 1433) and attempt authentication.
// This rule is DISABLED by default (allowAllAzureIps = false).
// If enabled for this student deployment, access is guarded strictly by SQL password complexity.
// PRODUCTION DESIGN: For enterprise zero-trust deployments, deploy Azure Functions on an App Service
// or Elastic Premium plan with Virtual Network Integration and connect to Azure SQL via an Azure Private
// Endpoint, eliminating public gateway access entirely.
resource allowAzureIpsRule 'Microsoft.Sql/servers/firewallRules@2022-05-01-preview' = if (allowAllAzureIps) {
  parent: sqlServer
  name: 'AllowAllWindowsAzureIps'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

// Firewall Rule: AllowClientMigrationIp (Administrator / Deployment Runner Workstation)
// NARROW CONNECTIVITY DESIGN: Allows only the specific developer/administrator workstation IPv4
// address through the firewall to execute database schema migrations and seed scripts securely.
// Only provisioned when clientIpAddress is non-empty AND publicNetworkAccess is 'Enabled'.
resource allowClientMigrationIpRule 'Microsoft.Sql/servers/firewallRules@2022-05-01-preview' = if (!empty(clientIpAddress) && publicNetworkAccess == 'Enabled') {
  parent: sqlServer
  name: 'AllowClientMigrationIp'
  properties: {
    startIpAddress: clientIpAddress
    endIpAddress: clientIpAddress
  }
}

// Microsoft Entra Administrator for Azure SQL Server
// Crucial: Required for an Entra administrator to log in and execute 'CREATE USER [<identity>] FROM EXTERNAL PROVIDER'
resource sqlEntraAdmin 'Microsoft.Sql/servers/administrators@2022-05-01-preview' = if (!empty(entraAdminLogin) && !empty(entraAdminSid)) {
  parent: sqlServer
  name: 'ActiveDirectory'
  properties: {
    administratorType: 'ActiveDirectory'
    login: entraAdminLogin
    sid: entraAdminSid
    tenantId: !empty(entraAdminTenantId) ? entraAdminTenantId : subscription().tenantId
  }
}

// Outputs
output sqlServerId string = sqlServer.id
output sqlServerName string = sqlServer.name
output sqlServerFqdn string = sqlServer.properties.fullyQualifiedDomainName
output sqlDatabaseId string = sqlDatabase.id
output sqlDatabaseName string = sqlDatabase.name

