using './main.bicep'

// AccessLease — Production / Staging Deployment Parameters
param appNamePrefix = 'accesslease'
param environment = 'dev'
param location = 'koreacentral'

param sqlAdminLogin = 'sqladmin'
param sqlAdminPassword = readEnvironmentVariable('ACCESSLEASE_SQL_ADMIN_PASSWORD')

param sqlDatabaseSku = 'Basic'
param sqlDatabaseTier = 'Basic'

// SQL Server Firewall Security Parameters
// SECURITY: allowAllAzureIps disabled by default to prevent non-subscription Azure traffic
param allowAllAzureIps = false
param clientIpAddress = readEnvironmentVariable('ACCESSLEASE_SQL_CLIENT_IP', '')

// Microsoft Entra ID Dual App Registration Parameters
param entraTenantId = '6e020805-70a1-44ae-a6c4-9f7dbc605905'
param entraSpaClientId = '934b724c-19ac-45a7-b463-a2f31a9fa9fb'
param entraApiClientId = 'aa3b2968-201b-4cbf-b650-abc839c2ad4c'
param entraApiAudience = 'api://aa3b2968-201b-4cbf-b650-abc839c2ad4c'
param entraApiScope = 'api://aa3b2968-201b-4cbf-b650-abc839c2ad4c/access_as_user'

// Microsoft Entra SQL Administrator Parameters (Optional during initial IaC provisioning)
param sqlEntraAdminLogin = ''
param sqlEntraAdminSid = ''

