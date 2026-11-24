@description('The Azure region into which the Function App should be deployed.')
param location string = resourceGroup().location

@description('Globally unique name for the Azure Function App (2-60 alphanumeric characters and hyphens).')
param functionAppName string

@description('Name of the App Service Hosting Plan.')
param hostingPlanName string

@description('Name of the associated Storage Account.')
param storageAccountName string

@description('Blob endpoint URI of the storage account (e.g. https://<account>.blob.core.windows.net/).')
param storageAccountBlobUri string

@description('Resource ID of the virtual network subnet delegated to Microsoft.App/environments for Flex Consumption integration.')
param virtualNetworkSubnetId string

@description('Maximum instance count for scaling. Set to 2-3 for academic project cost control.')
@minValue(1)
@maxValue(100)
param maximumInstanceCount int = 3

@description('Fully Qualified Domain Name of Azure SQL Server.')
param sqlServerFqdn string

@description('Name of Azure SQL Database.')
param sqlDatabaseName string

@description('Microsoft Entra Directory (Tenant) ID.')
param entraTenantId string = ''

@description('Microsoft Entra Frontend SPA Client ID.')
param entraSpaClientId string = ''

@description('Microsoft Entra Backend Web API Client ID.')
param entraApiClientId string = ''

@description('Microsoft Entra Backend Web API Audience.')
param entraApiAudience string = ''

@description('Microsoft Entra Backend Web API Delegated Scope.')
param entraApiScope string = ''

@description('Frontend SPA Redirect URI.')
param entraRedirectUri string = ''

@description('Allowed CORS origins for the Function App API.')
param corsAllowedOrigins array = [
  'http://localhost:7071'
  'http://localhost:3000'
  'http://127.0.0.1:5500'
]

@description('Application Insights Connection String for monitoring and diagnostics.')
param appInsightsConnectionString string = ''

@description('Resource tags.')
param tags object = {}

// App Service Plan (Flex Consumption Plan - Linux FC1 Tier for enterprise zero-trust serverless execution)
resource hostingPlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: hostingPlanName
  location: location
  tags: tags
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
    family: 'FC'
    capacity: 0
  }
  kind: 'functionapp,linux'
  properties: {
    reserved: true // Crucial: Designates Linux App Service Plan
  }
}

// Azure Function App (Flex Consumption Node.js 22 LTS on Linux, System-Assigned Managed Identity, VNet Integration, HTTPS-Only)
resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: hostingPlan.id
    reserved: true // Required for Linux sites
    httpsOnly: true
    clientAffinityEnabled: false
    virtualNetworkSubnetId: virtualNetworkSubnetId
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storageAccountBlobUri}app-packages'
          authentication: {
            type: 'SystemAssignedIdentity'
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: maximumInstanceCount
        instanceMemoryMB: 2048
      }
      runtime: {
        name: 'node'
        version: '22'
      }
    }
    siteConfig: {
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      cors: {
        allowedOrigins: corsAllowedOrigins
        supportCredentials: true
      }
      appSettings: [
        {
          name: 'AzureWebJobsStorage__accountName'
          value: storageAccountName
        }
        {
          name: 'AzureWebJobsStorage__credential'
          value: 'managedidentity'
        }
        {
          name: 'AzureWebJobsStorage__blobServiceUri'
          value: storageAccountBlobUri
        }
        {
          name: 'NODE_ENV'
          value: 'production'
        }
        {
          name: 'SQL_AUTH_MODE'
          value: 'azure-identity'
        }
        {
          name: 'SQL_SERVER'
          value: sqlServerFqdn
        }
        {
          name: 'SQL_DATABASE'
          value: sqlDatabaseName
        }
        {
          name: 'SQL_PORT'
          value: '1433'
        }
        {
          name: 'SQL_ENCRYPT'
          value: 'true'
        }
        {
          name: 'SQL_TRUST_SERVER_CERTIFICATE'
          value: 'false'
        }
        {
          name: 'SQL_CONNECTION_TIMEOUT'
          value: '45000'
        }
        {
          name: 'ENTRA_TENANT_ID'
          value: entraTenantId
        }
        {
          name: 'ENTRA_SPA_CLIENT_ID'
          value: entraSpaClientId
        }
        {
          name: 'ENTRA_API_CLIENT_ID'
          value: entraApiClientId
        }
        {
          name: 'ENTRA_API_AUDIENCE'
          value: entraApiAudience
        }
        {
          name: 'ENTRA_API_SCOPE'
          value: entraApiScope
        }
        {
          name: 'ENTRA_REDIRECT_URI'
          value: entraRedirectUri
        }
        {
          name: 'AZURE_STORAGE_ACCOUNT_NAME'
          value: storageAccountName
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsightsConnectionString
        }
      ]
    }
  }
}

// Outputs
output functionAppId string = functionApp.id
output functionAppName string = functionApp.name
output functionAppDefaultHostName string = functionApp.properties.defaultHostName
output functionAppPrincipalId string = functionApp.identity.principalId
