@description('The Azure region for the Static Web App hosting. Static Web Apps are globally distributed, but metadata resides in a specific supported region.')
@allowed([
  'eastus2'
  'centralus'
  'westus2'
  'westeurope'
  'eastasia'
])
param location string = 'eastus2'

@description('Globally unique name for the Azure Static Web App (1-40 alphanumeric characters and hyphens).')
param staticWebAppName string

@description('The SKU of the Static Web App. Default is Free for cost-conscious academic projects.')
@allowed([
  'Free'
  'Standard'
])
param sku string = 'Free'

@description('Resource tags.')
param tags object = {}

// Azure Static Web App (Free Tier: Global CDN, Free SSL Certificate, Custom Domain Support)
resource staticWebApp 'Microsoft.Web/staticSites@2023-01-01' = {
  name: staticWebAppName
  location: location
  tags: tags
  sku: {
    name: sku
    tier: sku
  }
  properties: {
    allowConfigFileUpdates: true
    stagingEnvironmentPolicy: 'Enabled'
    enterpriseGradeCdnStatus: 'Disabled'
  }
}

// Outputs
output staticWebAppId string = staticWebApp.id
output staticWebAppName string = staticWebApp.name
output staticWebAppDefaultHostName string = staticWebApp.properties.defaultHostname
output staticWebAppUrl string = 'https://${staticWebApp.properties.defaultHostname}'

