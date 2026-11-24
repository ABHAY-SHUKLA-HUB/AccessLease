@description('The Azure region into which Key Vault should be deployed.')
param location string = resourceGroup().location

@description('Globally unique name for the Azure Key Vault (3-24 alphanumeric characters and hyphens).')
param keyVaultName string

@description('Resource tags.')
param tags object = {}

// Azure Key Vault (Standard Tier with Azure RBAC Authorization)
resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// Outputs
output keyVaultId string = keyVault.id
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
