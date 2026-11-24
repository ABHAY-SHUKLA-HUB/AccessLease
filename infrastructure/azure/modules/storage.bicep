@description('The Azure region into which the storage resources should be deployed.')
param location string = resourceGroup().location

@description('Globally unique name for the Azure Storage Account (3-24 lowercase alphanumeric characters).')
param storageAccountName string

@description('Storage Account SKU. Default is Standard_LRS for cost optimization.')
@allowed([
  'Standard_LRS'
  'Standard_GRS'
  'Standard_ZRS'
])
param storageSku string = 'Standard_LRS'

@description('Resource tags.')
param tags object = {}

// Storage Account: General Purpose v2 with HTTPS enforced and public blob access disabled
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: storageSku
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    accessTier: 'Hot'
    encryption: {
      services: {
        blob: {
          enabled: true
          keyType: 'Account'
        }
        file: {
          enabled: true
          keyType: 'Account'
        }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

// Blob Service
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

// Container 1: Revocation Proof Receipts (Cryptographic evidence of deprovisioning)
resource revocationProofsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'revocation-proofs'
  properties: {
    publicAccess: 'None'
  }
}

// Container 2: Contractor Compliance Documents (SOWs, agreements, legal waivers)
resource contractorDocumentsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'contractor-documents'
  properties: {
    publicAccess: 'None'
  }
}

// Container 3: Flex Consumption Application Deployment Packages
resource appPackagesContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'app-packages'
  properties: {
    publicAccess: 'None'
  }
}

// Outputs
output storageAccountId string = storageAccount.id
output storageAccountName string = storageAccount.name
output primaryBlobEndpoint string = storageAccount.properties.primaryEndpoints.blob
output revocationProofsContainerName string = revocationProofsContainer.name
output contractorDocumentsContainerName string = contractorDocumentsContainer.name
output appPackagesContainerName string = appPackagesContainer.name

