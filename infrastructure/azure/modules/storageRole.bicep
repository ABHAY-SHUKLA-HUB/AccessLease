@description('Name of the existing Storage Account to which the role assignments should be applied.')
param storageAccountName string

@description('Principal ID of the Function App System-Assigned Managed Identity.')
param principalId string

// Built-in Azure RBAC Role IDs for Azure Storage Data Plane operations:
// 1. Storage Blob Data Owner: b7e6dc6d-f1e8-4753-8033-0f276bb0955b
//    Mandatory for AzureWebJobsStorage host runtime. Microsoft explicitly requires Storage Blob Data Owner
//    (not Contributor) at the storage account level because the host dynamically creates containers and acquires
//    blob leases (e.g. azure-webjobs-hosts/locks for multi-instance singleton execution and timer triggers).
//    Because this is assigned at the storage account scope, it also grants necessary read access to the
//    Flex Consumption deployment container (app-packages). A separate Storage Blob Data Contributor assignment
//    on app-packages is therefore redundant in this unified storage account architecture.
var storageBlobDataOwnerRoleId = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'

// LEAST-PRIVILEGE AUDIT NOTES:
// 2. Queue Storage (Storage Queue Data Contributor):
//    OMITTED. AccessLease contains zero queue triggers, zero queue bindings, and zero Durable Functions task hubs.
//    Timer triggers coordinate exclusively through Blob Storage leases, NOT queue storage. Therefore, Queue
//    permissions are completely unnecessary for this application and omitted to preserve strict least-privilege.
//
// 3. Table Storage (Storage Table Data Contributor):
//    OMITTED INTENTIONALLY. Neither the application nor the Functions v4 Linux host requires Table Storage for
//    core execution or timer triggers. The documented trade-off is that certain non-fatal host diagnostic events
//    cannot be persisted to Table Storage and may produce warnings in host logs, but Application Insights provides
//    the authoritative telemetry pipeline.

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

resource blobRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(principalId)) {
  name: guid(storageAccount.id, principalId, storageBlobDataOwnerRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleId)
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}

output blobRoleAssignmentId string = !empty(principalId) ? blobRoleAssignment.id : ''
