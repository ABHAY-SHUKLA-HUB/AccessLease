@description('The Azure region into which the networking resources should be deployed.')
param location string = resourceGroup().location

@description('Name of the Virtual Network.')
param vnetName string

@description('Resource ID of the Azure SQL Logical Server for Private Endpoint association.')
param sqlServerId string

@description('Resource tags.')
param tags object = {}

// Virtual Network with dedicated subnets for Flex Consumption Integration and Private Endpoints
resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'snet-func'
        properties: {
          addressPrefix: '10.0.1.0/24'
          delegations: [
            {
              name: 'flexDelegation'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'snet-pe'
        properties: {
          addressPrefix: '10.0.2.0/24'
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

// Azure Private DNS Zone for Azure SQL Server
// Note: Location must be 'global' for Microsoft.Network/privateDnsZones
var privateDnsZoneName = 'privatelink${environment().suffixes.sqlServerHostname}'

resource privateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: privateDnsZoneName
  location: 'global'
  tags: tags
}

// Virtual Network Link connecting the VNet to the Private DNS Zone
resource privateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZone
  name: '${vnetName}-link'
  location: 'global'
  tags: tags
  properties: {
    virtualNetwork: {
      id: virtualNetwork.id
    }
    registrationEnabled: false
  }
}

// Azure Private Endpoint for Azure SQL Server
resource sqlPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: take('pe-sql-${vnetName}', 64)
  location: location
  tags: tags
  properties: {
    subnet: {
      id: '${virtualNetwork.id}/subnets/snet-pe'
    }
    privateLinkServiceConnections: [
      {
        name: 'plsc-sql'
        properties: {
          privateLinkServiceId: sqlServerId
          groupIds: [
            'sqlServer'
          ]
        }
      }
    ]
  }
}

// Private DNS Zone Group linking Private Endpoint to Private DNS Zone
// This automatically registers and manages the SQL A-record in the private DNS zone
resource privateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-05-01' = {
  parent: sqlPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'sqlDnsConfig'
        properties: {
          privateDnsZoneId: privateDnsZone.id
        }
      }
    ]
  }
}

// Outputs
output vnetId string = virtualNetwork.id
output vnetName string = virtualNetwork.name
output functionSubnetId string = '${virtualNetwork.id}/subnets/snet-func'
output peSubnetId string = '${virtualNetwork.id}/subnets/snet-pe'
output privateEndpointId string = sqlPrivateEndpoint.id
output privateDnsZoneId string = privateDnsZone.id
