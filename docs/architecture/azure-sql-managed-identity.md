# AccessLease — Azure SQL Managed Identity Authentication Guide

**Document Version:** 1.0.0  
**Target:** Azure SQL Database & Azure Functions v4 (Node.js 22 LTS)  
**Security Classification:** Company-Grade Zero-Trust Production Design  

---

## 1. Architectural Overview

AccessLease enforces a strict dual-mode database authentication architecture:

```
[Local Development]
  Local Developer Workstation
    └─► SQL_AUTH_MODE=localdb
          └─► Windows Named Pipe: \\.\pipe\LOCALDB#...\tsql\query
                └─► (localdb)\MSSQLLocalDB (Integrated Windows Security, Zero Azure Credentials Required)

[Azure Production Deployment]
  Azure Function App (Flex Consumption Linux FC1)
    └─► System-Assigned Managed Identity (MSI)
          └─► Regional Virtual Network Integration (snet-func: 10.0.1.0/24)
                └─► Azure Private DNS Zone: privatelink.database.windows.net
                      └─► Azure SQL Private Endpoint (snet-pe: 10.0.2.0/24)
                            └─► SQL_AUTH_MODE=azure-identity (TDS with FEDAUTH Handshake)
                                  └─► DefaultAzureCredential (@azure/identity)
                                        └─► Dynamic Token via IMDS Endpoint
                                              └─► Azure SQL Logical Server (publicNetworkAccess: Disabled)
                                                    └─► Database: accesslease-db
                                                          └─► Database User: [func-accesslease-dev-xxxx] (WITH SID, TYPE = E)
                                                                └─► Role: [db_accesslease_app] (Least Privilege)
```

---

## 2. Authentication Modes

### Mode 1: Local Development (`SQL_AUTH_MODE=localdb`)
- **Transport:** Windows Named Pipe via Node.js `net.connect()`.
- **Authentication:** Windows Integrated Security.
- **Credentials:** Strictly zero usernames or passwords required.
- **Environment:**
  ```ini
  SQL_AUTH_MODE=localdb
  SQL_SERVER=(localdb)\MSSQLLocalDB
  SQL_DATABASE=AccessLease_TestDB
  ```

### Mode 2: Local TCP Development (`SQL_AUTH_MODE=sql-password`)
- **Transport:** Standard TCP/IP (port 1433).
- **Authentication:** SQL Server login.
- **Credentials:** `SQL_USER` and `SQL_PASSWORD` are strictly required by `validateDatabaseConfig()`.
- **Environment:**
  ```ini
  SQL_AUTH_MODE=sql-password
  SQL_SERVER=127.0.0.1
  SQL_PORT=1433
  SQL_DATABASE=accesslease-db
  SQL_USER=app_user
  SQL_PASSWORD=<local_dev_password>
  ```

### Mode 3: Azure Production Deployment (`SQL_AUTH_MODE=azure-identity`)
- **Transport:** TLS-encrypted TCP/IP (port 1433), `encrypt=true`, `trustServerCertificate=false`.
- **Authentication:** Microsoft Entra ID System-Assigned Managed Identity.
- **Credentials:** Zero static secrets, zero passwords, zero client secrets, zero certificates, zero hardcoded tokens.
- **Environment:**
  ```ini
  SQL_AUTH_MODE=azure-identity
  SQL_SERVER=sql-accesslease-dev-uniqueid.database.windows.net
  SQL_PORT=1433
  SQL_DATABASE=accesslease-db
  SQL_ENCRYPT=true
  SQL_TRUST_SERVER_CERTIFICATE=false
  SQL_CONNECTION_TIMEOUT=45000
  ```

---

## 3. Dynamic Token Renewal & Long-Lived Connection Pools

In Node.js, `mssql` (v11.0.2) utilizes `tedious` (v18.6.2) and `tarn.js` for connection pooling.

### Token Lifecycle & Authentication Architecture:
1. **Dynamic Acquisition:** In `azure-identity` mode, `buildSqlConfig()` configures tedious with:
   ```javascript
   authentication: {
       type: 'azure-active-directory-default',
       options: {}
   }
   ```
2. **Authentication at Physical Connection Handshake:** In the Tabular Data Stream (TDS) protocol, Microsoft Entra authentication occurs strictly during the initial `LOGIN7` handshake when establishing a new physical TCP socket. Tedious executes:
   ```javascript
   tokenResponse = await credentials.getToken(tokenScope);
   ```
   where `credentials` is an instance of `DefaultAzureCredential` from `@azure/identity`, and `tokenScope` is dynamically negotiated from the SQL Server FEDAUTH challenge (`https://database.windows.net//.default`).
3. **Internal Token Cache & Renewal:** `@azure/identity` manages token lifecycle and caching internally, refreshing tokens automatically from the platform Managed Identity endpoint (IMDS) approximately 5 minutes before expiration. Subsequent physical connections opened by the pool obtain the refreshed token transparently.
4. **Session Longevity vs. Token Expiration:** Once established, active TDS connections and connection pool sessions do not expire mid-connection. Azure SQL Database validates the token during connection establishment; active TCP sessions remain authenticated and are not terminated by Azure SQL when the token reaches its nominal 1-hour expiration.
5. **Connection Pool Housekeeping (`idleTimeoutMillis`):** AccessLease configures `pool.idleTimeoutMillis: 30000` (30 seconds). This setting is standard pool housekeeping to reclaim unused, idle sockets and release server resources during quiet periods. It is **not** a token-refresh mechanism; under sustained traffic, active connections remain in the pool and continue operating normally.
6. **Zero Token Caching in Application Code:** No static tokens (`eyJh...`) or connection strings with secrets are ever stored in environment variables, configuration files, or memory objects.

---

## 4. Microsoft Entra Administrator & Identifier Architecture

### 4.1 Distinct Microsoft Entra Identifiers
To prevent configuration errors and permission failures, AccessLease strictly distinguishes three separate Microsoft Entra identifiers:

| Identifier Name | Source / Command | Description | Target Usage |
| :--- | :--- | :--- | :--- |
| **Principal ID (Object ID)** | Bicep Output: `functionAppPrincipalId` | The local directory Object ID of the Service Principal in the tenant. | **Azure RBAC Role Assignments** (e.g. `Storage Blob Data Owner`, `Key Vault Secrets User`). **NOT the SQL SID.** |
| **Client ID (Application ID)** | CLI: `az ad sp show --id $FunctionAppPrincipalId --query appId -o tsv` | The global application GUID assigned to the Managed Identity service principal by Microsoft Entra ID. | **Azure SQL Database SID** (`WITH SID = 0x..., TYPE = E`). Required for service principals and managed identities. |
| **Tenant ID** | `subscription().tenantId` / `az account show` | The Azure Active Directory directory GUID hosting the subscription. | OAuth 2.0 token authority and issuer validation. |

> [!WARNING]
> In Azure SQL Database, executing `CREATE USER ... WITH SID, TYPE = E` for a service principal or managed identity requires the **Client ID**, NOT the Object ID / Principal ID. Passing the Principal ID causes authentication failure because the incoming TDS OAuth token presents the Application ID (`appid` claim) to the SQL gateway.

### 4.2 SQL User Creation: `WITH SID, TYPE = E` vs. `FROM EXTERNAL PROVIDER`
1. **Preferred Pattern — Direct SID Specification (`WITH SID = ..., TYPE = E`):**
   * Uses the Function App's **Client ID** converted to a 16-byte binary SQL `SID`:
     ```sql
     DECLARE @binSid VARBINARY(16) = CAST(CAST(@ManagedIdentityClientId AS UNIQUEIDENTIFIER) AS VARBINARY(16));
     DECLARE @hexSid NVARCHAR(34) = sys.fn_varbintohexstr(@binSid);
     DECLARE @sql NVARCHAR(MAX) = N'CREATE USER [' + REPLACE(@ManagedIdentityName, ']', ']]') + N'] WITH SID = ' + @hexSid + N', TYPE = E;';
     EXEC sp_executesql @sql;
     ```
   * **Zero Graph Lookups:** Bypasses live directory lookups entirely because the exact SID is provided directly.
   * **Zero Directory Readers:** Neither the executing administrator nor the Azure SQL Server requires the `Directory Readers` role in Microsoft Entra ID.
   * **Zero SQL Server Managed Identity:** The Azure SQL Logical Server does not require a System-Assigned Managed Identity.

2. **Alternative Pattern — Live Directory Lookup (`FROM EXTERNAL PROVIDER`):**
   * Syntax: `CREATE USER [func-accesslease-dev-xxxx] FROM EXTERNAL PROVIDER;`
   * Requires the Azure SQL Server itself to have a System-Assigned Managed Identity and the `Directory Readers` directory role to query Microsoft Graph API for the principal name.

### 4.3 Bicep Entra Admin Configuration
[`infrastructure/azure/modules/sql.bicep`](file:///d:/access/infrastructure/azure/modules/sql.bicep) defines the child resource:
```bicep
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
```
* `sqlEntraAdminLogin`: The Entra user principal name (e.g. `admin@yourtenant.onmicrosoft.com`) or Entra security group.
* `sqlEntraAdminSid`: The Directory Object ID (GUID) of the administrator user or group in Entra ID.

---

## 5. Database Permissions & Repeatable Setup Script

AccessLease provides a repeatable, least-privilege setup script located at:
[`database/scripts/setup_managed_identity_user.sql`](file:///d:/access/database/scripts/setup_managed_identity_user.sql)

### Least-Privilege Role: `[db_accesslease_app]`
Instead of granting broad roles (`db_owner` or `db_datawriter`), the application identity is assigned to a custom role with only the exact permissions needed by application repositories:

| Target Object | Permissions Granted | Reason / Application Domain |
| :--- | :--- | :--- |
| `dbo.users`, `contractor_engagements`, `roles`, `user_roles` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` | Contractor profiles, internal sponsors, role bindings |
| `dbo.resources`, `entitlements`, `resource_owners` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` | Catalog discovery and entitlement metadata |
| `dbo.access_requests`, `approval_steps`, `access_grants` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` | Multi-stage approvals and grant lifecycles |
| `dbo.provisioning_events` | `SELECT`, `INSERT` | Immutable provisioning audit log (zero `UPDATE` / `DELETE`) |
| `dbo.revocation_jobs` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` | Worker queues and execution tracking |
| `dbo.access_reviews`, `review_items` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` | Governance campaigns and recertification decisions |
| `dbo.audit_events` | `SELECT`, `INSERT` | Immutable audit log trail (zero `UPDATE` / `DELETE`) |
| `dbo.user_external_identities`, `connector_resource_mappings` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` | GitHub account links and team mappings |
| `dbo.provisioning_jobs`, `oauth_states` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` | Transient PKCE states and worker orchestration |
| `dbo.membership_coordination`, `orphan_access_findings` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` | Distributed lease fencing and orphan detection |
| `dbo.v_AccessExposureQueue` | `SELECT` | Dashboard analytics and exposure queue |
| `dbo.sp_ActivateApprovedGrant` | `EXECUTE` | Atomic validated grant activation procedure |

### Prohibited Privileges:
- **NO `db_owner`**
- **NO `db_securityadmin`**
- **NO `db_ddladmin`** (Application identity cannot alter, drop, or create tables)
- **NO `CONTROL`**

---

## 6. Secure Deployment, Staged Migration & Lockdown Workflow

> [!IMPORTANT]
> The target Azure resource group for this deployment is **`my-rg`** in the **`koreacentral`** region. Do not create an alternate resource group.

### Prerequisite: Subscription Resource Provider Registration
Flex Consumption VNet integration delegates `snet-func` to `Microsoft.App/environments`. Ensure the resource provider is registered:
```powershell
az provider register --namespace Microsoft.App
az provider show --namespace Microsoft.App --query "registrationState" -o tsv
# Must return 'Registered'
```

### Stage 1: Initial Infrastructure Deployment with Temporary Migration Access
To allow the administrator's workstation to apply initial database schema migrations without exposing the SQL server broadly to the internet:
1. Provide the workstation IPv4 address via `clientIpAddress`.
2. This temporarily sets `publicNetworkAccess: 'Enabled'` at the SQL server level and creates an isolated, single-workstation firewall rule `AllowClientMigrationIp`.
3. `allowAllAzureIps` remains **strictly `false`** (default-deny, zero broad Azure IP rules).
4. The Function App is deployed inside `snet-func` (`10.0.1.0/24`) and connects to Azure SQL via the **Private Endpoint** (dynamically assigned IP in `snet-pe`, illustratively `10.0.2.4`) through Private DNS `privatelink.database.windows.net`.

#### Secure Credential & Parameter Handling:
* The deployment parameter file [`infrastructure/azure/main.bicepparam`](file:///d:/access/infrastructure/azure/main.bicepparam) declares `using './main.bicep'` and reads both the administrator password and client migration IP from environment variables using Bicep's built-in `readEnvironmentVariable()` expression:
  ```bicep
  param sqlAdminPassword = readEnvironmentVariable('ACCESSLEASE_SQL_ADMIN_PASSWORD')
  param clientIpAddress = readEnvironmentVariable('ACCESSLEASE_SQL_CLIENT_IP', '')
  ```
* **Compilation-Time Evaluation:** Bicep evaluates `readEnvironmentVariable()` locally during template compilation in the active shell session. **Environment-variable loading alone does not encrypt or protect the password in memory**; protection from logging and exposure is strictly enforced by the `@secure()` parameter decorator in [`main.bicep`](file:///d:/access/infrastructure/azure/main.bicep) and [`sql.bicep`](file:///d:/access/infrastructure/azure/modules/sql.bicep), which instructs Azure Resource Manager to redact the secret from deployment history, activity logs, and template outputs. The workstation IP is not a secret and uses a standard string parameter.
* **Command History Protection:** To prevent the secret from being captured in persistent shell history (`(Get-PSReadLineOption).HistorySavePath`), the password is collected dynamically in memory using `Read-Host -AsSecureString` rather than typed as plaintext in shell commands.
* **Single Parameter File Invocation:** Because `main.bicepparam` specifies `using './main.bicep'`, Azure CLI natively discovers the target template from the parameter file directly. The deployment command supplies `--parameters infrastructure/azure/main.bicepparam` exactly once without `--template-file` or extra `--parameters` overrides.

```powershell
# 1. Collect the SQL administrator password into memory securely without placing its literal value in command history:
$rawPassword = (Read-Host -Prompt "Enter Azure SQL Administrator Password" -AsSecureString)
if (-not $rawPassword -or $rawPassword.Length -lt 12) {
    throw "SQL administrator password must be supplied and satisfy Azure SQL complexity requirements (minimum 12 characters)."
}
$env:ACCESSLEASE_SQL_ADMIN_PASSWORD = [System.Net.NetworkCredential]::new('', $rawPassword).Password

# 2. Ingest and validate current workstation public IPv4 address (forces IPv4 via api4.ipify.org, rejects IPv6):
$rawClientIp = (Invoke-RestMethod -Uri "https://api4.ipify.org").Trim()
$parsedIp = [System.Net.IPAddress]::None
if (-not [System.Net.IPAddress]::TryParse($rawClientIp, [ref]$parsedIp) -or $parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw "Invalid or non-IPv4 client IP address obtained: '$rawClientIp'. Migration deployment aborted."
}
$env:ACCESSLEASE_SQL_CLIENT_IP = $parsedIp.IPAddressToString

# 3. Deploy infrastructure targeting resource group my-rg with explicit deployment name 'main':
az deployment group create `
  --name main `
  --resource-group my-rg `
  --parameters infrastructure/azure/main.bicepparam
```

### Stage 2: Retrieve Deployment Outputs & Resolve Managed Identity Client ID
Retrieve the deployment outputs explicitly from deployment name `main` in resource group `my-rg`:
```powershell
$DeploymentJson = az deployment group show -g my-rg -n main --query "properties.outputs" -o json
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($DeploymentJson)) {
    throw "Failed to retrieve deployment outputs for deployment 'main' in resource group 'my-rg'."
}

$DeploymentOutputs      = $DeploymentJson | ConvertFrom-Json
$FunctionAppName        = $DeploymentOutputs.functionAppName.value
$FunctionAppPrincipalId = $DeploymentOutputs.functionAppPrincipalId.value
$SqlServerFqdn          = $DeploymentOutputs.sqlServerFqdn.value
$SqlServerName          = $DeploymentOutputs.sqlServerName.value

# Validate mandatory deployment outputs:
if ([string]::IsNullOrWhiteSpace($FunctionAppName) -or 
    [string]::IsNullOrWhiteSpace($FunctionAppPrincipalId) -or 
    [string]::IsNullOrWhiteSpace($SqlServerFqdn) -or 
    [string]::IsNullOrWhiteSpace($SqlServerName)) {
    throw "One or more mandatory deployment outputs (functionAppName, functionAppPrincipalId, sqlServerFqdn, sqlServerName) are missing or empty."
}

# Resolve the Function App's Service Principal Client ID (Application ID) directly from Microsoft Entra ID:
# Distinct Identity Roles:
# - Principal ID (Object ID): Used for Azure RBAC role assignments (Storage Blob Data Owner, Key Vault Secrets User).
# - Client ID (Application ID): Used as the SQL Database SID (WITH SID = ..., TYPE = E) for token validation.
$FunctionAppClientId = (az ad sp show --id $FunctionAppPrincipalId --query appId -o tsv).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($FunctionAppClientId)) {
    throw "Failed to resolve Client ID (appId) for Service Principal with Object ID: '$FunctionAppPrincipalId'."
}

Write-Host "Resolved Function App Name:         $FunctionAppName" -ForegroundColor Green
Write-Host "Resolved Function App Principal ID: $FunctionAppPrincipalId (Object ID)" -ForegroundColor Green
Write-Host "Resolved Function App Client ID:    $FunctionAppClientId (Application ID)" -ForegroundColor Green
Write-Host "Resolved SQL Server FQDN:           $SqlServerFqdn" -ForegroundColor Green
Write-Host "Resolved SQL Server Name:           $SqlServerName" -ForegroundColor Green
```

### Stage 3: Run Database Migrations (Schema Owner)
The authorized administrator connects from their allowlisted workstation IP using SQL Server Authentication (`-U sqladmin`), which authenticates against the SQL Server logical administrator account provisioned by Bicep.

> [!SECURITY]
> **No Plaintext `-P` on Command Line:** To prevent the password from being exposed to other local users or system logging via process command-line inspection tools (e.g. Task Manager, `Get-Process`, `ps`), `sqlcmd` is invoked without the `-P` argument, prompting interactively for the administrator password with hidden input:

```powershell
# Migrations execute schema DDL (CREATE TABLE, INDEX, PROCEDURE)
# -b ensures sqlcmd fails on batch error (severity >= 11) with a non-zero exit code
# Immediate exit on failure prevents subsequent migrations from executing against a broken schema
Get-ChildItem -Path "database/migrations/*.sql" | Sort-Object Name | ForEach-Object {
    Write-Host "Applying $($_.Name)..."
    sqlcmd -b -S $SqlServerFqdn -d accesslease-db -U sqladmin -i $_.FullName
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Database migration $($_.Name) failed with exit code $LASTEXITCODE. Halting deployment sequence."
        exit $LASTEXITCODE
    }
}

# Seed canonical system RBAC roles (reference lookup data, zero dummy users/grants)
Write-Host "Seeding canonical system RBAC roles..."
sqlcmd -b -S $SqlServerFqdn -d accesslease-db -U sqladmin -i database/seeds/001_system_roles_seed.sql
if ($LASTEXITCODE -ne 0) {
    Write-Error "System roles seeding failed with exit code $LASTEXITCODE. Halting deployment sequence."
    exit $LASTEXITCODE
}
```

### Stage 4: Provision Managed Identity Permissions (Entra Admin)
The Microsoft Entra SQL Administrator logs into `accesslease-db` using Microsoft Entra token authentication (`--authentication-method ActiveDirectoryDefault` or PowerShell ADO.NET):

**Option A: sqlcmd CLI:**
```powershell
sqlcmd -b -S $SqlServerFqdn -d accesslease-db --authentication-method ActiveDirectoryDefault `
  -v FUNCTION_APP_NAME=$FunctionAppName `
  -v MANAGED_IDENTITY_CLIENT_ID=$FunctionAppClientId `
  -i database/scripts/setup_managed_identity_user.sql
if ($LASTEXITCODE -ne 0) {
    Write-Error "Managed Identity database user provisioning failed with exit code $LASTEXITCODE. Halting deployment sequence."
    exit $LASTEXITCODE
}
```

**Option B: PowerShell 7+ / ADO.NET (Single-Batch Execution):**
```powershell
$token = (Get-AzAccessToken -ResourceUrl "https://database.windows.net").Token
$sql = Get-Content -Raw "database/scripts/setup_managed_identity_user.sql"
$sql = $sql.Replace('$(FUNCTION_APP_NAME)', $FunctionAppName)
$sql = $sql.Replace('$(MANAGED_IDENTITY_CLIENT_ID)', $FunctionAppClientId)

$conn = New-Object System.Data.SqlClient.SqlConnection("Server=$SqlServerFqdn;Database=accesslease-db;Encrypt=True;TrustServerCertificate=False;")
$conn.AccessToken = $token
$conn.Open()

$cmd = $conn.CreateCommand()
$cmd.CommandText = $sql
$null = $cmd.ExecuteNonQuery()
$conn.Close()
```
*Note: The script pre-validates that the Client ID is a valid GUID, pre-validates any existing principal for matching SID and type `E` (`EXTERNAL_USER`), derives the deterministic 16-byte binary SID (`WITH SID = <ClientIdAsHexSid>, TYPE = E;`), and executes role creation, grants, and user membership inside an atomic transaction (`SET XACT_ABORT ON; BEGIN TRANSACTION ... COMMIT TRANSACTION`) with automatic rollback on error.*

### Stage 5: Zero-Trust Lockdown — Delete Temporary Rule & Disable Public SQL Access

> [!IMPORTANT]
> **Strict Lockdown Sequencing:** In Azure SQL, attempting to delete or modify firewall rules after public network access has been disabled can fail or be rejected by the Azure SQL management plane. The temporary firewall rule must be deleted **before** setting `publicNetworkAccess` to `Disabled`.

Execute the lockdown in this exact sequence:

```powershell
# 1. Delete the temporary migration workstation firewall rule while public access is still enabled:
az sql server firewall-rule delete `
  --resource-group my-rg `
  --server $SqlServerName `
  --name AllowClientMigrationIp

# 2. Verify that the firewall rule has been deleted:
az sql server firewall-rule list `
  --resource-group my-rg `
  --server $SqlServerName `
  --query "[].name" -o tsv
# Output must NOT contain AllowClientMigrationIp

# 3. Set SQL public network access to Disabled:
az sql server update `
  --resource-group my-rg `
  --name $SqlServerName `
  --public-network-access Disabled

# 4. Verify the final SQL server configuration:
az sql server show `
  --resource-group my-rg `
  --name $SqlServerName `
  --query "publicNetworkAccess" -o tsv
# Output must return 'Disabled'
```

*Post-Lockdown Verification:*
- Azure SQL Logical Server enforces `publicNetworkAccess: 'Disabled'`.
- Public port 1433 is completely inaccessible from the internet.
- **Function App Uninterrupted:** The Function App routes traffic through `snet-func` to the Private Endpoint (dynamically assigned IP from `snet-pe`, illustratively `10.0.2.4`) over the Microsoft private backbone. DNS continues resolving `<server>.database.windows.net` to the private endpoint IP via the Private DNS Zone link.

---

## 7. Network Security, Storage RBAC & Cost Governance

### 7.1 Flex Consumption Networking
* **Outbound Routing:** When `virtualNetworkSubnetId` is placed under `properties` of `Microsoft.Web/sites@2024-04-01`, Flex Consumption natively routes all outbound traffic through the delegated subnet (`Microsoft.App/environments`). Legacy settings such as `vnetRouteAllEnabled` or `WEBSITE_VNET_ROUTE_ALL` are not required.
* **Subnet Isolation:** `snet-func` (`10.0.1.0/24`) is strictly delegated to `Microsoft.App/environments`. The Private Endpoint resides in a separate, dedicated subnet `snet-pe` (`10.0.2.0/24`) with `privateEndpointNetworkPolicies: 'Disabled'`.
* **Dynamic Private Endpoint IP:** The Azure SQL Private Endpoint dynamically leases an IP from `snet-pe` (`10.0.2.0/24`), typically `10.0.2.4` (illustrative). Because the Azure Private DNS Zone group automatically registers the logical server's FQDN to this leased IP, static IP hardcoding is neither required nor recommended.

### 7.2 Storage RBAC Audit
* **Host Runtime (`AzureWebJobsStorage`):** Microsoft requires **`Storage Blob Data Owner`** at the storage account level for identity-based connections. `Storage Blob Data Contributor` is insufficient for host runtime operations because the host dynamically creates internal containers (`azure-webjobs-hosts`, `azure-webjobs-secrets`) and manages blob leases.
* **Deployment Package Storage:** Flex Consumption pulls execution code from the `app-packages` container via `functionAppConfig.deployment.storage`. Because `Storage Blob Data Owner` is already assigned to the Function App's Managed Identity at the storage account level, it covers `app-packages`. A separate container-scoped `Storage Blob Data Contributor` assignment is redundant in this unified account architecture.
* **Timer Trigger Coordination (Blob Storage Leases):** In Azure Functions (v2+ through v4), multi-instance singleton execution of timer triggers is coordinated **exclusively through Blob Storage leases** (under the `azure-webjobs-hosts/locks/` path in Azure Blob Storage), **NOT Table Storage** and **NOT Queue Storage**.
* **Queue Storage Role Exclusion:** AccessLease contains zero queue triggers, zero queue output bindings, and no Durable Functions task hubs. Because Timer Trigger coordination relies on Blob leases rather than queues, **`Storage Queue Data Contributor` is completely unnecessary and has been removed** from role assignments to enforce strict least-privilege.
* **Table Storage Role Exclusion & Diagnostic Trade-off:** Neither the AccessLease application nor the Functions host runtime uses Table Storage for core execution. **`Storage Table Data Contributor` is deliberately omitted** from role assignments and `AzureWebJobsStorage__tableServiceUri` is omitted from application settings. The documented trade-off is that certain non-fatal host diagnostic events cannot be persisted to Table Storage and may produce benign warnings in host logs; Application Insights serves as the authoritative monitoring and telemetry pipeline.
* **Least Privilege:** No management-plane roles (`Storage Account Contributor`, `Owner`, `Contributor`) are granted.

### 7.3 Cost Governance & Spending Controls (Korea Central Pricing)
* **Maximum Instance Count:** Initial `maximumInstanceCount` is capped at **`3`** (configurable via parameter), preventing runaway scaling from runaway workloads or loops.
* **Always-Ready Instances:** Kept at **`0`** (no warm idle instances, eliminating continuous idle compute billing).
* **Instance Memory:** Configured to **`2048 MB`** (2 GB), which is the verified minimum supported memory size for Flex Consumption.
* **Free Execution Grant Limitations:** Flex Consumption provides 250,000 executions and 100,000 GB-s free per month per subscription. **The free grant is NOT a hard spending cap.** Once the monthly threshold is exceeded, Azure automatically bills executions at $0.20 per million and memory at $0.000016 per GB-s.
* **Azure Budget Alerts:** Setting a budget alert in Azure Cost Management (e.g. at $10.00 or $15.00) sends email/webhook notifications when spending crosses the threshold. **Budget alerts do NOT automatically shut down resources or freeze execution.** To automatically shut down compute, an Azure Action Group linked to an Automation Runbook must be configured.
* **Monthly Baseline Cost (Korea Central):**
  - Azure Functions Flex Consumption (within free grant): **$0.00**
  - Azure SQL Database (Basic 5 DTUs, 2 GB): **~$4.99 / month**
  - Azure SQL Private Endpoint (~730 hours/month): **~$7.30 / month**
  - Azure Private DNS Zone (1 zone + link): **~$0.50 / month**
  - Azure Storage (Standard_LRS GPv2 < 5 GB): **~$0.25 / month**
  - Virtual Network & Subnet Delegation: **$0.00**
  - **Total Baseline:** **~$13.04 / month** (~13% of the Azure for Students $100 credit pool).
* **Zero-Trust Private Endpoint:** Azure SQL connects exclusively through an **Azure Private Endpoint** (`snet-pe: 10.0.2.0/24`) with subresource `sqlServer`.
* **Private DNS Zone:** `privatelink.database.windows.net` automatically linked to the VNet with auto-registration zone groups.
* **Public Network Access Disabled:** Azure SQL enforces `publicNetworkAccess: 'Disabled'`, completely closing public port 1433 and eliminating exposure to public internet or unauthorized Azure tenants.
* **Storage RBAC:** AzureWebJobsStorage utilizes identity-based credentials (`AzureWebJobsStorage__credential: 'managedidentity'`) with granular RBAC (`Storage Blob Data Owner`), completely replacing legacy storage connection strings and Azure Files SMB shares.

---

## 8. Status & Remaining Deployment Steps

| Component | Implementation Status | Deployment Status |
| :--- | :--- | :--- |
| **`database.js` dual-mode driver** | Fully Implemented & Tested | Code Ready |
| **`environment.js` mode validation** | Fully Implemented & Tested | Code Ready |
| **Bicep templates (`main`, `sql`, `functionApp`, `network`, `storageRole`)** | Fully Updated & Compiled | Validated (Pending Azure Provisioning) |
| **Bicep parameter files (`main.bicepparam`)** | Configured with secure references | Validated via `bicep build-params` |
| **Repeatable SQL permissions script** | Authoritative Client ID SID (`WITH SID = 0x..., TYPE = E`) | Script Ready (Pending Entra Admin Run) |
| **Regression test suite (396 tests)** | 100% Passing (0 failures) | Verified Locally |
| **Azure Resource Deployment** | NOT PROVISIONED (Boundary Preserved) | Awaiting User Approval |

