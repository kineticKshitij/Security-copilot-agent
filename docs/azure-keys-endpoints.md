# Azure Keys and Endpoints Reference

This document provides a comprehensive guide to all Azure keys, endpoints, and configuration required for the Security Copilot Agent project.

## Quick Start

Run the discovery script to automatically find and configure your Azure resources:

```powershell
# Windows PowerShell
.\scripts\azure-discovery.ps1

# Or run specific sections
.\scripts\azure-discovery.ps1 sp        # Service Principal only
.\scripts\azure-discovery.ps1 sql       # SQL resources only
.\scripts\azure-discovery.ps1 kv        # Key Vault only
```

```bash
# Linux/macOS
./scripts/azure-discovery.sh

# Or run specific sections
./scripts/azure-discovery.sh sp         # Service Principal only
./scripts/azure-discovery.sh sql        # SQL resources only
./scripts/azure-discovery.sh kv         # Key Vault only
```

## Required Azure Resources and Keys

### 1. Azure Authentication (REQUIRED)

| Environment Variable | Description | How to Get | Azure CLI Command |
|---------------------|-------------|------------|-------------------|
| `AZURE_SUBSCRIPTION_ID` | Your Azure subscription ID | Azure Portal → Subscriptions | `az account show --query id -o tsv` |
| `AZURE_TENANT_ID` | Your Azure Active Directory tenant ID | Azure Portal → Azure Active Directory | `az account show --query tenantId -o tsv` |
| `AZURE_CLIENT_ID` | Service Principal Application ID | Created by discovery script | `az ad sp create-for-rbac --name security-copilot-sp` |
| `AZURE_CLIENT_SECRET` | Service Principal Password | Created by discovery script | Generated during SP creation |

**Required Service Principal Permissions:**
- `Reader` on subscription (for resource discovery)
- `Network Contributor` on subscription (for NSG scanning)
- `Security Reader` on subscription (for security assessments)

### 2. Azure SQL Database (OPTIONAL - for audit logging)

| Environment Variable | Description | How to Get | Azure CLI Command |
|---------------------|-------------|------------|-------------------|
| `AZURE_SQL_SERVER` | SQL Server hostname | Azure Portal → SQL servers | `az sql server list --query "[0].fullyQualifiedDomainName" -o tsv` |
| `AZURE_SQL_DATABASE` | Database name | Usually "security-copilot" | `az sql db list --server <server-name> --resource-group <rg>` |
| `AZURE_SQL_USERNAME` | SQL admin username | Set during creation | Provided during server creation |
| `AZURE_SQL_PASSWORD` | SQL admin password | Set during creation | Provided during server creation |
| `AZURE_SQL_CONNECTION_STRING` | Full connection string | Generated automatically | See connection string format below |

**SQL Connection String Format:**
```
Driver={ODBC Driver 18 for SQL Server};Server=tcp:<server>.database.windows.net,1433;Database=security-copilot;Uid=<username>;Pwd=<password>;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;
```

### 3. Azure Key Vault (RECOMMENDED - for secure secret storage)

| Environment Variable | Description | How to Get | Azure CLI Command |
|---------------------|-------------|------------|-------------------|
| `KEY_VAULT_URI` | Key Vault endpoint URL | Azure Portal → Key vaults | `az keyvault show --name <vault-name> --query properties.vaultUri -o tsv` |

### 4. Application Insights (OPTIONAL - for monitoring)

| Environment Variable | Description | How to Get | Azure CLI Command |
|---------------------|-------------|------------|-------------------|
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Application Insights connection string | Azure Portal → Application Insights | `az monitor app-insights component show --app <name> --resource-group <rg> --query connectionString -o tsv` |
| `APPLICATIONINSIGHTS_INSTRUMENTATION_KEY` | Legacy instrumentation key | Azure Portal → Application Insights | `az monitor app-insights component show --app <name> --resource-group <rg> --query instrumentationKey -o tsv` |

### 5. Log Analytics Workspace (OPTIONAL - for log aggregation)

| Environment Variable | Description | How to Get | Azure CLI Command |
|---------------------|-------------|------------|-------------------|
| `LOG_ANALYTICS_WORKSPACE_ID` | Workspace Customer ID | Azure Portal → Log Analytics workspaces | `az monitor log-analytics workspace show --workspace-name <name> --resource-group <rg> --query customerId -o tsv` |

## GitHub Integration (REQUIRED)

| Environment Variable | Description | How to Get |
|---------------------|-------------|------------|
| `GITHUB_TOKEN` | Personal Access Token | GitHub Settings → Developer settings → Personal access tokens |
| `GITHUB_REPO_OWNER` | GitHub username or organization | Your GitHub profile |
| `GITHUB_REPO_NAME` | Repository name | Your repository name |

**Required GitHub Token Scopes:**
- `repo` (Full control of private repositories)
- `public_repo` (Access public repositories)
- `admin:repo_hook` (Admin access to repository hooks)

## Azure Resource Creation Commands

### Create Service Principal with Required Permissions

```bash
# Create service principal
az ad sp create-for-rbac \
    --name "security-copilot-sp" \
    --role "Reader" \
    --scopes "/subscriptions/<subscription-id>"

# Add additional permissions
az role assignment create \
    --assignee <app-id> \
    --role "Network Contributor" \
    --scope "/subscriptions/<subscription-id>"

az role assignment create \
    --assignee <app-id> \
    --role "Security Reader" \
    --scope "/subscriptions/<subscription-id>"
```

### Create Azure SQL Database

```bash
# Create resource group
az group create --name security-copilot-rg --location "East US"

# Create SQL server
az sql server create \
    --name security-copilot-sql \
    --resource-group security-copilot-rg \
    --location "East US" \
    --admin-user sqladmin \
    --admin-password <secure-password>

# Create database
az sql db create \
    --server security-copilot-sql \
    --resource-group security-copilot-rg \
    --name security-copilot \
    --service-objective Basic

# Configure firewall for Azure services
az sql server firewall-rule create \
    --server security-copilot-sql \
    --resource-group security-copilot-rg \
    --name "AllowAzureServices" \
    --start-ip-address 0.0.0.0 \
    --end-ip-address 0.0.0.0
```

### Create Key Vault

```bash
# Create Key Vault
az keyvault create \
    --name security-copilot-kv \
    --resource-group security-copilot-rg \
    --location "East US"

# Set access policy for service principal
az keyvault set-policy \
    --name security-copilot-kv \
    --spn <service-principal-app-id> \
    --secret-permissions get list set delete
```

### Create Application Insights

```bash
# Create Application Insights
az monitor app-insights component create \
    --app security-copilot-ai \
    --location "East US" \
    --resource-group security-copilot-rg \
    --application-type web
```

### Create Log Analytics Workspace

```bash
# Create Log Analytics Workspace
az monitor log-analytics workspace create \
    --workspace-name security-copilot-la \
    --resource-group security-copilot-rg \
    --location "East US"
```

## Environment Variable Priority

The application loads configuration in this order (later sources override earlier ones):

1. **Default values** (in `config.py`)
2. **Environment variables** (from `.env` file or system)
3. **Azure Key Vault** (if `KEY_VAULT_URI` is provided)
4. **Azure Managed Identity** (if `USE_MANAGED_IDENTITY=true`)

## Security Best Practices

### For Development
- Use service principal authentication
- Store secrets in `.env` file (never commit to git)
- Use separate subscriptions/tenants for dev/prod

### For Production
- Use Azure Managed Identity instead of service principal
- Store secrets in Azure Key Vault
- Enable Azure Security Center monitoring
- Rotate credentials regularly

## Managed Identity Configuration (Production Recommended)

When deploying to Azure App Service or Container Instances, use Managed Identity:

```bash
# Enable system-assigned managed identity on App Service
az webapp identity assign --name <app-name> --resource-group <resource-group>

# Get the managed identity principal ID
PRINCIPAL_ID=$(az webapp identity show --name <app-name> --resource-group <resource-group> --query principalId -o tsv)

# Assign required roles to managed identity
az role assignment create \
    --assignee $PRINCIPAL_ID \
    --role "Reader" \
    --scope "/subscriptions/<subscription-id>"

az role assignment create \
    --assignee $PRINCIPAL_ID \
    --role "Network Contributor" \
    --scope "/subscriptions/<subscription-id>"

az role assignment create \
    --assignee $PRINCIPAL_ID \
    --role "Security Reader" \
    --scope "/subscriptions/<subscription-id>"
```

Set `USE_MANAGED_IDENTITY=true` in your environment variables.

## Troubleshooting Common Issues

### Authentication Errors

1. **"DefaultAzureCredential failed to retrieve a token"**
   - Ensure service principal has correct permissions
   - Verify client ID, secret, and tenant ID are correct
   - Check if managed identity is properly configured (for Azure deployments)

2. **"Insufficient privileges to complete the operation"**
   - Verify service principal has required roles assigned
   - Check the scope of role assignments (subscription level required)

### SQL Connection Issues

1. **"Cannot open server"**
   - Ensure firewall rules allow your IP or Azure services
   - Verify server name and credentials
   - Check if database exists

2. **"Login timeout expired"**
   - Check network connectivity
   - Verify connection string format
   - Ensure SQL server is running

### GitHub Integration Issues

1. **"Bad credentials"**
   - Verify GitHub token is valid and has required scopes
   - Check if token has expired

2. **"Not Found"**
   - Verify repository owner and name are correct
   - Ensure token has access to the repository

## Sample .env File

```bash
# Azure Authentication
AZURE_SUBSCRIPTION_ID=12345678-1234-1234-1234-123456789012
AZURE_CLIENT_ID=87654321-4321-4321-4321-210987654321
AZURE_CLIENT_SECRET=your-client-secret-here
AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111

# Use Managed Identity (for Azure deployments)
USE_MANAGED_IDENTITY=false

# GitHub Configuration
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GITHUB_REPO_OWNER=yourusername
GITHUB_REPO_NAME=security-copilot-agent

# Azure SQL (Optional)
AZURE_SQL_SERVER=security-copilot-sql.database.windows.net
AZURE_SQL_DATABASE=security-copilot
AZURE_SQL_USERNAME=sqladmin
AZURE_SQL_PASSWORD=YourSecurePassword123!

# Key Vault (Optional)
KEY_VAULT_URI=https://security-copilot-kv.vault.azure.net/

# Monitoring (Optional)
APPLICATIONINSIGHTS_CONNECTION_STRING=InstrumentationKey=12345678-1234-1234-1234-123456789012;IngestionEndpoint=https://eastus-8.in.applicationinsights.azure.com/
LOG_ANALYTICS_WORKSPACE_ID=12345678-1234-1234-1234-123456789012

# Application Configuration
LOG_LEVEL=INFO
SCAN_INTERVAL_HOURS=24
AUTO_REMEDIATION_ENABLED=false
MAX_CONCURRENT_SCANS=5
```

## Testing Your Configuration

Once you have configured your environment variables, test the setup:

```bash
# Test Azure authentication
python -c "from security_copilot.config import Config; print('Azure auth:', Config().azure_subscription_id)"

# Test GitHub connection
python -c "from security_copilot.github_integration import GitHubIntegration; gi = GitHubIntegration(); print('GitHub:', gi.test_connection())"

# Test SQL connection (if configured)
python -c "from security_copilot.database import DatabaseManager; dm = DatabaseManager(); print('SQL:', dm.test_connection())"

# Run a full status check
python -m security_copilot.cli status
```

## Additional Resources

- [Azure CLI Installation](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- [Azure SDK for Python](https://docs.microsoft.com/en-us/azure/developer/python/)
- [GitHub Personal Access Tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
- [Azure Managed Identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)
- [Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/)
