# Security Copilot Agent - Setup Checklist

## Prerequisites ✅

- [ ] Azure CLI installed and authenticated (`az login`)
- [ ] Python 3.9+ installed
- [ ] Git repository created on GitHub
- [ ] Active Azure subscription with appropriate permissions

## Quick Setup (5 minutes)

### 1. Run Auto-Discovery Script

**Windows:**
```powershell
.\scripts\azure-discovery.ps1
```

**Linux/macOS:**
```bash
chmod +x scripts/azure-discovery.sh
./scripts/azure-discovery.sh
```

This script will:
- ✅ Check Azure authentication
- ✅ Create service principal with required permissions
- ✅ Discover/create Azure SQL resources (optional)
- ✅ Discover/create Key Vault (optional)  
- ✅ Discover monitoring resources (optional)
- ✅ Generate `.env` file with all discovered values

### 2. Complete GitHub Configuration

The script will generate most values, but you need to manually add:

```bash
# Edit .env file and add:
GITHUB_TOKEN=your-github-personal-access-token
GITHUB_REPO_OWNER=your-github-username
GITHUB_REPO_NAME=your-repo-name
```

**Get GitHub Token:**
1. Go to: https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select scopes: `repo`, `issues`, `pull_requests`
4. Copy the token and add to `.env`

### 3. Test Configuration

```bash
python -m security_copilot.cli status
```

### 4. Run Your First Scan

```bash
python -m security_copilot.cli scan --subscription-id YOUR_SUBSCRIPTION_ID
```

## Manual Setup (if auto-discovery fails)

### Required Azure Keys

| Key | Command to Get | Example Value |
|-----|----------------|---------------|
| `AZURE_SUBSCRIPTION_ID` | `az account show --query id -o tsv` | `12345678-1234-1234-1234-123456789012` |
| `AZURE_TENANT_ID` | `az account show --query tenantId -o tsv` | `87654321-4321-4321-4321-210987654321` |
| `AZURE_CLIENT_ID` | Create service principal (see below) | `11111111-2222-3333-4444-555555555555` |
| `AZURE_CLIENT_SECRET` | Create service principal (see below) | `abc123def456ghi789jkl012mno345pqr678` |

### Create Service Principal

```bash
# Create with required permissions
az ad sp create-for-rbac \
    --name "security-copilot-sp" \
    --role "Reader" \
    --scopes "/subscriptions/$(az account show --query id -o tsv)" \
    --query "{appId:appId,password:password,tenant:tenant}" \
    -o table

# Add Network Contributor role
az role assignment create \
    --assignee <APP_ID_FROM_ABOVE> \
    --role "Network Contributor" \
    --scope "/subscriptions/$(az account show --query id -o tsv)"

# Add Security Reader role  
az role assignment create \
    --assignee <APP_ID_FROM_ABOVE> \
    --role "Security Reader" \
    --scope "/subscriptions/$(az account show --query id -o tsv)"
```

### Optional: Create Azure SQL Database

```bash
# Create resource group
az group create --name security-copilot-rg --location "East US"

# Create SQL server
az sql server create \
    --name security-copilot-sql-$(date +%s) \
    --resource-group security-copilot-rg \
    --location "East US" \
    --admin-user sqladmin \
    --admin-password "SecurePassword123!"

# Create database
az sql db create \
    --server <SERVER_NAME_FROM_ABOVE> \
    --resource-group security-copilot-rg \
    --name security-copilot \
    --service-objective Basic

# Allow Azure services
az sql server firewall-rule create \
    --server <SERVER_NAME_FROM_ABOVE> \
    --resource-group security-copilot-rg \
    --name "AllowAzureServices" \
    --start-ip-address 0.0.0.0 \
    --end-ip-address 0.0.0.0
```

## Environment Variables Checklist

### Required ✅
- [ ] `AZURE_SUBSCRIPTION_ID` - Your Azure subscription ID
- [ ] `AZURE_CLIENT_ID` - Service principal app ID  
- [ ] `AZURE_CLIENT_SECRET` - Service principal password
- [ ] `AZURE_TENANT_ID` - Azure AD tenant ID
- [ ] `GITHUB_TOKEN` - GitHub personal access token
- [ ] `GITHUB_REPO_OWNER` - GitHub username/organization
- [ ] `GITHUB_REPO_NAME` - GitHub repository name

### Optional (but recommended) 📋
- [ ] `AZURE_SQL_SERVER` - SQL server hostname
- [ ] `AZURE_SQL_DATABASE` - Database name (usually "security-copilot")
- [ ] `AZURE_SQL_USERNAME` - SQL admin username
- [ ] `AZURE_SQL_PASSWORD` - SQL admin password
- [ ] `KEY_VAULT_URI` - Azure Key Vault URL
- [ ] `APPLICATIONINSIGHTS_CONNECTION_STRING` - Application Insights connection
- [ ] `LOG_ANALYTICS_WORKSPACE_ID` - Log Analytics workspace ID

## Verification Commands

```bash
# Check Azure authentication
az account show

# Test Azure SDK connection
python -c "from azure.identity import DefaultAzureCredential; from azure.mgmt.network import NetworkManagementClient; print('✅ Azure SDK working')"

# Test GitHub connection  
python -c "from github import Github; g = Github('YOUR_TOKEN'); print(f'✅ GitHub: {g.get_user().login}')"

# Test SQL connection (if configured)
python -c "import pyodbc; print('✅ SQL driver available')"

# Full application test
python -m security_copilot.cli status
```

## Common Issues & Solutions

### ❌ "DefaultAzureCredential failed to retrieve a token"
**Solution:** Check service principal credentials in `.env` file

### ❌ "Bad credentials" (GitHub)
**Solution:** Verify GitHub token and ensure it has required scopes

### ❌ "Cannot open server" (SQL)
**Solution:** Check firewall rules and connection string

### ❌ "Insufficient privileges"
**Solution:** Ensure service principal has Reader, Network Contributor, and Security Reader roles

### ❌ Import errors
**Solution:** Install dependencies: `pip install -r requirements.txt`

## Security Checklist

### Development ✅
- [ ] `.env` file in `.gitignore`
- [ ] Service principal has minimum required permissions
- [ ] GitHub token has minimum required scopes
- [ ] SQL firewall properly configured

### Production ✅
- [ ] Use Azure Managed Identity instead of service principal
- [ ] Store secrets in Azure Key Vault
- [ ] Enable Azure Security Center
- [ ] Set up monitoring and alerting
- [ ] Implement secret rotation

## Next Steps

1. **Test the scanner:**
   ```bash
   python -m security_copilot.cli scan --subscription-id YOUR_SUBSCRIPTION_ID --dry-run
   ```

2. **Enable automation:**
   ```bash
   # Edit .env file
   AUTO_REMEDIATION_ENABLED=true
   CREATE_ISSUES_FOR_FINDINGS=true
   CREATE_PRS_FOR_AUTO_FIX=true
   ```

3. **Deploy to Azure:**
   ```bash
   cd deployment
   ./deploy.sh  # Linux/macOS
   # or
   .\deploy.ps1  # Windows PowerShell
   ```

4. **Set up CI/CD:**
   - Push code to GitHub
   - GitHub Actions will automatically run on commits
   - Configure deployment secrets in repository settings

5. **Monitor and maintain:**
   - Check Azure portal for Application Insights telemetry
   - Review GitHub issues created by the scanner
   - Monitor SQL database for audit logs
   - Set up alerts for critical security findings

## Getting Help

- **Documentation:** Check `docs/` directory for detailed guides
- **Logs:** Check application logs for detailed error messages
- **Azure Portal:** Monitor resources and costs
- **GitHub Issues:** Track security findings and remediations

## Useful Commands Reference

```bash
# Azure CLI helpers
az account list-locations -o table
az group list -o table  
az resource list -o table

# Application commands
python -m security_copilot.cli --help
python -m security_copilot.cli scan --help
python -m security_copilot.cli honeypot --help

# Docker commands (for deployment)
docker build -t security-copilot .
docker run --env-file .env security-copilot
```
