# 🚀 CLI Setup Guide for Security Copilot Agent

This guide provides step-by-step CLI commands to set up your complete CI/CD pipeline for the Security Copilot Agent project.

## 📋 Prerequisites

Before starting, ensure you have these tools installed:

### Windows
```powershell
# Azure CLI
winget install -e --id Microsoft.AzureCLI

# GitHub CLI
winget install --id GitHub.cli

# Docker Desktop
winget install -e --id Docker.DockerDesktop

# Git (if not already installed)
winget install --id Git.Git
```

### Linux (Ubuntu/Debian)
```bash
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# GitHub CLI
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install gh

# Docker
sudo apt-get update
sudo apt-get install docker.io
sudo systemctl start docker
sudo systemctl enable docker
```

### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Azure CLI
brew install azure-cli

# GitHub CLI
brew install gh

# Docker Desktop
brew install --cask docker
```

## 🔧 Step-by-Step Setup

### Step 1: Clone and Navigate to Repository

```bash
git clone https://github.com/kineticKshitij/Security-copilot-agent.git
cd Security-copilot-agent
```

### Step 2: Azure Authentication

```bash
# Login to Azure
az login

# List available subscriptions
az account list --output table

# Set your subscription (replace with your subscription ID)
az account set --subscription "YOUR_SUBSCRIPTION_ID"

# Verify current subscription
az account show
```

### Step 3: GitHub Authentication

```bash
# Login to GitHub
gh auth login

# Follow the prompts to authenticate via web browser or token

# Verify authentication
gh auth status
```

### Step 4: Create Azure Resources

#### Option A: Using PowerShell Script (Windows)
```powershell
# Navigate to scripts directory
cd scripts

# Run the setup script (replace with your subscription ID)
.\setup-azure-resources.ps1 -SubscriptionId "YOUR_SUBSCRIPTION_ID" -ResourceGroupName "security-copilot-rg" -Location "East US" -AppName "security-copilot"
```

#### Option B: Using Bash Script (Linux/Mac)
```bash
# Navigate to scripts directory
cd scripts

# Make script executable (Linux/Mac only)
chmod +x setup-azure-resources.sh

# Run the setup script (replace with your subscription ID)
./setup-azure-resources.sh --subscription-id "YOUR_SUBSCRIPTION_ID" --resource-group "security-copilot-rg" --location "East US" --app-name "security-copilot"
```

#### Option C: Manual Azure CLI Commands

```bash
# Set variables (replace with your values)
SUBSCRIPTION_ID="YOUR_SUBSCRIPTION_ID"
RESOURCE_GROUP="security-copilot-rg"
LOCATION="East US"
APP_NAME="security-copilot"

# Create resource group
az group create --name $RESOURCE_GROUP --location "$LOCATION"

# Create container registry
ACR_NAME="${APP_NAME}acr$RANDOM"
az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic --admin-enabled true

# Create service principal for GitHub Actions
SP_NAME="${APP_NAME}-github-actions-sp"
az ad sp create-for-rbac --name $SP_NAME --role Contributor --scopes "/subscriptions/$SUBSCRIPTION_ID" --output json

# Create SQL Server
SQL_SERVER="${APP_NAME}-sql-$RANDOM"
SQL_USER="sqladmin"
SQL_PASSWORD="SecureCopilot@$RANDOM"
az sql server create --name $SQL_SERVER --resource-group $RESOURCE_GROUP --location "$LOCATION" --admin-user $SQL_USER --admin-password $SQL_PASSWORD

# Create SQL Database
az sql db create --resource-group $RESOURCE_GROUP --server $SQL_SERVER --name "security-copilot-db" --edition Basic

# Allow Azure services to access SQL Server
az sql server firewall-rule create --resource-group $RESOURCE_GROUP --server $SQL_SERVER --name AllowAzureServices --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0

# Create App Service Plan
APP_PLAN="${APP_NAME}-plan"
az appservice plan create --name $APP_PLAN --resource-group $RESOURCE_GROUP --sku B1 --is-linux

# Create App Service
PROD_APP="${APP_NAME}-prod"
az webapp create --resource-group $RESOURCE_GROUP --plan $APP_PLAN --name $PROD_APP --deployment-container-image-name "nginx:latest"

# Create staging resource group
STAGING_RG="${RESOURCE_GROUP}-staging"
az group create --name $STAGING_RG --location "$LOCATION"
```

**📝 Important:** Save the output values from the service principal creation - you'll need them for GitHub secrets!

### Step 5: Configure GitHub Secrets

#### Option A: Using Scripts

**PowerShell (Windows):**
```powershell
.\setup-github-secrets.ps1 `
  -Owner "kineticKshitij" `
  -Repo "Security-copilot-agent" `
  -AzureSubscriptionId "YOUR_SUBSCRIPTION_ID" `
  -AzureClientId "YOUR_CLIENT_ID" `
  -AzureClientSecret "YOUR_CLIENT_SECRET" `
  -AzureTenantId "YOUR_TENANT_ID" `
  -AzureSqlConnectionString "YOUR_CONNECTION_STRING"
```

**Bash (Linux/Mac):**
```bash
./setup-github-secrets.sh \
  --owner "kineticKshitij" \
  --repo "Security-copilot-agent" \
  --azure-subscription-id "YOUR_SUBSCRIPTION_ID" \
  --azure-client-id "YOUR_CLIENT_ID" \
  --azure-client-secret "YOUR_CLIENT_SECRET" \
  --azure-tenant-id "YOUR_TENANT_ID" \
  --azure-sql-connection-string "YOUR_CONNECTION_STRING"
```

#### Option B: Manual GitHub Secret Setup

```bash
# Set individual secrets
gh secret set AZURE_SUBSCRIPTION_ID --repo kineticKshitij/Security-copilot-agent
# Enter your subscription ID when prompted

gh secret set AZURE_CLIENT_ID --repo kineticKshitij/Security-copilot-agent
# Enter your client ID when prompted

gh secret set AZURE_CLIENT_SECRET --repo kineticKshitij/Security-copilot-agent
# Enter your client secret when prompted

gh secret set AZURE_TENANT_ID --repo kineticKshitij/Security-copilot-agent
# Enter your tenant ID when prompted

gh secret set AZURE_SQL_CONNECTION_STRING --repo kineticKshitij/Security-copilot-agent
# Enter your SQL connection string when prompted

# Create Azure credentials JSON (replace with your values)
AZURE_CREDS='{"clientId":"YOUR_CLIENT_ID","clientSecret":"YOUR_CLIENT_SECRET","subscriptionId":"YOUR_SUBSCRIPTION_ID","tenantId":"YOUR_TENANT_ID"}'

echo $AZURE_CREDS | gh secret set AZURE_CREDENTIALS --repo kineticKshitij/Security-copilot-agent
echo $AZURE_CREDS | gh secret set AZURE_CREDENTIALS_PROD --repo kineticKshitij/Security-copilot-agent
```

### Step 6: Create GitHub Environments

```bash
# Create staging environment
curl -X PUT \
  -H "Authorization: token $(gh auth token)" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/kineticKshitij/Security-copilot-agent/environments/staging \
  -d '{"wait_timer":0,"reviewers":[],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'

# Create production environment with approval
USER_ID=$(gh api user --jq '.id')
curl -X PUT \
  -H "Authorization: token $(gh auth token)" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/kineticKshitij/Security-copilot-agent/environments/production \
  -d "{\"wait_timer\":5,\"reviewers\":[{\"type\":\"User\",\"id\":$USER_ID}],\"deployment_branch_policy\":{\"protected_branches\":true,\"custom_branch_policies\":false}}"
```

### Step 7: Update CI/CD Configuration

Edit `.github/workflows/ci-cd.yml` and update these values with your actual resource names:

```yaml
# Update these lines in the deployment sections:
resource-group: security-copilot-rg  # Your resource group name
app-name: security-copilot-prod      # Your app service name
dns-name-label: security-copilot-staging-${{ github.sha }}  # Your ACI name
```

### Step 8: Test the Setup

```bash
# Commit and push changes
git add .
git commit -m "Configure CI/CD pipeline with Azure resources"
git push origin main

# Monitor workflow execution
gh workflow list
gh run list
gh run watch  # Watch the latest run in real-time
```

## 🔍 Verification Commands

### Check Azure Resources
```bash
# List all resources in your resource group
az resource list --resource-group security-copilot-rg --output table

# Check container registry
az acr list --resource-group security-copilot-rg --output table

# Check app service
az webapp list --resource-group security-copilot-rg --output table

# Check SQL server
az sql server list --resource-group security-copilot-rg --output table
```

### Check GitHub Configuration
```bash
# List repository secrets
gh secret list --repo kineticKshitij/Security-copilot-agent

# Check environments
gh api repos/kineticKshitij/Security-copilot-agent/environments

# View workflow runs
gh run list --repo kineticKshitij/Security-copilot-agent

# View specific workflow run
gh run view <RUN_ID> --repo kineticKshitij/Security-copilot-agent
```

### Monitor Application
```bash
# Check app service logs
az webapp log tail --name security-copilot-prod --resource-group security-copilot-rg

# Check container registry repositories
az acr repository list --name YOUR_REGISTRY_NAME

# Test app service endpoint
curl https://security-copilot-prod.azurewebsites.net/health
```

## 🔧 Troubleshooting

### Common Issues and Solutions

1. **Azure CLI not authenticated**
   ```bash
   az login
   az account set --subscription "YOUR_SUBSCRIPTION_ID"
   ```

2. **GitHub CLI not authenticated**
   ```bash
   gh auth login
   gh auth status
   ```

3. **Resource naming conflicts**
   - Add random suffix to resource names
   - Check existing resources: `az resource list --output table`

4. **Permission issues**
   - Ensure service principal has Contributor role
   - Check role assignments: `az role assignment list --assignee YOUR_CLIENT_ID`

5. **Container registry access issues**
   ```bash
   # Enable admin user
   az acr update --name YOUR_REGISTRY_NAME --admin-enabled true
   
   # Get login credentials
   az acr credential show --name YOUR_REGISTRY_NAME
   ```

6. **SQL Database connection issues**
   ```bash
   # Check firewall rules
   az sql server firewall-rule list --resource-group security-copilot-rg --server YOUR_SQL_SERVER
   
   # Add your IP if needed
   az sql server firewall-rule create --resource-group security-copilot-rg --server YOUR_SQL_SERVER --name AllowMyIP --start-ip-address YOUR_IP --end-ip-address YOUR_IP
   ```

## 📚 Useful References

- [Azure CLI Documentation](https://docs.microsoft.com/en-us/cli/azure/)
- [GitHub CLI Documentation](https://cli.github.com/manual/)
- [GitHub Actions Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [Azure Service Principal](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
- [GitHub Environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment)

## 🚀 Quick Commands Reference

```bash
# Azure login and setup
az login
az account set --subscription "YOUR_SUBSCRIPTION_ID"

# GitHub authentication
gh auth login
gh auth status

# View workflows
gh workflow list
gh run list
gh run watch

# Update secrets
gh secret set SECRET_NAME --repo kineticKshitij/Security-copilot-agent

# Check Azure resources
az resource list --resource-group security-copilot-rg --output table

# Monitor app logs
az webapp log tail --name security-copilot-prod --resource-group security-copilot-rg
```

This setup will give you a complete CI/CD pipeline with automated testing, security scanning, containerized deployment, and proper Azure resource management! 🎉
