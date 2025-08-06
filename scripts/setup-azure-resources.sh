#!/bin/bash
# Azure Resources Setup Script for Security Copilot Agent (Linux/Mac version)
# This script creates all required Azure resources for the CI/CD pipeline

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Default values
SUBSCRIPTION_ID=""
RESOURCE_GROUP_NAME="security-copilot-rg"
LOCATION="East US"
APP_NAME="security-copilot"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --subscription-id)
            SUBSCRIPTION_ID="$2"
            shift 2
            ;;
        --resource-group)
            RESOURCE_GROUP_NAME="$2"
            shift 2
            ;;
        --location)
            LOCATION="$2"
            shift 2
            ;;
        --app-name)
            APP_NAME="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 --subscription-id <id> [--resource-group <name>] [--location <location>] [--app-name <name>]"
            exit 0
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

# Check required parameters
if [ -z "$SUBSCRIPTION_ID" ]; then
    echo -e "${RED}Error: --subscription-id is required${NC}"
    echo "Usage: $0 --subscription-id <id> [--resource-group <name>] [--location <location>] [--app-name <name>]"
    exit 1
fi

echo -e "${GREEN}🚀 Setting up Azure resources for Security Copilot Agent...${NC}"

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo -e "${RED}❌ Azure CLI is not installed. Please install it first:${NC}"
    echo -e "${YELLOW}   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash${NC}"
    exit 1
fi

# Login to Azure (if not already logged in)
echo -e "${YELLOW}Checking Azure login status...${NC}"
if ! az account show &> /dev/null; then
    echo -e "${RED}Please login to Azure first...${NC}"
    az login
fi

# Set subscription
echo -e "${YELLOW}Setting subscription to: $SUBSCRIPTION_ID${NC}"
az account set --subscription "$SUBSCRIPTION_ID"

# Create Resource Group
echo -e "${YELLOW}Creating resource group: $RESOURCE_GROUP_NAME${NC}"
az group create --name "$RESOURCE_GROUP_NAME" --location "$LOCATION"

# Create Azure Container Registry
ACR_NAME="${APP_NAME}acr$RANDOM"
echo -e "${YELLOW}Creating Azure Container Registry: $ACR_NAME${NC}"
az acr create --resource-group "$RESOURCE_GROUP_NAME" --name "$ACR_NAME" --sku Basic --admin-enabled true

# Create Service Principal for GitHub Actions
echo -e "${YELLOW}Creating Service Principal for GitHub Actions...${NC}"
SP_NAME="${APP_NAME}-github-actions-sp"
SCOPE="/subscriptions/$SUBSCRIPTION_ID"

SP_OUTPUT=$(az ad sp create-for-rbac --name "$SP_NAME" --role Contributor --scopes "$SCOPE" --output json)
CLIENT_ID=$(echo "$SP_OUTPUT" | jq -r '.appId')
CLIENT_SECRET=$(echo "$SP_OUTPUT" | jq -r '.password')
TENANT_ID=$(echo "$SP_OUTPUT" | jq -r '.tenant')

echo -e "${GREEN}Service Principal created successfully!${NC}"
echo -e "${CYAN}Client ID: $CLIENT_ID${NC}"
echo -e "${CYAN}Client Secret: $CLIENT_SECRET${NC}"
echo -e "${CYAN}Tenant ID: $TENANT_ID${NC}"

# Create Azure SQL Server and Database
SQL_SERVER_NAME="${APP_NAME}-sql-$RANDOM"
SQL_ADMIN_USER="sqladmin"
SQL_ADMIN_PASSWORD="SecureCopilot@$RANDOM"

echo -e "${YELLOW}Creating Azure SQL Server: $SQL_SERVER_NAME${NC}"
az sql server create --name "$SQL_SERVER_NAME" --resource-group "$RESOURCE_GROUP_NAME" --location "$LOCATION" --admin-user "$SQL_ADMIN_USER" --admin-password "$SQL_ADMIN_PASSWORD"

echo -e "${YELLOW}Creating Azure SQL Database...${NC}"
az sql db create --resource-group "$RESOURCE_GROUP_NAME" --server "$SQL_SERVER_NAME" --name "security-copilot-db" --edition Basic

# Configure SQL firewall to allow Azure services
echo -e "${YELLOW}Configuring SQL Server firewall...${NC}"
az sql server firewall-rule create --resource-group "$RESOURCE_GROUP_NAME" --server "$SQL_SERVER_NAME" --name AllowAzureServices --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0

# Create App Service Plan
echo -e "${YELLOW}Creating App Service Plan...${NC}"
APP_SERVICE_PLAN="${APP_NAME}-plan"
az appservice plan create --name "$APP_SERVICE_PLAN" --resource-group "$RESOURCE_GROUP_NAME" --sku B1 --is-linux

# Create App Service for Production
echo -e "${YELLOW}Creating App Service for Production...${NC}"
PROD_APP_NAME="${APP_NAME}-prod"
az webapp create --resource-group "$RESOURCE_GROUP_NAME" --plan "$APP_SERVICE_PLAN" --name "$PROD_APP_NAME" --deployment-container-image-name "nginx:latest"

# Create staging resource group
STAGING_RG_NAME="${RESOURCE_GROUP_NAME}-staging"
echo -e "${YELLOW}Creating staging resource group: $STAGING_RG_NAME${NC}"
az group create --name "$STAGING_RG_NAME" --location "$LOCATION"

# Generate Azure credentials JSON for GitHub Actions
AZURE_CREDENTIALS=$(cat <<EOF
{
  "clientId": "$CLIENT_ID",
  "clientSecret": "$CLIENT_SECRET",
  "subscriptionId": "$SUBSCRIPTION_ID",
  "tenantId": "$TENANT_ID"
}
EOF
)

# Create connection string for SQL Database
CONNECTION_STRING="Server=tcp:${SQL_SERVER_NAME}.database.windows.net,1433;Initial Catalog=security-copilot-db;Persist Security Info=False;User ID=${SQL_ADMIN_USER};Password=${SQL_ADMIN_PASSWORD};MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"

echo -e "${GREEN}✅ Azure resources created successfully!${NC}"
echo ""
echo -e "${YELLOW}📋 SAVE THESE VALUES FOR GITHUB SECRETS:${NC}"
echo -e "${YELLOW}============================================${NC}"
echo -e "${WHITE}AZURE_SUBSCRIPTION_ID: $SUBSCRIPTION_ID${NC}"
echo -e "${WHITE}AZURE_CLIENT_ID: $CLIENT_ID${NC}"
echo -e "${WHITE}AZURE_CLIENT_SECRET: $CLIENT_SECRET${NC}"
echo -e "${WHITE}AZURE_TENANT_ID: $TENANT_ID${NC}"
echo ""
echo -e "${WHITE}AZURE_CREDENTIALS (for staging):${NC}"
echo -e "${CYAN}$AZURE_CREDENTIALS${NC}"
echo ""
echo -e "${WHITE}AZURE_CREDENTIALS_PROD (same as above for now):${NC}"
echo -e "${CYAN}$AZURE_CREDENTIALS${NC}"
echo ""
echo -e "${WHITE}AZURE_SQL_CONNECTION_STRING:${NC}"
echo -e "${CYAN}$CONNECTION_STRING${NC}"
echo ""
echo -e "${YELLOW}📦 AZURE RESOURCES CREATED:${NC}"
echo -e "${YELLOW}============================================${NC}"
echo -e "${WHITE}Resource Group: $RESOURCE_GROUP_NAME${NC}"
echo -e "${WHITE}Container Registry: $ACR_NAME${NC}"
echo -e "${WHITE}SQL Server: $SQL_SERVER_NAME${NC}"
echo -e "${WHITE}SQL Database: security-copilot-db${NC}"
echo -e "${WHITE}App Service Plan: $APP_SERVICE_PLAN${NC}"
echo -e "${WHITE}Production App: $PROD_APP_NAME${NC}"
echo -e "${WHITE}Staging Resource Group: $STAGING_RG_NAME${NC}"
echo ""
echo -e "${YELLOW}🔧 NEXT STEPS:${NC}"
echo -e "${WHITE}1. Copy the secrets above to GitHub repository settings${NC}"
echo -e "${WHITE}2. Create staging and production environments in GitHub${NC}"
echo -e "${WHITE}3. Update ci-cd.yml with your resource names${NC}"
echo ""
echo -e "${YELLOW}To set GitHub secrets, run:${NC}"
echo -e "${CYAN}./scripts/setup-github-secrets.sh --owner 'your-username' --repo 'Security-copilot-agent'${NC}"

# Save values to a file for easy reference
OUTPUT_FILE="azure-setup-output.txt"
cat > "$OUTPUT_FILE" << EOF
Azure Resources Setup Output
=============================
Generated on: $(date)

GITHUB SECRETS:
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_CLIENT_ID=$CLIENT_ID
AZURE_CLIENT_SECRET=$CLIENT_SECRET
AZURE_TENANT_ID=$TENANT_ID
AZURE_SQL_CONNECTION_STRING=$CONNECTION_STRING

AZURE_CREDENTIALS:
$AZURE_CREDENTIALS

AZURE RESOURCES:
Resource Group: $RESOURCE_GROUP_NAME
Container Registry: $ACR_NAME
SQL Server: $SQL_SERVER_NAME
SQL Database: security-copilot-db
App Service Plan: $APP_SERVICE_PLAN
Production App: $PROD_APP_NAME
Staging Resource Group: $STAGING_RG_NAME
EOF

echo ""
echo -e "${GREEN}💾 Output saved to: $OUTPUT_FILE${NC}"
