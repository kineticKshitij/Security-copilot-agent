#!/bin/bash

# Security Copilot Agent - Azure Resource Discovery Script
# This script helps identify and set up all required Azure keys and endpoints

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="security-copilot"
RESOURCE_GROUP_NAME="${PROJECT_NAME}-rg"
LOCATION="East US"

print_header() {
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}🔍 Security Copilot Agent - Azure Resource Discovery${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
}

print_section() {
    echo -e "${CYAN}📋 $1${NC}"
    echo "----------------------------------------"
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_key() {
    echo -e "${PURPLE}🔑 $1:${NC} $2"
}

print_endpoint() {
    echo -e "${BLUE}🌐 $1:${NC} $2"
}

# Function to check Azure CLI login
check_azure_login() {
    print_section "Checking Azure Authentication"
    
    if ! command -v az &> /dev/null; then
        print_error "Azure CLI is not installed. Please install it first:"
        echo "https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        exit 1
    fi
    
    if ! az account show &> /dev/null; then
        print_warning "Not logged in to Azure. Please login:"
        az login
    fi
    
    CURRENT_SUB=$(az account show --query name -o tsv)
    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    TENANT_ID=$(az account show --query tenantId -o tsv)
    
    print_info "Current subscription: $CURRENT_SUB"
    print_key "AZURE_SUBSCRIPTION_ID" "$SUBSCRIPTION_ID"
    print_key "AZURE_TENANT_ID" "$TENANT_ID"
    echo ""
}

# Function to create service principal
create_service_principal() {
    print_section "Creating Service Principal for Security Copilot"
    
    SP_NAME="${PROJECT_NAME}-sp"
    
    # Check if service principal already exists
    if az ad sp list --display-name "$SP_NAME" --query "[].appId" -o tsv | grep -q .; then
        print_warning "Service principal '$SP_NAME' already exists"
        APP_ID=$(az ad sp list --display-name "$SP_NAME" --query "[0].appId" -o tsv)
        print_key "AZURE_CLIENT_ID" "$APP_ID"
        print_warning "Client secret needs to be regenerated for security"
        
        read -p "Do you want to create a new client secret? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            CLIENT_SECRET=$(az ad sp credential reset --id "$APP_ID" --query password -o tsv)
            print_key "AZURE_CLIENT_SECRET" "$CLIENT_SECRET"
        fi
    else
        print_info "Creating new service principal: $SP_NAME"
        
        # Create service principal with Reader role on subscription
        SP_OUTPUT=$(az ad sp create-for-rbac \
            --name "$SP_NAME" \
            --role "Reader" \
            --scopes "/subscriptions/$SUBSCRIPTION_ID" \
            --query "{appId:appId,password:password}" \
            -o json)
        
        APP_ID=$(echo $SP_OUTPUT | jq -r '.appId')
        CLIENT_SECRET=$(echo $SP_OUTPUT | jq -r '.password')
        
        print_key "AZURE_CLIENT_ID" "$APP_ID"
        print_key "AZURE_CLIENT_SECRET" "$CLIENT_SECRET"
        
        # Add additional required permissions
        print_info "Adding Network Contributor role for NSG scanning..."
        az role assignment create \
            --assignee "$APP_ID" \
            --role "Network Contributor" \
            --scope "/subscriptions/$SUBSCRIPTION_ID" \
            --output none
        
        print_info "Adding Security Reader role for security assessments..."
        az role assignment create \
            --assignee "$APP_ID" \
            --role "Security Reader" \
            --scope "/subscriptions/$SUBSCRIPTION_ID" \
            --output none
    fi
    echo ""
}

# Function to discover Azure SQL resources
discover_sql_resources() {
    print_section "Discovering Azure SQL Resources"
    
    # Check for existing SQL servers
    SQL_SERVERS=$(az sql server list --query "[].{name:name,resourceGroup:resourceGroup,location:location}" -o table)
    
    if [ -z "$SQL_SERVERS" ] || [ "$SQL_SERVERS" = "[]" ]; then
        print_warning "No Azure SQL servers found in subscription"
        print_info "You can create one with:"
        echo "az sql server create --name ${PROJECT_NAME}-sql --resource-group $RESOURCE_GROUP_NAME --location '$LOCATION' --admin-user sqladmin --admin-password <password>"
        echo ""
        
        read -p "Do you want to create a new Azure SQL server? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            create_sql_server
        fi
    else
        print_info "Found existing SQL servers:"
        echo "$SQL_SERVERS"
        echo ""
        
        # Get details of the first server
        FIRST_SERVER=$(az sql server list --query "[0].name" -o tsv)
        SERVER_RG=$(az sql server list --query "[0].resourceGroup" -o tsv)
        
        if [ ! -z "$FIRST_SERVER" ]; then
            SQL_ENDPOINT="${FIRST_SERVER}.database.windows.net"
            print_endpoint "AZURE_SQL_SERVER" "$SQL_ENDPOINT"
            
            # Check for security-copilot database
            DB_EXISTS=$(az sql db list --server "$FIRST_SERVER" --resource-group "$SERVER_RG" --query "[?name=='security-copilot'].name" -o tsv)
            
            if [ -z "$DB_EXISTS" ]; then
                print_warning "Database 'security-copilot' not found"
                read -p "Create security-copilot database? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    az sql db create --server "$FIRST_SERVER" --resource-group "$SERVER_RG" --name "security-copilot" --service-objective Basic
                    print_info "Database 'security-copilot' created"
                fi
            fi
            
            print_key "AZURE_SQL_DATABASE" "security-copilot"
            print_warning "You'll need to provide AZURE_SQL_USERNAME and AZURE_SQL_PASSWORD"
        fi
    fi
    echo ""
}

# Function to create SQL server
create_sql_server() {
    print_info "Creating Azure SQL Server..."
    
    SQL_SERVER_NAME="${PROJECT_NAME}-sql-$(date +%s)"
    read -p "Enter SQL admin username: " SQL_ADMIN
    read -s -p "Enter SQL admin password: " SQL_PASSWORD
    echo ""
    
    # Create resource group if it doesn't exist
    az group create --name "$RESOURCE_GROUP_NAME" --location "$LOCATION" --output none
    
    # Create SQL server
    az sql server create \
        --name "$SQL_SERVER_NAME" \
        --resource-group "$RESOURCE_GROUP_NAME" \
        --location "$LOCATION" \
        --admin-user "$SQL_ADMIN" \
        --admin-password "$SQL_PASSWORD" \
        --output none
    
    # Create database
    az sql db create \
        --server "$SQL_SERVER_NAME" \
        --resource-group "$RESOURCE_GROUP_NAME" \
        --name "security-copilot" \
        --service-objective Basic \
        --output none
    
    # Configure firewall (allow Azure services)
    az sql server firewall-rule create \
        --server "$SQL_SERVER_NAME" \
        --resource-group "$RESOURCE_GROUP_NAME" \
        --name "AllowAzureServices" \
        --start-ip-address 0.0.0.0 \
        --end-ip-address 0.0.0.0 \
        --output none
    
    SQL_ENDPOINT="${SQL_SERVER_NAME}.database.windows.net"
    print_endpoint "AZURE_SQL_SERVER" "$SQL_ENDPOINT"
    print_key "AZURE_SQL_USERNAME" "$SQL_ADMIN"
    print_key "AZURE_SQL_PASSWORD" "$SQL_PASSWORD"
    print_key "AZURE_SQL_DATABASE" "security-copilot"
    
    CONNECTION_STRING="Driver={ODBC Driver 18 for SQL Server};Server=tcp:${SQL_ENDPOINT},1433;Database=security-copilot;Uid=${SQL_ADMIN};Pwd=${SQL_PASSWORD};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
    print_key "AZURE_SQL_CONNECTION_STRING" "$CONNECTION_STRING"
}

# Function to discover Key Vault resources
discover_key_vault() {
    print_section "Discovering Azure Key Vault Resources"
    
    KEY_VAULTS=$(az keyvault list --query "[].{name:name,resourceGroup:resourceGroup,location:location}" -o table)
    
    if [ -z "$KEY_VAULTS" ] || [ "$KEY_VAULTS" = "[]" ]; then
        print_warning "No Key Vaults found in subscription"
        print_info "Key Vault is recommended for storing secrets securely"
        
        read -p "Do you want to create a Key Vault? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            create_key_vault
        fi
    else
        print_info "Found existing Key Vaults:"
        echo "$KEY_VAULTS"
        
        FIRST_KV=$(az keyvault list --query "[0].name" -o tsv)
        if [ ! -z "$FIRST_KV" ]; then
            KV_URI=$(az keyvault show --name "$FIRST_KV" --query "properties.vaultUri" -o tsv)
            print_endpoint "KEY_VAULT_URI" "$KV_URI"
        fi
    fi
    echo ""
}

# Function to create Key Vault
create_key_vault() {
    KV_NAME="${PROJECT_NAME}-kv-$(date +%s)"
    
    # Create resource group if it doesn't exist
    az group create --name "$RESOURCE_GROUP_NAME" --location "$LOCATION" --output none
    
    # Create Key Vault
    az keyvault create \
        --name "$KV_NAME" \
        --resource-group "$RESOURCE_GROUP_NAME" \
        --location "$LOCATION" \
        --output none
    
    KV_URI=$(az keyvault show --name "$KV_NAME" --query "properties.vaultUri" -o tsv)
    print_endpoint "KEY_VAULT_URI" "$KV_URI"
    print_info "Key Vault '$KV_NAME' created successfully"
}

# Function to discover Log Analytics and Application Insights
discover_monitoring() {
    print_section "Discovering Monitoring Resources"
    
    # Log Analytics Workspaces
    LA_WORKSPACES=$(az monitor log-analytics workspace list --query "[].{name:name,resourceGroup:resourceGroup,location:location}" -o table)
    
    if [ -z "$LA_WORKSPACES" ] || [ "$LA_WORKSPACES" = "[]" ]; then
        print_warning "No Log Analytics workspaces found"
    else
        print_info "Found Log Analytics workspaces:"
        echo "$LA_WORKSPACES"
        
        FIRST_LA=$(az monitor log-analytics workspace list --query "[0].name" -o tsv)
        LA_RG=$(az monitor log-analytics workspace list --query "[0].resourceGroup" -o tsv)
        
        if [ ! -z "$FIRST_LA" ]; then
            WORKSPACE_ID=$(az monitor log-analytics workspace show --workspace-name "$FIRST_LA" --resource-group "$LA_RG" --query "customerId" -o tsv)
            print_key "LOG_ANALYTICS_WORKSPACE_ID" "$WORKSPACE_ID"
        fi
    fi
    
    # Application Insights
    APP_INSIGHTS=$(az monitor app-insights component show-all --query "[].{name:name,resourceGroup:resourceGroup,location:location}" -o table)
    
    if [ -z "$APP_INSIGHTS" ] || [ "$APP_INSIGHTS" = "[]" ]; then
        print_warning "No Application Insights found"
    else
        print_info "Found Application Insights:"
        echo "$APP_INSIGHTS"
        
        FIRST_AI=$(az monitor app-insights component show-all --query "[0].name" -o tsv)
        AI_RG=$(az monitor app-insights component show-all --query "[0].resourceGroup" -o tsv)
        
        if [ ! -z "$FIRST_AI" ]; then
            INSTRUMENTATION_KEY=$(az monitor app-insights component show --app "$FIRST_AI" --resource-group "$AI_RG" --query "instrumentationKey" -o tsv)
            CONNECTION_STRING=$(az monitor app-insights component show --app "$FIRST_AI" --resource-group "$AI_RG" --query "connectionString" -o tsv)
            print_key "APPLICATIONINSIGHTS_INSTRUMENTATION_KEY" "$INSTRUMENTATION_KEY"
            print_key "APPLICATIONINSIGHTS_CONNECTION_STRING" "$CONNECTION_STRING"
        fi
    fi
    echo ""
}

# Function to generate .env file
generate_env_file() {
    print_section "Generating Environment Configuration"
    
    ENV_FILE=".env"
    
    if [ -f "$ENV_FILE" ]; then
        print_warning ".env file already exists. Creating .env.discovered instead"
        ENV_FILE=".env.discovered"
    fi
    
    cat > "$ENV_FILE" << EOF
# Azure Configuration - Generated by Azure Resource Discovery
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_CLIENT_ID=$APP_ID
AZURE_CLIENT_SECRET=$CLIENT_SECRET
AZURE_TENANT_ID=$TENANT_ID

# Use Managed Identity in Azure (recommended for production)
USE_MANAGED_IDENTITY=false

# GitHub Configuration (REQUIRED - You need to provide these)
GITHUB_TOKEN=your-github-personal-access-token
GITHUB_REPO_OWNER=your-github-username
GITHUB_REPO_NAME=your-repo-name

# Azure SQL Configuration (Optional - for audit logging)
EOF

    if [ ! -z "$SQL_ENDPOINT" ]; then
        cat >> "$ENV_FILE" << EOF
AZURE_SQL_SERVER=$SQL_ENDPOINT
AZURE_SQL_DATABASE=security-copilot
AZURE_SQL_USERNAME=$SQL_ADMIN
AZURE_SQL_PASSWORD=$SQL_PASSWORD
AZURE_SQL_CONNECTION_STRING=$CONNECTION_STRING
EOF
    else
        cat >> "$ENV_FILE" << EOF
AZURE_SQL_SERVER=your-sql-server.database.windows.net
AZURE_SQL_DATABASE=security-copilot
AZURE_SQL_USERNAME=your-username
AZURE_SQL_PASSWORD=your-password
AZURE_SQL_CONNECTION_STRING=Driver={ODBC Driver 18 for SQL Server};Server=tcp:your-server.database.windows.net,1433;Database=security-copilot;Uid=your-username;Pwd=your-password;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;
EOF
    fi

    cat >> "$ENV_FILE" << EOF

# Honeypot Integration (Optional)
HONEYPOT_LOG_PATH=/var/log/honeypot
HONEYPOT_API_ENDPOINT=https://your-honeypot-api.com/api/v1
HONEYPOT_API_KEY=your-honeypot-api-key

# Logging Configuration
LOG_LEVEL=INFO
LOG_FORMAT=json

# Scanner Configuration
SCAN_INTERVAL_HOURS=24
AUTO_REMEDIATION_ENABLED=false
MAX_CONCURRENT_SCANS=5

# GitHub Integration
CREATE_ISSUES_FOR_FINDINGS=true
CREATE_PRS_FOR_AUTO_FIX=true
GITHUB_ISSUE_LABELS=security,nsg,misconfiguration
GITHUB_PR_LABELS=security,auto-fix

# Notification Configuration (Optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/your/webhook/url
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-email-password
EOF

    if [ ! -z "$WORKSPACE_ID" ]; then
        cat >> "$ENV_FILE" << EOF

# Monitoring (Auto-discovered)
LOG_ANALYTICS_WORKSPACE_ID=$WORKSPACE_ID
EOF
    fi

    if [ ! -z "$CONNECTION_STRING" ]; then
        cat >> "$ENV_FILE" << EOF
APPLICATIONINSIGHTS_CONNECTION_STRING=$CONNECTION_STRING
EOF
    fi

    print_info "Environment configuration saved to: $ENV_FILE"
    echo ""
}

# Function to show required GitHub setup
show_github_setup() {
    print_section "GitHub Setup Required"
    
    print_warning "You need to manually configure the following GitHub settings:"
    echo ""
    
    print_info "1. Create a GitHub Personal Access Token:"
    echo "   - Go to: https://github.com/settings/tokens"
    echo "   - Click 'Generate new token (classic)'"
    echo "   - Select scopes: repo, issues, pull_requests"
    echo "   - Copy the token and add it to GITHUB_TOKEN in your .env file"
    echo ""
    
    print_info "2. Set Repository Information:"
    echo "   - GITHUB_REPO_OWNER: Your GitHub username or organization"
    echo "   - GITHUB_REPO_NAME: Repository name (e.g., security-copilot-agent)"
    echo ""
    
    print_info "3. Optional: Set up Webhooks for real-time integration"
    echo "   - Repository Settings → Webhooks → Add webhook"
    echo "   - Payload URL: Your deployed Azure App Service URL + /webhook"
    echo "   - Content type: application/json"
    echo "   - Events: Issues, Pull requests"
    echo ""
}

# Function to show next steps
show_next_steps() {
    print_section "Next Steps"
    
    print_info "1. Complete GitHub configuration (see above)"
    echo ""
    
    print_info "2. Test the configuration:"
    echo "   python -m security_copilot.cli status"
    echo ""
    
    print_info "3. Run your first security scan:"
    echo "   python -m security_copilot.cli scan --subscription-id $SUBSCRIPTION_ID"
    echo ""
    
    print_info "4. Deploy to Azure (optional):"
    echo "   cd deployment"
    echo "   ./deploy.sh"
    echo ""
    
    print_info "5. Set up monitoring and alerting in Azure portal"
    echo ""
    
    print_warning "Security Recommendations:"
    echo "   - Store secrets in Azure Key Vault (not .env files)"
    echo "   - Use Managed Identity when deploying to Azure"
    echo "   - Regularly rotate service principal credentials"
    echo "   - Enable Azure Security Center for additional monitoring"
    echo ""
}

# Main function
main() {
    print_header
    
    check_azure_login
    create_service_principal
    discover_sql_resources
    discover_key_vault
    discover_monitoring
    generate_env_file
    show_github_setup
    show_next_steps
    
    print_section "Discovery Complete!"
    print_info "All Azure resources have been discovered and configured."
    print_info "Check the generated .env file and complete the GitHub setup."
    echo ""
}

# Handle script arguments
case "${1:-main}" in
    "sp")
        check_azure_login
        create_service_principal
        ;;
    "sql")
        check_azure_login
        discover_sql_resources
        ;;
    "kv"|"keyvault")
        check_azure_login
        discover_key_vault
        ;;
    "monitoring")
        check_azure_login
        discover_monitoring
        ;;
    "env")
        generate_env_file
        ;;
    "help")
        echo "Usage: $0 [sp|sql|kv|monitoring|env|help]"
        echo ""
        echo "Commands:"
        echo "  sp         - Create/check service principal only"
        echo "  sql        - Discover/create SQL resources only"
        echo "  kv         - Discover/create Key Vault only"
        echo "  monitoring - Discover monitoring resources only"
        echo "  env        - Generate .env file only"
        echo "  help       - Show this help"
        echo "  (no args)  - Run full discovery"
        ;;
    *)
        main
        ;;
esac
