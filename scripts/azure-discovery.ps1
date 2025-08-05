# Security Copilot Agent - Azure Resource Discovery Script (PowerShell)
# This script helps identify and set up all required Azure keys and endpoints

param(
    [Parameter(Position = 0)]
    [ValidateSet("sp", "sql", "kv", "keyvault", "monitoring", "env", "help", "")]
    [string]$Command = ""
)

# Configuration
$ProjectName = "security-copilot"
$ResourceGroupName = "$ProjectName-rg"
$Location = "East US"

# Global variables
$script:SubscriptionId = ""
$script:TenantId = ""
$script:AppId = ""
$script:ClientSecret = ""
$script:SqlEndpoint = ""
$script:SqlAdmin = ""
$script:SqlPassword = ""
$script:WorkspaceId = ""
$script:ConnectionString = ""

function Write-Header {
    Write-Host "================================================================" -ForegroundColor Blue
    Write-Host "🔍 Security Copilot Agent - Azure Resource Discovery" -ForegroundColor Blue
    Write-Host "================================================================" -ForegroundColor Blue
    Write-Host ""
}

function Write-Section {
    param([string]$Title)
    Write-Host "📋 $Title" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-Key {
    param([string]$Name, [string]$Value)
    Write-Host "🔑 $Name`: " -ForegroundColor Magenta -NoNewline
    Write-Host $Value -ForegroundColor White
}

function Write-Endpoint {
    param([string]$Name, [string]$Value)
    Write-Host "🌐 $Name`: " -ForegroundColor Blue -NoNewline
    Write-Host $Value -ForegroundColor White
}

function Test-AzureLogin {
    Write-Section "Checking Azure Authentication"
    
    # Check if Azure CLI is installed
    try {
        $azVersion = az version 2>$null | ConvertFrom-Json
        if (-not $azVersion) {
            throw "Azure CLI not found"
        }
    }
    catch {
        Write-Error "Azure CLI is not installed. Please install it first:"
        Write-Host "https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        exit 1
    }
    
    # Check if logged in
    try {
        $account = az account show 2>$null | ConvertFrom-Json
        if (-not $account) {
            throw "Not logged in"
        }
    }
    catch {
        Write-Warning "Not logged in to Azure. Please login:"
        az login
        $account = az account show | ConvertFrom-Json
    }
    
    $script:SubscriptionId = $account.id
    $script:TenantId = $account.tenantId
    $currentSub = $account.name
    
    Write-Info "Current subscription: $currentSub"
    Write-Key "AZURE_SUBSCRIPTION_ID" $script:SubscriptionId
    Write-Key "AZURE_TENANT_ID" $script:TenantId
    Write-Host ""
}

function New-ServicePrincipal {
    Write-Section "Creating Service Principal for Security Copilot"
    
    $spName = "$ProjectName-sp"
    
    # Check if service principal already exists
    $existingSp = az ad sp list --display-name $spName --query "[].appId" -o tsv 2>$null
    
    if ($existingSp) {
        Write-Warning "Service principal '$spName' already exists"
        $script:AppId = $existingSp
        Write-Key "AZURE_CLIENT_ID" $script:AppId
        Write-Warning "Client secret needs to be regenerated for security"
        
        $response = Read-Host "Do you want to create a new client secret? (y/n)"
        if ($response -eq 'y' -or $response -eq 'Y') {
            $resetResult = az ad sp credential reset --id $script:AppId --query password -o tsv
            $script:ClientSecret = $resetResult
            Write-Key "AZURE_CLIENT_SECRET" $script:ClientSecret
        }
    }
    else {
        Write-Info "Creating new service principal: $spName"
        
        # Create service principal with Reader role on subscription
        $spOutput = az ad sp create-for-rbac `
            --name $spName `
            --role "Reader" `
            --scopes "/subscriptions/$script:SubscriptionId" `
            --query "{appId:appId,password:password}" `
            -o json | ConvertFrom-Json
        
        $script:AppId = $spOutput.appId
        $script:ClientSecret = $spOutput.password
        
        Write-Key "AZURE_CLIENT_ID" $script:AppId
        Write-Key "AZURE_CLIENT_SECRET" $script:ClientSecret
        
        # Add additional required permissions
        Write-Info "Adding Network Contributor role for NSG scanning..."
        az role assignment create `
            --assignee $script:AppId `
            --role "Network Contributor" `
            --scope "/subscriptions/$script:SubscriptionId" `
            --output none
        
        Write-Info "Adding Security Reader role for security assessments..."
        az role assignment create `
            --assignee $script:AppId `
            --role "Security Reader" `
            --scope "/subscriptions/$script:SubscriptionId" `
            --output none
    }
    Write-Host ""
}

function Find-SqlResources {
    Write-Section "Discovering Azure SQL Resources"
    
    # Check for existing SQL servers
    $sqlServers = az sql server list --query "[].{name:name,resourceGroup:resourceGroup,location:location}" -o json | ConvertFrom-Json
    
    if (-not $sqlServers -or $sqlServers.Count -eq 0) {
        Write-Warning "No Azure SQL servers found in subscription"
        Write-Info "You can create one with:"
        Write-Host "az sql server create --name $ProjectName-sql --resource-group $ResourceGroupName --location '$Location' --admin-user sqladmin --admin-password <password>"
        Write-Host ""
        
        $response = Read-Host "Do you want to create a new Azure SQL server? (y/n)"
        if ($response -eq 'y' -or $response -eq 'Y') {
            New-SqlServer
        }
    }
    else {
        Write-Info "Found existing SQL servers:"
        $sqlServers | Format-Table -AutoSize
        Write-Host ""
        
        # Get details of the first server
        $firstServer = $sqlServers[0].name
        $serverRg = $sqlServers[0].resourceGroup
        
        if ($firstServer) {
            $script:SqlEndpoint = "$firstServer.database.windows.net"
            Write-Endpoint "AZURE_SQL_SERVER" $script:SqlEndpoint
            
            # Check for security-copilot database
            $dbExists = az sql db list --server $firstServer --resource-group $serverRg --query "[?name=='security-copilot'].name" -o tsv
            
            if (-not $dbExists) {
                Write-Warning "Database 'security-copilot' not found"
                $response = Read-Host "Create security-copilot database? (y/n)"
                if ($response -eq 'y' -or $response -eq 'Y') {
                    az sql db create --server $firstServer --resource-group $serverRg --name "security-copilot" --service-objective Basic
                    Write-Info "Database 'security-copilot' created"
                }
            }
            
            Write-Key "AZURE_SQL_DATABASE" "security-copilot"
            Write-Warning "You'll need to provide AZURE_SQL_USERNAME and AZURE_SQL_PASSWORD"
        }
    }
    Write-Host ""
}

function New-SqlServer {
    Write-Info "Creating Azure SQL Server..."
    
    $sqlServerName = "$ProjectName-sql-$((Get-Date).Ticks)"
    $script:SqlAdmin = Read-Host "Enter SQL admin username"
    $securePassword = Read-Host "Enter SQL admin password" -AsSecureString
    $script:SqlPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
    
    # Create resource group if it doesn't exist
    az group create --name $ResourceGroupName --location $Location --output none
    
    # Create SQL server
    az sql server create `
        --name $sqlServerName `
        --resource-group $ResourceGroupName `
        --location $Location `
        --admin-user $script:SqlAdmin `
        --admin-password $script:SqlPassword `
        --output none
    
    # Create database
    az sql db create `
        --server $sqlServerName `
        --resource-group $ResourceGroupName `
        --name "security-copilot" `
        --service-objective Basic `
        --output none
    
    # Configure firewall (allow Azure services)
    az sql server firewall-rule create `
        --server $sqlServerName `
        --resource-group $ResourceGroupName `
        --name "AllowAzureServices" `
        --start-ip-address 0.0.0.0 `
        --end-ip-address 0.0.0.0 `
        --output none
    
    $script:SqlEndpoint = "$sqlServerName.database.windows.net"
    Write-Endpoint "AZURE_SQL_SERVER" $script:SqlEndpoint
    Write-Key "AZURE_SQL_USERNAME" $script:SqlAdmin
    Write-Key "AZURE_SQL_PASSWORD" $script:SqlPassword
    Write-Key "AZURE_SQL_DATABASE" "security-copilot"
    
    $connectionString = "Driver={ODBC Driver 18 for SQL Server};Server=tcp:$($script:SqlEndpoint),1433;Database=security-copilot;Uid=$($script:SqlAdmin);Pwd=$($script:SqlPassword);Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
    Write-Key "AZURE_SQL_CONNECTION_STRING" $connectionString
}

function Find-KeyVault {
    Write-Section "Discovering Azure Key Vault Resources"
    
    $keyVaults = az keyvault list --query "[].{name:name,resourceGroup:resourceGroup,location:location}" -o json | ConvertFrom-Json
    
    if (-not $keyVaults -or $keyVaults.Count -eq 0) {
        Write-Warning "No Key Vaults found in subscription"
        Write-Info "Key Vault is recommended for storing secrets securely"
        
        $response = Read-Host "Do you want to create a Key Vault? (y/n)"
        if ($response -eq 'y' -or $response -eq 'Y') {
            New-KeyVault
        }
    }
    else {
        Write-Info "Found existing Key Vaults:"
        $keyVaults | Format-Table -AutoSize
        
        $firstKv = $keyVaults[0].name
        if ($firstKv) {
            $kvUri = az keyvault show --name $firstKv --query "properties.vaultUri" -o tsv
            Write-Endpoint "KEY_VAULT_URI" $kvUri
        }
    }
    Write-Host ""
}

function New-KeyVault {
    $kvName = "$ProjectName-kv-$((Get-Date).Ticks)"
    
    # Create resource group if it doesn't exist
    az group create --name $ResourceGroupName --location $Location --output none
    
    # Create Key Vault
    az keyvault create `
        --name $kvName `
        --resource-group $ResourceGroupName `
        --location $Location `
        --output none
    
    $kvUri = az keyvault show --name $kvName --query "properties.vaultUri" -o tsv
    Write-Endpoint "KEY_VAULT_URI" $kvUri
    Write-Info "Key Vault '$kvName' created successfully"
}

function Find-MonitoringResources {
    Write-Section "Discovering Monitoring Resources"
    
    # Log Analytics Workspaces
    $laWorkspaces = az monitor log-analytics workspace list --query "[].{name:name,resourceGroup:resourceGroup,location:location}" -o json | ConvertFrom-Json
    
    if (-not $laWorkspaces -or $laWorkspaces.Count -eq 0) {
        Write-Warning "No Log Analytics workspaces found"
    }
    else {
        Write-Info "Found Log Analytics workspaces:"
        $laWorkspaces | Format-Table -AutoSize
        
        $firstLa = $laWorkspaces[0].name
        $laRg = $laWorkspaces[0].resourceGroup
        
        if ($firstLa) {
            $script:WorkspaceId = az monitor log-analytics workspace show --workspace-name $firstLa --resource-group $laRg --query "customerId" -o tsv
            Write-Key "LOG_ANALYTICS_WORKSPACE_ID" $script:WorkspaceId
        }
    }
    
    # Application Insights
    $appInsights = az monitor app-insights component show-all --query "[].{name:name,resourceGroup:resourceGroup,location:location}" -o json | ConvertFrom-Json
    
    if (-not $appInsights -or $appInsights.Count -eq 0) {
        Write-Warning "No Application Insights found"
    }
    else {
        Write-Info "Found Application Insights:"
        $appInsights | Format-Table -AutoSize
        
        $firstAi = $appInsights[0].name
        $aiRg = $appInsights[0].resourceGroup
        
        if ($firstAi) {
            $instrumentationKey = az monitor app-insights component show --app $firstAi --resource-group $aiRg --query "instrumentationKey" -o tsv
            $script:ConnectionString = az monitor app-insights component show --app $firstAi --resource-group $aiRg --query "connectionString" -o tsv
            Write-Key "APPLICATIONINSIGHTS_INSTRUMENTATION_KEY" $instrumentationKey
            Write-Key "APPLICATIONINSIGHTS_CONNECTION_STRING" $script:ConnectionString
        }
    }
    Write-Host ""
}

function New-EnvFile {
    Write-Section "Generating Environment Configuration"
    
    $envFile = ".env"
    
    if (Test-Path $envFile) {
        Write-Warning ".env file already exists. Creating .env.discovered instead"
        $envFile = ".env.discovered"
    }
    
    $envContent = @"
# Azure Configuration - Generated by Azure Resource Discovery
AZURE_SUBSCRIPTION_ID=$script:SubscriptionId
AZURE_CLIENT_ID=$script:AppId
AZURE_CLIENT_SECRET=$script:ClientSecret
AZURE_TENANT_ID=$script:TenantId

# Use Managed Identity in Azure (recommended for production)
USE_MANAGED_IDENTITY=false

# GitHub Configuration (REQUIRED - You need to provide these)
GITHUB_TOKEN=your-github-personal-access-token
GITHUB_REPO_OWNER=your-github-username
GITHUB_REPO_NAME=your-repo-name

# Azure SQL Configuration (Optional - for audit logging)
"@

    if ($script:SqlEndpoint) {
        $envContent += @"

AZURE_SQL_SERVER=$script:SqlEndpoint
AZURE_SQL_DATABASE=security-copilot
AZURE_SQL_USERNAME=$script:SqlAdmin
AZURE_SQL_PASSWORD=$script:SqlPassword
"@
        if ($script:SqlAdmin -and $script:SqlPassword) {
            $connectionStr = "Driver={ODBC Driver 18 for SQL Server};Server=tcp:$($script:SqlEndpoint),1433;Database=security-copilot;Uid=$($script:SqlAdmin);Pwd=$($script:SqlPassword);Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
            $envContent += "`nAZURE_SQL_CONNECTION_STRING=$connectionStr"
        }
    }
    else {
        $envContent += @"

AZURE_SQL_SERVER=your-sql-server.database.windows.net
AZURE_SQL_DATABASE=security-copilot
AZURE_SQL_USERNAME=your-username
AZURE_SQL_PASSWORD=your-password
AZURE_SQL_CONNECTION_STRING=Driver={ODBC Driver 18 for SQL Server};Server=tcp:your-server.database.windows.net,1433;Database=security-copilot;Uid=your-username;Pwd=your-password;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;
"@
    }

    $envContent += @"

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
"@

    if ($script:WorkspaceId) {
        $envContent += "`n`n# Monitoring (Auto-discovered)`nLOG_ANALYTICS_WORKSPACE_ID=$script:WorkspaceId"
    }

    if ($script:ConnectionString) {
        $envContent += "`nAPPLICATIONINSIGHTS_CONNECTION_STRING=$script:ConnectionString"
    }

    $envContent | Out-File -FilePath $envFile -Encoding UTF8
    Write-Info "Environment configuration saved to: $envFile"
    Write-Host ""
}

function Show-GitHubSetup {
    Write-Section "GitHub Setup Required"
    
    Write-Warning "You need to manually configure the following GitHub settings:"
    Write-Host ""
    
    Write-Info "1. Create a GitHub Personal Access Token:"
    Write-Host "   - Go to: https://github.com/settings/tokens"
    Write-Host "   - Click 'Generate new token (classic)'"
    Write-Host "   - Select scopes: repo, issues, pull_requests"
    Write-Host "   - Copy the token and add it to GITHUB_TOKEN in your .env file"
    Write-Host ""
    
    Write-Info "2. Set Repository Information:"
    Write-Host "   - GITHUB_REPO_OWNER: Your GitHub username or organization"
    Write-Host "   - GITHUB_REPO_NAME: Repository name (e.g., security-copilot-agent)"
    Write-Host ""
    
    Write-Info "3. Optional: Set up Webhooks for real-time integration"
    Write-Host "   - Repository Settings → Webhooks → Add webhook"
    Write-Host "   - Payload URL: Your deployed Azure App Service URL + /webhook"
    Write-Host "   - Content type: application/json"
    Write-Host "   - Events: Issues, Pull requests"
    Write-Host ""
}

function Show-NextSteps {
    Write-Section "Next Steps"
    
    Write-Info "1. Complete GitHub configuration (see above)"
    Write-Host ""
    
    Write-Info "2. Test the configuration:"
    Write-Host "   python -m security_copilot.cli status"
    Write-Host ""
    
    Write-Info "3. Run your first security scan:"
    Write-Host "   python -m security_copilot.cli scan --subscription-id $script:SubscriptionId"
    Write-Host ""
    
    Write-Info "4. Deploy to Azure (optional):"
    Write-Host "   cd deployment"
    Write-Host "   .\deploy.ps1"
    Write-Host ""
    
    Write-Info "5. Set up monitoring and alerting in Azure portal"
    Write-Host ""
    
    Write-Warning "Security Recommendations:"
    Write-Host "   - Store secrets in Azure Key Vault (not .env files)"
    Write-Host "   - Use Managed Identity when deploying to Azure"
    Write-Host "   - Regularly rotate service principal credentials"
    Write-Host "   - Enable Azure Security Center for additional monitoring"
    Write-Host ""
}

function Invoke-Main {
    Write-Header
    
    Test-AzureLogin
    New-ServicePrincipal
    Find-SqlResources
    Find-KeyVault
    Find-MonitoringResources
    New-EnvFile
    Show-GitHubSetup
    Show-NextSteps
    
    Write-Section "Discovery Complete!"
    Write-Info "All Azure resources have been discovered and configured."
    Write-Info "Check the generated .env file and complete the GitHub setup."
    Write-Host ""
}

# Main script execution
switch ($Command) {
    "sp" {
        Test-AzureLogin
        New-ServicePrincipal
    }
    "sql" {
        Test-AzureLogin
        Find-SqlResources
    }
    "kv" {
        Test-AzureLogin
        Find-KeyVault
    }
    "keyvault" {
        Test-AzureLogin
        Find-KeyVault
    }
    "monitoring" {
        Test-AzureLogin
        Find-MonitoringResources
    }
    "env" {
        New-EnvFile
    }
    "help" {
        Write-Host "Usage: .\azure-discovery.ps1 [sp|sql|kv|monitoring|env|help]"
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  sp         - Create/check service principal only"
        Write-Host "  sql        - Discover/create SQL resources only"
        Write-Host "  kv         - Discover/create Key Vault only"
        Write-Host "  monitoring - Discover monitoring resources only"
        Write-Host "  env        - Generate .env file only"
        Write-Host "  help       - Show this help"
        Write-Host "  (no args)  - Run full discovery"
    }
    default {
        Invoke-Main
    }
}
