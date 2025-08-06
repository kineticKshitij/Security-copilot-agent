# Azure Resources Setup Script for Security Copilot Agent
# This script creates all required Azure resources for the CI/CD pipeline

param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName = "security-copilot-rg",
    
    [Parameter(Mandatory = $true)]
    [string]$Location = "East US",
    
    [Parameter(Mandatory = $true)]
    [string]$AppName = "security-copilot"
)

Write-Host "🚀 Setting up Azure resources for Security Copilot Agent..." -ForegroundColor Green

# Login to Azure (if not already logged in)
Write-Host "Checking Azure login status..." -ForegroundColor Yellow
$context = az account show --output json 2>$null | ConvertFrom-Json
if (-not $context) {
    Write-Host "Please login to Azure first..." -ForegroundColor Red
    az login
}

# Set subscription
Write-Host "Setting subscription to: $SubscriptionId" -ForegroundColor Yellow
az account set --subscription $SubscriptionId

# Create Resource Group
Write-Host "Creating resource group: $ResourceGroupName" -ForegroundColor Yellow
az group create --name $ResourceGroupName --location $Location

# Create Azure Container Registry
$acrName = "$AppName" + "acr" + (Get-Random -Maximum 9999)
Write-Host "Creating Azure Container Registry: $acrName" -ForegroundColor Yellow
az acr create --resource-group $ResourceGroupName --name $acrName --sku Basic --admin-enabled true

# Create Service Principal for GitHub Actions
Write-Host "Creating Service Principal for GitHub Actions..." -ForegroundColor Yellow
$spName = "$AppName-github-actions-sp"
$scope = "/subscriptions/$SubscriptionId"

$sp = az ad sp create-for-rbac --name $spName --role Contributor --scopes $scope --output json | ConvertFrom-Json

Write-Host "Service Principal created successfully!" -ForegroundColor Green
Write-Host "Client ID: $($sp.appId)" -ForegroundColor Cyan
Write-Host "Client Secret: $($sp.password)" -ForegroundColor Cyan
Write-Host "Tenant ID: $($sp.tenant)" -ForegroundColor Cyan

# Create Azure SQL Server and Database
$sqlServerName = "$AppName-sql-" + (Get-Random -Maximum 9999)
$sqlAdminUser = "sqladmin"
$sqlAdminPassword = "SecureCopilot@" + (Get-Random -Maximum 9999)

Write-Host "Creating Azure SQL Server: $sqlServerName" -ForegroundColor Yellow
az sql server create --name $sqlServerName --resource-group $ResourceGroupName --location $Location --admin-user $sqlAdminUser --admin-password $sqlAdminPassword

Write-Host "Creating Azure SQL Database..." -ForegroundColor Yellow
az sql db create --resource-group $ResourceGroupName --server $sqlServerName --name "security-copilot-db" --edition Basic

# Configure SQL firewall to allow Azure services
Write-Host "Configuring SQL Server firewall..." -ForegroundColor Yellow
az sql server firewall-rule create --resource-group $ResourceGroupName --server $sqlServerName --name AllowAzureServices --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0

# Create App Service Plan
Write-Host "Creating App Service Plan..." -ForegroundColor Yellow
$appServicePlan = "$AppName-plan"
az appservice plan create --name $appServicePlan --resource-group $ResourceGroupName --sku B1 --is-linux

# Create App Service for Production
Write-Host "Creating App Service for Production..." -ForegroundColor Yellow
$prodAppName = "$AppName-prod"
az webapp create --resource-group $ResourceGroupName --plan $appServicePlan --name $prodAppName --deployment-container-image-name "nginx:latest"

# Create staging resource group and container instance
$stagingRgName = "$ResourceGroupName-staging"
Write-Host "Creating staging resource group: $stagingRgName" -ForegroundColor Yellow
az group create --name $stagingRgName --location $Location

# Generate Azure credentials JSON for GitHub Actions
$azureCredentials = @{
    clientId       = $sp.appId
    clientSecret   = $sp.password
    subscriptionId = $SubscriptionId
    tenantId       = $sp.tenant
} | ConvertTo-Json

# Create connection string for SQL Database
$connectionString = "Server=tcp:$sqlServerName.database.windows.net,1433;Initial Catalog=security-copilot-db;Persist Security Info=False;User ID=$sqlAdminUser;Password=$sqlAdminPassword;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"

Write-Host "✅ Azure resources created successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 SAVE THESE VALUES FOR GITHUB SECRETS:" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "AZURE_SUBSCRIPTION_ID: $SubscriptionId" -ForegroundColor White
Write-Host "AZURE_CLIENT_ID: $($sp.appId)" -ForegroundColor White
Write-Host "AZURE_CLIENT_SECRET: $($sp.password)" -ForegroundColor White
Write-Host "AZURE_TENANT_ID: $($sp.tenant)" -ForegroundColor White
Write-Host ""
Write-Host "AZURE_CREDENTIALS (for staging):" -ForegroundColor White
Write-Host $azureCredentials -ForegroundColor Gray
Write-Host ""
Write-Host "AZURE_CREDENTIALS_PROD (same as above for now):" -ForegroundColor White
Write-Host $azureCredentials -ForegroundColor Gray
Write-Host ""
Write-Host "AZURE_SQL_CONNECTION_STRING:" -ForegroundColor White
Write-Host $connectionString -ForegroundColor Gray
Write-Host ""
Write-Host "📦 AZURE RESOURCES CREATED:" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host "Container Registry: $acrName" -ForegroundColor White
Write-Host "SQL Server: $sqlServerName" -ForegroundColor White
Write-Host "SQL Database: security-copilot-db" -ForegroundColor White
Write-Host "App Service Plan: $appServicePlan" -ForegroundColor White
Write-Host "Production App: $prodAppName" -ForegroundColor White
Write-Host "Staging Resource Group: $stagingRgName" -ForegroundColor White
Write-Host ""
Write-Host "🔧 NEXT STEPS:" -ForegroundColor Yellow
Write-Host "1. Copy the secrets above to GitHub repository settings" -ForegroundColor White
Write-Host "2. Create staging and production environments in GitHub" -ForegroundColor White
Write-Host "3. Update ci-cd.yml with your resource names" -ForegroundColor White
Write-Host ""
Write-Host "To set GitHub secrets, run:" -ForegroundColor Yellow
Write-Host ".\scripts\setup-github-secrets.ps1 -Owner 'your-username' -Repo 'Security-copilot-agent'" -ForegroundColor Cyan
