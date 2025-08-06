# GitHub Secrets and Environments Setup Script
# This script configures GitHub repository secrets and environments using GitHub CLI

param(
    [Parameter(Mandatory = $true)]
    [string]$Owner,
    
    [Parameter(Mandatory = $true)]
    [string]$Repo,
    
    [Parameter(Mandatory = $false)]
    [string]$AzureSubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [string]$AzureClientId,
    
    [Parameter(Mandatory = $false)]
    [string]$AzureClientSecret,
    
    [Parameter(Mandatory = $false)]
    [string]$AzureTenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$AzureSqlConnectionString
)

Write-Host "🔐 Setting up GitHub secrets and environments..." -ForegroundColor Green

# Check if GitHub CLI is installed
$ghVersion = gh --version 2>$null
if (-not $ghVersion) {
    Write-Host "❌ GitHub CLI is not installed. Please install it first:" -ForegroundColor Red
    Write-Host "winget install --id GitHub.cli" -ForegroundColor Yellow
    exit 1
}

# Check if user is authenticated
$authStatus = gh auth status 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Please authenticate with GitHub first:" -ForegroundColor Yellow
    Write-Host "gh auth login" -ForegroundColor Cyan
    exit 1
}

# Repository reference
$repoRef = "$Owner/$Repo"
Write-Host "Setting up secrets for repository: $repoRef" -ForegroundColor Yellow

# Function to set repository secret
function Set-GitHubSecret {
    param($Name, $Value)
    if ($Value) {
        Write-Host "Setting secret: $Name" -ForegroundColor Cyan
        echo $Value | gh secret set $Name --repo $repoRef
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Secret $Name set successfully" -ForegroundColor Green
        }
        else {
            Write-Host "❌ Failed to set secret $Name" -ForegroundColor Red
        }
    }
    else {
        Write-Host "⚠️ Skipping $Name - no value provided" -ForegroundColor Yellow
    }
}

# Set Azure secrets
if ($AzureSubscriptionId) {
    Set-GitHubSecret "AZURE_SUBSCRIPTION_ID" $AzureSubscriptionId
}

if ($AzureClientId) {
    Set-GitHubSecret "AZURE_CLIENT_ID" $AzureClientId
}

if ($AzureClientSecret) {
    Set-GitHubSecret "AZURE_CLIENT_SECRET" $AzureClientSecret
}

if ($AzureTenantId) {
    Set-GitHubSecret "AZURE_TENANT_ID" $AzureTenantId
}

if ($AzureSqlConnectionString) {
    Set-GitHubSecret "AZURE_SQL_CONNECTION_STRING" $AzureSqlConnectionString
}

# Create Azure credentials JSON for deployment
if ($AzureClientId -and $AzureClientSecret -and $AzureSubscriptionId -and $AzureTenantId) {
    $azureCredentials = @{
        clientId       = $AzureClientId
        clientSecret   = $AzureClientSecret
        subscriptionId = $AzureSubscriptionId
        tenantId       = $AzureTenantId
    } | ConvertTo-Json -Compress
    
    Set-GitHubSecret "AZURE_CREDENTIALS" $azureCredentials
    Set-GitHubSecret "AZURE_CREDENTIALS_PROD" $azureCredentials
}

Write-Host ""
Write-Host "🌍 Creating GitHub environments..." -ForegroundColor Yellow

# Create staging environment
Write-Host "Creating staging environment..." -ForegroundColor Cyan
$stagingEnv = @{
    wait_timer               = 0
    reviewers                = @()
    deployment_branch_policy = @{
        protected_branches     = $false
        custom_branch_policies = $true
    }
} | ConvertTo-Json -Depth 3

try {
    $stagingEnv | gh api repos/$repoRef/environments/staging --method PUT --input -
    Write-Host "✅ Staging environment created" -ForegroundColor Green
}
catch {
    Write-Host "⚠️ Staging environment may already exist or failed to create" -ForegroundColor Yellow
}

# Create production environment with approval requirement
Write-Host "Creating production environment with approval..." -ForegroundColor Cyan
$prodEnv = @{
    wait_timer               = 5
    reviewers                = @(
        @{
            type = "User"
            id   = (gh api user --jq '.id')
        }
    )
    deployment_branch_policy = @{
        protected_branches     = $true
        custom_branch_policies = $false
    }
} | ConvertTo-Json -Depth 3

try {
    $prodEnv | gh api repos/$repoRef/environments/production --method PUT --input -
    Write-Host "✅ Production environment created with approval requirement" -ForegroundColor Green
}
catch {
    Write-Host "⚠️ Production environment may already exist or failed to create" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "✅ GitHub setup completed!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 VERIFICATION STEPS:" -ForegroundColor Yellow
Write-Host "1. Check secrets at: https://github.com/$repoRef/settings/secrets/actions" -ForegroundColor White
Write-Host "2. Check environments at: https://github.com/$repoRef/settings/environments" -ForegroundColor White
Write-Host "3. Trigger a workflow to test the setup" -ForegroundColor White
Write-Host ""
Write-Host "🔧 ADDITIONAL MANUAL STEPS:" -ForegroundColor Yellow
Write-Host "1. Update ci-cd.yml with your actual Azure resource names" -ForegroundColor White
Write-Host "2. Configure branch protection rules if needed" -ForegroundColor White
Write-Host "3. Set up notification webhooks if desired" -ForegroundColor White
