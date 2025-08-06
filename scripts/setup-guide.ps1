# Complete Setup Guide - CLI Commands
# Execute these commands step by step to set up your entire CI/CD pipeline

Write-Host "🚀 Security Copilot Agent - Complete CLI Setup Guide" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green

# Prerequisites Check
Write-Host ""
Write-Host "📋 PREREQUISITES CHECK" -ForegroundColor Yellow
Write-Host "======================" -ForegroundColor Yellow

# Check Azure CLI
$azVersion = az --version 2>$null
if ($azVersion) {
    Write-Host "✅ Azure CLI is installed" -ForegroundColor Green
}
else {
    Write-Host "❌ Azure CLI not found. Install it:" -ForegroundColor Red
    Write-Host "   winget install -e --id Microsoft.AzureCLI" -ForegroundColor Cyan
    Write-Host "   Or download from: https://aka.ms/installazurecliwindows" -ForegroundColor Cyan
}

# Check GitHub CLI
$ghVersion = gh --version 2>$null
if ($ghVersion) {
    Write-Host "✅ GitHub CLI is installed" -ForegroundColor Green
}
else {
    Write-Host "❌ GitHub CLI not found. Install it:" -ForegroundColor Red
    Write-Host "   winget install --id GitHub.cli" -ForegroundColor Cyan
    Write-Host "   Or download from: https://cli.github.com/" -ForegroundColor Cyan
}

# Check Docker
$dockerVersion = docker --version 2>$null
if ($dockerVersion) {
    Write-Host "✅ Docker is installed" -ForegroundColor Green
}
else {
    Write-Host "❌ Docker not found. Install Docker Desktop:" -ForegroundColor Red
    Write-Host "   winget install -e --id Docker.DockerDesktop" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "🔧 STEP-BY-STEP SETUP COMMANDS" -ForegroundColor Yellow
Write-Host "===============================" -ForegroundColor Yellow

Write-Host ""
Write-Host "STEP 1: Azure Login and Setup" -ForegroundColor Cyan
Write-Host "------------------------------" -ForegroundColor Cyan
Write-Host "# Login to Azure" -ForegroundColor White
Write-Host "az login" -ForegroundColor Gray
Write-Host ""
Write-Host "# List subscriptions and copy your subscription ID" -ForegroundColor White
Write-Host "az account list --output table" -ForegroundColor Gray
Write-Host ""
Write-Host "# Set your subscription (replace with your subscription ID)" -ForegroundColor White
Write-Host "az account set --subscription 'YOUR_SUBSCRIPTION_ID'" -ForegroundColor Gray

Write-Host ""
Write-Host "STEP 2: GitHub Authentication" -ForegroundColor Cyan
Write-Host "------------------------------" -ForegroundColor Cyan
Write-Host "# Login to GitHub" -ForegroundColor White
Write-Host "gh auth login" -ForegroundColor Gray
Write-Host ""
Write-Host "# Verify authentication" -ForegroundColor White
Write-Host "gh auth status" -ForegroundColor Gray

Write-Host ""
Write-Host "STEP 3: Create Azure Resources" -ForegroundColor Cyan
Write-Host "-------------------------------" -ForegroundColor Cyan
Write-Host "# Run the Azure setup script (replace with your subscription ID)" -ForegroundColor White
Write-Host ".\scripts\setup-azure-resources.ps1 -SubscriptionId 'YOUR_SUBSCRIPTION_ID' -ResourceGroupName 'security-copilot-rg' -Location 'East US' -AppName 'security-copilot'" -ForegroundColor Gray
Write-Host ""
Write-Host "# Save the output values - you'll need them for GitHub secrets!" -ForegroundColor Red

Write-Host ""
Write-Host "STEP 4: Configure GitHub Secrets" -ForegroundColor Cyan
Write-Host "---------------------------------" -ForegroundColor Cyan
Write-Host "# Option A: Use the automated script (replace with your values)" -ForegroundColor White
Write-Host ".\scripts\setup-github-secrets.ps1 ``" -ForegroundColor Gray
Write-Host "  -Owner 'kineticKshitij' ``" -ForegroundColor Gray
Write-Host "  -Repo 'Security-copilot-agent' ``" -ForegroundColor Gray
Write-Host "  -AzureSubscriptionId 'YOUR_SUBSCRIPTION_ID' ``" -ForegroundColor Gray
Write-Host "  -AzureClientId 'YOUR_CLIENT_ID' ``" -ForegroundColor Gray
Write-Host "  -AzureClientSecret 'YOUR_CLIENT_SECRET' ``" -ForegroundColor Gray
Write-Host "  -AzureTenantId 'YOUR_TENANT_ID' ``" -ForegroundColor Gray
Write-Host "  -AzureSqlConnectionString 'YOUR_CONNECTION_STRING'" -ForegroundColor Gray
Write-Host ""
Write-Host "# Option B: Set secrets manually" -ForegroundColor White
Write-Host "gh secret set AZURE_SUBSCRIPTION_ID --repo kineticKshitij/Security-copilot-agent" -ForegroundColor Gray
Write-Host "gh secret set AZURE_CLIENT_ID --repo kineticKshitij/Security-copilot-agent" -ForegroundColor Gray
Write-Host "gh secret set AZURE_CLIENT_SECRET --repo kineticKshitij/Security-copilot-agent" -ForegroundColor Gray
Write-Host "gh secret set AZURE_TENANT_ID --repo kineticKshitij/Security-copilot-agent" -ForegroundColor Gray
Write-Host "gh secret set AZURE_CREDENTIALS --repo kineticKshitij/Security-copilot-agent" -ForegroundColor Gray
Write-Host "gh secret set AZURE_CREDENTIALS_PROD --repo kineticKshitij/Security-copilot-agent" -ForegroundColor Gray
Write-Host "gh secret set AZURE_SQL_CONNECTION_STRING --repo kineticKshitij/Security-copilot-agent" -ForegroundColor Gray

Write-Host ""
Write-Host "STEP 5: Update CI/CD Configuration" -ForegroundColor Cyan
Write-Host "-----------------------------------" -ForegroundColor Cyan
Write-Host "# Edit .github/workflows/ci-cd.yml and update these values:" -ForegroundColor White
Write-Host "# - resource-group: security-copilot-rg" -ForegroundColor Gray
Write-Host "# - app-name: security-copilot-prod" -ForegroundColor Gray
Write-Host "# - registry: your-container-registry-name" -ForegroundColor Gray

Write-Host ""
Write-Host "STEP 6: Test the Setup" -ForegroundColor Cyan
Write-Host "----------------------" -ForegroundColor Cyan
Write-Host "# Commit and push changes to trigger CI/CD" -ForegroundColor White
Write-Host "git add ." -ForegroundColor Gray
Write-Host "git commit -m 'Configure CI/CD pipeline with Azure resources'" -ForegroundColor Gray
Write-Host "git push origin main" -ForegroundColor Gray
Write-Host ""
Write-Host "# Monitor the workflow" -ForegroundColor White
Write-Host "gh workflow list" -ForegroundColor Gray
Write-Host "gh run list" -ForegroundColor Gray
Write-Host "gh run watch" -ForegroundColor Gray

Write-Host ""
Write-Host "STEP 7: Verify Resources" -ForegroundColor Cyan
Write-Host "-------------------------" -ForegroundColor Cyan
Write-Host "# Check Azure resources" -ForegroundColor White
Write-Host "az resource list --resource-group security-copilot-rg --output table" -ForegroundColor Gray
Write-Host ""
Write-Host "# Check GitHub secrets" -ForegroundColor White
Write-Host "gh secret list --repo kineticKshitij/Security-copilot-agent" -ForegroundColor Gray
Write-Host ""
Write-Host "# Check GitHub environments" -ForegroundColor White
Write-Host "gh api repos/kineticKshitij/Security-copilot-agent/environments" -ForegroundColor Gray

Write-Host ""
Write-Host "📊 QUICK REFERENCE COMMANDS" -ForegroundColor Yellow
Write-Host "============================" -ForegroundColor Yellow
Write-Host ""
Write-Host "# View workflow runs" -ForegroundColor White
Write-Host "gh run list --repo kineticKshitij/Security-copilot-agent" -ForegroundColor Gray
Write-Host ""
Write-Host "# View specific workflow run" -ForegroundColor White
Write-Host "gh run view RUN_ID --repo kineticKshitij/Security-copilot-agent" -ForegroundColor Gray
Write-Host ""
Write-Host "# Check app service logs" -ForegroundColor White
Write-Host "az webapp log tail --name security-copilot-prod --resource-group security-copilot-rg" -ForegroundColor Gray
Write-Host ""
Write-Host "# Check container registry images" -ForegroundColor White
Write-Host "az acr repository list --name YOUR_REGISTRY_NAME" -ForegroundColor Gray
Write-Host ""
Write-Host "# Update a secret" -ForegroundColor White
Write-Host "gh secret set SECRET_NAME --repo kineticKshitij/Security-copilot-agent" -ForegroundColor Gray

Write-Host ""
Write-Host "🔗 USEFUL LINKS" -ForegroundColor Yellow
Write-Host "===============" -ForegroundColor Yellow
Write-Host "GitHub Repository: https://github.com/kineticKshitij/Security-copilot-agent" -ForegroundColor Cyan
Write-Host "GitHub Actions: https://github.com/kineticKshitij/Security-copilot-agent/actions" -ForegroundColor Cyan
Write-Host "GitHub Secrets: https://github.com/kineticKshitij/Security-copilot-agent/settings/secrets/actions" -ForegroundColor Cyan
Write-Host "GitHub Environments: https://github.com/kineticKshitij/Security-copilot-agent/settings/environments" -ForegroundColor Cyan
Write-Host "Azure Portal: https://portal.azure.com" -ForegroundColor Cyan

Write-Host ""
Write-Host "✅ Setup guide complete! Follow the steps above to configure your CI/CD pipeline." -ForegroundColor Green
