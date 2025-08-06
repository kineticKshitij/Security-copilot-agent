#!/bin/bash
# GitHub Secrets and Environments Setup Script (Linux/Mac version)
# This script configures GitHub repository secrets and environments using GitHub CLI

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Default values
OWNER=""
REPO=""
AZURE_SUBSCRIPTION_ID=""
AZURE_CLIENT_ID=""
AZURE_CLIENT_SECRET=""
AZURE_TENANT_ID=""
AZURE_SQL_CONNECTION_STRING=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --owner)
            OWNER="$2"
            shift 2
            ;;
        --repo)
            REPO="$2"
            shift 2
            ;;
        --azure-subscription-id)
            AZURE_SUBSCRIPTION_ID="$2"
            shift 2
            ;;
        --azure-client-id)
            AZURE_CLIENT_ID="$2"
            shift 2
            ;;
        --azure-client-secret)
            AZURE_CLIENT_SECRET="$2"
            shift 2
            ;;
        --azure-tenant-id)
            AZURE_TENANT_ID="$2"
            shift 2
            ;;
        --azure-sql-connection-string)
            AZURE_SQL_CONNECTION_STRING="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 --owner <owner> --repo <repo> [options]"
            echo "Options:"
            echo "  --azure-subscription-id <id>"
            echo "  --azure-client-id <id>"
            echo "  --azure-client-secret <secret>"
            echo "  --azure-tenant-id <id>"
            echo "  --azure-sql-connection-string <string>"
            exit 0
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

# Check required parameters
if [ -z "$OWNER" ] || [ -z "$REPO" ]; then
    echo -e "${RED}Error: --owner and --repo are required${NC}"
    echo "Usage: $0 --owner <owner> --repo <repo> [options]"
    exit 1
fi

echo -e "${GREEN}🔐 Setting up GitHub secrets and environments...${NC}"

# Check if GitHub CLI is installed
if ! command -v gh &> /dev/null; then
    echo -e "${RED}❌ GitHub CLI is not installed. Please install it first:${NC}"
    echo -e "${YELLOW}   # On Ubuntu/Debian:${NC}"
    echo -e "${YELLOW}   curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg${NC}"
    echo -e "${YELLOW}   echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null${NC}"
    echo -e "${YELLOW}   sudo apt update && sudo apt install gh${NC}"
    echo ""
    echo -e "${YELLOW}   # On macOS:${NC}"
    echo -e "${YELLOW}   brew install gh${NC}"
    exit 1
fi

# Check if user is authenticated
if ! gh auth status &> /dev/null; then
    echo -e "${YELLOW}Please authenticate with GitHub first:${NC}"
    echo -e "${CYAN}gh auth login${NC}"
    exit 1
fi

# Repository reference
REPO_REF="$OWNER/$REPO"
echo -e "${YELLOW}Setting up secrets for repository: $REPO_REF${NC}"

# Function to set repository secret
set_github_secret() {
    local name=$1
    local value=$2
    
    if [ -n "$value" ]; then
        echo -e "${CYAN}Setting secret: $name${NC}"
        echo "$value" | gh secret set "$name" --repo "$REPO_REF"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Secret $name set successfully${NC}"
        else
            echo -e "${RED}❌ Failed to set secret $name${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️ Skipping $name - no value provided${NC}"
    fi
}

# Set Azure secrets
if [ -n "$AZURE_SUBSCRIPTION_ID" ]; then
    set_github_secret "AZURE_SUBSCRIPTION_ID" "$AZURE_SUBSCRIPTION_ID"
fi

if [ -n "$AZURE_CLIENT_ID" ]; then
    set_github_secret "AZURE_CLIENT_ID" "$AZURE_CLIENT_ID"
fi

if [ -n "$AZURE_CLIENT_SECRET" ]; then
    set_github_secret "AZURE_CLIENT_SECRET" "$AZURE_CLIENT_SECRET"
fi

if [ -n "$AZURE_TENANT_ID" ]; then
    set_github_secret "AZURE_TENANT_ID" "$AZURE_TENANT_ID"
fi

if [ -n "$AZURE_SQL_CONNECTION_STRING" ]; then
    set_github_secret "AZURE_SQL_CONNECTION_STRING" "$AZURE_SQL_CONNECTION_STRING"
fi

# Create Azure credentials JSON for deployment
if [ -n "$AZURE_CLIENT_ID" ] && [ -n "$AZURE_CLIENT_SECRET" ] && [ -n "$AZURE_SUBSCRIPTION_ID" ] && [ -n "$AZURE_TENANT_ID" ]; then
    AZURE_CREDENTIALS=$(cat <<EOF
{"clientId":"$AZURE_CLIENT_ID","clientSecret":"$AZURE_CLIENT_SECRET","subscriptionId":"$AZURE_SUBSCRIPTION_ID","tenantId":"$AZURE_TENANT_ID"}
EOF
)
    
    set_github_secret "AZURE_CREDENTIALS" "$AZURE_CREDENTIALS"
    set_github_secret "AZURE_CREDENTIALS_PROD" "$AZURE_CREDENTIALS"
fi

echo ""
echo -e "${YELLOW}🌍 Creating GitHub environments...${NC}"

# Create staging environment
echo -e "${CYAN}Creating staging environment...${NC}"
STAGING_ENV=$(cat <<EOF
{
  "wait_timer": 0,
  "reviewers": [],
  "deployment_branch_policy": {
    "protected_branches": false,
    "custom_branch_policies": true
  }
}
EOF
)

echo "$STAGING_ENV" | gh api "repos/$REPO_REF/environments/staging" --method PUT --input - || echo -e "${YELLOW}⚠️ Staging environment may already exist or failed to create${NC}"

# Create production environment with approval requirement
echo -e "${CYAN}Creating production environment with approval...${NC}"
USER_ID=$(gh api user --jq '.id')
PROD_ENV=$(cat <<EOF
{
  "wait_timer": 5,
  "reviewers": [
    {
      "type": "User",
      "id": $USER_ID
    }
  ],
  "deployment_branch_policy": {
    "protected_branches": true,
    "custom_branch_policies": false
  }
}
EOF
)

echo "$PROD_ENV" | gh api "repos/$REPO_REF/environments/production" --method PUT --input - || echo -e "${YELLOW}⚠️ Production environment may already exist or failed to create${NC}"

echo ""
echo -e "${GREEN}✅ GitHub setup completed!${NC}"
echo ""
echo -e "${YELLOW}📋 VERIFICATION STEPS:${NC}"
echo -e "${WHITE}1. Check secrets at: https://github.com/$REPO_REF/settings/secrets/actions${NC}"
echo -e "${WHITE}2. Check environments at: https://github.com/$REPO_REF/settings/environments${NC}"
echo -e "${WHITE}3. Trigger a workflow to test the setup${NC}"
echo ""
echo -e "${YELLOW}🔧 ADDITIONAL MANUAL STEPS:${NC}"
echo -e "${WHITE}1. Update ci-cd.yml with your actual Azure resource names${NC}"
echo -e "${WHITE}2. Configure branch protection rules if needed${NC}"
echo -e "${WHITE}3. Set up notification webhooks if desired${NC}"
