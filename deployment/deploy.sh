#!/bin/bash

# Security Copilot Agent - Azure Deployment Script
# This script deploys the Security Copilot Agent to Azure

set -e

# Configuration
RESOURCE_GROUP_NAME="security-copilot-rg"
LOCATION="East US"
APP_NAME="security-copilot"
ENVIRONMENT="staging"
TEMPLATE_FILE="azure-infrastructure.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if required tools are installed
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v az &> /dev/null; then
        print_error "Azure CLI is not installed. Please install it first."
        exit 1
    fi
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install it first."
        exit 1
    fi
    
    print_status "Prerequisites check passed."
}

# Function to login to Azure
azure_login() {
    print_status "Checking Azure login status..."
    
    if ! az account show &> /dev/null; then
        print_status "Please login to Azure..."
        az login
    else
        print_status "Already logged in to Azure."
    fi
    
    # Show current subscription
    CURRENT_SUB=$(az account show --query name -o tsv)
    print_status "Current subscription: $CURRENT_SUB"
}

# Function to create resource group
create_resource_group() {
    print_status "Creating resource group: $RESOURCE_GROUP_NAME"
    
    if az group show --name $RESOURCE_GROUP_NAME &> /dev/null; then
        print_warning "Resource group $RESOURCE_GROUP_NAME already exists."
    else
        az group create --name $RESOURCE_GROUP_NAME --location "$LOCATION"
        print_status "Resource group created successfully."
    fi
}

# Function to build and push container image
build_and_push_image() {
    print_status "Building container image..."
    
    # Get the container registry from environment or use default
    REGISTRY=${CONTAINER_REGISTRY:-"ghcr.io/$(whoami)"}
    IMAGE_NAME="$REGISTRY/security-copilot-agent"
    IMAGE_TAG="${GITHUB_SHA:-latest}"
    FULL_IMAGE_NAME="$IMAGE_NAME:$IMAGE_TAG"
    
    print_status "Building image: $FULL_IMAGE_NAME"
    
    # Build the image
    docker build -t $FULL_IMAGE_NAME .
    
    # Push the image
    print_status "Pushing image to registry..."
    docker push $FULL_IMAGE_NAME
    
    echo $FULL_IMAGE_NAME
}

# Function to deploy infrastructure
deploy_infrastructure() {
    local image_name=$1
    
    print_status "Deploying Azure infrastructure..."
    
    # Prompt for required parameters
    read -p "Enter Azure Subscription ID to monitor: " AZURE_SUBSCRIPTION_ID
    read -p "Enter GitHub repository owner: " GITHUB_REPO_OWNER
    read -p "Enter GitHub repository name: " GITHUB_REPO_NAME
    read -s -p "Enter GitHub personal access token: " GITHUB_TOKEN
    echo
    read -p "Enter SQL Server name: " SQL_SERVER_NAME
    read -p "Enter SQL admin username: " SQL_ADMIN_USERNAME
    read -s -p "Enter SQL admin password: " SQL_ADMIN_PASSWORD
    echo
    
    # Deploy the ARM template
    az deployment group create \
        --resource-group $RESOURCE_GROUP_NAME \
        --template-file $TEMPLATE_FILE \
        --parameters \
            appName=$APP_NAME \
            environment=$ENVIRONMENT \
            containerImage="$image_name" \
            azureSubscriptionId="$AZURE_SUBSCRIPTION_ID" \
            githubToken="$GITHUB_TOKEN" \
            githubRepoOwner="$GITHUB_REPO_OWNER" \
            githubRepoName="$GITHUB_REPO_NAME" \
            sqlServerName="$SQL_SERVER_NAME" \
            sqlDatabaseName="security-copilot" \
            sqlAdminUsername="$SQL_ADMIN_USERNAME" \
            sqlAdminPassword="$SQL_ADMIN_PASSWORD"
    
    print_status "Infrastructure deployment completed."
}

# Function to setup database
setup_database() {
    print_status "Setting up database schema..."
    
    # Get the web app name
    WEB_APP_NAME="$APP_NAME-$ENVIRONMENT"
    
    # Run database migration via web app
    az webapp ssh --resource-group $RESOURCE_GROUP_NAME --name $WEB_APP_NAME --command "python -c 'from security_copilot.database import Base, engine; Base.metadata.create_all(bind=engine); print(\"Database schema created successfully\")'"
    
    print_status "Database setup completed."
}

# Function to run initial security scan
run_initial_scan() {
    print_status "Running initial security scan..."
    
    WEB_APP_NAME="$APP_NAME-$ENVIRONMENT"
    
    # Trigger initial scan
    az webapp ssh --resource-group $RESOURCE_GROUP_NAME --name $WEB_APP_NAME --command "python -m security_copilot.cli scan --output-format json"
    
    print_status "Initial scan completed."
}

# Function to setup monitoring
setup_monitoring() {
    print_status "Setting up monitoring and alerts..."
    
    # Create action group for alerts
    az monitor action-group create \
        --resource-group $RESOURCE_GROUP_NAME \
        --name "security-copilot-alerts" \
        --short-name "sec-alerts"
    
    # Create metric alert for high CPU usage
    az monitor metrics alert create \
        --resource-group $RESOURCE_GROUP_NAME \
        --name "high-cpu-alert" \
        --description "Alert when CPU usage is high" \
        --severity 2 \
        --condition "avg Percentage CPU > 80" \
        --window-size 5m \
        --evaluation-frequency 1m \
        --action "security-copilot-alerts"
    
    print_status "Monitoring setup completed."
}

# Function to display deployment summary
show_deployment_summary() {
    print_status "Deployment Summary"
    echo "===================="
    
    WEB_APP_NAME="$APP_NAME-$ENVIRONMENT"
    
    # Get the web app URL
    WEB_APP_URL=$(az webapp show --resource-group $RESOURCE_GROUP_NAME --name $WEB_APP_NAME --query defaultHostName -o tsv)
    
    echo "Resource Group: $RESOURCE_GROUP_NAME"
    echo "Web App Name: $WEB_APP_NAME"
    echo "Web App URL: https://$WEB_APP_URL"
    echo "Environment: $ENVIRONMENT"
    echo ""
    
    print_status "Next steps:"
    echo "1. Configure your GitHub repository with the webhook URL"
    echo "2. Set up scheduled scans in GitHub Actions"
    echo "3. Review and test the security scanning functionality"
    echo "4. Configure notification channels (Slack, Teams, email)"
    echo ""
    
    print_status "Useful commands:"
    echo "- View logs: az webapp log tail --resource-group $RESOURCE_GROUP_NAME --name $WEB_APP_NAME"
    echo "- SSH to container: az webapp ssh --resource-group $RESOURCE_GROUP_NAME --name $WEB_APP_NAME"
    echo "- View metrics: az monitor metrics list --resource /subscriptions/\$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP_NAME/providers/Microsoft.Web/sites/$WEB_APP_NAME"
}

# Main deployment function
main() {
    print_status "Starting Security Copilot Agent deployment..."
    
    # Check if template file exists
    if [ ! -f "$TEMPLATE_FILE" ]; then
        print_error "Template file $TEMPLATE_FILE not found. Please run this script from the deployment directory."
        exit 1
    fi
    
    check_prerequisites
    azure_login
    create_resource_group
    
    # Build and push image
    IMAGE_NAME=$(build_and_push_image)
    
    # Deploy infrastructure
    deploy_infrastructure "$IMAGE_NAME"
    
    # Setup database
    setup_database
    
    # Setup monitoring
    setup_monitoring
    
    # Run initial scan
    run_initial_scan
    
    # Show summary
    show_deployment_summary
    
    print_status "Deployment completed successfully! 🎉"
}

# Handle script arguments
case "$1" in
    "clean")
        print_warning "Cleaning up resources..."
        az group delete --name $RESOURCE_GROUP_NAME --yes --no-wait
        print_status "Cleanup initiated."
        ;;
    "logs")
        WEB_APP_NAME="$APP_NAME-$ENVIRONMENT"
        az webapp log tail --resource-group $RESOURCE_GROUP_NAME --name $WEB_APP_NAME
        ;;
    "status")
        WEB_APP_NAME="$APP_NAME-$ENVIRONMENT"
        az webapp show --resource-group $RESOURCE_GROUP_NAME --name $WEB_APP_NAME --query "{name:name,state:state,defaultHostName:defaultHostName}" -o table
        ;;
    *)
        main
        ;;
esac
