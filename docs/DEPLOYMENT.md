# 🚀 Deployment Guide - Security Copilot Agent

## Overview

This comprehensive deployment guide covers all deployment scenarios for the Security Copilot Agent, from development environments to enterprise-scale production deployments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Environment Types](#environment-types)
- [Deployment Options](#deployment-options)
- [Configuration Management](#configuration-management)
- [Monitoring & Logging](#monitoring--logging)
- [Security Hardening](#security-hardening)
- [Troubleshooting](#troubleshooting)
- [Maintenance](#maintenance)

## Prerequisites

### Azure Requirements
- **Azure Subscription** with the following permissions:
  - Security Reader
  - Network Contributor
  - Reader
  - SQL DB Contributor (for database logging)
- **Azure SQL Database** (recommended for production)
- **Azure Container Registry** (for container deployments)
- **Azure Key Vault** (for secrets management)

### Development Tools
- **Docker** 20.10+
- **Azure CLI** 2.50+
- **Python** 3.9+
- **Git** 2.30+

### Network Requirements
- **Outbound HTTPS (443)** to:
  - `management.azure.com` (Azure API)
  - `api.github.com` (GitHub API)
  - `login.microsoftonline.com` (Azure AD)
  - Your Azure SQL Database endpoint

## Environment Types

### Development Environment
**Use Case**: Local development and testing
**Resources**: Minimal Azure resources, local database
**Security**: Relaxed for development convenience

### Staging Environment  
**Use Case**: Pre-production testing and validation
**Resources**: Scaled-down production replica
**Security**: Production-like security controls

### Production Environment
**Use Case**: Live security monitoring and automation
**Resources**: High availability, redundancy, monitoring
**Security**: Full security hardening and compliance

## Deployment Options

## 1. Azure Container Instances (ACI) - Recommended

### Simple ACI Deployment
```bash
#!/bin/bash
# deploy-aci-simple.sh

# Variables
RESOURCE_GROUP="security-copilot-rg"
CONTAINER_NAME="security-copilot"
IMAGE_NAME="yourregistry.azurecr.io/security-copilot:latest"
LOCATION="eastus"

# Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# Deploy container
az container create \
  --resource-group $RESOURCE_GROUP \
  --name $CONTAINER_NAME \
  --image $IMAGE_NAME \
  --cpu 2 \
  --memory 4 \
  --restart-policy Always \
  --ports 8080 \
  --environment-variables \
    AZURE_SUBSCRIPTION_ID="$AZURE_SUBSCRIPTION_ID" \
    AZURE_CLIENT_ID="$AZURE_CLIENT_ID" \
    GITHUB_REPO_OWNER="$GITHUB_REPO_OWNER" \
    GITHUB_REPO_NAME="$GITHUB_REPO_NAME" \
  --secure-environment-variables \
    AZURE_CLIENT_SECRET="$AZURE_CLIENT_SECRET" \
    AZURE_TENANT_ID="$AZURE_TENANT_ID" \
    GITHUB_TOKEN="$GITHUB_TOKEN" \
    AZURE_SQL_PASSWORD="$AZURE_SQL_PASSWORD" \
  --log-analytics-workspace "$LOG_ANALYTICS_WORKSPACE_ID" \
  --log-analytics-workspace-key "$LOG_ANALYTICS_KEY"
```

### Advanced ACI with ARM Template
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "containerName": {
      "type": "string",
      "defaultValue": "security-copilot"
    },
    "imageTag": {
      "type": "string",
      "defaultValue": "latest"
    },
    "azureSubscriptionId": {
      "type": "string"
    },
    "azureClientId": {
      "type": "string"
    },
    "azureClientSecret": {
      "type": "securestring"
    },
    "azureTenantId": {
      "type": "string"
    },
    "githubToken": {
      "type": "securestring"
    },
    "sqlServerName": {
      "type": "string"
    },
    "sqlDatabaseName": {
      "type": "string",
      "defaultValue": "security-copilot"
    },
    "sqlUsername": {
      "type": "string"
    },
    "sqlPassword": {
      "type": "securestring"
    }
  },
  "resources": [
    {
      "type": "Microsoft.ContainerInstance/containerGroups",
      "apiVersion": "2021-10-01",
      "name": "[parameters('containerName')]",
      "location": "[resourceGroup().location]",
      "properties": {
        "containers": [
          {
            "name": "[parameters('containerName')]",
            "properties": {
              "image": "[concat('yourregistry.azurecr.io/security-copilot:', parameters('imageTag'))]",
              "ports": [
                {
                  "port": 8080,
                  "protocol": "TCP"
                }
              ],
              "environmentVariables": [
                {
                  "name": "AZURE_SUBSCRIPTION_ID",
                  "value": "[parameters('azureSubscriptionId')]"
                },
                {
                  "name": "AZURE_CLIENT_ID", 
                  "value": "[parameters('azureClientId')]"
                },
                {
                  "name": "AZURE_TENANT_ID",
                  "secureValue": "[parameters('azureTenantId')]"
                },
                {
                  "name": "AZURE_CLIENT_SECRET",
                  "secureValue": "[parameters('azureClientSecret')]"
                },
                {
                  "name": "GITHUB_TOKEN",
                  "secureValue": "[parameters('githubToken')]"
                },
                {
                  "name": "AZURE_SQL_SERVER",
                  "value": "[concat(parameters('sqlServerName'), '.database.windows.net')]"
                },
                {
                  "name": "AZURE_SQL_DATABASE",
                  "value": "[parameters('sqlDatabaseName')]"
                },
                {
                  "name": "AZURE_SQL_USERNAME",
                  "value": "[parameters('sqlUsername')]"
                },
                {
                  "name": "AZURE_SQL_PASSWORD",
                  "secureValue": "[parameters('sqlPassword')]"
                }
              ],
              "resources": {
                "requests": {
                  "cpu": 2,
                  "memoryInGB": 4
                }
              }
            }
          }
        ],
        "osType": "Linux",
        "restartPolicy": "Always",
        "ipAddress": {
          "type": "Public",
          "ports": [
            {
              "port": 8080,
              "protocol": "TCP"
            }
          ]
        }
      }
    }
  ]
}
```

## 2. Azure App Service

### App Service Deployment Script
```bash
#!/bin/bash
# deploy-appservice.sh

# Variables
RESOURCE_GROUP="security-copilot-rg"
APP_SERVICE_PLAN="security-copilot-plan"
WEB_APP_NAME="security-copilot-webapp"
LOCATION="eastus"
CONTAINER_IMAGE="yourregistry.azurecr.io/security-copilot:latest"

# Create App Service Plan
az appservice plan create \
  --name $APP_SERVICE_PLAN \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku P1V3 \
  --is-linux

# Create Web App
az webapp create \
  --resource-group $RESOURCE_GROUP \
  --plan $APP_SERVICE_PLAN \
  --name $WEB_APP_NAME \
  --deployment-container-image-name $CONTAINER_IMAGE

# Configure container settings
az webapp config container set \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --container-image-name $CONTAINER_IMAGE \
  --container-registry-url "https://yourregistry.azurecr.io" \
  --container-registry-user "$ACR_USERNAME" \
  --container-registry-password "$ACR_PASSWORD"

# Configure application settings
az webapp config appsettings set \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --settings \
    AZURE_SUBSCRIPTION_ID="$AZURE_SUBSCRIPTION_ID" \
    AZURE_CLIENT_ID="$AZURE_CLIENT_ID" \
    GITHUB_REPO_OWNER="$GITHUB_REPO_OWNER" \
    GITHUB_REPO_NAME="$GITHUB_REPO_NAME" \
    AZURE_SQL_SERVER="$AZURE_SQL_SERVER" \
    AZURE_SQL_DATABASE="$AZURE_SQL_DATABASE" \
    AZURE_SQL_USERNAME="$AZURE_SQL_USERNAME"

# Configure secure settings (stored in Key Vault)
az webapp config appsettings set \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --settings \
    AZURE_CLIENT_SECRET="@Microsoft.KeyVault(VaultName=your-keyvault;SecretName=azure-client-secret)" \
    AZURE_TENANT_ID="@Microsoft.KeyVault(VaultName=your-keyvault;SecretName=azure-tenant-id)" \
    GITHUB_TOKEN="@Microsoft.KeyVault(VaultName=your-keyvault;SecretName=github-token)" \
    AZURE_SQL_PASSWORD="@Microsoft.KeyVault(VaultName=your-keyvault;SecretName=sql-password)"

# Enable system-assigned managed identity
az webapp identity assign \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP

# Configure health check
az webapp config set \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --health-check-path "/health"
```

## 3. Azure Kubernetes Service (AKS) - Enterprise

### AKS Cluster Setup
```bash
#!/bin/bash
# setup-aks-cluster.sh

# Variables
RESOURCE_GROUP="security-copilot-rg"
CLUSTER_NAME="security-copilot-aks"
NODE_COUNT=3
NODE_SIZE="Standard_D4s_v3"
LOCATION="eastus"

# Create AKS cluster
az aks create \
  --resource-group $RESOURCE_GROUP \
  --name $CLUSTER_NAME \
  --node-count $NODE_COUNT \
  --node-vm-size $NODE_SIZE \
  --location $LOCATION \
  --enable-managed-identity \
  --enable-addons monitoring \
  --kubernetes-version 1.27.3 \
  --network-plugin azure \
  --network-policy azure \
  --enable-pod-security-policy

# Get credentials
az aks get-credentials \
  --resource-group $RESOURCE_GROUP \
  --name $CLUSTER_NAME

# Create namespace
kubectl create namespace security-copilot
```

### Kubernetes Manifests

#### Namespace and ServiceAccount
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: security-copilot
  labels:
    name: security-copilot
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: security-copilot-sa
  namespace: security-copilot
  annotations:
    azure.workload.identity/client-id: "your-managed-identity-client-id"
```

#### ConfigMap
```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: security-copilot-config
  namespace: security-copilot
data:
  AZURE_SUBSCRIPTION_ID: "e17f4f74-0d91-4313-9716-0a2edcceefb7"
  GITHUB_REPO_OWNER: "kineticKshitij"
  GITHUB_REPO_NAME: "Security-copilot-agent"
  AZURE_SQL_SERVER: "your-server.database.windows.net"
  AZURE_SQL_DATABASE: "security-copilot"
  AZURE_SQL_USERNAME: "security_admin"
  SCAN_INTERVAL_MINUTES: "60"
  LOG_LEVEL: "INFO"
```

#### Secret
```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: security-copilot-secrets
  namespace: security-copilot
type: Opaque
data:
  AZURE_CLIENT_SECRET: <base64-encoded-secret>
  AZURE_TENANT_ID: <base64-encoded-tenant-id>
  GITHUB_TOKEN: <base64-encoded-github-token>
  AZURE_SQL_PASSWORD: <base64-encoded-sql-password>
```

#### Deployment
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-copilot
  namespace: security-copilot
  labels:
    app: security-copilot
spec:
  replicas: 3
  selector:
    matchLabels:
      app: security-copilot
  template:
    metadata:
      labels:
        app: security-copilot
    spec:
      serviceAccountName: security-copilot-sa
      containers:
      - name: security-copilot
        image: yourregistry.azurecr.io/security-copilot:latest
        ports:
        - containerPort: 8080
          name: http
        envFrom:
        - configMapRef:
            name: security-copilot-config
        - secretRef:
            name: security-copilot-secrets
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir: {}
      imagePullSecrets:
      - name: acr-secret
```

#### Service and Ingress
```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: security-copilot-service
  namespace: security-copilot
spec:
  selector:
    app: security-copilot
  ports:
  - name: http
    port: 80
    targetPort: 8080
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: security-copilot-ingress
  namespace: security-copilot
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - security-copilot.your-domain.com
    secretName: security-copilot-tls
  rules:
  - host: security-copilot.your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: security-copilot-service
            port:
              number: 80
```

#### HorizontalPodAutoscaler
```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: security-copilot-hpa
  namespace: security-copilot
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: security-copilot
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Configuration Management

### Environment-Specific Configuration

#### Development (.env.dev)
```env
# Development Environment Configuration
LOG_LEVEL=DEBUG
SCAN_INTERVAL_MINUTES=5
ENABLE_AUTO_REMEDIATION=false
DRY_RUN_MODE=true

# Relaxed security for development
SKIP_SSL_VERIFICATION=true
ENABLE_DEBUG_ENDPOINTS=true

# Local database
USE_LOCAL_DATABASE=true
DATABASE_URL=sqlite:///local_security_copilot.db

# Development GitHub repo
GITHUB_REPO_OWNER=your-dev-account
GITHUB_REPO_NAME=security-copilot-agent-dev
```

#### Staging (.env.staging)
```env
# Staging Environment Configuration
LOG_LEVEL=INFO
SCAN_INTERVAL_MINUTES=30
ENABLE_AUTO_REMEDIATION=false
DRY_RUN_MODE=false

# Production-like security
SKIP_SSL_VERIFICATION=false
ENABLE_DEBUG_ENDPOINTS=false

# Azure SQL Database
AZURE_SQL_SERVER=staging-sql-server.database.windows.net
AZURE_SQL_DATABASE=security-copilot-staging

# Staging GitHub repo
GITHUB_REPO_OWNER=your-org
GITHUB_REPO_NAME=security-copilot-agent-staging
```

#### Production (.env.prod)
```env
# Production Environment Configuration
LOG_LEVEL=WARNING
SCAN_INTERVAL_MINUTES=60
ENABLE_AUTO_REMEDIATION=true
DRY_RUN_MODE=false

# Production security
SKIP_SSL_VERIFICATION=false
ENABLE_DEBUG_ENDPOINTS=false
ENFORCE_HTTPS=true

# High availability database
AZURE_SQL_SERVER=prod-sql-server.database.windows.net
AZURE_SQL_DATABASE=security-copilot-prod

# Production GitHub repo
GITHUB_REPO_OWNER=your-org
GITHUB_REPO_NAME=security-copilot-agent
```

### Azure Key Vault Integration

#### Key Vault Setup Script
```bash
#!/bin/bash
# setup-keyvault.sh

# Variables
RESOURCE_GROUP="security-copilot-rg"
KEY_VAULT_NAME="security-copilot-kv"
LOCATION="eastus"

# Create Key Vault
az keyvault create \
  --name $KEY_VAULT_NAME \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku standard \
  --enable-soft-delete true \
  --retention-days 90

# Store secrets
az keyvault secret set \
  --vault-name $KEY_VAULT_NAME \
  --name "azure-client-secret" \
  --value "$AZURE_CLIENT_SECRET"

az keyvault secret set \
  --vault-name $KEY_VAULT_NAME \
  --name "azure-tenant-id" \
  --value "$AZURE_TENANT_ID"

az keyvault secret set \
  --vault-name $KEY_VAULT_NAME \
  --name "github-token" \
  --value "$GITHUB_TOKEN"

az keyvault secret set \
  --vault-name $KEY_VAULT_NAME \
  --name "sql-password" \
  --value "$AZURE_SQL_PASSWORD"

# Grant access to managed identity
az keyvault set-policy \
  --name $KEY_VAULT_NAME \
  --object-id "$MANAGED_IDENTITY_OBJECT_ID" \
  --secret-permissions get list
```

## Monitoring & Logging

### Azure Monitor Configuration

#### Application Insights Setup
```bash
#!/bin/bash
# setup-monitoring.sh

# Variables
RESOURCE_GROUP="security-copilot-rg"
APP_INSIGHTS_NAME="security-copilot-insights"
LOG_ANALYTICS_NAME="security-copilot-logs"
LOCATION="eastus"

# Create Log Analytics Workspace
az monitor log-analytics workspace create \
  --resource-group $RESOURCE_GROUP \
  --workspace-name $LOG_ANALYTICS_NAME \
  --location $LOCATION

# Create Application Insights
az monitor app-insights component create \
  --app $APP_INSIGHTS_NAME \
  --location $LOCATION \
  --resource-group $RESOURCE_GROUP \
  --application-type web \
  --workspace "$LOG_ANALYTICS_NAME"

# Get instrumentation key
INSTRUMENTATION_KEY=$(az monitor app-insights component show \
  --app $APP_INSIGHTS_NAME \
  --resource-group $RESOURCE_GROUP \
  --query instrumentationKey -o tsv)

echo "Application Insights Instrumentation Key: $INSTRUMENTATION_KEY"
```

#### Custom Metrics and Alerts
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Insights/metricAlerts",
      "apiVersion": "2018-03-01",
      "name": "HighSeverityFindingsAlert",
      "properties": {
        "description": "Alert when critical security findings are detected",
        "severity": 1,
        "enabled": true,
        "scopes": [
          "[resourceId('Microsoft.Insights/components', 'security-copilot-insights')]"
        ],
        "evaluationFrequency": "PT5M",
        "windowSize": "PT15M",
        "criteria": {
          "odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
          "allOf": [
            {
              "name": "CriticalFindings",
              "metricName": "security_findings_critical",
              "operator": "GreaterThan",
              "threshold": 0,
              "timeAggregation": "Count"
            }
          ]
        },
        "actions": [
          {
            "actionGroupId": "[resourceId('Microsoft.Insights/actionGroups', 'SecurityTeamActionGroup')]"
          }
        ]
      }
    }
  ]
}
```

### Logging Configuration

#### Structured Logging Setup
```python
# logging_config.py
import logging
import json
from datetime import datetime
from azure.monitor.opentelemetry import configure_azure_monitor

class StructuredFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
            
        return json.dumps(log_entry)

def setup_logging():
    # Configure Azure Monitor
    configure_azure_monitor(
        connection_string=os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING")
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Console handler with structured format
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(StructuredFormatter())
    root_logger.addHandler(console_handler)
    
    # File handler for local debugging
    if os.getenv("ENVIRONMENT") == "development":
        file_handler = logging.FileHandler("security_copilot.log")
        file_handler.setFormatter(StructuredFormatter())
        root_logger.addHandler(file_handler)
```

## Security Hardening

### Container Security

#### Secure Dockerfile
```dockerfile
# Use specific version and slim image
FROM python:3.11.5-slim-bullseye

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Install security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appuser . .

# Remove unnecessary files
RUN find . -type f -name "*.pyc" -delete && \
    find . -type d -name "__pycache__" -delete

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run application
CMD ["python", "-m", "security_copilot.main"]
```

#### Security Scanning
```bash
#!/bin/bash
# security-scan.sh

# Scan container for vulnerabilities
echo "Scanning container for vulnerabilities..."
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $(pwd):/project \
    aquasec/trivy image security-copilot:latest

# Scan for secrets
echo "Scanning for secrets..."
docker run --rm -v $(pwd):/project \
    trufflesecurity/trufflehog:latest filesystem /project

# Static code analysis
echo "Running static code analysis..."
docker run --rm -v $(pwd):/project \
    pipelinecomponents/bandit bandit -r /project/security_copilot
```

### Network Security

#### Network Security Group Rules
```json
{
  "securityRules": [
    {
      "name": "AllowHTTPS",
      "properties": {
        "protocol": "Tcp",
        "sourcePortRange": "*",
        "destinationPortRange": "443",
        "sourceAddressPrefix": "*",
        "destinationAddressPrefix": "*",
        "access": "Allow",
        "priority": 100,
        "direction": "Inbound"
      }
    },
    {
      "name": "AllowHTTP",
      "properties": {
        "protocol": "Tcp",
        "sourcePortRange": "*",
        "destinationPortRange": "80",
        "sourceAddressPrefix": "*",
        "destinationAddressPrefix": "*",
        "access": "Allow",
        "priority": 110,
        "direction": "Inbound"
      }
    },
    {
      "name": "DenyAll",
      "properties": {
        "protocol": "*",
        "sourcePortRange": "*",
        "destinationPortRange": "*",
        "sourceAddressPrefix": "*",
        "destinationAddressPrefix": "*",
        "access": "Deny",
        "priority": 4096,
        "direction": "Inbound"
      }
    }
  ]
}
```

## Troubleshooting

### Common Issues

#### Issue: Container Fails to Start
```bash
# Check container logs
az container logs --resource-group security-copilot-rg --name security-copilot

# Check container events
az container show --resource-group security-copilot-rg --name security-copilot --query "containers[0].instanceView"

# Debug with interactive shell
az container exec --resource-group security-copilot-rg --name security-copilot --exec-command "/bin/bash"
```

#### Issue: Database Connection Fails
```bash
# Test SQL connectivity
python -c "
import pyodbc
server = 'your-server.database.windows.net'
database = 'security-copilot'
username = 'your-username'
password = 'your-password'
try:
    conn = pyodbc.connect(f'DRIVER={{ODBC Driver 18 for SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password}')
    print('Database connection successful')
except Exception as e:
    print(f'Database connection failed: {e}')
"
```

#### Issue: Azure Authentication Fails
```bash
# Test Azure authentication
az account show
az ad signed-in-user show

# Test service principal
az login --service-principal \
  --username "$AZURE_CLIENT_ID" \
  --password "$AZURE_CLIENT_SECRET" \
  --tenant "$AZURE_TENANT_ID"
```

### Diagnostic Commands

#### Health Check Script
```bash
#!/bin/bash
# health-check.sh

echo "=== Security Copilot Health Check ==="

# Check Azure connectivity
echo "Checking Azure connectivity..."
curl -s "https://management.azure.com/" > /dev/null && echo "✓ Azure API reachable" || echo "✗ Azure API unreachable"

# Check GitHub connectivity
echo "Checking GitHub connectivity..."
curl -s "https://api.github.com/" > /dev/null && echo "✓ GitHub API reachable" || echo "✗ GitHub API unreachable"

# Check database connectivity
echo "Checking database connectivity..."
python -c "
import os
import pyodbc
try:
    server = os.getenv('AZURE_SQL_SERVER')
    database = os.getenv('AZURE_SQL_DATABASE')
    username = os.getenv('AZURE_SQL_USERNAME')
    password = os.getenv('AZURE_SQL_PASSWORD')
    conn = pyodbc.connect(f'DRIVER={{ODBC Driver 18 for SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password}')
    print('✓ Database connection successful')
except Exception as e:
    print(f'✗ Database connection failed: {e}')
"

# Check application status
echo "Checking application status..."
curl -s "http://localhost:8080/health" > /dev/null && echo "✓ Application responding" || echo "✗ Application not responding"

echo "=== Health Check Complete ==="
```

## Maintenance

### Backup Procedures

#### Database Backup
```bash
#!/bin/bash
# backup-database.sh

# Variables
RESOURCE_GROUP="security-copilot-rg"
SQL_SERVER="your-sql-server"
DATABASE="security-copilot"
STORAGE_ACCOUNT="backupstorage"
CONTAINER="database-backups"
BACKUP_NAME="security-copilot-$(date +%Y%m%d-%H%M%S).bacpac"

# Export database
az sql db export \
  --resource-group $RESOURCE_GROUP \
  --server $SQL_SERVER \
  --name $DATABASE \
  --storage-key-type StorageAccessKey \
  --storage-key "$STORAGE_KEY" \
  --storage-uri "https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER/$BACKUP_NAME" \
  --admin-user "$SQL_ADMIN_USER" \
  --admin-password "$SQL_ADMIN_PASSWORD"

echo "Database backup completed: $BACKUP_NAME"
```

#### Configuration Backup
```bash
#!/bin/bash
# backup-config.sh

# Create backup directory
BACKUP_DIR="./backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup environment files
cp .env* "$BACKUP_DIR/"

# Backup Kubernetes manifests
if [ -d "k8s" ]; then
    cp -r k8s "$BACKUP_DIR/"
fi

# Backup custom rules
if [ -d "custom-rules" ]; then
    cp -r custom-rules "$BACKUP_DIR/"
fi

# Create archive
tar -czf "security-copilot-config-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$BACKUP_DIR" .

echo "Configuration backup completed"
```

### Update Procedures

#### Rolling Update Script
```bash
#!/bin/bash
# rolling-update.sh

# Variables
NEW_IMAGE_TAG="$1"
NAMESPACE="security-copilot"
DEPLOYMENT="security-copilot"

if [ -z "$NEW_IMAGE_TAG" ]; then
    echo "Usage: $0 <new-image-tag>"
    exit 1
fi

echo "Starting rolling update to version: $NEW_IMAGE_TAG"

# Update deployment image
kubectl set image deployment/$DEPLOYMENT \
    security-copilot=yourregistry.azurecr.io/security-copilot:$NEW_IMAGE_TAG \
    -n $NAMESPACE

# Wait for rollout to complete
kubectl rollout status deployment/$DEPLOYMENT -n $NAMESPACE

# Verify deployment
kubectl get pods -n $NAMESPACE -l app=security-copilot

echo "Rolling update completed successfully"
```

### Performance Optimization

#### Resource Monitoring Script
```bash
#!/bin/bash
# monitor-resources.sh

echo "=== Resource Usage Monitor ==="

# CPU and Memory usage
echo "CPU and Memory usage:"
kubectl top pods -n security-copilot

# Pod status
echo -e "\nPod status:"
kubectl get pods -n security-copilot -o wide

# Service endpoints
echo -e "\nService endpoints:"
kubectl get endpoints -n security-copilot

# Horizontal Pod Autoscaler status
echo -e "\nHPA status:"
kubectl get hpa -n security-copilot

# Recent events
echo -e "\nRecent events:"
kubectl get events -n security-copilot --sort-by='.lastTimestamp' | tail -10
```

---

## Support and Next Steps

### Deployment Support
- 📧 **Email**: deployment-support@security-copilot.com
- 💬 **Discord**: [#deployment-help](https://discord.gg/security-copilot)
- 📚 **Documentation**: [docs.security-copilot.com](https://docs.security-copilot.com)

### Professional Services
- 🏢 **Enterprise Deployment**: Contact professional-services@security-copilot.com
- 🎓 **Training & Certification**: Available for enterprise customers
- 🤝 **Managed Deployment**: Full deployment and maintenance service available

This deployment guide covers all aspects of deploying Security Copilot Agent in various environments. Choose the deployment option that best fits your requirements and follow the security best practices outlined above.
