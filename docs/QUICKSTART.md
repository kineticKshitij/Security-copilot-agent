# Security Copilot Agent - Quick Start Guide

## Overview

The Security Copilot Agent is an automated Azure security scanner that continuously monitors your infrastructure for misconfigurations and provides automated remediation through GitHub integration.

## Prerequisites

- Python 3.9 or higher
- Azure subscription with Network Reader permissions
- GitHub repository with write access
- Optional: Azure SQL Database for audit logging

## Installation

### Option 1: Local Development

1. **Clone and Setup**
```bash
git clone <repository-url>
cd security-copilot-agent
pip install -r requirements.txt
```

2. **Configure Environment**
```bash
cp .env.example .env
# Edit .env with your credentials
```

3. **Run Initial Scan**
```bash
python -m security_copilot.cli scan --subscription-id <your-sub-id>
```

### Option 2: Azure Deployment

1. **Quick Deploy**
```bash
cd deployment
./deploy.sh
```

2. **Manual Deployment**
```bash
az group create --name security-copilot-rg --location "East US"
az deployment group create \
  --resource-group security-copilot-rg \
  --template-file azure-infrastructure.json \
  --parameters @parameters.json
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_SUBSCRIPTION_ID` | Yes | Azure subscription to monitor |
| `AZURE_CLIENT_ID` | Yes* | Service principal client ID |
| `AZURE_CLIENT_SECRET` | Yes* | Service principal secret |
| `AZURE_TENANT_ID` | Yes* | Azure tenant ID |
| `USE_MANAGED_IDENTITY` | No | Use managed identity instead of SP |
| `GITHUB_TOKEN` | Yes | GitHub personal access token |
| `GITHUB_REPO_OWNER` | Yes | GitHub repository owner |
| `GITHUB_REPO_NAME` | Yes | GitHub repository name |
| `AZURE_SQL_CONNECTION_STRING` | No | Azure SQL for audit logging |

*Not required if using managed identity in Azure

### GitHub Token Permissions

Your GitHub token needs the following permissions:
- `repo` - Full control of private repositories
- `issues` - Read and write access to issues
- `pull_requests` - Read and write access to pull requests

## Usage Examples

### Basic Scanning

```bash
# Scan entire subscription
security-copilot scan

# Scan specific resource groups
security-copilot scan --resource-group rg1 --resource-group rg2

# Scan with auto-remediation
security-copilot scan --auto-remediate

# JSON output for automation
security-copilot scan --output-format json > results.json
```

### Monitoring

```bash
# List current findings
security-copilot list-findings

# Filter by severity
security-copilot list-findings --severity CRITICAL

# View scan history
security-copilot scan-history

# Real-time monitoring
security-copilot monitor --honeypot-logs
```

### Reporting

```bash
# Generate compliance report
security-copilot report --format json --output compliance.json

# System status
security-copilot status
```

## Security Rules

The agent checks for these common misconfigurations:

### Critical Findings
- **Unrestricted SSH/RDP**: Ports 22/3389 open to 0.0.0.0/0
- **Database Exposure**: Database ports accessible from internet
- **Admin Interface Exposure**: Management ports exposed publicly

### High Findings
- **Open to Internet**: Any service accessible from 0.0.0.0/0
- **Overly Permissive Rules**: Rules allowing too much access

### Medium/Low Findings
- **Weak Protocols**: Unencrypted protocols in use
- **Missing Network Segmentation**: Lack of proper network isolation

## GitHub Integration

### Issues Created
- Detailed security finding description
- Current configuration details
- Step-by-step remediation instructions
- Risk assessment and CVSS scores
- Automated labeling and categorization

### Pull Requests
- Auto-generated remediation scripts
- Safe defaults and validation
- Documentation and testing instructions
- Draft PRs for safety review

### Example Issue Content
```markdown
## 🚨 Security Finding: NSG Rule allows unrestricted SSH access

**Severity**: CRITICAL
**Risk Score**: 95/100

### Description
The NSG rule 'allow-ssh' allows SSH access from any internet source...

### Remediation Steps
1. Restrict source IP to specific management networks
2. Enable Azure Bastion for secure remote access
3. Implement multi-factor authentication
...
```

## Honeypot Integration

### Log Monitoring
```bash
# Monitor honeypot logs
export HONEYPOT_LOG_PATH=/var/log/honeypot
security-copilot monitor --honeypot-logs
```

### API Integration
```bash
# Configure API endpoint
export HONEYPOT_API_ENDPOINT=https://honeypot-api.com/api/v1
export HONEYPOT_API_KEY=your-api-key
```

### Real-time Correlation
- Correlates attack patterns with exposed services
- Creates security findings for active attacks
- Generates threat intelligence reports
- Sends real-time alerts for critical threats

## Database Logging

### Schema
- `security_findings` - All detected misconfigurations
- `scan_results` - Scan execution history
- `honeypot_events` - Security events from honeypots
- `audit_logs` - System operation audit trail

### Queries
```sql
-- Get critical findings by resource group
SELECT * FROM security_findings 
WHERE severity = 'CRITICAL' 
AND resource_group = 'production-rg'
ORDER BY detected_at DESC;

-- Scan performance metrics
SELECT 
  DATE(started_at) as scan_date,
  COUNT(*) as scan_count,
  AVG(total_findings) as avg_findings
FROM scan_results 
WHERE started_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY DATE(started_at);
```

## Advanced Configuration

### Custom Security Rules
```python
# Add custom rule to scanner.py
def _check_custom_vulnerability(self, rule: SecurityRule) -> List[SecurityFinding]:
    findings = []
    # Your custom logic here
    return findings
```

### Notification Channels
```bash
# Slack integration
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Microsoft Teams
export TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...

# Email alerts
export EMAIL_SMTP_SERVER=smtp.gmail.com
export EMAIL_USERNAME=alerts@company.com
```

### Scheduled Scanning
```yaml
# GitHub Actions (.github/workflows/security-scan.yml)
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC
```

## Troubleshooting

### Common Issues

1. **Azure Authentication Errors**
```bash
# Verify credentials
az login
az account show

# Check permissions
az role assignment list --assignee <principal-id>
```

2. **GitHub API Rate Limits**
```bash
# Check rate limit status
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/rate_limit
```

3. **Database Connection Issues**
```bash
# Test SQL connection
python -c "from security_copilot.database import db_manager; print(db_manager.is_enabled())"
```

### Debug Mode
```bash
# Enable verbose logging
export LOG_LEVEL=DEBUG
security-copilot --verbose scan
```

### Health Checks
```bash
# System status
security-copilot status

# Test individual components
python -c "from security_copilot import SecurityScanner; print('Scanner OK')"
```

## Security Considerations

### Principle of Least Privilege
- Use minimal required Azure permissions
- Rotate GitHub tokens regularly
- Enable managed identity in Azure
- Store secrets in Azure Key Vault

### Safe Auto-Remediation
- All PRs created as drafts
- Manual review required before merge
- Backup configurations before changes
- Test in non-production first

### Audit and Compliance
- Complete audit logging to database
- Immutable security findings records
- Regular compliance reporting
- Integration with SIEM systems

## Support and Contributing

### Getting Help
- Check the [GitHub Issues](https://github.com/your-org/security-copilot-agent/issues)
- Review the [Documentation](docs/)
- Contact the security team

### Contributing
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request
5. Ensure all tests pass

### Development Setup
```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest black flake8 mypy

# Run tests
pytest tests/ -v

# Code formatting
black src/
flake8 src/
mypy src/
```
