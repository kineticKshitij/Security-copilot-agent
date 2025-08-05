# Security Copilot Agent

A comprehensive Azure security automation tool that scans Network Security Groups (NSGs) and firewall rules for misconfigurations, automatically creates GitHub issues with remediation steps, generates pull requests for fixes, and logs all findings to Azure SQL Database.

## Features

- **🔍 Security Scanning**: Automated analysis of Azure NSGs and firewall rules
- **🛠️ Auto-Remediation**: Generates GitHub issues and PRs with fix recommendations
- **📊 Audit Logging**: Comprehensive logging to Azure SQL Database
- **🍯 Honeypot Integration**: Real-time threat response capabilities
- **☁️ Azure Native**: Designed for Azure hosting with managed identity support
- **🔄 CI/CD Ready**: GitHub Actions workflows included

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Azure NSGs    │    │   Firewall      │    │   Honeypot      │
│   & Rules       │    │   Rules         │    │   Logs          │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────┬───────────┘                      │
                     │                                  │
          ┌─────────▼─────────┐                        │
          │  Security Copilot │◄───────────────────────┘
          │     Agent         │
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐    ┌─────────────────┐
          │   GitHub API      │    │   Azure SQL     │
          │ (Issues & PRs)    │    │   Database      │
          └───────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.9+
- Azure subscription with appropriate permissions
- GitHub repository with write access
- Azure SQL Database (optional)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd security-copilot-agent
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your Azure and GitHub credentials
```

4. Run the scanner:
```bash
python -m security_copilot scan --subscription-id <your-subscription-id>
```

## Configuration

Create a `.env` file in the root directory:

```env
# Azure Configuration
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_TENANT_ID=your-tenant-id

# GitHub Configuration
GITHUB_TOKEN=your-github-token
GITHUB_REPO_OWNER=your-github-username
GITHUB_REPO_NAME=your-repo-name

# Azure SQL Configuration (Optional)
AZURE_SQL_SERVER=your-sql-server.database.windows.net
AZURE_SQL_DATABASE=security-copilot
AZURE_SQL_USERNAME=your-username
AZURE_SQL_PASSWORD=your-password

# Honeypot Configuration (Optional)
HONEYPOT_LOG_PATH=/path/to/honeypot/logs
HONEYPOT_API_ENDPOINT=https://your-honeypot-api.com
```

## Usage

### CLI Commands

```bash
# Scan all NSGs in a subscription
security-copilot scan --subscription-id <sub-id>

# Scan specific resource group
security-copilot scan --resource-group <rg-name>

# Scan with auto-remediation
security-copilot scan --auto-remediate

# Monitor honeypot logs
security-copilot monitor --honeypot-logs

# Generate compliance report
security-copilot report --format json
```

### Programmatic Usage

```python
from security_copilot import SecurityScanner, GitHubIntegration

# Initialize scanner
scanner = SecurityScanner(subscription_id="your-sub-id")

# Scan for misconfigurations
findings = scanner.scan_nsgs()

# Create GitHub issues for findings
github = GitHubIntegration(token="your-token")
github.create_issues_for_findings(findings)
```

## Security Rules

The agent checks for common misconfigurations:

- **Open to Internet (0.0.0.0/0)**: High-risk inbound rules
- **Unrestricted SSH/RDP**: Port 22/3389 open to all
- **Database Ports**: Common DB ports exposed externally
- **Administrative Ports**: Management interfaces exposed
- **Weak Protocols**: Outdated or insecure protocols
- **Missing Network Segmentation**: Overly permissive rules

## Deployment

### Azure Container Instances

```bash
# Build and deploy to Azure
az container create \
  --resource-group security-copilot-rg \
  --name security-copilot \
  --image security-copilot:latest \
  --environment-variables AZURE_SUBSCRIPTION_ID=<sub-id>
```

### GitHub Actions

The project includes CI/CD workflows for:
- Automated testing
- Security scanning
- Container building
- Azure deployment

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

For issues and questions:
- GitHub Issues: Report bugs and feature requests
- Documentation: See [docs/](docs/) directory
- Security Issues: Email security@company.com
