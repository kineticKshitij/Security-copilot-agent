"""
Test configuration and fixtures for Security Copilot Agent
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock
from datetime import datetime

# Test configuration
pytest_plugins = ['pytest_asyncio']


@pytest.fixture
def mock_azure_network_client():
    """Mock Azure Network Management Client"""
    client = MagicMock()
    
    # Mock NSG
    mock_nsg = MagicMock()
    mock_nsg.name = "test-nsg"
    mock_nsg.security_rules = []
    mock_nsg.default_security_rules = []
    
    client.network_security_groups.list.return_value = [mock_nsg]
    
    return client


@pytest.fixture
def mock_github_client():
    """Mock GitHub client"""
    from unittest.mock import MagicMock
    
    client = MagicMock()
    repo = MagicMock()
    
    # Mock repository
    client.get_repo.return_value = repo
    repo.full_name = "test-owner/test-repo"
    
    # Mock issue creation
    issue = MagicMock()
    issue.number = 123
    issue.html_url = "https://github.com/test-owner/test-repo/issues/123"
    repo.create_issue.return_value = issue
    
    return client


@pytest.fixture
def sample_security_rule():
    """Sample security rule for testing"""
    from security_copilot.models import SecurityRule, RuleType
    
    return SecurityRule(
        id="test-rule-id",
        name="test-rule",
        resource_group="test-rg",
        subscription_id="test-sub-id",
        rule_type=RuleType.NSG_RULE,
        priority=100,
        direction="Inbound",
        access="Allow",
        protocol="TCP",
        source_address_prefix="0.0.0.0/0",
        source_port_range="*",
        destination_address_prefix="*",
        destination_port_range="22"
    )


@pytest.fixture
def sample_security_finding():
    """Sample security finding for testing"""
    from security_copilot.models import SecurityFinding, FindingType, Severity, SecurityRule, RuleType
    
    rule = SecurityRule(
        id="test-rule-id",
        name="test-rule",
        resource_group="test-rg",
        subscription_id="test-sub-id",
        rule_type=RuleType.NSG_RULE,
        priority=100,
        direction="Inbound",
        access="Allow",
        protocol="TCP",
        source_address_prefix="0.0.0.0/0",
        destination_port_range="22"
    )
    
    return SecurityFinding(
        finding_type=FindingType.UNRESTRICTED_SSH_RDP,
        severity=Severity.CRITICAL,
        title="Test SSH exposure",
        description="Test finding description",
        affected_rule=rule,
        risk_score=95,
        remediation_steps=["Fix step 1", "Fix step 2"],
        auto_remediable=True,
        remediation_script="echo 'test fix'"
    )


@pytest.fixture
def mock_database():
    """Mock database manager"""
    db = MagicMock()
    db.is_enabled.return_value = True
    db.save_scan_result = AsyncMock(return_value=True)
    db.save_findings = AsyncMock(return_value=1)
    db.save_honeypot_event = AsyncMock(return_value=True)
    return db


@pytest.fixture
def sample_honeypot_event():
    """Sample honeypot event for testing"""
    from security_copilot.models import HoneypotEvent, Severity
    
    return HoneypotEvent(
        id="test-event-id",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        destination_port=22,
        protocol="TCP",
        event_type="brute_force_attempt",
        severity=Severity.HIGH,
        threat_indicators=["brute_force"]
    )


@pytest.fixture
def mock_config():
    """Mock configuration"""
    config = MagicMock()
    config.azure_subscription_id = "test-subscription-id"
    config.github_token = "test-github-token"
    config.github_repo_owner = "test-owner"
    config.github_repo_name = "test-repo"
    config.github_labels_list = ["security", "test"]
    config.github_pr_labels_list = ["auto-fix", "test"]
    config.create_issues_for_findings = True
    config.create_prs_for_auto_fix = True
    config.azure_sql_connection_string = "test-connection-string"
    return config


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
