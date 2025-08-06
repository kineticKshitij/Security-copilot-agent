"""
Tests for Security Scanner module
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

from security_copilot.scanner import SecurityScanner
from security_copilot.models import FindingType, Severity


class TestSecurityScanner:
    
    def test_scanner_initialization(self, mock_config):
        """Test scanner initialization"""
        with patch('security_copilot.scanner.config', mock_config):
            scanner = SecurityScanner("test-subscription")
            assert scanner.subscription_id == "test-subscription"
    
    def test_high_risk_ports_definition(self, mock_config):
        """Test that high risk ports are properly defined"""
        with patch('security_copilot.scanner.config', mock_config):
            scanner = SecurityScanner()
            
            assert 22 in scanner.high_risk_ports  # SSH
            assert 3389 in scanner.high_risk_ports  # RDP
            assert 1433 in scanner.high_risk_ports  # SQL Server
            assert scanner.high_risk_ports[22] == "SSH"
    
    def test_is_open_to_internet(self, sample_security_rule, mock_config):
        """Test detection of rules open to internet"""
        with patch('security_copilot.scanner.config', mock_config):
            scanner = SecurityScanner()
            
            # Test rule open to internet
            rule = sample_security_rule
            rule.source_address_prefix = "0.0.0.0/0"
            rule.direction = "Inbound"
            rule.access = "Allow"
            
            assert scanner._is_open_to_internet(rule) is True
            
            # Test rule not open to internet
            rule.source_address_prefix = "10.0.0.0/24"
            assert scanner._is_open_to_internet(rule) is False
    
    def test_is_unrestricted_ssh_rdp(self, sample_security_rule, mock_config):
        """Test detection of unrestricted SSH/RDP access"""
        with patch('security_copilot.scanner.config', mock_config):
            scanner = SecurityScanner()
            
            # Test SSH exposure
            rule = sample_security_rule
            rule.source_address_prefix = "0.0.0.0/0"
            rule.destination_port_range = "22"
            rule.direction = "Inbound"
            rule.access = "Allow"
            
            assert scanner._is_unrestricted_ssh_rdp(rule) is True
            
            # Test RDP exposure
            rule.destination_port_range = "3389"
            assert scanner._is_unrestricted_ssh_rdp(rule) is True
            
            # Test non-SSH/RDP port
            rule.destination_port_range = "80"
            assert scanner._is_unrestricted_ssh_rdp(rule) is False
    
    def test_has_exposed_database_ports(self, sample_security_rule, mock_config):
        """Test detection of exposed database ports"""
        with patch('security_copilot.scanner.config', mock_config):
            scanner = SecurityScanner()
            
            # Test SQL Server exposure
            rule = sample_security_rule
            rule.source_address_prefix = "0.0.0.0/0"
            rule.destination_port_range = "1433"
            rule.direction = "Inbound"
            rule.access = "Allow"
            
            assert scanner._has_exposed_database_ports(rule) is True
            
            # Test MySQL exposure
            rule.destination_port_range = "3306"
            assert scanner._has_exposed_database_ports(rule) is True
            
            # Test non-database port
            rule.destination_port_range = "80"
            assert scanner._has_exposed_database_ports(rule) is False
    
    def test_analyze_security_rule(self, sample_security_rule, mock_config):
        """Test security rule analysis"""
        with patch('security_copilot.scanner.config', mock_config):
            scanner = SecurityScanner()
            
            # Test SSH exposure finding
            rule = sample_security_rule
            rule.source_address_prefix = "0.0.0.0/0"
            rule.destination_port_range = "22"
            rule.direction = "Inbound"
            rule.access = "Allow"
            
            findings = scanner._analyze_security_rule(rule)
            
            assert len(findings) > 0
            ssh_finding = next((f for f in findings if f.finding_type == FindingType.UNRESTRICTED_SSH_RDP), None)
            assert ssh_finding is not None
            assert ssh_finding.severity == Severity.CRITICAL
    
    def test_create_ssh_rdp_finding(self, sample_security_rule, mock_config):
        """Test creation of SSH/RDP findings"""
        with patch('security_copilot.scanner.config', mock_config):
            scanner = SecurityScanner()
            
            rule = sample_security_rule
            rule.destination_port_range = "22"
            
            finding = scanner._create_ssh_rdp_finding(rule)
            
            assert finding.finding_type == FindingType.UNRESTRICTED_SSH_RDP
            assert finding.severity == Severity.CRITICAL
            assert finding.auto_remediable is True
            assert finding.remediation_script is not None
            assert "SSH" in finding.title
    
    def test_generate_remediation_scripts(self, sample_security_rule, mock_config):
        """Test generation of remediation scripts"""
        with patch('security_copilot.scanner.config', mock_config):
            scanner = SecurityScanner()
            
            rule = sample_security_rule
            
            # Test NSG fix script
            script = scanner._generate_nsg_fix_script(rule)
            assert "az network nsg rule update" in script
            assert rule.resource_group in script
            assert rule.name in script
            
            # Test SSH/RDP fix script
            ssh_script = scanner._generate_ssh_rdp_fix_script(rule)
            assert "CRITICAL" in ssh_script
            assert "az network nsg rule update" in ssh_script
            assert "bastion" in ssh_script.lower()
    
    @pytest.mark.asyncio
    @patch('security_copilot.scanner.NetworkManagementClient')
    async def test_scan_subscription(self, mock_network_client, mock_config):
        """Test subscription scanning"""
        with patch('security_copilot.scanner.config', mock_config):
            # Mock the network client
            mock_client_instance = MagicMock()
            mock_network_client.return_value = mock_client_instance
            
            # Mock resource client
            with patch('security_copilot.scanner.ResourceManagementClient') as mock_resource_client:
                mock_resource_instance = MagicMock()
                mock_resource_client.return_value = mock_resource_instance
                
                # Mock resource groups
                mock_rg = MagicMock()
                mock_rg.name = "test-rg"
                mock_resource_instance.resource_groups.list.return_value = [mock_rg]
                
                # Mock NSGs
                mock_nsg = MagicMock()
                mock_nsg.name = "test-nsg"
                mock_nsg.security_rules = []
                mock_nsg.default_security_rules = []
                mock_client_instance.network_security_groups.list.return_value = [mock_nsg]
                
                scanner = SecurityScanner()
                scan_result = await scanner.scan_subscription()
                
                assert scan_result.subscription_id == mock_config.azure_subscription_id
                assert scan_result.status == "completed"
                assert scan_result.completed_at is not None


class TestSecurityRuleAnalysis:
    
    def test_deny_rules_ignored(self, sample_security_rule, mock_config):
        """Test that deny rules are not flagged as findings"""
        with patch('security_copilot.scanner.config', mock_config):
            scanner = SecurityScanner()
            
            rule = sample_security_rule
            rule.access = "Deny"  # Deny rules are generally good
            rule.source_address_prefix = "0.0.0.0/0"
            rule.destination_port_range = "22"
            
            findings = scanner._analyze_security_rule(rule)
            assert len(findings) == 0
    
    def test_multiple_findings_per_rule(self, sample_security_rule, mock_config):
        """Test that a single rule can generate multiple findings"""
        with patch('security_copilot.scanner.config', mock_config):
            scanner = SecurityScanner()
            
            rule = sample_security_rule
            rule.source_address_prefix = "0.0.0.0/0"
            rule.destination_port_range = "22,1433"  # Both SSH and SQL Server
            rule.direction = "Inbound"
            rule.access = "Allow"
            
            findings = scanner._analyze_security_rule(rule)
            
            # Should generate findings for both SSH and database exposure
            finding_types = [f.finding_type for f in findings]
            assert FindingType.UNRESTRICTED_SSH_RDP in finding_types
            assert FindingType.DATABASE_PORTS_EXPOSED in finding_types


class TestPerformance:
    
    @pytest.mark.asyncio
    async def test_concurrent_scanning(self, mock_config):
        """Test that scanning can handle multiple resource groups concurrently"""
        with patch('security_copilot.scanner.config', mock_config):
            with patch('security_copilot.scanner.NetworkManagementClient'):
                scanner = SecurityScanner()
                
                # Mock multiple resource groups
                resource_groups = ["rg1", "rg2", "rg3", "rg4", "rg5"]
                
                # This should complete without errors
                with patch.object(scanner, '_scan_resource_group_nsgs', new_callable=AsyncMock) as mock_scan:
                    mock_scan.return_value = []
                    
                    scan_result = await scanner.scan_subscription(resource_groups)
                    
                    assert scan_result.status == "completed"
                    assert mock_scan.call_count == len(resource_groups)
