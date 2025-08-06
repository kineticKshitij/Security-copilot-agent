"""
Azure Security Scanner - Core scanning functionality for NSGs and firewall rules
"""

import asyncio
import re
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import AzureError
import structlog

from .models import (
    SecurityRule,
    SecurityFinding,
    FindingType,
    Severity,
    RuleType,
    ScanResult,
)
from .config import config

logger = structlog.get_logger(__name__)


class SecurityScanner:
    """Main security scanner for Azure NSGs and firewall rules"""

    def __init__(self, subscription_id: Optional[str] = None):
        self.subscription_id = subscription_id or config.azure_subscription_id
        self.network_client = self._get_network_client()

        # Define high-risk ports
        self.high_risk_ports = {
            22: "SSH",
            23: "Telnet",
            3389: "RDP",
            445: "SMB",
            135: "RPC",
            139: "NetBIOS",
            1433: "SQL Server",
            1521: "Oracle",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            5984: "CouchDB",
            9200: "Elasticsearch",
        }

        # Define administrative ports
        self.admin_ports = {
            80: "HTTP Management",
            443: "HTTPS Management",
            8080: "HTTP Alt",
            8443: "HTTPS Alt",
            9090: "Management Console",
            9443: "Secure Management",
        }

    def _get_network_client(self) -> NetworkManagementClient:
        """Initialize Azure Network Management Client with appropriate credentials"""
        try:
            if config.use_managed_identity:
                credential = DefaultAzureCredential()
                logger.info("Using Azure Managed Identity for authentication")
            else:
                credential = ClientSecretCredential(
                    tenant_id=config.azure_tenant_id,
                    client_id=config.azure_client_id,
                    client_secret=config.azure_client_secret,
                )
                logger.info("Using Service Principal for authentication")

            return NetworkManagementClient(credential, self.subscription_id)
        except Exception as e:
            logger.error("Failed to initialize Azure Network client", error=str(e))
            raise

    async def scan_subscription(
        self, resource_groups: Optional[List[str]] = None
    ) -> ScanResult:
        """Scan entire subscription or specific resource groups for security misconfigurations"""
        scan_result = ScanResult(subscription_id=self.subscription_id)

        try:
            logger.info(
                "Starting security scan",
                subscription_id=self.subscription_id,
                resource_groups=resource_groups,
            )

            # Get all resource groups if none specified
            if not resource_groups:
                resource_groups = await self._get_all_resource_groups()

            scan_result.resource_groups = resource_groups

            # Scan NSGs in parallel
            nsg_tasks = [self._scan_resource_group_nsgs(rg) for rg in resource_groups]
            nsg_results = await asyncio.gather(*nsg_tasks, return_exceptions=True)

            # Process results
            for result in nsg_results:
                if isinstance(result, Exception):
                    logger.error("Error scanning resource group", error=str(result))
                    continue

                scan_result.findings.extend(result)
                scan_result.total_rules_scanned += len(result)

            scan_result.completed_at = datetime.now(timezone.utc)
            scan_result.status = "completed"

            logger.info(
                "Security scan completed",
                scan_id=scan_result.scan_id,
                total_findings=len(scan_result.findings),
                duration=scan_result.duration_seconds,
            )

            return scan_result

        except Exception as e:
            scan_result.status = "failed"
            scan_result.error_message = str(e)
            scan_result.completed_at = datetime.now(timezone.utc)
            logger.error("Security scan failed", error=str(e))
            raise

    async def _get_all_resource_groups(self) -> List[str]:
        """Get all resource groups in the subscription"""
        try:
            from azure.mgmt.resource import ResourceManagementClient

            resource_client = ResourceManagementClient(
                self.network_client._config.credential, self.subscription_id
            )

            rgs = []
            for rg in resource_client.resource_groups.list():
                rgs.append(rg.name)

            logger.info("Found resource groups", count=len(rgs))
            return rgs

        except Exception as e:
            logger.error("Failed to get resource groups", error=str(e))
            return []

    async def _scan_resource_group_nsgs(
        self, resource_group: str
    ) -> List[SecurityFinding]:
        """Scan all NSGs in a specific resource group"""
        findings = []

        try:
            logger.debug(
                "Scanning NSGs in resource group", resource_group=resource_group
            )

            # Get all NSGs in the resource group
            nsgs = self.network_client.network_security_groups.list(resource_group)

            for nsg in nsgs:
                logger.debug(
                    "Scanning NSG", nsg_name=nsg.name, resource_group=resource_group
                )

                # Scan security rules
                if nsg.security_rules:
                    for rule in nsg.security_rules:
                        security_rule = self._convert_to_security_rule(
                            rule, resource_group, nsg.name
                        )
                        rule_findings = self._analyze_security_rule(security_rule)
                        findings.extend(rule_findings)

                # Scan default security rules
                if nsg.default_security_rules:
                    for rule in nsg.default_security_rules:
                        security_rule = self._convert_to_security_rule(
                            rule, resource_group, nsg.name
                        )
                        rule_findings = self._analyze_security_rule(security_rule)
                        findings.extend(rule_findings)

        except AzureError as e:
            logger.error(
                "Azure error scanning NSGs", resource_group=resource_group, error=str(e)
            )
        except Exception as e:
            logger.error(
                "Unexpected error scanning NSGs",
                resource_group=resource_group,
                error=str(e),
            )

        logger.debug(
            "Completed NSG scan",
            resource_group=resource_group,
            findings_count=len(findings),
        )
        return findings

    def _convert_to_security_rule(
        self, azure_rule: Any, resource_group: str, nsg_name: str
    ) -> SecurityRule:
        """Convert Azure NSG rule to our SecurityRule model"""
        return SecurityRule(
            id=azure_rule.id or f"{nsg_name}/{azure_rule.name}",
            name=azure_rule.name,
            resource_group=resource_group,
            subscription_id=self.subscription_id,
            rule_type=RuleType.NSG_RULE,
            priority=azure_rule.priority,
            direction=azure_rule.direction,
            access=azure_rule.access,
            protocol=azure_rule.protocol,
            source_address_prefix=azure_rule.source_address_prefix,
            source_port_range=azure_rule.source_port_range,
            destination_address_prefix=azure_rule.destination_address_prefix,
            destination_port_range=azure_rule.destination_port_range,
            description=azure_rule.description,
        )

    def _analyze_security_rule(self, rule: SecurityRule) -> List[SecurityFinding]:
        """Analyze a security rule for misconfigurations"""
        findings = []

        # Skip deny rules (they are generally good)
        if rule.access.lower() == "deny":
            return findings

        # Check for rules open to the internet
        if self._is_open_to_internet(rule):
            findings.append(self._create_open_to_internet_finding(rule))

        # Check for unrestricted SSH/RDP access
        if self._is_unrestricted_ssh_rdp(rule):
            findings.append(self._create_ssh_rdp_finding(rule))

        # Check for exposed database ports
        if self._has_exposed_database_ports(rule):
            findings.append(self._create_database_exposure_finding(rule))

        # Check for exposed administrative ports
        if self._has_exposed_admin_ports(rule):
            findings.append(self._create_admin_exposure_finding(rule))

        # Check for weak protocols
        if self._uses_weak_protocols(rule):
            findings.append(self._create_weak_protocol_finding(rule))

        return findings

    def _is_open_to_internet(self, rule: SecurityRule) -> bool:
        """Check if rule allows access from anywhere on the internet"""
        internet_sources = ["0.0.0.0/0", "*", "Internet", "any"]
        return (
            rule.direction.lower() == "inbound"
            and rule.access.lower() == "allow"
            and rule.source_address_prefix
            and rule.source_address_prefix.lower()
            in [s.lower() for s in internet_sources]
        )

    def _is_unrestricted_ssh_rdp(self, rule: SecurityRule) -> bool:
        """Check for unrestricted SSH (22) or RDP (3389) access"""
        risky_ports = ["22", "3389"]
        return (
            self._is_open_to_internet(rule)
            and rule.destination_port_range
            and any(port in rule.destination_port_range for port in risky_ports)
        )

    def _has_exposed_database_ports(self, rule: SecurityRule) -> bool:
        """Check for exposed database ports"""
        db_ports = ["1433", "1521", "3306", "5432", "6379", "27017", "5984", "9200"]
        return (
            self._is_open_to_internet(rule)
            and rule.destination_port_range
            and any(port in rule.destination_port_range for port in db_ports)
        )

    def _has_exposed_admin_ports(self, rule: SecurityRule) -> bool:
        """Check for exposed administrative ports"""
        return (
            self._is_open_to_internet(rule)
            and rule.destination_port_range
            and any(
                str(port) in rule.destination_port_range
                for port in self.admin_ports.keys()
            )
        )

    def _uses_weak_protocols(self, rule: SecurityRule) -> bool:
        """Check for weak protocols (currently just flags unencrypted protocols)"""
        weak_protocols = ["http", "ftp", "telnet", "smtp", "pop3", "imap"]
        return rule.protocol and rule.protocol.lower() in weak_protocols

    def _create_open_to_internet_finding(self, rule: SecurityRule) -> SecurityFinding:
        """Create finding for rule open to internet"""
        return SecurityFinding(
            finding_type=FindingType.OPEN_TO_INTERNET,
            severity=Severity.HIGH,
            title=f"NSG Rule '{rule.name}' allows unrestricted internet access",
            description=f"The NSG rule '{rule.name}' in resource group '{rule.resource_group}' "
            f"allows inbound traffic from any source (0.0.0.0/0) to port(s) "
            f"{rule.destination_port_range or 'any'}. This creates a potential "
            f"security risk by exposing resources to the entire internet.",
            affected_rule=rule,
            risk_score=75,
            remediation_steps=[
                "Review if this rule is actually needed",
                "Restrict source IP ranges to only necessary networks",
                "Consider using Azure Bastion for management access",
                "Implement additional security controls (WAF, DDoS protection)",
                "Monitor traffic for suspicious activity",
            ],
            auto_remediable=True,
            remediation_script=self._generate_nsg_fix_script(rule),
            tags=["nsg", "internet-exposure", "high-risk"],
        )

    def _create_ssh_rdp_finding(self, rule: SecurityRule) -> SecurityFinding:
        """Create finding for unrestricted SSH/RDP access"""
        port_info = (
            "SSH (22)" if "22" in str(rule.destination_port_range) else "RDP (3389)"
        )

        return SecurityFinding(
            finding_type=FindingType.UNRESTRICTED_SSH_RDP,
            severity=Severity.CRITICAL,
            title=f"NSG Rule '{rule.name}' allows unrestricted {port_info} access",
            description=f"The NSG rule '{rule.name}' allows {port_info} access from any "
            f"internet source. This is extremely dangerous as it exposes "
            f"management interfaces to potential brute force attacks.",
            affected_rule=rule,
            risk_score=95,
            cvss_score=9.8,
            remediation_steps=[
                "Immediately restrict source IP to specific management networks",
                "Enable Azure Bastion for secure remote access",
                "Implement multi-factor authentication",
                "Use Network Security Groups with strict source IP filtering",
                "Consider using Azure Private Link for administrative access",
                "Enable just-in-time VM access if using Azure Security Center",
            ],
            auto_remediable=True,
            remediation_script=self._generate_ssh_rdp_fix_script(rule),
            tags=["nsg", "ssh", "rdp", "critical-risk", "remote-access"],
        )

    def _create_database_exposure_finding(self, rule: SecurityRule) -> SecurityFinding:
        """Create finding for exposed database ports"""
        return SecurityFinding(
            finding_type=FindingType.DATABASE_PORTS_EXPOSED,
            severity=Severity.HIGH,
            title=f"NSG Rule '{rule.name}' exposes database ports to internet",
            description=f"The NSG rule '{rule.name}' allows internet access to database "
            f"ports ({rule.destination_port_range}). Database servers should "
            f"never be directly accessible from the internet.",
            affected_rule=rule,
            risk_score=85,
            remediation_steps=[
                "Move database servers to private subnets",
                "Remove direct internet access to database ports",
                "Use Azure Private Link for database connectivity",
                "Implement application-layer access controls",
                "Enable database firewalls and audit logging",
            ],
            auto_remediable=True,
            remediation_script=self._generate_database_fix_script(rule),
            tags=["nsg", "database", "data-exposure"],
        )

    def _create_admin_exposure_finding(self, rule: SecurityRule) -> SecurityFinding:
        """Create finding for exposed administrative ports"""
        return SecurityFinding(
            finding_type=FindingType.ADMIN_PORTS_EXPOSED,
            severity=Severity.MEDIUM,
            title=f"NSG Rule '{rule.name}' exposes administrative ports",
            description=f"The NSG rule '{rule.name}' allows internet access to "
            f"administrative ports ({rule.destination_port_range}). "
            f"Management interfaces should be protected.",
            affected_rule=rule,
            risk_score=60,
            remediation_steps=[
                "Restrict access to administrative networks only",
                "Use VPN or Azure Bastion for management access",
                "Implement additional authentication for admin interfaces",
                "Consider using Azure Private Link",
            ],
            auto_remediable=True,
            remediation_script=self._generate_admin_fix_script(rule),
            tags=["nsg", "admin-access", "management"],
        )

    def _create_weak_protocol_finding(self, rule: SecurityRule) -> SecurityFinding:
        """Create finding for weak protocols"""
        return SecurityFinding(
            finding_type=FindingType.WEAK_PROTOCOLS,
            severity=Severity.MEDIUM,
            title=f"NSG Rule '{rule.name}' allows weak protocol",
            description=f"The NSG rule '{rule.name}' allows traffic using weak or "
            f"unencrypted protocol ({rule.protocol}). This could expose "
            f"sensitive data in transit.",
            affected_rule=rule,
            risk_score=45,
            remediation_steps=[
                "Replace with secure protocol alternatives (HTTPS, SFTP, etc.)",
                "Implement TLS encryption",
                "Use VPN tunnels for legacy protocol requirements",
            ],
            auto_remediable=False,
            tags=["nsg", "weak-protocol", "encryption"],
        )

    def _generate_nsg_fix_script(self, rule: SecurityRule) -> str:
        """Generate Azure CLI script to fix overly permissive NSG rule"""
        return f"""# Fix for NSG rule '{rule.name}' - Restrict source to specific networks
# Replace 'YOUR_MANAGEMENT_NETWORK' with your actual management network CIDR

az network nsg rule update \\
  --resource-group "{rule.resource_group}" \\
  --nsg-name "$(echo '{rule.id}' | cut -d'/' -f9)" \\
  --name "{rule.name}" \\
  --source-address-prefix "YOUR_MANAGEMENT_NETWORK" \\
  --description "Restricted access - Updated by Security Copilot"
"""

    def _generate_ssh_rdp_fix_script(self, rule: SecurityRule) -> str:
        """Generate script to fix SSH/RDP exposure"""
        return f"""# CRITICAL: Fix SSH/RDP exposure for rule '{rule.name}'
# This script restricts access to management networks only

az network nsg rule update \\
  --resource-group "{rule.resource_group}" \\
  --nsg-name "$(echo '{rule.id}' | cut -d'/' -f9)" \\
  --name "{rule.name}" \\
  --source-address-prefix "YOUR_MANAGEMENT_NETWORK" \\
  --description "Restricted SSH/RDP access - Security Copilot auto-fix"

# Consider using Azure Bastion instead:
# az network bastion create \\
#   --resource-group "{rule.resource_group}" \\
#   --name "bastion-host" \\
#   --public-ip-address "bastion-pip" \\
#   --vnet-name "your-vnet"
"""

    def _generate_database_fix_script(self, rule: SecurityRule) -> str:
        """Generate script to fix database exposure"""
        return f"""# Fix database exposure for rule '{rule.name}'
# This script denies internet access to database ports

az network nsg rule update \\
  --resource-group "{rule.resource_group}" \\
  --nsg-name "$(echo '{rule.id}' | cut -d'/' -f9)" \\
  --name "{rule.name}" \\
  --access "Deny" \\
  --description "Database access denied from internet - Security Copilot auto-fix"

# Create a new rule for application subnet access:
# az network nsg rule create \\
#   --resource-group "{rule.resource_group}" \\
#   --nsg-name "$(echo '{rule.id}' | cut -d'/' -f9)" \\
#   --name "allow-app-subnet-database" \\
#   --priority $((rule.priority + 1)) \\
#   --source-address-prefix "10.0.1.0/24" \\
#   --destination-port-range "{rule.destination_port_range}" \\
#   --access "Allow"
"""

    def _generate_admin_fix_script(self, rule: SecurityRule) -> str:
        """Generate script to fix admin port exposure"""
        return f"""# Fix administrative port exposure for rule '{rule.name}'

az network nsg rule update \\
  --resource-group "{rule.resource_group}" \\
  --nsg-name "$(echo '{rule.id}' | cut -d'/' -f9)" \\
  --name "{rule.name}" \\
  --source-address-prefix "YOUR_ADMIN_NETWORK" \\
  --description "Restricted admin access - Security Copilot auto-fix"
"""
