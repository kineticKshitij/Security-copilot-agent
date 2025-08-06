"""
Data models for Security Copilot Agent
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Security finding severity levels"""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RuleType(str, Enum):
    """Type of security rule"""

    NSG_RULE = "NSG_RULE"
    FIREWALL_RULE = "FIREWALL_RULE"
    ROUTE_TABLE = "ROUTE_TABLE"
    APPLICATION_GATEWAY = "APPLICATION_GATEWAY"


class FindingType(str, Enum):
    """Type of security finding"""

    OPEN_TO_INTERNET = "OPEN_TO_INTERNET"
    UNRESTRICTED_SSH_RDP = "UNRESTRICTED_SSH_RDP"
    DATABASE_PORTS_EXPOSED = "DATABASE_PORTS_EXPOSED"
    ADMIN_PORTS_EXPOSED = "ADMIN_PORTS_EXPOSED"
    WEAK_PROTOCOLS = "WEAK_PROTOCOLS"
    MISSING_NETWORK_SEGMENTATION = "MISSING_NETWORK_SEGMENTATION"
    OVERLY_PERMISSIVE_RULES = "OVERLY_PERMISSIVE_RULES"
    SUSPICIOUS_TRAFFIC_PATTERN = "SUSPICIOUS_TRAFFIC_PATTERN"


class SecurityRule(BaseModel):
    """Represents a security rule (NSG or firewall)"""

    id: str
    name: str
    resource_group: str
    subscription_id: str
    rule_type: RuleType
    priority: int
    direction: str  # Inbound/Outbound
    access: str  # Allow/Deny
    protocol: str  # TCP/UDP/Any
    source_address_prefix: Optional[str] = None
    source_port_range: Optional[str] = None
    destination_address_prefix: Optional[str] = None
    destination_port_range: Optional[str] = None
    description: Optional[str] = None
    created_time: Optional[datetime] = None
    last_modified: Optional[datetime] = None


class SecurityFinding(BaseModel):
    """Represents a security misconfiguration finding"""

    id: str = Field(
        default_factory=lambda: f"finding-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    )
    finding_type: FindingType
    severity: Severity
    title: str
    description: str
    affected_rule: SecurityRule
    remediation_steps: List[str]

    # Risk assessment
    risk_score: int = Field(ge=0, le=100)  # 0-100 risk score
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)

    # Metadata
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "security-copilot-agent"
    tags: List[str] = Field(default_factory=list)

    # GitHub integration
    github_issue_url: Optional[str] = None
    github_pr_url: Optional[str] = None

    # Remediation
    auto_remediable: bool = False
    remediation_script: Optional[str] = None

    def to_github_issue_body(self) -> str:
        """Convert finding to GitHub issue markdown"""
        body = f"""## 🚨 Security Finding: {self.title}

**Severity**: {self.severity.value}
**Type**: {self.finding_type.value}
**Risk Score**: {self.risk_score}/100

### Description
{self.description}

### Affected Resource
- **Resource**: {self.affected_rule.name}
- **Resource Group**: {self.affected_rule.resource_group}
- **Subscription**: {self.affected_rule.subscription_id}
- **Rule Type**: {self.affected_rule.rule_type.value}

### Current Configuration
- **Direction**: {self.affected_rule.direction}
- **Access**: {self.affected_rule.access}
- **Protocol**: {self.affected_rule.protocol}
- **Source**: {self.affected_rule.source_address_prefix or 'Any'}
- **Source Ports**: {self.affected_rule.source_port_range or 'Any'}
- **Destination**: {self.affected_rule.destination_address_prefix or 'Any'}
- **Destination Ports**: {self.affected_rule.destination_port_range or 'Any'}

### Remediation Steps
"""
        for i, step in enumerate(self.remediation_steps, 1):
            body += f"{i}. {step}\n"

        if self.auto_remediable and self.remediation_script:
            body += f"""
### Auto-Remediation Available
This finding can be automatically remediated. A pull request will be created with the necessary changes.

```bash
{self.remediation_script}
```
"""

        body += f"""
### Additional Information
- **Detected At**: {self.detected_at.isoformat()}
- **Source**: {self.source}
- **Tags**: {', '.join(self.tags)}

---
*This issue was automatically created by Security Copilot Agent*
"""
        return body


class HoneypotEvent(BaseModel):
    """Represents a honeypot security event"""

    id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    event_type: str  # connection_attempt, brute_force, malware_download, etc.
    severity: Severity
    geolocation: Optional[Dict[str, Any]] = None
    user_agent: Optional[str] = None
    payload: Optional[str] = None
    threat_indicators: List[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Represents the result of a security scan"""

    scan_id: str = Field(
        default_factory=lambda: f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    )
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    subscription_id: str
    resource_groups: List[str] = Field(default_factory=list)

    # Scan statistics
    total_rules_scanned: int = 0
    findings: List[SecurityFinding] = Field(default_factory=list)

    # Status
    status: str = "in_progress"  # in_progress, completed, failed
    error_message: Optional[str] = None

    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate scan duration in seconds"""
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def findings_by_severity(self) -> Dict[Severity, int]:
        """Count findings by severity"""
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def critical_findings(self) -> List[SecurityFinding]:
        """Get only critical findings"""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> List[SecurityFinding]:
        """Get only high severity findings"""
        return [f for f in self.findings if f.severity == Severity.HIGH]


class ComplianceReport(BaseModel):
    """Represents a compliance report"""

    report_id: str = Field(
        default_factory=lambda: f"report-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    )
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    subscription_id: str

    # Compliance metrics
    total_resources: int = 0
    compliant_resources: int = 0
    non_compliant_resources: int = 0

    # Findings summary
    total_findings: int = 0
    findings_by_severity: Dict[Severity, int] = Field(default_factory=dict)
    findings_by_type: Dict[FindingType, int] = Field(default_factory=dict)

    # Recommendations
    recommendations: List[str] = Field(default_factory=list)

    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage"""
        if self.total_resources == 0:
            return 100.0
        return (self.compliant_resources / self.total_resources) * 100.0
