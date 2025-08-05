# 🔌 Security Copilot Agent API Documentation

## Overview

The Security Copilot Agent provides both REST API endpoints and Python SDK for programmatic access to security scanning, findings management, and automation capabilities.

## Table of Contents

- [Authentication](#authentication)
- [REST API Reference](#rest-api-reference)
- [Python SDK Reference](#python-sdk-reference)
- [Webhooks](#webhooks)
- [Rate Limits](#rate-limits)
- [Error Handling](#error-handling)
- [Examples](#examples)

## Authentication

### API Key Authentication
```http
Authorization: Bearer <your-api-token>
```

### Azure Managed Identity (Recommended)
```python
from azure.identity import DefaultAzureCredential
from security_copilot import SecurityCopilotClient

credential = DefaultAzureCredential()
client = SecurityCopilotClient(credential=credential)
```

### Service Principal
```python
from azure.identity import ClientSecretCredential
from security_copilot import SecurityCopilotClient

credential = ClientSecretCredential(
    tenant_id="your-tenant-id",
    client_id="your-client-id",
    client_secret="your-client-secret"
)
client = SecurityCopilotClient(credential=credential)
```

## REST API Reference

### Base URL
```
Production: https://api.security-copilot.com/v1
Staging: https://staging-api.security-copilot.com/v1
```

### Scans

#### Trigger New Scan
```http
POST /scans
Content-Type: application/json
Authorization: Bearer <token>

{
  "subscription_id": "e17f4f74-0d91-4313-9716-0a2edcceefb7",
  "scope": "subscription|resource_group",
  "resource_group": "optional-rg-name",
  "auto_remediate": false,
  "create_issues": true,
  "severity_filter": ["critical", "high"],
  "notification_channels": ["slack", "email"],
  "custom_rules": ["rule1", "rule2"]
}
```

**Response:**
```json
{
  "scan_id": "scan-20250805-174258",
  "status": "running",
  "created_at": "2025-08-05T17:42:58Z",
  "estimated_completion": "2025-08-05T17:45:00Z"
}
```

#### Get Scan Status
```http
GET /scans/{scan_id}
Authorization: Bearer <token>
```

**Response:**
```json
{
  "scan_id": "scan-20250805-174258",
  "status": "completed",
  "created_at": "2025-08-05T17:42:58Z",
  "completed_at": "2025-08-05T17:43:15Z",
  "duration_seconds": 17,
  "resources_scanned": 156,
  "findings_count": {
    "critical": 1,
    "high": 2,
    "medium": 5,
    "low": 8
  }
}
```

#### Get Scan Results
```http
GET /scans/{scan_id}/results
Authorization: Bearer <token>
```

**Response:**
```json
{
  "scan_id": "scan-20250805-174258",
  "findings": [
    {
      "id": "finding-20250805-174301",
      "severity": "critical",
      "title": "Unrestricted SSH access detected",
      "description": "SSH port 22 is open to the internet (0.0.0.0/0)",
      "resource_name": "SSH",
      "resource_group": "Honeypot_group",
      "resource_type": "NSG_RULE",
      "risk_score": 95,
      "cvss_score": 9.8,
      "auto_remediable": true,
      "remediation_steps": [
        "Restrict SSH access to management subnet",
        "Implement Just-In-Time (JIT) access",
        "Enable Azure Bastion for secure access"
      ],
      "github_issue_url": "https://github.com/owner/repo/issues/123",
      "detected_at": "2025-08-05T17:43:01Z"
    }
  ],
  "summary": {
    "total_findings": 16,
    "by_severity": {
      "critical": 1,
      "high": 2,
      "medium": 5,
      "low": 8
    },
    "auto_remediable": 12,
    "manual_review_required": 4
  }
}
```

### Findings

#### List All Findings
```http
GET /findings?status=open&severity=critical,high&limit=50&offset=0
Authorization: Bearer <token>
```

#### Get Finding Details
```http
GET /findings/{finding_id}
Authorization: Bearer <token>
```

#### Update Finding Status
```http
PATCH /findings/{finding_id}
Content-Type: application/json
Authorization: Bearer <token>

{
  "status": "resolved",
  "resolution_notes": "Fixed by restricting SSH access to management subnet",
  "resolved_by": "admin@company.com"
}
```

#### Bulk Update Findings
```http
POST /findings/bulk-update
Content-Type: application/json
Authorization: Bearer <token>

{
  "finding_ids": ["finding-1", "finding-2", "finding-3"],
  "action": "resolve",
  "resolution_notes": "Mass remediation applied"
}
```

### Remediation

#### Trigger Auto-Remediation
```http
POST /findings/{finding_id}/remediate
Content-Type: application/json
Authorization: Bearer <token>

{
  "auto_approve": false,
  "create_pr": true,
  "notify_team": true
}
```

#### Get Remediation Status
```http
GET /remediation/{remediation_id}/status
Authorization: Bearer <token>
```

### Reports

#### Generate Compliance Report
```http
POST /reports/compliance
Content-Type: application/json
Authorization: Bearer <token>

{
  "format": "pdf",
  "compliance_frameworks": ["soc2", "pci-dss", "hipaa"],
  "date_range": {
    "start": "2025-07-01",
    "end": "2025-08-01"
  },
  "include_remediation_status": true
}
```

#### Generate Executive Summary
```http
POST /reports/executive
Content-Type: application/json
Authorization: Bearer <token>

{
  "format": "json",
  "date_range": {
    "start": "2025-07-01",
    "end": "2025-08-01"
  }
}
```

### Configuration

#### Get Current Configuration
```http
GET /config
Authorization: Bearer <token>
```

#### Update Configuration
```http
PUT /config
Content-Type: application/json
Authorization: Bearer <token>

{
  "scan_interval_minutes": 60,
  "auto_remediation_enabled": false,
  "notification_settings": {
    "slack_webhook": "https://hooks.slack.com/...",
    "email_recipients": ["security@company.com"]
  },
  "severity_thresholds": {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0
  }
}
```

## Python SDK Reference

### Installation
```bash
pip install security-copilot-sdk
```

### Basic Usage
```python
from security_copilot import SecurityCopilotClient
from security_copilot.models import ScanConfig, FindingSeverity

# Initialize client
client = SecurityCopilotClient(
    endpoint="https://api.security-copilot.com/v1",
    credential=credential
)

# Trigger scan
scan_config = ScanConfig(
    subscription_id="your-subscription-id",
    auto_remediate=False,
    severity_filter=[FindingSeverity.CRITICAL, FindingSeverity.HIGH]
)

scan = await client.scans.create(scan_config)
print(f"Scan started: {scan.scan_id}")

# Wait for completion
scan_result = await client.scans.wait_for_completion(scan.scan_id)
print(f"Found {len(scan_result.findings)} security issues")

# Process findings
for finding in scan_result.findings:
    if finding.auto_remediable:
        remediation = await client.remediation.create(finding.id)
        print(f"Remediation started: {remediation.id}")
```

### Advanced SDK Usage

#### Custom Rules
```python
from security_copilot.rules import CustomRule, RuleCondition

class DatabaseExposureRule(CustomRule):
    def __init__(self):
        super().__init__(
            name="database_exposure_check",
            severity=FindingSeverity.HIGH,
            description="Detects database ports exposed to internet"
        )
    
    def evaluate(self, resource):
        if resource.type == "NSG_RULE":
            return self._check_database_ports(resource)
        return False
    
    def _check_database_ports(self, rule):
        db_ports = [1433, 3306, 5432, 1521, 27017]
        return (
            rule.destination_port in db_ports and
            rule.source_address_prefix == "0.0.0.0/0" and
            rule.access == "Allow"
        )

# Register custom rule
client.rules.register(DatabaseExposureRule())
```

#### Batch Operations
```python
# Bulk finding updates
findings = await client.findings.list(status="open", severity="critical")
updates = [
    {"id": f.id, "status": "in_progress", "assigned_to": "security-team"}
    for f in findings
]
await client.findings.bulk_update(updates)

# Batch remediation
critical_findings = [f for f in findings if f.severity == "critical"]
remediation_tasks = await client.remediation.create_batch(
    [f.id for f in critical_findings]
)
```

#### Event Streaming
```python
# Real-time findings stream
async def handle_new_finding(finding):
    print(f"New {finding.severity} finding: {finding.title}")
    if finding.severity == "critical":
        await send_alert_to_security_team(finding)

# Subscribe to events
await client.events.subscribe("finding.created", handle_new_finding)
await client.events.subscribe("scan.completed", handle_scan_completion)
```

## Webhooks

### Webhook Events

#### Finding Created
```json
{
  "event_type": "finding.created",
  "timestamp": "2025-08-05T17:43:01Z",
  "data": {
    "finding_id": "finding-20250805-174301",
    "severity": "critical",
    "title": "Unrestricted SSH access detected",
    "resource_name": "SSH",
    "resource_group": "Honeypot_group"
  }
}
```

#### Scan Completed
```json
{
  "event_type": "scan.completed",
  "timestamp": "2025-08-05T17:43:15Z",
  "data": {
    "scan_id": "scan-20250805-174258",
    "findings_count": 16,
    "critical_findings": 1,
    "duration_seconds": 17
  }
}
```

#### Remediation Applied
```json
{
  "event_type": "remediation.applied",
  "timestamp": "2025-08-05T17:45:30Z",
  "data": {
    "finding_id": "finding-20250805-174301",
    "remediation_id": "rem-20250805-174530",
    "status": "success",
    "github_pr_url": "https://github.com/owner/repo/pull/456"
  }
}
```

### Webhook Configuration
```python
# Register webhook endpoint
webhook_config = {
    "url": "https://your-app.com/webhooks/security-copilot",
    "events": ["finding.created", "scan.completed", "remediation.applied"],
    "secret": "your-webhook-secret"
}

await client.webhooks.create(webhook_config)
```

### Webhook Verification
```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected_signature = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected_signature}", signature)
```

## Rate Limits

### API Rate Limits
- **Standard Tier**: 1,000 requests/hour
- **Professional Tier**: 10,000 requests/hour  
- **Enterprise Tier**: 100,000 requests/hour

### Rate Limit Headers
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1691251200
```

### Rate Limit Handling
```python
from security_copilot.exceptions import RateLimitExceeded
import asyncio

async def handle_rate_limit():
    try:
        result = await client.scans.create(scan_config)
    except RateLimitExceeded as e:
        wait_time = e.retry_after
        print(f"Rate limit exceeded. Waiting {wait_time} seconds...")
        await asyncio.sleep(wait_time)
        result = await client.scans.create(scan_config)
```

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Subscription ID is required",
    "details": {
      "field": "subscription_id",
      "reason": "missing_required_field"
    },
    "request_id": "req-20250805-174301"
  }
}
```

### Common Error Codes
- `INVALID_REQUEST` (400) - Malformed request
- `UNAUTHORIZED` (401) - Invalid credentials
- `FORBIDDEN` (403) - Insufficient permissions
- `NOT_FOUND` (404) - Resource not found
- `RATE_LIMITED` (429) - Rate limit exceeded
- `INTERNAL_ERROR` (500) - Server error

### SDK Error Handling
```python
from security_copilot.exceptions import (
    SecurityCopilotError,
    AuthenticationError,
    PermissionError,
    NotFoundError,
    RateLimitExceeded
)

try:
    scan = await client.scans.create(scan_config)
except AuthenticationError:
    print("Invalid credentials")
except PermissionError:
    print("Insufficient permissions")
except NotFoundError:
    print("Resource not found")
except RateLimitExceeded as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds")
except SecurityCopilotError as e:
    print(f"API error: {e.message}")
```

## Examples

### Complete Scan Workflow
```python
import asyncio
from security_copilot import SecurityCopilotClient
from security_copilot.models import ScanConfig, FindingSeverity

async def complete_security_scan():
    client = SecurityCopilotClient(credential=credential)
    
    # Configure scan
    config = ScanConfig(
        subscription_id="your-subscription-id",
        auto_remediate=False,
        create_issues=True,
        severity_filter=[FindingSeverity.CRITICAL, FindingSeverity.HIGH]
    )
    
    # Start scan
    scan = await client.scans.create(config)
    print(f"Scan {scan.scan_id} started...")
    
    # Wait for completion
    result = await client.scans.wait_for_completion(scan.scan_id)
    print(f"Scan completed in {result.duration_seconds}s")
    
    # Process critical findings
    critical_findings = [
        f for f in result.findings 
        if f.severity == FindingSeverity.CRITICAL
    ]
    
    for finding in critical_findings:
        print(f"CRITICAL: {finding.title}")
        
        if finding.auto_remediable:
            # Create remediation PR
            remediation = await client.remediation.create(
                finding.id,
                auto_approve=False,
                create_pr=True
            )
            print(f"Remediation PR created: {remediation.github_pr_url}")
        else:
            # Assign to security team
            await client.findings.update(
                finding.id,
                assigned_to="security-team@company.com",
                priority="urgent"
            )
    
    # Generate report
    report = await client.reports.generate_compliance(
        format="pdf",
        frameworks=["soc2", "pci-dss"]
    )
    print(f"Compliance report: {report.download_url}")

if __name__ == "__main__":
    asyncio.run(complete_security_scan())
```

### Custom Integration Example
```python
# Slack notification integration
import asyncio
import json
from slack_sdk.web.async_client import AsyncWebClient

async def send_slack_notification(finding):
    slack_client = AsyncWebClient(token="your-slack-token")
    
    color = {
        "critical": "#ff0000",
        "high": "#ff8800",
        "medium": "#ffaa00",
        "low": "#00ff00"
    }.get(finding.severity, "#cccccc")
    
    attachment = {
        "color": color,
        "title": finding.title,
        "title_link": finding.github_issue_url,
        "fields": [
            {"title": "Severity", "value": finding.severity.upper(), "short": True},
            {"title": "Resource", "value": finding.resource_name, "short": True},
            {"title": "Risk Score", "value": str(finding.risk_score), "short": True},
            {"title": "Auto-Remediable", "value": "Yes" if finding.auto_remediable else "No", "short": True}
        ],
        "footer": "Security Copilot Agent",
        "ts": finding.detected_at.timestamp()
    }
    
    await slack_client.chat_postMessage(
        channel="#security-alerts",
        text=f"🚨 {finding.severity.upper()} Security Finding",
        attachments=[attachment]
    )

# Usage with webhook
async def webhook_handler(request):
    payload = await request.json()
    
    if payload["event_type"] == "finding.created":
        finding_data = payload["data"]
        if finding_data["severity"] in ["critical", "high"]:
            await send_slack_notification(finding_data)
    
    return {"status": "ok"}
```

---

## Support

For API support and questions:
- 📧 **Email**: api-support@security-copilot.com
- 💬 **Discord**: [#api-support](https://discord.gg/security-copilot)
- 📚 **Documentation**: [docs.security-copilot.com](https://docs.security-copilot.com)
- 🐛 **Issues**: [GitHub Issues](https://github.com/kineticKshitij/Security-copilot-agent/issues)
