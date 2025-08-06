"""
Honeypot Integration for Security Copilot Agent
Monitors honeypot logs and integrates threat intelligence with security scanning
"""

import asyncio
import json
import re
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, AsyncGenerator
from pathlib import Path
import structlog
import aiofiles
import aiohttp
from ipaddress import ip_address, ip_network

from .models import HoneypotEvent, SecurityFinding, FindingType, Severity
from .database import db_manager
from .config import config

logger = structlog.get_logger(__name__)


class HoneypotMonitor:
    """Monitors honeypot logs and correlates with security findings"""

    def __init__(self):
        self.log_path = (
            Path(config.honeypot_log_path) if config.honeypot_log_path else None
        )
        self.api_endpoint = config.honeypot_api_endpoint
        self.api_key = config.honeypot_api_key

        # Threat intelligence patterns
        self.malicious_patterns = {
            "sql_injection": [
                r"(union.*select|select.*from|drop.*table|insert.*into)",
                r"(\\'|\"|\\x00|\\n|\\r)",
                r"(script.*alert|javascript:|vbscript:)",
            ],
            "xss_attempts": [
                r"(<script.*>|</script>|javascript:|onload=|onerror=)",
                r"(alert\(|prompt\(|confirm\()",
                r"(document\.cookie|window\.location)",
            ],
            "directory_traversal": [
                r"(\.\./|\.\.\|%2e%2e%2f|%252e%252e%252f)",
                r"(/etc/passwd|/etc/shadow|/proc/version|/windows/system32)",
            ],
            "command_injection": [
                r"(;.*ls|;.*cat|;.*pwd|;.*id|;.*whoami)",
                r"(\|.*ls|\|.*cat|\|.*pwd|\|.*id)",
                r"(`.*ls|`.*cat|`.*pwd|`.*id)",
            ],
            "brute_force": [
                r"(admin|administrator|root|test|guest|demo)",
                r"(password|123456|admin|test|guest)",
            ],
        }

        # High-risk ports for correlation
        self.high_risk_ports = {
            22: "SSH",
            3389: "RDP",
            23: "Telnet",
            445: "SMB",
            1433: "SQL Server",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            9200: "Elasticsearch",
        }

        logger.info(
            "Honeypot monitor initialized",
            log_path=str(self.log_path) if self.log_path else None,
            api_endpoint=self.api_endpoint,
        )

    async def start_monitoring(self) -> None:
        """Start continuous monitoring of honeypot logs"""
        logger.info("Starting honeypot monitoring")

        try:
            while True:
                if self.log_path and self.log_path.exists():
                    await self._monitor_log_files()

                if self.api_endpoint:
                    await self._monitor_api_events()

                await asyncio.sleep(30)  # Check every 30 seconds

        except asyncio.CancelledError:
            logger.info("Honeypot monitoring stopped")
        except Exception as e:
            logger.error("Honeypot monitoring error", error=str(e))
            raise

    async def _monitor_log_files(self) -> None:
        """Monitor honeypot log files for new events"""
        try:
            # Watch for new log files
            log_files = list(self.log_path.glob("*.log"))

            for log_file in log_files:
                async for event in self._parse_log_file(log_file):
                    await self._process_honeypot_event(event)

        except Exception as e:
            logger.error("Error monitoring log files", error=str(e))

    async def _monitor_api_events(self) -> None:
        """Monitor honeypot events via API"""
        try:
            headers = (
                {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            )

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.api_endpoint}/events/recent", headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        events = data.get("events", [])

                        for event_data in events:
                            event = await self._parse_api_event(event_data)
                            if event:
                                await self._process_honeypot_event(event)
                    else:
                        logger.warning(
                            "API request failed",
                            status=response.status,
                            endpoint=self.api_endpoint,
                        )

        except Exception as e:
            logger.error("Error monitoring API events", error=str(e))

    async def _parse_log_file(
        self, log_file: Path
    ) -> AsyncGenerator[HoneypotEvent, None]:
        """Parse honeypot log file and yield events"""
        try:
            async with aiofiles.open(log_file, "r") as f:
                async for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    event = await self._parse_log_line(line)
                    if event:
                        yield event

        except Exception as e:
            logger.error("Error parsing log file", file=str(log_file), error=str(e))

    async def _parse_log_line(self, line: str) -> Optional[HoneypotEvent]:
        """Parse a single log line into a HoneypotEvent"""
        try:
            # Try JSON format first
            if line.startswith("{"):
                data = json.loads(line)
                return HoneypotEvent(
                    id=data.get(
                        "id",
                        f"honeypot-{datetime.utcnow().strftime('%Y%m%d-%H%M%S-%f')}",
                    ),
                    timestamp=datetime.fromisoformat(
                        data["timestamp"].replace("Z", "+00:00")
                    ),
                    source_ip=data["source_ip"],
                    destination_ip=data["destination_ip"],
                    destination_port=data["destination_port"],
                    protocol=data.get("protocol", "TCP"),
                    event_type=data.get("event_type", "connection_attempt"),
                    severity=Severity(data.get("severity", "MEDIUM")),
                    geolocation=data.get("geolocation"),
                    user_agent=data.get("user_agent"),
                    payload=data.get("payload"),
                    threat_indicators=data.get("threat_indicators", []),
                )

            # Try common log formats
            # Common format: timestamp source_ip:port -> dest_ip:port protocol event_type
            log_pattern = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w+)\s+(.+)"
            match = re.match(log_pattern, line)

            if match:
                (
                    timestamp_str,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    protocol,
                    event_data,
                ) = match.groups()

                # Analyze event data for threat indicators
                threat_indicators = self._analyze_payload(event_data)
                severity = self._calculate_severity(threat_indicators, int(dst_port))

                return HoneypotEvent(
                    id=f"honeypot-{datetime.utcnow().strftime('%Y%m%d-%H%M%S-%f')}",
                    timestamp=datetime.fromisoformat(timestamp_str),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    destination_port=int(dst_port),
                    protocol=protocol,
                    event_type=self._classify_event_type(event_data, threat_indicators),
                    severity=severity,
                    payload=event_data,
                    threat_indicators=threat_indicators,
                )

            return None

        except Exception as e:
            logger.error("Error parsing log line", line=line[:100], error=str(e))
            return None

    async def _parse_api_event(
        self, event_data: Dict[str, Any]
    ) -> Optional[HoneypotEvent]:
        """Parse event data from API response"""
        try:
            return HoneypotEvent(
                id=event_data.get(
                    "id", f"api-{datetime.utcnow().strftime('%Y%m%d-%H%M%S-%f')}"
                ),
                timestamp=datetime.fromisoformat(
                    event_data["timestamp"].replace("Z", "+00:00")
                ),
                source_ip=event_data["source_ip"],
                destination_ip=event_data["destination_ip"],
                destination_port=event_data["destination_port"],
                protocol=event_data.get("protocol", "TCP"),
                event_type=event_data.get("event_type", "connection_attempt"),
                severity=Severity(event_data.get("severity", "MEDIUM")),
                geolocation=event_data.get("geolocation"),
                user_agent=event_data.get("user_agent"),
                payload=event_data.get("payload"),
                threat_indicators=event_data.get("threat_indicators", []),
            )

        except Exception as e:
            logger.error("Error parsing API event", error=str(e))
            return None

    def _analyze_payload(self, payload: str) -> List[str]:
        """Analyze payload for threat indicators"""
        indicators = []
        payload_lower = payload.lower()

        for threat_type, patterns in self.malicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload_lower, re.IGNORECASE):
                    indicators.append(threat_type)
                    break

        return list(set(indicators))  # Remove duplicates

    def _calculate_severity(self, threat_indicators: List[str], port: int) -> Severity:
        """Calculate severity based on threat indicators and port"""
        if not threat_indicators:
            if port in self.high_risk_ports:
                return Severity.MEDIUM
            return Severity.LOW

        # High severity for dangerous attack types
        dangerous_indicators = [
            "sql_injection",
            "command_injection",
            "directory_traversal",
        ]
        if any(indicator in threat_indicators for indicator in dangerous_indicators):
            return Severity.HIGH

        # Critical for multiple attack types on high-risk ports
        if len(threat_indicators) > 2 and port in self.high_risk_ports:
            return Severity.CRITICAL

        # Medium for any detected attack
        if threat_indicators:
            return Severity.MEDIUM

        return Severity.LOW

    def _classify_event_type(
        self, event_data: str, threat_indicators: List[str]
    ) -> str:
        """Classify the type of security event"""
        if "sql_injection" in threat_indicators:
            return "sql_injection_attempt"
        elif "xss_attempts" in threat_indicators:
            return "xss_attempt"
        elif "directory_traversal" in threat_indicators:
            return "directory_traversal_attempt"
        elif "command_injection" in threat_indicators:
            return "command_injection_attempt"
        elif "brute_force" in threat_indicators:
            return "brute_force_attempt"
        elif "login" in event_data.lower() or "auth" in event_data.lower():
            return "authentication_attempt"
        elif "scan" in event_data.lower() or "probe" in event_data.lower():
            return "port_scan"
        else:
            return "connection_attempt"

    async def _process_honeypot_event(self, event: HoneypotEvent) -> None:
        """Process a honeypot event and take appropriate actions"""
        try:
            logger.info(
                "Processing honeypot event",
                event_id=event.id,
                source_ip=event.source_ip,
                event_type=event.event_type,
                severity=event.severity.value,
            )

            # Save to database
            if db_manager.is_enabled():
                await db_manager.save_honeypot_event(event)

            # Correlate with existing security findings
            correlations = await self._correlate_with_findings(event)

            # Generate new findings for high-severity events
            if event.severity in [Severity.CRITICAL, Severity.HIGH]:
                finding = await self._create_finding_from_event(event)
                if finding:
                    # Save finding to database
                    if db_manager.is_enabled():
                        await db_manager.save_findings([finding])

                    # TODO: Integrate with GitHub to create issues
                    logger.info(
                        "Created security finding from honeypot event",
                        finding_id=finding.id,
                        event_id=event.id,
                    )

            # Alert on critical events
            if event.severity == Severity.CRITICAL:
                await self._send_critical_alert(event)

        except Exception as e:
            logger.error(
                "Error processing honeypot event", event_id=event.id, error=str(e)
            )

    async def _correlate_with_findings(self, event: HoneypotEvent) -> List[str]:
        """Correlate honeypot event with existing security findings"""
        correlations = []

        try:
            if not db_manager.is_enabled():
                return correlations

            # Get recent findings
            findings = await db_manager.get_open_findings()

            for finding in findings:
                # Check if source IP matches any exposed resources
                if self._is_ip_in_range(event.source_ip, "0.0.0.0/0"):
                    # This is an attack against internet-exposed resources
                    if finding["finding_type"] == "OPEN_TO_INTERNET":
                        correlations.append(finding["id"])
                        logger.info(
                            "Correlated honeypot event with finding",
                            event_id=event.id,
                            finding_id=finding["id"],
                            correlation_type="internet_exposure",
                        )

                # Check port correlation
                if str(event.destination_port) in finding.get("resource_name", ""):
                    correlations.append(finding["id"])
                    logger.info(
                        "Correlated honeypot event with finding",
                        event_id=event.id,
                        finding_id=finding["id"],
                        correlation_type="port_match",
                    )

        except Exception as e:
            logger.error("Error correlating honeypot event", error=str(e))

        return correlations

    async def _create_finding_from_event(
        self, event: HoneypotEvent
    ) -> Optional[SecurityFinding]:
        """Create a security finding from a high-severity honeypot event"""
        try:
            # Create a mock security rule for the finding
            from .models import SecurityRule, RuleType

            # This represents the exposed service that was attacked
            mock_rule = SecurityRule(
                id=f"honeypot-rule-{event.destination_port}",
                name=f"Exposed service on port {event.destination_port}",
                resource_group="honeypot-monitored",
                subscription_id="honeypot-correlation",
                rule_type=RuleType.NSG_RULE,
                priority=1000,
                direction="Inbound",
                access="Allow",
                protocol=event.protocol,
                source_address_prefix="0.0.0.0/0",
                destination_port_range=str(event.destination_port),
            )

            # Determine finding type based on event
            finding_type = FindingType.SUSPICIOUS_TRAFFIC_PATTERN
            if event.event_type in ["brute_force_attempt", "authentication_attempt"]:
                finding_type = FindingType.UNRESTRICTED_SSH_RDP
            elif event.destination_port in [1433, 3306, 5432, 6379, 27017]:
                finding_type = FindingType.DATABASE_PORTS_EXPOSED

            title = f"Active attack detected on port {event.destination_port}"
            if event.threat_indicators:
                title += f" ({', '.join(event.threat_indicators)})"

            description = (
                f"Honeypot detected active attack from {event.source_ip} "
                f"targeting port {event.destination_port}. "
                f"Event type: {event.event_type}. "
                f"This indicates that your exposed resources on this port "
                f"are actively being targeted by attackers."
            )

            if event.threat_indicators:
                description += (
                    f" Threat indicators: {', '.join(event.threat_indicators)}."
                )

            if event.payload:
                description += f" Attack payload detected: {event.payload[:200]}..."

            remediation_steps = [
                f"Immediately review NSG rules for port {event.destination_port}",
                f"Block source IP {event.source_ip} if not legitimate",
                "Implement rate limiting and intrusion detection",
                "Review logs for similar attack patterns",
                "Consider moving service to private subnet",
                "Enable Azure DDoS protection if not already active",
            ]

            return SecurityFinding(
                finding_type=finding_type,
                severity=event.severity,
                title=title,
                description=description,
                affected_rule=mock_rule,
                risk_score=min(90, 50 + len(event.threat_indicators) * 10),
                remediation_steps=remediation_steps,
                auto_remediable=False,  # Manual review required for attack events
                tags=["honeypot", "active-attack", "real-time"]
                + event.threat_indicators,
            )

        except Exception as e:
            logger.error(
                "Error creating finding from event", event_id=event.id, error=str(e)
            )
            return None

    async def _send_critical_alert(self, event: HoneypotEvent) -> None:
        """Send critical alert for high-severity events"""
        try:
            alert_message = (
                f"🚨 CRITICAL SECURITY ALERT 🚨\n\n"
                f"Active attack detected:\n"
                f"• Source: {event.source_ip}\n"
                f"• Target Port: {event.destination_port}\n"
                f"• Event Type: {event.event_type}\n"
                f"• Threat Indicators: {', '.join(event.threat_indicators)}\n"
                f"• Time: {event.timestamp}\n\n"
                f"Immediate action required!"
            )

            # Send to configured notification channels
            if config.slack_webhook_url:
                await self._send_slack_alert(alert_message)

            if config.teams_webhook_url:
                await self._send_teams_alert(alert_message)

            logger.critical(
                "Critical security alert sent",
                event_id=event.id,
                source_ip=event.source_ip,
                event_type=event.event_type,
            )

        except Exception as e:
            logger.error("Error sending critical alert", error=str(e))

    async def _send_slack_alert(self, message: str) -> None:
        """Send alert to Slack webhook"""
        try:
            payload = {
                "text": message,
                "username": "Security Copilot",
                "icon_emoji": ":warning:",
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    config.slack_webhook_url, json=payload
                ) as response:
                    if response.status != 200:
                        logger.error(
                            "Failed to send Slack alert", status=response.status
                        )

        except Exception as e:
            logger.error("Error sending Slack alert", error=str(e))

    async def _send_teams_alert(self, message: str) -> None:
        """Send alert to Microsoft Teams webhook"""
        try:
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": "Security Copilot Critical Alert",
                "themeColor": "FF0000",
                "title": "🚨 Critical Security Alert",
                "text": message,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    config.teams_webhook_url, json=payload
                ) as response:
                    if response.status != 200:
                        logger.error(
                            "Failed to send Teams alert", status=response.status
                        )

        except Exception as e:
            logger.error("Error sending Teams alert", error=str(e))

    def _is_ip_in_range(self, ip: str, cidr: str) -> bool:
        """Check if IP address is in CIDR range"""
        try:
            return ip_address(ip) in ip_network(cidr, strict=False)
        except Exception:
            return False

    async def get_recent_events(
        self, hours: int = 24, severity_filter: Optional[Severity] = None
    ) -> List[HoneypotEvent]:
        """Get recent honeypot events from database"""
        if not db_manager.is_enabled():
            return []

        try:
            # This would need to be implemented in the database manager
            # For now, return empty list
            logger.info("Getting recent honeypot events", hours=hours)
            return []

        except Exception as e:
            logger.error("Error getting recent events", error=str(e))
            return []


# Global honeypot monitor instance
honeypot_monitor = HoneypotMonitor()
