"""
Command Line Interface for Security Copilot Agent
"""

import asyncio
import sys
from datetime import datetime
from typing import Optional, List
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
import structlog

from .scanner import SecurityScanner
from .github_integration import GitHubIntegration
from .database import db_manager
from .models import Severity
from .config import config

console = Console()
logger = structlog.get_logger(__name__)


def setup_logging():
    """Setup structured logging"""
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
            (
                structlog.processors.JSONRenderer()
                if config.log_format == "json"
                else structlog.dev.ConsoleRenderer()
            ),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option(
    "--config-file", type=click.Path(exists=True), help="Path to configuration file"
)
def cli(verbose: bool, config_file: Optional[str]):
    """Security Copilot Agent - Azure Security Scanner and Automation Tool"""
    setup_logging()

    if verbose:
        config.log_level = "DEBUG"

    console.print(
        Panel.fit(
            Text("🛡️  Security Copilot Agent", style="bold blue"),
            subtitle="Azure Security Scanner and Automation Tool",
        )
    )


@cli.command()
@click.option("--subscription-id", "-s", help="Azure subscription ID to scan")
@click.option(
    "--resource-group", "-rg", multiple=True, help="Specific resource group(s) to scan"
)
@click.option("--auto-remediate", is_flag=True, help="Enable automatic remediation")
@click.option(
    "--create-issues",
    is_flag=True,
    default=True,
    help="Create GitHub issues for findings",
)
@click.option(
    "--output-format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def scan(
    subscription_id: Optional[str],
    resource_group: List[str],
    auto_remediate: bool,
    create_issues: bool,
    output_format: str,
):
    """Scan Azure NSGs and firewall rules for security misconfigurations"""

    async def run_scan():
        try:
            # Initialize scanner
            scanner = SecurityScanner(subscription_id)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:

                # Start scan
                task = progress.add_task("🔍 Scanning Azure resources...", total=None)

                scan_result = await scanner.scan_subscription(
                    resource_groups=list(resource_group) if resource_group else None
                )

                progress.update(task, description="✅ Scan completed")

            # Display results
            display_scan_results(scan_result, output_format)

            # Save to database if configured
            if db_manager.is_enabled():
                with Progress(console=console) as progress:
                    task = progress.add_task("💾 Saving to database...", total=None)
                    await db_manager.save_scan_result(scan_result)
                    await db_manager.save_findings(scan_result.findings)
                    progress.update(task, description="✅ Saved to database")

            # GitHub integration
            if create_issues and config.github_token:
                with Progress(console=console) as progress:
                    task = progress.add_task("🐙 Creating GitHub issues...", total=None)
                    github = GitHubIntegration()
                    github_results = await github.process_scan_results(scan_result)
                    progress.update(task, description="✅ GitHub integration completed")

                    console.print(f"📊 GitHub Results:")
                    console.print(
                        f"   • Issues created: {github_results['issues_created']}"
                    )
                    console.print(f"   • PRs created: {github_results['prs_created']}")
                    if github_results["errors"]:
                        console.print(f"   • Errors: {len(github_results['errors'])}")

        except Exception as e:
            console.print(f"❌ Scan failed: {str(e)}", style="red")
            sys.exit(1)

    asyncio.run(run_scan())


@cli.command()
@click.option("--subscription-id", "-s", help="Filter by subscription ID")
@click.option(
    "--severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    help="Filter by severity level",
)
@click.option("--limit", default=50, help="Maximum number of results")
@click.option("--output-format", type=click.Choice(["table", "json"]), default="table")
def list_findings(
    subscription_id: Optional[str],
    severity: Optional[str],
    limit: int,
    output_format: str,
):
    """List current security findings"""

    async def run_list():
        try:
            if not db_manager.is_enabled():
                console.print(
                    "❌ Database not configured. Cannot list findings.", style="red"
                )
                return

            findings = await db_manager.get_open_findings(subscription_id)

            # Filter by severity if specified
            if severity:
                findings = [f for f in findings if f["severity"] == severity]

            # Limit results
            findings = findings[:limit]

            if output_format == "json":
                import json

                console.print(json.dumps(findings, indent=2, default=str))
            else:
                display_findings_table(findings)

        except Exception as e:
            console.print(f"❌ Failed to list findings: {str(e)}", style="red")
            sys.exit(1)

    asyncio.run(run_list())


@cli.command()
@click.option("--subscription-id", "-s", help="Filter by subscription ID")
@click.option("--limit", default=20, help="Maximum number of results")
def scan_history(subscription_id: Optional[str], limit: int):
    """Show scan history"""

    async def run_history():
        try:
            if not db_manager.is_enabled():
                console.print(
                    "❌ Database not configured. Cannot show scan history.", style="red"
                )
                return

            scans = await db_manager.get_scan_history(subscription_id, limit)
            display_scan_history_table(scans)

        except Exception as e:
            console.print(f"❌ Failed to get scan history: {str(e)}", style="red")
            sys.exit(1)

    asyncio.run(run_history())


@cli.command()
@click.option("--honeypot-logs", is_flag=True, help="Monitor honeypot logs")
@click.option("--interval", default=60, help="Monitoring interval in seconds")
def monitor(honeypot_logs: bool, interval: int):
    """Monitor for security events in real-time"""

    async def run_monitor():
        console.print("🔍 Starting security monitoring...")
        console.print("Press Ctrl+C to stop")

        try:
            while True:
                if honeypot_logs and config.is_honeypot_configured():
                    # TODO: Implement honeypot log monitoring
                    console.print(
                        "📊 Monitoring honeypot logs... (Feature coming soon)"
                    )

                await asyncio.sleep(interval)

        except KeyboardInterrupt:
            console.print("\n👋 Monitoring stopped")
        except Exception as e:
            console.print(f"❌ Monitoring failed: {str(e)}", style="red")
            sys.exit(1)

    asyncio.run(run_monitor())


@cli.command()
@click.option("--subscription-id", "-s", help="Subscription ID for the report")
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["json", "html", "pdf"]),
    default="json",
    help="Report format",
)
@click.option("--output", "-o", help="Output file path")
def report(subscription_id: Optional[str], report_format: str, output: Optional[str]):
    """Generate compliance and security report"""

    async def run_report():
        try:
            if not db_manager.is_enabled():
                console.print(
                    "❌ Database not configured. Cannot generate report.", style="red"
                )
                return

            console.print("📊 Generating security report...")

            # Get findings and scan history
            findings = await db_manager.get_open_findings(subscription_id)
            scans = await db_manager.get_scan_history(subscription_id, 10)

            # Generate report based on format
            if report_format == "json":
                report_data = generate_json_report(findings, scans, subscription_id)

                if output:
                    with open(output, "w") as f:
                        import json

                        json.dump(report_data, f, indent=2, default=str)
                    console.print(f"📄 Report saved to: {output}")
                else:
                    import json

                    console.print(json.dumps(report_data, indent=2, default=str))
            else:
                console.print(
                    f"❌ Report format '{report_format}' not yet implemented",
                    style="red",
                )

        except Exception as e:
            console.print(f"❌ Report generation failed: {str(e)}", style="red")
            sys.exit(1)

    asyncio.run(run_report())


@cli.command()
def status():
    """Show system status and configuration"""

    table = Table(title="🛡️ Security Copilot Agent Status")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details")

    # Azure configuration
    azure_status = (
        "✅ Configured" if config.azure_subscription_id else "❌ Not configured"
    )
    table.add_row(
        "Azure",
        azure_status,
        (
            f"Subscription: {config.azure_subscription_id[:8]}..."
            if config.azure_subscription_id
            else "No subscription ID"
        ),
    )

    # GitHub configuration
    github_status = "✅ Configured" if config.github_token else "❌ Not configured"
    table.add_row(
        "GitHub",
        github_status,
        (
            f"Repo: {config.github_repo_owner}/{config.github_repo_name}"
            if config.github_token
            else "No token"
        ),
    )

    # Database configuration
    db_status = "✅ Enabled" if db_manager.is_enabled() else "❌ Disabled"
    table.add_row(
        "Database",
        db_status,
        "Azure SQL Database" if db_manager.is_enabled() else "No connection string",
    )

    # Honeypot configuration
    honeypot_status = (
        "✅ Configured" if config.is_honeypot_configured() else "❌ Not configured"
    )
    table.add_row(
        "Honeypot",
        honeypot_status,
        (
            "Integration enabled"
            if config.is_honeypot_configured()
            else "No configuration"
        ),
    )

    console.print(table)


def display_scan_results(scan_result, output_format: str):
    """Display scan results in the specified format"""

    if output_format == "json":
        import json

        console.print(
            json.dumps(
                {
                    "scan_id": scan_result.scan_id,
                    "subscription_id": scan_result.subscription_id,
                    "started_at": scan_result.started_at.isoformat(),
                    "completed_at": (
                        scan_result.completed_at.isoformat()
                        if scan_result.completed_at
                        else None
                    ),
                    "duration_seconds": scan_result.duration_seconds,
                    "total_rules_scanned": scan_result.total_rules_scanned,
                    "findings_by_severity": {
                        k.value: v for k, v in scan_result.findings_by_severity.items()
                    },
                    "findings": [
                        {
                            "id": f.id,
                            "type": f.finding_type.value,
                            "severity": f.severity.value,
                            "title": f.title,
                            "resource": f.affected_rule.name,
                            "resource_group": f.affected_rule.resource_group,
                            "risk_score": f.risk_score,
                            "auto_remediable": f.auto_remediable,
                        }
                        for f in scan_result.findings
                    ],
                },
                indent=2,
            )
        )
        return

    # Table format
    console.print(f"\n🔍 Scan Results: {scan_result.scan_id}")
    console.print(f"📅 Completed: {scan_result.completed_at}")
    console.print(f"⏱️  Duration: {scan_result.duration_seconds:.2f}s")
    console.print(f"🔢 Rules Scanned: {scan_result.total_rules_scanned}")

    # Summary table
    summary_table = Table(title="📊 Findings Summary")
    summary_table.add_column("Severity", style="cyan")
    summary_table.add_column("Count", style="green")

    findings_by_severity = scan_result.findings_by_severity
    for severity in [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]:
        count = findings_by_severity.get(severity, 0)
        if count > 0:
            emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵",
                "INFO": "⚪",
            }.get(severity.value, "⚪")
            summary_table.add_row(f"{emoji} {severity.value}", str(count))

    console.print(summary_table)

    # Detailed findings table
    if scan_result.findings:
        findings_table = Table(title="🚨 Security Findings")
        findings_table.add_column("Severity", style="red")
        findings_table.add_column("Type", style="cyan")
        findings_table.add_column("Resource", style="blue")
        findings_table.add_column("Resource Group", style="green")
        findings_table.add_column("Risk Score", style="yellow")
        findings_table.add_column("Auto-Fix", style="magenta")

        for finding in scan_result.findings:
            emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵",
                "INFO": "⚪",
            }.get(finding.severity.value, "⚪")
            findings_table.add_row(
                f"{emoji} {finding.severity.value}",
                finding.finding_type.value.replace("_", " ").title(),
                finding.affected_rule.name,
                finding.affected_rule.resource_group,
                str(finding.risk_score),
                "✅" if finding.auto_remediable else "❌",
            )

        console.print(findings_table)


def display_findings_table(findings: List[dict]):
    """Display findings in table format"""

    if not findings:
        console.print("✅ No open findings found")
        return

    table = Table(title="🚨 Open Security Findings")
    table.add_column("ID", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("Type", style="blue")
    table.add_column("Resource", style="green")
    table.add_column("Detected", style="yellow")
    table.add_column("GitHub", style="magenta")

    for finding in findings:
        emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪",
        }.get(finding["severity"], "⚪")

        github_status = "✅" if finding.get("github_issue_url") else "❌"

        table.add_row(
            finding["id"][:12] + "...",
            f"{emoji} {finding['severity']}",
            finding["finding_type"].replace("_", " ").title(),
            finding["resource_name"],
            finding["detected_at"].strftime("%Y-%m-%d"),
            github_status,
        )

    console.print(table)


def display_scan_history_table(scans: List[dict]):
    """Display scan history in table format"""

    if not scans:
        console.print("📭 No scan history found")
        return

    table = Table(title="📊 Scan History")
    table.add_column("Scan ID", style="cyan")
    table.add_column("Started", style="green")
    table.add_column("Status", style="blue")
    table.add_column("Total Findings", style="red")
    table.add_column("Critical", style="red")
    table.add_column("High", style="yellow")

    for scan in scans:
        status_emoji = {"completed": "✅", "failed": "❌", "in_progress": "🔄"}.get(
            scan["status"], "❓"
        )

        table.add_row(
            scan["scan_id"][:12] + "...",
            scan["started_at"].strftime("%Y-%m-%d %H:%M"),
            f"{status_emoji} {scan['status']}",
            str(scan["total_findings"]),
            str(scan["critical_findings"]),
            str(scan["high_findings"]),
        )

    console.print(table)


def generate_json_report(
    findings: List[dict], scans: List[dict], subscription_id: Optional[str]
) -> dict:
    """Generate a JSON compliance report"""

    # Calculate statistics
    total_findings = len(findings)
    severity_counts = {}
    type_counts = {}

    for finding in findings:
        severity = finding["severity"]
        finding_type = finding["finding_type"]

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1

    # Calculate compliance percentage (simplified)
    total_resources = sum(
        scan.get("total_rules_scanned", 0) for scan in scans[:1]
    )  # Use latest scan
    compliance_percentage = max(
        0, 100 - (total_findings / max(total_resources, 1)) * 100
    )

    return {
        "report_id": f"report-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        "generated_at": datetime.utcnow().isoformat(),
        "subscription_id": subscription_id,
        "summary": {
            "total_findings": total_findings,
            "compliance_percentage": round(compliance_percentage, 2),
            "last_scan": scans[0]["started_at"].isoformat() if scans else None,
        },
        "findings_by_severity": severity_counts,
        "findings_by_type": type_counts,
        "recent_scans": scans[:5],  # Last 5 scans
        "recommendations": [
            "Address all CRITICAL findings immediately",
            "Schedule regular security scans (weekly recommended)",
            "Implement automated remediation where possible",
            "Review and update security policies regularly",
            "Enable continuous monitoring for real-time detection",
        ],
    }


def main():
    """Main entry point for the CLI"""
    cli()


if __name__ == "__main__":
    main()
