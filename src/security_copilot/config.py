"""
Configuration management for Security Copilot Agent
"""

import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Config(BaseSettings):
    """Application configuration using Pydantic BaseSettings"""

    # Azure Configuration
    azure_subscription_id: str = Field(..., env="AZURE_SUBSCRIPTION_ID")
    azure_client_id: Optional[str] = Field(None, env="AZURE_CLIENT_ID")
    azure_client_secret: Optional[str] = Field(None, env="AZURE_CLIENT_SECRET")
    azure_tenant_id: Optional[str] = Field(None, env="AZURE_TENANT_ID")
    use_managed_identity: bool = Field(False, env="USE_MANAGED_IDENTITY")

    # GitHub Configuration
    github_token: str = Field(..., env="GITHUB_TOKEN")
    github_repo_owner: str = Field(..., env="GITHUB_REPO_OWNER")
    github_repo_name: str = Field(..., env="GITHUB_REPO_NAME")

    # Azure SQL Configuration (Optional)
    azure_sql_server: Optional[str] = Field(None, env="AZURE_SQL_SERVER")
    azure_sql_database: Optional[str] = Field(None, env="AZURE_SQL_DATABASE")
    azure_sql_username: Optional[str] = Field(None, env="AZURE_SQL_USERNAME")
    azure_sql_password: Optional[str] = Field(None, env="AZURE_SQL_PASSWORD")
    azure_sql_connection_string: Optional[str] = Field(
        None, env="AZURE_SQL_CONNECTION_STRING"
    )

    # Honeypot Configuration (Optional)
    honeypot_log_path: Optional[str] = Field(None, env="HONEYPOT_LOG_PATH")
    honeypot_api_endpoint: Optional[str] = Field(None, env="HONEYPOT_API_ENDPOINT")
    honeypot_api_key: Optional[str] = Field(None, env="HONEYPOT_API_KEY")

    # Logging Configuration
    log_level: str = Field("INFO", env="LOG_LEVEL")
    log_format: str = Field("json", env="LOG_FORMAT")

    # Scanner Configuration
    scan_interval_hours: int = Field(24, env="SCAN_INTERVAL_HOURS")
    auto_remediation_enabled: bool = Field(False, env="AUTO_REMEDIATION_ENABLED")
    max_concurrent_scans: int = Field(5, env="MAX_CONCURRENT_SCANS")

    # GitHub Integration
    create_issues_for_findings: bool = Field(True, env="CREATE_ISSUES_FOR_FINDINGS")
    create_prs_for_auto_fix: bool = Field(True, env="CREATE_PRS_FOR_AUTO_FIX")
    github_issue_labels: str = Field(
        "security,nsg,misconfiguration", env="GITHUB_ISSUE_LABELS"
    )
    github_pr_labels: str = Field("security,auto-fix", env="GITHUB_PR_LABELS")

    # Notification Configuration (Optional)
    slack_webhook_url: Optional[str] = Field(None, env="SLACK_WEBHOOK_URL")
    teams_webhook_url: Optional[str] = Field(None, env="TEAMS_WEBHOOK_URL")
    email_smtp_server: Optional[str] = Field(None, env="EMAIL_SMTP_SERVER")
    email_smtp_port: int = Field(587, env="EMAIL_SMTP_PORT")
    email_username: Optional[str] = Field(None, env="EMAIL_USERNAME")
    email_password: Optional[str] = Field(None, env="EMAIL_PASSWORD")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @property
    def github_labels_list(self) -> list[str]:
        """Convert comma-separated label string to list"""
        return [label.strip() for label in self.github_issue_labels.split(",")]

    @property
    def github_pr_labels_list(self) -> list[str]:
        """Convert comma-separated PR label string to list"""
        return [label.strip() for label in self.github_pr_labels.split(",")]

    def is_sql_configured(self) -> bool:
        """Check if Azure SQL is properly configured"""
        return bool(
            self.azure_sql_connection_string
            or (self.azure_sql_server and self.azure_sql_database)
        )

    def is_honeypot_configured(self) -> bool:
        """Check if honeypot integration is configured"""
        return bool(self.honeypot_log_path or self.honeypot_api_endpoint)


# Global configuration instance
config = Config()
