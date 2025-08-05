"""
Security Copilot Agent

A comprehensive Azure security automation tool that scans Network Security Groups (NSGs) 
and firewall rules for misconfigurations, automatically creates GitHub issues with 
remediation steps, generates pull requests for fixes, and logs all findings to Azure SQL Database.
"""

__version__ = "1.0.0"
__author__ = "Security Team"
__email__ = "security@company.com"

from .scanner import SecurityScanner
from .github_integration import GitHubIntegration
from .models import SecurityFinding, Severity
from .config import Config

__all__ = [
    "SecurityScanner",
    "GitHubIntegration", 
    "SecurityFinding",
    "Severity",
    "Config",
]
