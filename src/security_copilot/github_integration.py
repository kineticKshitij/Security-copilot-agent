"""
GitHub Integration for Security Copilot Agent
Handles creating issues and pull requests for security findings
"""

import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime
import structlog
from github import Github, GithubException
from github.Repository import Repository
from github.Issue import Issue
from github.PullRequest import PullRequest

from .models import SecurityFinding, ScanResult, Severity
from .config import config

logger = structlog.get_logger(__name__)


class GitHubIntegration:
    """GitHub integration for creating issues and pull requests"""
    
    def __init__(self, token: Optional[str] = None, repo_owner: Optional[str] = None, 
                 repo_name: Optional[str] = None):
        self.token = token or config.github_token
        self.repo_owner = repo_owner or config.github_repo_owner
        self.repo_name = repo_name or config.github_repo_name
        
        self.github = Github(self.token)
        self.repository = self._get_repository()
        
        logger.info("GitHub integration initialized", 
                   repo=f"{self.repo_owner}/{self.repo_name}")
    
    def _get_repository(self) -> Repository:
        """Get the GitHub repository"""
        try:
            repo = self.github.get_repo(f"{self.repo_owner}/{self.repo_name}")
            logger.debug("Connected to GitHub repository", repo=repo.full_name)
            return repo
        except GithubException as e:
            logger.error("Failed to connect to GitHub repository", 
                        repo=f"{self.repo_owner}/{self.repo_name}",
                        error=str(e))
            raise
    
    async def process_scan_results(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Process scan results and create GitHub issues/PRs as needed"""
        results = {
            "issues_created": 0,
            "prs_created": 0,
            "errors": []
        }
        
        try:
            logger.info("Processing scan results for GitHub integration",
                       scan_id=scan_result.scan_id,
                       findings_count=len(scan_result.findings))
            
            # Create issues for findings
            if config.create_issues_for_findings:
                for finding in scan_result.findings:
                    try:
                        issue = await self.create_issue_for_finding(finding)
                        if issue:
                            finding.github_issue_url = issue.html_url
                            results["issues_created"] += 1
                            
                            # Create PR for auto-remediable findings
                            if (config.create_prs_for_auto_fix and 
                                finding.auto_remediable and 
                                finding.remediation_script):
                                try:
                                    pr = await self.create_pr_for_finding(finding, issue)
                                    if pr:
                                        finding.github_pr_url = pr.html_url
                                        results["prs_created"] += 1
                                except Exception as e:
                                    error_msg = f"Failed to create PR for finding {finding.id}: {str(e)}"
                                    logger.error("PR creation failed", finding_id=finding.id, error=str(e))
                                    results["errors"].append(error_msg)
                    
                    except Exception as e:
                        error_msg = f"Failed to create issue for finding {finding.id}: {str(e)}"
                        logger.error("Issue creation failed", finding_id=finding.id, error=str(e))
                        results["errors"].append(error_msg)
            
            # Create summary issue for high-severity findings
            critical_and_high = [f for f in scan_result.findings 
                               if f.severity in [Severity.CRITICAL, Severity.HIGH]]
            
            if critical_and_high:
                try:
                    summary_issue = await self.create_summary_issue(scan_result, critical_and_high)
                    if summary_issue:
                        results["summary_issue_created"] = True
                        results["summary_issue_url"] = summary_issue.html_url
                except Exception as e:
                    error_msg = f"Failed to create summary issue: {str(e)}"
                    logger.error("Summary issue creation failed", error=str(e))
                    results["errors"].append(error_msg)
            
            logger.info("GitHub integration processing completed", 
                       scan_id=scan_result.scan_id,
                       **results)
            
            return results
            
        except Exception as e:
            logger.error("GitHub integration processing failed", error=str(e))
            results["errors"].append(f"General processing error: {str(e)}")
            return results
    
    async def create_issue_for_finding(self, finding: SecurityFinding) -> Optional[Issue]:
        """Create a GitHub issue for a security finding"""
        try:
            # Check if issue already exists
            existing_issue = self._find_existing_issue(finding)
            if existing_issue:
                logger.debug("Issue already exists for finding", 
                           finding_id=finding.id,
                           issue_number=existing_issue.number)
                return existing_issue
            
            # Create issue title and body
            title = f"🚨 {finding.severity.value}: {finding.title}"
            body = finding.to_github_issue_body()
            
            # Create labels
            labels = self._get_labels_for_finding(finding)
            
            # Create the issue
            issue = self.repository.create_issue(
                title=title,
                body=body,
                labels=labels
            )
            
            logger.info("Created GitHub issue for security finding",
                       finding_id=finding.id,
                       issue_number=issue.number,
                       issue_url=issue.html_url)
            
            return issue
            
        except GithubException as e:
            logger.error("Failed to create GitHub issue", 
                        finding_id=finding.id,
                        error=str(e))
            return None
    
    async def create_pr_for_finding(self, finding: SecurityFinding, 
                                  related_issue: Issue) -> Optional[PullRequest]:
        """Create a pull request with auto-remediation for a finding"""
        if not finding.auto_remediable or not finding.remediation_script:
            return None
        
        try:
            # Create a new branch for the fix
            branch_name = f"security-fix/{finding.id}"
            base_branch = self.repository.default_branch
            
            # Get the base branch reference
            base_ref = self.repository.get_git_ref(f"heads/{base_branch}")
            
            # Create new branch
            try:
                self.repository.create_git_ref(
                    ref=f"refs/heads/{branch_name}",
                    sha=base_ref.object.sha
                )
                logger.debug("Created branch for security fix", branch=branch_name)
            except GithubException as e:
                if "Reference already exists" in str(e):
                    logger.debug("Branch already exists", branch=branch_name)
                else:
                    raise
            
            # Create or update remediation script file
            script_path = f"scripts/security-fixes/{finding.id}-remediation.sh"
            script_content = f"""#!/bin/bash
# Auto-generated security remediation script
# Finding ID: {finding.id}
# Finding Type: {finding.finding_type.value}
# Severity: {finding.severity.value}
# Generated: {datetime.utcnow().isoformat()}

set -e

echo "Applying security fix for finding: {finding.id}"
echo "Affected resource: {finding.affected_rule.name}"
echo "Resource group: {finding.affected_rule.resource_group}"

{finding.remediation_script}

echo "Security fix applied successfully!"
"""
            
            # Commit the script
            try:
                self.repository.create_file(
                    path=script_path,
                    message=f"Add remediation script for security finding {finding.id}",
                    content=script_content,
                    branch=branch_name
                )
                logger.debug("Created remediation script file", path=script_path)
            except GithubException as e:
                if "path already exists" in str(e).lower():
                    # Update existing file
                    file_obj = self.repository.get_contents(script_path, ref=branch_name)
                    self.repository.update_file(
                        path=script_path,
                        message=f"Update remediation script for security finding {finding.id}",
                        content=script_content,
                        sha=file_obj.sha,
                        branch=branch_name
                    )
                    logger.debug("Updated existing remediation script file", path=script_path)
                else:
                    raise
            
            # Create documentation file
            doc_path = f"docs/security-findings/{finding.id}.md"
            doc_content = f"""# Security Finding: {finding.title}

**Finding ID**: {finding.id}
**Severity**: {finding.severity.value}
**Type**: {finding.finding_type.value}
**Risk Score**: {finding.risk_score}/100
**Detected**: {finding.detected_at.isoformat()}

## Description
{finding.description}

## Affected Resource
- **Name**: {finding.affected_rule.name}
- **Resource Group**: {finding.affected_rule.resource_group}
- **Subscription**: {finding.affected_rule.subscription_id}
- **Type**: {finding.affected_rule.rule_type.value}

## Current Configuration
- **Direction**: {finding.affected_rule.direction}
- **Access**: {finding.affected_rule.access}
- **Protocol**: {finding.affected_rule.protocol}
- **Source**: {finding.affected_rule.source_address_prefix or 'Any'}
- **Source Ports**: {finding.affected_rule.source_port_range or 'Any'}
- **Destination**: {finding.affected_rule.destination_address_prefix or 'Any'}
- **Destination Ports**: {finding.affected_rule.destination_port_range or 'Any'}

## Remediation Steps
"""
            for i, step in enumerate(finding.remediation_steps, 1):
                doc_content += f"{i}. {step}\n"
            
            doc_content += f"""
## Auto-Remediation
This finding can be automatically remediated using the script: `{script_path}`

**⚠️ WARNING**: Review the script carefully before execution. Always test in a non-production environment first.

## Related Issue
This finding is tracked in issue #{related_issue.number}: {related_issue.html_url}
"""
            
            try:
                self.repository.create_file(
                    path=doc_path,
                    message=f"Add documentation for security finding {finding.id}",
                    content=doc_content,
                    branch=branch_name
                )
                logger.debug("Created documentation file", path=doc_path)
            except GithubException as e:
                if "path already exists" in str(e).lower():
                    file_obj = self.repository.get_contents(doc_path, ref=branch_name)
                    self.repository.update_file(
                        path=doc_path,
                        message=f"Update documentation for security finding {finding.id}",
                        content=doc_content,
                        sha=file_obj.sha,
                        branch=branch_name
                    )
                    logger.debug("Updated existing documentation file", path=doc_path)
                else:
                    raise
            
            # Create pull request
            pr_title = f"🔧 Auto-fix: {finding.title}"
            pr_body = f"""## Security Auto-Remediation Pull Request

This PR contains an automated fix for security finding **{finding.id}**.

### Finding Details
- **Severity**: {finding.severity.value}
- **Type**: {finding.finding_type.value}
- **Risk Score**: {finding.risk_score}/100
- **Affected Resource**: {finding.affected_rule.name}

### Changes
- ✅ Added remediation script: `{script_path}`
- ✅ Added documentation: `{doc_path}`

### ⚠️ Important Notes
1. **Review Carefully**: This is an automated fix. Please review all changes before merging.
2. **Test First**: Always test remediation scripts in a non-production environment.
3. **Backup**: Ensure you have backups of current configurations.
4. **Monitor**: Monitor the affected resources after applying changes.

### Remediation Script
The remediation script will:
"""
            for step in finding.remediation_steps:
                pr_body += f"- {step}\n"
            
            pr_body += f"""
### Related Issue
Fixes #{related_issue.number}

---
*This PR was automatically generated by Security Copilot Agent*
"""
            
            # Get labels for PR
            pr_labels = config.github_pr_labels_list + [
                f"severity-{finding.severity.value.lower()}",
                f"type-{finding.finding_type.value.lower().replace('_', '-')}"
            ]
            
            pull_request = self.repository.create_pull(
                title=pr_title,
                body=pr_body,
                head=branch_name,
                base=base_branch,
                draft=True  # Create as draft for safety
            )
            
            # Add labels to PR
            pull_request.add_to_labels(*pr_labels)
            
            # Link the PR to the issue
            issue_comment = f"""🔧 **Auto-Remediation Available**

A pull request has been created with automated fixes for this security finding:
- **PR**: {pull_request.html_url}
- **Branch**: `{branch_name}`
- **Status**: Draft (requires review)

### Next Steps
1. Review the remediation script and documentation
2. Test the changes in a non-production environment  
3. If satisfied, mark the PR as ready for review and merge

⚠️ **Important**: Always review and test automated security fixes before applying to production resources.
"""
            
            related_issue.create_comment(issue_comment)
            
            logger.info("Created pull request for security finding",
                       finding_id=finding.id,
                       pr_number=pull_request.number,
                       pr_url=pull_request.html_url,
                       branch=branch_name)
            
            return pull_request
            
        except Exception as e:
            logger.error("Failed to create pull request for finding",
                        finding_id=finding.id,
                        error=str(e))
            return None
    
    async def create_summary_issue(self, scan_result: ScanResult, 
                                 high_severity_findings: List[SecurityFinding]) -> Optional[Issue]:
        """Create a summary issue for high-severity findings"""
        try:
            title = f"🚨 Security Scan Summary - {len(high_severity_findings)} High/Critical Findings"
            
            # Create summary body
            body = f"""# Security Scan Summary Report

**Scan ID**: {scan_result.scan_id}
**Completed**: {scan_result.completed_at.isoformat() if scan_result.completed_at else 'In Progress'}
**Subscription**: {scan_result.subscription_id}
**Duration**: {scan_result.duration_seconds:.2f}s

## Executive Summary
This automated security scan identified **{len(high_severity_findings)}** high or critical severity findings that require immediate attention.

### Findings by Severity
"""
            
            findings_by_severity = scan_result.findings_by_severity
            for severity, count in findings_by_severity.items():
                if count > 0:
                    emoji = "🔴" if severity == Severity.CRITICAL else "🟠" if severity == Severity.HIGH else "🟡" if severity == Severity.MEDIUM else "🔵"
                    body += f"- {emoji} **{severity.value}**: {count} findings\n"
            
            body += f"""
### Critical Issues Requiring Immediate Action
"""
            
            critical_findings = [f for f in high_severity_findings if f.severity == Severity.CRITICAL]
            if critical_findings:
                for finding in critical_findings:
                    body += f"- 🔴 [{finding.title}](#{finding.id}) - {finding.affected_rule.name}\n"
            else:
                body += "- ✅ No critical findings detected\n"
            
            body += f"""
### High-Priority Issues
"""
            
            high_findings = [f for f in high_severity_findings if f.severity == Severity.HIGH]
            if high_findings:
                for finding in high_findings:
                    body += f"- 🟠 [{finding.title}](#{finding.id}) - {finding.affected_rule.name}\n"
            else:
                body += "- ✅ No high-priority findings detected\n"
            
            body += f"""
## Resource Groups Scanned
"""
            for rg in scan_result.resource_groups:
                body += f"- {rg}\n"
            
            body += f"""
## Recommended Actions
1. **Immediate**: Address all CRITICAL findings within 24 hours
2. **Priority**: Address all HIGH findings within 1 week  
3. **Review**: Evaluate MEDIUM and LOW findings for compliance requirements
4. **Monitor**: Set up continuous monitoring for these resource groups

## Auto-Remediation
{len([f for f in high_severity_findings if f.auto_remediable])} of these findings can be automatically remediated with pull requests.

---
*This summary was automatically generated by Security Copilot Agent*
*Next scan scheduled: {(datetime.utcnow()).strftime('%Y-%m-%d %H:%M UTC')}*
"""
            
            # Create labels
            labels = ["security-summary", "high-priority"] + config.github_labels_list
            
            # Create the summary issue
            issue = self.repository.create_issue(
                title=title,
                body=body,
                labels=labels
            )
            
            logger.info("Created summary issue for security scan",
                       scan_id=scan_result.scan_id,
                       issue_number=issue.number,
                       high_severity_count=len(high_severity_findings))
            
            return issue
            
        except Exception as e:
            logger.error("Failed to create summary issue", 
                        scan_id=scan_result.scan_id,
                        error=str(e))
            return None
    
    def _find_existing_issue(self, finding: SecurityFinding) -> Optional[Issue]:
        """Check if an issue already exists for this finding"""
        try:
            # Search for issues with finding ID in title or body
            search_query = f"repo:{self.repo_owner}/{self.repo_name} is:issue {finding.id}"
            issues = self.github.search_issues(search_query)
            
            for issue in issues:
                if finding.id in issue.title or finding.id in (issue.body or ""):
                    return issue
            
            return None
            
        except Exception as e:
            logger.error("Error searching for existing issues", 
                        finding_id=finding.id,
                        error=str(e))
            return None
    
    def _get_labels_for_finding(self, finding: SecurityFinding) -> List[str]:
        """Get appropriate labels for a security finding"""
        labels = config.github_labels_list.copy()
        
        # Add severity label
        labels.append(f"severity-{finding.severity.value.lower()}")
        
        # Add finding type label
        labels.append(f"type-{finding.finding_type.value.lower().replace('_', '-')}")
        
        # Add resource type label
        labels.append(f"resource-{finding.affected_rule.rule_type.value.lower().replace('_', '-')}")
        
        # Add auto-remediation label if applicable
        if finding.auto_remediable:
            labels.append("auto-remediable")
        
        # Add subscription label
        labels.append(f"subscription-{finding.affected_rule.subscription_id[:8]}")
        
        return labels
    
    async def close_resolved_issues(self, current_findings: List[SecurityFinding]) -> int:
        """Close issues for findings that are no longer present"""
        try:
            # Get all open security issues
            open_issues = self.repository.get_issues(state="open", labels=config.github_labels_list)
            
            current_finding_ids = {f.id for f in current_findings}
            closed_count = 0
            
            for issue in open_issues:
                # Extract finding ID from issue (if present)
                finding_id = self._extract_finding_id_from_issue(issue)
                
                if finding_id and finding_id not in current_finding_ids:
                    # Finding no longer exists, close the issue
                    issue.edit(state="closed")
                    issue.create_comment(
                        "✅ **Issue Resolved**\n\n"
                        "This security finding is no longer detected in the latest scan. "
                        "The issue has been automatically closed.\n\n"
                        "*Closed by Security Copilot Agent*"
                    )
                    closed_count += 1
                    logger.info("Closed resolved issue", 
                               issue_number=issue.number,
                               finding_id=finding_id)
            
            return closed_count
            
        except Exception as e:
            logger.error("Error closing resolved issues", error=str(e))
            return 0
    
    def _extract_finding_id_from_issue(self, issue: Issue) -> Optional[str]:
        """Extract finding ID from GitHub issue"""
        import re
        
        # Look for finding ID pattern in title and body
        pattern = r'finding-\d{8}-\d{6}'
        
        # Check title
        if issue.title:
            match = re.search(pattern, issue.title)
            if match:
                return match.group()
        
        # Check body
        if issue.body:
            match = re.search(pattern, issue.body)
            if match:
                return match.group()
        
        return None
