"""
Database integration for Security Copilot Agent
Handles logging findings and audit trails to Azure SQL Database
"""

import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any
import structlog
from sqlalchemy import create_engine, Column, String, DateTime, Integer, Text, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError

from .models import SecurityFinding, ScanResult, HoneypotEvent, Severity, FindingType
from .config import config

logger = structlog.get_logger(__name__)

Base = declarative_base()


class SecurityFindingDB(Base):
    """Database model for security findings"""
    __tablename__ = 'security_findings'
    
    id = Column(String(50), primary_key=True)
    finding_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    
    # Affected resource details
    resource_name = Column(String(200), nullable=False)
    resource_group = Column(String(100), nullable=False)
    subscription_id = Column(String(50), nullable=False)
    resource_type = Column(String(50), nullable=False)
    
    # Risk assessment
    risk_score = Column(Integer, nullable=False)
    cvss_score = Column(Float, nullable=True)
    
    # Timestamps
    detected_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Status tracking
    status = Column(String(20), default='open')  # open, resolved, false_positive, ignored
    resolved_at = Column(DateTime, nullable=True)
    
    # GitHub integration
    github_issue_url = Column(String(500), nullable=True)
    github_pr_url = Column(String(500), nullable=True)
    
    # Remediation
    auto_remediable = Column(Boolean, default=False)
    remediation_applied = Column(Boolean, default=False)
    remediation_applied_at = Column(DateTime, nullable=True)


class ScanResultDB(Base):
    """Database model for scan results"""
    __tablename__ = 'scan_results'
    
    scan_id = Column(String(50), primary_key=True)
    subscription_id = Column(String(50), nullable=False)
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    
    # Scan statistics
    total_rules_scanned = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    
    # Status
    status = Column(String(20), default='in_progress')
    error_message = Column(Text, nullable=True)
    
    # Metadata
    resource_groups = Column(Text, nullable=True)  # JSON string
    created_at = Column(DateTime, default=datetime.utcnow)


class HoneypotEventDB(Base):
    """Database model for honeypot events"""
    __tablename__ = 'honeypot_events'
    
    id = Column(String(50), primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    source_ip = Column(String(45), nullable=False)  # Support IPv6
    destination_ip = Column(String(45), nullable=False)
    destination_port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    
    # Additional data
    geolocation = Column(Text, nullable=True)  # JSON string
    user_agent = Column(Text, nullable=True)
    payload = Column(Text, nullable=True)
    threat_indicators = Column(Text, nullable=True)  # JSON string
    
    # Processing status
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLogDB(Base):
    """Database model for audit logs"""
    __tablename__ = 'audit_logs'
    
    id = Column(String(50), primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(200), nullable=False)
    
    # Action details
    action_details = Column(Text, nullable=True)  # JSON string
    user_context = Column(String(100), nullable=True)
    source_system = Column(String(50), default='security-copilot-agent')
    
    # Results
    success = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)


class DatabaseManager:
    """Manages database connections and operations for Security Copilot Agent"""
    
    def __init__(self, connection_string: Optional[str] = None):
        self.connection_string = connection_string or config.azure_sql_connection_string
        self.engine = None
        self.SessionLocal = None
        
        if self._should_initialize_database():
            self._initialize_database()
        else:
            logger.warning("No database connection string provided - database features disabled")
    
    def _should_initialize_database(self) -> bool:
        """Check if we should initialize the database"""
        return bool(
            self.connection_string or 
            (config.azure_sql_server and config.azure_sql_database and config.azure_sql_username)
        )
    
    def _build_sqlalchemy_url(self) -> str:
        """Build SQLAlchemy URL from config"""
        if self.connection_string and not self.connection_string.startswith(('mssql+', 'sqlite')):
            # If it's an ODBC connection string, convert to SQLAlchemy format
            if config.azure_sql_server and config.azure_sql_username:
                url = (
                    f"mssql+pymssql://{config.azure_sql_username}:{config.azure_sql_password}@"
                    f"{config.azure_sql_server}/{config.azure_sql_database}"
                )
                return url
        return self.connection_string or ""
    
    def _initialize_database(self):
        """Initialize database connection and create tables"""
        try:
            sqlalchemy_url = self._build_sqlalchemy_url()
            
            if not sqlalchemy_url:
                logger.warning("No valid database URL - skipping database initialization")
                return
                
            self.engine = create_engine(
                sqlalchemy_url,
                echo=False,  # Set to True for SQL debugging
                pool_pre_ping=True,
                pool_recycle=3600,
                connect_args={
                    "driver": "ODBC Driver 18 for SQL Server",
                    "timeout": 30,
                    "autocommit": False
                }
            )
            
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            
            # Create tables if they don't exist
            Base.metadata.create_all(bind=self.engine)
            
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize database", error=str(e))
            raise
    
    def is_enabled(self) -> bool:
        """Check if database integration is enabled"""
        return self.engine is not None
    
    async def save_scan_result(self, scan_result: ScanResult) -> bool:
        """Save scan result to database"""
        if not self.is_enabled():
            return False
        
        try:
            session = self.SessionLocal()
            
            # Convert findings by severity to counts
            findings_by_severity = scan_result.findings_by_severity
            
            # Create scan result record
            scan_db = ScanResultDB(
                scan_id=scan_result.scan_id,
                subscription_id=scan_result.subscription_id,
                started_at=scan_result.started_at,
                completed_at=scan_result.completed_at,
                total_rules_scanned=scan_result.total_rules_scanned,
                total_findings=len(scan_result.findings),
                critical_findings=findings_by_severity.get(Severity.CRITICAL, 0),
                high_findings=findings_by_severity.get(Severity.HIGH, 0),
                medium_findings=findings_by_severity.get(Severity.MEDIUM, 0),
                low_findings=findings_by_severity.get(Severity.LOW, 0),
                status=scan_result.status,
                error_message=scan_result.error_message,
                resource_groups=','.join(scan_result.resource_groups)
            )
            
            session.add(scan_db)
            session.commit()
            
            logger.info("Saved scan result to database", scan_id=scan_result.scan_id)
            return True
            
        except SQLAlchemyError as e:
            logger.error("Failed to save scan result", scan_id=scan_result.scan_id, error=str(e))
            session.rollback()
            return False
        finally:
            session.close()
    
    async def save_findings(self, findings: List[SecurityFinding]) -> int:
        """Save security findings to database"""
        if not self.is_enabled():
            return 0
        
        saved_count = 0
        session = self.SessionLocal()
        
        try:
            for finding in findings:
                try:
                    # Check if finding already exists
                    existing = session.query(SecurityFindingDB).filter(
                        SecurityFindingDB.id == finding.id
                    ).first()
                    
                    if existing:
                        # Update existing record
                        existing.status = 'open'  # Re-open if it was previously resolved
                        existing.updated_at = datetime.utcnow()
                        existing.github_issue_url = finding.github_issue_url
                        existing.github_pr_url = finding.github_pr_url
                    else:
                        # Create new record
                        finding_db = SecurityFindingDB(
                            id=finding.id,
                            finding_type=finding.finding_type.value,
                            severity=finding.severity.value,
                            title=finding.title,
                            description=finding.description,
                            resource_name=finding.affected_rule.name,
                            resource_group=finding.affected_rule.resource_group,
                            subscription_id=finding.affected_rule.subscription_id,
                            resource_type=finding.affected_rule.rule_type.value,
                            risk_score=finding.risk_score,
                            cvss_score=finding.cvss_score,
                            detected_at=finding.detected_at,
                            github_issue_url=finding.github_issue_url,
                            github_pr_url=finding.github_pr_url,
                            auto_remediable=finding.auto_remediable
                        )
                        session.add(finding_db)
                    
                    saved_count += 1
                    
                except Exception as e:
                    logger.error("Failed to save individual finding", 
                               finding_id=finding.id, error=str(e))
                    continue
            
            session.commit()
            logger.info("Saved findings to database", count=saved_count)
            
        except SQLAlchemyError as e:
            logger.error("Failed to save findings batch", error=str(e))
            session.rollback()
        finally:
            session.close()
        
        return saved_count
    
    async def save_honeypot_event(self, event: HoneypotEvent) -> bool:
        """Save honeypot event to database"""
        if not self.is_enabled():
            return False
        
        try:
            session = self.SessionLocal()
            
            event_db = HoneypotEventDB(
                id=event.id,
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                destination_port=event.destination_port,
                protocol=event.protocol,
                event_type=event.event_type,
                severity=event.severity.value,
                geolocation=str(event.geolocation) if event.geolocation else None,
                user_agent=event.user_agent,
                payload=event.payload,
                threat_indicators=','.join(event.threat_indicators) if event.threat_indicators else None
            )
            
            session.add(event_db)
            session.commit()
            
            logger.info("Saved honeypot event to database", event_id=event.id)
            return True
            
        except SQLAlchemyError as e:
            logger.error("Failed to save honeypot event", event_id=event.id, error=str(e))
            session.rollback()
            return False
        finally:
            session.close()
    
    async def mark_finding_resolved(self, finding_id: str) -> bool:
        """Mark a finding as resolved"""
        if not self.is_enabled():
            return False
        
        try:
            session = self.SessionLocal()
            
            finding = session.query(SecurityFindingDB).filter(
                SecurityFindingDB.id == finding_id
            ).first()
            
            if finding:
                finding.status = 'resolved'
                finding.resolved_at = datetime.utcnow()
                finding.updated_at = datetime.utcnow()
                session.commit()
                
                logger.info("Marked finding as resolved", finding_id=finding_id)
                return True
            else:
                logger.warning("Finding not found for resolution", finding_id=finding_id)
                return False
                
        except SQLAlchemyError as e:
            logger.error("Failed to mark finding as resolved", 
                        finding_id=finding_id, error=str(e))
            session.rollback()
            return False
        finally:
            session.close()
    
    async def get_open_findings(self, subscription_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all open findings, optionally filtered by subscription"""
        if not self.is_enabled():
            return []
        
        try:
            session = self.SessionLocal()
            
            query = session.query(SecurityFindingDB).filter(
                SecurityFindingDB.status == 'open'
            )
            
            if subscription_id:
                query = query.filter(SecurityFindingDB.subscription_id == subscription_id)
            
            findings = query.all()
            
            result = []
            for finding in findings:
                result.append({
                    'id': finding.id,
                    'finding_type': finding.finding_type,
                    'severity': finding.severity,
                    'title': finding.title,
                    'resource_name': finding.resource_name,
                    'resource_group': finding.resource_group,
                    'subscription_id': finding.subscription_id,
                    'risk_score': finding.risk_score,
                    'detected_at': finding.detected_at,
                    'github_issue_url': finding.github_issue_url,
                    'github_pr_url': finding.github_pr_url,
                    'auto_remediable': finding.auto_remediable
                })
            
            logger.info("Retrieved open findings", count=len(result))
            return result
            
        except SQLAlchemyError as e:
            logger.error("Failed to get open findings", error=str(e))
            return []
        finally:
            session.close()
    
    async def get_scan_history(self, subscription_id: Optional[str] = None, 
                             limit: int = 50) -> List[Dict[str, Any]]:
        """Get scan history, optionally filtered by subscription"""
        if not self.is_enabled():
            return []
        
        try:
            session = self.SessionLocal()
            
            query = session.query(ScanResultDB).order_by(ScanResultDB.started_at.desc())
            
            if subscription_id:
                query = query.filter(ScanResultDB.subscription_id == subscription_id)
            
            scans = query.limit(limit).all()
            
            result = []
            for scan in scans:
                result.append({
                    'scan_id': scan.scan_id,
                    'subscription_id': scan.subscription_id,
                    'started_at': scan.started_at,
                    'completed_at': scan.completed_at,
                    'status': scan.status,
                    'total_findings': scan.total_findings,
                    'critical_findings': scan.critical_findings,
                    'high_findings': scan.high_findings,
                    'medium_findings': scan.medium_findings,
                    'low_findings': scan.low_findings,
                    'resource_groups': scan.resource_groups.split(',') if scan.resource_groups else []
                })
            
            logger.info("Retrieved scan history", count=len(result))
            return result
            
        except SQLAlchemyError as e:
            logger.error("Failed to get scan history", error=str(e))
            return []
        finally:
            session.close()
    
    async def log_audit_event(self, action: str, resource_type: str, resource_id: str,
                            action_details: Optional[Dict[str, Any]] = None,
                            success: bool = True, error_message: Optional[str] = None) -> bool:
        """Log an audit event"""
        if not self.is_enabled():
            return False
        
        try:
            session = self.SessionLocal()
            
            audit_log = AuditLogDB(
                id=f"audit-{datetime.utcnow().strftime('%Y%m%d-%H%M%S-%f')}",
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                action_details=str(action_details) if action_details else None,
                success=success,
                error_message=error_message
            )
            
            session.add(audit_log)
            session.commit()
            
            return True
            
        except SQLAlchemyError as e:
            logger.error("Failed to log audit event", error=str(e))
            session.rollback()
            return False
        finally:
            session.close()


# Global database manager instance
db_manager = DatabaseManager()
