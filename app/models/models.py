"""
SQLAlchemy ORM models for the bug bounty platform.

Models:
    Target      - Scoped domain/target
    Scan        - Scan run instance
    Asset       - Discovered subdomains, URLs, endpoints
    Finding     - Vulnerability or misconfiguration finding
    AttackPath  - Correlated chain of findings
    AttackPathNode - Individual step in an attack path
    Log         - Scan activity log entries
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.utils.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssetType(str, enum.Enum):
    SUBDOMAIN = "subdomain"
    URL = "url"
    ENDPOINT = "endpoint"
    IP = "ip"


class FindingSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, enum.Enum):
    XSS = "xss"
    SQLI = "sqli"
    LFI = "lfi"
    SSRF = "ssrf"
    MISCONFIGURATION = "misconfiguration"
    SENSITIVE_DATA = "sensitive_data"
    RCE = "rce"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    XXE = "xxe"
    SSTI = "ssti"
    OTHER = "other"


class Target(Base):
    __tablename__ = "targets"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    scope_include = Column(JSONB, default=list)   # list of in-scope patterns
    scope_exclude = Column(JSONB, default=list)   # list of out-of-scope patterns
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Target {self.domain}>"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    target_id = Column(UUID(as_uuid=False), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    celery_task_id = Column(String(255), nullable=True, index=True)

    # Pipeline step tracking
    steps_total = Column(Integer, default=0)
    steps_completed = Column(Integer, default=0)
    current_step = Column(String(100), nullable=True)

    # Scan options
    options = Column(JSONB, default=dict)  # e.g. {"run_ffuf": true, "nuclei_severity": "high,critical"}

    # Results summary
    assets_found = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    target = relationship("Target", back_populates="scans")
    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    attack_paths = relationship("AttackPath", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scans_target_status", "target_id", "status"),
    )

    def __repr__(self) -> str:
        return f"<Scan {self.id} [{self.status}]>"


class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_type = Column(Enum(AssetType), nullable=False, index=True)
    value = Column(String(2048), nullable=False)

    # For subdomains / IPs
    ip_address = Column(String(45), nullable=True)
    is_alive = Column(Boolean, nullable=True)
    status_code = Column(Integer, nullable=True)
    technologies = Column(JSONB, default=list)   # detected tech stack
    headers = Column(JSONB, default=dict)
    screenshot_path = Column(String(512), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("Scan", back_populates="assets")

    __table_args__ = (
        UniqueConstraint("scan_id", "value", name="uq_asset_scan_value"),
        Index("ix_assets_scan_type", "scan_id", "asset_type"),
    )

    def __repr__(self) -> str:
        return f"<Asset {self.asset_type.value}: {self.value}>"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    # Classification
    category = Column(Enum(FindingCategory), nullable=False)
    severity = Column(Enum(FindingSeverity), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)

    # Location
    url = Column(String(2048), nullable=True)
    parameter = Column(String(255), nullable=True)
    method = Column(String(10), nullable=True)   # GET, POST, etc.

    # Evidence
    request_snippet = Column(Text, nullable=True)
    response_snippet = Column(Text, nullable=True)
    evidence = Column(JSONB, default=dict)   # raw tool output / match data

    # Source tool
    source_tool = Column(String(100), nullable=True)
    template_id = Column(String(255), nullable=True)   # nuclei template ID

    # Analyst workflow
    is_validated = Column(Boolean, default=False)
    analyst_notes = Column(Text, nullable=True)
    false_positive = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("Scan", back_populates="findings")
    attack_path_nodes = relationship("AttackPathNode", back_populates="finding")

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_category", "category"),
    )

    def __repr__(self) -> str:
        return f"<Finding [{self.severity.value}] {self.title}>"


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False, default=0.5)   # 0.0 - 1.0
    impact = Column(String(255), nullable=True)

    # Pre-computed steps for analyst presentation
    steps = Column(JSONB, default=list)   # list of human-readable step strings

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("Scan", back_populates="attack_paths")
    nodes = relationship("AttackPathNode", back_populates="attack_path", cascade="all, delete-orphan", order_by="AttackPathNode.order")

    def __repr__(self) -> str:
        return f"<AttackPath {self.title} confidence={self.confidence}>"


class AttackPathNode(Base):
    __tablename__ = "attack_path_nodes"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    attack_path_id = Column(UUID(as_uuid=False), ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)

    order = Column(Integer, nullable=False)
    label = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    validation_command = Column(Text, nullable=True)   # Suggested manual command

    attack_path = relationship("AttackPath", back_populates="nodes")
    finding = relationship("Finding", back_populates="attack_path_nodes")

    def __repr__(self) -> str:
        return f"<AttackPathNode order={self.order} {self.label}>"


class Log(Base):
    __tablename__ = "logs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    level = Column(String(20), default="info", nullable=False)
    step = Column(String(100), nullable=True)
    message = Column(Text, nullable=False)
    details = Column(JSONB, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("Scan", back_populates="logs")

    __table_args__ = (
        Index("ix_logs_scan_created", "scan_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Log [{self.level}] {self.message[:60]}>"
