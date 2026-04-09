import enum
import uuid

from sqlalchemy import Boolean, Column, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
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


class ScanStageType(str, enum.Enum):
    RECON = "recon"
    ENUMERATION = "enumeration"
    PROBING = "probing"
    SCANNING = "scanning"
    VALIDATION = "validation"
    REPORTING = "reporting"


class StageStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class AssetType(str, enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    ENDPOINT = "endpoint"


class FindingSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, enum.Enum):
    XSS = "xss"
    SQLI = "sqli"
    MISCONFIG = "misconfig"
    EXPOSURE = "exposure"
    SSRF = "ssrf"
    RCE = "rce"
    IDOR = "idor"
    OTHER = "other"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"


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
    assets = relationship("Asset", back_populates="target", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Target {self.domain}>"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    target_id = Column(UUID(as_uuid=False), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    celery_task_id = Column(String(255), nullable=True, index=True)

    steps_total = Column(Integer, default=6)
    steps_completed = Column(Integer, default=0)
    current_step = Column(String(100), nullable=True, index=True)

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
    stages = relationship("ScanStage", back_populates="scan", cascade="all, delete-orphan")
    asset_diffs = relationship("AssetSnapshotDiff", back_populates="scan", cascade="all, delete-orphan")
    finding_diffs = relationship("FindingSnapshotDiff", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scans_target_status", "target_id", "status"),
    )

    def __repr__(self) -> str:
        return f"<Scan {self.id} [{self.status}]>"


class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    target_id = Column(UUID(as_uuid=False), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_type = Column(Enum(AssetType), nullable=False, index=True)
    value = Column(String(2048), nullable=False)
    normalized_key = Column(String(2048), nullable=False, index=True)
    parent_asset_id = Column(UUID(as_uuid=False), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    in_scope = Column(Boolean, nullable=False, default=True, index=True)
    source = Column(String(120), nullable=True)
    raw_data = Column(JSONB, default=dict)

    # For subdomains / IPs
    ip_address = Column(String(45), nullable=True)
    is_alive = Column(Boolean, nullable=True)
    status_code = Column(Integer, nullable=True)
    technologies = Column(JSONB, default=list)   # detected tech stack
    headers = Column(JSONB, default=dict)
    screenshot_path = Column(String(512), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    target = relationship("Target", back_populates="assets")
    scan = relationship("Scan", back_populates="assets")
    parent_asset = relationship("Asset", remote_side=[id], uselist=False)
    findings = relationship("Finding", back_populates="asset")

    __table_args__ = (
        UniqueConstraint("scan_id", "normalized_key", name="uq_asset_scan_normalized"),
        Index("ix_assets_scan_type", "scan_id", "asset_type"),
    )

    def __repr__(self) -> str:
        return f"<Asset {self.asset_type.value}: {self.value}>"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(UUID(as_uuid=False), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=False), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)

    # Classification
    category = Column(Enum(FindingCategory), nullable=False)
    severity = Column(Enum(FindingSeverity), nullable=False, index=True)
    status = Column(Enum(FindingStatus), nullable=False, default=FindingStatus.OPEN, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    tags = Column(JSONB, default=list)
    vuln_fingerprint = Column(String(512), nullable=False, index=True)
    endpoint_signature = Column(String(2048), nullable=False, index=True)

    # Location
    url = Column(String(2048), nullable=True)
    parameter = Column(String(255), nullable=True)
    method = Column(String(10), nullable=True)   # GET, POST, etc.

    # Evidence
    request_snippet = Column(Text, nullable=True)
    response_snippet = Column(Text, nullable=True)
    evidence = Column(JSONB, default=dict)

    # Source tool
    source_tool = Column(String(100), nullable=True)
    template_id = Column(String(255), nullable=True)
    cvss_base_score = Column(Float, nullable=False, default=0.0)
    exploitability_score = Column(Float, nullable=False, default=0.0)
    weighted_score = Column(Float, nullable=False, default=0.0, index=True)
    confidence = Column(Float, nullable=False, default=0.5)

    # Analyst workflow
    is_validated = Column(Boolean, default=False)
    analyst_notes = Column(Text, nullable=True)
    false_positive = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("Scan", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    evidences = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("target_id", "vuln_fingerprint", "endpoint_signature", name="uq_finding_dedup"),
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_category", "category"),
    )

    def __repr__(self) -> str:
        return f"<Finding [{self.severity.value}] {self.title}>"


class ScanStage(Base):
    __tablename__ = "scan_stages"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    stage_type = Column(Enum(ScanStageType), nullable=False, index=True)
    status = Column(Enum(StageStatus), nullable=False, default=StageStatus.PENDING, index=True)
    attempt = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=2)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    stage_data = Column(JSONB, default=dict)

    scan = relationship("Scan", back_populates="stages")

    __table_args__ = (
        UniqueConstraint("scan_id", "stage_type", name="uq_scan_stage"),
    )


class Evidence(Base):
    __tablename__ = "evidences"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(64), nullable=False, index=True)
    storage_path = Column(String(1024), nullable=True)
    content = Column(JSONB, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    finding = relationship("Finding", back_populates="evidences")


class AssetSnapshotDiff(Base):
    __tablename__ = "asset_snapshot_diffs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    added = Column(JSONB, default=list)
    removed = Column(JSONB, default=list)
    unchanged_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("Scan", back_populates="asset_diffs")


class FindingSnapshotDiff(Base):
    __tablename__ = "finding_snapshot_diffs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    new_fingerprints = Column(JSONB, default=list)
    resolved_fingerprints = Column(JSONB, default=list)
    unchanged_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("Scan", back_populates="finding_diffs")


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
