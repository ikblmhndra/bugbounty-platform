"""
Pydantic v2 schemas for API request validation and response serialization.
"""
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.models import (
    AssetType,
    FindingCategory,
    FindingSeverity,
    ScanStatus,
)


# ─── Base ────────────────────────────────────────────────────────────────────

class OrmBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ─── Target ──────────────────────────────────────────────────────────────────

class TargetCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = None
    scope_include: list[str] = Field(default_factory=list)
    scope_exclude: list[str] = Field(default_factory=list)

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v: str) -> str:
        return v.strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")


class TargetUpdate(BaseModel):
    description: Optional[str] = None
    scope_include: Optional[list[str]] = None
    scope_exclude: Optional[list[str]] = None
    is_active: Optional[bool] = None


class TargetResponse(OrmBase):
    id: str
    domain: str
    description: Optional[str]
    scope_include: list[str]
    scope_exclude: list[str]
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime]


# ─── Scan ─────────────────────────────────────────────────────────────────────

class ScanOptions(BaseModel):
    run_ffuf: bool = False
    run_gowitness: bool = True
    nuclei_severity: str = "low,medium,high,critical"
    ffuf_wordlist: Optional[str] = None
    timeout: int = Field(default=3600, ge=60, le=86400)


class ScanCreate(BaseModel):
    domain: str = Field(..., min_length=3)
    options: ScanOptions = Field(default_factory=ScanOptions)


class ScanResponse(OrmBase):
    id: str
    target_id: str
    status: ScanStatus
    celery_task_id: Optional[str]
    steps_total: int
    steps_completed: int
    current_step: Optional[str]
    assets_found: int
    findings_count: int
    error_message: Optional[str]
    options: dict
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime


class ScanListResponse(OrmBase):
    id: str
    target_id: str
    status: ScanStatus
    steps_total: int
    steps_completed: int
    current_step: Optional[str]
    assets_found: int
    findings_count: int
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]


# ─── Asset ────────────────────────────────────────────────────────────────────

class AssetResponse(OrmBase):
    id: str
    scan_id: str
    asset_type: AssetType
    value: str
    ip_address: Optional[str]
    is_alive: Optional[bool]
    status_code: Optional[int]
    technologies: list[str]
    screenshot_path: Optional[str]
    created_at: datetime


# ─── Finding ─────────────────────────────────────────────────────────────────

class FindingUpdate(BaseModel):
    is_validated: Optional[bool] = None
    analyst_notes: Optional[str] = None
    false_positive: Optional[bool] = None


class FindingResponse(OrmBase):
    id: str
    scan_id: str
    category: FindingCategory
    severity: FindingSeverity
    title: str
    description: Optional[str]
    url: Optional[str]
    parameter: Optional[str]
    method: Optional[str]
    request_snippet: Optional[str]
    response_snippet: Optional[str]
    evidence: dict
    source_tool: Optional[str]
    template_id: Optional[str]
    is_validated: bool
    analyst_notes: Optional[str]
    false_positive: bool
    created_at: datetime


class FindingFilter(BaseModel):
    scan_id: Optional[str] = None
    severity: Optional[list[FindingSeverity]] = None
    category: Optional[list[FindingCategory]] = None
    is_validated: Optional[bool] = None
    false_positive: Optional[bool] = None
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


# ─── Attack Path ─────────────────────────────────────────────────────────────

class AttackPathNodeResponse(OrmBase):
    id: str
    finding_id: Optional[str]
    order: int
    label: str
    description: Optional[str]
    validation_command: Optional[str]


class AttackPathResponse(OrmBase):
    id: str
    scan_id: str
    title: str
    description: str
    confidence: float
    impact: Optional[str]
    steps: list[str]
    nodes: list[AttackPathNodeResponse]
    created_at: datetime


# ─── Log ─────────────────────────────────────────────────────────────────────

class LogResponse(OrmBase):
    id: str
    scan_id: str
    level: str
    step: Optional[str]
    message: str
    details: dict
    created_at: datetime


# ─── Dashboard ───────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_targets: int
    total_scans: int
    active_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    findings_by_category: dict[str, int]
    recent_scans: list[ScanListResponse]


# ─── Report ──────────────────────────────────────────────────────────────────

class ReportFormat(str):
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"
