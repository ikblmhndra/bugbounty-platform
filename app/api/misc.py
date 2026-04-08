"""
Supplementary API Routers
=========================
- GET /paths           - List attack paths
- GET /assets          - List discovered assets
- GET /dashboard       - Aggregate stats
- GET /reports/{id}    - Generate and download report
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.models.models import (
    Asset,
    AssetType,
    AttackPath,
    Finding,
    FindingCategory,
    FindingSeverity,
    Scan,
    ScanStatus,
    Target,
)
from app.schemas.schemas import (
    AssetResponse,
    AttackPathResponse,
    DashboardStats,
    ScanListResponse,
)
from app.services.report_service import (
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
    save_report,
)
from app.utils.database import get_async_db

# ─── Attack Paths ─────────────────────────────────────────────────────────────
paths_router = APIRouter(prefix="/paths", tags=["attack-paths"])


@paths_router.get("", response_model=list[AttackPathResponse])
async def list_attack_paths(
    scan_id: Optional[str] = Query(None),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    db: AsyncSession = Depends(get_async_db),
):
    """List attack paths, optionally filtered by scan and confidence threshold."""
    q = (
        select(AttackPath)
        .where(AttackPath.confidence >= min_confidence)
        .options(selectinload(AttackPath.nodes))
        .order_by(AttackPath.confidence.desc())
    )
    if scan_id:
        q = q.where(AttackPath.scan_id == scan_id)
    result = await db.execute(q)
    return result.scalars().all()


@paths_router.get("/{path_id}", response_model=AttackPathResponse)
async def get_attack_path(path_id: str, db: AsyncSession = Depends(get_async_db)):
    result = await db.execute(
        select(AttackPath)
        .where(AttackPath.id == path_id)
        .options(selectinload(AttackPath.nodes))
    )
    path = result.scalar_one_or_none()
    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")
    return path


# ─── Assets ───────────────────────────────────────────────────────────────────
assets_router = APIRouter(prefix="/assets", tags=["assets"])


@assets_router.get("", response_model=list[AssetResponse])
async def list_assets(
    scan_id: Optional[str] = Query(None),
    asset_type: Optional[AssetType] = Query(None),
    is_alive: Optional[bool] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_async_db),
):
    """List discovered assets with optional filters."""
    q = select(Asset).order_by(Asset.created_at.desc()).offset(offset).limit(limit)
    if scan_id:
        q = q.where(Asset.scan_id == scan_id)
    if asset_type:
        q = q.where(Asset.asset_type == asset_type)
    if is_alive is not None:
        q = q.where(Asset.is_alive == is_alive)
    result = await db.execute(q)
    return result.scalars().all()


# ─── Dashboard ────────────────────────────────────────────────────────────────
dashboard_router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@dashboard_router.get("", response_model=DashboardStats)
async def get_dashboard(db: AsyncSession = Depends(get_async_db)):
    """Return aggregate statistics for the dashboard."""
    total_targets = (await db.execute(select(func.count(Target.id)))).scalar_one()
    total_scans = (await db.execute(select(func.count(Scan.id)))).scalar_one()
    active_scans = (await db.execute(
        select(func.count(Scan.id)).where(Scan.status == ScanStatus.RUNNING)
    )).scalar_one()
    total_findings = (await db.execute(select(func.count(Finding.id)))).scalar_one()

    # Severity breakdown
    sev_counts = {}
    for sev in FindingSeverity:
        count = (await db.execute(
            select(func.count(Finding.id)).where(Finding.severity == sev, Finding.false_positive == False)
        )).scalar_one()
        sev_counts[sev.value] = count

    # Category breakdown
    cat_results = await db.execute(
        select(Finding.category, func.count(Finding.id))
        .where(Finding.false_positive == False)
        .group_by(Finding.category)
    )
    by_category = {row[0].value: row[1] for row in cat_results}

    # Recent scans
    recent_result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(10)
    )
    recent_scans = recent_result.scalars().all()

    return DashboardStats(
        total_targets=total_targets,
        total_scans=total_scans,
        active_scans=active_scans,
        total_findings=total_findings,
        critical_findings=sev_counts.get("critical", 0),
        high_findings=sev_counts.get("high", 0),
        medium_findings=sev_counts.get("medium", 0),
        low_findings=sev_counts.get("low", 0),
        findings_by_category=by_category,
        recent_scans=[ScanListResponse.model_validate(s) for s in recent_scans],
    )


# ─── Reports ──────────────────────────────────────────────────────────────────
reports_router = APIRouter(prefix="/reports", tags=["reports"])


@reports_router.get("/{scan_id}")
async def generate_report(
    scan_id: str,
    fmt: str = Query("json", regex="^(json|markdown|html)$"),
    save: bool = Query(False),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Generate a report for a scan.

    Args:
        scan_id: Scan UUID.
        fmt: Report format: json | markdown | html
        save: If True, also persist the report to disk.
    """
    # Load scan + target
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_result.scalar_one_or_none()

    # Load findings and attack paths
    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = list(findings_result.scalars().all())

    paths_result = await db.execute(
        select(AttackPath)
        .where(AttackPath.scan_id == scan_id)
        .options(selectinload(AttackPath.nodes))
    )
    attack_paths = list(paths_result.scalars().all())

    if fmt == "json":
        report_data = generate_json_report(scan, target, findings, attack_paths)
        if save:
            save_report(scan_id, str(report_data), "json")
        return JSONResponse(content=report_data)

    elif fmt == "markdown":
        content = generate_markdown_report(scan, target, findings, attack_paths)
        if save:
            save_report(scan_id, content, "markdown")
        return PlainTextResponse(content=content, media_type="text/markdown")

    elif fmt == "html":
        content = generate_html_report(scan, target, findings, attack_paths)
        if save:
            save_report(scan_id, content, "html")
        return HTMLResponse(content=content)
