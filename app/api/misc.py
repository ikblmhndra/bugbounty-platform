from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.models import (
    Asset,
    AssetType,
    Finding,
    FindingSeverity,
    Scan,
    ScanStatus,
    Target,
)
from app.schemas.schemas import (
    AssetResponse,
    DashboardStats,
    ScanListResponse,
)
from app.utils.database import get_async_db

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
    total_assets = (await db.execute(select(func.count(Asset.id)))).scalar_one()
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
    findings_by_severity = sev_counts

    # Recent scans
    recent_result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(10)
    )
    recent_scans = recent_result.scalars().all()

    return DashboardStats(
        total_targets=total_targets,
        total_scans=total_scans,
        active_scans=active_scans,
        total_assets=total_assets,
        total_findings=total_findings,
        critical_findings=sev_counts.get("critical", 0),
        high_findings=sev_counts.get("high", 0),
        medium_findings=sev_counts.get("medium", 0),
        low_findings=sev_counts.get("low", 0),
        findings_by_category=by_category,
        findings_by_severity=findings_by_severity,
        findings_trend=[],
        recent_scans=[ScanListResponse.model_validate(s) for s in recent_scans],
    )
