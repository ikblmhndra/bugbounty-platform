"""
Scan API Router
===============
POST /scans          - Trigger a new scan
GET  /scans          - List all scans
GET  /scans/{id}     - Get scan detail
GET  /scans/{id}/logs - Get scan logs
DELETE /scans/{id}   - Cancel/delete a scan
"""
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.config import get_settings
from app.models.models import AttackSurfaceNode, Log, Scan, ScanStage, ScanStatus, Target
from app.schemas.schemas import LogResponse, ScanCreate, ScanListResponse, ScanResponse, ScanStageResponse
from app.utils.database import get_async_db
from app.utils.logging import get_logger
from app.utils.validation import sanitize_domain
from app.workers.scan_tasks import run_scan

router = APIRouter(prefix="/scans", tags=["scans"])
logger = get_logger(__name__)
settings = get_settings()


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_async_db),
):
    """
    Trigger a new scan for a domain.
    Creates or reuses a Target record, then enqueues the scan task.
    """
    try:
        sanitized_domain = sanitize_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Upsert target
    result = await db.execute(select(Target).where(Target.domain == sanitized_domain))
    target = result.scalar_one_or_none()
    if not target:
        target = Target(domain=sanitized_domain)
        db.add(target)
        await db.flush()

    # Create scan record
    scan = Scan(
        target_id=target.id,
        status=ScanStatus.PENDING,
        options=payload.options.model_dump(),
        steps_total=0,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Enqueue Celery task
    task = run_scan.apply_async(args=[scan.id], queue="scans")
    scan.celery_task_id = task.id
    await db.commit()
    await db.refresh(scan)

    logger.info("Scan created", scan_id=scan.id, domain=sanitized_domain, task_id=task.id)
    return scan


@router.get("", response_model=list[ScanListResponse])
async def list_scans(
    status_filter: Optional[ScanStatus] = Query(None, alias="status"),
    target_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_async_db),
):
    """List scans with optional filtering."""
    q = select(Scan).order_by(desc(Scan.created_at)).offset(offset).limit(limit)
    if status_filter:
        q = q.where(Scan.status == status_filter)
    if target_id:
        q = q.where(Scan.target_id == target_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_async_db)):
    """Get full details for a specific scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/logs", response_model=list[LogResponse])
async def get_scan_logs(
    scan_id: str,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_async_db),
):
    """Get chronological logs for a scan."""
    from sqlalchemy import asc
    result = await db.execute(
        select(Log)
        .where(Log.scan_id == scan_id)
        .order_by(asc(Log.created_at))
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/{scan_id}/stages", response_model=list[ScanStageResponse])
async def get_scan_stages(scan_id: str, db: AsyncSession = Depends(get_async_db)):
    result = await db.execute(
        select(ScanStage)
        .where(ScanStage.scan_id == scan_id)
        .order_by(ScanStage.started_at.asc().nullsfirst())
    )
    return result.scalars().all()


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_async_db)):
    """Cancel a pending/running scan."""
    from app.workers.celery_app import celery_app as capp
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.celery_task_id:
        capp.control.revoke(scan.celery_task_id, terminate=True)
    scan.status = ScanStatus.CANCELLED
    await db.commit()
    logger.info("Scan cancelled", scan_id=scan_id)


@router.get("/{scan_id}/attack-surface")
async def get_attack_surface(scan_id: str, db: AsyncSession = Depends(get_async_db)):
    result = await db.execute(
        select(AttackSurfaceNode)
        .where(AttackSurfaceNode.scan_id == scan_id)
        .order_by(AttackSurfaceNode.risk_score.desc())
    )
    nodes = result.scalars().all()
    return [
        {
            "id": n.id,
            "type": n.node_type,
            "value": n.value,
            "parent_value": n.parent_value,
            "category": n.endpoint_category,
            "risk_score": n.risk_score,
            "risk_level": n.risk_level,
            "metadata": n.node_metadata,
        }
        for n in nodes
    ]


@router.get("/{scan_id}/prioritized")
async def get_prioritized_targets(scan_id: str, db: AsyncSession = Depends(get_async_db)):
    result = await db.execute(
        select(AttackSurfaceNode)
        .where(AttackSurfaceNode.scan_id == scan_id, AttackSurfaceNode.node_type == "endpoint")
        .order_by(AttackSurfaceNode.risk_score.desc())
    )
    nodes = result.scalars().all()
    return [
        {"url": n.value, "risk_score": n.risk_score, "risk_level": n.risk_level, "category": n.endpoint_category}
        for n in nodes
        if n.risk_level in ("high", "medium")
    ]


@router.get("/{scan_id}/report/{fmt}")
async def download_report(scan_id: str, fmt: str):
    ext = "json" if fmt == "json" else "md"
    path = Path(settings.reports_dir) / f"report_{scan_id}.{ext}"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path=str(path), filename=path.name)
