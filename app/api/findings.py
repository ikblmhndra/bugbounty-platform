"""
Findings API Router
===================
GET  /findings              - List findings with filtering
GET  /findings/{id}         - Get finding detail
PATCH /findings/{id}        - Update analyst notes / validation status
GET  /findings/{id}/validate - Get suggested validation commands
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.models import Evidence, Finding, FindingCategory, FindingSeverity, FindingStatus
from app.schemas.schemas import FindingResponse, FindingUpdate
from app.services.validation_service import generate_validation_suggestions
from app.utils.database import get_async_db

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    scan_id: Optional[str] = Query(None),
    severity: Optional[list[FindingSeverity]] = Query(None),
    category: Optional[list[FindingCategory]] = Query(None),
    is_validated: Optional[bool] = Query(None),
    false_positive: Optional[bool] = Query(None),
    status: Optional[list[FindingStatus]] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_async_db),
):
    """
    List findings with optional filters.
    Supports multi-value severity and category filters via repeated query params.
    """
    q = select(Finding).order_by(Finding.created_at.desc()).offset(offset).limit(limit)
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity.in_(severity))
    if category:
        q = q.where(Finding.category.in_(category))
    if is_validated is not None:
        q = q.where(Finding.is_validated == is_validated)
    if false_positive is not None:
        q = q.where(Finding.false_positive == false_positive)
    if status:
        q = q.where(Finding.status.in_(status))

    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_async_db)):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    db: AsyncSession = Depends(get_async_db),
):
    """
    Update analyst notes, validation status, or false-positive flag.
    Allows analysts to record results from manual validation.
    """
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(finding, field, value)
    if payload.false_positive is True:
        finding.status = FindingStatus.FALSE_POSITIVE
    await db.commit()
    await db.refresh(finding)
    return finding


@router.get("/{finding_id}/validate")
async def get_validation_commands(
    finding_id: str,
    db: AsyncSession = Depends(get_async_db),
):
    """
    Return suggested manual validation commands for a finding.
    These are informational only — NOT auto-executed.
    """
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    suggestion = generate_validation_suggestions(
        finding_id=finding.id,
        title=finding.title,
        severity=finding.severity,
        category=finding.category,
        url=finding.url or "",
        parameter=finding.parameter,
    )

    return {
        "finding_id": finding_id,
        "title": suggestion.title,
        "category": suggestion.category,
        "severity": suggestion.severity,
        "url": suggestion.url,
        "commands": suggestion.commands,
        "notes": suggestion.notes,
        "risk_note": suggestion.risk_note,
        "disclaimer": "These commands are for manual analyst use only. Do not automate without authorization.",
    }


@router.get("/{finding_id}/evidence")
async def get_finding_evidence(finding_id: str, db: AsyncSession = Depends(get_async_db)):
    result = await db.execute(select(Evidence).where(Evidence.finding_id == finding_id))
    return result.scalars().all()
