"""
Targets API Router
==================
CRUD operations for scan targets.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.models import Target
from app.schemas.schemas import TargetCreate, TargetResponse, TargetUpdate
from app.utils.database import get_async_db
from app.utils.logging import get_logger

router = APIRouter(prefix="/targets", tags=["targets"])
logger = get_logger(__name__)


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetCreate,
    db: AsyncSession = Depends(get_async_db),
):
    """Create a new target. Domain must be unique."""
    existing = await db.execute(select(Target).where(Target.domain == payload.domain))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Target with this domain already exists")

    target = Target(**payload.model_dump())
    db.add(target)
    await db.commit()
    await db.refresh(target)
    logger.info("Target created", domain=target.domain)
    return target


@router.get("", response_model=list[TargetResponse])
async def list_targets(db: AsyncSession = Depends(get_async_db)):
    """List all targets."""
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    return result.scalars().all()


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str, db: AsyncSession = Depends(get_async_db)):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.patch("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: str,
    payload: TargetUpdate,
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(target, field, value)
    await db.commit()
    await db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: str, db: AsyncSession = Depends(get_async_db)):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.delete(target)
    await db.commit()
