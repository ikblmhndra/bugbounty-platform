"""
Database engine, session factory, and dependency injection helpers.
Supports both async (FastAPI) and sync (Celery workers) usage.
"""
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.pool import NullPool

from app.config import get_settings
from app.utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

Base = declarative_base()

# Async engine (FastAPI)
async_engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# Sync engine (Celery workers)
sync_engine = create_engine(
    settings.sync_database_url,
    echo=settings.debug,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    autocommit=False,
    autoflush=False,
)


async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@contextmanager
def get_sync_db() -> Generator[Session, None, None]:
    """Context manager for sync DB sessions (used in Celery workers)."""
    session = SyncSessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


async def init_db() -> None:
    """Create all tables. Called on application startup."""
    async with async_engine.begin() as conn:
        # Serialize schema init on Postgres to avoid create_all race conditions.
        if conn.dialect.name == "postgresql":
            # Use transaction-scoped lock to avoid manual unlock in failed tx.
            await conn.execute(text("SELECT pg_advisory_xact_lock(9142026)"))

        await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables initialized")


async def drop_db() -> None:
    """Drop all tables. Used in testing."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
