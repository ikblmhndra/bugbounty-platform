"""
FastAPI Application Entry Point
================================
Registers all routers, middleware, startup/shutdown hooks,
and OpenAPI configuration.
"""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.findings import router as findings_router
from app.api.misc import (
    assets_router,
    dashboard_router,
)
from app.api.scans import router as scans_router
from app.api.targets import router as targets_router
from app.api.ws import router as ws_router
from app.config import get_settings
from app.services.metrics import metrics_store
from app.utils.database import init_db
from app.utils.logging import get_logger, setup_logging

setup_logging()
logger = get_logger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown logic."""
    logger.info("Starting Bug Bounty Platform API", env=settings.app_env)

    # Ensure output directories exist
    os.makedirs(settings.reports_dir, exist_ok=True)
    os.makedirs(settings.screenshots_dir, exist_ok=True)

    # Initialize database tables
    await init_db()

    # Sentry integration (if configured)
    if settings.sentry_dsn:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        sentry_sdk.init(dsn=settings.sentry_dsn, integrations=[FastApiIntegration()])
        logger.info("Sentry initialized")

    yield

    logger.info("Shutting down Bug Bounty Platform API")


app = FastAPI(
    title="Bug Bounty Platform API",
    description=(
        "Reconnaissance and vulnerability analysis platform for authorized security assessments. "
        "All scan results are analyst-facing; no autonomous exploitation is performed."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ─── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://0.0.0.0:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def metrics_middleware(request, call_next):
    metrics_store.inc("http_requests_total")
    response = await call_next(request)
    metrics_store.inc(f"http_status_{response.status_code}")
    return response

# ─── Routers ──────────────────────────────────────────────────────────────────
app.include_router(targets_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(findings_router, prefix="/api/v1")
app.include_router(assets_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(ws_router)


# ─── Health ───────────────────────────────────────────────────────────────────
@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/metrics", tags=["system"])
async def metrics():
    return metrics_store.snapshot()


# ─── Global Exception Handler ─────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.exception("Unhandled exception", path=str(request.url), error=str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
