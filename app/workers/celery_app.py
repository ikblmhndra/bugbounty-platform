"""
Celery application factory and configuration.
"""
from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "bugbounty",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    broker_connection_retry_on_startup=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=settings.default_scan_timeout,
    task_time_limit=settings.default_scan_timeout + 300,
    task_routes={
        "app.workers.scan_tasks.run_scan": {"queue": "scans"},
    },
    task_default_rate_limit="30/m",
    beat_schedule={
        "scheduled-scan-orchestration": {
            "task": "app.workers.scan_tasks.process_scheduled_scans",
            "schedule": 300.0,
            "options": {"queue": "orchestration"},
        }
    },
)
