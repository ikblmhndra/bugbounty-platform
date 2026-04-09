import asyncio
import time
from collections import defaultdict
from datetime import datetime, timedelta
from threading import Lock
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.models import Scan, ScanStatus, Target
from app.utils.database import get_sync_db


# Rate limiting
_target_locks: Dict[str, Lock] = defaultdict(Lock)
_target_tokens: Dict[str, Tuple[float, int]] = {}

# Scheduling
_scheduled_scans: Dict[str, asyncio.Task] = {}
_scheduler_lock = Lock()


def acquire_target_lock(target_id: str) -> Lock:
    """Get or create a lock for target-level concurrency control."""
    return _target_locks[target_id]


def allow_request(target_id: str, max_rps: int = 10) -> bool:
    """Rate limiting per target."""
    now = time.monotonic()
    ts, count = _target_tokens.get(target_id, (now, 0))
    if now - ts >= 1.0:
        _target_tokens[target_id] = (now, 1)
        return True
    if count >= max_rps:
        return False
    _target_tokens[target_id] = (ts, count + 1)
    return True


def get_adaptive_scan_depth(target_id: str) -> Dict[str, bool]:
    """
    Determine scan depth based on previous scan results and target characteristics.
    Returns options dict for scan configuration.
    """
    with get_sync_db() as db:
        # Get recent scans for this target
        recent_scans = db.query(Scan).filter(
            Scan.target_id == target_id,
            Scan.created_at >= datetime.utcnow() - timedelta(days=30)
        ).order_by(Scan.created_at.desc()).limit(5).all()

        if not recent_scans:
            # First scan - run full depth
            return {
                "run_ffuf": True,
                "nuclei_severity": "info,low,medium,high,critical",
                "run_naabu": True,
                "deep_enumeration": True
            }

        # Analyze previous results
        total_findings = sum(scan.findings_count or 0 for scan in recent_scans)
        avg_findings = total_findings / len(recent_scans)

        # Adaptive logic
        options = {
            "run_ffuf": avg_findings > 5,  # Run fuzzing if historically productive
            "nuclei_severity": "medium,high,critical" if avg_findings < 10 else "info,low,medium,high,critical",
            "run_naabu": True,  # Always run port scanning
            "deep_enumeration": avg_findings > 2  # Deeper enumeration if findings are common
        }

        return options


def schedule_scan(target_id: str, cron_expression: Optional[str] = None, delay_minutes: int = 0) -> str:
    """
    Schedule a scan for later execution.
    Returns scan_id of the scheduled scan.
    """
    from app.api.scans import create_scan  # Import here to avoid circular imports

    with _scheduler_lock:
        if delay_minutes > 0:
            # Schedule delayed execution
            async def delayed_scan():
                await asyncio.sleep(delay_minutes * 60)
                try:
                    # Create and start the scan
                    scan_data = {"target_id": target_id, "options": get_adaptive_scan_depth(target_id)}
                    scan = create_scan(scan_data)
                    # Here you would trigger the actual scan execution
                    # For now, just mark as scheduled
                except Exception as e:
                    print(f"Scheduled scan failed: {e}")

            task = asyncio.create_task(delayed_scan())
            task_id = f"scheduled_{target_id}_{int(time.time())}"
            _scheduled_scans[task_id] = task
            return task_id

        # Immediate scheduling
        scan_data = {"target_id": target_id, "options": get_adaptive_scan_depth(target_id)}
        scan = create_scan(scan_data)
        return scan.id


def get_concurrency_limit(target_id: str) -> int:
    """
    Determine max concurrent scans for a target based on its size and history.
    """
    with get_sync_db() as db:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            return 1

        # Count active scans
        active_scans = db.query(Scan).filter(
            Scan.target_id == target_id,
            Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING])
        ).count()

        # Base limit of 2, reduce if target has many active scans
        base_limit = 2
        if active_scans >= 2:
            return 1
        elif active_scans >= 1:
            return 1

        return base_limit


def can_start_scan(target_id: str) -> Tuple[bool, str]:
    """
    Check if a new scan can be started for the target.
    Returns (allowed, reason)
    """
    # Check concurrency
    concurrency_limit = get_concurrency_limit(target_id)
    with get_sync_db() as db:
        active_scans = db.query(Scan).filter(
            Scan.target_id == target_id,
            Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING])
        ).count()

        if active_scans >= concurrency_limit:
            return False, f"Concurrency limit reached ({active_scans}/{concurrency_limit})"

    # Check rate limiting
    if not allow_request(target_id, max_rps=5):  # 5 scans per second max
        return False, "Rate limit exceeded"

    return True, "OK"


def cleanup_completed_schedules() -> None:
    """Clean up completed scheduled tasks."""
    with _scheduler_lock:
        to_remove = []
        for task_id, task in _scheduled_scans.items():
            if task.done():
                to_remove.append(task_id)
        for task_id in to_remove:
            del _scheduled_scans[task_id]
