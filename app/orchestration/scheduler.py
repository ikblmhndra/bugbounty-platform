from datetime import datetime, timezone


def should_run_recurring(last_completed_at: datetime | None, cron_expr: str | None) -> bool:
    if not cron_expr:
        return False
    if not last_completed_at:
        return True
    # Lightweight scheduling policy for vertical slice: hourly recurrence.
    return (datetime.now(timezone.utc) - last_completed_at).total_seconds() >= 3600


def adaptive_depth(base_depth: int, previous_findings: int, previous_new_assets: int) -> int:
    if previous_findings > 20 or previous_new_assets > 100:
        return min(base_depth + 2, 8)
    if previous_findings == 0 and previous_new_assets < 10:
        return max(base_depth - 1, 1)
    return base_depth
