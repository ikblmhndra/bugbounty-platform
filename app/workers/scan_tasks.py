import asyncio
from datetime import datetime, timezone

from celery import Task
from celery.utils.log import get_task_logger
from sqlalchemy.orm import Session

from app.models.models import Asset, AssetType, Evidence, Finding, FindingCategory, FindingSeverity, FindingStatus, Log, Scan, ScanStage, ScanStageType, ScanStatus, StageStatus, Target
from app.orchestration.controls import acquire_target_lock
from app.orchestration.state_machine import STAGE_ORDER
from app.plugins.base import PluginContext
from app.services.analysis_service import normalize_nuclei_findings
from app.services.finding_engine import dedup_fingerprint, endpoint_signature, score_finding, tags_for_category
from app.services.normalization import in_scope, normalize_asset
from app.plugins.builtin import FfufPlugin, HttpProbePlugin, NaabuPlugin, NucleiPlugin, SubdomainPlugin
from app.utils.database import get_sync_db
from app.workers.celery_app import celery_app

logger = get_task_logger(__name__)


def build_default_registry():
    """Build the default plugin registry."""
    return {
        "subdomain": SubdomainPlugin(),
        "http_probe": HttpProbePlugin(),
        "naabu": NaabuPlugin(),
        "nuclei": NucleiPlugin(),
        "ffuf": FfufPlugin(),
    }


registry = build_default_registry()


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _log(db: Session, scan_id: str, message: str, level: str = "info", step: str = None, details: dict = None) -> None:
    """Persist a log entry for the scan."""
    entry = Log(
        scan_id=scan_id,
        level=level,
        step=step,
        message=message,
        details=details or {},
    )
    db.add(entry)
    db.commit()


def _update_scan(db: Session, scan: Scan, **kwargs) -> None:
    """Update scan fields and commit."""
    for key, value in kwargs.items():
        setattr(scan, key, value)
    db.commit()


def _advance_step(scan: Scan, step_name: str) -> None:
    scan.steps_completed = min((scan.steps_completed or 0) + 1, scan.steps_total or 6)
    scan.current_step = step_name


def _upsert_asset(db, target: Target, scan: Scan, asset_type: AssetType, value: str, source: str, raw_data: dict | None = None, **kwargs) -> Asset:
    key = normalize_asset(asset_type, value)
    existing = db.query(Asset).filter_by(scan_id=scan.id, normalized_key=key).first()
    if existing:
        return existing
    asset = Asset(
        target_id=target.id,
        scan_id=scan.id,
        asset_type=asset_type,
        value=value,
        normalized_key=key,
        in_scope=in_scope(value, target.scope_include or [], target.scope_exclude or []),
        source=source,
        raw_data=raw_data or {},
        **kwargs,
    )
    db.add(asset)
    return asset


# ─── Main Task ────────────────────────────────────────────────────────────────

class ScanTask(Task):
    """Custom base task with failure handling."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        scan_id = args[0] if args else kwargs.get("scan_id")
        if scan_id:
            with get_sync_db() as db:
                scan = db.query(Scan).filter_by(id=scan_id).first()
                if scan:
                    _update_scan(
                        db, scan,
                        status=ScanStatus.FAILED,
                        error_message=str(exc)[:2000],
                        completed_at=datetime.now(timezone.utc),
                    )
                    _log(db, scan_id, f"Scan failed: {exc}", level="error")


@celery_app.task(bind=True, base=ScanTask, name="app.workers.scan_tasks.run_scan", max_retries=2)
def run_scan(self, scan_id: str) -> dict:
    logger.info("Starting scan %s", scan_id)

    with get_sync_db() as db:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        target = db.query(Target).filter_by(id=scan.target_id).first()
        if not target:
            raise ValueError(f"Target for scan {scan_id} not found")
        lock = acquire_target_lock(target.id)

    runtime = {}
    with lock:
        with get_sync_db() as db:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            _update_scan(db, scan, status=ScanStatus.RUNNING, started_at=datetime.now(timezone.utc), steps_total=len(STAGE_ORDER), steps_completed=0, current_step=STAGE_ORDER[0].value)
            for stage in STAGE_ORDER:
                db.add(ScanStage(scan_id=scan.id, stage_type=stage, status=StageStatus.PENDING, max_retries=2))
            db.commit()

        for stage in STAGE_ORDER:
            for attempt in range(0, 3):
                target_domain = None
                scan_options = None
                with get_sync_db() as db:
                    scan = db.query(Scan).filter_by(id=scan_id).first()
                    target = db.query(Target).filter_by(id=scan.target_id).first()
                    stage_row = db.query(ScanStage).filter_by(scan_id=scan.id, stage_type=stage).first()
                    stage_row.status = StageStatus.RUNNING
                    stage_row.started_at = datetime.now(timezone.utc)
                    stage_row.attempt = attempt
                    _advance_step(scan, stage.value)
                    _log(db, scan_id, f"Stage started: {stage.value}", step=stage.value)
                    db.commit()
                    # Store values for use outside db context
                    target_domain = target.domain
                    scan_options = scan.options or {}
                try:
                    if stage == ScanStageType.RECON:
                        runtime["recon"] = {"target": target_domain}
                    elif stage == ScanStageType.ENUMERATION:
                        plugin = registry.get("subdomain")
                        context = PluginContext(
                            target_domain=target_domain,
                            options=scan_options,
                            previous=runtime,
                            timeout=300
                        )
                        result = asyncio.run(plugin.run_with_retry(context))
                        if result.success:
                            out = result.data
                            runtime.update(out)
                            with get_sync_db() as db:
                                scan = db.query(Scan).filter_by(id=scan_id).first()
                                target = db.query(Target).filter_by(id=scan.target_id).first()
                                for item in out.get("subdomains", []):
                                    _upsert_asset(db, target, scan, AssetType.SUBDOMAIN, item, source="subfinder")
                                db.commit()
                        else:
                            _log(db, scan_id, f"Subdomain enumeration failed: {result.error}", level="error", step=stage.value)
                            raise Exception(f"Subdomain enumeration failed: {result.error}")
                    elif stage == ScanStageType.PROBING:
                        plugin = registry.get("http_probe")
                        context = PluginContext(
                            target_domain=target_domain,
                            options=scan_options,
                            previous=runtime,
                            timeout=600
                        )
                        result = asyncio.run(plugin.run_with_retry(context))
                        if result.success:
                            out = result.data
                            runtime.update(out)
                            with get_sync_db() as db:
                                scan = db.query(Scan).filter_by(id=scan_id).first()
                                target = db.query(Target).filter_by(id=scan.target_id).first()
                                for probe in out.get("raw_probe", []):
                                    if probe.get("is_alive"):
                                        _upsert_asset(
                                            db,
                                            target,
                                            scan,
                                            AssetType.URL,
                                            probe.get("url", ""),
                                            source="httpx",
                                            raw_data=probe,
                                            ip_address=probe.get("ip"),
                                            is_alive=True,
                                            status_code=probe.get("status_code"),
                                            technologies=probe.get("technologies", []),
                                            headers=probe.get("headers", {}),
                                        )
                                scan.assets_found = db.query(Asset).filter_by(scan_id=scan.id).count()
                                db.commit()
                        else:
                            _log(db, scan_id, f"HTTP probing failed: {result.error}", level="error", step=stage.value)
                            raise Exception(f"HTTP probing failed: {result.error}")
                    elif stage == ScanStageType.SCANNING:
                        plugin = registry.get("nuclei")
                        context = PluginContext(
                            target_domain=target_domain,
                            options=scan_options,
                            previous=runtime,
                            timeout=1800  # 30 minutes for scanning
                        )
                        result = asyncio.run(plugin.run_with_retry(context))
                        if result.success:
                            out = result.data
                            runtime.update(out)
                        else:
                            _log(db, scan_id, f"Vulnerability scanning failed: {result.error}", level="error", step=stage.value)
                            raise Exception(f"Vulnerability scanning failed: {result.error}")
                    elif stage == ScanStageType.VALIDATION:
                        normalized = normalize_nuclei_findings(
                            [
                                type(
                                    "nuclei",
                                    (),
                                    {
                                        "template_id": r.get("template_id", ""),
                                        "name": r.get("name", ""),
                                        "severity": r.get("severity", "info"),
                                        "url": r.get("url", ""),
                                        "matched_at": r.get("matched_at", ""),
                                        "description": r.get("description", ""),
                                        "request": r.get("request", ""),
                                        "response": r.get("response", ""),
                                        "raw": r.get("raw", {}),
                                    },
                                )()
                                for r in runtime.get("raw_nuclei", [])
                            ]
                        )
                        with get_sync_db() as db:
                            scan = db.query(Scan).filter_by(id=scan_id).first()
                            target = db.query(Target).filter_by(id=scan.target_id).first()
                            for nf in normalized:
                                fp = dedup_fingerprint(nf.template_id, nf.title, nf.category)
                                sig = endpoint_signature(nf.url, nf.method)
                                existing = db.query(Finding).filter_by(target_id=target.id, vuln_fingerprint=fp, endpoint_signature=sig).first()
                                if existing:
                                    continue
                                base, exp, weighted = score_finding(nf.severity, exploitability=0.7, confidence=0.8)
                                finding = Finding(
                                    scan_id=scan.id,
                                    target_id=target.id,
                                    category=nf.category if nf.category in list(FindingCategory) else FindingCategory.OTHER,
                                    severity=nf.severity if nf.severity in list(FindingSeverity) else FindingSeverity.INFO,
                                    status=FindingStatus.OPEN,
                                    title=nf.title,
                                    description=nf.description,
                                    tags=tags_for_category(nf.category if nf.category in list(FindingCategory) else FindingCategory.OTHER),
                                    vuln_fingerprint=fp,
                                    endpoint_signature=sig,
                                    url=nf.url,
                                    parameter=nf.parameter,
                                    method=nf.method,
                                    request_snippet=nf.request_snippet,
                                    response_snippet=nf.response_snippet,
                                    evidence=nf.evidence,
                                    source_tool=nf.source_tool,
                                    template_id=nf.template_id,
                                    cvss_base_score=base,
                                    exploitability_score=exp,
                                    weighted_score=weighted,
                                    confidence=0.8,
                                )
                                db.add(finding)
                                db.flush()
                                db.add(Evidence(finding_id=finding.id, evidence_type="raw_tool_output", content=nf.evidence))
                            scan.findings_count = db.query(Finding).filter_by(scan_id=scan.id).count()
                            db.commit()
                    elif stage == ScanStageType.REPORTING:
                        with get_sync_db() as db:
                            scan = db.query(Scan).filter_by(id=scan_id).first()
                            scan.assets_found = db.query(Asset).filter_by(scan_id=scan.id).count()
                            scan.findings_count = db.query(Finding).filter_by(scan_id=scan.id).count()
                            db.commit()
                    with get_sync_db() as db:
                        stage_row = db.query(ScanStage).filter_by(scan_id=scan_id, stage_type=stage).first()
                        stage_row.status = StageStatus.COMPLETED
                        stage_row.completed_at = datetime.now(timezone.utc)
                        db.commit()
                    break
                except Exception as exc:
                    with get_sync_db() as db:
                        stage_row = db.query(ScanStage).filter_by(scan_id=scan_id, stage_type=stage).first()
                        stage_row.status = StageStatus.FAILED
                        stage_row.error_message = str(exc)[:2000]
                        db.commit()
                        _log(db, scan_id, f"Stage failed: {stage.value} ({exc})", level="error", step=stage.value)
                    if attempt >= 2:
                        raise

    with get_sync_db() as db:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        _update_scan(db, scan, status=ScanStatus.COMPLETED, completed_at=datetime.now(timezone.utc), current_step="completed")
        _log(db, scan_id, "Scan completed successfully", step="completed", details={"assets": scan.assets_found, "findings": scan.findings_count})
        final_assets = scan.assets_found
        final_findings = scan.findings_count

    logger.info("Scan %s completed. Assets=%s Findings=%s", scan_id, final_assets, final_findings)
    return {
        "scan_id": scan_id,
        "status": "completed",
        "assets": int(final_assets),
        "findings": int(final_findings),
    }


@celery_app.task(name="app.workers.scan_tasks.process_scheduled_scans")
def process_scheduled_scans() -> dict:
    return {"status": "ok"}
