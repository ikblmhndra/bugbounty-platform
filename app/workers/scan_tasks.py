"""
Celery Scan Tasks
=================
Orchestrates the full recon pipeline for a given scan ID.
Pulls jobs from the queue, executes modular recon steps,
persists results incrementally, and handles failures gracefully.
"""
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from celery import Task
from celery.utils.log import get_task_logger
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.models import (
    Asset,
    AssetType,
    AttackPath,
    AttackPathNode,
    Finding,
    FindingCategory,
    FindingSeverity,
    Log,
    Scan,
    ScanStatus,
    Target,
)
from app.services.analysis_service import (
    analyze_finding_relationships,
    normalize_nuclei_findings,
)
from app.services.recon_service import (
    collect_urls,
    fuzz_endpoints,
    probe_alive,
    scan_vulnerabilities,
    subdomain_enum,
    take_screenshots,
)
from app.utils.database import get_sync_db
from app.workers.celery_app import celery_app

logger = get_task_logger(__name__)
settings = get_settings()


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


def _advance_step(db: Session, scan: Scan, step_name: str) -> None:
    """Increment the step counter and update current_step."""
    scan.steps_completed += 1
    scan.current_step = step_name
    db.commit()


def _upsert_asset(db: Session, scan_id: str, asset_type: AssetType, value: str, **kwargs) -> Asset:
    """Insert asset if it doesn't already exist for this scan."""
    existing = db.query(Asset).filter_by(scan_id=scan_id, value=value).first()
    if existing:
        return existing
    asset = Asset(scan_id=scan_id, asset_type=asset_type, value=value, **kwargs)
    db.add(asset)
    db.commit()
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


@celery_app.task(bind=True, base=ScanTask, name="app.workers.scan_tasks.run_scan", max_retries=1)
def run_scan(self, scan_id: str) -> dict:
    """
    Main scan task. Executes the full recon pipeline for a scan.

    Pipeline:
        1. Subdomain enumeration
        2. Probe alive hosts
        3. Collect URLs
        4. Screenshot alive hosts
        5. Fuzz endpoints (optional)
        6. Nuclei vulnerability scan
        7. Normalize + analyze findings
        8. Persist attack paths

    Args:
        scan_id: UUID of the Scan record to execute.

    Returns:
        Summary dict with counts.
    """
    logger.info(f"Starting scan {scan_id}")

    with get_sync_db() as db:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        target = db.query(Target).filter_by(id=scan.target_id).first()
        if not target:
            raise ValueError(f"Target for scan {scan_id} not found")

        options = scan.options or {}
        domain = target.domain
        run_ffuf = options.get("run_ffuf", False)
        run_gowitness = options.get("run_gowitness", True)
        nuclei_severity = options.get("nuclei_severity", settings.nuclei_severity)
        ffuf_wordlist = options.get("ffuf_wordlist", settings.ffuf_wordlist)

        total_steps = 6 + (1 if run_ffuf else 0) + (1 if run_gowitness else 0)
        _update_scan(
            db, scan,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            steps_total=total_steps,
            steps_completed=0,
            current_step="starting",
        )
        _log(db, scan_id, f"Scan started for domain: {domain}", step="init")

    # ── Step 1: Subdomain Enumeration ────────────────────────────────────────
    try:
        with get_sync_db() as db:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            _advance_step(db, scan, "subdomain_enum")
            _log(db, scan_id, "Starting subdomain enumeration", step="subdomain_enum")

        subdomain_results = subdomain_enum(domain)
        subdomains = [r.subdomain for r in subdomain_results]

        with get_sync_db() as db:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            for r in subdomain_results:
                _upsert_asset(db, scan_id, AssetType.SUBDOMAIN, r.subdomain)
            _log(db, scan_id, f"Found {len(subdomains)} subdomains", step="subdomain_enum",
                 details={"count": len(subdomains)})

    except Exception as e:
        logger.error(f"Subdomain enum failed: {e}")
        with get_sync_db() as db:
            _log(db, scan_id, f"Subdomain enum error: {e}", level="warning", step="subdomain_enum")
        subdomains = [domain]

    # ── Step 2: Probe Alive ───────────────────────────────────────────────────
    try:
        with get_sync_db() as db:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            _advance_step(db, scan, "probe_alive")
            _log(db, scan_id, f"Probing {len(subdomains)} hosts", step="probe_alive")

        probe_results = probe_alive(subdomains)
        alive_urls = [p.url for p in probe_results if p.is_alive]

        with get_sync_db() as db:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            for pr in probe_results:
                if pr.is_alive:
                    _upsert_asset(
                        db, scan_id, AssetType.URL, pr.url,
                        ip_address=pr.ip,
                        is_alive=True,
                        status_code=pr.status_code,
                        technologies=pr.technologies,
                        headers=pr.headers,
                    )
            scan.assets_found = db.query(Asset).filter_by(scan_id=scan_id).count()
            db.commit()
            _log(db, scan_id, f"{len(alive_urls)} alive hosts found", step="probe_alive",
                 details={"alive": len(alive_urls)})

    except Exception as e:
        logger.error(f"Probe alive failed: {e}")
        with get_sync_db() as db:
            _log(db, scan_id, f"Probe alive error: {e}", level="warning", step="probe_alive")
        alive_urls = [f"https://{domain}"]

    # ── Step 3: Collect URLs ──────────────────────────────────────────────────
    try:
        with get_sync_db() as db:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            _advance_step(db, scan, "collect_urls")
            _log(db, scan_id, "Collecting URLs", step="collect_urls")

        url_results = collect_urls(domain, alive_urls)
        collected_urls = [r.url for r in url_results]

        with get_sync_db() as db:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            # Deduplicate and persist (bulk, no upsert loop to save time)
            existing = {a.value for a in db.query(Asset.value).filter_by(scan_id=scan_id)}
            new_assets = [
                Asset(scan_id=scan_id, asset_type=AssetType.URL, value=r.url)
                for r in url_results if r.url not in existing
            ]
            if new_assets:
                db.bulk_save_objects(new_assets)
            scan.assets_found = db.query(Asset).filter_by(scan_id=scan_id).count()
            db.commit()
            _log(db, scan_id, f"Collected {len(url_results)} URLs", step="collect_urls",
                 details={"count": len(url_results)})

    except Exception as e:
        logger.error(f"URL collection failed: {e}")
        with get_sync_db() as db:
            _log(db, scan_id, f"URL collection error: {e}", level="warning", step="collect_urls")
        collected_urls = alive_urls

    # ── Step 4: Screenshots (optional) ───────────────────────────────────────
    if run_gowitness:
        try:
            with get_sync_db() as db:
                scan = db.query(Scan).filter_by(id=scan_id).first()
                _advance_step(db, scan, "screenshots")
                _log(db, scan_id, "Taking screenshots", step="screenshots")

            screenshots_dir = os.path.join(settings.screenshots_dir, scan_id)
            screenshot_map = take_screenshots(alive_urls[:30], screenshots_dir)

            with get_sync_db() as db:
                for url, path in screenshot_map.items():
                    asset = db.query(Asset).filter_by(scan_id=scan_id, value=url).first()
                    if asset:
                        asset.screenshot_path = path
                db.commit()
                _log(db, scan_id, f"Screenshots captured: {len(screenshot_map)}", step="screenshots")

        except Exception as e:
            logger.error(f"Screenshots failed: {e}")
            with get_sync_db() as db:
                _log(db, scan_id, f"Screenshot error: {e}", level="warning", step="screenshots")

    # ── Step 5: Endpoint Fuzzing (optional) ───────────────────────────────────
    if run_ffuf:
        try:
            with get_sync_db() as db:
                scan = db.query(Scan).filter_by(id=scan_id).first()
                _advance_step(db, scan, "fuzz_endpoints")
                _log(db, scan_id, "Fuzzing endpoints with ffuf", step="fuzz_endpoints")

            fuzz_results = fuzz_endpoints(alive_urls, wordlist=ffuf_wordlist)

            with get_sync_db() as db:
                scan = db.query(Scan).filter_by(id=scan_id).first()
                existing = {a.value for a in db.query(Asset.value).filter_by(scan_id=scan_id)}
                new_eps = [
                    Asset(scan_id=scan_id, asset_type=AssetType.ENDPOINT,
                          value=r.url, status_code=r.status_code)
                    for r in fuzz_results if r.url not in existing
                ]
                if new_eps:
                    db.bulk_save_objects(new_eps)
                scan.assets_found = db.query(Asset).filter_by(scan_id=scan_id).count()
                db.commit()
                _log(db, scan_id, f"Fuzz discovered {len(fuzz_results)} endpoints", step="fuzz_endpoints")

        except Exception as e:
            logger.error(f"Fuzzing failed: {e}")
            with get_sync_db() as db:
                _log(db, scan_id, f"Fuzz error: {e}", level="warning", step="fuzz_endpoints")

    # ── Step 6: Nuclei Vulnerability Scan ────────────────────────────────────
    nuclei_results = []
    try:
        with get_sync_db() as db:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            _advance_step(db, scan, "scan_vulnerabilities")
            _log(db, scan_id, f"Running nuclei (severity: {nuclei_severity})", step="scan_vulnerabilities")

        # Use alive URLs + a sample of collected URLs
        scan_targets = list(set(alive_urls + collected_urls[:200]))
        nuclei_results = scan_vulnerabilities(scan_targets, severity=nuclei_severity)

        with get_sync_db() as db:
            _log(db, scan_id, f"Nuclei found {len(nuclei_results)} potential issues", step="scan_vulnerabilities",
                 details={"count": len(nuclei_results)})

    except Exception as e:
        logger.error(f"Nuclei scan failed: {e}")
        with get_sync_db() as db:
            _log(db, scan_id, f"Nuclei error: {e}", level="warning", step="scan_vulnerabilities")

    # ── Step 7: Normalize + Persist Findings ─────────────────────────────────
    try:
        with get_sync_db() as db:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            _advance_step(db, scan, "normalize_findings")
            _log(db, scan_id, "Normalizing findings", step="normalize_findings")

        normalized = normalize_nuclei_findings(nuclei_results)

        with get_sync_db() as db:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            for nf in normalized:
                finding = Finding(
                    scan_id=scan_id,
                    category=nf.category,
                    severity=nf.severity,
                    title=nf.title,
                    description=nf.description,
                    url=nf.url,
                    parameter=nf.parameter,
                    request_snippet=nf.request_snippet,
                    response_snippet=nf.response_snippet,
                    evidence=nf.evidence,
                    source_tool=nf.source_tool,
                    template_id=nf.template_id,
                )
                db.add(finding)
            scan.findings_count = len(normalized)
            db.commit()
            _log(db, scan_id, f"Persisted {len(normalized)} findings", step="normalize_findings")

    except Exception as e:
        logger.error(f"Finding normalization failed: {e}")
        with get_sync_db() as db:
            _log(db, scan_id, f"Normalization error: {e}", level="error", step="normalize_findings")
        normalized = []

    # ── Step 8: Attack Path Analysis ─────────────────────────────────────────
    try:
        with get_sync_db() as db:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            _advance_step(db, scan, "attack_path_analysis")
            _log(db, scan_id, "Analyzing attack paths", step="attack_path_analysis")

        attack_paths = analyze_finding_relationships(normalized)

        with get_sync_db() as db:
            for ap in attack_paths:
                db_path = AttackPath(
                    scan_id=scan_id,
                    title=ap.title,
                    description=ap.description,
                    confidence=ap.confidence,
                    impact=ap.impact,
                    steps=ap.steps,
                )
                db.add(db_path)
                db.flush()  # get db_path.id

                for i, node in enumerate(ap.path_nodes):
                    db_node = AttackPathNode(
                        attack_path_id=db_path.id,
                        order=i,
                        label=node.label,
                        description=node.description,
                        validation_command=node.validation_command,
                    )
                    db.add(db_node)

            db.commit()
            _log(db, scan_id, f"Identified {len(attack_paths)} attack paths", step="attack_path_analysis")

    except Exception as e:
        logger.error(f"Attack path analysis failed: {e}")
        with get_sync_db() as db:
            _log(db, scan_id, f"Attack path error: {e}", level="warning", step="attack_path_analysis")

    # ── Finalize ─────────────────────────────────────────────────────────────
    with get_sync_db() as db:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        _update_scan(
            db, scan,
            status=ScanStatus.COMPLETED,
            completed_at=datetime.now(timezone.utc),
            current_step="completed",
        )
        _log(db, scan_id, "Scan completed successfully", step="completed",
             details={
                 "assets": scan.assets_found,
                 "findings": scan.findings_count,
             })

    logger.info(f"Scan {scan_id} completed. Assets: {scan.assets_found}, Findings: {scan.findings_count}")
    return {
        "scan_id": scan_id,
        "status": "completed",
        "assets": scan.assets_found,
        "findings": scan.findings_count,
    }
