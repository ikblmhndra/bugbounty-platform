from datetime import datetime, timezone
from pathlib import Path

from celery import Task
from celery.utils.log import get_task_logger
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.models import AttackSurfaceNode, Asset, AssetType, Evidence, Finding, FindingCategory, FindingSeverity, FindingStatus, Log, Scan, ScanStage, ScanStageType, ScanStatus, StageStatus, Target
from app.orchestration.controls import acquire_target_lock
from app.orchestration.state_machine import STAGE_ORDER
from app.services.finding_engine import dedup_fingerprint, endpoint_signature, score_finding, tags_for_category
from app.services.normalization import in_scope, normalize_asset
from app.services.recon_service import (
    collect_urls,
    detect_tech_whatweb,
    fuzz_endpoints,
    parse_endpoints,
    probe_alive,
    run_nikto,
    scan_ports_naabu,
    scan_ports_nmap,
    scan_vulnerabilities,
    score_endpoint,
    subdomain_enum,
    take_screenshots,
)
from app.services.report_service import generate_json_report, generate_markdown_report, save_report
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


def _advance_step(scan: Scan, step_name: str) -> None:
    scan.steps_completed = min((scan.steps_completed or 0) + 1, scan.steps_total or len(STAGE_ORDER))
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

    runtime: dict = {}
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
                    if stage == ScanStageType.TARGET_INPUT:
                        runtime["target"] = target_domain
                    elif stage == ScanStageType.SUBDOMAIN_ENUM:
                        runtime["subdomains"] = [s.subdomain for s in subdomain_enum(target_domain)]
                    elif stage == ScanStageType.ALIVE_DETECTION:
                        probes = probe_alive(runtime.get("subdomains", []))
                        runtime["probes"] = [
                            {
                                "url": p.url,
                                "status_code": p.status_code,
                                "ip": p.ip,
                                "technologies": p.technologies,
                                "headers": p.headers,
                            }
                            for p in probes
                        ]
                        runtime["alive_urls"] = [p.url for p in probes if p.is_alive]
                    elif stage == ScanStageType.URL_COLLECTION:
                        urls = collect_urls(target_domain, runtime.get("alive_urls", []))
                        runtime["urls"] = [u.url for u in urls]
                    elif stage == ScanStageType.ENDPOINT_PARSING:
                        runtime["endpoints"] = parse_endpoints(runtime.get("urls", []))
                    elif stage == ScanStageType.ATTACK_SURFACE_MODELING:
                        with get_sync_db() as db:
                            scan = db.query(Scan).filter_by(id=scan_id).first()
                            target = db.query(Target).filter_by(id=scan.target_id).first()
                            domain_node = AttackSurfaceNode(
                                scan_id=scan.id,
                                target_id=target.id,
                                node_type="domain",
                                value=target.domain,
                                risk_score=0,
                                risk_level="low",
                            )
                            db.merge(domain_node)
                            for sub in runtime.get("subdomains", []):
                                db.merge(AttackSurfaceNode(scan_id=scan.id, target_id=target.id, node_type="subdomain", value=sub, parent_value=target.domain))
                            for ep in runtime.get("endpoints", []):
                                db.merge(
                                    AttackSurfaceNode(
                                        scan_id=scan.id,
                                        target_id=target.id,
                                        node_type="endpoint",
                                        value=ep.get("url"),
                                        parent_value=ep.get("subdomain"),
                                        endpoint_category=ep.get("category"),
                                        node_metadata={"path": ep.get("path"), "parameters": ep.get("parameters", [])},
                                    )
                                )
                            db.commit()
                    elif stage == ScanStageType.RISK_SCORING:
                        ports_blob = runtime.get("naabu_ports", []) + runtime.get("nmap_ports", [])
                        with get_sync_db() as db:
                            scan = db.query(Scan).filter_by(id=scan_id).first()
                            target = db.query(Target).filter_by(id=scan.target_id).first()
                            for ep in runtime.get("endpoints", []):
                                related_tech = []
                                for probe in runtime.get("probes", []):
                                    if probe.get("url", "").startswith(f"http://{ep.get('subdomain')}") or probe.get("url", "").startswith(f"https://{ep.get('subdomain')}"):
                                        related_tech = probe.get("technologies", [])
                                        break
                                scored = score_endpoint(ep, related_tech, ports_blob)
                                ep["risk_score"] = scored["score"]
                                ep["risk_level"] = scored["level"]
                                db.query(AttackSurfaceNode).filter_by(scan_id=scan.id, node_type="endpoint", value=ep.get("url")).update(
                                    {"risk_score": scored["score"], "risk_level": scored["level"]}
                                )
                            db.commit()
                    elif stage == ScanStageType.SMART_PRIORITIZATION:
                        runtime["prioritized_endpoints"] = sorted(
                            runtime.get("endpoints", []),
                            key=lambda e: e.get("risk_score", 0),
                            reverse=True,
                        )
                        runtime["scan_targets"] = [
                            ep.get("url")
                            for ep in runtime["prioritized_endpoints"]
                            if ep.get("risk_level") in ("high", "medium")
                        ]
                    elif stage == ScanStageType.ORCHESTRATION:
                        orchestration = []
                        for ep in runtime.get("prioritized_endpoints", []):
                            if ep.get("risk_level") == "low":
                                orchestration.append({"url": ep.get("url"), "mode": "light"})
                                continue
                            tasks = ["nuclei"]
                            if ep.get("parameters"):
                                tasks.append("nuclei-xss")
                            if ep.get("category") == "login/auth":
                                tasks.append("auth-testing")
                            if ep.get("category") == "api":
                                tasks.append("ffuf")
                            if ep.get("risk_level") == "high":
                                tasks.extend(["ffuf", "nikto"])
                            orchestration.append({"url": ep.get("url"), "tasks": sorted(set(tasks))})
                        runtime["orchestration_plan"] = orchestration
                    elif stage == ScanStageType.VULN_SCANNING:
                        targets = runtime.get("scan_targets", []) or runtime.get("alive_urls", [])
                        nuclei_results = scan_vulnerabilities(targets, scan_options.get("nuclei_severity"))
                        ffuf_results = fuzz_endpoints(targets, scan_options.get("ffuf_wordlist"), max_targets=20) if scan_options.get("run_ffuf", True) else []
                        nikto_results = run_nikto(targets) if scan_options.get("run_nikto", True) else []
                        runtime["nuclei"] = [n.__dict__ for n in nuclei_results]
                        runtime["ffuf"] = [f.__dict__ for f in ffuf_results]
                        runtime["nikto"] = nikto_results
                    elif stage == ScanStageType.PORT_SCANNING:
                        hosts = list({url.split("://", 1)[-1].split("/", 1)[0] for url in runtime.get("alive_urls", [])})
                        runtime["naabu_ports"] = scan_ports_naabu(hosts, rate_limit=int(scan_options.get("rate_limit", 1000)))
                        runtime["nmap_ports"] = scan_ports_nmap(hosts)
                    elif stage == ScanStageType.TECH_DETECTION:
                        runtime["whatweb"] = detect_tech_whatweb(runtime.get("alive_urls", [])) if scan_options.get("run_whatweb", True) else []
                    elif stage == ScanStageType.SCREENSHOT:
                        if scan_options.get("run_gowitness", True):
                            shots_dir = str(Path(settings.screenshots_dir) / scan_id)
                            runtime["screenshots"] = take_screenshots(runtime.get("alive_urls", []), shots_dir)
                    elif stage == ScanStageType.NORMALIZATION:
                        runtime["normalized"] = {
                            "target": target_domain,
                            "subdomains": runtime.get("subdomains", []),
                            "alive": runtime.get("probes", []),
                            "urls": runtime.get("urls", []),
                            "endpoints": runtime.get("endpoints", []),
                            "ports": {"naabu": runtime.get("naabu_ports", []), "nmap": runtime.get("nmap_ports", [])},
                            "tech": runtime.get("whatweb", []),
                            "vulnerabilities": {
                                "nuclei": runtime.get("nuclei", []),
                                "ffuf": runtime.get("ffuf", []),
                                "nikto": runtime.get("nikto", []),
                            },
                        }
                    elif stage == ScanStageType.STORAGE:
                        with get_sync_db() as db:
                            scan = db.query(Scan).filter_by(id=scan_id).first()
                            target = db.query(Target).filter_by(id=scan.target_id).first()
                            for item in runtime.get("subdomains", []):
                                _upsert_asset(db, target, scan, AssetType.SUBDOMAIN, item, source="subfinder")
                            for probe in runtime.get("probes", []):
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
                            for ep in runtime.get("endpoints", []):
                                _upsert_asset(
                                    db,
                                    target,
                                    scan,
                                    AssetType.ENDPOINT,
                                    ep.get("url", ""),
                                    source="parser",
                                    raw_data=ep,
                                    endpoint_path=ep.get("path"),
                                    query_params=ep.get("parameters", []),
                                    endpoint_category=ep.get("category"),
                                    risk_score=ep.get("risk_score", 0),
                                )
                            for finding_row in runtime.get("nuclei", []):
                                category = FindingCategory.OTHER
                                title = finding_row.get("name", "Nuclei finding")
                                severity = finding_row.get("severity", "info")
                                fp = dedup_fingerprint(finding_row.get("template_id", ""), title, category)
                                sig = endpoint_signature(finding_row.get("url", ""), "GET")
                                if db.query(Finding).filter_by(target_id=target.id, vuln_fingerprint=fp, endpoint_signature=sig).first():
                                    continue
                                sev_enum = FindingSeverity(severity) if severity in [s.value for s in FindingSeverity] else FindingSeverity.INFO
                                base, exp, weighted = score_finding(sev_enum, exploitability=0.7, confidence=0.8)
                                finding = Finding(
                                    scan_id=scan.id,
                                    target_id=target.id,
                                    category=category,
                                    severity=sev_enum,
                                    status=FindingStatus.OPEN,
                                    title=title,
                                    description=finding_row.get("description"),
                                    tags=tags_for_category(category),
                                    vuln_fingerprint=fp,
                                    endpoint_signature=sig,
                                    url=finding_row.get("url"),
                                    evidence=finding_row,
                                    source_tool="nuclei",
                                    template_id=finding_row.get("template_id"),
                                    cvss_base_score=base,
                                    exploitability_score=exp,
                                    weighted_score=weighted,
                                    confidence=0.8,
                                )
                                db.add(finding)
                                db.flush()
                                db.add(Evidence(finding_id=finding.id, evidence_type="raw_tool_output", content=finding_row))
                            scan.assets_found = db.query(Asset).filter_by(scan_id=scan.id).count()
                            scan.findings_count = db.query(Finding).filter_by(scan_id=scan.id).count()
                            db.commit()
                    elif stage == ScanStageType.REPORTING:
                        with get_sync_db() as db:
                            scan = db.query(Scan).filter_by(id=scan_id).first()
                            target = db.query(Target).filter_by(id=scan.target_id).first()
                            findings = db.query(Finding).filter_by(scan_id=scan_id).all()
                            report_json = generate_json_report(scan, target, findings, runtime.get("prioritized_endpoints", []), runtime.get("orchestration_plan", []))
                            report_md = generate_markdown_report(scan, target, findings, runtime.get("prioritized_endpoints", []), runtime.get("orchestration_plan", []))
                            runtime["report_json_path"] = save_report(scan_id, report_json, "json")
                            runtime["report_md_path"] = save_report(scan_id, report_md, "markdown")
                    elif stage == ScanStageType.DASHBOARD_EXPOSURE:
                        runtime["dashboard"] = {
                            "scan_id": scan_id,
                            "assets": len(runtime.get("subdomains", [])),
                            "prioritized": len(runtime.get("scan_targets", [])),
                            "reports": [runtime.get("report_json_path"), runtime.get("report_md_path")],
                        }
                    with get_sync_db() as db:
                        stage_row = db.query(ScanStage).filter_by(scan_id=scan_id, stage_type=stage).first()
                        stage_row.stage_data = {"runtime_keys": sorted(runtime.keys())}
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
