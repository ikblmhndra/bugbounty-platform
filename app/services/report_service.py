"""
Reporting Service
=================
Generates scan reports in Markdown, JSON, and HTML formats.
Includes findings, attack paths, and validation suggestions.
"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, BaseLoader
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.models import AttackPath, Finding, Scan, Target
from app.utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Bug Bounty Report - {{ target_domain }}</title>
<style>
  :root { --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff; --border: #30363d;
          --critical: #ff4444; --high: #ff8c00; --medium: #ffd700; --low: #3fb950; --info: #8b949e; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--fg); font-family: 'Segoe UI', system-ui, sans-serif;
         line-height: 1.6; padding: 40px; }
  h1 { font-size: 2rem; color: var(--accent); margin-bottom: 8px; }
  h2 { font-size: 1.4rem; color: var(--accent); margin: 32px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
  h3 { font-size: 1.1rem; margin: 20px 0 8px; }
  .meta { color: var(--info); font-size: 0.9rem; margin-bottom: 32px; }
  .stats { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 32px; }
  .stat-card { background: #161b22; border: 1px solid var(--border); border-radius: 8px;
               padding: 16px 24px; min-width: 120px; text-align: center; }
  .stat-card .val { font-size: 2rem; font-weight: bold; }
  .stat-card .lbl { font-size: 0.8rem; color: var(--info); text-transform: uppercase; }
  .finding { background: #161b22; border: 1px solid var(--border); border-radius: 8px;
             padding: 20px; margin-bottom: 16px; }
  .finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
  .badge { padding: 3px 10px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }
  .badge.critical { background: var(--critical); color: #fff; }
  .badge.high     { background: var(--high); color: #000; }
  .badge.medium   { background: var(--medium); color: #000; }
  .badge.low      { background: var(--low); color: #000; }
  .badge.info     { background: var(--info); color: #fff; }
  .badge.cat      { background: #21262d; color: var(--fg); }
  .url { font-size: 0.85rem; color: var(--info); font-family: monospace; margin-top: 4px; }
  pre { background: #0d1117; border: 1px solid var(--border); border-radius: 4px;
        padding: 12px; overflow-x: auto; font-size: 0.82rem; margin-top: 8px; }
  .path { background: #161b22; border: 1px solid var(--border); border-left: 4px solid var(--accent);
           border-radius: 8px; padding: 20px; margin-bottom: 20px; }
  .confidence { font-size: 0.85rem; color: var(--info); }
  .steps ol { padding-left: 20px; margin-top: 8px; }
  .steps li { margin-bottom: 6px; font-size: 0.9rem; }
  footer { margin-top: 48px; color: var(--info); font-size: 0.8rem; text-align: center; }
</style>
</head>
<body>
<h1>🔍 Security Assessment Report</h1>
<div class="meta">
  Target: <strong>{{ target_domain }}</strong> &nbsp;|&nbsp;
  Scan ID: <code>{{ scan_id }}</code> &nbsp;|&nbsp;
  Generated: {{ generated_at }}
</div>

<div class="stats">
  <div class="stat-card"><div class="val">{{ stats.total }}</div><div class="lbl">Findings</div></div>
  <div class="stat-card" style="border-color: var(--critical)"><div class="val" style="color:var(--critical)">{{ stats.critical }}</div><div class="lbl">Critical</div></div>
  <div class="stat-card" style="border-color: var(--high)"><div class="val" style="color:var(--high)">{{ stats.high }}</div><div class="lbl">High</div></div>
  <div class="stat-card" style="border-color: var(--medium)"><div class="val" style="color:var(--medium)">{{ stats.medium }}</div><div class="lbl">Medium</div></div>
  <div class="stat-card"><div class="val">{{ stats.assets }}</div><div class="lbl">Assets</div></div>
  <div class="stat-card"><div class="val">{{ stats.attack_paths }}</div><div class="lbl">Attack Paths</div></div>
</div>

<h2>Findings</h2>
{% for f in findings %}
<div class="finding">
  <div class="finding-header">
    <span class="badge {{ f.severity }}">{{ f.severity }}</span>
    <span class="badge cat">{{ f.category }}</span>
    <strong>{{ f.title }}</strong>
  </div>
  {% if f.url %}<div class="url">{{ f.url }}</div>{% endif %}
  {% if f.description %}<p style="margin-top:8px; font-size:0.9rem;">{{ f.description }}</p>{% endif %}
  {% if f.template_id %}<div style="font-size:0.8rem; color: var(--info); margin-top:6px;">Template: <code>{{ f.template_id }}</code></div>{% endif %}
</div>
{% else %}
<p style="color: var(--info)">No findings recorded.</p>
{% endfor %}

<h2>Attack Paths</h2>
{% for path in attack_paths %}
<div class="path">
  <h3>{{ path.title }}</h3>
  <div class="confidence">Confidence: {{ (path.confidence * 100)|int }}% &nbsp;|&nbsp; Impact: {{ path.impact }}</div>
  <p style="margin-top: 10px; font-size: 0.9rem;">{{ path.description }}</p>
  <div class="steps">
    <ol>{% for step in path.steps %}<li>{{ step }}</li>{% endfor %}</ol>
  </div>
</div>
{% else %}
<p style="color: var(--info)">No attack paths identified.</p>
{% endfor %}

<footer>Generated by Bug Bounty Platform &mdash; For authorized use only.</footer>
</body>
</html>"""


def generate_markdown_report(
    scan: Scan,
    target: Target,
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> str:
    """Generate a Markdown report string."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Security Assessment Report",
        f"",
        f"**Target:** `{target.domain}`  ",
        f"**Scan ID:** `{scan.id}`  ",
        f"**Status:** {scan.status.value}  ",
        f"**Generated:** {now}  ",
        f"",
        f"---",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if not f.false_positive:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    for sev, count in severity_counts.items():
        lines.append(f"| {sev.capitalize()} | {count} |")

    lines += [
        f"",
        f"**Assets Discovered:** {scan.assets_found}  ",
        f"**Attack Paths Identified:** {len(attack_paths)}  ",
        f"",
        f"---",
        f"",
        f"## Findings",
        f"",
    ]

    for f in findings:
        if f.false_positive:
            continue
        lines += [
            f"### [{f.severity.value.upper()}] {f.title}",
            f"",
            f"- **Category:** `{f.category.value}`",
            f"- **Template:** `{f.template_id or 'N/A'}`",
            f"- **URL:** `{f.url or 'N/A'}`",
        ]
        if f.parameter:
            lines.append(f"- **Parameter:** `{f.parameter}`")
        if f.description:
            lines += [f"", f"{f.description}"]
        if f.analyst_notes:
            lines += [f"", f"**Analyst Notes:** {f.analyst_notes}"]
        lines += ["", "---", ""]

    lines += [f"## Attack Paths", f""]
    for ap in attack_paths:
        confidence_pct = int(ap.confidence * 100)
        lines += [
            f"### {ap.title}",
            f"",
            f"**Confidence:** {confidence_pct}% | **Impact:** {ap.impact or 'N/A'}",
            f"",
            ap.description,
            f"",
            f"**Steps:**",
            f"",
        ]
        for step in ap.steps:
            lines.append(f"- {step}")
        lines += ["", "---", ""]

    lines += [
        f"",
        f"*Report generated by Bug Bounty Platform. For authorized use only.*",
    ]
    return "\n".join(lines)


def generate_json_report(
    scan: Scan,
    target: Target,
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> dict:
    """Generate a JSON-serializable report dict."""
    return {
        "report_version": "1.0",
        "generated_at": datetime.utcnow().isoformat(),
        "scan": {
            "id": scan.id,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
        "target": {
            "id": target.id,
            "domain": target.domain,
        },
        "summary": {
            "assets": scan.assets_found,
            "findings": len([f for f in findings if not f.false_positive]),
            "attack_paths": len(attack_paths),
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "url": f.url,
                "parameter": f.parameter,
                "description": f.description,
                "template_id": f.template_id,
                "is_validated": f.is_validated,
                "false_positive": f.false_positive,
                "analyst_notes": f.analyst_notes,
            }
            for f in findings if not f.false_positive
        ],
        "attack_paths": [
            {
                "id": ap.id,
                "title": ap.title,
                "description": ap.description,
                "confidence": ap.confidence,
                "impact": ap.impact,
                "steps": ap.steps,
            }
            for ap in attack_paths
        ],
    }


def generate_html_report(
    scan: Scan,
    target: Target,
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> str:
    """Generate an HTML report string from Jinja2 template."""
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if not f.false_positive:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    env = Environment(loader=BaseLoader())
    tmpl = env.from_string(HTML_TEMPLATE)
    return tmpl.render(
        target_domain=target.domain,
        scan_id=scan.id,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        stats={
            "total": sum(sev_counts.values()),
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "assets": scan.assets_found,
            "attack_paths": len(attack_paths),
        },
        findings=[
            {
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "url": f.url,
                "description": f.description,
                "template_id": f.template_id,
            }
            for f in findings if not f.false_positive
        ],
        attack_paths=[
            {
                "title": ap.title,
                "description": ap.description,
                "confidence": ap.confidence,
                "impact": ap.impact or "Unknown",
                "steps": ap.steps,
            }
            for ap in attack_paths
        ],
    )


def save_report(scan_id: str, content: str, fmt: str) -> str:
    """
    Save a report to disk and return the file path.

    Args:
        scan_id: Scan UUID.
        content: Report content string.
        fmt: Format string: "markdown", "json", "html".

    Returns:
        Absolute path to saved file.
    """
    ext_map = {"markdown": "md", "json": "json", "html": "html"}
    ext = ext_map.get(fmt, "txt")
    reports_dir = Path(settings.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"report_{scan_id}.{ext}"
    path.write_text(content, encoding="utf-8")
    logger.info("Report saved", path=str(path), format=fmt)
    return str(path)
