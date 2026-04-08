"""
Finding Analysis Service
========================
Normalizes raw tool output into categorized findings.
Identifies relationships between findings and constructs attack paths.

This module does NOT perform exploitation. It provides:
    - Category/severity normalization
    - Relationship mapping between findings
    - Human-readable attack path descriptions for analyst review
"""
import re
from dataclasses import dataclass, field
from typing import Optional

from app.models.models import FindingCategory, FindingSeverity
from app.services.recon_service import NucleiResult
from app.utils.logging import get_logger

logger = get_logger(__name__)


# ─── Normalized Finding ───────────────────────────────────────────────────────

@dataclass
class NormalizedFinding:
    title: str
    description: str
    category: FindingCategory
    severity: FindingSeverity
    url: str
    parameter: Optional[str] = None
    method: Optional[str] = None
    request_snippet: Optional[str] = None
    response_snippet: Optional[str] = None
    evidence: dict = field(default_factory=dict)
    source_tool: str = "nuclei"
    template_id: Optional[str] = None


# ─── Attack Path ──────────────────────────────────────────────────────────────

@dataclass
class AttackPathStep:
    label: str
    description: str
    finding_ref: Optional[NormalizedFinding] = None
    validation_command: Optional[str] = None


@dataclass
class AnalyzedAttackPath:
    title: str
    description: str
    confidence: float   # 0.0 – 1.0
    impact: str
    steps: list[str]
    path_nodes: list[AttackPathStep]


# ─── Nuclei Severity Mapping ──────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "critical": FindingSeverity.CRITICAL,
    "high":     FindingSeverity.HIGH,
    "medium":   FindingSeverity.MEDIUM,
    "low":      FindingSeverity.LOW,
    "info":     FindingSeverity.INFO,
    "unknown":  FindingSeverity.INFO,
}

# ─── Template → Category heuristics ─────────────────────────────────────────

_CATEGORY_KEYWORDS: list[tuple[list[str], FindingCategory]] = [
    (["xss", "cross-site-scripting", "script-injection"], FindingCategory.XSS),
    (["sqli", "sql-injection", "blind-sql", "time-based-sql"], FindingCategory.SQLI),
    (["lfi", "local-file", "path-traversal", "directory-traversal"], FindingCategory.LFI),
    (["ssrf", "server-side-request-forgery", "internal-ip"], FindingCategory.SSRF),
    (["rce", "remote-code-execution", "code-injection", "command-injection", "os-injection"], FindingCategory.RCE),
    (["idor", "insecure-direct-object", "broken-access-control"], FindingCategory.IDOR),
    (["open-redirect", "redirect"], FindingCategory.OPEN_REDIRECT),
    (["csrf", "cross-site-request-forgery"], FindingCategory.CSRF),
    (["xxe", "xml-external"], FindingCategory.XXE),
    (["ssti", "server-side-template"], FindingCategory.SSTI),
    (["exposed", "disclosure", "sensitive-data", "api-key", "secret", "password", "token", "leak"], FindingCategory.SENSITIVE_DATA),
    (["misconfig", "misconfiguration", "cors", "csp", "hsts", "clickjacking", "header", "takeover", "s3-bucket"], FindingCategory.MISCONFIGURATION),
]


def _categorize_finding(template_id: str, name: str) -> FindingCategory:
    """Infer category from template ID and name using keyword matching."""
    text = f"{template_id} {name}".lower()
    for keywords, category in _CATEGORY_KEYWORDS:
        for kw in keywords:
            if kw in text:
                return category
    return FindingCategory.OTHER


# ─── Validation Command Suggestions ──────────────────────────────────────────

_VALIDATION_COMMANDS: dict[FindingCategory, str] = {
    FindingCategory.XSS: (
        'dalfox url "{url}" --follow-redirects\n'
        '# OR: curl -s "{url}&q=<script>alert(1)</script>" | grep -i "<script>"'
    ),
    FindingCategory.SQLI: (
        'sqlmap -u "{url}" --batch --risk=1 --level=1 --output-dir=/tmp/sqlmap_out\n'
        '# Hint: Use --data for POST parameters'
    ),
    FindingCategory.LFI: (
        'curl -s "{url}?file=../../../../etc/passwd" | head -20\n'
        'curl -s "{url}?path=....//....//etc/hosts"'
    ),
    FindingCategory.SSRF: (
        '# Use an out-of-band detector (Burp Collaborator / interactsh)\n'
        'curl -s "{url}?url=https://your-interactsh-host.com"'
    ),
    FindingCategory.RCE: (
        '# Test with a safe ping/sleep first\n'
        'curl -s "{url}" --data "cmd=id"\n'
        '# Verify with: curl "http://your-interactsh-host.com"'
    ),
    FindingCategory.SENSITIVE_DATA: (
        'curl -I "{url}"\n'
        'curl -s "{url}" | head -50'
    ),
    FindingCategory.MISCONFIGURATION: (
        'curl -I "{url}"\n'
        '# Check response headers carefully'
    ),
    FindingCategory.IDOR: (
        '# Manually test with different object IDs\n'
        'curl -s "{url}" -H "Authorization: Bearer <victim_token>"'
    ),
    FindingCategory.OPEN_REDIRECT: (
        'curl -I "{url}?next=https://evil.com" | grep -i location'
    ),
}


def get_validation_command(category: FindingCategory, url: str) -> str:
    """Return a suggested validation command for analyst manual testing."""
    template = _VALIDATION_COMMANDS.get(category, 'curl -s "{url}"')
    return template.format(url=url)


# ─── Normalize Nuclei Findings ───────────────────────────────────────────────

def normalize_nuclei_findings(nuclei_results: list[NucleiResult]) -> list[NormalizedFinding]:
    """
    Convert raw nuclei results into normalized NormalizedFinding objects.

    Args:
        nuclei_results: List of NucleiResult from recon_service.scan_vulnerabilities()

    Returns:
        List of NormalizedFinding objects.
    """
    normalized = []
    for nr in nuclei_results:
        category = _categorize_finding(nr.template_id, nr.name)
        severity = _SEVERITY_MAP.get(nr.severity.lower(), FindingSeverity.INFO)

        nf = NormalizedFinding(
            title=nr.name or nr.template_id,
            description=nr.description or f"Detected by nuclei template: {nr.template_id}",
            category=category,
            severity=severity,
            url=nr.url or nr.matched_at,
            request_snippet=nr.request[:2000] if nr.request else None,
            response_snippet=nr.response[:2000] if nr.response else None,
            evidence=nr.raw,
            source_tool="nuclei",
            template_id=nr.template_id,
        )

        # Extract parameter from matched-at URL if present
        if "?" in nr.matched_at:
            try:
                param_part = nr.matched_at.split("?", 1)[1]
                params = [p.split("=")[0] for p in param_part.split("&") if "=" in p]
                if params:
                    nf.parameter = params[0]
            except Exception:
                pass

        normalized.append(nf)

    logger.info("Normalized nuclei findings", count=len(normalized))
    return normalized


# ─── Finding Relationship Analysis ───────────────────────────────────────────

def analyze_finding_relationships(
    findings: list[NormalizedFinding],
) -> list[AnalyzedAttackPath]:
    """
    Identify relationships between findings and produce analyst-facing attack paths.
    Purely analytical — does not perform any exploitation.

    Attack path patterns detected:
        1. XSS + session cookie → account takeover path
        2. SSRF + cloud metadata → credential leak path
        3. SQLi + sensitive data → data exfiltration path
        4. LFI + config exposure → credential access path
        5. Misconfiguration chains

    Args:
        findings: List of normalized findings from a scan.

    Returns:
        List of AnalyzedAttackPath for analyst review.
    """
    by_category: dict[FindingCategory, list[NormalizedFinding]] = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    paths: list[AnalyzedAttackPath] = []

    # Pattern 1: XSS → Account Takeover
    if FindingCategory.XSS in by_category:
        xss_findings = by_category[FindingCategory.XSS]
        high_xss = [f for f in xss_findings if f.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)]
        if high_xss:
            sample = high_xss[0]
            path = AnalyzedAttackPath(
                title="XSS → Session Hijacking → Account Takeover",
                description=(
                    f"A reflected or stored XSS vulnerability exists at {sample.url}. "
                    "If session cookies are not marked HttpOnly, JavaScript can access them, "
                    "enabling an attacker to hijack authenticated sessions."
                ),
                confidence=0.65,
                impact="Account takeover, privilege escalation",
                steps=[
                    f"1. Confirm XSS at: {sample.url}",
                    "2. Check if cookies lack HttpOnly flag (inspect Set-Cookie headers)",
                    "3. Test if document.cookie is accessible via injected script",
                    "4. Attempt session reuse on protected endpoints with stolen token",
                ],
                path_nodes=[
                    AttackPathStep(
                        label="XSS Trigger",
                        description=f"Inject payload at {sample.url}",
                        finding_ref=sample,
                        validation_command=get_validation_command(FindingCategory.XSS, sample.url),
                    ),
                    AttackPathStep(
                        label="Cookie Accessibility Check",
                        description="Verify HttpOnly flag is absent",
                        validation_command=f'curl -I "{sample.url}" | grep -i set-cookie',
                    ),
                    AttackPathStep(
                        label="Session Reuse",
                        description="Manually replay stolen cookie on authenticated endpoint",
                        validation_command=f'curl -s -H "Cookie: session=<stolen_value>" "{sample.url}" | head -50',
                    ),
                ],
            )
            paths.append(path)

    # Pattern 2: SSRF → Cloud Metadata
    if FindingCategory.SSRF in by_category:
        ssrf_findings = by_category[FindingCategory.SSRF]
        sample = ssrf_findings[0]
        path = AnalyzedAttackPath(
            title="SSRF → Internal Metadata → Credential Exposure",
            description=(
                f"SSRF vulnerability detected at {sample.url}. "
                "If the target is hosted on cloud infrastructure (AWS, GCP, Azure), "
                "an SSRF may allow fetching IAM credentials from the metadata endpoint."
            ),
            confidence=0.55,
            impact="Cloud credential exposure, lateral movement",
            steps=[
                f"1. Confirm SSRF at: {sample.url}",
                "2. Test redirect to http://169.254.169.254/latest/meta-data/",
                "3. If AWS: attempt /latest/meta-data/iam/security-credentials/",
                "4. If GCP: attempt http://metadata.google.internal/computeMetadata/v1/",
                "5. Verify response contains credential data",
            ],
            path_nodes=[
                AttackPathStep(
                    label="SSRF Confirmation",
                    description="Confirm out-of-band callback works",
                    finding_ref=sample,
                    validation_command=get_validation_command(FindingCategory.SSRF, sample.url),
                ),
                AttackPathStep(
                    label="Cloud Metadata Probe",
                    description="Attempt metadata endpoint access",
                    validation_command=(
                        f'# AWS metadata test\n'
                        f'curl -s "{sample.url}?url=http://169.254.169.254/latest/meta-data/"'
                    ),
                ),
            ],
        )
        paths.append(path)

    # Pattern 3: SQLi → Data Exfiltration
    if FindingCategory.SQLI in by_category:
        sqli_findings = by_category[FindingCategory.SQLI]
        sample = sqli_findings[0]
        has_sensitive = FindingCategory.SENSITIVE_DATA in by_category
        confidence = 0.80 if has_sensitive else 0.60

        path = AnalyzedAttackPath(
            title="SQL Injection → Data Exfiltration",
            description=(
                f"SQL injection detected at {sample.url}. "
                "Combined with observed sensitive data exposures, this may allow "
                "exfiltration of user credentials, PII, or application secrets."
                + (" Sensitive data endpoints were also found in this scan." if has_sensitive else "")
            ),
            confidence=confidence,
            impact="Database exfiltration, credential dump",
            steps=[
                f"1. Confirm SQLi at: {sample.url}",
                "2. Enumerate databases with safe UNION/information_schema queries",
                "3. Identify tables with PII or credential data",
                "4. Report structure to triage team before proceeding",
            ],
            path_nodes=[
                AttackPathStep(
                    label="SQLi Confirmation",
                    description="Run sqlmap in safe mode (no data dumping)",
                    finding_ref=sample,
                    validation_command=get_validation_command(FindingCategory.SQLI, sample.url),
                ),
                AttackPathStep(
                    label="Schema Enumeration",
                    description="Enumerate database structure only",
                    validation_command=(
                        f'sqlmap -u "{sample.url}" --batch --risk=1 --level=1 '
                        f'--dbs --technique=B --output-dir=/tmp/sqlmap_out'
                    ),
                ),
            ],
        )
        paths.append(path)

    # Pattern 4: LFI → Configuration Exposure
    if FindingCategory.LFI in by_category:
        lfi_findings = by_category[FindingCategory.LFI]
        sample = lfi_findings[0]
        path = AnalyzedAttackPath(
            title="LFI → Configuration File Exposure → Credential Access",
            description=(
                f"Local File Inclusion detected at {sample.url}. "
                "This may allow reading application config files, SSH keys, or /etc/passwd, "
                "potentially exposing credentials or enabling further compromise."
            ),
            confidence=0.70,
            impact="Credential exposure, system information disclosure",
            steps=[
                f"1. Confirm LFI at: {sample.url}",
                "2. Test common paths: /etc/passwd, /proc/self/environ",
                "3. Test app-specific paths: .env, config.php, application.yml",
                "4. Document readable files and report for triage",
            ],
            path_nodes=[
                AttackPathStep(
                    label="LFI Confirmation",
                    description="Read /etc/passwd to confirm file read",
                    finding_ref=sample,
                    validation_command=get_validation_command(FindingCategory.LFI, sample.url),
                ),
                AttackPathStep(
                    label="Config File Read",
                    description="Attempt to read application configuration",
                    validation_command=(
                        f'curl -s "{sample.url}?file=../../../../.env"\n'
                        f'curl -s "{sample.url}?file=../../../../etc/shadow"'
                    ),
                ),
            ],
        )
        paths.append(path)

    # Pattern 5: Misconfiguration Chain
    misconfigs = by_category.get(FindingCategory.MISCONFIGURATION, [])
    if len(misconfigs) >= 3:
        path = AnalyzedAttackPath(
            title="Misconfiguration Cluster → Elevated Attack Surface",
            description=(
                f"{len(misconfigs)} misconfiguration findings detected across the target. "
                "Clusters of misconfigurations often indicate systemic security hygiene issues "
                "and may compound to enable more significant attacks."
            ),
            confidence=0.50,
            impact="Increased attack surface, information disclosure",
            steps=[
                f"1. Review all {len(misconfigs)} misconfiguration findings",
                "2. Prioritize those with CORS wildcard or subdomain takeover potential",
                "3. Check for missing security headers (CSP, HSTS, X-Frame-Options)",
                "4. Validate each with manual curl requests",
            ],
            path_nodes=[
                AttackPathStep(
                    label="Security Header Audit",
                    description="Verify missing headers across live hosts",
                    validation_command=(
                        'curl -I "TARGET_URL" | grep -iE "strict-transport|content-security|x-frame"'
                    ),
                ),
            ],
        )
        paths.append(path)

    logger.info("Attack path analysis complete", paths=len(paths))
    return paths


# ─── Summary Statistics ───────────────────────────────────────────────────────

def summarize_findings(findings: list[NormalizedFinding]) -> dict:
    """Produce a summary dict of findings by severity and category."""
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}

    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        by_category[f.category.value] = by_category.get(f.category.value, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
    }
