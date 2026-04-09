import hashlib
from typing import Dict, List, Tuple

from app.models.models import FindingCategory, FindingSeverity


TAG_MAP = {
    FindingCategory.XSS: ["xss", "injection", "client-side"],
    FindingCategory.SQLI: ["sqli", "injection", "database"],
    FindingCategory.MISCONFIG: ["misconfig", "configuration", "exposure"],
    FindingCategory.EXPOSURE: ["exposure", "sensitive", "leak"],
    FindingCategory.SSRF: ["ssrf", "server-side", "request"],
    FindingCategory.RCE: ["rce", "remote-code", "execution"],
    FindingCategory.IDOR: ["idor", "authorization", "access-control"],
    FindingCategory.OTHER: ["other"],
}


def cvss_base_score(severity: FindingSeverity) -> float:
    """CVSS v3.1 base score mapping."""
    mapping = {
        FindingSeverity.INFO: 0.0,
        FindingSeverity.LOW: 2.5,
        FindingSeverity.MEDIUM: 5.0,
        FindingSeverity.HIGH: 7.5,
        FindingSeverity.CRITICAL: 9.8,
    }
    return mapping.get(severity, 0.0)


def calculate_cvss_score(
    severity: FindingSeverity,
    exploitability: float,
    impact: float,
    confidence: float
) -> Tuple[float, float, float]:
    """
    Calculate CVSS-like score with temporal and environmental factors.

    Args:
        severity: Base severity level
        exploitability: How easily exploitable (0.0-1.0)
        impact: Potential impact (0.0-1.0)
        confidence: Confidence in finding (0.0-1.0)

    Returns:
        Tuple of (base_score, exploitability_score, final_score)
    """
    base = cvss_base_score(severity)

    # Exploitability factors
    exploitability_factors = {
        'network_access': 0.8,  # Assume network accessible
        'complexity': 0.5 if exploitability > 0.7 else 0.8,  # Low vs High complexity
        'privileges': 0.7,  # Assume some privileges needed
        'interaction': 0.3 if exploitability > 0.8 else 0.5,  # None vs Required
    }

    exploitability_score = min(10.0, sum(exploitability_factors.values()) * exploitability)

    # Impact score (confidentiality, integrity, availability)
    impact_score = min(6.42, (impact * 3))  # Simplified CIA impact

    # Base score calculation (simplified CVSS)
    if impact_score == 0:
        base_score = 0
    else:
        base_score = min(10.0, ((0.6 * impact_score) + (0.4 * exploitability_score) - 1.5) * 1.176)

    # Temporal score (confidence affects temporal metric)
    temporal_score = base_score * confidence

    # Environmental score (simplified - assume standard environment)
    environmental_score = temporal_score

    return round(base_score, 1), round(exploitability_score, 1), round(environmental_score, 1)


def score_finding(severity: FindingSeverity, exploitability: float, confidence: float) -> Tuple[float, float, float]:
    """
    Legacy compatibility wrapper for CVSS scoring.
    """
    impact = 0.8 if severity in [FindingSeverity.HIGH, FindingSeverity.CRITICAL] else 0.5
    return calculate_cvss_score(severity, exploitability, impact, confidence)


def dedup_fingerprint(template_id: str | None, title: str, category: FindingCategory, url: str | None = None) -> str:
    """
    Enhanced deduplication fingerprint that includes URL context to reduce false positives.
    """
    url_context = ""
    if url:
        # Extract domain and path pattern
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc
            path_parts = parsed.path.strip('/').split('/')[:2]  # First two path segments
            path_pattern = '/'.join(path_parts) if path_parts else ''
            url_context = f"{domain}::{path_pattern}"
        except:
            url_context = url[:100]  # Fallback

    seed = f"{template_id or 'na'}::{title.lower().strip()}::{category.value}::{url_context}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def endpoint_signature(url: str | None, method: str | None = None, parameter: str | None = None) -> str:
    """
    Enhanced endpoint signature including parameter context.
    """
    method_part = (method or 'GET').upper()
    url_part = (url or '').strip().lower()
    param_part = (parameter or '').strip().lower()

    seed = f"{method_part}::{url_part}::{param_part}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def tags_for_category(category: FindingCategory) -> List[str]:
    """Get tags for a finding category."""
    return TAG_MAP.get(category, [category.value])


def categorize_finding_by_content(title: str, description: str) -> FindingCategory:
    """
    ML-like categorization based on content analysis.
    """
    content = f"{title} {description}".lower()

    # XSS indicators
    if any(word in content for word in ['xss', 'cross-site', 'scripting', 'injection', 'javascript']):
        return FindingCategory.XSS

    # SQLi indicators
    if any(word in content for word in ['sql', 'injection', 'database', 'query', 'mysql', 'postgresql']):
        return FindingCategory.SQLI

    # SSRF indicators
    if any(word in content for word in ['ssrf', 'server-side', 'request', 'forge', 'redirect']):
        return FindingCategory.SSRF

    # RCE indicators
    if any(word in content for word in ['rce', 'remote', 'code', 'execution', 'command', 'shell']):
        return FindingCategory.RCE

    # IDOR indicators
    if any(word in content for word in ['idor', 'authorization', 'access', 'control', 'insecure']):
        return FindingCategory.IDOR

    # Exposure indicators
    if any(word in content for word in ['exposure', 'leak', 'sensitive', 'information', 'disclosure']):
        return FindingCategory.EXPOSURE

    # Misconfig indicators
    if any(word in content for word in ['misconfig', 'configuration', 'default', 'weak', 'insecure']):
        return FindingCategory.MISCONFIG

    return FindingCategory.OTHER
