import hashlib

from app.models.models import FindingCategory, FindingSeverity


TAG_MAP = {
    FindingCategory.XSS: ["xss"],
    FindingCategory.SQLI: ["sqli"],
    FindingCategory.MISCONFIG: ["misconfig"],
    FindingCategory.EXPOSURE: ["exposure"],
}


def score_finding(severity: FindingSeverity, exploitability: float, confidence: float) -> tuple[float, float, float]:
    base_map = {
        FindingSeverity.INFO: 0.0,
        FindingSeverity.LOW: 3.1,
        FindingSeverity.MEDIUM: 5.5,
        FindingSeverity.HIGH: 8.0,
        FindingSeverity.CRITICAL: 9.5,
    }
    base = base_map[severity]
    weighted = min(10.0, (base * 0.7) + (exploitability * 2.0) + (confidence * 1.0))
    return base, exploitability, weighted


def dedup_fingerprint(template_id: str | None, title: str, category: FindingCategory) -> str:
    seed = f"{template_id or 'na'}::{title.lower().strip()}::{category.value}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def endpoint_signature(url: str | None, method: str | None = None) -> str:
    seed = f"{(method or 'GET').upper()}::{(url or '').strip().lower()}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def tags_for_category(category: FindingCategory) -> list[str]:
    return TAG_MAP.get(category, [category.value])
