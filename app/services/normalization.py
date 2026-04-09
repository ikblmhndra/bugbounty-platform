from urllib.parse import urlparse

from app.models.models import AssetType


def normalize_asset(asset_type: AssetType, value: str) -> str:
    cleaned = (value or "").strip().lower()
    if asset_type in (AssetType.URL, AssetType.ENDPOINT):
        parsed = urlparse(cleaned)
        host = parsed.netloc.lower()
        path = parsed.path or "/"
        return f"{parsed.scheme}://{host}{path}"
    return cleaned


def in_scope(value: str, includes: list[str], excludes: list[str]) -> bool:
    value = value.lower()
    if excludes and any(p.lower() in value for p in excludes):
        return False
    if not includes:
        return True
    return any(p.lower() in value for p in includes)
