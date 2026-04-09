import re
from urllib.parse import urlparse


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$", re.IGNORECASE)


def sanitize_domain(raw_value: str) -> str:
    value = (raw_value or "").strip().lower()
    if not value:
        raise ValueError("Domain is required")
    if "://" in value:
        value = urlparse(value).netloc or value
    value = value.split("/")[0].split(":")[0].strip(".")
    if not DOMAIN_RE.match(value):
        raise ValueError("Invalid domain format")
    return value
