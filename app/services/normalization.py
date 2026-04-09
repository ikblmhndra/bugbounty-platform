import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from app.models.models import AssetType


def normalize_domain(domain: str) -> str:
    """Normalize domain name with proper handling of subdomains."""
    domain = domain.strip().lower()
    # Remove protocol if present
    if '://' in domain:
        domain = urlparse(domain).netloc
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    # Remove trailing dots
    domain = domain.rstrip('.')
    return domain


def normalize_url(url: str) -> str:
    """Normalize URL with canonical form."""
    if not url:
        return ""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    # Normalize scheme
    scheme = parsed.scheme.lower()
    # Normalize host
    host = parsed.netloc.lower()
    if ':' in host:
        host = host.split(':')[0]  # Remove port for normalization
    # Normalize path
    path = parsed.path or '/'
    if not path.startswith('/'):
        path = '/' + path
    # Remove trailing slash except for root
    if path != '/' and path.endswith('/'):
        path = path.rstrip('/')

    return f"{scheme}://{host}{path}"


def normalize_ip(ip: str) -> str:
    """Normalize IP address."""
    ip = ip.strip()
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def normalize_asset(asset_type: AssetType, value: str) -> str:
    """Enhanced asset normalization with type-specific logic."""
    if not value:
        return ""

    if asset_type == AssetType.DOMAIN:
        return normalize_domain(value)
    elif asset_type == AssetType.SUBDOMAIN:
        return normalize_domain(value)
    elif asset_type == AssetType.URL:
        return normalize_url(value)
    elif asset_type == AssetType.ENDPOINT:
        return normalize_url(value)
    elif asset_type == AssetType.IP:
        return normalize_ip(value)
    else:
        return value.strip().lower()


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower().split(':')[0] if parsed.netloc else None
    except:
        return None


def is_subdomain_of(subdomain: str, domain: str) -> bool:
    """Check if subdomain is actually a subdomain of domain."""
    subdomain = normalize_domain(subdomain)
    domain = normalize_domain(domain)

    if subdomain == domain:
        return True

    return subdomain.endswith('.' + domain)


def deduplicate_assets(assets: List[Dict], target_domain: str) -> List[Dict]:
    """
    Deduplicate assets with intelligent merging.
    Prioritizes more specific information and handles conflicts.
    """
    seen_keys: Set[str] = set()
    deduped: List[Dict] = []

    # Sort by specificity (URLs > subdomains > domains)
    asset_priority = {
        AssetType.URL: 3,
        AssetType.ENDPOINT: 3,
        AssetType.SUBDOMAIN: 2,
        AssetType.DOMAIN: 1,
        AssetType.IP: 1,
    }

    sorted_assets = sorted(
        assets,
        key=lambda x: (
            asset_priority.get(x.get('asset_type'), 0),
            len(x.get('value', '')),
            x.get('source', '')
        ),
        reverse=True
    )

    for asset in sorted_assets:
        asset_type = asset.get('asset_type')
        value = asset.get('value', '')
        normalized_key = normalize_asset(asset_type, value)

        if normalized_key in seen_keys:
            continue

        # Additional validation for subdomains
        if asset_type == AssetType.SUBDOMAIN:
            if not is_subdomain_of(value, target_domain):
                continue

        seen_keys.add(normalized_key)
        deduped.append(asset)

    return deduped


def in_scope(value: str, includes: List[str], excludes: List[str]) -> bool:
    """Enhanced scope checking with pattern matching."""
    value = value.lower()

    # Check exclusions first
    for exclude in excludes:
        exclude = exclude.lower().strip()
        if exclude in value:
            return False
        # Support wildcards
        if '*' in exclude:
            pattern = re.escape(exclude).replace(r'\*', '.*')
            if re.search(pattern, value):
                return False

    # If no includes specified, everything is in scope (except excluded)
    if not includes:
        return True

    # Check inclusions
    for include in includes:
        include = include.lower().strip()
        if include in value:
            return True
        # Support wildcards
        if '*' in include:
            pattern = re.escape(include).replace(r'\*', '.*')
            if re.search(pattern, value):
                return True

    return False


def extract_technologies_from_headers(headers: Dict[str, str]) -> List[str]:
    """Extract technology stack from HTTP headers."""
    techs = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    # Server header
    if 'server' in headers_lower:
        server = headers_lower['server']
        if 'nginx' in server:
            techs.append('nginx')
        elif 'apache' in server:
            techs.append('apache')
        elif 'iis' in server:
            techs.append('iis')

    # X-Powered-By
    if 'x-powered-by' in headers_lower:
        powered = headers_lower['x-powered-by']
        if 'php' in powered:
            techs.append('php')
        elif 'asp.net' in powered:
            techs.append('asp.net')

    # Framework detection
    if 'x-framework' in headers_lower:
        techs.append(headers_lower['x-framework'])

    return list(set(techs))  # Remove duplicates
