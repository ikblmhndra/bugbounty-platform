"""
Recon Pipeline Service
======================
Modular reconnaissance functions that wrap external Go/Python tools.
Each function is independent, composable, and returns structured data.

Tools used:
    subfinder, assetfinder   → subdomain enumeration
    httpx                    → probe alive hosts
    gau, waybackurls, katana → URL / endpoint collection
    ffuf                     → endpoint fuzzing
    nuclei                   → vulnerability scanning
    gowitness                → screenshots
"""
import json
import os
import tempfile
from pathlib import Path
from typing import Optional

from app.config import get_settings
from app.utils.logging import get_logger
from app.utils.shell import CommandResult, run_command

logger = get_logger(__name__)
settings = get_settings()


# ─── Data Classes ────────────────────────────────────────────────────────────

class SubdomainResult:
    def __init__(self, subdomain: str, source: str):
        self.subdomain = subdomain.strip().lower()
        self.source = source


class ProbeResult:
    def __init__(self, url: str, status_code: int, ip: str, technologies: list[str], headers: dict):
        self.url = url
        self.status_code = status_code
        self.ip = ip
        self.technologies = technologies
        self.headers = headers
        self.is_alive = 200 <= status_code < 600


class UrlResult:
    def __init__(self, url: str, source: str):
        self.url = url
        self.source = source


class FuzzResult:
    def __init__(self, url: str, status_code: int, content_length: int, words: int):
        self.url = url
        self.status_code = status_code
        self.content_length = content_length
        self.words = words


class NucleiResult:
    def __init__(
        self,
        template_id: str,
        name: str,
        severity: str,
        url: str,
        matched_at: str,
        description: str,
        request: str,
        response: str,
        raw: dict,
    ):
        self.template_id = template_id
        self.name = name
        self.severity = severity
        self.url = url
        self.matched_at = matched_at
        self.description = description
        self.request = request
        self.response = response
        self.raw = raw


# ─── Subdomain Enumeration ───────────────────────────────────────────────────

def subdomain_enum(domain: str) -> list[SubdomainResult]:
    """
    Enumerate subdomains using subfinder and assetfinder (passive only).
    Results are deduplicated.

    Args:
        domain: Target root domain (e.g. "example.com")

    Returns:
        Deduplicated list of SubdomainResult objects.
    """
    results: dict[str, SubdomainResult] = {}

    # subfinder
    logger.info("Running subfinder", domain=domain)
    cmd = [settings.subfinder_path, "-d", domain, "-silent", "-all", "-json"]
    result = run_command(cmd, timeout=300)
    if result.success:
        for line in result.lines():
            try:
                data = json.loads(line)
                sub = data.get("host", "").strip().lower()
                if sub and sub.endswith(f".{domain}") or sub == domain:
                    if sub not in results:
                        results[sub] = SubdomainResult(sub, "subfinder")
            except json.JSONDecodeError:
                # Non-JSON line (some versions output plain text)
                sub = line.strip().lower()
                if sub and (sub.endswith(f".{domain}") or sub == domain):
                    if sub not in results:
                        results[sub] = SubdomainResult(sub, "subfinder")
    else:
        logger.warning("subfinder failed or unavailable", stderr=result.stderr[:500])

    # assetfinder
    logger.info("Running assetfinder", domain=domain)
    cmd = [settings.assetfinder_path, "--subs-only", domain]
    result = run_command(cmd, timeout=120)
    if result.success:
        for line in result.lines():
            sub = line.strip().lower()
            if sub and (sub.endswith(f".{domain}") or sub == domain):
                if sub not in results:
                    results[sub] = SubdomainResult(sub, "assetfinder")
    else:
        logger.warning("assetfinder failed or unavailable", stderr=result.stderr[:500])

    # Always include root domain
    if domain not in results:
        results[domain] = SubdomainResult(domain, "root")

    logger.info("Subdomain enumeration complete", domain=domain, count=len(results))
    return list(results.values())


# ─── Probe Alive ─────────────────────────────────────────────────────────────

def probe_alive(subdomains: list[str]) -> list[ProbeResult]:
    """
    Probe a list of subdomains/hosts using httpx to determine liveness,
    status codes, IP addresses, and detected technologies.

    Args:
        subdomains: List of hostname strings.

    Returns:
        List of ProbeResult for alive hosts.
    """
    if not subdomains:
        return []

    logger.info("Probing hosts with httpx", count=len(subdomains))

    # Write targets to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        targets_file = f.name

    try:
        cmd = [
            settings.httpx_path,
            "-l", targets_file,
            "-json",
            "-silent",
            "-tech-detect",
            "-status-code",
            "-ip",
            "-follow-redirects",
            "-threads", "50",
            "-timeout", "10",
        ]
        result = run_command(cmd, timeout=600)

        probe_results = []
        if result.success or result.stdout:
            for line in result.lines():
                try:
                    data = json.loads(line)
                    pr = ProbeResult(
                        url=data.get("url", ""),
                        status_code=data.get("status-code", 0),
                        ip=data.get("host", ""),
                        technologies=data.get("technologies", []),
                        headers=data.get("headers", {}),
                    )
                    probe_results.append(pr)
                except (json.JSONDecodeError, KeyError) as e:
                    logger.debug("Failed to parse httpx line", line=line[:200], error=str(e))
        else:
            logger.warning("httpx produced no output", stderr=result.stderr[:500])

        logger.info("Probing complete", alive=len(probe_results))
        return probe_results
    finally:
        os.unlink(targets_file)


# ─── URL Collection ──────────────────────────────────────────────────────────

def collect_urls(domain: str, alive_urls: list[str]) -> list[UrlResult]:
    """
    Collect historical and crawled URLs using gau, waybackurls, and katana.
    Results are deduplicated.

    Args:
        domain: Root domain for passive tools.
        alive_urls: Live URLs for active crawling with katana.

    Returns:
        Deduplicated list of UrlResult objects.
    """
    seen: set[str] = set()
    results: list[UrlResult] = []

    def add_url(url: str, source: str) -> None:
        url = url.strip()
        if url and url not in seen:
            seen.add(url)
            results.append(UrlResult(url=url, source=source))

    # gau (passive)
    logger.info("Running gau", domain=domain)
    cmd = [settings.gau_path, "--subs", domain]
    result = run_command(cmd, timeout=300)
    if result.success:
        for line in result.lines():
            add_url(line, "gau")
    else:
        logger.warning("gau failed", stderr=result.stderr[:300])

    # waybackurls (passive)
    logger.info("Running waybackurls", domain=domain)
    cmd = [settings.waybackurls_path, domain]
    result = run_command(cmd, timeout=300)
    if result.success:
        for line in result.lines():
            add_url(line, "waybackurls")
    else:
        logger.warning("waybackurls failed", stderr=result.stderr[:300])

    # katana (active crawling on alive hosts)
    if alive_urls:
        logger.info("Running katana", targets=len(alive_urls))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(alive_urls[:50]))  # limit to 50 targets
            targets_file = f.name
        try:
            cmd = [
                settings.katana_path,
                "-list", targets_file,
                "-silent",
                "-depth", "3",
                "-concurrency", "20",
                "-timeout", "10",
            ]
            result = run_command(cmd, timeout=600)
            if result.success:
                for line in result.lines():
                    add_url(line, "katana")
            else:
                logger.warning("katana failed", stderr=result.stderr[:300])
        finally:
            os.unlink(targets_file)

    logger.info("URL collection complete", domain=domain, count=len(results))
    return results


# ─── Endpoint Fuzzing ────────────────────────────────────────────────────────

def fuzz_endpoints(
    alive_urls: list[str],
    wordlist: Optional[str] = None,
    max_targets: int = 10,
) -> list[FuzzResult]:
    """
    Fuzz endpoints on alive hosts using ffuf.
    Limited to max_targets to avoid excessive noise.

    Args:
        alive_urls: List of alive base URLs to fuzz.
        wordlist: Path to wordlist file.
        max_targets: Maximum hosts to fuzz.

    Returns:
        List of FuzzResult objects for discovered endpoints.
    """
    wl = wordlist or settings.ffuf_wordlist
    if not os.path.exists(wl):
        logger.warning("Wordlist not found, skipping ffuf", wordlist=wl)
        return []

    results: list[FuzzResult] = []
    targets = alive_urls[:max_targets]

    for base_url in targets:
        url = base_url.rstrip("/") + "/FUZZ"
        logger.info("Fuzzing endpoints", target=url)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out_f:
            out_file = out_f.name

        try:
            cmd = [
                settings.ffuf_path,
                "-u", url,
                "-w", wl,
                "-o", out_file,
                "-of", "json",
                "-mc", "200,204,301,302,307,401,403",
                "-t", "50",
                "-timeout", "10",
                "-sa",  # stop on all error
                "-s",   # silent
            ]
            result = run_command(cmd, timeout=300)

            if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                try:
                    with open(out_file) as f:
                        data = json.load(f)
                    for item in data.get("results", []):
                        results.append(FuzzResult(
                            url=item.get("url", ""),
                            status_code=item.get("status", 0),
                            content_length=item.get("length", 0),
                            words=item.get("words", 0),
                        ))
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning("Failed to parse ffuf output", error=str(e))
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)

    logger.info("Fuzzing complete", results=len(results))
    return results


# ─── Vulnerability Scanning ──────────────────────────────────────────────────

def scan_vulnerabilities(
    alive_urls: list[str],
    severity: Optional[str] = None,
) -> list[NucleiResult]:
    """
    Run nuclei vulnerability scanner against alive hosts.

    Args:
        alive_urls: List of alive URLs to scan.
        severity: Comma-separated severity levels (e.g. "medium,high,critical").

    Returns:
        List of NucleiResult objects.
    """
    if not alive_urls:
        return []

    sev = severity or settings.nuclei_severity
    logger.info("Running nuclei", targets=len(alive_urls), severity=sev)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(alive_urls))
        targets_file = f.name

    try:
        cmd = [
            settings.nuclei_path,
            "-l", targets_file,
            "-severity", sev,
            "-json",
            "-silent",
            "-rate-limit", "50",
            "-concurrency", "25",
            "-timeout", "15",
            "-retries", "1",
        ]
        result = run_command(cmd, timeout=1800)

        nuclei_results: list[NucleiResult] = []
        for line in result.lines():
            try:
                data = json.loads(line)
                info = data.get("info", {})
                nr = NucleiResult(
                    template_id=data.get("template-id", ""),
                    name=info.get("name", ""),
                    severity=info.get("severity", "info"),
                    url=data.get("host", ""),
                    matched_at=data.get("matched-at", ""),
                    description=info.get("description", ""),
                    request=data.get("request", ""),
                    response=data.get("response", ""),
                    raw=data,
                )
                nuclei_results.append(nr)
            except (json.JSONDecodeError, KeyError) as e:
                logger.debug("Failed to parse nuclei output line", error=str(e))

        logger.info("Nuclei scan complete", findings=len(nuclei_results))
        return nuclei_results
    finally:
        os.unlink(targets_file)


# ─── Screenshots ─────────────────────────────────────────────────────────────

def take_screenshots(alive_urls: list[str], output_dir: str) -> dict[str, str]:
    """
    Take screenshots of alive URLs using gowitness.

    Args:
        alive_urls: List of URLs to screenshot.
        output_dir: Directory to save screenshots.

    Returns:
        Dict mapping URL to screenshot file path.
    """
    if not alive_urls:
        return {}

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    logger.info("Taking screenshots", count=len(alive_urls))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(alive_urls))
        targets_file = f.name

    try:
        cmd = [
            settings.gowitness_path,
            "file",
            "-f", targets_file,
            "--screenshot-path", output_dir,
            "--no-db",
            "--timeout", "15",
        ]
        result = run_command(cmd, timeout=600)
        if not result.success:
            logger.warning("gowitness completed with errors", stderr=result.stderr[:300])
    finally:
        os.unlink(targets_file)

    # Map URLs to screenshot paths (gowitness naming convention)
    mapping: dict[str, str] = {}
    for url in alive_urls:
        safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")
        for ext in [".png", ".jpeg"]:
            path = os.path.join(output_dir, safe_name + ext)
            if os.path.exists(path):
                mapping[url] = path
                break

    logger.info("Screenshots complete", captured=len(mapping))
    return mapping
