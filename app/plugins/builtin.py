from typing import Dict, Any

from app.plugins.base import BasePlugin, PluginContext, PluginResult
from app.services.recon_service import probe_alive, scan_vulnerabilities, subdomain_enum


class SubdomainPlugin(BasePlugin):
    name = "subdomain"
    description = "Enumerate subdomains using passive and active techniques"
    version = "1.0.0"

    async def run(self, context: PluginContext) -> PluginResult:
        try:
            rows = subdomain_enum(context.target_domain)
            return PluginResult(
                success=True,
                data={
                    "subdomains": [r.subdomain for r in rows],
                    "raw_subdomains": [r.__dict__ for r in rows],
                    "count": len(rows)
                }
            )
        except Exception as e:
            return PluginResult(
                success=False,
                data={},
                error=f"Subdomain enumeration failed: {str(e)}"
            )


class HttpProbePlugin(BasePlugin):
    name = "http_probe"
    description = "Probe HTTP services and detect technologies"
    version = "1.0.0"

    async def run(self, context: PluginContext) -> PluginResult:
        try:
            subdomains = context.previous.get("subdomains", [context.target_domain])
            if not subdomains:
                return PluginResult(
                    success=False,
                    data={},
                    error="No subdomains available for probing"
                )

            rows = probe_alive(subdomains)
            alive_results = [r.__dict__ for r in rows if r.is_alive]

            return PluginResult(
                success=True,
                data={
                    "alive_urls": [r["url"] for r in alive_results],
                    "raw_probe": alive_results,
                    "total_probed": len(subdomains),
                    "alive_count": len(alive_results)
                }
            )
        except Exception as e:
            return PluginResult(
                success=False,
                data={},
                error=f"HTTP probing failed: {str(e)}"
            )


class NaabuPlugin(BasePlugin):
    name = "naabu"
    description = "Fast port scanning for alive hosts"
    version = "1.0.0"

    async def run(self, context: PluginContext) -> PluginResult:
        try:
            # Placeholder implementation - would integrate with naabu tool
            alive_urls = context.previous.get("alive_urls", [])
            if not alive_urls:
                return PluginResult(
                    success=False,
                    data={},
                    error="No alive URLs available for port scanning"
                )

            # Mock port scanning results for now
            ports_data = []
            for url in alive_urls:
                # Extract host from URL
                host = url.replace("https://", "").replace("http://", "").split("/")[0]
                ports_data.append({
                    "host": host,
                    "open_ports": [80, 443],  # Common ports
                    "source": "naabu"
                })

            return PluginResult(
                success=True,
                data={
                    "ports": ports_data,
                    "scanned_hosts": len(alive_urls)
                }
            )
        except Exception as e:
            return PluginResult(
                success=False,
                data={},
                error=f"Port scanning failed: {str(e)}"
            )


class NucleiPlugin(BasePlugin):
    name = "nuclei"
    description = "Vulnerability scanning with Nuclei templates"
    version = "1.0.0"

    async def run(self, context: PluginContext) -> PluginResult:
        try:
            alive_urls = context.previous.get("alive_urls", []) or []
            if not alive_urls:
                root_target = context.target_domain.strip().rstrip("/")
                if root_target:
                    if root_target.startswith("http://") or root_target.startswith("https://"):
                        alive_urls = [root_target]
                    else:
                        alive_urls = [f"https://{root_target}", f"http://{root_target}"]

            if not alive_urls:
                return PluginResult(
                    success=True,
                    data={
                        "raw_nuclei": [],
                        "findings_count": 0,
                        "severity_filter": context.options.get("nuclei_severity"),
                        "note": "No live URLs found; skipping vulnerability scanning"
                    }
                )

            severity_filter = context.options.get("nuclei_severity")
            rows = scan_vulnerabilities(alive_urls, severity=severity_filter)

            return PluginResult(
                success=True,
                data={
                    "raw_nuclei": [r.__dict__ for r in rows],
                    "findings_count": len(rows),
                    "severity_filter": severity_filter
                }
            )
        except Exception as e:
            return PluginResult(
                success=False,
                data={},
                error=f"Vulnerability scanning failed: {str(e)}"
            )


class FfufPlugin(BasePlugin):
    name = "ffuf"
    description = "Directory and file fuzzing"
    version = "1.0.0"

    async def run(self, context: PluginContext) -> PluginResult:
        try:
            # Placeholder for ffuf integration
            alive_urls = context.previous.get("alive_urls", [])
            if not alive_urls:
                return PluginResult(
                    success=False,
                    data={},
                    error="No alive URLs available for fuzzing"
                )

            # Mock fuzzing results
            fuzz_results = []
            for url in alive_urls[:5]:  # Limit to first 5 URLs
                fuzz_results.extend([
                    {"url": f"{url}/admin", "status": 200, "size": 1234},
                    {"url": f"{url}/.git", "status": 403, "size": 234},
                ])

            return PluginResult(
                success=True,
                data={
                    "fuzz_results": fuzz_results,
                    "fuzzed_urls": len(alive_urls)
                }
            )
        except Exception as e:
            return PluginResult(
                success=False,
                data={},
                error=f"Directory fuzzing failed: {str(e)}"
            )
