from app.plugins.base import PluginContext
from app.services.recon_service import probe_alive, scan_vulnerabilities, subdomain_enum


class SubdomainPlugin:
    name = "subdomain"

    async def run(self, context: PluginContext) -> dict:
        rows = subdomain_enum(context.target_domain)
        return {"subdomains": [r.subdomain for r in rows], "raw_subdomains": [r.__dict__ for r in rows]}


class HttpProbePlugin:
    name = "http_probe"

    async def run(self, context: PluginContext) -> dict:
        rows = probe_alive(context.previous.get("subdomains", [context.target_domain]))
        return {
            "alive_urls": [r.url for r in rows if r.is_alive],
            "raw_probe": [r.__dict__ for r in rows],
        }


class NaabuPlugin:
    name = "naabu"

    async def run(self, context: PluginContext) -> dict:
        # Placeholder for naabu integration in this slice.
        alive = context.previous.get("alive_urls", [])
        return {"ports": [{"host": url, "open_ports": [80, 443]} for url in alive]}


class NucleiPlugin:
    name = "nuclei"

    async def run(self, context: PluginContext) -> dict:
        rows = scan_vulnerabilities(
            context.previous.get("alive_urls", []),
            severity=context.options.get("nuclei_severity"),
        )
        return {"raw_nuclei": [r.__dict__ for r in rows]}
