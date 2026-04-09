from app.plugins.base import PluginRegistry
from app.plugins.builtin import HttpProbePlugin, NaabuPlugin, NucleiPlugin, SubdomainPlugin


def build_default_registry() -> PluginRegistry:
    registry = PluginRegistry()
    registry.register(SubdomainPlugin())
    registry.register(HttpProbePlugin())
    registry.register(NaabuPlugin())
    registry.register(NucleiPlugin())
    return registry
