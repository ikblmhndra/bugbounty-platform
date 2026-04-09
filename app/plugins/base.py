from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class PluginContext:
    target_domain: str
    options: dict[str, Any]
    previous: dict[str, Any] = field(default_factory=dict)


class ScannerPlugin(Protocol):
    name: str

    async def run(self, context: PluginContext) -> dict[str, Any]:
        ...


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, ScannerPlugin] = {}

    def register(self, plugin: ScannerPlugin) -> None:
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> ScannerPlugin:
        return self._plugins[name]

    def all(self) -> dict[str, ScannerPlugin]:
        return self._plugins
