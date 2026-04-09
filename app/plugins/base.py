import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol

from app.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class PluginContext:
    target_domain: str
    options: Dict[str, Any]
    previous: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 300  # Default 5 minutes
    retry_count: int = 2


@dataclass
class PluginResult:
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    duration: float = 0.0
    retries: int = 0


class ScannerPlugin(Protocol):
    name: str
    description: str = ""
    version: str = "1.0.0"

    async def run(self, context: PluginContext) -> PluginResult:
        """Execute the plugin with error handling and timing."""
        ...


class BasePlugin:
    """Base class for plugins with common functionality."""

    name: str
    description: str = ""
    version: str = "1.0.0"

    async def run_with_retry(self, context: PluginContext) -> PluginResult:
        """Run plugin with retry logic and error handling."""
        start_time = time.time()
        last_error = None

        for attempt in range(context.retry_count + 1):
            try:
                logger.info(f"Running plugin {self.name} (attempt {attempt + 1})",
                          plugin=self.name, attempt=attempt + 1)

                result = await self.run(context)
                duration = time.time() - start_time

                if result.success:
                    result.duration = duration
                    result.retries = attempt
                    logger.info(f"Plugin {self.name} completed successfully",
                              plugin=self.name, duration=duration, retries=attempt)
                    return result
                else:
                    last_error = result.error or "Plugin returned failure"
                    logger.warning(f"Plugin {self.name} failed (attempt {attempt + 1}): {last_error}",
                                 plugin=self.name, attempt=attempt + 1, error=last_error)

            except Exception as e:
                last_error = str(e)
                logger.error(f"Plugin {self.name} exception (attempt {attempt + 1}): {last_error}",
                           plugin=self.name, attempt=attempt + 1, error=last_error, exc_info=True)

            # Wait before retry (exponential backoff)
            if attempt < context.retry_count:
                wait_time = 2 ** attempt  # 1s, 2s, 4s...
                logger.info(f"Retrying plugin {self.name} in {wait_time}s",
                          plugin=self.name, wait_time=wait_time)
                await asyncio.sleep(wait_time)

        # All attempts failed
        duration = time.time() - start_time
        logger.error(f"Plugin {self.name} failed permanently after {context.retry_count + 1} attempts",
                   plugin=self.name, total_attempts=context.retry_count + 1, last_error=last_error)

        return PluginResult(
            success=False,
            data={},
            error=last_error,
            duration=duration,
            retries=context.retry_count
        )

    async def run(self, context: PluginContext) -> PluginResult:
        """Override this method in subclasses."""
        raise NotImplementedError


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: Dict[str, ScannerPlugin] = {}

    def register(self, plugin: ScannerPlugin) -> None:
        self._plugins[plugin.name] = plugin
        logger.info(f"Registered plugin: {plugin.name}")

    def get(self, name: str) -> ScannerPlugin:
        if name not in self._plugins:
            raise ValueError(f"Plugin '{name}' not registered")
        return self._plugins[name]

    def all(self) -> Dict[str, ScannerPlugin]:
        return self._plugins.copy()

    def list_plugins(self) -> list[str]:
        return list(self._plugins.keys())
