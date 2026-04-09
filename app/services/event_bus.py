from collections import defaultdict
from typing import Any

from fastapi import WebSocket


class ScanEventBus:
    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[scan_id].append(websocket)

    def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        if scan_id in self._connections and websocket in self._connections[scan_id]:
            self._connections[scan_id].remove(websocket)

    async def publish(self, scan_id: str, payload: dict[str, Any]) -> None:
        for ws in list(self._connections.get(scan_id, [])):
            try:
                await ws.send_json(payload)
            except Exception:
                self.disconnect(scan_id, ws)


scan_event_bus = ScanEventBus()
