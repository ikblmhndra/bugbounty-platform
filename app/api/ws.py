from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.event_bus import scan_event_bus

router = APIRouter(prefix="/ws", tags=["ws"])


@router.websocket("/scans/{scan_id}")
async def scan_stream(websocket: WebSocket, scan_id: str):
    await scan_event_bus.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        scan_event_bus.disconnect(scan_id, websocket)
